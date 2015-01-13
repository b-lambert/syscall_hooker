/*
 *
 *   ______________.___. __________________     _____  .____    .____
 *  /   _____/\__  |   |/   _____/\_   ___ \   /  _  \ |    |   |    |
 *  \_____  \  /   |   |\_____  \ /    \  \/  /  /_\  \|    |   |    |
 *  /        \ \____   |/        \\     \____/    |    \    |___|    |___
 * /_______  / / ______/_______  / \______  /\____|__  /_______ \_______ \
 * \/  \/              \/         \/         \/        \/       \/
 *   ___ ___ ________   ________   ____  __._____________________
 *  /   |   \\_____  \  \_____  \ |    |/ _|\_   _____/\______   \
 * /    ~    \/   |   \  /   |   \|      <   |    __)_  |       _/
 * \    Y    /    |    \/    |    \    |  \  |        \ |    |   \
 *  \___|_  /\_______  /\_______  /____|__ \/_______  / |____|_  /
 *
 * syscall hooker
 *
 *
 * (c) Will Yee, 2015 - will.yee@live.com
 *
 * MicroLinker.cpp
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "includes/MicroLinker.h"
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>

#include <utility>

MicroLinker::MicroLinker(std::vector<uint8_t>& kextBuffer, std::vector<uint8_t>& kernelBuffer, std::vector<std::pair<std::string, std::string> >& syscallsToHook, Kernel& kernel, tAddress addressOfShadowTable)
: kextBuffer(kextBuffer)
, kernelBuffer(kernelBuffer)
, syscallsToHook(syscallsToHook)
, kernel(kernel)
, injectedAddress(0)
, addressOfShadowTable(addressOfShadowTable)
{
}

MicroLinker::~MicroLinker()
{
    
}

bool MicroLinker::RestoreHook(std::string syscall)
{
    bool success = false;
    kResult result = KERN_FAILURE;
    
    if (injectedAddress != 0)
    {
        KernelInterface& kernInterface = kernel.GetKernelInterface();
        
        // Get the address of the entry for the system call to that was hooked
        tAddress syscallAddressInTable = addressOfShadowTable + (sizeof(sysent_t) * sysentSymToOffset.at(syscall));
        
        tAddress originalSyscallAddress = kernelSymbolMap[syscall];
        
        result = kernInterface.WriteToKernelMemory(syscallAddressInTable, reinterpret_cast<unsigned char*>(&originalSyscallAddress), sizeof(tAddress));
        
        if (result == KERN_SUCCESS)
        {
            success = true;
        }
        
    }
    
    return success;
}

bool MicroLinker::InjectAndHook(sysent_t* pSysent)
{
    bool success = false;
    
    if (kernel.IsReady() == true)
    {
        success = ParseKernelSymbols();
        if (success == true)
        {
            success = ParseKextSymbols();
            if (success == true)
            {
                success = InjectKext();
                if (success == true)
                {
                    success = FixUpExternalReolcations();
                    if (success == true)
                    {
                        success = FixUpLocalRelocations();
                        if (success == true)
                        {
                            success = HookSystemCalls(pSysent);
                            if (success == true)
                            {
                                // We're good, just return, this statement is not needed
                                // success = true;
                            }
                        }
                    }
                }
            }
        }
    }
    
    return  success;
}

bool MicroLinker::FixUpExternalReolcations()
{
    bool success = false;
    kResult result = KERN_FAILURE;
    
    if (injectedAddress != 0)
    {
        KernelInterface& kernInterface = kernel.GetKernelInterface();
        
        for (std::vector<std::pair<uint64_t, tAddress> >::iterator it = externRelocTable.begin(); it != externRelocTable.end(); ++it)
        {
            // The string representation of the symbol that needs to be looked up
            std::string symbol = kextSymbolNumToString[it->first];
            
            // Address of the symbol in the kernel
            tAddress address = kernelSymbolMap[symbol];
            
            // Address of where the relocation needs to be updated with the address of the
            // symbol in the kernel
            tAddress relocUpdateNeeded = injectedAddress + it->second;
            
            result = kernInterface.WriteToKernelMemory(relocUpdateNeeded, reinterpret_cast<unsigned char*>(&address), sizeof(tAddress));
            
            // If the write fails, bailout
            if (result != KERN_SUCCESS)
            {
                break;
            }
            
        }
        
        if (result == KERN_SUCCESS)
        {
            success = true;
        }
        
        if (externRelocTable.size() == 0)
        {
            success = true;
        }
        
    }
    return success;
}

bool MicroLinker::FixUpLocalRelocations()
{
    bool success = false;
    kResult result = KERN_FAILURE;
    
    if (injectedAddress != 0)
    {
        KernelInterface& kernInterface = kernel.GetKernelInterface();
        
        for (std::vector<std::pair<uint64_t, tAddress> >::iterator it = localRelocTable.begin(); it != localRelocTable.end(); ++it)
        {
            uint64_t* pOffset = reinterpret_cast<uint64_t*>(&kextBuffer[0] + it->second);

            if (pOffset != nullptr)
            {
                tAddress localSymbolAddress = injectedAddress + (*pOffset);
                
                result = kernInterface.WriteToKernelMemory(injectedAddress + it->second, reinterpret_cast<unsigned char*>(&localSymbolAddress), sizeof(tAddress));
                
                unsigned char buffer[512];
                
                kernInterface.ReadFromKernelMemory(buffer, localSymbolAddress, 512);
                
                if (result != KERN_SUCCESS)
                {
                    break;
                }
            }
        }
        
        if (result == KERN_SUCCESS)
        {
            success = true;
        }
    }
    
    return success;
}

bool MicroLinker::InjectKext()
{
    bool             success = false;
    kResult          result = KERN_FAILURE;
    KernelInterface& kernInterface = kernel.GetKernelInterface();
    tAddress         addressInKernel = 0;
    
    result = kernInterface.AllocateKernelMemory(&addressInKernel, kextBuffer.size());
    
    if (result == KERN_SUCCESS && addressInKernel != 0)
    {
        // Change page protections of newly allocated section of memory to RWX
        result = kernInterface.ChangeKernelMemoryProtections(addressInKernel, kextBuffer.size(), false, VM_PROT_ALL);
        
        if (result == KERN_SUCCESS)
        {
            result = kernInterface.WriteToKernelMemory(addressInKernel, &kextBuffer[0], static_cast<mach_msg_type_number_t>(kextBuffer.size()));
            
            if (result == KERN_SUCCESS)
            {
                injectedAddress = addressInKernel;
                success = true;
            }
        }
    }
    
    return success;
}

bool MicroLinker::HookSystemCalls(sysent_t* pSysent)
{
    bool success = false;
    kResult result = KERN_FAILURE;
    
    if (injectedAddress != 0)
    {
        KernelInterface& kernInterface = kernel.GetKernelInterface();
    
        for (std::vector<std::pair<std::string, std::string> >::iterator it = syscallsToHook.begin(); it != syscallsToHook.end(); ++it)
        {
            // Get the address of the hook
            tAddress addressOfHook = injectedAddress + kextSymbolMap[it->second];

            unsigned char buffer[512];
            
            kernInterface.ReadFromKernelMemory(buffer, addressOfHook, 512);
                        
            // Get the address of the entry for the system call to be hooked
            tAddress syscallAddressInTable = addressOfShadowTable + (sizeof(sysent_t) * sysentSymToOffset.at(it->first));
            
            // Write the address of the hook to the address of the entry of the system call
            // to be hooked
            result = kernInterface.WriteToKernelMemory(syscallAddressInTable, reinterpret_cast<unsigned char*>(&addressOfHook), sizeof(tAddress));
            
            if (result != KERN_SUCCESS)
            {
                break;
            }
        }
        
        if (result == KERN_SUCCESS)
        {
            success = true;
        }
    }
    
    return success;
}

bool MicroLinker::ParseKernelSymbols()
{
    bool success = false;
    uint64_t kaslrSlide = kernel.GetKaslrSlide();
    uint8_t* pBuffer = &kernelBuffer[0];
    uint8_t* tempAddress = nullptr;
    uint32_t nLoadCommands = 0;
    
    uint32_t* pMagicNumber = reinterpret_cast<uint32_t*>(pBuffer);
    if (pMagicNumber != nullptr && *pMagicNumber == MH_MAGIC_64)
    {
        struct mach_header_64* machHeader = reinterpret_cast<struct mach_header_64*>(pBuffer);
        nLoadCommands = machHeader->ncmds;
        
        // Making the assumption that load commands are right after the header
        tempAddress = reinterpret_cast<uint8_t*>(pBuffer + sizeof(struct mach_header_64));
        
        for (uint32_t i = 0; i < nLoadCommands; ++i)
        {
            struct load_command* loadCommand = reinterpret_cast<struct load_command*>(tempAddress);
            
            switch (loadCommand->cmd)
            {
                case LC_SYMTAB:
                {
                    struct symtab_command* pCommand = reinterpret_cast<struct symtab_command*>(loadCommand);
                    uint8_t* stroff = pBuffer + pCommand->stroff;
                    struct nlist_64* pNlists = reinterpret_cast<struct nlist_64*>(pBuffer + pCommand->symoff);
                    
                    for (uint32_t j = 0; j < pCommand->nsyms; ++j)
                    {
                        uint32_t offset = pNlists[j].n_un.n_strx;
                        std::string symbolName(reinterpret_cast<char*>(&stroff[offset]));
                        
                        kernelSymbolMap.insert(std::make_pair(symbolName, pNlists[j].n_value + kaslrSlide));
                    }
                    
                    success = true;
                    break;
                }
                    
                default:
                    break;
            }
            
            // Advance to the next command
            tempAddress += loadCommand->cmdsize;
        }
        
    }
    
    return success;
}

bool MicroLinker::ParseKextSymbols()
{
    bool success = false;
    
    uint8_t* tempAddress = nullptr;
    uint32_t nLoadCmds = 0;
    uint32_t* pMagicNumber = reinterpret_cast<uint32_t*>(&kextBuffer[0]);
    
    if (pMagicNumber != nullptr && *pMagicNumber == MH_MAGIC_64)
    {
        struct mach_header_64* machHeader = reinterpret_cast<struct mach_header_64*>(&kextBuffer[0]);
        nLoadCmds = machHeader->ncmds;
        
        // Get the first load command
        tempAddress = reinterpret_cast<uint8_t*>(&kextBuffer[0] + sizeof(struct mach_header_64));
        
        if (tempAddress != nullptr)
        {
            for (uint32_t i = 0; i < nLoadCmds; i++)
            {
                struct load_command* loadCommand = reinterpret_cast<struct load_command*>(tempAddress);
                
                switch (loadCommand->cmd)
                {
                    case LC_DYSYMTAB:
                    {
                        struct dysymtab_command* pCommand = reinterpret_cast<struct dysymtab_command*>(loadCommand);
                        
                        // Get the pointer to the table of external relocations
                        struct relocation_info* pExternalRelocations = reinterpret_cast<struct relocation_info*>(&kextBuffer[0] + pCommand->extreloff);
                        
                        // Get the pointer to the table of local relocations
                        struct relocation_info* pLocalRelocations = reinterpret_cast<struct relocation_info*>(&kextBuffer[0] + pCommand->locreloff);
                        
                        for (int j = 0; j < pCommand->nextrel; ++j)
                        {
                            struct relocation_info relocation = pExternalRelocations[j];
                            
                            externRelocTable.push_back(std::make_pair(static_cast<uint64_t>(relocation.r_symbolnum), static_cast<tAddress>(relocation.r_address)));
                        }
                        
                        for (int j = 0; j < pCommand->nlocrel; ++j)
                        {
                            struct relocation_info relocation = pLocalRelocations[j];
                            
                            localRelocTable.push_back(std::make_pair(static_cast<uint64_t>(relocation.r_symbolnum), static_cast<tAddress>(relocation.r_address)));
                        }
                        
                        break;
                    }
                        
                    case LC_SYMTAB:
                    {
                        struct symtab_command* pCommand = reinterpret_cast<struct symtab_command*>(loadCommand);
                        
                        char* pStringTableOffset =reinterpret_cast<char*> (&kextBuffer[0] + pCommand->stroff);
                        
                        // Get the pointer to the symbol table
                        struct nlist_64* pNLists = reinterpret_cast<struct nlist_64*>(&kextBuffer[0] + pCommand->symoff);
                        
                        for (int j = 0; j < pCommand->nsyms; ++j)
                        {
                            // Get the offset into the string table for this symbol
                            uint32_t index = pNLists[j].n_un.n_strx;
                            
                            std::string symbolName(&pStringTableOffset[index]);
                            kextSymbolNumToString.insert(std::make_pair(j, symbolName));
                            kextSymbolMap.insert(std::make_pair(symbolName, pNLists[j].n_value));
                        }
                        
                        break;
                    }
                    default:
                        break;
                        
                }
                
                // Move to the next command
                tempAddress += loadCommand->cmdsize;
            }
            
            success = true;
        }
    }
    
    return success;
}