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
 * SyscallHooker.cpp
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

#include "includes/SyscallHooker.h"
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <mach-o/loader.h>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <vector>
#include <iterator>

SyscallHooker::SyscallHooker(std::string fileName)
: isInGoodState(false)
, machKernel()
, dataSection(FindDataSection())
, addressOfShadowTable(0)
, pMicroLinker(nullptr)
{
    std::ifstream fileInputStream(fileName, std::ios::binary);
    std::ifstream kernelFileInputStream;
    
    if (machKernel.GetMajorVersion() == MAVERICKS)
    {
        kernelFileInputStream = std::ifstream(MACH_KERNEL_LOCATION_MAVERICKS, std::ios::binary);
    }
    
    if (fileInputStream.good() == true && kernelFileInputStream.good() == true)
    {
        // Copy into memory the kext that contains the hooks and the mach_kernel file
        kernelBuffer = std::vector<uint8_t>((std::istreambuf_iterator<char>(kernelFileInputStream)),
                                            std::istreambuf_iterator<char>());
    
        fileBuffer = std::vector<uint8_t>((std::istreambuf_iterator<char>(fileInputStream)),
                                    std::istreambuf_iterator<char>());
    }
    
    if (machKernel.IsReady() == true &&
        FindSysent() == true &&
        fileBuffer.size() > 0 &&
        kernelBuffer.size() > 0)
    {
        isInGoodState = true;
    }
}

SyscallHooker::~SyscallHooker()
{
    if (pMicroLinker != nullptr)
    {
        delete pMicroLinker;
        pMicroLinker = nullptr;
    }
}

bool SyscallHooker::HookEmUp()
{
    bool success = false;
    
    success = InstallShadowTable();
    
    if (success == true && addressOfShadowTable != 0 && isInGoodState == true)
    {
        if (pMicroLinker == nullptr)
        {
            pMicroLinker = new MicroLinker(fileBuffer, kernelBuffer, syscallsToHook, machKernel, addressOfShadowTable);
        }
  
        if (pMicroLinker != nullptr)
        {
            success = pMicroLinker->InjectAndHook(pSysentTable);
        }
    }
    
    return success;
}

bool SyscallHooker::InstallShadowTable()
{
    bool success = false;
    kResult result = KERN_FAILURE;
    
    if (isInGoodState == true)
    {
        isInGoodState = false;
        KernelInterface& kernInterface = machKernel.GetKernelInterface();
        
        // Allocate space in kernel space for shadow sysent table
        result = kernInterface.AllocateKernelMemory(&addressOfShadowTable, sizeof(sysent_t) * NSYSENT);
        
        if (result == KERN_SUCCESS && addressOfShadowTable != 0)
        {
            // Write the sysent table that was read into newly allocated kernel space
            result = kernInterface.WriteToKernelMemory(addressOfShadowTable, reinterpret_cast<unsigned char*>(pSysentTable), sizeof(sysent_t) * NSYSENT);
                        
            if (result == KERN_SUCCESS)
            {
                // Overwrite the __got entry that points to the original sysent table
                // to point to our shadow table. Dtrace_init will still use the original but
                // we only care about _unix_syscall and _unix_syscall_64
                result = kernInterface.WriteToKernelMemory(dataSection.first + GOT_OFFSET_MAVERICKS, reinterpret_cast<unsigned char*>(&addressOfShadowTable), sizeof(tAddress));
                
                if (result == KERN_SUCCESS)
                {
                    success = true;
                    isInGoodState = true;
                }
            }
        }
    }
    
    return success;
}

bool SyscallHooker::AddSysCallHook(std::string systemCallName, std::string hookName)
{
    bool success = false;
    
    if (isInGoodState == true)
    {
        syscallsToHook.push_back(std::make_pair(systemCallName, hookName));
        success = true;
    }
    
    return success;
}

bool SyscallHooker::RestoreSysCall(std::string systemCallName)
{
    bool success = false;
    
    if (isInGoodState == true && pMicroLinker != nullptr)
    {
        success = pMicroLinker->RestoreHook(systemCallName);
    }
    
    return success;
}

// Based off of fG!'s bruteforcesysent https://github.com/gdbinit/bruteforcesysent
bool SyscallHooker::FindSysent()
{
    bool             success            = false;
    kResult          result             = KERN_FAILURE;
    KernelInterface& kernInterface      = machKernel.GetKernelInterface();
    tAddress         dataSectionAddress = dataSection.first;
    uint64_t         dataSectionSize    = dataSection.second;
    uint8_t*         pDataSection       = reinterpret_cast<uint8_t*>(malloc(dataSectionSize));
    
    if (pDataSection != nullptr)
    {
        // Copy over the entire data section
        result = kernInterface.ReadFromKernelMemory(pDataSection, dataSectionAddress, dataSectionSize);

        if (result == KERN_SUCCESS)
        {
            if (machKernel.GetMajorVersion() >= MAVERICKS)
            {
                for (uint64_t i = 0; i < dataSectionSize; ++i)
                {
                    sysent_t* table = reinterpret_cast<struct sysent*>(&pDataSection[i]);
                    if(table[SYS_exit].sy_narg      == 1 &&
                       table[SYS_fork].sy_narg      == 0 &&
                       table[SYS_read].sy_narg      == 3 &&
                       table[SYS_setuid].sy_narg    == 1 &&
                       table[SYS_wait4].sy_narg     == 4 &&
                       table[SYS_ptrace].sy_narg    == 4 &&
                       table[SYS_getxattr].sy_narg  == 6 &&
                       table[SYS_listxattr].sy_narg == 4 &&
                       table[SYS_recvmsg].sy_narg   == 3)
                    {
                        // Copy over the entire sysent table
                        memcpy(pSysentTable, table, sizeof(sysent_t) * NSYSENT);
                        success = true;
                        break;
                    }
                }
                
            }
        }
    }
    
    free(pDataSection);
    
    return success;
}

std::pair<tAddress, uint64_t> SyscallHooker::FindDataSection()
{
    std::pair<tAddress, uint64_t> tempDataSection;
    dataSection.first = 0;
    dataSection.second = 0;
    
    kResult          result = KERN_FAILURE;
    uint8_t          buffer[MAX_COPY_SIZE];
    KernelInterface& kernInterface = machKernel.GetKernelInterface();
    
    result = kernInterface.ReadFromKernelMemory(buffer, machKernel.GetKernelBase(), MAX_COPY_SIZE);
    if (result == KERN_SUCCESS)
    {
        uint8_t* tempAddress = nullptr;
        uint32_t nLoadCmds = 0;
        uint32_t* pMagicNumber = reinterpret_cast<uint32_t*>(buffer);
        
        if (pMagicNumber != nullptr && *pMagicNumber == MH_MAGIC_64) // only 64 bit support
        {
            struct mach_header_64* machHeader = reinterpret_cast<struct mach_header_64*>(buffer);
            nLoadCmds = machHeader->ncmds;
            
            // First load command address
            tempAddress = reinterpret_cast<uint8_t*>(buffer + sizeof(struct mach_header_64));
            
            // Additional check to make sure we don't read out of our buffer as well
            for (uint32_t i = 0; i < nLoadCmds && tempAddress <= (buffer + MAX_COPY_SIZE); ++i)
            {
                struct load_command* loadCommand = reinterpret_cast<struct load_command*>(tempAddress);
                
                switch (loadCommand->cmd)
                {
                    case LC_SEGMENT_64:
                    {
                        struct segment_command_64* segmentCommand = reinterpret_cast<struct segment_command_64*>(loadCommand);
                        
                        std::string segName = segmentCommand->segname;
                        
                        if (segName.find("__DATA") != std::string::npos)
                        {
                            tempDataSection.first = segmentCommand->vmaddr;
                            tempDataSection.second = segmentCommand->vmsize;
                        }
                        
                        break;
                    }
                    default:
                        break;
                }
                
                // Advance to the next command
                tempAddress += loadCommand->cmdsize;
                
            }
        }
    }
    
    return tempDataSection;
}
