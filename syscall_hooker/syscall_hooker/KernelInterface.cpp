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
 * KernelInterface.cpp
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

#include <iostream>

#include "includes/KernelInterface.h"
#include "includes/KernelDefs.h"


KernelInterface::KernelInterface(mach_port_t& kernelPort, tAddress idtAddress, uint64_t inBitness)
: kernelPort(kernelPort)
, idtAddress(idtAddress)
, bitness(inBitness)
, int80Address(GetInt80AddressFromKernel())
, isInGoodState(false)
{
    if (kernelPort != 0 &&
        idtAddress != 0 &&
        bitness    != 0 &&
        int80Address != 0)
    {
        isInGoodState = true;
    }

}

KernelInterface::~KernelInterface()
{

}

kResult KernelInterface::ReadFromKernelMemory(unsigned char* buffer, mach_vm_address_t kernelAddress, const size_t amtToRead)
{
    kResult result = KERN_FAILURE;
    
    // Reading the address of int80Address - SKIP_OFFSET_MAVERICKS seems to cause a kernel panic, avoid
    if (int80Address - SKIP_OFFSET_MAVERICKS != kernelAddress)
    {
        // Parameter sanity checks
        if (kernelPort != 0 && buffer != nullptr)
        {
            // Determine the amount of copies to do from kernel space into user space
            uint64_t copiesNeeded = amtToRead / MAX_COPY_SIZE;
            uint64_t leftOverBytes = amtToRead % MAX_COPY_SIZE;
            uint64_t totalAmtRead = 0;
            uint64_t currentAmtRead = 0;
            
            result = KERN_SUCCESS; // Set to KERN_SUCCESS, if no copies are needed, the last remaining bytes will be copied over, otherwise if a read fails in the for loop, this function will return KERN_[ERROR]
            
            for (uint64_t i = 0; i < copiesNeeded && result == KERN_SUCCESS; ++i)
            {
                uint64_t offset = i * MAX_COPY_SIZE;
                
                result = mach_vm_read_overwrite(kernelPort, kernelAddress + offset, MAX_COPY_SIZE, reinterpret_cast<mach_vm_address_t>(buffer + offset), &currentAmtRead);
                
                totalAmtRead += currentAmtRead;
                currentAmtRead = 0; // not really needed but why not
            }
            
            // If the copying went well, copy the left over bytes (if any)
            if (result == KERN_SUCCESS && leftOverBytes != 0)
            {
                result = mach_vm_read_overwrite(kernelPort, kernelAddress + (copiesNeeded * MAX_COPY_SIZE), leftOverBytes, reinterpret_cast<mach_vm_address_t>(buffer + (copiesNeeded * MAX_COPY_SIZE)), &currentAmtRead);
                
                totalAmtRead += currentAmtRead;
            }
                        
            // Validate the amount read
            if (totalAmtRead != amtToRead)
            {
                // Only change the value of result if it's KERN_SUCCESS, otherwise let the
                // error pass through and be returned
                if (result == KERN_SUCCESS)
                {
                    result = KERN_FAILURE;
                }
            }
        }
    }
    
    return result;
}

kResult KernelInterface::WriteToKernelMemory(mach_vm_address_t kernelAddress, unsigned char* dataToWrite, mach_msg_type_number_t amtToWrite)
{
    kResult result = KERN_FAILURE;
    
    // Parameter sanity checks
    if (kernelPort != 0 && kernelAddress != 0 && dataToWrite != nullptr)
    {
        // Determine the amount of copies needed from kernel space into user space
        uint64_t copiesNeeded = amtToWrite / MAX_COPY_SIZE;
        uint64_t leftOverBytes = amtToWrite % MAX_COPY_SIZE;
        uint64_t totalAmtWritten = 0;
        
        result = KERN_SUCCESS; // Set to KERN_SUCCESS, if no copies are needed, the last remaining bytes will be copied over, otherwise if a write fails in the for loop, this function will return KERN_[ERROR]
        
        for (uint64_t i = 0; i < copiesNeeded && result == KERN_SUCCESS; ++i)
        {
            uint64_t offset = i * MAX_COPY_SIZE;
            
            result = mach_vm_write(kernelPort, kernelAddress + offset, reinterpret_cast<vm_offset_t>(dataToWrite + offset), static_cast<mach_msg_type_number_t>(MAX_COPY_SIZE));
            
            totalAmtWritten += MAX_COPY_SIZE;
        }
        
        // If the copying went well, copy the left over bytes (if any)
        if (result == KERN_SUCCESS && leftOverBytes != 0)
        {
            result = mach_vm_write(kernelPort, kernelAddress + (copiesNeeded * MAX_COPY_SIZE), reinterpret_cast<vm_offset_t> (dataToWrite + (copiesNeeded * MAX_COPY_SIZE)), static_cast<mach_msg_type_number_t>(leftOverBytes));
        
            totalAmtWritten += leftOverBytes;
        }
        
        // Validate the amount written to kernel memory
        if (totalAmtWritten != amtToWrite)
        {
            // Only change the value of result if it's KERN_SUCCESS, otherwise let the
            // error pass through and be returned
            if (result == KERN_SUCCESS)
            {
                result = KERN_FAILURE;
            }
        }
        
    }
    
    return result;
}

kResult KernelInterface::AllocateKernelMemory(uint64_t* addressOfMemory, uint64_t size)
{
    kResult result = KERN_FAILURE;
    
    // Parameter sanity checks
    if (kernelPort != 0 && addressOfMemory != nullptr && size != 0)
    {
        result = mach_vm_allocate(kernelPort, addressOfMemory, size, VM_FLAGS_ANYWHERE);
    }
    
    return result;
}

kResult KernelInterface::ChangeKernelMemoryProtections(mach_vm_address_t kernelAddress, mach_vm_size_t size, boolean_t setMax, vm_prot_t newProtections)
{
    kResult result = KERN_FAILURE;
    
    // Parameter sanity checks
    if (kernelPort != 0 && kernelAddress != 0)
    {
        result = mach_vm_protect(kernelPort, kernelAddress, size, setMax, newProtections);
    }
    
    return result;
}

tAddress KernelInterface::GetInt80AddressFromKernel()
{
    tAddress result = 0;
    kResult kernResult = KERN_FAILURE;
    
    // Taken from fG!'s CheckIDT
    
    struct descriptor_idt int80Descriptor;
    
    uint64_t high = 0;
    uint32_t middle = 0;
    
    kernResult = ReadFromKernelMemory(reinterpret_cast<unsigned char*>(&int80Descriptor), idtAddress + sizeof(struct descriptor_idt) * 0x80, sizeof(struct descriptor_idt));
    
    if (kernResult == KERN_SUCCESS)
    {
        if (bitness == 64)
        {
            high = (uint64_t)int80Descriptor.offset_high << 32;
            middle = (uint32_t)int80Descriptor.offset_middle << 16;
            
            result = (uint64_t)(high + middle + int80Descriptor.offset_low);
        }
        else // No support for 32 bit
        {
            result = 0;
        }
    }
    
    return result;
}
