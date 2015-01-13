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
 * KernelInterface.h
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

#ifndef KERNELINTERFACE_H
#define KERNELINTERFACE_H

#include <mach/mach_vm.h>
#include "KernelDefs.h"

static const uint64_t MAX_COPY_SIZE = 0x800; // Misleading title, actually an arbitrary value
static const uint64_t SKIP_OFFSET_MAVERICKS = 0xF3494; // Some reason reading this offset from the address of int80 causes kernel panic, need to avoid and investigate further as to why

class KernelInterface
{
    
public:
    KernelInterface(mach_port_t& kernelPort, tAddress idtAddress, uint64_t inBitness);
    ~KernelInterface();
    
    kResult ReadFromKernelMemory(unsigned char* pBuffer,
                                 mach_vm_address_t kernelAddress,
                                 const size_t amtToRead);
    
    kResult WriteToKernelMemory(mach_vm_address_t kernelAddress,
                                unsigned char* dataToWrite,
                                mach_msg_type_number_t amtToWrite);
    
    kResult AllocateKernelMemory(uint64_t* addressOfMemory,
                                 uint64_t size);
    
    kResult ChangeKernelMemoryProtections(mach_vm_address_t kernelAddress,
                                          mach_vm_size_t size,
                                          boolean_t setMax = false,
                                          vm_prot_t newProtections = VM_PROT_ALL);

    bool     IsReady() { return isInGoodState; }
    tAddress GetInt80Address() { return int80Address; }
    
    
private:
    
    tAddress GetInt80AddressFromKernel();
    
    mach_port_t& kernelPort;
    tAddress     idtAddress;
    uint64_t     bitness;
    tAddress     int80Address;
    bool         isInGoodState;
    
    // Hide disallowed interfaces
    KernelInterface();
    KernelInterface& operator=(const KernelInterface&);
    KernelInterface(const KernelInterface&);
    
};

#endif
