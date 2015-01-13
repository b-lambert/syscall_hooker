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
 * KernelInfo.cpp
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

#include <cstdlib>
#include <string>
#include <sstream>
#include <sys/sysctl.h>
#include <sys/syscall.h>

#include "includes/KernelInfo.h"

KernelInfo::KernelInfo()
{
    
}

KernelInfo::~KernelInfo()
{
    
}

uint64_t KernelInfo::GetKernelBitness()
{
    size_t size = 0;
    uint64_t result = 0;
    
    std::string name = "hw.machine";
    
    // Get the size needed to store the string
    int err = sysctlbyname(name.c_str(), nullptr, &size, nullptr, 0);
    
    if (err == 0)
    {
        // allocate
        char* hwMachine = (char*)malloc(size); // possibly unsafe?
        
        if (hwMachine != nullptr)
        {
            // Now get the string
            err = sysctlbyname(name.c_str(), hwMachine, &size, nullptr, 0);
            
            if (err == 0)
            {
                std::string arch = hwMachine;
                if (arch.compare("i386") == 0)
                {
                    result = 32;
                }
                
                if (arch.compare("x86_64") == 0)
                {
                    result = 64;
                }
            }
        }
        
        // C standard, 7.20.3.2/2 from ISO-IEC 9899: if pointer is null, no action occurs
        free (hwMachine);
        hwMachine = nullptr;
    }
    
    return result;
}

int KernelInfo::GetKernelVersion()
{
    int result = 0;
    
    size_t size = 0;
    std::string osRelease = "kern.osrelease";
    
    int err = sysctlbyname(osRelease.c_str(), nullptr, &size, nullptr, 0);
    
    if (err == 0)
    {
        char* osString = (char*)malloc(size); // possibly unsafe?
        
        if (osString != nullptr)
        {
            err = sysctlbyname(osRelease.c_str(), osString, &size, nullptr, 0);
            
            if (err == 0)
            {
                std::string osVersion = osString;
                std::string majorVersion = osVersion.substr(0, 2);
                std::istringstream converter(majorVersion);
                
                converter >> result;
                
                if (converter.fail() == true)
                {
                    result = 0;
                }
            }
        }
        
        // C standard, 7.20.3.2/2 from ISO-IEC 9899: if pointer is null, no action occurs
        free(osString);
    }
    
    return result;
}

tAddress KernelInfo::GetIDTAddress()
{
    // Taken from fG!'s CheckIDT: https://github.com/gdbinit/checkidt
    // Read about the technique here: http://www.phrack.org/issues.html?issue=59&id=4#article
    
    uint8_t idtr[10];
    uint64_t idt = 0;
    uint64_t bitness = GetKernelBitness();
    
    __asm__ volatile ("sidt %0": "=m" (idtr));
    switch (bitness) {
        case 32:
            // 32 bit not supported
            idt = 0;
            break;
        case 64:
            idt = *((uint64_t*) &idtr[2]);
            break;
        default:
            idt = 0;
            break;
    }
    
    return idt;
}

uint64_t KernelInfo::GetKaslrSlide()
{
    // Uses the fG!'s technique for obtaining the KASLR slide
    // https://github.com/gdbinit/kextstat_aslr/tree/master/kextstat_aslr
    
    size_t size = sizeof(size_t);
    uint64_t kaslrSlide = 0;
    uint64_t* pKaslrSlide = &kaslrSlide;
    size_t* pSize = &size;
    
    
    uint64_t syscallnr = SYSCALL_CONSTRUCT_UNIX(SYS_kas_info);
    uint64_t selector = KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR;
    int result = 0;
    __asm__ ("movq %1, %%rdi\n\t"
             "movq %2, %%rsi\n\t"
             "movq %3, %%rdx\n\t"
             "movq %4, %%rax\n\t"
             "syscall"
             : "=a" (result)
             : "r" (selector), "m" (pKaslrSlide), "m" (pSize), "a" (syscallnr)
             : "rdi", "rsi", "rdx", "rax"
             );

    return kaslrSlide;
}
