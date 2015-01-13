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
 * SyscallHooker.h
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

#ifndef SYSCALLHOOKER_H
#define SYSCALLHOOKER_H

#pragma GCC visibility push(default)

#include <vector>
#include <mach/mach_vm.h>

#include "Kernel.h"
#include "MicroLinker.h"

static const std::string MACH_KERNEL_LOCATION_MAVERICKS = "/mach_kernel";

class SyscallHooker
{
    
public:
    SyscallHooker(std::string fileName);
    ~SyscallHooker();
    
    bool HookEmUp();
    bool AddSysCallHook(std::string systemCallName, std::string hookName);
    bool RestoreSysCall(std::string systemCallName);
    
private:

    std::pair<tAddress, uint64_t> FindDataSection();
    bool                          FindSysent();
    bool                          InstallShadowTable();
    
    std::vector<std::pair<std::string, std::string> > syscallsToHook;
  
    Kernel                        machKernel;
    MicroLinker*                  pMicroLinker;
    sysent_t                      pSysentTable[NSYSENT];
    tAddress                      addressOfShadowTable;
    std::pair<tAddress, uint64_t> dataSection;
    bool                          isInGoodState;
    std::vector<uint8_t>          fileBuffer;
    std::vector<uint8_t>          kernelBuffer;
    
    SyscallHooker& operator=(const SyscallHooker&);
    SyscallHooker(const SyscallHooker&);
    
};

#pragma GCC visibility pop
#endif
