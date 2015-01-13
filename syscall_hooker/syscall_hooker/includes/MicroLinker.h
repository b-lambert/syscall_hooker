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
 * MicroLinker.h
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

#ifndef MICROLINKER_H
#define MICROLINKER_H

#include <vector>
#include "Kernel.h"

class MicroLinker
{
public:
    
    MicroLinker(std::vector<uint8_t>& kextBuffer, std::vector<uint8_t>& kernelBuffer, std::vector<std::pair<std::string, std::string> >& syscallsToHook, Kernel& kernel, tAddress addressOfShadowTable);
    ~MicroLinker();
    
    bool InjectAndHook(sysent_t* pSysent);
    bool RestoreHook(std::string syscall);
    
private:
    
    bool ParseKernelSymbols();
    bool ParseKextSymbols();
    bool InjectKext();
    bool HookSystemCalls(sysent_t* pSysent);
    bool FixUpLocalRelocations();
    bool FixUpExternalReolcations();

    Kernel&               kernel;
    tAddress              addressOfShadowTable;
    tAddress              injectedAddress;
    std::vector<uint8_t>& kernelBuffer;
    std::map<std::string, tAddress> kernelSymbolMap;
    
    // Kext related symbol information and data
    std::vector<uint8_t>&           kextBuffer;
    std::map<std::string, tAddress> kextSymbolMap;
    std::map<uint64_t, std::string> kextSymbolNumToString;
    std::vector<std::pair<uint64_t, tAddress> > externRelocTable;
    std::vector<std::pair<uint64_t, tAddress> > localRelocTable;
    
    std::vector<std::pair<std::string, std::string> >& syscallsToHook;
};

#endif
