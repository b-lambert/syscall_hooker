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
 * KernelDefs.h
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

#ifndef KERNELDEFS_H
#define KERNELDEFS_H

#include <mach/mach_vm.h>
#include <map>
#include <string>

// 16 bytes IDT descriptor, used for 32 and 64 bits kernels (64 bit capable cpus!)
struct descriptor_idt
{
    uint16_t offset_low;
    uint16_t seg_selector;
    uint8_t reserved;
    uint8_t flag;
    uint16_t offset_middle;
    uint32_t offset_high;
    uint32_t reserved2;
};

// Sysent table format used by Mavericks and higher
struct sysent {
    uint64_t    *sy_call;
    uint64_t    *sy_arg_munge32;
    uint64_t    *sy_arg_munge64;
    int32_t     sy_return_type;
    int16_t     sy_narg;
    uint16_t    sy_arg_bytes;
};

static const int MAVERICKS = 13;
static const int NSYSENT = 456;
static const int GOT_OFFSET_MAVERICKS = 0xF8;

extern const std::map<std::string, uint64_t> sysentSymToOffset;

typedef kern_return_t kResult;
typedef uint64_t tAddress;
typedef struct sysent sysent_t;



#endif
