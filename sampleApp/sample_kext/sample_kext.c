//
//  sample_kext.c
//  sample_kext
//
//

#include "syscalls.h"

#include <sys/systm.h>
#include <sys/syscall.h>

kern_return_t sample_kext_start(kmod_info_t * ki, void *d);
kern_return_t sample_kext_stop(kmod_info_t *ki, void *d);

kern_return_t sample_kext_start(kmod_info_t * ki, void *d)
{
    return KERN_SUCCESS;
}

kern_return_t sample_kext_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}

int setuid_hook(struct proc* p, struct setuid_args* args, int* retval)
{
    printf("Setuid called by PID: %d, with args: %d\n", proc_pid(p), args->uid);
    return setuid(p, args, retval);
}

int open_hook(struct proc* p, struct open_args* args, int* retval)
{
    char buffer[PATH_MAX];
    size_t done = 0;
    copystr((void*)args->path, buffer, PATH_MAX, &done);
    printf("open called by PID: %d, for file: %s\n", proc_pid(p), buffer);
    return open(p, args, retval);
}