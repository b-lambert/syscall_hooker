//
//  syscalls.h
//  sample_kext
//
//

#ifndef sample_kext_syscalls_h
#define sample_kext_syscalls_h

#include <mach/mach_types.h>
#include <sys/types.h>

#if CONFIG_REQUIRES_U32_MUNGING
#define	PAD_(t)	(sizeof(uint64_t) <= sizeof(t) \
    ? 0 : sizeof(uint64_t) - sizeof(t))
#else
    #define	PAD_(t)	(sizeof(uint32_t) <= sizeof(t) \
    ? 0 : sizeof(uint32_t) - sizeof(t))
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
    #define	PADL_(t)	0
    #define	PADR_(t)	PAD_(t)
#else
    #define	PADL_(t)	PAD_(t)
    #define	PADR_(t)	0
#endif

// To find all the struct arg definitions, look at http://www.opensource.apple.com/source/xnu/xnu-792.13.8/bsd/sys/sysproto.h
// Or you can run makesyscalls.sh on syscalls.master if you download the
// XNU kernel from opensource.apple.com
struct setuid_args {
    char uid_l_[PADL_(uid_t)]; uid_t uid; char uid_r_[PADR_(uid_t)];
};

struct open_args {
    char path_l_[PADL_(user_addr_t)]; user_addr_t path; char path_r_[PADR_(user_addr_t)];
    char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
    char mode_l_[PADL_(int)]; int mode; char mode_r_[PADR_(int)];
};

struct write_args {
    char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
    char cbuf_l_[PADL_(user_addr_t)]; user_addr_t cbuf; char cbuf_r_[PADR_(user_addr_t)];
    char nbyte_l_[PADL_(user_size_t)]; user_size_t nbyte; char nbyte_r_[PADR_(user_size_t)];
};

int setuid(struct proc* p, struct setuid_args* args, int* retval);
int open(struct proc* p, struct open_args* args, int* retval);
int write(struct proc* p, struct write_args* args, int* retval);



#endif
