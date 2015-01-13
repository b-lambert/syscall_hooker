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
 * SysentMap.cpp
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

#include "includes/KernelDefs.h"

const std::map<std::string, uint64_t> sysentSymToOffset = { {"_exit", 1}, {"_fork", 2}, {"_read", 3}, {"_write", 4}, {"_open", 5}, {"_close", 6}, {"_wait4", 7}, {"_link", 9}, {"_unlink", 10}, {"_chdir", 12}, {"_fchdir", 13}, {"_mknod", 14}, {"_chmod", 15}, {"_chown", 16}, {"_getfsstat", 18}, {"_getpid", 20}, {"_setuid", 23}, {"_getuid", 24}, {"_geteuid", 25}, {"_ptrace", 26}, {"_recvmsg", 27}, {"_sendmsg", 28}, {"_recvfrom", 29}, {"_accept", 30}, {"_getpeername", 31}, {"_getsockname", 32}, {"_access", 33}, {"_chflags", 34}, {"_fchflags", 35}, {"_sync", 36}, {"_kill", 37}, {"_getppid", 39}, {"_dup", 41}, {"_pipe", 42}, {"_getegid", 43}, {"_sigaction", 46}, {"_getgid", 47}, {"_sigprocmask", 48}, {"_getlogin", 49}, {"_setlogin", 50}, {"_acct", 51}, {"_sigpending", 52}, {"_sigaltstack", 53}, {"_ioctl", 54}, {"_reboot", 55}, {"_revoke", 56}, {"_symlink", 57}, {"_readlink", 58}, {"_execve", 59}, {"_umask", 60}, {"_chroot", 61}, {"_msync", 65}, {"_vfork", 66}, {"_munmap", 73}, {"_mprotect", 74}, {"_madvise", 75}, {"_mincore", 78}, {"_getgroups", 79}, {"_setgroups", 80}, {"_getpgrp", 81}, {"_setpgid", 82}, {"_setitimer", 83}, {"_swapon", 85}, {"_getitimer", 86}, {"_getdtablesize", 89}, {"_dup2", 90}, {"_fcntl", 92}, {"_select", 93}, {"_fsync", 95}, {"_setpriority", 96}, {"_socket", 97}, {"_connect", 98}, {"_getpriority", 100}, {"_bind", 104}, {"_setsockopt", 105}, {"_listen", 106}, {"_sigsuspend", 111}, {"_gettimeofday", 116}, {"_getrusage", 117}, {"_getsockopt", 118}, {"_readv", 120}, {"_writev", 121}, {"_settimeofday", 122}, {"_fchown", 123}, {"_fchmod", 124}, {"_setreuid", 126}, {"_setregid", 127}, {"_rename", 128}, {"_flock", 131}, {"_mkfifo", 132}, {"_sendto", 133}, {"_shutdown", 134}, {"_socketpair", 135}, {"_mkdir", 136}, {"_rmdir", 137}, {"_utimes", 138}, {"_futimes", 139}, {"_adjtime", 140}, {"_gethostuuid", 142}, {"_setsid", 147}, {"_getpgid", 151}, {"_setprivexec", 152}, {"_pread", 153}, {"_pwrite", 154}, {"_nfssvc", 155}, {"_statfs", 157}, {"_fstatfs", 158}, {"_unmount", 159}, {"_getfh", 161}, {"_quotactl", 165}, {"_mount", 167}, {"_csops", 169}, {"_csops_audittoken", 170}, {"_waitid", 173}, {"_kdebug_trace", 180}, {"_setgid", 181}, {"_setegid", 182}, {"_seteuid", 183}, {"_sigreturn", 184}, {"_chud", 185}, {"_fdatasync", 187}, {"_stat", 188}, {"_fstat", 189}, {"_lstat", 190}, {"_pathconf", 191}, {"_fpathconf", 192}, {"_getrlimit", 194}, {"_setrlimit", 195}, {"_getdirentries", 196}, {"_mmap", 197}, {"_lseek", 199}, {"_truncate", 200}, {"_ftruncate", 201}, {"___sysctl", 202}, {"_mlock", 203}, {"_munlock", 204}, {"_undelete", 205}, {"_open_dprotected_np", 216}, {"_getattrlist", 220}, {"_setattrlist", 221}, {"_getdirentriesattr", 222}, {"_exchangedata", 223}, {"_searchfs", 225}, {"_delete", 226}, {"_copyfile", 227}, {"_fgetattrlist", 228}, {"_fsetattrlist", 229}, {"_poll", 230}, {"_watchevent", 231}, {"_waitevent", 232}, {"_modwatch", 233}, {"_getxattr", 234}, {"_fgetxattr", 235}, {"_setxattr", 236}, {"_fsetxattr", 237}, {"_removexattr", 238}, {"_fremovexattr", 239}, {"_listxattr", 240}, {"_flistxattr", 241}, {"_fsctl", 242}, {"_initgroups", 243}, {"_posix_spawn", 244}, {"_ffsctl", 245}, {"_nfsclnt", 247}, {"_fhopen", 248}, {"_minherit", 250}, {"_semsys", 251}, {"_msgsys", 252}, {"_shmsys", 253}, {"_semctl", 254}, {"_semget", 255}, {"_semop", 256}, {"_msgctl", 258}, {"_msgget", 259}, {"_msgsnd", 260}, {"_msgrcv", 261}, {"_shmat", 262}, {"_shmctl", 263}, {"_shmdt", 264}, {"_shmget", 265}, {"_shm_open", 266}, {"_shm_unlink", 267}, {"_sem_open", 268}, {"_sem_close", 269}, {"_sem_unlink", 270}, {"_sem_wait", 271}, {"_sem_trywait", 272}, {"_sem_post", 273}, {"_sem_getvalue", 274}, {"_sem_init", 275}, {"_sem_destroy", 276}, {"_open_extended", 277}, {"_umask_extended", 278}, {"_stat_extended", 279}, {"_lstat_extended", 280}, {"_fstat_extended", 281}, {"_chmod_extended", 282}, {"_fchmod_extended", 283}, {"_access_extended", 284}, {"_settid", 285}, {"_gettid", 286}, {"_setsgroups", 287}, {"_getsgroups", 288}, {"_setwgroups", 289}, {"_getwgroups", 290}, {"_mkfifo_extended", 291}, {"_mkdir_extended", 292}, {"_identitysvc", 293}, {"_shared_region_check_np", 294}, {"_vm_pressure_monitor", 296}, {"_psynch_rw_longrdlock", 297}, {"_psynch_rw_yieldwrlock", 298}, {"_psynch_rw_downgrade", 299}, {"_psynch_rw_upgrade", 300}, {"_psynch_mutexwait", 301}, {"_psynch_mutexdrop", 302}, {"_psynch_cvbroad", 303}, {"_psynch_cvsignal", 304}, {"_psynch_cvwait", 305}, {"_psynch_rw_rdlock", 306}, {"_psynch_rw_wrlock", 307}, {"_psynch_rw_unlock", 308}, {"_psynch_rw_unlock2", 309}, {"_getsid", 310}, {"_settid_with_pid", 311}, {"_psynch_cvclrprepost", 312}, {"_aio_fsync", 313}, {"_aio_return", 314}, {"_aio_suspend", 315}, {"_aio_cancel", 316}, {"_aio_error", 317}, {"_aio_read", 318}, {"_aio_write", 319}, {"_lio_listio", 320}, {"_iopolicysys", 322}, {"_process_policy", 323}, {"_mlockall", 324}, {"_munlockall", 325}, {"_issetugid", 327}, {"___pthread_kill", 328}, {"___pthread_sigmask", 329}, {"___sigwait", 330}, {"___disable_threadsignal", 331}, {"___pthread_markcancel", 332}, {"___pthread_canceled", 333}, {"___semwait_signal", 334}, {"_proc_info", 336}, {"_sendfile", 337}, {"_stat64", 338}, {"_fstat64", 339}, {"_lstat64", 340}, {"_stat64_extended", 341}, {"_lstat64_extended", 342}, {"_fstat64_extended", 343}, {"_getdirentries64", 344}, {"_statfs64", 345}, {"_fstatfs64", 346}, {"_getfsstat64", 347}, {"___pthread_chdir", 348}, {"___pthread_fchdir", 349}, {"_audit", 350}, {"_auditon", 351}, {"_getauid", 353}, {"_setauid", 354}, {"_getaudit_addr", 357}, {"_setaudit_addr", 358}, {"_auditctl", 359}, {"_bsdthread_create", 360}, {"_bsdthread_terminate", 361}, {"_kqueue", 362}, {"_kevent", 363}, {"_lchown", 364}, {"_stack_snapshot", 365}, {"_bsdthread_register", 366}, {"_workq_open", 367}, {"_workq_kernreturn", 368}, {"_kevent64", 369}, {"___old_semwait_signal", 370}, {"___old_semwait_signal_nocancel", 371}, {"_thread_selfi", 372}, {"_ledger", 373}, {"___mac_execve", 380}, {"___mac_syscall", 381}, {"___mac_get_file", 382}, {"___mac_set_file", 383}, {"___mac_get_link", 384}, {"___mac_set_link", 385}, {"___mac_get_proc", 386}, {"___mac_set_proc", 387}, {"___mac_get_fd", 388}, {"___mac_set_fd", 389}, {"___mac_get_pid", 390}, {"___mac_get_lcid", 391}, {"___mac_get_lctx", 392}, {"___mac_set_lctx", 393}, {"_setlcid", 394}, {"_getlcid", 395}, {"_read_nocancel", 396}, {"_write_nocancel", 397}, {"_open_nocancel", 398}, {"_close_nocancel", 399}, {"_wait4_nocancel", 400}, {"_recvmsg_nocancel", 401}, {"_sendmsg_nocancel", 402}, {"_recvfrom_nocancel", 403}, {"_accept_nocancel", 404}, {"_msync_nocancel", 405}, {"_fcntl_nocancel", 406}, {"_select_nocancel", 407}, {"_fsync_nocancel", 408}, {"_connect_nocancel", 409}, {"_sigsuspend_nocancel", 410}, {"_readv_nocancel", 411}, {"_writev_nocancel", 412}, {"_sendto_nocancel", 413}, {"_pread_nocancel", 414}, {"_pwrite_nocancel", 415}, {"_waitid_nocancel", 416}, {"_poll_nocancel", 417}, {"_msgsnd_nocancel", 418}, {"_msgrcv_nocancel", 419}, {"_sem_wait_nocancel", 420}, {"_aio_suspend_nocancel", 421}, {"___sigwait_nocancel", 422}, {"___semwait_signal_nocancel", 423}, {"___mac_mount", 424}, {"___mac_get_mount", 425}, {"___mac_getfsstat", 426}, {"_fsgetpath", 427}, {"_audit_session_self", 428}, {"_audit_session_join", 429}, {"_fileport_makeport", 430}, {"_fileport_makefd", 431}, {"_audit_session_port", 432}, {"_pid_suspend", 433}, {"_pid_resume", 434}, {"_shared_region_map_and_slide_np", 438}, {"_kas_info", 439}, {"_memorystatus_control", 440}, {"_guarded_open_np", 441}, {"_guarded_close_np", 442}, {"_guarded_kqueue_np", 443}, {"_change_fdguard_np", 444}, {"_proc_rlimit_control", 446}, {"_connectx", 447}, {"_disconnectx", 448}, {"_peeloff", 449}, {"_socket_delegate", 450}, {"_telemetry", 451}, {"_proc_uuid_policy", 452}, {"_memorystatus_get_level", 453}, {"_system_override", 454}, {"_vfs_purge", 455} };