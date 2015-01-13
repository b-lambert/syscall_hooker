Description
==============
syscall_hooker is a library for hooking system calls globally on OS X 10.9.5. It operates by injecting a kext directly into the kernel and fixes up the relocations before swapping the sysent table. 

* 10.10 support is being worked on
* You need to create your own code signing certificate for the kext (Or use an existing one)
* Needs r00tz

Not For The Faint of Heart
==============
Hooking system calls and injecting kexts will almost certainly result in kernel panic unless you know what you're doing. This project is certainly not bug free and contributions are welcome. That being said, when the doo doo hits the fan, it's your problem, not mine. If you find a bug, please file it.

Version History
==============
syscall_hooker 0.1 Jan 12 2015
