//
//  main.cpp
//  sampleApp
//
//

#include <iostream>

#include "SyscallHooker.h"

int main(int argc, const char * argv[])
{
    
    SyscallHooker hook("sample_kext.kext/Contents/MacOs/sample_kext");
    
    bool success = hook.AddSysCallHook("_setuid", "_setuid_hook");
    hook.AddSysCallHook("_open", "_open_hook");
    if (success == true)
    {
        success = hook.HookEmUp();
        
        std::cout << "successfully hooked setuid and open!" << std::endl;
    }
    else
    {
        std::cout << "Something went wrong :(" << std::endl;
    }
    
    return 0;
}
