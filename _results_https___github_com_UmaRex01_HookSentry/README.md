
                      /
                0x9DC20:        jmp             0x2005a0
                0x9DC20:        mov             r10, rcx
                0x9DC23:        mov             eax, 0x3a
                0x9DC25:        int3
                0x9DC26:        int3
                0x9DC27:        int3
                Function in memory:
                Function on disk:
        -a, --all: Analyze all active processes
        -d, --disass: Display disassembled code
        -h, --help: Show this message
        -p <PID>, --pid <PID>: Analyze the process with PID <PID>
        -v, --verbose: Enable verbose output
        C:\Windows\SYSTEM32\ntdll.dll contains 86 hooks
        C:\Windows\System32\KERNEL32.DLL contains 8 hooks
        C:\Windows\System32\KERNELBASE.dll contains 45 hooks
        [+] Function ZwWriteVirtualMemory HOOKED!
# HookSentry
## Example
## TODO
## Usage
*** SUMMARY ***
**The tool is only compatible with x64 systems.**
- [ ] Identify jump target
- [ ] Reduce false positives
- [x] Perform full system scan
---
C:\Users\user\Desktop>.\HookSentry.exe -h
C:\Users\user\Desktop>.\HookSentry.exe -v -d
HookSentry is a quick & dirty tool for inspecting system DLLs loaded into processes, looking for functions hooked from AV/EDR.
HookSentry is still under development! Next steps:
In addition to scanning individual processes, HookSentry can perform a full scan of all active processes on the system. It can also be used to check a specific process or even scan itself for any hooks.
It scans for potential hooks in system libraries and provides detailed information about each hook it finds. The tool compares the in-memory image of each DLL with its on-disk version, identifies hooked functions, and prints disassembled code to help analyze the changes.
Options:
Usage: HookSentry.exe [-a|-p <PID>|-v]
V0.3 - 2024 - @Umarex
[*] C:\Program Files\Bitdefender\Bitdefender Security\atcuf\dlls_267396668276705800\atcuf64.dll not a system library. skipped.
[*] C:\Program Files\Bitdefender\Bitdefender Security\bdhkm\dlls_266864023745032704\bdhkm64.dll not a system library. skipped.
[*] Selected current process.
[*] Working on process 1 of 1 with PID: 2120
[*] Working on: C:\Windows\SYSTEM32\VCRUNTIME140.dll
[*] Working on: C:\Windows\SYSTEM32\ntdll.dll
[*] Working on: C:\Windows\System32\ucrtbase.dll
[+] PID: 2120 has 139 hooked functions
[...]
```
```cmd
| |(_)(_)|<_)(/_| | | |\/
|_| _  _ | (~ _  _ _|_ _
