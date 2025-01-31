
  
   
     
   -  ASSEMBLY_PUBLIC_KEY = // [the value
   - ASSEMBLY_BITNESS = // "64" for an x64 payload, "32" for x86 payload;
   - ASSEMBLY_NAME = // the assembly name
   - ASSEMBLY_VERSION = // the value from `sigcheck.exe -n
   - PAYLOAD_ASSEMBLY_PATH = // local path to your created payload
   PAYLOAD_ASSEMBLY_PATH`
   `sn.exe -T PAYLOAD_ASSEMBLY_PATH`
   from](https://learn.microsoft.com/en-us/dotnet/framework/tools/sn-exe-strong-name-tool)
 3. Compile **DCOMUploadExec** and use it
# DCOM Upload & Execute
## Basic Usage
## Credits
## Limitations
## Payload Configuration
* [Eliran Nissan](https://x.com/eliran_nissan)**PayloadConfig.h** is used to configure the payload **DCOMUploadExec** will use.
-  **AssemblyPayload** - A .NET DLL that pops a MessageBox. It is the default payload **DCOMUploadExec** uses
-  **DCOMUploadExec** - A C++ project which hosts the lateral movement attack code
- Execute an export from the DLL
- Load the DLL to a remote MSIEXEC.exe process
- Receive a result from the export
- Upload the default payload DLL, **AssemblyPayload**, to the remote PC
1. The attacker and victim machines must be in the same domain or forest.
1. create a [strong-named](https://learn.microsoft.com/en-us/dotnet/standard/assembly/strong-named) .NET assembly that exports a function named *InitializeEmbeddedUI* - this will be the function that **DCOMUploadExec** will eventually execute on the remote target
2. Fill your custom payload's details in **PayloadConfig.h**:
2. The attacker and victim machines must be consistent with the [DCOM Hardening patch](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c) - either with the patch applied on both systems or absent on both.
3. The assembly payload must have a [strong-name](https://learn.microsoft.com/en-us/dotnet/standard/assembly/strong-named).
4. The assembly payload must be either x86 or x64 (Can't be AnyCPU).
Compile the solution
DCOM Lateral movement POC abusing the IMsiServer interface
DCOMUploadExec.exe will:
In order to use a custom payload:
It is defaulted to the output of **AssemblyPayload**.
The payload must be a [strong-named](https://learn.microsoft.com/en-us/dotnet/standard/assembly/strong-named) .NET assembly
The solution contains 2 projects
`Local Usage: DCOMUploadExec.exe LOCALHOST (Run this as administrator)`
`Usage: DCOMUploadExec.exe [domain]\[user]:[password]@[address]`
https://www.deepinstinct.com/blog/forget-psexec-dcom-upload-execute-backdoor
