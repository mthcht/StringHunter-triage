
# Invoke-RunAsWithCert
## Description
## Usage
A PowerShell script to perform PKINIT authentication with the Windows API from a non domain-joined machine.
As `KerbCheckKdcCertificate` is not exported by `kerberos.dll`, symbols need to be retrieved.
For a more detailed explanation, see the associated [blogpost](https://www.synacktiv.com/publications/understanding-and-evading-microsoft-defender-for-identity-pkinit-detection).
For the symbols to be automatically retrieved by this cmdlet, the environment variable 
If the symbols are not already on disk, an Internet connection is needed to download them.
In patch mode (`-PatchLsass`), the `KerbCheckKdcCertificate` function in LSASS will be patched.
In registry mode (the default), administrator privileges are needed to set the relevant
It is meant to be run on a non domain-joined VM. The cmdlet has two modes: one that sets
PS > Invoke-RunAsWithCert user.pfx -Domain CORP.LOCAL
The Windows SDK is also needed to download the symbols. By default, the script will
This cmdlet creates a new logon session with the specified certificate via PKINIT.
`_NT_SYMBOL_PATH` needs to be defined (e.g. `SRV*c:\symbols*https://msdl.microsoft.com/download/symbols`).
```
but will bypass any client-side check related to the KDC certificate.
bypassed with the registry keys), the patch method can be tried instead. It is less elegant
is not joined to the domain.
look in `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64` to find the DLLs it
needs (`dbghelp.dll` and `symsrv.dll`).
privileges are not required. Moreover, the CA certificate must be added to the list of
registry keys (and restore them at the end). If the keys are already set, administrator
registry keys and one that patches LSASS memory to bypass client-side checks related
to the domain controller's certificate. These checks fail when running on a machine that
trusted certification authorities. If this method fails (e.g. because of a check that is not
