
# blindsight
## Cross-compiling (macOS example)
## Examples
## TODO
## Tested on
## Usage
$ brew install mingw-w64
$ cargo build --release --target x86_64-pc-windows-gnu
$ rustup target add x86_64-pc-windows-gnu
* <https://attack.mitre.org/techniques/T1003/001/>
* <https://github.com/Kudaes/Dumpy>
* <https://github.com/anthemtotheego/CredBandit>
* <https://github.com/fortra/nanodump>
* <https://github.com/joaoviictorti/RustRedOps>
* <https://github.com/w1u0u1/minidump>
* <https://security.humanativaspa.it/an-offensive-rust-encore>
* <https://www.ired.team/offensive-security/credential-access-and-credential-dumping>
* <https://www.synacktiv.com/en/publications/windows-secrets-extraction-a-summary>
* Allow to manually specify LSASS pid to avoid noisy process scans
* Avoid directly opening LSASS handle (e.g., via PssCaptureSnapshot)
* Consider better command line handling if minimal is not enough
* Consider dumping to memory using minidump callbacks instead of TxF API
* Implement fileless exfiltration channels (e.g., TFTP, FTP, HTTP...)
* Microsoft Windows 10 (x64)
* Microsoft Windows 11 (ARM64)
* Microsoft Windows 11 (x64)
* Microsoft Windows Server 2016 (x64)
* Microsoft Windows Server 2019 (x64)
* Microsoft Windows Server 2022 (x64)
* Optimize memory usage (simply corrupt "magic bytes" instead of XORing?)
* Use https://github.com/Kudaes/DInvoke_rs or similar for API hooks evasion
* Use litcrypt2 or similar to encrypt strings locally
* https://adepts.of0x.cc/hookson-hootoff/
* https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-3.html
*Note: Do not test on production servers, as accessing LSASS might cause system instability!*
>
> "There's no such things as survival of the fittest.  
> -- Peter Watts, Blindsight (2006)
> All that matters is whether it beats the alternative."
> It doesn't matter whether a solution's optimal.  
> Survival of the most adequate, maybe.  
Blog post:
C:\> .\blindsight.exe
C:\> .\blindsight.exe 29ABE9Hy.log
C:\> .\blindsight.exe [dump | file_to_unscramble.log]
Dump LSASS memory:
Inside an Administrator's PowerShell window:
It uses Transactional NTFS (TxF API) to transparently scramble the memory
Red teaming tool to dump LSASS memory, bypassing basic countermeasures.
See also:
Unscramble memory dump:
[![](https://img.shields.io/badge/mastodon-%40raptor-purple.svg)](https://infosec.exchange/@raptor)
[![](https://img.shields.io/badge/twitter-%400xdea-blue.svg)](https://twitter.com/0xdea)
[![](https://img.shields.io/github/forks/0xdea/blindsight.svg?style=flat&color=green)](https://github.com/0xdea/blindsight)
[![](https://img.shields.io/github/stars/0xdea/blindsight.svg?style=flat&color=yellow)](https://github.com/0xdea/blindsight)
[![](https://img.shields.io/github/watchers/0xdea/blindsight.svg?style=flat&color=red)](https://github.com/0xdea/blindsight)
```
```sh
dump, to avoid triggering AV/EDR/XDR.
