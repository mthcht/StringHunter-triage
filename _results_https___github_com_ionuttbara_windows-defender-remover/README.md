
    
            - Exploit Guard (something about Exploits)
            - Hypervisor startup (this fixes disablation of Virtualization Based Security, this will auto enable if you use Hyper-V and/or WSL (Windows Subsystem for Linux), WSA (Windows Subsystem for Android))
            - LUA (disables File Virtualization and User Account Control, which will run all apps as administrator priviliges (also fixes old app errors))
            - Tamper Protection (for Windows 11 21H2 or earlier)
            - Windows Smart Control
          - "Services Mitigations" (search on admx.help for more informations, its policy)
          - Spectre and Meltdown Mitigation (for get +30% performance on old Intel CPUs)
        - Pluton Support and Pluton Services Support
        - SecHealthUI (Windows Security UWP App)
        - SmartScreen
        - System Mitigations
        - Windows Security Section from Settings App.
        - support for Windows Security Center including Windows Security Center Service (wscsvc), Windows Security Service (SgrmBroker, Sgrm Drivers) which are needed to run Windows Security App.
        - virtualization support.
        <img alt="Defender Remover" src="https://user-images.githubusercontent.com/79479952/239704528-c017473e-1d2a-4d4a-a215-bf71d137b86a.png">
        <source media="(prefers-color-scheme: dark)" srcset="https://github.com/drunkwinter/windows-defender-remover/assets/38593134/8072a566-5bf0-4f05-9994-808145406bdc">
      - Antivirus Scanning Tasks
      - Antivirus Service
      - Hides Antivirus Protection section from Windows Security App.
      - Shell Associations (Context Menu)
      - Windows Defender Antivirus filter and windows defender rootkit scanner drivers
      - Windows Defender Definition Update List (this will disable updating definitions of Defender because its removed)
      - Windows Defender SpyNet Telemetry
    $PackageFullName = $appx.PackageFullName; 
    $PackageName = $appx.PackageName; $PackageFamilyName = ($appxpackage |where {$_.Name -eq $appx.DisplayName}).PackageFamilyName 
    $next = !1; foreach ($no in $skip) {if ($appx.PackageFullName -like "*$no*") {$next = !0}} ; if ($next) {continue}
    $next = !1; foreach ($no in $skip) {if ($appx.PackageName -like "*$no*") {$next = !0}} ; if ($next) {continue}
    **%location of extracted ISO%\sources\$OEM$\$$\Panther\**
    </picture>
    <picture>
    This script forcily removes following antivirus components:
    This script removes/disables following security components:
    dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 >''
    foreach ($sid in $users) {ni "$store\EndOfLife\$sid\$PackageFullName" -force >''} ; $eol += $PackageFullName
    foreach ($sid in $users) {ni "$store\EndOfLife\$sid\$PackageName" -force >''} ; $eol += $PackageName
    ni "$store\Deprovisioned\$PackageFamilyName" -force >''; $PackageFamilyName  
    ni "$store\Deprovisioned\$appx.PackageFamilyName" -force >''; $PackageFullName
    remove-appxpackage -package $PackageFullName -allusers >''
    remove-appxprovisionedpackage -packagename $PackageName -online -allusers >''
   The path it shown like to
  foreach ($appx in $($appxpackage |where {$_.PackageFullName -like "*$choice*"})) {
  foreach ($appx in $($provisioned |where {$_.PackageName -like "*$choice*"})) {
  }
![cli](https://github.com/drunkwinter/windows-defender-remover/assets/38593134/46007191-0a65-43c2-b451-a993ff90e00e)
# Removal
## Creating an ISO with Windows Defender and Services disabled
## Disable or Remove Windows Defender *Application Guard Policies* (advanced)
### Removing Antivirus Components
### Removing Security Components
#### Removing
$remove_appx = @("SecHealthUI"); $provisioned = get-appxprovisionedpackage -online; $appxpackage = get-appxpackage -allusers; $eol = @()
$store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
$users = @('S-1-5-18'); if (test-path $store) {$users += $((dir $store -ea 0 |where {$_ -like '*S-1-5-21*'}).PSChildName)}
- In Code Integrity Folder
- In EFI Partition
- In WinSxS Folder
- In Windows Folder
1. Download the packed script from [Releases](https://github.com/ionuttbara/windows-defender-remover/releases)
1. Download the source code from [Releases](https://github.com/jbara2002/windows-defender-remover/releases).
1. Mount the ISO and extract it into location.
2. Choose the file **Source Code(.zip)** from last version and download it.
2. Open the **sources** folder and create the **$OEM$** folder. (this is needed to run the DefenderRemover part in OOBE).
2. Run the ".exe" as administrator
3. Follow the instructions displayed
3. Open the **$OEM$** folder and create the folder with **$$** name.
3. Unarchive the file into a folder and run the Script_Run.bat.
4. Open the **$$** folder and create the folder with **Panther** name.
5. Open the **Panther** folder.
6. Download the unnatended.xml file from repo in ISO_Maker folder and put it in Panther folder.
7. Save this as bootable ISO. (for now the script can't do this automaticly, but it will do in next version).
</a>
<a href="https://github.com/ionuttbara/windows-defender-remover">
> A system restore point is recommended before you run the script. (if you don't know what are you doing)
> [!NOTE]
Defender.Remover.exe /r <# or /R #>
Disable with this command and reboot.
Here are the rules:
If the script is not working for you, check if you have the Windows Security Intelligence Update installed. If you do, disable tamper protection, and re-run the script.
If you have any problems when opening an app (*extremely rare*) and get the message "The app can not run because Device Guard" or "Windows Defender Application Guard Blocked this app", you have to remove 4 files with the same name, from different locations.
OR
Paste this code into a powershell file and after **Run as Administrator**.
Remove-Item -LiteralPath "$((Get-Partition | ? IsSystem).AccessPaths[0])Microsoft\Boot\WiSiPolicy.p7b"
Remove-Item -LiteralPath "$env:windir\Boot\EFI\wisipolicy.p7b"
Remove-Item -LiteralPath "$env:windir\System32\CodeIntegrity\WiSiPolicy.p7b"
Remove-Item -Path "$env:windir\WinSxS" -Include *winsipolicy.p7b* -Recurse
Run the desired ".bat" file from cmd with PowerRun (by dragging to the executable). You must reboot for the changes to take effect.
Script_Run.bat
Some security apps flag this app as a virus because of the way the ".exe" files are created. Download with **git** or source code .zip will indicate virus-free.
Starting with Defender 12.6.x , some versions are considered as virus, some are not (its a bug from me, so do not file for this).
That is a false positive.
This application removes / disables Windows Defender, including the Windows Security App, Windows Virtualization-Based Security (VBS), Windows SmartScreen, Windows Security Services, Windows Web-Threat Service, Windows File Virtualization (UAC), Microsoft Defender App Guard, Microsoft Driver Block List, System Mitigations and the Windows Defender page in the Settings App on Windows 10 or later.
Windows Update includes a ```Intelligence Update``` which blocks certain actions and modifies Windows Defender/Security policies.
You can create an ISO with Windoows Defender and Security Services Disabled. It's easy, so this is a fiie which it can helps you.
You can file an [issue](https://github.com/ionuttbara/windows-defender-remover/issues) if you experience any problems.
You can remove Defender with arguments.
```
```PowerShell
bcdedit /set hypervisorlaunchtype off
cd windows-defender-remover
foreach ($choice in $remove_appx) { if ('' -eq $choice.Trim()) {continue}
git clone https://github.com/ionuttbara/windows-defender-remover.git
you can use download entire source code
you can use git
}
