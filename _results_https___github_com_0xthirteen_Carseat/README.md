
    + AMSIProviders          - Providers registered for AMSI
    + AntiVirus              - Registered antivirus (via WMI)
    + AppLocker              - AppLocker settings, if installed
    + AuditPolicyRegistry    - Audit settings via the registry
    + AutoRuns               - Auto run executables/scripts/programs
    + ChromiumBookmarks      - Parses any found Chrome/Edge/Brave/Opera bookmark files
    + ChromiumHistory        - Parses any found Chrome/Edge/Brave/Opera history files
    + ChromiumPresence       - Checks if interesting Chrome/Edge/Brave/Opera files exist
    + CloudCredentials       - AWS/Google/Azure/Bluemix cloud credential files
    + CloudSyncProviders     - All configured Office 365 endpoints (tenants and teamsites) which are synchronised by OneDrive.
    + CredGuard              - CredentialGuard configuration
    + DNSCache               - DNS cache entries (via WMI)
    + DotNet                 - DotNet versions
    + DpapiMasterKeys        - List DPAPI master keys
    + EnvironmentVariables   - Current environment variables
    + ExplicitLogonEvents    - Explicit Logon events (Event ID 4648) from the security event log. Default of 7 days, argument == last X days.
    + ExplorerRunCommands    - Recent Explorer "run" commands
    + FileZilla              - FileZilla configuration files
    + FirefoxHistory         - Parses any found FireFox history files
    + FirefoxPresence        - Checks if interesting Firefox files exist
    + Hotfixes               - Installed hotfixes (via WMI)
    + IEFavorites            - Internet Explorer favorites
    + IEUrls                 - Internet Explorer typed URLs (last 7 days, argument == last X days)
    + InstalledProducts      - Installed products via the registry
    + InterestingProcesses   - "Interesting" processes - defensive products and admin tools
    + KeePass                - Finds KeePass configuration files
    + LAPS                   - LAPS settings, if installed
    + LSASettings            - LSA settings (including auth packages)
    + LastShutdown           - Returns the DateTime of the last system shutdown (via the registry).
    + LocalGroups            - Non-empty local groups, "-full" displays all groups (argument == computername to enumerate)
    + LocalUsers             - Local users, whether they're active/disabled, and pwd last set (argument == computername to enumerate)
    + LogonEvents            - Logon events (Event ID 4624) from the security event log. Default of 10 days, argument == last X days.
    + LogonSessions          - Windows logon sessions
    + MappedDrives           - Users' mapped drives (via WMI)
    + NTLMSettings           - NTLM authentication settings
    + NetworkProfiles        - Windows network profiles
    + NetworkShares          - Network shares exposed by the machine (via WMI)
    + OSInfo                 - Basic OS info (i.e. architecture, OS version, etc.)
    + OptionalFeatures       - List Optional Features/Roles (via WMI)
    + OutlookDownloads       - List files downloaded by Outlook
    + PSSessionSettings      - Enumerates PS Session Settings from the registry
    + PowerShell             - PowerShell versions and security settings
    + PowerShellEvents       - PowerShell script block logs (4104) with sensitive data.
    + PowerShellHistory      - Searches PowerShell console history files for sensitive regex matches.
    + PoweredOnEvents        - Reboot and sleep schedule based on the System event log EIDs 1, 12, 13, 42, and 6008. Default of 7 days, argument == last X days.
    + ProcessCreationEvents  - Process creation logs (4688) with sensitive data.
    + ProcessOwners          - Running non-session 0 process list with owners. For remote use.
    + PuttyHostKeys          - Saved Putty SSH host keys
    + PuttySessions          - Saved Putty configuration (interesting fields) and SSH host keys
    + RDPSavedConnections    - Saved RDP connections stored in the registry
    + RDPsettings            - Remote Desktop Server/Client Settings
    + SCCM                   - System Center Configuration Manager (SCCM) settings, if applicable
    + ScheduledTasks         - Scheduled tasks (via WMI) that aren't authored by 'Microsoft', "-full" dumps all Scheduled tasks
    + SecureBoot             - Secure Boot configuration
    + SlackDownloads         - Parses any found 'slack-downloads' files
    + SlackPresence          - Checks if interesting Slack files exist
    + SlackWorkspaces        - Parses any found 'slack-workspaces' files
    + SuperPutty             - SuperPutty configuration files
    + Sysmon                 - Sysmon configuration from the registry
    + SysmonEvents           - Sysmon process creation logs (1) with sensitive data.
    + UAC                    - UAC system policies via the registry
    + WMI                    - Runs a specified WMI query
    + WSUS                   - Windows Server Update Services (WSUS) settings, if applicable
    + WindowsAutoLogon       - Registry autologon information
    + WindowsDefender        - Windows Defender settings (including exclusion locations)
    + WindowsEventForwarding - Windows Event Forwarding (WEF) settings via the registry
    + WindowsFirewall        - Non-standard firewall rules, "-full" dumps all (arguments == allow/deny/tcp/udp/in/out/domain/private/public)
# Carseat - A Junior Seatbelt
## Description
### Credits
### Useage
### installation
All credits going to all of the awesome work done by Will ([@harmj0y](http://twitter.com/harmj0y)) Lee ([@tifkin_](http://twitter.com/tifkin_)) and all of the [contributors](https://github.com/GhostPack/Seatbelt?tab=readme-ov-file#acknowledgments) of Seatbelt over the years.
Available commands:
Carseat is a python implementation of [Seatbelt](https://github.com/GhostPack/Seatbelt/). This tool contains all (all minus one technically) modules in Seatbelt that support remote execution as an option. Just like Seatbelt you likely will need privileged access to the target host you are running any modules against.
Event log parsing code comes from Iwan Timmer's [tivan project](https://github.com/irtimmer/tivan)
Groups are the same as Seatbelt's. Only difference is `-group remote` will run all modules since they are all considered remote. 
Like other impacket tools CarSeat accepts passwords, hashes or kerberos tickets for authentication.
Note: Command names and descriptions are from Seatbelts README
The only non-standard python libraries used are impacket and pefile. So you can install them individually or through the requirements file. 
To run a single command
To run command with arguments
To run grouped commands
To run multiple at once
```
export KRB5CCNAME=admin_tgt.ccache
or
pip3 install -r requirements.txt
python CarSeat.py -group remote domain/user:password@10.10.10.10 ExplicitLogonEvents 10
python CarSeat.py -group remote domain/user:password@10.10.10.10 InterestingProcesses
python CarSeat.py -hashes :8846F7EAEE8FB117AD06BDD830B7586C -no-pass domain/user:@10.10.10.10 WSUS
python CarSeat.py -k -no-pass domain/user:@10.10.10.10 WindowsFirewall
python CarSeat.py domain/user:password@10.10.10.10 AntiVirus
python CarSeat.py domain/user:password@10.10.10.10 AntiVirus,UAC,ScheduledTasks
