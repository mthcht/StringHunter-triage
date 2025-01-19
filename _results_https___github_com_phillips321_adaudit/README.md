
                 by phillips321
  * Get-AccountPassDontExpire
  * Get-AdminAccountChecks
  * Get-AuthenticationPoliciesAndSilos
  * Get-CriticalServicesStatus
  * Get-DCEval
  * Get-DCsNotOwnedByDA
  * Get-DNSZoneInsecure
  * Get-DefaultDomainControllersPolicy
  * Get-DisabledAccounts
  * Get-DomainTrusts
  * Get-FunctionalLevel
  * Get-GPOEnum
  * Get-GPOsPerOU
  * Get-GPOtoFile
  * Get-HostDetails
  * Get-InactiveAccounts
  * Get-LAPSStatus
  * Get-LastWUDate
  * Get-LockedAccounts
  * Get-MachineAccountQuota
  * Get-NTDSdit
  * Get-NULLSessions
  * Get-OUPerms
  * Get-OldBoxes
  * Get-PasswordPolicy
  * Get-PasswordQuality
  * Get-PrivilegedGroupAccounts
  * Get-PrivilegedGroupMembership
  * Get-ProtectedUsers
  * Get-RODC
  * Get-RecentChanges
  * Get-RecycleBinState
  * Get-ReplicationType
  * Get-SMB1Support
  * Get-SYSVOLXMLS
  * Get-TimeSource
  * Get-UserPasswordNotChangedRecently
# adaudit
## Runtime Args
## What this does
* -accounts identifies account issues such as expired, disabled, etc...
* -acl checks for dangerous ACL permissions on Users, Groups and Computers. 
* -adcs checks for ADCS vulnerabiltiies, ESC1,2,3,4 and 8.
* -all runs all checks, e.g. AdAudit.ps1 -all
* -asrep checks for ASREPRoastable accounts
* -authpolsilos checks for existence of authentication policies and silos
* -domainaudit retrieves information about the AD such as functional level
* -exclude allows you to exclude specific checks when using adaudit.ps1 -all -exclude ouperms,ntds,adcs"
* -gpo dumps the GPOs in XML and HTML for later analysis
* -hostdetails retrieves hostname and other useful audit info
* -insecurednszone checks for insecure DNS zones
* -installdeps installs optionnal features (DSInternals)
* -laps checks if LAPS is installed
* -ldapsecurity checks for multiple LDAP issues
* -ntds dumps the NTDS.dit file using ntdsutil
* -oldboxes identified outdated OSs like XP/2003 joined to the domain
* -ouperms checks generic OU permission issues
* -passwordpolicy retrieves password policy information
* -recentchanges checks for newly created users and groups (last 30 days)
* -select allows you to exclude specific checks when using adaudit.ps1 -all "gpo,ntds,acl"
* -spn checks for high value kerberoastable accounts 
* -trusts retrieves information about any doman trusts
* Check For Existence of Authentication Polices and Silos
* Check For Existence of LAPS in domain
* Check Generic Group AD Permissions
* Check LDAP and LDAPs settings (Signing, null sessions etc )
* Check for ADCS vulnerabiltiies, ESC1,2,3,4 and 8. 
* Check for ASREPRoastable accounts
* Check for dangerous ACL permissions on Users, Groups and Computers. 
* Check for high value kerberoastable accounts 
* Check for insecure DNS zones
* Check for newly created users and groups
* Computer Objects Audit
* Device Information
* Domain Audit
* Domain Trust Audit
* Dumps NTDS.dit
* GPO audit (and checking SYSVOL for passwords)
* Password Information Audit
* User Accounts Audit
If you have any decent powershell one liners that could be used in the script please let me know. I'm trying to keep this script as a single file with no requirements on external tools (other than ntdsutil and cmd.exe)
Run directly on a DC using a DA. If you don't trust the code I suggest reading it first and you'll see it's all harmless! (But shouldn't you be doing that anyway with code you download off the net and then run as DA??)
The following switches can be used in combination
This PowerShell script is designed to conduct a comprehensive audit of Microsoft Active Directory, focusing on identifying common security vulnerabilities and weaknesses. Its execution facilitates the pinpointing of critical areas that require reinforcement, thereby fortifying your infrastructure against prevalent tactics used in lateral movement or privilege escalation attacks targeting Active Directory.
_____ ____     _____       _ _ _
```
|     |  |  |  |     | | | . | |  _|
|  _  |    \   |  _  |_ _ _| |_| |_
|__|__|____/   |__|__|___|___|_|_|
