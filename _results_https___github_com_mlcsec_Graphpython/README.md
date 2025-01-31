
 
  
    - [Add-ApplicationCertificate](https://github.com/mlcsec/Graphpython/wiki/Demos#add-applicationcertificate)
    - [Add-ApplicationPermission](https://github.com/mlcsec/Graphpython/wiki/Demos#add-applicationpermission)
    - [Add-ExclusionGroupToPolicy](https://github.com/mlcsec/Graphpython/wiki/Demos#add-exclusiongrouptopolicy)
    - [Assign-PrivilegedRole](https://github.com/mlcsec/Graphpython/wiki/Demos#assign-privilegedrole)
    - [Backdoor-Script](https://github.com/mlcsec/Graphpython/wiki/Demos#backdoor-script)
    - [Deploy-MaliciousScript](https://github.com/mlcsec/Graphpython/wiki/Demos#deploy-maliciousscript)
    - [Deploy-MaliciousWebLink](https://github.com/mlcsec/Graphpython/wiki/Demos#deploy-maliciousweblink)
    - [Display-AVPolicyRules](https://github.com/mlcsec/Graphpython/wiki/Demos#display-avpolicyrules)
    - [Find-DynamicGroups](https://github.com/mlcsec/Graphpython/wiki/Demos#find-dynamicgroups)
    - [Find-PrivilegedApplications](https://github.com/mlcsec/Graphpython/wiki/Demos#find-privilegedapplications)
    - [Find-PrivilegedRoleUsers](https://github.com/mlcsec/Graphpython/wiki/Demos#find-privilegedroleusers)
    - [Find-UpdatableGroups](https://github.com/mlcsec/Graphpython/wiki/Demos#find-updatablegroups)
    - [Get-Application](https://github.com/mlcsec/Graphpython/wiki/Demos#get-application)
    - [Get-CurrentUser](https://github.com/mlcsec/Graphpython/wiki/Demos#get-currentuser)
    - [Get-DeviceCompliancePolicies](https://github.com/mlcsec/Graphpython/wiki/Demos#get-devicecompliancepolicies)
    - [Get-DeviceConfigurationPolicies](https://github.com/mlcsec/Graphpython/wiki/Demos#get-deviceconfigurationpolicies)
    - [Get-Domains](https://github.com/mlcsec/Graphpython/wiki/Demos#get-domains)
    - [Get-GraphTokens](https://github.com/mlcsec/Graphpython/wiki/Demos#get-graphtokens)
    - [Get-Group](https://github.com/mlcsec/Graphpython/wiki/Demos#get-group)
    - [Get-ManagedDevices](https://github.com/mlcsec/Graphpython/wiki/Demos#get-manageddevices)
    - [Get-ScriptContent](https://github.com/mlcsec/Graphpython/wiki/Demos#get-scriptcontent)
    - [Get-TenantID](https://github.com/mlcsec/Graphpython/wiki/Demos#get-tenantid)
    - [Get-UserDevices](https://github.com/mlcsec/Graphpython/wiki/Demos#get-userdevices) 
    - [Get-UserPrivileges](https://github.com/mlcsec/Graphpython/wiki/Demos#get-userprivileges)
    - [Get-User](https://github.com/mlcsec/Graphpython/wiki/Demos#get-user)
    - [Invite-GuestUser](https://github.com/mlcsec/Graphpython/wiki/Demos#invite-guestuser)
    - [Invoke-CertToAccessToken](https://github.com/mlcsec/Graphpython/wiki/Demos#invoke-certtoaccesstoken)
    - [Invoke-ESTSCookieToAccessToken](https://github.com/mlcsec/Graphpython/wiki/Demos#invoke-estscookietoaccesstoken)
    - [Invoke-ReconAsOutsider](https://github.com/mlcsec/Graphpython/wiki/Demos#invoke-reconasoutsider)
    - [Invoke-RefreshToAzureManagementToken](https://github.com/mlcsec/Graphpython/wiki/Demos#invoke-refreshtoazuremanagementtoken)
    - [Invoke-RefreshToMSGraphToken](https://github.com/mlcsec/Graphpython/wiki/Demos#invoke-refreshtomsgraphtoken)
    - [Invoke-Search](https://github.com/mlcsec/Graphpython/wiki/Demos#invoke-search)
    - [Invoke-UserEnumerationAsOutsider](https://github.com/mlcsec/Graphpython/wiki/Demos#invoke-userenumerationasoutsider)
    - [List-RecentOneDriveFiles](https://github.com/mlcsec/Graphpython/wiki/Demos#list-recentonedrivefiles)
    - [Locate-DirectoryRole](https://github.com/mlcsec/Graphpython/wiki/Demos#locate-directoryrole)
    - [Locate-ObjectID](https://github.com/mlcsec/Graphpython/wiki/Demos#locate-objectid)
    - [Locate-PermissionID](https://github.com/mlcsec/Graphpython/wiki/Demos#locate-permissionid)
    - [Remove-GroupMember](https://github.com/mlcsec/Graphpython/wiki/Demos#remove-groupmember)
    - [Spoof-OWAEmailMessage](https://github.com/mlcsec/Graphpython/wiki/Demos#spoof-owaemailmessage)
    - check also [here](https://learn.microsoft.com/en-us/graph/api/resources/intune-app-conceptual?view=graph-rest-1.0) for managing iOS, Android, LOB apps etc. via graph
  - [ ] --proxy option
  - [ ] Add nextlink for `get-user` and `get-group` 
  - [ ] `Deploy-MaliciousWebLink` - add option to deploy script which copies new windows web app link to all user desktops
  - [ ] `Deploy-MaliciousWin32Exe/MSI` - use IntuneWinAppUtil.exe to package the EXE/MSI and deploy to devices
  - [ ] `Get-UserPrivileges` - update to flag any privileged directory role app ids green
  - [ ] `Invoke-AADIntReconAsGuest` and `Invoke-AADIntUserEnumerationAsGuest` - port from AADInternals 
  - [ ] `Invoke-MFASweep` - port mfa sweep and add to outsider commands
  - [ ] `Update/Deploy-Policy` - update existing rules for av, asr, etc. policy or deploy a new one with specific groups/devices
  - [x] `Locate-DirectoryRoleID` - similar to other locator functions but for resolving directory role ids
  <img src="./.github/python.png" />
  <img src="./.github/usage.png" />
# Demos
# Graphpython
# or
## Acknowledgements and References
## Commands
## Index
## Installation
## Todo
## Usage
### Authentication
### Cleanup
### Locators
### Outsider
### Post-Auth Enumeration
### Post-Auth Exploitation
### Post-Auth Intune Enumeration
### Post-Auth Intune Exploitation
- Add-ApplicationCertificate
- Add-ApplicationPassword
- Add-ApplicationPermission
- Add-ExclusionGroupToPolicy
- Add-GroupMember
- Add-UserTAP
- Assign-PrivilegedRole
- Backdoor-Script
- Create-Application
- Create-NewUser
- Decode-AccessToken
- Delete-Application
- Delete-Device
- Delete-Group
- Delete-User
- Deploy-MaliciousScript
- Deploy-MaliciousWebLink
- Display-ASRPolicyRules
- Display-AVPolicyRules
- Display-DiskEncryptionPolicyRules
- Display-EDRPolicyRules
- Display-FirewallConfigPolicyRules
- Display-FirewallRulePolicyRules
- Display-LAPSAccountProtectionPolicyRules
- Display-UserGroupAccountProtectionPolicyRules
- Dump-AndroidApps
- Dump-DeviceManagementScripts
- Dump-OWAMailbox
- Dump-WindowsApps
- Dump-iOSApps
- Dump-macOSApps
- Find-DynamicGroups
- Find-PrivilegedApplications
- Find-PrivilegedRoleUsers
- Find-SecurityGroups
- Find-UpdatableGroups
- Get-AdministrativeUnitMember
- Get-AppRoleAssignments
- Get-AppServicePrincipal
- Get-Application
- Get-CAPs
- Get-ConditionalAccessPolicy
- Get-CrossTenantAccessPolicy
- Get-CurrentUser
- Get-CurrentUserActivity
- Get-DeviceCategories
- Get-DeviceCompliancePolicies
- Get-DeviceComplianceSummary
- Get-DeviceConfigurationPolicies
- Get-DeviceConfigurationPolicySettings
- Get-DeviceConfigurations
- Get-DeviceEnrollmentConfigurations
- Get-DeviceGroupPolicyConfigurations
- Get-DeviceGroupPolicyDefinition
- Get-Domains
- Get-GraphTokens
- Get-Group
- Get-GroupMember
- Get-ManagedDevices
- Get-Messages
- Get-OneDriveFiles
- Get-OrgInfo
- Get-PartnerCrossTenantAccessPolicy
- Get-Password
- Get-PersonalContacts
- Get-RoleAssignments
- Get-RoleDefinitions
- Get-ScriptContent
- Get-ServicePrincipal
- Get-ServicePrincipalAppRoleAssignments
- Get-TemporaryAccessPassword
- Get-TenantID
- Get-TokenScope
- Get-User
- Get-UserChatMessages
- Get-UserDevices
- Get-UserGroupMembership
- Get-UserPermissionGrants
- Get-UserProperties
- Get-UserTransitiveGroupMembership
- Get-oauth2PermissionGrants
- Grant-AppAdminConsent
- Invite-GuestUser
- Invoke-AppSecretToAccessToken
- Invoke-CertToAccessToken
- Invoke-CustomQuery
- Invoke-ESTSCookieToAccessToken
- Invoke-ReconAsOutsider
- Invoke-RefreshToAzureManagementToken
- Invoke-RefreshToIntuneEnrollmentToken
- Invoke-RefreshToMSGraphToken
- Invoke-RefreshToMSTeamsToken
- Invoke-RefreshToOfficeAppsToken
- Invoke-RefreshToOfficeManagementToken
- Invoke-RefreshToOneDriveToken
- Invoke-RefreshToOutlookToken
- Invoke-RefreshToSharePointToken
- Invoke-RefreshToSubstrateToken
- Invoke-RefreshToVaultToken
- Invoke-RefreshToYammerToken
- Invoke-Search
- Invoke-UserEnumerationAsOutsider
- List-AdministrativeUnits
- List-Applications
- List-AuthMethods
- List-ChatMessages
- List-Chats
- List-ConditionalAccessPolicies
- List-ConditionalAuthenticationContexts
- List-ConditionalNamedLocations
- List-Devices
- List-DirectoryRoles
- List-ExternalConnections
- List-JoinedTeams
- List-Notebooks
- List-OneDriveURLs
- List-OneDrives
- List-RecentOneDriveFiles
- List-ServicePrincipals
- List-SharePointRoot
- List-SharePointSites
- List-SharePointURLs
- List-SharedOneDriveFiles
- List-Tenants
- Locate-DirectoryRole
- Locate-ObjectID
- Locate-PermissionID
- Lock-Device
- New-SignedJWT
- New:
- Open-OWAMailboxInBrowser
- Options:
- Reboot-Device
- Remove-GroupMember
- Retire-Device
- Shutdown-Device
- Spoof-OWAEmailMessage
- Update-DeviceConfig
- Update-UserPassword
- Update-UserProperties
- Update:
- Wipe-Device
- [AADInternals](https://github.com/Gerenios/AADInternals)
- [Authentication](https://github.com/mlcsec/Graphpython/wiki/Demos#authentication)
- [Cleanup](https://github.com/mlcsec/Graphpython/wiki/Demos#cleanup)
- [Commands](#Commands)
- [Demos](#Demos)
- [GraphRunner](https://github.com/dafthack/GraphRunner)
- [Installation](#Installation)
- [Locators](https://github.com/mlcsec/Graphpython/wiki/Demos#locators)
- [Outsider](https://github.com/mlcsec/Graphpython/wiki/Demos#outsider)
- [Post-Auth Enumeration](https://github.com/mlcsec/Graphpython/wiki/Demos#post-auth-enumeration)    
- [Post-Auth Exploitation](https://github.com/mlcsec/Graphpython/wiki/Demos#post-auth-exploitation)    
- [Post-Auth Intune Enumeration](https://github.com/mlcsec/Graphpython/wiki/Demos#post-auth-intune-enumeration)
- [Post-Auth Intune Exploitation](https://github.com/mlcsec/Graphpython/wiki/Demos#post-auth-intune-exploitation)
- [TokenTactics](https://github.com/rvrsh3ll/TokenTactics) and [TokenTacticsV2](https://github.com/f-bader/TokenTacticsV2)
- [Usage](#Usage)
- [https://graphpermissions.merill.net/](https://graphpermissions.merill.net/)
- [https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)
- [https://learn.microsoft.com/en-us/graph/permissions-reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
</p>
<br>
<p align="center">
Graphpython -h
Graphpython covers external reconnaissance, authentication/token manipulation, enumeration, and post-exploitation of various Microsoft services, including Entra ID (Azure AD), Office 365 (Outlook, SharePoint, OneDrive, Teams), and Intune (Endpoint Management).
Graphpython is a modular Python tool for cross-platform Microsoft Graph API enumeration and exploitation. It builds upon the capabilities of AADInternals (Killchain.ps1), GraphRunner, and TokenTactics(V2) to provide a comprehensive solution for interacting with the Microsoft Graph API for red team and cloud assumed breach operations. 
Graphpython is designed to be cross-platform, ensuring compatibility with both Windows and Linux based operating systems:
Please refer to the [Wiki](https://github.com/mlcsec/Graphpython/wiki/Commands) for more details on the available commands
Please refer to the [Wiki](https://github.com/mlcsec/Graphpython/wiki/Demos) for the following demos
Please refer to the [Wiki](https://github.com/mlcsec/Graphpython/wiki/Usage) for more details
```
```bash
cd Graphpython
git clone https://github.com/mlcsec/Graphpython.git
pip install .
python3 Graphpython.py -h
