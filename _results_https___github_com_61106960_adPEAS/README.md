
![](https://github.com/61106960/adPEAS/raw/main/images/adPEAS_large.jpg)
# How It Works
# Some How To Use Examples
# adPEAS
## Simple usage with generic program parameters
## Special thanks go to...
## Usage with a single enumeration module
## adPEAS Modules
### All modules below can be combined with all generic program parameters explained above.
### Important Note about the BloodHound Module
$Cred = New-Object System.Management.Automation.PSCredential('contoso\johndoe', $SecPassword)
$SecPassword = ConvertTo-SecureString 'Passw0rd1!' -AsPlainText -Force
* ADCS - Searching for basic Active Directory Certificate Services information, like CA Name, CA Server and vulnerable Templates
* Accounts - Searching for non-disabled high privileged user accounts in predefined groups and account issues like e.g. old passwords
* BloodHound - Enumerating Active Directory with the SharpHound collector for BloodHound Community Edition
* BloodHound Community Edition
* Charlie Clark @exploitph, for his ongoing work on PowerView
* Christoph Falta @cfalta, for his inspiring work on PoshADCS
* Computer - Enumerating Domain Controllers, Certificate Services, Exchange Server and outdated OS versions like Windows Server 2008R2, etc.
* Creds - Searching for different kind of credential exposure, like ASREPRoast, Kerberoasting, GroupPolicies, Netlogon scripts, LAPS, gMSA, certain legacy attributes, e.g. UnixPassword, etc.
* Delegation - Searching for delegation issues, like 'Constrained Delegation', 'Unconstrained Delegation' and 'Resource Based Constrained Delegation', for computer and user accounts
* Dirk-jan @_dirkjan, for his great AD and Windows research
* Domain - Searching for basic Active Directory information, like Domain Controllers, Sites und Subnets, Trusts and Password/Kerberos policy
* GPO -  Searching for basic GPO related things, like local group membership on domain computer
* PoshADCS
* PowerView
* Rights - Searching for specific Active Directory rights and permissions, like LAPS, DCSync and adding computer to domain
* Since more features are constantly added to BloodHound, the ingestor may be frequently updates as well to support more complex enumeration techniques. This repo will try to keep up with the newest versions.
* Since the older version of BloodHound is still in use, a different fork (BloodHound-Old) will exist to cover their needs.
* SpecterOps, for their fantastic BloodHound
* Will Schroeder @harmjoy, for his great PowerView
* adPEAS is currently using the SharpHound ingestor by [BloodHound Community Edition](https://github.com/SpecterOps/BloodHound). This ingestor will NOT work with the older versions of BloodHound.
* and all the people who inspired me on my journey...* and some own written lines of code
. .\adPEAS.ps1
As said, adPEAS is a wrapper for other tools. They are almost all written in pure Powershell but some of them are included as compressed binary blob or C# code.
Enumerates basic Active Directory Certificate Services information, like CA Name, CA Server and common Template vulnerabilities.
Enumerates basic Active Directory information, like Domain Controllers, Password Policy, Sites and Subnets and Trusts.
Enumerates basic GPO information, like set local group membership on domain computer.
Enumerates credential exposure issues, like ASREPRoast, Kerberoasting, Linux/Unix password attributes, gMSA, LAPS (if your account has the rights to read it), Group Policies, Netlogon scripts.
Enumerates delegation issues, like 'Unconstrained Delegation', 'Constrained Delegation', 'Resource Based Constrained Delegation' for user and computer objects.
Enumerates installed Domain Controllers, Active Directory Certificate Services, Exchange Server and outdated OS versions like Windows Server 2008R2.
Enumerates specific Active Directory rights and permissions, like LAPS, DCSync and adding computer to domain.
Enumerates users in high privileged groups which are NOT disabled, like Administrators, Domain Admins, Enterprise Admins, Group Policy Creators, DNS Admins, Account Operators, Server Operators, Printer Operators, Backup Operators, Hyper-V Admins, Remote Management Users und CERT Publishers.
First you have to load adPEAS in Powershell...
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/61106960/adPEAS/main/adPEAS.ps1')
If the system you are running adPEAS from is not domain joined or you want to enumerate another domain, use a certain domain controller to connect to, use different credentials or just to enumerate for credential exposure only, you can do it by using defined parameters.
Import-Module .\adPEAS.ps1
In fact, adPEAS is like a wrapper for different other cool projects like
Invoke-adPEAS
Invoke-adPEAS -Domain 'contoso.com' -Cred $Cred
Invoke-adPEAS -Domain 'contoso.com' -Outputfile 'C:\temp\adPEAS_outputfile' -NoColor
Invoke-adPEAS -Domain 'contoso.com' -Server 'dc1.contoso.com'
Invoke-adPEAS -Domain 'contoso.com' -Server 'dc1.contoso.com' -Username 'contoso\johndoe' -Password 'Passw0rd1!' -Force
Invoke-adPEAS -Module ADCS
Invoke-adPEAS -Module Accounts
Invoke-adPEAS -Module Bloodhound
Invoke-adPEAS -Module Bloodhound -Scope All
Invoke-adPEAS -Module Computer
Invoke-adPEAS -Module Creds
Invoke-adPEAS -Module Delegation
Invoke-adPEAS -Module Domain
Invoke-adPEAS -Module GPO
Invoke-adPEAS -Module Rights
Start adPEAS with all enumeration modules and enumerate the domain 'contoso.com'. In addition it writes all output without any ANSI color codes to a file.
Start adPEAS with all enumeration modules and enumerate the domain the logged-on user and computer is connected to.
Start adPEAS with all enumeration modules, enumerate the domain 'contoso.com' and use the domain controller 'dc1.contoso.com' for almost all enumeration requests.
Start adPEAS with all enumeration modules, enumerate the domain 'contoso.com' and use the passed PSCredential object during enumeration.
Start adPEAS with all enumeration modules, enumerate the domain 'contoso.com' by using the domain controller 'dc1.contoso.com' and use the username 'contoso\johndoe' with password 'Passw0rd1!' during enumeration. If, due to DNS issues Active Directory detection fails, the switch -Force forces adPEAS to ignore those issues and try to get still as much information as possible.
Starts Bloodhound enumeration with the scope All. With this option the SharpHound collector will contact each member computer of the domain. Output ZIP files are stored in the same directory adPEAS is started from.
Starts Bloodhound enumeration with the scope DCOnly. Output ZIP files are stored in the same directory adPEAS is started from. The implemented SharpHound ingestor supports BloodHound Community Edition only.
```
adPEAS can be run simply by starting the script via _invoke-adPEAS_ if it is started on a domain joined computer.
adPEAS consists of the following enumeration modules:
adPEAS is a Powershell tool to automate Active Directory enumeration.
adPEAS-Light is a version without Bloodhound and it is more likely that it will not blocked by an AV solution.
gc -raw .\adPEAS.ps1 | iex
or
