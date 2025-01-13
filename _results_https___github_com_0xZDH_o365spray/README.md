
                        (e.g. http://127.0.0.1:8080).
                        Default: 0
                        Default: 1
                        Default: 10
                        Default: 10000
                        Default: 15 minutes
                        Default: current directory
                        Default: getuserrealm
                        Default: oauth2
                        Default: office
                        File containing list of passwords.
                        File containing list of user agents for randomization.
                        File containing list of usernames.
                        FireProx API URL.
                        Lockout policy's reset time (in minutes).
                        Number of password attempts to run per user before resetting
                        Password(s) delimited using commas.
                        Specify which enumeration module to run.
                        Specify which password spraying module to run.
                        Specify which valiadtion module to run.
                        Target domain for validation, user enumeration, and/or
                        Username(s) delimited using commas.
                        are observed.
                        by passing the value `-1` (between 1 sec and 2 mins).
                        enumeration and spraying.
                        format.
                        password spraying.
                        spraying.
                        the lockout account timer.
  - [Enumeration](#enumeration)
  - [Enumeration](#enumeration-1)
  - [Spraying](#spraying)
  - [Spraying](#spraying-1)
  - [Validation](#validation)
  --adfs-url ADFS_URL   AuthURL of the target domain's ADFS login page for password
  --debug               Enable debug output.
  --enum                Run username enumeration.
  --enum-module ENUM_MODULE
  --jitter [0-100]      Jitter extends --sleep period by percentage given (0-100).
  --output OUTPUT       Output directory for results and test case files.
  --paired PAIRED       File containing list of credentials in username:password
  --poolsize POOLSIZE   Maximum size of the ThreadPoolExecutor.
  --proxy PROXY         HTTP/S proxy to pass traffic through
  --proxy-url PROXY_URL
  --rate RATE           Number of concurrent connections (attempts) during
  --safe SAFE           Terminate password spraying run if `N` locked accounts
  --sleep [-1, 0-120]   Throttle HTTP requests every `N` seconds. This can be randomized
  --spray               Run password spraying.
  --spray-module SPRAY_MODULE
  --timeout TIMEOUT     HTTP request timeout in seconds. Default: 25
  --useragents USERAGENTS
  --validate            Run domain validation only.
  --validate-module VALIDATE_MODULE
  -P PASSFILE, --passfile PASSFILE
  -U USERFILE, --userfile USERFILE
  -c COUNT, --count COUNT
  -d DOMAIN, --domain DOMAIN
  -h, --help            show this help message and exit
  -l LOCKOUT, --lockout LOCKOUT
  -p PASSWORD, --password PASSWORD
  -u USERNAME, --username USERNAME
  -v, --version         Print the tool version.
  <br>
  <img src="static/o365spray_validate.png" alt="o365spray" width="90%">
# Table of Contents
# o365spray
# v1.3.7
# v2.0.4
## Acknowledgments
## Bugs
## FireProx Base URLs
## Modules
## Omnispray
## Usage
## User Agent Randomization
## Using Previous Versions
### Enumeration
### Spraying
### Validation
* activesync
* adfs
* autodiscover
* autologon
* getuserrealm (default)
* oauth2 (default)
* office
* onedrive
* reporting
* rst
- [Acknowledgments](#acknowledgments)
- [Bugs](#bugs)
- [FireProx URLs](#fireprox-base-urls)
- [Modules](#modules)
- [Previous Versions](#using-previous-versions)
- [Usage](#usage)
- [User Agent Randomization](#user-agent-randomization)
- https://github.com/sqlmapproject/sqlmap/blob/master/data/txt/user-agents.txt
- https://www.useragentstring.com/pages/useragentstring.php?name=<browser>
</h2>
<h2 align="center">
> For educational, authorized and/or research purposes only.
> NOTE: Make sure to use the correct `--enum-module` or `--spray-module` flag with the base URL used to create the FireProx URL.
> The 'tenant' value in the OneDrive URL is the domain name value that is provided via the `--domain` flag.
> The oAuth2 module can be used for federated spraying, but it should be noted that this will ONLY work when the target tenant has enabled password synchronization - otherwise authentication will always fail. The default mechanic is to default to the 'adfs' module when federation is identified.
> The onedrive module relies on the target user(s) having previously logged into OneDrive. If a valid user has not yet used OneDrive, their account will show as 'invalid'.
> WARNING: The Autologon, oAuth2, and RST user enumeration modules work by submitting a single authentication attempt per user. If the modules are run in conjunction with password spraying in a single execution, o365spray will automatically reset the lockout timer prior to performing the password spray -- if enumeration is run alone, the user should be aware of how many and when each authentication attempt was made and manually reset the lockout timer before performing any password spraying.
Actions:
Credentials:
Debug:
HTTP Configuration:
If any bugs/errors are encountered, please open an Issue with the details (or a Pull Request with the proposed fix). See the [section below](#using-previous-versions) for more information about using previous versions.
If issues are encountered, try checking out previous versions prior to code rewrites:
Microsoft has made it more difficult to perform password spraying, so using tools like [FireProx](https://github.com/ustayready/fireprox) help to bypass rate-limiting based on IP addresses.
Module Configuration:
Output Configuration:
Password Spraying Configuration:
Perform password spraying against a given domain:<br>
Perform username enumeration against a given domain:<br>
Scan Configuration:
Target:
The agents in the example data set were collected from the following:
The o365spray framework has been ported to a new tool: [Omnispray](https://github.com/0xZDH/Omnispray). This tool is meant to modularize the original enumeration and spraying framework to allow for generic targeting, not just O365. Omnispray includes template modules for enumeration and spraying that can be modified and leveraged for any target.
To use FireProx with o365spray, create a proxy URL for the given o365spray module based on the base URL tables below. The proxy URL can then be passed in via `--proxy-url`.
User-Agent randomization is now supported and can be accomplished by providing a User-Agent file to the `--useragents` flag. o365spray includes an example file with 4,800+ agents via [resc/user-agents.txt](resc/user-agents.txt).
Validate a domain is using O365:<br>
```
```bash
`o365spray --enum -U usernames.txt --domain test.com`
`o365spray --spray -U usernames.txt -P passwords.txt --count 2 --lockout 5 --domain test.com`
`o365spray --validate --domain test.com`
git checkout a585432f269a8f527d61f064822bb08880c887ef
git checkout e235abdcebad61dbd2cde80974aca21ddb188704
o365spray is a username enumeration and password spraying tool aimed at Microsoft Office 365 (O365). This tool reimplements a collection of enumeration and spray techniques researched and identified by those mentioned in [Acknowledgments](#Acknowledgments).
o365spray | Microsoft O365 User Enumerator and Password Sprayer -- v3.0.4
options:
usage: o365spray [flags]
| ---          | ---      |
| ---    | ---           | ---  |
| Author | Tool/Research | Link |
| Module       | Base URL |
| [Daniel Chronlund](https://danielchronlund.com/) / [xFreed0m](https://github.com/xFreed0m) | Invoke-AzureAdPasswordSprayAttack / ADFSpray: Office 365 reporting API password spraying | [Invoke-AzureAdPasswordSprayAttack](https://danielchronlund.com/2020/03/17/azure-ad-password-spray-attacks-with-powershell-and-how-to-defend-your-tenant/) / [ADFSpray](https://github.com/xFreed0m/ADFSpray) |
| [Mr-Un1k0d3r](https://github.com/Mr-Un1k0d3r) | adfs-spray: ADFS password spraying | [adfs-spray](https://github.com/Mr-Un1k0d3r/RedTeamScripts/blob/master/adfs-spray.py) |
| [Nestori Syynimaa](https://github.com/NestoriSyynimaa) | AADInternals: oAuth2 and autologon modules | [AADInternals](https://github.com/Gerenios/AADInternals) |
| [Optiv](https://github.com/optiv) (Several Authors) | Go365: RST user enumeration and password spraying module | [Go365](https://github.com/optiv/Go365) |
| [Raikia](https://github.com/Raikia) | UhOh365: User enumeration via Autodiscover without authentication. | [UhOh365](https://github.com/Raikia/UhOh365) |
| [byt3bl33d3r](https://github.com/byt3bl33d3r) | MSOLSpray: Python reimplementation | [Gist](https://gist.github.com/byt3bl33d3r/19a48fff8fdc34cc1dd1f1d2807e1b7f) |
| [byt3bl33d3r](https://github.com/byt3bl33d3r) | SprayingToolkit: Code references | [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit/) |
| [dafthack](https://github.com/dafthack) | MSOLSpray: Password spraying via MSOL | [MSOLSpray](https://github.com/dafthack/MSOLSpray) |
| [gremwell](https://github.com/gremwell) | o365enum: User enumeration via [office.com](#) without authentication | [o365enum](https://github.com/gremwell/o365enum) |
| [grimhacker](https://bitbucket.org/grimhacker) | office365userenum: ActiveSync user enumeration research and discovery. | [office365userenum](https://bitbucket.org/grimhacker/office365userenum/src/master/) / [blog post](https://grimhacker.com/2017/07/24/office365-activesync-username-enumeration/) |
| [nyxgeek](https://github.com/nyxgeek) | onedrive_user_enum: OneDrive user enumeration | [onedrive_user_enum](https://github.com/nyxgeek/onedrive_user_enum) / [blog post](https://www.trustedsec.com/blog/achieving-passive-user-enumeration-with-onedrive/) |
| [sensepost](https://github.com/sensepost) | ruler: Code references | [Ruler](https://github.com/sensepost/ruler/) |
| activesync   | `https://outlook.office365.com/` |
| adfs         | Currently not implemented |
| autodiscover | `https://autodiscover-s.outlook.com/` |
| autodiscover | `https://outlook.office365.com/` |
| autologon    | `https://autologon.microsoftazuread-sso.com/` |
| oauth2       | `https://login.microsoftonline.com/` |
| office       | `https://login.microsoftonline.com/` |
| onedrive     | `https://<tenant>-my.sharepoint.com/` |
| reporting    | `https://reports.office365.com/` |
| rst          | `https://login.microsoftonline.com/` |
