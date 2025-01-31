	* List Users, Groups, Applications, Devices, Conditional Access Policies, ...
	* Password, ESTSAuth Cookie, PRT, ...
	* UIcons by [Flaticon](https://www.flaticon.com/uicons)	* While this should not have any direct impact on the user, edge cases might currently throw exceptions to the GraphSpy output instead of handling them in a cleaner way.
	* [AADInternals](https://github.com/Gerenios/AADInternals)
	* [GraphRunner](https://github.com/dafthack/GraphRunner) is a PowerShell tool with a lot of similar features, which was released while GraphSpy was already in development. Regardless, both tools still have their distinguishing factors.
	* [Introducing a new phishing technique for compromising Office 365 accounts](https://aadinternals.com/post/phishing/)
	* [The Art of the Device Code Phish](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html)
	* [TokenTactics](https://github.com/rvrsh3ll/TokenTactics) and [TokenTacticsV2](https://github.com/f-bader/TokenTacticsV2)
	- [Execution](#execution)
	- [Installation](#installation)
	- [Usage](#usage)

        \/           \/|__|        \/        \/|__|   \/
   ________                             _________
  * Download authenticated files
  * Upload files and images
  /       /  by RedByte1337    __      /        /           
 /  _____/___________  ______ |  |__  /   _____/_____ ______
 \______  /__|  |____  |   __/|___|  /_______  /   ___/ ____|
![Access Tokens](images/access_tokens_1.png)
![Custom Request](images/custom_request_templates.png)
![Custom Request](images/custom_requests.png)
![Custom Request](images/entra_users_details_1.png)
![Custom Request](images/entra_users_overview.png)
![Device Codes](images/device_codes.png)
![Graph Request](images/settings.png)
![Graph Search](images/graph_search_2.png)
![MFA Methods FIDO](images/mfa_methods_fido.png)
![MFA Methods Overview](images/mfa_methods_overview.png)
![MS Teams GraphSpy](images/ms_teams.png)
![OneDrive](images/onedrive_2.png)
![Outlook GraphSpy](images/outlook_1.png)
![Outlook](images/outlook_2.png)
![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![Recent Files](images/recent_files.png)
![Refresh Tokens](images/refresh_tokens.png)
![Token Side Bar](images/token_side_bar_1.png)
# Credits
# Features
# GraphSpy
# Install pipx (skip this if you already have it)
# Install the latest version of GraphSpy from pypi
# Quick Start
# Release Notes
# Run GraphSpy on http://192.168.0.10
# Run GraphSpy on port 8080 on all interfaces
# Table of Contents
# Upcoming Features
## Access and Refresh Tokens
## Custom Requests
## Dark Mode
## Device Codes
## Entra ID
## Execution
## Files and SharePoint
## Graph Searching
## Installation
## MFA Methods
## MS Teams
## Multiple Databases
## Outlook
## Usage
* Acknowledgements
* Assets
* Automatic Access Token Refreshing
* Cleaner exception handling
* Entra ID
* Improve Microsoft Teams Module
* More authentication options
* Rename files and create folders
- Alternative email address
- Custom OTP App, or use GraphSpy as OTP app to generate TOTP codes on the fly!
- FIDO Security Keys!
- Microsoft Authenticator App
- Mobile/Office/Alternative Phones (SMS or call)
- [Credits](#credits)
- [Features](#features)
- [GraphSpy](#graphspy)
- [Quick Start](#quick-start)
- [Release Notes](#release-notes)
- [Table of Contents](#table-of-contents)
- [Upcoming Features](#upcoming-features)
/   \  __\_  __ \__  \ \____ \|  |  \ \_____  \\____ \   |  |
Additionally, list the user's recently accessed files or files shared with the user.
After installation, the application can be launched using the `graphspy` command from any location on the system.
Browse through files and folders in the user's OneDrive or any accessible SharePoint site through an intuitive file explorer interface.
Custom request templates with variables can be stored in the database to allow easy reuse of common custom API requests.
Easily create and poll multiple device codes at once. If a user used the device code to authenticate, GraphSpy will automatically store the access and refresh token in its database.
Easily switch between them or request new access tokens from any page.
For a quick feature overview, check out the [official release blog post](https://insights.spotit.be/2024/04/05/graphspy-the-swiss-army-knife-for-attacking-m365-entra/).
For detailed instructions and other command line arguments, please refer to the [Execution page](https://github.com/RedByte1337/GraphSpy/wiki/Execution) on the wiki.
For instance, use this to search for any files or emails containing keywords such as "password", "secret", ...
For other installation options and detailed instructions, check the [Installation page](https://github.com/RedByte1337/GraphSpy/wiki/Installation) on the wiki.
GraphSpy is built to work on every operating system, although it was mainly tested on Linux and Windows. 
GraphSpy supports multiple databases. This is useful when working on multiple assessments at once to keep your tokens and device codes organized.
However, a lot of previous research was done by countless other persons (specifically regarding Device Code Phishing, which lead to the initial requirement for such a tool in the first place).
List all Entra ID users and their properties using the Microsoft Graph API.
Now simply open `http://127.0.0.1:5000` in your favorite browser to get started!
Of course, files can also be directly downloaded, or new files can be uploaded.
Open the user's Outlook with a single click using just an Outlook access token (FOCI)!
Perform custom API requests towards any endpoint using access tokens stored in GraphSpy.
Please refer to the [GitHub Wiki](https://github.com/RedByte1337/GraphSpy/wiki) for full usage details.
Read and send messages using the Microsoft Teams module with a FOCI access token of the skype API (https://api.spaces.skype.com/).
Refer to the [Release Notes](https://github.com/RedByte1337/GraphSpy/wiki/Release-Notes) page on the GitHub Wiki
Running GraphSpy without any command line arguments will launch GraphSpy and make it available at `http://127.0.0.1:5000` by default.
Search for keywords through all Microsoft 365 applications using the Microsoft Search API.
Store your access and refresh tokens for multiple users and scopes in one location. 
The following MFA methods can be added from GraphSpy to set up persistance:
The following goes over the recommended installation process using pipx to avoid any dependency conflicts.
The main motivation for creating GraphSpy was the lack of an easy to use way to perform post-compromise activities targetting Office365 applications (such as Outlook, Microsoft Teams, OneDrive, SharePoint, ...) with just an access token.
Use the `-i` and `-p` arguments to modify the interface and port to listen on.
Use the dark mode by default, or switch to light mode.
View additional details for a user, such as its group memberships, role assignments, devices, app roles and API permissions.
View, modify and create MFA methods linked to the account of the user.
While several command-line tools existed which provided some basic functionality, none of them came close to the intuitive interactive experience which the original applications provide (such as the file explorer-like interface of OneDrive and SharePoint).
[![PyPi Version](https://img.shields.io/pypi/v/GraphSpy.svg)](https://pypi.org/project/GraphSpy/)
[![Twitter](https://img.shields.io/twitter/follow/RedByte1337?label=RedByte1337&style=social)](https://twitter.com/intent/follow?screen_name=RedByte1337)
\    \_\  \  | \/  __ \|  |_> |   \  \/        \  |_> \___  |
```
```bash
apt install pipx
graphspy
graphspy -i 0.0.0.0 -p 8080
graphspy -i 192.168.0.10 -p 80
pipx ensurepath
pipx install graphspy
