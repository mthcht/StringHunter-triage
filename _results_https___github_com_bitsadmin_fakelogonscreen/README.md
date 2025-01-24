
![FakeLogonScreen demo in Cobalt Strike](https://raw.githubusercontent.com/bitsadmin/fakelogonscreen/master/demo.gif "FakeLogonScreen demo in Cobalt Strike")
# FakeLogonScreen
# Features
# Screenshot
**Authored by Arris Huijgen ([@bitsadmin](https://twitter.com/bitsadmin/) - https://github.com/bitsadmin/)**
- / (root): Built against .NET Framework 4.5 which is installed by default in Windows 8, 8.1 and 10
- Blocks many shortkeys to prevent circumventing the screen
- DOTNET35: Built against .NET Framework 3.5 which is installed by default in Windows 7
- FakeLogonScreen.exe: Writes output to console which for example is compatible with Cobalt Strike
- FakeLogonScreenToFile.exe: Writes output to console and `%LOCALAPPDATA%\Microsoft\user.db`
- If custom background is configured by the user, shows that background instead of the default one
- Minimizes all existing windows to avoid other windows staying on top
- Primary display shows a Windows 10 login screen while additional screens turn black
- Username and passwords entered are outputted to console or stored in a file
- Validates entered password before closing the screen
Binaries available from the [Releases](https://github.com/bitsadmin/fakelogonscreen/releases) page.
FakeLogonScreen is a utility to fake the Windows logon screen in order to obtain the user's password. The password entered is validated against the Active Directory or local machine to make sure it is correct and is then displayed to the console or saved to disk.
Folders:
It can either be executed by simply running the .exe file, or using for example Cobalt Strike's `execute-assembly` command.
