	

![image](https://github.com/Leo4j/Invoke-SessionHunter/assets/61951374/0505d8d7-231a-4e3e-b157-58900e7bba85)
# Invoke-SessionHunter
### Do not run a port scan to enumerate for alive hosts before trying to retrieve sessions
### Retrieve and display information about active user sessions on servers only
### Retrieve and display information about active user sessions on workstations only
### Return custom PSObjects instead of table-formatted results
### Show active session for the specified user only
### Specify a comma-separated list of targets or the full path to a file containing a list of targets - one per line
### Specify the target domain
### Usage:
All switches can be combined
As a result, they won't show among the retrieved sessions.
Gather sessions by authenticating to targets where you have local admin access ('klist sessions' command is run on targets)
If run without parameters or switches it will retrieve active sessions for all computers in the current domain by querying their remote registry
If the `-CheckAdminAccess` switch is provided, it will gather sessions by authenticating to targets where you have local admin access using [Invoke-WMIRemoting](https://github.com/Leo4j/Invoke-WMIRemoting) (which most likely will retrieve more results)
If you want to include them within the retrieved results please provide the -ShowAll and/or -IncludeLocalHost switches.
Invoke-SessionHunter
Invoke-SessionHunter -CheckAsAdmin
Invoke-SessionHunter -CheckAsAdmin -UserName "ferrari\Administrator" -Password "P@ssw0rd!"
Invoke-SessionHunter -CheckAsAdmin -UserName "ferrari\Administrator" -Password "P@ssw0rd!" -Timeout 5000 -Match
Invoke-SessionHunter -Domain contoso.local
Invoke-SessionHunter -Hunt "Administrator"
Invoke-SessionHunter -Match
Invoke-SessionHunter -NoPortScan
Invoke-SessionHunter -RawResults
Invoke-SessionHunter -Servers
Invoke-SessionHunter -ShowAll -IncludeLocalHost
Invoke-SessionHunter -Targets "DC01,Workstation01.contoso.local"
Invoke-SessionHunter -Targets c:\Users\Public\Documents\targets.txt
Invoke-SessionHunter -Timeout 5000
Invoke-SessionHunter -Workstations
Invoke-SessionHunter is designed to keep your host machine, your current user, and the provided username out of scope. 
Invoke-SessionHunter will skip any target where the remote registry fails to respond within 2000ms (2 seconds).
It's important to note that the remote registry service needs to be running on the remote computer for the tool to work effectively. In my tests, if the service is stopped but its Startup type is configured to "Automatic" or "Manual", the service will start automatically on the target computer once queried (this is native behavior), and sessions information will be retrieved. If set to "Disabled" no session information can be retrieved from the target.
Load Invoke-SessionHunter in memory
Note: if a host is not reachable it may hang for a while
Retrieve and display information about active user sessions on remote computers. No admin privileges required.
The tool leverages the remote registry service to query the HKEY_USERS registry hive on the remote computers. It identifies and extracts Security Identifiers (SIDs) associated with active user sessions, and translates these into corresponding usernames, offering insights into who is currently logged in.
Use the -Match switch to show only targets where you have admin access and a privileged user is logged in
You can optionally provide credentials in the following format
You have control on the timeout by providing the -Timeout parameter | Default = 2000, increase for slower networks.
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Invoke-SessionHunter/main/Invoke-SessionHunter.ps1')
