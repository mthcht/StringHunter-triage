
                       Note: Variable LHOST is required.
                       When entered without command, switches to SHELL context.
                       When entered without ms, shows the current interval.
                       When entered without parameters, it shows the currently set variables.
# ReVBShell
## Components
## Files
### Client
### Server
* client.vbs - Visual Basic Script client which connectes to the IP/port specified and periodically fetches commands
* intSleep - Default delay between the polls to the server
* server.py - Interactive Python shell, listening on port 8080 for clients
* strHost - IP of host to connect back to; should be the IP of the host where server.py is running
* strPort - Listening port on the above host
**Default settings**
**Supported commands**
- CD [directory]     - Change directory. Shows current directory when without parameter.
- DOWNLOAD [path]    - Download the file at [path] to the .\Downloads folder.
- GETUID             - Get shell user id.
- GETWD              - Get working directory. Same as CD.
- HELP               - Show this help.
- IFCONFIG           - Show network configuration.
- KILL               - Stop script on the remote host.
- PS                 - Show process list.
- PWD                - Same as GETWD and CD.
- SET [name] [value] - Set a variable, for example SET LHOST 192.168.1.77.
- SHELL [command]    - Execute command in cmd.exe interpreter;
- SHUTDOWN           - Exit this commandline interface (does not shutdown the client).
- SLEEP [ms]         - Set client polling interval;
- SYSINFO            - Show sytem information.
- UNSET [name]       - Unset a variable
- UPLOAD [localpath] - Upload the file at [path] to the remote host.
- WGET [url]         - Download file from url.
Configuration can be set in the .vbs file itself.
_Interactive Python shell_
_VBS client_
```
intSleep = 5000
strHost = "127.0.0.1"
strPort = "8080"
