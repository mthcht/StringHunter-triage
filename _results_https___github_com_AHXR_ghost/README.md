	<img src="https://i.imgur.com/NDCXXgD.jpg" />
	<img src="https://i.imgur.com/W5aC6rg.png" />

# ghost
#### Bot Features
**Note**: This project was only made for education purposes and to test out my recently published repositories ([ahxrlogger](https://github.com/AHXR/ahxrlogger) & [ahxrsocket](https://github.com/AHXR/ahxrwinsocket)). If you choose to use this for malicious reasons, you are completely responsible for the outcome.**ghost** is a light [RAT](http://searchsecurity.techtarget.com/definition/RAT-remote-access-Trojan) that gives the server/attacker full remote access to the user's command-line interpreter (cmd.exe).
- Data sent and received is encrypted (substitution cipher)
- Disable Task Manager
- Download and run file (Hidden)
- Easily spread malware through download feature
- Files are hidden
- Installed Antivirus shown to server
- Remote command execution 
- Safe Mode startup
- Silent background process
- Startup info doesn't show in msconfig or other startup checking programs like CCleaner
- Will automatically connect to the server
---
</p>
<p align="center">
They are allowed to execute commands silently without the client/zombie noticing. The server/attacker is also given the ability to download and execute files on the client/zombie's computer. This is also
This malware is distributed simply by running *zombie.exe*. This file name can be changed to whatever. There is no restriction. When run, it searches for the first two arguments (IP & Port). If neither
This means that the zombie will silently just idle in the background and whenever the server is up, it will automatically connect.
When starting the server, it will prompt for you a listening port. This is the port that you need to use in the command-line for zombie.exe. Once you provide the port, your server information will be
When successfully started, it adds itself to the start-up pool and runs silently in the background. It will try to repeatedly connect to the server. This process does not hog any memory or CPU usage.
```
a silent and hidden process. Like most Remote Access Trojans, this download and execution ability helps distribute viruses and other pieces of malware.
is provided, the program doesn't run. With that being said, make sure you provide the server's IP and Port in the command-line arguments. Example:
likely fool the client/zombie.
provided and the menu will be down. The IP address provided is your external IP. With that being said, unless the client/zombie is actively looking and tracking open connections, it will probably be 
smart to run this server under a remote location if you want to stay anonymous. If this does not interest you, simply renaming zombie.exe and/or changing the assembly information using a tool will 
zombie.exe 127.0.0.1 27015
