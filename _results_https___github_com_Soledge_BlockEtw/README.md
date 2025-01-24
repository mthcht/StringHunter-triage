
# BlockETW
.Net 3.5 / 4.5 Assembly to block ETW telemetry in a process
> shinject <pid> /opt/shellcode/blocketw.bin
Credits go to RastaMouse and XPN for creating SharpC2 from which this tool is based
For injecting into a process:  
It WILL NOT WORK if your using  spawnto
Release Build is built with .net 4.5 (but can be built for 3.5)
There is no output currently for the command. 
You must "Self-Inject" the blocketw.bin to the session that your beacon lives in
and thier research on ETW bypassing.
https://blog.xpnsec.com/hiding-your-dotnet-etw/
https://rastamouse.me/2020/05/sharpc2/
