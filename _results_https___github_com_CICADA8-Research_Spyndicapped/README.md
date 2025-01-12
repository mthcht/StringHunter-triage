
                |
                |L___,
              '._.'   L
              .' '.  T
              ._
             :  *  :_|
         --debug <- displays more information
         --ignore-handlers <- I have created handlers for various apps, but u can use the generic HandleOther() with this flag
         --logfile <filename> <- store all events into the log file
         --no-property-events <- disables MyPropertyChangedEventHandler
         --no-uia-events <- disables MyAutomationEventHandler
         --pid <pid> <- grabs information from that process (GUI Required)
         --timeout <sec> <- interval to process events (default 1 sec)
         --window <name> <- grabs information from that window
         Spyndicapped.exe find
         Spyndicapped.exe spy
         Spyndicapped.exe spy --pid 123
         Spyndicapped.exe spy --window "Program Manager"
        Displays the windows available for spying with --window or --pid
        Window(s) spying mode
        [EXAMPLES]
  .\Spyndicapped find
  .\Spyndicapped spy
  .\Spyndicapped spy --logfile 1.txt
  .\Spyndicapped spy --pid <pid from find command>
# And log everything into the file
# Find target and spy by the pid
# How it works
# Spy the whole system (high load may be!)
# Spyndicapped
# TL;DR
# Usage examples
And whatsapp web:
CICADA8 Research Team
Check keepass looting above :))
Christmas present from MzHmO
In addition, the tool can parse Telegram messages:
In fact, I have two handlers:
Keepass looting example:
Note that the tool captures the text you enter, shows the sender's name and the recipient's name. In this case, I'm writing a message to a chat.
PS A:\ssd\gitrepo\Spyndicapped_dev\x64\Debug> .\Spyndicapped.exe -h
So, there is a Windows User Automation framework that allows you to work with any Windows graphical elements. I just studied it over the New Year holidays and made a small POC :P It just so happens that in parallel I became an expert in Windows programming for handicapped people. Why didn't anyone tell me about this when I first started learning pentest?
Spy of your users with Microsoft UIA! 
The exact same functionality is supported for the Web version of Slack:
There are different work modes:
They handle all the GUI changes we are interested in: data input, text copying, data modification. Among other things, I've added handlers under different processes and even domains in the browser so you can get more familiar with the framework! See the examples below for more details. Also, I added an example of using patterns (one of the UIA components) on the example of KeePass looting.
With this project you will be able to learn Windows UIA! I use almost all concepts: event handling, pattern calling, tree traversal, item lookup.
You can find out more details in [this article on medium](https://cicada-8.medium.com/im-watching-you-how-to-spy-windows-users-via-ms-uia-c9acd30f94c4).
[FIND mode]
[Other]
[SPY mode]
[Spyndicapped]
```
```shell
