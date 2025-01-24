
![Working SharpLocker](https://github.com/Pickfordmatt/SharpLocker/blob/master/sharplocker.png?raw=true)
# SharpLocker
## Credits 
## How to
## What SharpLocker is
## What SharpLocker is NOT
## Works
* A .NET application that is supposed to be run in memory on a target device
* A password stealing tool that emails plain text credentials
* An executable that is supposed to be double clicked
* Compile SharpLocker from source via VisualStudio etc
* Main monitor needs to be 1080p otherwise the location of the elements are wrong
* Pray and wait for creds
* Single/Multiple Monitors
* Windows 10
* Within a Cobalt Strike implant run execute-assembly C:/{location of exe}
- NetNTLMv2PasswordChecker [opdsealey](https://github.com/opdsealey/NetNTLMv2PasswordChecker)SharpLocker helps get current user credentials by popping a fake Windows lock screen, all output is sent to Console which works perfect for Cobalt Strike. It is written in C# to allow for direct execution via memory injection using techniques such as execute-assembly found in Cobalt Strike or others, this method prevents the executable from ever touching disk. It is NOT intended to be compilled and run locally on a device. 
