
# SCCMVNC
## Compile
## Connect to the host via native SCCM Remote Control tool
## Details
## Usage
CmRcViewer.exe <target hostname/IP>
I have attached a copy of the files required to use the native SCCM Remote Control tool. However, it is highly recommended to copy from your SCCM server under the `C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\i386\`.
Imagine being able to connect to any SCCM-managed system using a VNC-like connection without the need for installing additional malicious modules, and even doing so remotely by exploiting SCCM Remote Control features.
Re-configure SCCM Remote Control setting to mute all the user conent requirement and notifications:
Read existing SCCM Remote Control setting:
SCCMVNC.exe read [/target:CLIENT01]
SCCMVNC.exe reconfig [/target:CLIENT01] [/viewonly] [viewer:user01,user02]
``````
c:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe SCCMVNC.cs
https://www.netero1010-securitylab.com/red-team/abuse-sccm-remote-control-as-native-vnc
