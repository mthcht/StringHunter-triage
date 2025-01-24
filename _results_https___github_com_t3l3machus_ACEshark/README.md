
                        ACEshark creates log files every time you run the extractor script on a machine (stored in ~/.ACEshark). Use this option to regenerate a services config analysis from a log file. This
                        Change the delimiter value used for service config serialization (default: #~). Use this option cautiously. It is rarely needed.
                        Change the temporary filename used to store the extracted services configuration before transferring the data via HTTP (default: sc.txt).
                        List only those service ACEs that can potentially be abused by your user, based on their SID and group membership, with at least (WRITE_PROPERTY AND CONTROL_ACCESS) or GENERIC_ALL
                        Optional: Path to the TLS certificate for enabling HTTPS.
                        Optional: Path to the private key for the TLS certificate.
                        Provide a comma-separated list of integers representing the generic access rights to match. Only service ACEs that your user may be able to abuse, based on their SID and group
                        Similar to --interesting-only but with stricter criteria. A service is labeled as a great candidate for privilege escalation if the service's START_TYPE == DEMAND_START AND TYPE ==
                        WIN32_OWN_PROCESS AND your user has (WRITE_PROPERTY AND CONTROL_ACCESS) OR GENERIC_ALL privileges.
                        Your server IP or domain name. This option cannot be used with -f.
                        approach, though less elegant, is more likely to succeed in most cases.
                        membership matching the provided rights, will be listed. Use -lg to list all predefined generic access rights.
                        option cannot be used with -s.
                        privileges.
                        the current user's SID and group membership information. By default, the WRITE_PROPERTY and CONTROL_ACCESS rights are highlighted for simplicity when they are present.
  -a, --audit           Audit mode. Analyzes all service ACEs without searching for user-specific abusable services (Long output). This option also downgrades the extractor script, omitting the retrieval of
  -c CERTFILE, --certfile CERTFILE
  -d DELIMITER, --delimiter DELIMITER
  -e, --encode          Generate Base64-encoded services configuration extractor script instead of raw PowerShell.
  -f FILE_INPUT, --file-input FILE_INPUT
  -g, --great-candidates
  -gs, --get-service    This option modifies the extractor script to use Get-Service for listing available services. While cleaner, it may not work with a low-privileged account. The default Get-ChildItem
  -h, --help            show this help message and exit
  -i, --interesting-only
  -k KEYFILE, --keyfile KEYFILE
  -lg, --list-generic   List all predefined generic access rights.
  -p PORT, --port PORT  HTTP / HTTPS server port (default: 80 / 443).
  -q, --quiet           Do not print the banner on startup.
  -s SERVER_ADDRESS, --server-address SERVER_ADDRESS
  -v, --verbose         Print the user's SID and group membership info as well (not applicable in Audit mode).
  -x CUSTOM_MODE, --custom-mode CUSTOM_MODE
  -z CONFIG_FILENAME, --config-filename CONFIG_FILENAME
![aceshark2](https://github.com/user-attachments/assets/09789877-665d-476a-8c2c-a86000380614)
![image](https://github.com/user-attachments/assets/e292d618-1aa2-4431-953f-96c9a888e2a5)
# ACEshark
## How it works
## Installation
## Overview
## Special Thanks
## Usage
## What is it?
## Why?
**Note**: If automatic copy to clipboard of the extractor script fails, you may need to install a copy/paste mechanism, like `sudo apt-get install xclip` or `sudo apt-get install xselect`.
- Audit service permissions for specific users or across all groups and accounts.
- Efficiently identify and analyze service permissions to uncover potential privilege escalation vectors (changing the `binpath` of a service and restarting it).  
- Marios K. Pappas (aka [Pri3st](https://www.github.com/Pri3st)), for helping test the tool!
- [TJ_Null](https://x.com/TJ_Null), for testing and providing valuable feedback!
1. Clone the repository:
1. Even if a service is characterized as a great candidate for privilege escalation according to its ACEs and configuration, there are other Windows security features that may prevent you from actually abusing it.
2. Install dependencies:
2. This is probably not going to be particularly stealthy.
3. Using this tool against hosts that you do not have explicit permission to test is illegal. You are responsible for any trouble you may cause by using this tool.
<img src="https://img.shields.io/badge/Developed%20on-kali%20linux-blueviolet">
<img src="https://img.shields.io/badge/Experimental-ff0000">
<img src="https://img.shields.io/badge/Maintained%3F-Yes-96c40f">
<img src="https://img.shields.io/badge/PowerShell-%E2%89%A5%20v3.0-blue">
ACEshark generates a log file for each extracted services configuration, allowing reports to be regenerated if needed.
ACEshark is a utility designed for rapid extraction and analysis of Windows service configurations and Access Control Entries, eliminating the need for tools like `accesschk.exe` or other non-native binaries.
ACEshark is a utility designed for rapid extraction and analysis of Windows service configurations and Access Control Entries, eliminating the need for tools like accesschk.exe or other non-native binaries.
ACEshark.py [-h] [-s SERVER_ADDRESS] [-p PORT] [-c CERTFILE] [-k KEYFILE] [-f FILE_INPUT] [-i] [-g] [-a] [-x CUSTOM_MODE] [-lg] [-gs] [-e] [-z CONFIG_FILENAME] [-d DELIMITER] [-q] [-v]
BASIC OPTIONS:
EXTRACTOR MODIFICATIONS:
MODES:
OUTPUT:
Running ACEshark starts an HTTP/HTTPS server to act as a listener for service configurations and Access Control Entries. It generates a small extractor script based on the specified options, which the user runs on the target machine. ACEshark then retrieves and processes the data, providing a detailed analysis.
[![License](https://img.shields.io/badge/License-BSD-red.svg)](https://github.com/t3l3machus/ACEshark/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/Python-%E2%89%A5%203.12-yellow.svg)](https://www.python.org/) 
```
cd ACEshark  
git clone https://github.com/t3l3machus/ACEshark
options:
pip3 install -r requirements.txt  
