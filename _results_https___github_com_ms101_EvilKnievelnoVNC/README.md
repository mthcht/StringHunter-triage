
                                                     
        ./start.sh dynamic http://example.com
        1280x720  16bits: ./start.sh 1280x720x16 http://example.com
        1280x720  24bits: ./start.sh 1280x720x24 http://example.com
        1920x1080 16bits: ./start.sh 1920x1080x16 http://example.com
        1920x1080 24bits: ./start.sh 1920x1080x24 http://example.com
    * add an email address per victim
    * admin pw for dashboard
    * collected credentials
    * define own TLS certificate+key location in setup.sh
    * docker, bash and realpath required as basic dependencies, screen/byobu/lazydocker is recommended
    * maximum amount of instances (>=300 MB of RAM per active session)
    * monitor active victims in real-time
    * overview of phishing campaign progress
    * place your own TLS certificate, define location in setup.sh
    * react on victim's actions: view session, overtake (authenticated) session or reset session
    * server should be reachable via a phishing domain with valid TLS certificate
    * sha1 `AE:28:1B:05:5B:C0:55:41:22:DA:7C:6F:D2:51:8D:D1:11:B2:7C:21`
    * sha256 `D0:B6:9D:86:6D:AE:B4:E1:CA:F0:C1:F5:4D:82:45:7E:13:06:CD:1A:DE:49:A3:80:DC:21:6A:5C:A8:F4:84:1B`
    * target and phishing domain
    * there is no guarantee for anything, check the code and test it before usage
    * there needs to be at least another container running before haproxy is started! (haproxy limitation)
    * use responsibly and only in legal manners
    * with some adjustments, it can be placed in the path of the URL as well
   * for a reset stop all containers and run `./setup.sh clean`, removes all generated and collected data
   * or run each container manually with its `./run.sh` script in controller/, haproxy/, EvilnoVNC/. Control via lazydocker
   * run centrally with `./run.sh` (BETA)
  ---------------- by @JoelGMSec --------------
  _____       _ _          __     ___   _  ____
 |  _| \ \ / / | | '_ \ / _ \ \ / /|  \| | |
 | ____|_   _(_) |_ __   __\ \   / / \ | |/ ___|
 | |___ \ V /| | | | | | (_) \ V / | |\  | |___
 |_____| \_/ |_|_|_| |_|\___/ \_/  |_| \_|\____|
![Logo](img/logo.png)
![dashboard](img/dashboard.png)
![targets](img/targets.png)
# Contact
# Credits and Acknowledgments
# Download
# EvilKnievelnoVNC
# EvilnoVNC
# Features & To Do
# License
# Requirements
# Support
# Usage
## Advanced Usage
## Features
## See Also
## Setup
## Technical Overview
## To Do List
## Usage
### The detailed guide of use can be found at the following link:
* Chromium extension inside noVNC that monitors the victim's activity
* HAproxy used as loadbalancer and gatekeeper
* Running on multiple Docker containers with internal networking
* [CuddlePhish](https://github.com/fkasler/cuddlephish) using WebRTC
* [MultiEvilnoVNC](https://github.com/wanetty/MultiEvilnoVNC)
* [NoPhish](https://github.com/powerseb/NoPhish)
* a victim's user agent is replicated
* access to EvilnoVNC sessions is limited to generated URLs with random victim-specific identifier in parameter
* add Squid proxy for accessing target sites over same IP when Chromium profile has been copied to admin
* admin dashboard
* after setup, run EvilKnievelnoVNC components
* auto block users after successful authentication, presenting a custom message/page
* block user if a specific (session) cookie pops up (halfway implemented, see EvilnoVNC/Files/content.js)
* blocking users on successful login requires at least one defined search string (EvilnoVNC/Files/content.js)
* by default a self-signed TLS certificate will be presented (CN: testing-server) with the following fingerprints
* caution
* clone repo to server
* concurrent [EvilnoVNC](https://github.com/JoelGMSec/EvilnoVNC) instances, as many as your server can handle
* configure victims in the dashboard via "Manage Targets"
* consider adapting error messages to impede suspision (haproxy/503.http), e.g. in the design of the target site
* consider adjusting timezone info in config files (grep), the default is Europe/Berlin
* consider customizing the error page when users get bocked (EvilnoVNC/Files/vnc_light.html)
* consider customizing the name of the identifier URL parameter (haproxy/haproxy.cfg and controller/src/*/*.php)
* consider customizing the preloading page to fit to the target site (EvilnoVNC/Files/index.php)
* consider running controller and haproxy manually with their respective run.sh for debugging and insights
* customize variables in setup.sh
* dynamic resolution mode with preloading page is currently the default
* keylog, decrypted cookies, Chromium profile and downloads are put in the central Loot directory (docker volume)
* manipulate target site via Chromium extension, e.g. hide alternative login methods such as hardware token, or perform any action in the name of the victim
* nginx for simple dashboard
* real dynamic resolution: adapt noVNC canvas when victim changes their window size
* rebuild admin dashboard
* run setup.sh from its directory (`./setup.sh`)
* send the generated URLs to the victims and monitor the activity in the dashboard
* stress test implementation for lots of concurrent activity (feedback is welcome)
* victim actions are logged to accesslog.txt and submitlog.txt
* victim data and statistics is stored in a central targets.json
* victims can paste text to noVNC via dirty trick
* when running EvilKnievelnoVNC the admin dashboard is reachable via the defined URL and basic auth credentials (<URL>/phishboard)
**EvilnoVNC** is a Ready to go Phishing Platform. 
- Chromium
- Docker
- [ ] Replicate real user-agent and other stuff
- [X] Basic keylogger
- [X] Decrypt cookies in real time
- [X] Disable access to Thunar
- [X] Disable key combinations (like Alt+1 or Ctrl+S)
- [X] Disable parameters in URL (like password)
- [X] Dynamic resolution from preload page
- [X] Dynamic title from original website
- [X] Expand cookie life to 99999999999999999
- [X] Export Evil-Chromium profile to host
- [X] Save download files on host
./start.sh -h
<img src="img/arch.png" alt="arch" width="500" />
<p align="center"><img width=600 alt="EvilnoVNC" src="https://github.com/JoelGMSec/EvilnoVNC/blob/main/EvilnoVNC.png"></p>
Additionally, it's necessary to build Docker manually. You can do this by running the following commands:
Dynamic resolution:
Examples:
For more information, you can find me on Twitter as [@JoelGMSec](https://twitter.com/JoelGMSec) and on my blog [darkbyte.net](https://darkbyte.net).
In addition, this tool allows us to see in real time all of the victim's actions, access to their downloaded files and the entire browser profile, including cookies, saved passwords, browsing history and much more.
It's recommended to clone the complete repository or download the zip file.\
Original idea by [@mrd0x](https://twitter.com/mrd0x): https://mrd0x.com/bypass-2fa-using-novnc \
This project is licensed under the GNU 3.0 license - see the LICENSE file for more details.
This software does not offer any kind of guarantee. Its use is exclusive for educational environments and / or security audits with the corresponding consent of the client. I am not responsible for its misuse or for any possible damage caused by it.
Unlike other phishing techniques, EvilnoVNC allows 2FA bypassing by using a real browser over a noVNC connection.
Usage:  ./start.sh $resolution $url
Weaponized EvilnoVNC: scalable and semi-automated MFA-Phishing via "browser-in-the-middle"
You can support my work buying me a coffee:
[<img width=250 alt="buymeacoffe" src="https://cdn.buymeacoffee.com/buttons/v2/default-blue.png">](https://www.buymeacoffee.com/joelgmsec)
```
cd EvilnoVNC ; sudo chown -R 103 Downloads
git clone https://github.com/JoelGMSec/EvilnoVNC
https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc
sudo docker build -t joelgmsec/evilnovnc .
