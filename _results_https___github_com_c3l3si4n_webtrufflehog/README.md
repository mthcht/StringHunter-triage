
![Extension Popup](popup.png)
![WebTruffleHog Logo](icons/icon128.png)
# Credits
# Troubleshooting
# Usage
# Warning
# WebTruffleHog
## How it works?
## Installation
## Key Features
### Prerequisites
- Chrome or Chromium-based browser
- If the tool is not working, you can check the logs in /opt/webtrufflehog/webtrufflehog.log
- If you want to remove the tool, you can disable the extension in chrome://extensions and remove the native messaging host in your chrome directory.
- Linux-based operating system
- Python 3.x
- Results are saved in /opt/webtrufflehog/results.json
- TruffleHog (must be available in system PATH)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) and Dylan from TruffleSec1. Clone this repository: 
2. Run the setup script pointing to your Chrome/Chromium config directory. (You can find that in chrome://version)
3. Reload your browser
4. Open chrome://extensions
5. Enable "Developer mode"
6. Click "Load unpacked"
7. Select the "/opt/webtrufflehog" directory and load the extension
8. Now you should see the extension icon in the toolbar. The tool works passively and is always scanning all visited URLs on your browser. 
The implementation requires a Native Messaging Host manifest in Chrome's configuration directory (typically ~/.config/google-chrome on Linux systems), which establishes the bridge between the extension and the TruffleHog scanner process. 
The native host functions as a wrapper for the TruffleHog scanner, executing in an isolated process for security and stability. When receiving a URL, it initiates a fresh HTTP request to fetch and analyze the content, as direct access to Chrome's cache or local storage is architecturally restricted. While this approach ensures accurate scanning, it introduces limitations for authenticated sessions and dynamically generated content.
The tool works passively and is always scanning all visited URLs on your browser. 
WebTruffleHog is a Chrome/Chromium extension that scans web traffic in real-time for exposed secrets using TruffleHog. It helps security professionals, bug bounty hunters and developers identify potential security risks by detecting sensitive information like API keys, passwords, and tokens that might be accidentally exposed in web responses.
WebTruffleHog leverages Chrome's webRequest API, specifically the onCompleted event listener, to analyze completed HTTP requests. Upon event triggering, the extension establishes communication with a native host process through Chrome's Native Messaging protocol.
While I do this, I don't advise using this tool on your main browser. It probably takes quite a bit of performance overhead and could lag your browser, specially in high-traffic environments.
You can view the results in the extension popup by clicking the icon in the toolbar.
```
```bash
git clone https://github.com/c3l3si4n/webtrufflehog.git
sudo ./setup.sh --chrome-dir /path/to/chrome/config
