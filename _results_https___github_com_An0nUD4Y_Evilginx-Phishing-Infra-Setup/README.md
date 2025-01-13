
    
      
        			//Organization: []string{"Gophish"},
        			Organization: []string{"Microsoft Corporation"},
        		SerialNumber: serialNumber,
        		Subject: pkix.Name{
        		},
        	template := x509.Certificate{
        
          
            			// Handle error - Obfuscation failed
            			d_inject = "<script" + js_nonce + ">" + "function doNothing() {var x =0};" + script + "</script>\n${1}"
            		"cert_path": "example.crt",
            		"cert_path": "gophish_admin.crt",
            		"filename": "",
            		"key_path": "example.key"
            		"key_path": "gophish_admin.key",
            		"level": ""
            		"listen_url": "127.0.0.1:60002",
            		"listen_url": "127.0.0.1:8080",
            		"trusted_origins": []
            		"use_tls": false,
            		"use_tls": true,
            		//d_inject = "<script" + js_nonce + ">" + "function doNothing() {var x =0};" + script + "</script>\n${1}"
            		d_inject = "<script" + js_nonce + " type=\"application/javascript\" src=\"" + src_url + "\"></script>\n${1}"
            		d_inject = "<script" + js_nonce + ">" + "function doNothing() {var x =0};" + obfuscatedScript + "</script>\n${1}"
            		if err != nil {
            		minifier := minify.New() // "github.com/tdewolff/minify/js"
            		minifier.AddFunc("text/javascript", js.Minify)
            		obfuscatedScript, err := minifier.String("text/javascript", script)
            		return body
            		}
            	"admin_server": {
            	"contact_address": "",
            	"db_name": "sqlite3",
            	"db_path": "gophish.db",
            	"logging": {
            	"migrations_prefix": "db/db_",
            	"phish_server": {
            	fmt.Fprintln(w, "User-agent: *\nDisallow: /*/*\nDisallow: /.git/*")
            	http.Error(w, "Try again!", http.StatusNotFound)
            	if script != "" {
            	re := regexp.MustCompile(`(?i)(<\s*/body\s*>)`)
            	var d_inject string
            	}
            	} 
            	} else if src_url != "" {
            	} else {
            	},
            
                    
                        proxy_pass http://backend;
                        proxy_pass https://backend_https;
                        proxy_set_header Host $host;
                        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                        proxy_set_header X-Forwarded-Proto $scheme;
                        proxy_set_header X-Real-IP $remote_addr;
                        return 403;
                    # Reject requests with "bot" or "Bot" in User-Agent
                    # Reject requests with user agent other than "iamdevil"
                    if ($http_user_agent != "iamdevil") {
                    if ($http_user_agent ~* (bot|Bot)) {
                    listen 60001 ssl default_server;
                    listen 80 default_server;
                    location / {
                    server localhost:60002;
                    server localhost:8080;
                    ssl_certificate /root/Phishing/gophish-mod/gophish_admin.crt;
                    ssl_certificate_key /root/Phishing/gophish-mod/gophish_admin.key;
                    }
                # Define event processing parameters here
                # HTTP server
                # HTTPS server
                server {
                upstream backend {
                upstream backend_https {
                worker_connections 1024; # Adjust according to your requirements
                }
            # /etc/nginx/nginx.conf
            - Responsible evilginx Code Functionality (For cookie-Name) : https://github.com/kgretzky/evilginx2/blob/9e32484719681892945130187ea52737b3d72051/core/http_proxy.go#L1984
            - Responsible evilginx Code Functionality (For cookie-Value) : https://github.com/kgretzky/evilginx2/blob/9e32484719681892945130187ea52737b3d72051/core/http_proxy.go#L895
            - To automate from phishlet Check this PR : https://github.com/kgretzky/evilginx2/pull/1006
            - `resp.Header.Set("Referrer-Policy", "no-referrer")`
            - the full snippet js blob logic is here https://gist.github.com/rad9800/bb73de360fc07ac544f0bc9faac9082d
            // RobotsHandler prevents search engines, etc. from indexing phishing materials
            //Modified Response
            ```
            ```go
            ```jsx
            ```yaml
            events {
            func (ps *PhishingServer) RobotsHandler(w http.ResponseWriter, r *http.Request) {
            func customNotFound(w http.ResponseWriter, r *http.Request) {
            http {
            {
            {key:'a', value: 'HOW'}
            {key:'b', value: 'MUCH'}
            {key:'d', value: 'IS'}
            {key:'e', value: 'THE'}
            {key:'f', value: 'PHISH'}
            {key:'q', value: '{id}'}
            }
        ![Untitled](img/Untitled%201.png)
        ![Untitled](img/Untitled.png)
        # Only Work in Evilginx Pro Version
        # Similar functionality can be implemented in public version as well.
        - Add below custom function in `controllers/phish.go` file
        - Add some sub_filters to modify the content of the pages to avoid content based detections, like (Favicon, form title font or style, or anything which seems relevant)
        - Be aware of this research : https://catching-transparent-phish.github.io/catching_transparent_phish.pdf , repo - https://catching-transparent-phish.github.io/
        - Block the feedback/telemetry/logs/analytics subdomains using the phishlet sub_filters which can log the domain or may help later on analysis.
        - Bypassing (CSS,JS) Canary AiTM Detection : https://insights.spotit.be/2024/06/03/clipping-the-canarys-wings-bypassing-aitm-phishing-detections/
        - Easy orchestration in the Microsoft Admin portal of custom domains, create a ton of fake accounts.
        - Emails come from legit Microsoft IPs and domains, so you don't have to worry about domain categorization or lifespan since it's Microsoft.
        - Emails originate from legit Microsoft SMTP servers so they can't block it.
        - Host Evilginx at Azure and use their domain (limit proxy host in phishlet to 1 or find a way , may be create multiple azure sub domains and try with that)
        - Like images name , example : pixel.png , modify it to something else.
        - M365 allows you to set arbitrary display names. So in a targets outlook the email can look like its from `admin@domain.com` but it's really from `admin@maliciousdomain.com` (Technical people can easily figure this out though)
        - Make sure to add "[github.com/tdewolff/minify/js](http://github.com/tdewolff/minify/js)" in imports
        - Make sure to modify all the instances of `"rid"` to something else.
        - Make sure to not leak your Evilginx infra IP, Check the DNS history to make sure its not stored anywhere (Analysts may look for older DNS Records of the domain)
        - Modify Unauth redirect static contents
        - Modify code to request wildcard certificates for root domain from Let'sEncrypt other than requesting for each subdomains (As mentioned in Kuba's blog) - Check this repo for reference https://github.com/ss23/evilginx2
        - Modify the respective code in phish.go file to below one.
        - Now replace all instances of `http.NotFound(w, r)` to `customNotFound(w, r)`
        - Put evilginx behind a proxy to help against TLS fingerprinting (JA3 and JA3S)
        - Read this for more : https://insights.spotit.be/2024/06/03/clipping-the-canarys-wings-bypassing-aitm-phishing-detections/
        - Reduce the Number of proxyhosts in phishlet if possible to reduce content loading time.
        - Remove IOCs (X-Evilginx header and Default Cert Details)
        - Rewrite URLs on Phishing Pages to avoid detection through URL Path pattern matching (by Kuba).
        - Rule 1: Cookie name=XXXX-XXXX & value=64_hex_chars
        - Rule 1: Cookie name=XXXX-XXXX & value=64_hex_chars - https://gist.github.com/rad9800/bb73de360fc07ac544f0bc9faac9082d#file-index-js-L130
        - Rule 2: Script path=/s/64_hex_chars.js with content-length=0
        - Rule 3: Both Rule 1 & Rule 2 present
        - See if js-injected is static or dynamic , if static modify the evilginx js-inject code to create dynamic/obfuscated version of your js for each user/target.
        - Targets who get the encrypted email are the only ones who can open it, if they forward it to their DFIR, they will have to login as that user to even see your message.
        - These are also present in evilginx3.3 source code , So make sure to modify there as well.
        - Use cloudflare in between if possible/feasible (You have to configure the SSL Settings correctly, change it to Full in cloudflare settings)
        - Use some known ASN blacklist to avoid getting detected like here (https://github.com/aalex954/evilginx2-TTPs#ip-blacklist)
        - You need to change the gophish `config.json` to change the ports for http from 80 to 8080 and https from default to 60002, as shown below
        - `service nginx start`
        - haven't had any problem
        - https://blog.thinkst.com/2024/01/defending-against-the-attack-of-the-cloned-websites.html
        - https://github.com/juzeon/spoofed-round-tripper
        - https://github.com/refraction-networking/utls
        - the full snippet js blob logic is here https://gist.github.com/rad9800/bb73de360fc07ac544f0bc9faac9082d
        - useful service but honestly, You need Pro pain plan to be lucky not to be on a spamlist
        1. Make an account with a Microsoft 365 Business Standard (or higher) license.  ([https://www.microsoft.com/en-us/microsoft-365/enterprise/office365-plans-and-pricing](https://www.microsoft.com/en-us/microsoft-365/enterprise/office365-plans-and-pricing))
        2. Create a generic company name.
        3. Get a Azure Information Protection Premium P1 license to be able to use encryption. ([https://support.microsoft.com/en-us/office/encrypt-email-messages-373339cb-bf1a-4509-b296-802a39d801dc](https://support.microsoft.com/en-us/office/encrypt-email-messages-373339cb-bf1a-4509-b296-802a39d801dc))
        4. Import your domain.
        5. Create a user with an email to your custom domain to send the phish and give it the M365 Business and Azure IPP P1 license.
        6. Draft your phishing message in Outlook online and press the encrypt button
        7. ????
        8. Profit
        Controllers > api > util.go
        ```
        ```go
        ```markdown
        ```yaml
        domains: ['www.linkedin.com']
        models > testdata > email_request.go
        models > testdata > email_request_test.go
        models > testdata > maillog.go
        models > testdata > maillog_test.go
        models > testdata > smtp_test.go
        path: '/this/is/not/the/path/you/are/looking/for.php'
        paths: ['^/login$']
        query:
        rewrite:
        rewrite_urls:
        trigger:
    - Also to avoid the static injected js code signature detection , You can modify the code as below
    - Block Referrer headers from leaking your phishing domain name - check [this](https://insights.spotit.be/2024/06/03/clipping-the-canarys-wings-bypassing-aitm-phishing-detections/) research blog for reference :
    - Bluecoat/Symantec - [https://sitereview.bluecoat.com/#/](https://sitereview.bluecoat.com/#/)
    - Bobber : [https://github.com/Flangvik/Bobber](https://github.com/Flangvik/Bobber)
    - Brevo : https://www.brevo.com/free-smtp-server/
    - BrightCloud - http://www.brightcloud.com/tools/url-ip-lookup.php
    - Chameleon : https://github.com/mdsecactivebreach/Chameleon
    - Change 404 response
    - Change the Certificate Properties in `util/util.go` file
    - Change the default Admin server port in `config.json` file.
    - Change the gophish email headers sequence pattern. It may be used to detect the gophish (From BreakDev Red Community).
    - Check if target site is using some sort of canary tokens (CSS, JS) and avoid them
    - Checkpoint - [https://www.checkpoint.com/urlcat/main.htm](https://www.checkpoint.com/urlcat/main.htm) (needs registration)
    - Cyren - [https://www.cyren.com/security-center/url-category-check-gate](https://www.cyren.com/security-center/url-category-check-gate)
    - Define your own CSP (Content security Policy) to avoid telemetry/canary/detection by leaking phishing domain.
    - Domainhunter: https://github.com/threatexpress/domainhunter
    - Evilginx Docs : [https://help.evilginx.com/](https://help.evilginx.com/)
    - Evilginx Less Known Techniques : [https://github.com/An0nUD4Y/Evilginx2-Phishlets?tab=readme-ov-file#some-less-known-techniques](https://github.com/An0nUD4Y/Evilginx2-Phishlets?tab=readme-ov-file#some-less-known-techniques)
    - Evilginx Mastery Course : [https://academy.breakdev.org/evilginx-mastery](https://academy.breakdev.org/evilginx-mastery)
    - Evilginx Phishlets Collections : [https://github.com/An0nUD4Y/Evilginx2-Phishlets](https://github.com/An0nUD4Y/Evilginx2-Phishlets)
    - For advance preventions, You can modify the static folder as well and rename it to something else, also rename the files inside it to avoid path based detection. Just do not forget to modify the relevance source code as well.
    - FortiGuard - [https://www.fortiguard.com/webfilter](https://www.fortiguard.com/webfilter)
    - Generate QR : [https://github.com/Flangvik/QRucible](https://github.com/Flangvik/QRucible)
    - Gmail
    - IBM X-force - [https://exchange.xforce.ibmcloud.com](https://exchange.xforce.ibmcloud.com/)
    - If you are having issues with delivering emails due to email filtering, consider using Microsoft 365 and Azure IPP to send encrypted emails to your targets!
    - JA4 Database : [https://ja4db.com/](https://ja4db.com/)
    - JA4 fingerprint evasion
    - LightSpeed Systems - https://archive.lightspeedsystems.com/
    - MailGun - https://app.mailgun.com/
    - McAfee - [https://www.trustedsource.org](https://www.trustedsource.org/)
    - Modify Gophish Tracking Pixel signature to avoid detection based on signatured tracking pixel.
    - Modify Test Email Message Signatures, To avoid detection during SMTP Testing. `Controllers > api > util.go`
    - Modify core/cert.db file as well
    - Modify the lure/session identifier cookies signatured pattern and value (by @[rad9800](https://x.com/rad9800/status/1858242066356019317?s=46&t=mlJvZy0Zrkrxzuvtt7m2cQ) )
    - More Can be found at : [https://lots-project.com/](https://lots-project.com/)
    - Open Redirect at : [https://googleweblight.com/i?u=m4lici0u5.com](https://googleweblight.com/i?u=m4lici0u5.com)
    - Outlook
    - Palo Alto Wildfire - [https://urlfiltering.paloaltonetworks.com](https://urlfiltering.paloaltonetworks.com/)
    - Push Security's chrome extension detect evilginx with some pretty brittle rules
    - Remove X-Evilginx header (Check all the code lines with `req.Header.Set` and comment relevant functions)
    - Remove `X-Gophish` instances ( `X-Gophish-Contact` , `X-Gophish-Signature`)
    - Remove `const ServerName= "gophish"` and change it to `const ServerName= "IGNORE"` in file `config/config.go`
    - Remove robots.txt hardcoded response and modify it in file `controllers/phish.go`
    - Rewrite URLs on Phishing Pages to avoid detection through URL Path pattern matching (by Kuba). [This Feature not available in evilginx Public Version, You have to implement it yourself.]
    - Screenshot
    - Search for `<html>` in core/http_proxy.go file and modify the html code to remove any static signatures.
    - Setup a Microsoft365 Tenant
    - Slides : [https://github.com/kgretzky/talks/blob/main/2024/x33fcon/a-smooth-sea-never-made-a-skilled-phisherman.pdf](https://github.com/kgretzky/talks/blob/main/2024/x33fcon/a-smooth-sea-never-made-a-skilled-phisherman.pdf)
    - Sophos - https://secure2.sophos.com/en-us/support/contact-support.aspx  (submission only; no checking) (Click Submit a Sample -> Web Address)
    - Steps
    - Talk : [https://youtu.be/Nh99d3YnpI4?si=Ltwus2PS0z97gf2R](https://youtu.be/Nh99d3YnpI4?si=Ltwus2PS0z97gf2R)
    - Trend Micro - [https://global.sitesafety.trendmicro.com/](https://global.sitesafety.trendmicro.com/)
    - TryCloudflare : [https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/)
    - Use Nginx to proxy traffic through it to avoid any Golang Server Fingerprint
    - Use SendGrid - http://sendgrid.com/
    - Websense - [https://csi.forcepoint.com](https://csi.forcepoint.com/) & [https://www.websense.com/content/SiteLookup.aspx](https://www.websense.com/content/SiteLookup.aspx) (needs registration)
    - [Amazon AWS SES](https://aws.amazon.com/ses/)
    - [https://cyberwarfare.live/wp-content/uploads/2023/08/Certified-Red-Team-CredOps-Infiltrator-CRT-COI-1.pdf](https://cyberwarfare.live/wp-content/uploads/2023/08/Certified-Red-Team-CredOps-Infiltrator-CRT-COI-1.pdf)
    - [https://expireddomains.net/](https://expireddomains.net/)
    - [https://gist.github.com/RedTeamOperations/33f245a777c9b322b0466b59d6687f15](https://gist.github.com/RedTeamOperations/33f245a777c9b322b0466b59d6687f15)
    - [https://gist.github.com/dunderhay/d5fcded54cc88a1b7e12599839b6badb](https://gist.github.com/dunderhay/d5fcded54cc88a1b7e12599839b6badb)
    - [https://github.com/An0nUD4Y/Evilginx2-Phishlets#securing-evilginx-infra-tips](https://github.com/An0nUD4Y/Evilginx2-Phishlets#securing-evilginx-infra-tips)
    - [https://github.com/kgretzky/evilqr](https://github.com/kgretzky/evilqr) , [https://breakdev.org/evilqr-phishing/](https://breakdev.org/evilqr-phishing/)
    - [https://github.com/swagkarna/EvilJack](https://github.com/swagkarna/EvilJack)
    - [https://github.com/zolderio/AITMWorker](https://github.com/zolderio/AITMWorker)
    - [https://m3rcer.netlify.app/redteaming/spamfilterbypass/](https://m3rcer.netlify.app/redteaming/spamfilterbypass/)
    - [https://techcommunity.microsoft.com/t5/microsoft-security-experts-blog/hunting-for-qr-code-aitm-phishing-and-user-compromise/bc-p/4054850](https://techcommunity.microsoft.com/t5/microsoft-security-experts-blog/hunting-for-qr-code-aitm-phishing-and-user-compromise/bc-p/4054850)
    - [https://untrustednetwork.net/en/2024/02/26/google-open-redirect/](https://untrustednetwork.net/en/2024/02/26/google-open-redirect/)
    - https://youtu.be/EYUp_MNtJIk?si=sg_9RQggDvqOSLNL
    - https://youtu.be/KhdzIPPW4W0?si=E4CmWx0iO8EaR6JF
    - https://youtu.be/py68OE4tQ4Q?si=n6QlNuro88c1PRzn
    - https://youtu.be/tHNi5BzScVo?si=H2czog19AmTp_O26
# Phishing Engagement Infrastructure Setup Guide
## AiTM Post Exploitation / Phishing Research Blogs/Talks
## Awesome Enterprise Email Security
## Blogs/Talks
## Delivering Emails in Inbox
## Domain Purchase and Categorization Techniques
## Improve Phishing Email Writing Using Tools
## Other Techniques
## Phishing Engagements With Evilginx
## Red Team/Phishing Infra Automation
## Securing GoPhish Infra
## Test Email Spammyness
### Defense Tactics Against Evilginx
### Evilginx Research Blogs/Talks :
- (Improve Evilginx email delivery trust) Adding SPF, DMARC, DKIM, MX records : [https://fortbridge.co.uk/research/add-spf-dmarc-dkim-mx-records-evilginx/](https://fortbridge.co.uk/research/add-spf-dmarc-dkim-mx-records-evilginx/)
- **Building Evilginx Phishlets**
- **Evilginx Installation Scripts**
- **Securing Evilginx Infra tips -**
- A smooth sea never made a skilled phisherman - Kuba Gretzky (x33fc0n 2024) :
- AiTm (Post Exploitation) : https://www.youtube.com/live/WY4mH-8TbWY?si=LkZ1LuduDln1vRuj
- Automating Domain Reputation Checking/Submission
- BHIS | How to Build a Phishing Engagement - Coding TTP's : [https://m.youtube.com/watch?si=YTjMa8XBusj_tPdc&v=VglCgoIjztE&feature=youtu.be](https://m.youtube.com/watch?si=YTjMa8XBusj_tPdc&v=VglCgoIjztE&feature=youtu.be)
- BITB : [https://mrd0x.com/browser-in-the-browser-phishing-attack/](https://mrd0x.com/browser-in-the-browser-phishing-attack/)
- Bypassing Canary AiTM Detection : [https://insights.spotit.be/2024/06/03/clipping-the-canarys-wings-bypassing-aitm-phishing-detections/](https://insights.spotit.be/2024/06/03/clipping-the-canarys-wings-bypassing-aitm-phishing-detections/)
- Check for Expired Domain and Possibly purchase the good ones
- Decode-Spam-Headers : https://github.com/mgeeky/decode-spam-headers
- Detecting evilginx using JA3, JA3S, JA4 fingerprinting
- Domain Categorization
- Drink Like a Phish - How to Make Your Phishing Sites Blend In ****: [https://posts.specterops.io/drink-like-a-phish-b9e91d0b5677](https://posts.specterops.io/drink-like-a-phish-b9e91d0b5677?source=collection_home---6------0-----------------------)
- EvilGoPhish : [https://github.com/fin3ss3g0d/evilgophish](https://github.com/fin3ss3g0d/evilgophish)
- EvilQR - QR Phishing
- Evilginx + BITB + Evasion Tactics : [https://youtu.be/p1opa2wnRvg](https://youtu.be/p1opa2wnRvg)
- Evilginx + BITB - [https://www.youtube.com/watch?v=luJjxpEwVHI&feature=youtu.be](https://www.youtube.com/watch?v=luJjxpEwVHI&feature=youtu.be)
- Feeding the Phishes : ****https://posts.specterops.io/feeding-the-phishes-276c3579bba7
- For Abusing legit sites for Phishing : [https://lots-project.com/](https://lots-project.com/)
- Google Open Redirection for phishing
- HTML-Linter (avoid common phishing email words) : [https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing/phishing-HTML-linter.py](https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing/phishing-HTML-linter.py)
- Hook, Line and Phishlet - Conquering AD FS With Evilginx : [https://research.aurainfosec.io/pentest/hook-line-and-phishlet/](https://research.aurainfosec.io/pentest/hook-line-and-phishlet/)
- Hook, Line and Sinker: Phishing Windows Hello for Business using Evilginx : [https://medium.com/@yudasm/bypassing-windows-hello-for-business-for-phishing-181f2271dc02](https://medium.com/@yudasm/bypassing-windows-hello-for-business-for-phishing-181f2271dc02)
- Like Shooting Phish in a Barrel - Bypassing Link Crawlers : ****https://posts.specterops.io/like-shooting-phish-in-a-barrel-926c1905bb4b
- Method - 2 (By Andre Rosario - From **BreakDev Red** Discord)
- Method -1
- Modifications in gophish source code and file structure to Secure the GoPhish Infra
- NoPhish : [https://github.com/powerseb/NoPhish](https://github.com/powerseb/NoPhish) and [https://badoption.eu/blog/2023/07/12/entra_phish.html](https://badoption.eu/blog/2023/07/12/entra_phish.html)
- O365 Phishing Infrastructure - [https://badoption.eu/blog/2023/12/03/PhishingInfra.html](https://badoption.eu/blog/2023/12/03/PhishingInfra.html)
- Phishing Past Mail Protection Controls using Azure Information Protection
- Phishing Tactics and OPSEC : [https://mgeeky.tech/uploads/WarCon22 - Modern Initial Access and Evasion Tactics.pdf](https://mgeeky.tech/uploads/WarCon22%20-%20Modern%20Initial%20Access%20and%20Evasion%20Tactics.pdf)
- Phishing With CloudFlare Workers
- Phishing the resistant - Phishing for primary Refresh token in Microsoft Entra by Dirk Jan  : [https://youtu.be/tNh_sYkmurI?si=qcb917IB5zHU1fQk](https://youtu.be/tNh_sYkmurI?si=qcb917IB5zHU1fQk)
- Progressive Web Apps (PWA) Phishing : [https://mrd0x.com/progressive-web-apps-pwa-phishing/](https://mrd0x.com/progressive-web-apps-pwa-phishing/)
- Protect Against Modern Phishing : [https://bleekseeks.com/blog/how-to-protect-against-modern-phishing-attacks](https://bleekseeks.com/blog/how-to-protect-against-modern-phishing-attacks)
- Protect Evilginx using cloudflare and HTML obf : [https://www.jackphilipbutton.com/post/how-to-protect-evilginx-using-cloudflare-and-html-obfuscation](https://www.jackphilipbutton.com/post/how-to-protect-evilginx-using-cloudflare-and-html-obfuscation)
- Push Security Phishing Tools Detection : https://gist.github.com/rad9800/bb73de360fc07ac544f0bc9faac9082d
- Smishing : [https://blog.shared-video.mov/systematic-destruction-hacking-the-scammers-pt.-2](https://blog.shared-video.mov/systematic-destruction-hacking-the-scammers-pt.-2)
- The triforce of initial Access : [https://trustedsec.com/blog/the-triforce-of-initial-access](https://trustedsec.com/blog/the-triforce-of-initial-access)
- Tips : Use {{.URL}} parameter in phishing template while using with evilginx ( [https://github.com/kgretzky/evilginx2/issues/1042#issuecomment-2052073864](https://github.com/kgretzky/evilginx2/issues/1042#issuecomment-2052073864))
- Unravelling and Countering Adversary in the middle Phishing - X33fcon 2024 - [https://youtu.be/-W-LxcbUxI4](https://youtu.be/-W-LxcbUxI4?feature=shared)
- Using HoneyTokens to detect AiTM : [https://zolder.io/using-honeytokens-to-detect-aitm-phishing-attacks-on-your-microsoft-365-tenant/](https://zolder.io/using-honeytokens-to-detect-aitm-phishing-attacks-on-your-microsoft-365-tenant/)
- X33fcon 2024 - [https://youtu.be/Nh99d3YnpI4?si=Ltwus2PS0z97gf2R](https://youtu.be/Nh99d3YnpI4?si=Ltwus2PS0z97gf2R)
- [https://cybercx.co.nz/blog/identifying-gophish-servers/](https://cybercx.co.nz/blog/identifying-gophish-servers/)
- [https://cyberwarfare.live/wp-content/uploads/2023/08/OPSEC-on-the-High-Seas_-A-Gophish-Adventure.pdf](https://cyberwarfare.live/wp-content/uploads/2023/08/OPSEC-on-the-High-Seas_-A-Gophish-Adventure.pdf)
- [https://edermi.github.io/post/2021/modding_gophish/](https://edermi.github.io/post/2021/modding_gophish/)
- [https://github.com/dazzyddos/HSC24RedTeamInfra/blob/main/RedTeamInfraAutomation.pdf](https://github.com/dazzyddos/HSC24RedTeamInfra/blob/main/RedTeamInfraAutomation.pdf)
- [https://github.com/gophish/gophish/issues/1553#issuecomment-523969887](https://github.com/gophish/gophish/issues/1553#issuecomment-523969887)
- [https://github.com/puzzlepeaches/sneaky_gophish](https://github.com/puzzlepeaches/sneaky_gophish)
- [https://janbakker.tech/evilginx-resources-for-microsoft-365/](https://janbakker.tech/evilginx-resources-for-microsoft-365/)
- [https://www.sprocketsecurity.com/resources/never-had-a-bad-day-phishing-how-to-set-up-gophish-to-evade-security-controls](https://www.sprocketsecurity.com/resources/never-had-a-bad-day-phishing-how-to-set-up-gophish-to-evade-security-controls)
- [https://www.youtube.com/watch?v=wTLB0Yh70_0](https://www.youtube.com/watch?v=wTLB0Yh70_0)
- https://github.com/0xAnalyst/awesome-email-security
- https://nicolasuter.medium.com/aitm-phishing-with-azure-functions-a1530b52df05
- https://posts.specterops.io/one-phish-two-phish-red-teams-spew-phish-1a2f02010ed7
- https://posts.specterops.io/phish-out-of-water-aaeb677a5af3
- https://pushsecurity.com/blog/a-new-class-of-phishing-verification-phishing-and-cross-idp-impersonation/
- https://trustedsec.com/blog/the-triforce-of-initial-access
- https://www.mail-tester.com/
- https://youtu.be/6jYZQKDlKco?si=cpfd4tWQ4V8ZAZaI
- mgeeky : [https://github.com/mgeeky/Penetration-Testing-Tools/tree/master/phishing](https://github.com/mgeeky/Penetration-Testing-Tools/tree/master/phishing)
- noVNC Phishing : [https://adepts.of0x.cc/novnc-phishing/](https://adepts.of0x.cc/novnc-phishing/)
- noVNC and Docker : [https://powerseb.github.io/posts/Another-phishing-tool/](https://powerseb.github.io/posts/Another-phishing-tool/)
> 
> **Note:** These are copy of my [personal notes](https://an0nud4y.notion.site/Phishing-Red-Team-Engagement-Infra-1c6fba8f2d854a14ba76320284161c5e?pvs=4). Please Do not completely rely on them.
> These modifications will also work in the latest evilginx + gophish version i.e evilginx3.3
