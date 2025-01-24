
  
    
     
     or 
     sudo apt-get install libssl-dev
     sudo dnf install openssl-devel
     ~$ cd GonnaCry/C
     ~$ gcc main.c lib/func.c lib/struct.c lib/crypto.c -o bin/GonnaCry -lcrypto 
     ~$ make
    daemon
    decryptor
    gonnacry    
    sh comp.sh # to compile the Encryptor
    sh decryptorcomp.sh to compile the Decryptor
    ~$ make clean
    ~$ pyinstaller -F --clean decryptor.py -n decryptor
    ~$ pyinstaller -F --clean main.py -n gonnacry
    ~$ sudo pip install -r requeriments.txt
# C GonnaCry version
# COMPILED VERSIONS OF GONNACRY
# Compiling
# Compiling the code
# DANGER ZONE
# Deleting
# Dependencies
# Disassembly
# Disclaimer
# Features
# GONNACRY WEBSERVER
# GonnaCry Rasomware
# GonnaCry src files
# How this version works:
# Objectives:
# Python GonnaCry version
# Requeriments 
# THIS VERSION IS OUTDATED, GO CHECK PYTHON VERSION
# Test enviroment 
# What's a Ransomware?
# Work flow
**Be aware running C/bin/GonnaCry or Python/GonnaCry/main.py Python/GonnaCry/bin/gonnacry in your computer, it may harm.**
**Be aware running GonnaCry/main.py GonnaCry/bin/gonnacry in your computer, it may harm.**
**Be aware running bin/GonnaCry in your computer, it may harm.**
**How this ransomware encryption scheme works:**
**How this ransomware works:**
**Mentions:**
**Property 1**: The hostile binary code must not contain any secret (e.g. deciphering
**Property 2**: Only the author of the attack should be able to decrypt the
**Property 3**: Decrypting one device can not provide any useful information
**Ransomware Impact on industry**
- Debian and derivates:
- [ ] Change wallpaper -> still figuring out how to save the img on the code.
- [ ] Communicate with the server to exchange private key.
- [ ] Decrypt recover file and read to get the path, key and iv from the file.
- [ ] Download Decryptor
- [ ] Download GonnaCry from dropper
- [ ] Dropper
- [ ] Encrypt recover file with RSA 1024 or 2048.
- [x] Change computer wallpaper -> Gnome, LXDE, KDE, XFCE.
- [x] Changes computer wallpaper -> Gnome, LXDE, KDE, XFCE.
- [x] Communication with the server to decrypt Client-private-key.
- [x] Daemon
- [x] Decrypt all files.
- [x] Decryptor that communicate to server to send keys.
- [x] Encrypt HD/pendrive on the victim machine.
- [x] Encrypt all user files with AES-CBC 256.
- [x] Generate unique Key and IV for each file.
- [x] Kills databases
- [x] Random AES key and IV for each file.
- [x] Save path, key and iv from each file on the desktop (recover file).
- [x] Shred file before removing (Zeroing).
- [x] Works even without internet connection.
- [x] decrypt the private key 
- [x] encrypt AES key with client-public-key RSA-2048.
- [x] encrypt all user files with AES-256-CBC.
- [x] encrypt client-private-key with RSA-2048 server-public-key.
- [x] encrypts AES key with client-public-key RSA-2048.
- [x] encrypts all user files with AES-256-CBC.
- [x] encrypts client-private-key with RSA-2048 server-public-key.
- [x] python webserver
- fedora:
-------------
A ransomware is a type of malware that prevents legitimate users from accessing
Daemon encrypt new files, calls decryptor and change wallpaper
Decryptor try to communicate to server to send the Client private key wich is encrypted.
Functions:
GONNACRY BINARIES
GonnaCry is a linux ransomware that encrypts all the user files with a strong encryption scheme.
GonnaCry is an academic ransomware made for learning and awareness about security/cryptography.
GonnaCry requires openssl Library, instalation below
GonnaCry requires the pycrypto library and requests, installation below
Gonnacry encrypt all files and call Daemon
If u want to test the ransomware, here is the place
Inside the files/ folder, there is some files that will be Encrypted/Decrypted
Its purpose is only to share knowledge and awareness about Malware/Cryptography/Operating Systems/Programming.
Original Repository of the GonnaCry Ransomware.
They have been used for mass extortion in various forms, but the
This Ransomware mustn't be used to harm/threat/hurt other person's computer.
This directory contains the C code of the GonnaCry Ransomware
This directory contains the Python original code of the GonnaCry ransomware
This directory does not affect your computer, 
This project is OpenSource, feel free to use, study and/or send pull request.
To be widely successful a ransomware must fulfill three properties:
[![Travis branch](https://img.shields.io/badge/made%20with-%3C3-red.svg)](https://github.com/tarcisio-marinho/GonnaCry)
[![Travis branch](https://img.shields.io/cran/l/devtools.svg)](https://github.com/tarcisio-marinho/GonnaCry/blob/master/LICENSE)
[![Travis branch](https://img.shields.io/github/stars/tarcisio-marinho/GonnaCry.svg)](https://github.com/tarcisio-marinho/GonnaCry/stargazers)
[![Travis branch](https://img.shields.io/travis/rust-lang/rust/master.svg)](https://github.com/tarcisio-marinho/GonnaCry)
can be applied to ransomware.
encrypted and the key can be obtained paying the attacker.
for other infected devices, in particular the key must not be shared among them.
here is the compiled binary of the actual version
here's the web server to respond to the decryptor
https://0x00sec.org/t/how-ransomware-works-and-gonnacry-linux-ransomware/4594
https://hackingvision.com/2017/07/18/gonnacry-linux-ransomware/
https://medium.com/@tarcisioma/how-can-a-malware-encrypt-a-company-existence-c7ed584f66b3
https://medium.com/@tarcisioma/how-ransomware-works-and-gonnacry-linux-ransomware-17f77a549114
https://medium.com/@tarcisioma/ransomware-encryption-techniques-696531d07bb9
https://medium.com/@tarcisiomarinho/ransomware-encryption-techniques-696531d07bb9
https://www.sentinelone.com/blog/sentinelone-detects-prevents-wsl-abuse/
https://www.youtube.com/watch?v=gSfa2L158Uw
infected device.
keys). At least not in an easily retrievable form, indeed white box cryptography
most successful one seems to be encrypting ransomware: most of the user data are
objdump -d GonnaCry
objdump -d decryptor
their device or data and asks for a payment in exchange for the stolen functionality.
this may harm your computer if executed
| ------------- |:-------------:|
| File          | description   |
| asymmetric.py | RSA encryption |
| daemon.py     | dropped by main.py and run |
| decryptor.py  | communicate with the server, decrypt keys and files|
| dropper.py    | drop the malware on the computer |
| environment.py| environment variables|
| generate_keys.py | Generate random AES keys|
| get_files.py | Find files to be encrypted|
| main.py      | GonnaCry start file|
| persistence.py | Persistence routines for linux OS|
| symmetric.py      |AES encryption|
| utils.py | Utilities routines|
| variables.py | Images and malware binaries|
