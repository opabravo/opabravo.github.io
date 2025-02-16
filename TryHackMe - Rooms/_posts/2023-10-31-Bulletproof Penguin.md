---
render_with_liquid: false
title: Bulletproof Penguin
tags: [tryhackme, linux, hardening, blue-team]
---




## Redis Server No Password

```bash
thm@ip-10-10-131-119:~$ ss -ltnp|grep 0.0.0.0
LISTEN  0        4096       127.0.0.53%lo:53             0.0.0.0:*
LISTEN  0        128              0.0.0.0:22             0.0.0.0:*
LISTEN  0        128              0.0.0.0:23             0.0.0.0:*
LISTEN  0        511              0.0.0.0:8000           0.0.0.0:*
LISTEN  0        4096           127.0.0.1:39713          0.0.0.0:*
LISTEN  0        70             127.0.0.1:33060          0.0.0.0:*
LISTEN  0        151              0.0.0.0:3306           0.0.0.0:*
LISTEN  0        511              0.0.0.0:6379           0.0.0.0:*
```

### Patch redis config

```bash
cat > /etc/redis/redis.conf <<EOF
requirepass "bravosec1337"
bind 127.0.0.1
protect-mode yes
EOF
```

```bash
root@ip-10-10-131-119:/home/thm# systemctl list-units --type service|grep redis
  redis-server.service                           loaded deactivating stop-sigterm restart Advanced key-value store
root@ip-10-10-131-119:/home/thm# systemctl restart redis-server.service
```

## Report Default Community Names of the SNMP Agent

```bash
┌──(bravosec㉿fsociety)-[~/thm/Bulletproof Penguin]
└─$ snmp-check $(pt get rhost) | tee snmp-check.txt
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.10.131.119:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 10.10.131.119
  Hostname                      : ip-10-10-131-119
  Description                   : Linux ip-10-10-131-119 5.15.0-1044-aws #49~20.04.1-Ubuntu SMP Mon Aug 21 17:09:32 UTC 2023 x86_64
  Contact                       : Me <me@example.org>
  Location                      : Sitting on the Dock of the Bay
  Uptime snmp                   : 00:27:42.30
  Uptime system                 : 00:27:30.74
  System date                   : 2023-10-30 18:05:14.0
```

### Change community name

Search for `public` and change to private string

```bash
vi /etc/snmp/snmpd.conf
```

```bash
root@ip-10-10-131-119:/home/thm# systemctl list-units|grep snmp
  snmpd.service                                                           loaded active       running              Simple Network Management Protocol (SNMP) Daemon.
root@ip-10-10-131-119:/home/thm# systemctl restart snmpd
```

## Nginx running as root

```bash
root@ip-10-10-131-119:/home/thm# ps auxfw|grep nginx|grep root
root         656  0.0  0.1  51216  1448 ?        Ss   17:37   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
root         661  0.0  0.4  51916  4628 ?        S    17:37   0:00  \_ nginx: worker process
root         665  0.0  0.3  51780  3448 ?        S    17:37   0:00  \_ nginx: worker process
root        2177  0.0  0.0   8168   720 pts/0    S+   18:13   0:00                          \_ grep --color=auto nginx
```

### Change user to www-data

```bash
sed -i.bak 's/user root;/user www-data;/g' /etc/nginx/nginx.conf
systemctl restart nginx
```

## Cleartext Protocols

```bash
root@ip-10-10-131-119:/home/thm# ss -ltnp|grep :23
LISTEN                      0                           128                                                     0.0.0.0:23                                                     0.0.0.0:*                          users:(("inetd",pid=487,fd=7))
```

### Disable telnet

```bash
systemctl disable inetd
systemctl disable inetd
```

## Weak SSH Crypto

### Patch ssh config

Recover ssh's default config

```bash
mv /etc/ssh/sshd_config /etc/ssh/sshd_config~
cp /usr/share/openssh/sshd_config /etc/ssh/sshd_config
systemctl restart ssh.service
```

## Anonymous FTP Login Reporting

### Disable ftp anonymous login

```bash
sed -i.bak '/^ftp/d' /etc/passwd
```

## Weak Passwords


### Unused accounts

```bash
userdel -rf joseph
userdel -rf test1
```

### Bulk change users' password

```bash
┌──(bravosec㉿fsociety)-[~/thm/Bulletproof Penguin]
└─$ openssl passwd -6 -salt xyz bravosec1337
$6$xyz$AWIVzlZPM3bGYMMs83tjb7v/DE2N7447Ee9OQw4PiNcNAZn3qhkXsJuha87Aw7WVGq3hvBfvZ913wbWP2s1Sy0
```

```bash
for USER in $(cat /etc/passwd|grep sh$|cut -d":" -f1|xargs); do /usr/sbin/usermod -p '$6$xyz$AWIVzlZPM3bGYMMs83tjb7v/DE2N7447Ee9OQw4PiNcNAZn3qhkXsJuha87Aw7WVGq3hvBfvZ913wbWP2s1Sy0' $USER; done
```


## Review Sudo Permissions


### Patch sudoers config file

```bash
vi /etc/sudoers
```

- `ALL=(ALL:ALL) ALL`
- `NOPASSWD`

> The user `mary` must be able to run the `/usr/bin/ss` command as root. When doing so, she must NOT be asked for her password. Assign the corresponding sudo privileges.

```bash
mary ALL=(root) NOPASSWD : /usr/bin/ss
```


## Exposed Database Ports

```bash
root@ip-10-10-131-119:/home/thm# ss -ltunp|grep 0.0.0.0
udp    UNCONN  0       0             127.0.0.53%lo:53             0.0.0.0:*      users:(("systemd-resolve",pid=412,fd=12))
udp    UNCONN  0       0        10.10.131.119%ens5:68             0.0.0.0:*      users:(("systemd-network",pid=409,fd=15))
udp    UNCONN  0       0                   0.0.0.0:161            0.0.0.0:*      users:(("snmpd",pid=2190,fd=6))
tcp    LISTEN  0       4096          127.0.0.53%lo:53             0.0.0.0:*      users:(("systemd-resolve",pid=412,fd=13))
tcp    LISTEN  0       128                 0.0.0.0:22             0.0.0.0:*      users:(("sshd",pid=3769,fd=3))
tcp    LISTEN  0       511                 0.0.0.0:8000           0.0.0.0:*      users:(("nginx",pid=2234,fd=6),("nginx",pid=2233,fd=6),("nginx",pid=2232,fd=6))
tcp    LISTEN  0       4096              127.0.0.1:39713          0.0.0.0:*      users:(("containerd",pid=522,fd=14))
tcp    LISTEN  0       70                127.0.0.1:33060          0.0.0.0:*      users:(("mysqld",pid=892,fd=21))
tcp    LISTEN  0       151                 0.0.0.0:3306           0.0.0.0:*      users:(("mysqld",pid=892,fd=23))
tcp    LISTEN  0       511                 0.0.0.0:6379           0.0.0.0:*      users:(("redis-server",pid=770,fd=6))
```

### Bind mysql to localhost only

```bash
sed -i.bak 's/bind-address.*/bind-address = 127.0.0.1/I' /etc/mysql/mysql.conf.d/mysqld.cnf
systemctl restart mysql
```


## Get flags

```bash
root@ip-10-10-131-119:/home/thm# get-flags
{
  "ssh_weak_ciphers": "THM{9ff9c182cad601291d45951c01d0b2c7}",
  "ssh_weak_kex": "THM{d9baf598ee934d79346f425a81bd693a}",
  "ssh_weak_macs": "THM{e3d6b82f291b64f95213583dcd89b659}",
  "redis_nopass": "THM{ae4e5bb7aac2c2252363ca466f10ffd0}",
  "redis_port_public": "THM{20a809866dbcf94109189c5bafabc5c2}",
  "mysql_port_public": "THM{526e33142b54e13bb47b17056823ab60}",
  "snmp_public": "THM{aa397a808d527fd71f023c78d3c04591}",
  "nginx_asroot": "THM{bebb02b22bb56b2f79ba706975714ee2}",
  "unused_accounts": "THM{1b354db0e71f75057abe69de26a637ab}",
  "change_pass": "THM{be74a521c3982298d2e9b0e347a3807d}",
  "sudoers_mary": "THM{a0bcb9b72fd26d0ad55cdcdcd21698f1}",
  "sudoers_munra": "THM{1e9ee13fb42fea2a9eb2730c51448241}",
  "cleartext_services": "THM{33704d74ec53c8cf50daf817bea836a1}",
  "anon_ftp": "THM{f20b5ff5a3d4c779e99c3a93d1f68c6d}"
}
```