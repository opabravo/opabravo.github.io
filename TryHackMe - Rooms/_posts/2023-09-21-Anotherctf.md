---
render_with_liquid: false
title: Anotherctf
tags: [tryhackme, nmap, linux, ciphey, crypto]
---




# Recon
---

## Nmap

```bash

```


# User
---
```bash
www-data@ubuntu-bionic:/var/www/html$ cat /home/www-data/.../look.txt
Super Secure Password => ctfbros:WTBCT1dUQjFVR3hBZVZSb0lYTmpWR1kv
```

```bash
┌──(bravosec㉿fsociety)-[~/thm/AnotherCTF]
└─$ echo 'WTBCT1dUQjFVR3hBZVZSb0lYTmpWR1kv'|base64 -d|base64 -d
c@NY0uPl@yTh!scTf?
```

```bash
┌──(bravosec㉿fsociety)-[~/thm/AnotherCTF]
└─$ rlwrap nc anotherctf.thm 8888
Username: ctfbros
Password: c@NY0uPl@yTh!scTf?
Authentication successful. Welcome!
Enter a command (list to show something, exit to quit): id
Invalid command. Try again.
Enter a command (list to show something, exit to quit): list
secret1
secret2
secret3
Enter a command (list to show something, exit to quit): secret1
ydLMriqVXnJiAb84Kiwv4tBfXLs1V65ndwtr3zCXMCPZcknHZnmscABg3HdScv7ovkoyCnxYSQDDvm43UUN
Enter a command (list to show something, exit to quit): secret3
There is a secret file on /tmp
Enter a command (list to show something, exit to quit): secret2
Ayo it's Trevohack!

Enter a command (list to show something, exit to quit): __import__('os').system('id')
Invalid command. Try again.
```

```bash
┌──(bravosec㉿fsociety)-[~/thm/AnotherCTF]
└─$ ciphey -t 'ydLMriqVXnJiAb84Kiwv4tBfXLs1V65ndwtr3zCXMCPZcknHZnmscABg3HdScv7ovkoyCnxYSQDDvm43UUN'
Possible plaintext: 'Hey John here is your recovered password youMe@nReversing123?' (y/N): y
╭─────────────────────────────────────────────────────────────────────────────────────────────╮
│ Formats used:                                                                               │
│    base58_bitcoinPlaintext: "Hey John here is your recovered password youMe@nReversing123?" │
╰─────────────────────────────────────────────────────────────────────────────────────────────╯
```


# Root
---


# Additional
---
