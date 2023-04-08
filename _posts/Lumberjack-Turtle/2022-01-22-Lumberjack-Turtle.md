---
title: Lumberjack-Turtle TryHackMe Writeup
tags: [nsca,writeup,tryhackme,nagios,linux,escape-docker,log4j,docker]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Lumberjack-Turtle/1.png)

## Scanning
We run nmap on all ports with scripts and software versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Lumberjack-Turtle/2.png)

## Enumeration
We access the site, we find a message that gives us a "*hint*" that the site is under **java**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Lumberjack-Turtle/3.png)

We use **dirsearch** and find a "*logs*" directory. 


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Lumberjack-Turtle/4.png)

We access and find a phrase that sounds familiar, doesn't it?

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Lumberjack-Turtle/5.png)

Nmap showed us that a Nagios log server is deployed. Searching for information I found this [interesting article](https://www.nagios.com/news/2021/12/update-on-apache-log4j-vulnerability/)

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Lumberjack-Turtle/6.png)

## Exploitation
As we do not have a control panel, I had to test a "PoC" payload on each header. I quickly realized that the "*Accept*" header is vulnerable to **Log4j**.

### PoC
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Lumberjack-Turtle/7.png)

### Reverse shell
Exploit: [https://github.com/pimps/JNDI-Exploit-Kit](https://github.com/pimps/JNDI-Exploit-Kit)

I downloaded the exploit and inserted a typical **Pentestmonkey** reverse shell, it worked without any problem as we can see in the following images.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Lumberjack-Turtle/9.png)


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Lumberjack-Turtle/10.png)

Once inside, we search for files containing "*flag*" and find the hidden flag and read it.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Lumberjack-Turtle/11.png)

## Privilege Escalation
We are in a somewhat restrictive shell and we are missing several binaries, but we can check binaries by **SUID**, find **mount**, **unmount** and **wall**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Lumberjack-Turtle/12.png)

We list the drives and mount the "*/dev/xvda1*" drive and see that we now have access to the machine's files.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Lumberjack-Turtle/13.png)

But the flag is not in the root folder!

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Lumberjack-Turtle/14.png)

We enter our public key, access via **SSH** and thus get a more stable shell.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Lumberjack-Turtle/15.png)

We searched by flag, we found two files in the "**Docker**" folder

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Lumberjack-Turtle/17.png)

If we check its integrity, we see that it is the same file.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Lumberjack-Turtle/18.png)

After a lot of searching, I noticed something that I had not taken into account, there is a folder with three dots "...". The flag is hidden there!

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Lumberjack-Turtle/16.png)




