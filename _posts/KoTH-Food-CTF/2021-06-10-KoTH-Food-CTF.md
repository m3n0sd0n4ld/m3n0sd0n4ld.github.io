---
title: KoTH-Food-CTF TryHackMe Writeup
tags: [writeup,tryhackme,linux,screen,mysql,setuid]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Food-CTF/1.png)

## Scanning
We performed an **nmap** scan, including all ports and software versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Food-CTF/2.png)

## Enumeration
We access the web resource on a high port.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Food-CTF/3.png)

On *port 16109*, it shows an image. This is a CTF, it is possible that this image contains stego, so we download it.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Food-CTF/4.png)

## Exploitation
We run the **steghide** tool without password and get a file containing credentials.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Food-CTF/5.png)

It seems to be very easy, we try the credentials obtained in the **SSH** service and get access to the machine.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Food-CTF/6.png)

Recall that we had enumerated a **MySQL**, we tried to access with the **default credentials** with success, we enumerated the *"Users"* table, we enumerated the password of the user *"ramen"* and another *flag*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Food-CTF/10.png)

We authenticate as the user *"ramen"*, but it seems that we will not be able to do much with it.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Food-CTF/11.png)

## Privilege Escalation
We launch the tool **lse.sh**, we enumerate the *Screen 4.5.0 binary*, I already knew this binary, it has an **[exploit](https://www.exploit-db.com/exploits/41154)** to escalate privileges.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Food-CTF/12.png)

In my case I did it manually, so I compiled the *"libhax.so"* and *"rootshell"* files in my Kali, mounted a server with **Python** to share the files and executed the following commands to escalate privileges to the *root* user.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Food-CTF/13.png)

#### Some of the flags found (My idea was just to root the machine)

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Food-CTF/7.png)
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Food-CTF/8.png)
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Food-CTF/9.png)
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Food-CTF/14.png)
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Food-CTF/15.png)




