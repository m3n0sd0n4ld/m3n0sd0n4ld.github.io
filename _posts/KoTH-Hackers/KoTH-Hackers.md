---
title: KoTH-Hackers TryHackMe Writeup
tags: [writeup,rest,python,tryhackme,linux,api,suid]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/1.png)

## Scanning
We scanned with the nmap tool all ports with scripts and software versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/2.png)

## Enumeration
We access web services and we enumerate the corporate website.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/3.png)

We also list several corporate users.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/3-3.png)

We access the **FTP** service with the default credentials and download a file called *"notes"*, where a list of passwords and user names are filtered.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/4.png)

We create a file with listed *users* and another one with the mentioned *passwords*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/6.png)

We tried to brute force the **SSH** service without success, so we used the **dirsearch** tool with a medium directory dictionary and listed the *"/backdoor/"* directory.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/7.png)

We access and find an authentication system, we will probably have to brute force.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/8.png)

After much testing, there was no way and I had to start again from scratch... This time, I reused the listed users and the *rockyou* dictionary on the **FTP** service.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/9.png)
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/9-2.png)

Recall that we found a note stating that the user *"gcrawford"* exposed his cryptographic keys.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/10.png)

## Exploitation
Access the **FTP** service with the new credentials, check hidden files and find the *".ssh"* directory with the user's ssh keys (private included).

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/11.png)

We see that the private key is encrypted and we need the key to be able to use it.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/12.png)

We use the **"ssh2john"** tool to obtain the hash of the *"id_rsa"* file, crack it with the *rockyou* dictionary and in a few seconds we obtain the plain password.

We use the password, access by **SSH** and see that we can run **nano** on a text file and as the *root* user.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/13.png)

## Privilege Escalation
We run **nano** with sudo calling the text file, there we will execute commands to obtain a shell as root.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/15.png)

#### Root prompt

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/16.png)

#### Some of the flags found (the idea was just to root the machine)
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/14.png)

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/14-2.png)

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/KoTH-Hackers/14-3.png)




