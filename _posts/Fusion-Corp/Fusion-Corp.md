---
title: Fusion-Corp TryHackMe Writeup
tags: [writeup,rest,python,tryhackme,linux,api,suid]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/1.jpeg)

## Scanning
We launch **nmap** a bit *"aggressive"* (but we are in a controlled environment and we can afford it :P), to all ports and with verbosity to discover ports as **nmap** is getting them.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/2.png)

### nmap with versions and scripts

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/3.png)

## Enumeration
We access the web service, find the corporate website and list some of the organization's users. This is great, as we could use them to brute force some exposed service.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/4.png)

We use the **nikto** tool, it discovers the directory *"/backup/*. 

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/5.png)

Accessing the directory, we find an office file containing the name and username of the employees.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/6.png)

#### Content ods file
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/7.png)

We use the **kerbrute** tool to check which users exist, it quickly lists the user *"lparker"*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/8.png)

## Exploitation
Once we have a user, we can check if the account is ASReproastable and consult its hash in the KDC.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/9.png)

We crack the hash with **hashcat** and *rockyou dictionary*, we will get the password in clear.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/10.png)

### Read the first flag 

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/11.png)

We do a reconnaissance, we see that AV is enabled in the system and it prevents us from running some reconnaissance binaries.

Seeing that I can't find anything, I launch ldapsearch with the credentials and coincidentally, I find some flat credentials in the description of the user "jmurphy".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/13.png)

#### Credentials evidence
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/14.png)

We use the credentials of the new user, read the user flag and see the privileges.... Oh wow! The privilege escalation looks good ;)

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/15.png)

## Privilege Escalation
We make use of the great tool **evil-winrm** and this article from [HackPlayers](https://www.hackplayers.com/2020/06/backup-tosystem-abusando-de-los.html). Actually the vulnerability allows to abuse the backup privilege to write and restore the modified ACLs as we wish.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/16.png)

We connect with our user and read the administrator flag.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/17.png)

## Post-exploitation

Once we have gained access, it is time to obtain the hashes of the most relevant users.

#### NTLM HASHES
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/18.png)

#### Commitment Active Directory

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/19.png)

#### RDP connection

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Fusion-Corp/20.png)




