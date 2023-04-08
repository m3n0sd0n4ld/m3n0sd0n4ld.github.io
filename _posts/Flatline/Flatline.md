---
title: Flatline TryHackMe Writeup
tags: [writeup,rest,python,tryhackme,linux,api,suid]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Flatline/0.png)

## Scanning
We run nmap on all ports with scripts and software versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Flatline/1.png)

## Enumeration
We access to service on 8021 port, this service have exploit for RCE without authentitation.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Flatline/2.png)


## Exploitation

#### Exploit used: [https://www.exploit-db.com/exploits/47799 ](https://www.exploit-db.com/exploits/47799)

We see is working! 

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Flatline/3.png)

We transfer the **netcat** to the machine, listen on port *443* and run a **netcat** on the victim to get an interactive session.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Flatline/4.png)

We try to read the *root.txt* flag, but we don't have access, so we only read the *user.txt* flag.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Flatline/5.png)


## Privilege Escalation
We see the privileges, we identify the famous "*SeImpersonatePrivilege*", but I can already tell you that the machine seems to be patched.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Flatline/6.png)

We also identify the operating system and its architecture.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Flatline/7.png)

We download the "**Winpeas**" tool, identify a software called "**OpenClinic**" and a "**Tomcat 8**".
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Flatline/8.png)

There is a local exploit for privilege escalation:
#### Exploit used: [https://www.exploit-db.com/exploits/50448](https://www.exploit-db.com/exploits/50448)

We create a malicious binary with "**msfvenom**" with a reverse shell to our machine on port 5555.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Flatline/9.png)

Transfer the malicious binary, rename the file "**mysqld.exe**" to "**mysqld.bak**" and replace the malicious binary with "**mysqld.exe**".
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Flatline/10.png)

We set our **netcat** to listen on port 5555 and restart the victim machine.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Flatline/11.png)

In a few minutes, we will get a connection on our machine and as the user "*nt authority system*".

Finally, we will read the flag from *root.txt*.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Flatline/12.png)




