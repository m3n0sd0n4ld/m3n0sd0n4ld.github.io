---
title: Late HackTheBox Writeup
tags: [writeup,rest,python,hackthebox,linux,api,suid]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Late/1.png)

## Scanning
We run nmap on all ports with scripts and software versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Late/2.png)


## Enumeration
We access the web site and find the domain (we put it in our */etc/hosts* file).

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Late/3.png)


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Late/4.png)

We launch **wfuzz** to enumerate subdomains and find the "*images.late.htb*" (we insert it in our */etc/hosts* file).

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Late/5.png)

We access the site, we find the application that seems to be able to convert the image to text.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Late/6.png)

It seems that the app does not control the errors well, trying a python import os we see that it gives error and returns the absolute path with the user name.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Late/7.png)


## Exploitation
We try to insert possible commands to identify a possible *SSTI*, we put those payloads in a photo with **gimp**:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Late/8.png)

We see that there are at least two possible payloads (**jinja2**) that we can use to exploit the *SSTI*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Late/9.png)

I think this was the most complicated part of the machine, it took me several hours to explode the whole line, I had to "*play*" with the font and size.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Late/10.png)

And finally I got the user's **SSH** private key.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Late/11.png)

We connect via **SSH** and read the user flag:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Late/12.png)


## Privilege Escalation
Transfer and run **pspy64** to check if the script is being executed by root.

We see that it is, so we check the permissions and verify that we have permissions to modify the file "*ssh-alert.sh*" and insert a line to get a reverse shell when executed by the scheduled process.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Late/13.png)

We put a **netcat** listening, we make a **SSH** connection, we see that the script is executed and we manage to obtain root access.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Late/14.png)




