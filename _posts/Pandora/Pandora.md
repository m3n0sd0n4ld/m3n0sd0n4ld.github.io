---
title: Pandora HackTheBox Writeup
tags: [writeup,rest,python,hackthebox,linux,api,suid]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/1.jpg)

## Scanning
We run nmap on all ports with scripts and software versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/2.png)

## Enumeration
We access the web service, enumerate a domain name and put it in our "*/etc/hosts*" file.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/3.png)

We found nothing enumerating, neither by fuzzing, nor by vhost, we checked by UDP ports and found the **snmp** open:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/4.png)

We use the **snmpwalk** tool with public channel and see that information is being exfiltrated.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/5.png)

We saved all the information in a file and found quite relevant information:

#### Kernel linux used:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/7.png)

We found an internal process running with plaintext credentials.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/6.png)


## Exploitation
We successfully used the credentials via the **SSH** service, but we do not have sufficient permissions to read the "*user.txt*" file.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/8.png)

We launch the "**linpeas.sh**" tool, check that the last modified files correspond to "*Pandora*" (wow, just like the name of the machine ;))

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/9.png)

Reviewing the information extracted from the "**snmp**" service, we find a process called "*pandora_backup*", we look for the binary and we see that it would be possible to execute it with the "*root*" or "*matt*" user:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/10.png)

We list the **Pandora FMS 5.1** version:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/11.png)

From outside it was not possible to see that resource, so I checked the "*/etc/hosts*" file of the machine and discovered that there is "*localhost.localdomain*" and "*pandora.pandora.htb*".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/12.png)

Let's remember that we can enumerate the exact version of **Pandora FMS**, but we can only reach the resource locally, so we will have to perform port forwarding and redirect the traffic to our machine through **proxychains**:

 ![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/13.png)

We make the port forwarding by **SSH** and we see that we already have access to the resource from our machine.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/14.png)

For the version, there is an exploit that affects this version of **Pandora** and would allow us to execute remote code, the bad news is that it requires credentials and we don't have them. 


In addition, it is clear that we will only be able to operate via API:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/15.png)

We inject in the "*session_id*" parameter with the "**SQLMap**" tool and manage to enumerate the database.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/16.png)

We extract the interesting tables and columns, we have the hashed password of the user "**matt**", but we can't crack it.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/17.png)

So, we extract the session cookie stored in the database and from the user "*matt*", add it in the URL and insert it in our browser cookies. We managed to access with the user's session.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/18.png)

Checking the CMS, we found a file manager, we tried to upload a PHP file with a reverse shell.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/19.png)

##### Execute m3.php file:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/20.png)

We managed to gain access to the machine with the user "*matt*", we read the file "*user.txt*".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/21.png)


## Privilege Escalation
We check the "*pandora_backup*" binary, we see that it is calling the "**tar**" binary without the absolute path, so we could try to do path hijacking and execute an illegitimate binary with root privileges.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/22.png)

We create a file called "**tar**" that will contain a "**bash**", give it execution permissions and change our PATH. We run the binary, log in as the user "*root*" and read the file "*root.txt*".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Pandora/23.png)




