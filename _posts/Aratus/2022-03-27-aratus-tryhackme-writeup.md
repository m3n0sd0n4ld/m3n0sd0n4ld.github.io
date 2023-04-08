---
title: Aratus TryHackMe Writeup
tags: [writeup,tryhackme,capabilities,linux,tcpdump,ansible]
style: border
color: success
description: Aratus TryHackMe Writeup
---

![logo](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/1.png)

## Scanning
We run nmap on all ports with scripts and software versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/2.png)

## Enumeration
We list in the **HTTP** and **HTTPS** service the default page of *Apache CentOS*. 

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/3.png)

We continue reviewing the services, we continue with the **FTP** service, we see that it is possible to access with the "*anonymous*" credentials, we find a resource but there is nothing useful.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/4.png)

We continue reviewing the **SMB** service, we find a resource that catches our attention "*temporary share*", we try to see the permissions, but we cannot enumerate it with the "**smbmap**" tool.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/5.png)

But you should not be satisfied with what a tool can tell you, you have to check with other tools or manually.
As you can see, the "**enum4linux**" tool tells us that we have read permissions on the Samba resource.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/6.png)


## Exploitation
We connect with the "**smbclient**" tool and see the root path of a user, but we only have access to the "*message-to-simeon.txt*" file and the "chapter" folder listing.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/7.png)

We download and read the file "*message-to-simeon.txt*", we see that the user *Theodore* (looks like an administrator) is complaining that *Simeon* uses bad passwords and is a bit dirty with the files...

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/8.png)

Coincidentally, **enum4linux** listed me *3 system users*, so a third one called "*automation*" comes in.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/9.png)

It is time to examine the files in the "*chapters*" directories, it seems that all the files have the same size, this makes it a little difficult to enumerate different files... Or not? We can make use of the "**find**" command and list the last modified files, this works and only one comes out. 

```bash
find . -printf "%T@ %Tc %p\n" | sort -n
```

We read the file "*/chapter7/paragraph7.1/text2.txt*" and find an encrypted SSH private key inside the file. 

*NOTE: To work more comfortably, I set up the SMB resource on my machine.*

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/10.png)

We use the tool "**ssh2john**" to obtain the hash of the password used, then we crack the hash with "**john**" and the dictionary "*rockyou*".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/11.png)

We access through the **SSH** service and with the private key, but we still do not have access to the "*user.txt*" file, so we will have to escalate to the "*theodore*" user.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/12.png)

For a moment I saw "*the light*", but it turned out to be a *rabbit hole*, so the password used in the "*.htpasswd*" file is not functional.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/13.png)

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/14.png)

We launch the tool "**linpeas.sh**", it lists that we have permissions by "*capabilities*" of the **tcpdump** binary, so we would have the ability to sniff the network traffic.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/15.png)
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/16.png)

We run "**ip add**", we see that we have two network interfaces "*lo* and *eth0*".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/18.png)

We ran **tcpdump** on "*eth0*", but found nothing, so I tried it on "*lo*" and we will run **Wireshark** on our computer.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/17.png)

#### Found credentials

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/19.png)

We decode the trace to *base64* and find the correct credentials of the user "*theodore*".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/20.png)

We use the credentials to authenticate as "*theodore*" and read the "*user.txt*" file.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/21.png)


## Privilege Escalation
We execute "*sudo -l*", we see that we have permissions as the user "*automation*" to execute a script in **Bash**.

The script appears to run a series of "*Yaml*" files with the "**ansible**" binary.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/22.png)

Reviewing directories and files that follow the script, except for one file, it seems that the rest we do not have write permissions to insert malicious code and make a privilege escalation.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/23.png)

But watch out! There is a "*+*" in the permissions of the file "*configure-RedHat.yml*".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/24.png)

Indeed! We can edit the file! Reading a bit about privilege escalations in "**ansible**", it seems that it is simple, adding a line like "*shell: command...*" we can execute commands as the user that is predefined (in this case, as root).

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/25.png)

We put a netcat listening on our attacker's machine and run the script with **SUDO**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/26.png)

We wait for the remote connection, run our command list and read the flag from the "*root.txt*" file.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Aratus/27.png)
