---
title: RouterSpace HackTheBox Writeup
tags: [writeup,anbox,command-injection,sudo,apk,hackthebox]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/1.png)

## Scanning
We run nmap on 22 and 80 ports with scripts and software versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/2.png)

## Enumeration
We access port 80, we see the website of a router.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/3.png)

We can see a button where we download a file "*RouterSpace.apk*".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/4.png)

Download and extract the contents of the apk. I looked in case it stored some credentials that I could use for the **SSH** service, but it did not.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/5.png)

We check the apk with **MobaSF**, we find the domain "*routerspace.htb*":

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/6.png)

We access the web service through the domain, but it goes to the same site.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/7.png)


## Exploitation
We proceed to virtualize the apk (I used **Anbox**) and I configured my *Burp on port 9000*. (Yes, the picture is wrong, sorry)

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/11.png)

```bash
adb shell settings put global http_proxy 192.168.174.130:9000
adb install RouterSpace.apk
```

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/8.png)

We check that it has been installed correctly, double click and run them.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/9.png)

#### View RouterSpace application
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/10.png)

We intercept the request by pressing the button on the mobile application, we see that it appears to be executing an action such as a *ping* on the remote device activity check.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/12.png)

It was easy, as it is a typical vulnerability in IoT/IIoT devices, we evidenced that it is possible to inject commands.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/13.png)

We abuse vulnerability for read "*user.txt*" file:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/14.png)

I saw that it did not reach the *id_rsa*, but it does have the *authorized_keys* file

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/15.png)

So I will insert my public key in the file and I should get access to the machine via **SSH**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/16.png)

We connect to **SSH** service:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/17.png)


## Privilege Escalation
We can use **linpeas** tool and we enumerate the **SUDO** version *1.8.31*:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/18.png)

I downloaded the checker and PoC from Bl4sty and my friend Lockedbyte.
#### Exploit: [CVE-2021-3156](https://github.com/m3n0sd0n4ld/CVE-Exploits/tree/main/CVE-2021-3156)

We upload the files, compile and run the checker... It is vulnerable! We run the exploit with option "*1*", become root and read the flag.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/RouterSpace/19.png)




