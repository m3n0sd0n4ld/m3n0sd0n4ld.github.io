---
title: Mustacchio TryHackMe Writeup
tags: [writeup,tryhackme,xxe,tail,linux,path-absolute]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/1.png)

## Scanning
We performed an nmap scan of all ports, with scripts and versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/2.png)

## Enumeration
We access the first web resource (port 80), check the website and its source code, but find nothing useful.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/3.png)

We launch the **dirsearch** tool, list the directory *"/custom/"* which looks interesting.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/4.png)

We access the directory and find a file *"users.bak"* which usually contains relevant information.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/5.png)

Download the file, crack the password hash with an online tool and get the password in clear.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/6.png)

We access the other web resource (port 8765), insert the credentials in the administration panel and access the inside of the application.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/7.png)

## Exploitation
We see that the site asks us to write **XML code**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/8.png)

We do some XML code tests, nothing interesting so far. But on the other hand, we see a new path to a *.bak* file and we get a hint that the user *"Barry"* can connect via **SSH** service with his private key.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/9.png)

We download the file, we see that we have listed the structure of the XML in question, so we could continue investigating to exploit it.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/10.png)

#### Testing

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/11.png)

#### PoC XXE/XEE
```XML
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "/etc/passwd"> ]>
<comment>
  <name>Testing</name>
  <author>m3n0sd0n4ld</author>
  <com>&xxe;</com>
</comment> 
```

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/12.png)

We repeat the same process, this time we will read the **id_rsa** file of the user *"Barry"*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/13.png)

We copy the key, we see that it is encrypted. We use the tool **ssh2john.py** and crack it with the *rockyou dictionary*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/14.png)

We authenticate through the **SSH** service and read the *user.txt* flag.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/15.png)

We list the binary *"live_log"* in the path of the user *"joe"*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/16.png)

#### Use strings in file

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/17.png)

## Privilege Escalation

Since the call to the **"tail"** binary is not made with its absolute path, an attacker could create a malicious binary and change its *PATH* to execute the illegitimate one.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Mustacchio/18.png)




