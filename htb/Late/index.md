# Late HackTheBox Writeup
### Level: `Easy` | OS: `Linux`

![logo](1.png)

## Scanning
We run nmap on all ports with scripts and software versions.

![](2.png)


## Enumeration
We access the web site and find the domain (we put it in our */etc/hosts* file).

![](3.png)

It also tells us about a photo editing application, but we can't find any link to it, so it's probably on another subdomain.

![](4.png)

We launch **wfuzz** to enumerate subdomains and find the "*images.late.htb*" (we insert it in our */etc/hosts* file).

![](5.png)

We access the site, we find the application that seems to be able to convert the image to text.

![](6.png)

It seems that the app does not control the errors well, trying a python import os we see that it gives error and returns the absolute path with the user name.

![](7.png)


## Exploitation
We try to insert possible commands to identify a possible *SSTI*, we put those payloads in a photo with **gimp**:

![](8.png)

We see that there are at least two possible payloads (**jinja2**) that we can use to exploit the *SSTI*.

![](9.png)

I think this was the most complicated part of the machine, it took me several hours to explode the whole line, I had to "*play*" with the font and size.

![](10.png)

And finally I got the user's **SSH** private key.

![](11.png)

We connect via **SSH** and read the user flag:

![](12.png)


## Privilege Escalation
Transfer and run **pspy64** to check if the script is being executed by root.

We see that it is, so we check the permissions and verify that we have permissions to modify the file "*ssh-alert.sh*" and insert a line to get a reverse shell when executed by the scheduled process.

![](13.png)

We put a **netcat** listening, we make a **SSH** connection, we see that the script is executed and we manage to obtain root access.

![](14.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)