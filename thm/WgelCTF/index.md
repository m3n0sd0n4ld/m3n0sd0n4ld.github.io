# Wgel CTF TryHackMe Writeup
### Level: `Easy` | OS: `Linux`

![logo](1.png)

## Scanning
We use nmap to scan all ports with scripts and software versions.

![](2.png)

## Enumeration
We access the web service and find a default Apache page.

![](3.png)

We enumerate the "Jessie" user in code HTML.

![](3-2.png)

We use the **dirsearch** tool with a common dictionary and we enumerate the *"/sitemap/"* directory.

![](4.png)

We access to this web, we find a corporate web.

![](5.png)

We return use **dirsearch** tool in the new directory and we find the *"/.ssh/"* directory with *id_rsa* file.

![](6.png)

#### Evidence a id_rsa file

![](7.png)

## Exploitation
We use **id_rsa** file with *"Jessie"* user in SSH service, We enumerate commands SUDO and we reading *"user_flag.txt"* file.

![](8.png)

## Privilege Escalation

Previously, we saw that we can run **wget** as **SUDO**. We use the flag *"--post-file"*, we put a **netcat** listening and we see that it prints the file *"/etc/shadow"*. 

![](9.png)

After that, we tried to crack the hash with rockyou, but I can't get the password. So I think, if I can read any file.... Why not read the root flag? 

![](10.png)

But please... This is cheating! Let's break the machine as it deserves.

So we will not complicate it, we will copy the file *"/etc/passwd"* and save it in our local kali.

![](11.png)

We will create a new user, specify the hash of a password we know and save our *"passwd"* file.

![](12.png)

Perfect! Then we will put in the variable *"URL"* the address of the file to our machine, *"LFILE"* will be the destination where the legitimate file will be replaced and we will execute the **wget** command as **SUDO**.

After seeing the *"saved"*, we will authenticate with our **new user**, we will be root and we will be able to read again the root flag.

![](13.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)
