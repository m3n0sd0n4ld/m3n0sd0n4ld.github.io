# KoTH Hackers TryHackMe Writeup
### Level: `Medium` | OS: `Linux`

![logo](1.png)

## Scanning
We scanned with the nmap tool all ports with scripts and software versions.

![](2.png)

## Enumeration
We access web services and we enumerate the corporate website.

![](3.png)

We also list several corporate users.

![](3-3.png)

We access the **FTP** service with the default credentials and download a file called *"notes"*, where a list of passwords and user names are filtered.

![](4.png)

We create a file with listed *users* and another one with the mentioned *passwords*.

![](6.png)

We tried to brute force the **SSH** service without success, so we used the **dirsearch** tool with a medium directory dictionary and listed the *"/backdoor/"* directory.

![](7.png)

We access and find an authentication system, we will probably have to brute force.

![](8.png)

After much testing, there was no way and I had to start again from scratch... This time, I reused the listed users and the *rockyou* dictionary on the **FTP** service.

![](9.png)
![](9-2.png)

Recall that we found a note stating that the user *"gcrawford"* exposed his cryptographic keys.

![](10.png)

## Exploitation
Access the **FTP** service with the new credentials, check hidden files and find the *".ssh"* directory with the user's ssh keys (private included).

![](11.png)

We see that the private key is encrypted and we need the key to be able to use it.

![](12.png)

We use the **"ssh2john"** tool to obtain the hash of the *"id_rsa"* file, crack it with the *rockyou* dictionary and in a few seconds we obtain the plain password.

We use the password, access by **SSH** and see that we can run **nano** on a text file and as the *root* user.

![](13.png)

## Privilege Escalation
We run **nano** with sudo calling the text file, there we will execute commands to obtain a shell as root.

![](15.png)

#### Root prompt

![](16.png)

#### Some of the flags found (the idea was just to root the machine)
![](14.png)

![](14-2.png)

![](14-3.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)
