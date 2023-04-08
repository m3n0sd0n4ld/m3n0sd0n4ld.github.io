---
title: Harder TryHackMe Writeup
tags: [writeup,rest,python,tryhackme,linux,api,suid]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/1.png)

## Scanning
We scan the open ports with the **nmap** tool with scripts and software versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/2.png)

## Enumeration
We access the web service and find the corporate website and the software they use.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/3.png)

Using the **Nikto** tool, we list a *phpinfo.php* file that can also help us to list deployed software and its exact versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/4.png)

#### PHPinfo File

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/5.png)

We see in the server response that it reveals a domain name, we add it to our *"/etc/hosts"* file.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/6.png)

We list an administration panel that asks for credentials.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/7.png)

We set the default credentials to *"admin:admin"* and it lets us through, but we get the following message...

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/8.png)

We use **dirsearch** and several **seclist** dictionaries, we list some files and directories that might be relevant.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/9.png)

We can't access it from the browser, but we can use the **[GitTools](https://github.com/internetwache/GitTools)** suite to dumpe it.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/10.png)

We extract information...

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/11.png)

We read the file *"index.php"*, we see that it requires the file *"hmac.php"*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/12.png)

#### Contents of file "hmac.php".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/13.png)

The best way to be able to review code is to play with it, so I used a web to run **PHP** to debug the code and do a test to get an *hmac hash* for a personal host.

```PHP
<?php
$secret = hash_hmac('sha256', "m3n0sd0n4ld.github.io", false);
echo $secret;
```

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/14.png)

Now with all the data, we fill in the variables and we see that the site returns a new url and credentials.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/15.png)

We access the new site, enter the credentials but it seems that it only allows access to a specific network range.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/16.png)

We add the header *"X-Forwarded-For: 10.10.10.X"* and we see that it opens the web site.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/17.png)

## Exploitation

Once inside, we see that we can execute system commands.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/18.png)

#### Read user flag

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/19.png)

We see that the shell type is an "ash", so we change the netcat type and we will get a more or less stable reverse shell.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/21.png)

#### Reverse shell

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/22.png)

We do an enumeration on the machine, we find a *backup file* that hides the credentials of the user **"evs"**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/25.png)

We connect via **SSH** to have a more stable session.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/26.png)

## Privilege Escalation
Let's remember the file we found with the **"evs"** credentials *(ToDo: create a backup script....)*

We use find to list the scripts that we could review.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/27.png)

So nothing, we do a test with the **"whoami"** command, encrypt it with **gpg** and run the *"execute-crypted"* binary and see that it executes *"root"*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/28.png)

Great! So now we use **netcat** again to establish a reverse shell as root, we put it in the *"command"* file, do a cat to check that it is OK, encrypt the file in **gpg** and run the binary.... Below we will see that we already have a *shell as root* and we can read the flag.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Harder/29.png)




