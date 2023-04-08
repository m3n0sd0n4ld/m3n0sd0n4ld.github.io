---
title: BroScience HackTheBox Writeup
tags: [writeup,hackthebox,serialization,certificates]
style: border
color: success
description: ""
---

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/1.png)

## Scanning

We launch **nmap** tool with scripts and versions on all ports.

```bash
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 df17c6bab18222d91db5ebff5d3d2cb7 (RSA)
|   256 3f8a56f8958faeafe3ae7eb880f679d2 (ECDSA)
|_  256 3c6575274ae2ef9391374cfdd9d46341 (ED25519)
80/tcp  open  http     Apache httpd 2.4.54
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Did not follow redirect to https://broscience.htb/
443/tcp open  ssl/http Apache httpd 2.4.54 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| ssl-cert: Subject: commonName=broscience.htb/organizationName=BroScience/countryName=AT
| Not valid before: 2022-07-14T19:48:36
|_Not valid after:  2023-07-14T19:48:36
|_http-title: BroScience : Home
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.54 (Debian)
Service Info: Host: broscience.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We see that nmap shows us the domain *broscience.htb*, so we include it in our */etc/hosts* file.

## Enumeration

Web access the website:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/2.png)

We detected a couple of interesting parameters, and we also listed the users on the site.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/3.png)

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/4.png)

We managed to list all the users on the platform by changing the identifier.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/5.png)

In addition, there is an authentication and registration form, but the registration is not enabled.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/6.png)

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/7.png)

We created a **Python** script for brute-forcing and managed to enumerate the credentials of the user '*hacker*', but the account is not activated.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/8.png)

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/9.png)

## Exploitation

After trying to use the *activate.php* file and being unable to determine the code, we discovered that some variables load the ID or other functionalities. As a result, we tested the *img.php* file.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/10.png)

We tried with the '*path*' parameter, and it seems to attempt to load the file, but without success.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/11.png)

We attempted a basic Local File Inclusion attack and noticed that the code mitigates the attack through some filtering mechanism. However, this is interesting because the vulnerability is likely to be located here.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/12.png)

We used the payloads from [HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion) and found that we were able to bypass the protection with the first few attempts.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/13.png)

It seems that we don't need to use any *wrappers*, so we can read the contents of the **PHP** files.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/14.png)

We are viewing the *register.php* file:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/15.png)

We are enumerating the *utils.php* file, which is responsible for generating the random activation code. We can generate the activation code ourselves, so we will download the code to obtain the activation code.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/16.png)

Now that we have the code, we can create a small script that generates valid tokens associated with the registration date and time in a loop, and activate it ourselves without being an administrator.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/18.png)

#### Proof of concept

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/17.png)


Using the exploit to generate one token per second:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/19.png)

To simplify the process, I used all the tokens and launched it with the *Intruder* tool in **Burp Suite** to filter by the response '*Account activated!*'

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/20.png)

We authenticate ourselves and access the user panel:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/21.png)

After reviewing all the PHP files, it seems that this one writes content in temporary files of the path of an image:

```php
<?php

class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}

$code = base64_encode(serialize(new AvatarInterface));

echo "$code"

?>

```

We did a test and found that we can serialize and deserialize the '*code*' parameter correctly.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/23.png)

We generated our malicious payload to obtain a reverse shell.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/24.png)

We copied the payload and placed it in the cookie, then reloaded the website.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/25.png)

In my scenario, I set up a server with **Python** to run my '*m3.php*' file on the victim server. This file contains a classic reverse shell from *Pentester Monkey*:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/26.png)

We waited for the server to execute the payload, and then we obtained an interactive connection with the victim machine.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/27.png)

Once inside, I enumerated the database and extracted the hashes it stored, and then attempted to crack them with **hashcat**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/28.png)

#### Cracking with hashcat

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/29.png)

We reused *Bill's* credentials to authenticate via **SSH**.

## Privilege Escalation

It seems that there's a bash script for renewing certificates, and they're being moved to Bill's folder.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/30.png)

We launched the **pspy** tool and observed the execution of the script:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/31.png)

We created the certificate and injected a reverse shell into several fields, with the idea of it being executed by the root user and obtaining privileged shell access.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/BroScience/32.png)