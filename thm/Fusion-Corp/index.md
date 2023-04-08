# Fusion Corp TryHackMe Writeup
### Level: `Hard` | OS: `Windows`

![logo](1.jpeg)

## Scanning
We launch **nmap** a bit *"aggressive"* (but we are in a controlled environment and we can afford it :P), to all ports and with verbosity to discover ports as **nmap** is getting them.

![](2.png)

### nmap with versions and scripts

![](3.png)

## Enumeration
We access the web service, find the corporate website and list some of the organization's users. This is great, as we could use them to brute force some exposed service.

![](4.png)

We use the **nikto** tool, it discovers the directory *"/backup/*. 

![](5.png)

Accessing the directory, we find an office file containing the name and username of the employees.

![](6.png)

#### Content ods file
![](7.png)

We use the **kerbrute** tool to check which users exist, it quickly lists the user *"lparker"*.

![](8.png)

## Exploitation
Once we have a user, we can check if the account is ASReproastable and consult its hash in the KDC.

![](9.png)

We crack the hash with **hashcat** and *rockyou dictionary*, we will get the password in clear.

![](10.png)

### Read the first flag 

![](11.png)

We do a reconnaissance, we see that AV is enabled in the system and it prevents us from running some reconnaissance binaries.

Seeing that I can't find anything, I launch ldapsearch with the credentials and coincidentally, I find some flat credentials in the description of the user "jmurphy".

![](13.png)

#### Credentials evidence
![](14.png)

We use the credentials of the new user, read the user flag and see the privileges.... Oh wow! The privilege escalation looks good ;)

![](15.png)

## Privilege Escalation
We make use of the great tool **evil-winrm** and this article from [HackPlayers](https://www.hackplayers.com/2020/06/backup-tosystem-abusando-de-los.html). Actually the vulnerability allows to abuse the backup privilege to write and restore the modified ACLs as we wish.

![](16.png)

We connect with our user and read the administrator flag.

![](17.png)

## Post-exploitation

Once we have gained access, it is time to obtain the hashes of the most relevant users.

#### NTLM HASHES
![](18.png)

#### Commitment Active Directory

![](19.png)

#### RDP connection

![](20.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)
