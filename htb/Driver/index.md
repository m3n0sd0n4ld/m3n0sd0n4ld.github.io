# Driver HackTheBox Writeup
### Level: `Easy` | OS: `Windows`

![logo](1.png)

## Scanning
We launch a previous nmap to all ports and launch again an **nmap** with services and scripts to these ports.

![](2.png)

## Enumeration
We access the website, we see that we need a username and password to access what looks like a printer administration panel.

![](3.png)

We use the credentials "*admin:admin*" and access the printer control panel. We also enumerate the *driver.htb* domain, we put it in our "**/etc/hosts**" file.

![](4.png)

## Exploitation

We upload a reverse shell in **PHP** and see that it accepts it.

![](5.png)

After trying to upload a file to obtain command execution, we see that it does not work.

So, reading the statement, it says "*share*", so it occurred to me to look for information about drivers and samba, I found information about the use of "**.scf**" files (*Shell Command File)*.

![](6.png)

We run "**responder.py**" and upload the file. 
The idea is as follows:
- The machine, will execute the file upload by searching our SMB resource.
- When accessing our resource, it should show the hash "**NTLMv2**".
- We will crack the NTLMv2 hash to get the plain password, as these hashes are not usable for passthehash.

#### Burp request
![](7.png)

#### Capture NTLMv2 Hash with Responder.py

![](8.png)

We crack the password with the "**rockyou**" dictionary.

![](9.png)

We connect to "**evil-winrm**" and read the flag from *user.txt*.

![](10.png)


## Privilege Escalation
I didn't bother if there was an alternative route to climbing. Since the machine is called "**Driver**" and uses "**Windows**", I directly escalated privileges by exploiting the "**PrintNightmare**" vulnerability.

We create a user who will be an administrator.

![](11.png)

We connect to **evil-winrm**, we see that we are administrators and we read the flag of *root.txt*.

![](12.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)
