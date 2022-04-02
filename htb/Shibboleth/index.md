# Shibboleth HackTheBox Writeup
### Level: `Medium` | OS: `Linux`

![logo](1.jpg)

## Scanning
We run nmap on all ports with scripts and software versions.

![](2.png)

## Enumeration
We put the domain in our "*/etc/hosts*" file and access the web site.

![](3.png)

There seems to be nothing interesting on the site, I do fuzzing and virtual hosting to get more valid subdomains.
![](4.png)

All subdomains found point to the Zabbix dashboard.
![](5.png)

After a long time without finding anything, I try again to launch **nmap**, this time only to *UDP ports*.

*Port 623* appears, used in **IPMI** services.
![](6.png)

We tried using the metasploit scanner and managed to enumerate the version used in the IPMI service.
![](7.png)


![](8.png)

With the valid credentials, we access the site panel and the **Zabbix 5.0.17** version.
![](9.png)

## Exploitation
We searched for exploits in **searchsploit** and found a Remote Code Execution (RCE) in our version. (It can't be a coincidence :P)
![](10.png)

#### Exploit: [Zabbix 5.0.17 - Remote Code Execution (RCE) (Authenticated) - PHP webapps Exploit (exploit-db.com)](https://www.exploit-db.com/exploits/50816)

We set a **netcat** to listen and run the exploit to gain access to the machine:
![](11.png)

#### Result
![](12.png)

We access the user folder "*ipmi-svc*", but we do not have access to read the file "*user.txt*".

We also found the file *.backup.sh* and *.ipmi-svc.log*, it turned out to be the tool "**linpeas.sh**" and the log with the result, from here thank the person who left me the dirty work done! ;)
![](13.png)

We review what **linpeas** has put out, we see that we have the database credentials.
![](14.png)

We access the **MariaDB** database, find the hashes of the three users. Here I realized that I had the **Zabbix** password of the "*administrator*" user (*Administrator aka IPMI Service*, does it ring a bell?).
![](15.png)

We try to authenticate with the password and yes! We gain access with the user and we can read the flag of *user.txt*.

PS: I tried to crack the other two hashes, but without success.
![](16.png)

## Privilege Escalation
After a while of looking around, I was listing software versions that I could use, until I found that I had the solution right under my nose.
![](17.png)

This version of **MariaDB** is vulnerable to *command injection* by abusing the "*wsrep_provider*" functionality, we will take advantage of this flaw to load our own malicious binary and gain root access.

#### Exploit: [MariaDB 10.2 - 'wsrep_provider' OS Command Execution](https://www.exploit-db.com/exploits/49765)

We create our malicious binary in which we will insert a reverse shell.
![](18.png)

Afterwards, we will put a **netcat** listening and execute the following command.
```bash
mysql -u zabbix -p -e 'SET GLOBAL wsrep_provider="/tmp/m3.so";'
```
![](19.png)

We gain root access and we can read the flag *root.txt*.
![](20.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)
