---
title: Shibboleth HackTheBox Writeup
tags: [mariadb,writeup,ipmi,zabbix,hackthebox,linux]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/1.jpg)

## Scanning
We run nmap on all ports with scripts and software versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/2.png)

## Enumeration
We put the domain in our "*/etc/hosts*" file and access the web site.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/3.png)

There seems to be nothing interesting on the site, I do fuzzing and virtual hosting to get more valid subdomains.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/4.png)

All subdomains found point to the Zabbix dashboard.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/5.png)

After a long time without finding anything, I try again to launch **nmap**, this time only to *UDP ports*.

*Port 623* appears, used in **IPMI** services.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/6.png)

We tried using the metasploit scanner and managed to enumerate the version used in the IPMI service.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/7.png)


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/8.png)

With the valid credentials, we access the site panel and the **Zabbix 5.0.17** version.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/9.png)

## Exploitation
We searched for exploits in **searchsploit** and found a Remote Code Execution (RCE) in our version. (It can't be a coincidence :P)
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/10.png)

#### Exploit: [Zabbix 5.0.17 - Remote Code Execution (RCE) (Authenticated) - PHP webapps Exploit (exploit-db.com)](https://www.exploit-db.com/exploits/50816)

We set a **netcat** to listen and run the exploit to gain access to the machine:
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/11.png)

#### Result
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/12.png)

We access the user folder "*ipmi-svc*", but we do not have access to read the file "*user.txt*".

We also found the file *.backup.sh* and *.ipmi-svc.log*, it turned out to be the tool "**linpeas.sh**" and the log with the result, from here thank the person who left me the dirty work done! ;)
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/13.png)

We review what **linpeas** has put out, we see that we have the database credentials.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/14.png)

We access the **MariaDB** database, find the hashes of the three users. Here I realized that I had the **Zabbix** password of the "*administrator*" user (*Administrator aka IPMI Service*, does it ring a bell?).
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/15.png)

We try to authenticate with the password and yes! We gain access with the user and we can read the flag of *user.txt*.

PS: I tried to crack the other two hashes, but without success.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/16.png)

## Privilege Escalation
After a while of looking around, I was listing software versions that I could use, until I found that I had the solution right under my nose.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/17.png)

This version of **MariaDB** is vulnerable to *command injection* by abusing the "*wsrep_provider*" functionality, we will take advantage of this flaw to load our own malicious binary and gain root access.

#### Exploit: [MariaDB 10.2 - 'wsrep_provider' OS Command Execution](https://www.exploit-db.com/exploits/49765)

We create our malicious binary in which we will insert a reverse shell.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/18.png)

Afterwards, we will put a **netcat** listening and execute the following command.
```bash
mysql -u zabbix -p -e 'SET GLOBAL wsrep_provider="/tmp/m3.so";'
```
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/19.png)

We gain root access and we can read the flag *root.txt*.
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Shibboleth/20.png)




