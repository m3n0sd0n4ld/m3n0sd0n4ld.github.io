# Couch TryHackMe Writeup
### Level: `Easy` | OS: `Linux`

![logo](1.jpg)

## Scanning
We launched the **nmap** tool, with script and software versions.

![](2.png)

## Enumeration
We access the site, and at first glance we see a **couchdb** information leak.

![](3.png)

Looking for information about this software, I find some basic commands that will help us to obtain information from the different databases.

#### List all the databases
![](4.png)

#### Displays the database information we specify
![](5.png)

#### Example of obtaining relevant information:
![](6.png)

## Exploitation
Now that we know how it works, let's check the database called "*secret*" and get some credentials in plain text.

![](7.png)

We access through the **SSH** service and read the flag of *user.txt.*
![](8.png)

## Privilege Escalation
We read the file "*.bash_history*", we find a record of a connection to **docker**.

![](9.png)

#### Reading of the root flag

![](10.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)
