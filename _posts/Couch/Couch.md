---
title: Couch TryHackMe Writeup
tags: [writeup,rest,python,tryhackme,linux,api,suid]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Couch/1.jpg)

## Scanning
We launched the **nmap** tool, with script and software versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Couch/2.png)

## Enumeration
We access the site, and at first glance we see a **couchdb** information leak.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Couch/3.png)


#### List all the databases
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Couch/4.png)

#### Displays the database information we specify
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Couch/5.png)

#### Example of obtaining relevant information:
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Couch/6.png)

## Exploitation
Now that we know how it works, let's check the database called "*secret*" and get some credentials in plain text.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Couch/7.png)

We access through the **SSH** service and read the flag of *user.txt.*
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Couch/8.png)

## Privilege Escalation
We read the file "*.bash_history*", we find a record of a connection to **docker**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Couch/9.png)

#### Reading of the root flag

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Couch/10.png)




