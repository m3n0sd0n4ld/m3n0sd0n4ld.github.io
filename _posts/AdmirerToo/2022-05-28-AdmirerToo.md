---
title: AdmirerToo HackTheBox Writeup
tags: [writeup,rest,python,hackthebox,linux,api,suid]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/1.png)

## Scanning
We run nmap on all ports with scripts and software versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/2.png)

## Enumeration
We access the website, review source code and versions, but it looks like a simple corporate website.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/3.png)

We found an open directory listing with image files of the site, nothing we can use:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/4.png)

If we access a non-existent resource, we find that a domain name appears in "*mailto*".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/5.png)

We insert the domain in our "*/etc/hosts*" file, but we continue to see the same web site.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/6.png)

We tried to enumerate subdomains with the **wfuzz** tool, we managed to enumerate the subdomain "*db.admirer-gallery.htb*".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/7.png)

We access the resource and find the **Adminer 4.7.8** database manager.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/8.png)


We access the database manager, we list a table called "*gallery*" and we also have a *SQL command console* that might help us:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/8.png)


## Exploitation
Reviewing exploits, we found that we require authentication, the curious thing is that we have accessed only by clicking on the "*enter*" button, if we review the code we will find the credentials in hidden fields.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/9.png)

It was this resource that helped me to exploit the **SSRF**: [Vulnerability/Adminer SSRF（CVE-2021-21311)](https://github.com/EdgeSecurityTeam/Vulnerability/blob/main/Adminer%20SSRF%EF%BC%88CVE-2021-21311%EF%BC%89.md)

We create the redirection script, intercept the authentication request, change the IP and put the one of our VPN:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/10.png)

We intercept the request, change the server IP, the driver type and send the request.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/11.png)

The following image shows an unsuccessful attempt to upload a remote file.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/12.png)

Let's do another test, this time we will set the local IP to port 80 (default) and see what happens.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/13.png)

We run it and see that we are able to print the HTML code of the adminer site:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/14.png)

If we remember, there were ports that were *filtered*, I tried one by one until this one caught my attention.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/15.png)

We list an internally deployed **OpenTSDB**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/16.png)

#### Exploit: [OpenTSDB Arbitrary Code Execution](https://security.snyk.io/vuln/SNYK-JAVA-NETOPENTSDB-1041751l)

We make a proof of concept to send us 4 packets by icmp, we see that we are able to execute commands.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/17.png)

We set up a reverse shell and concatenate both vulnerabilities to gain access to the machine.

We try to read the file "*user.txt*", but we do not have permissions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/18.png)

We continue reviewing files, we find commented credentials in the file "*servers.php*".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/19.png)

We tested the credentials obtained on the user "*Jennifer*", managed to access by **SSH** and read the file "*user.txt*":

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/20.png)


## Privilege Escalation
We launch **linpeas.sh** and list a configuration file of the **OpenCATS** application:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/21.png)

We also list **fail2ban** deployed on the server.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/22.png)

This binary adds us to a block list when multiple failed **SSH** connections are made (exploited on other machines to escalate privileges).

#### Version Fail2ban v0.10.2:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/23.png)

We check the file, but we do not have write permissions, so we cannot abuse it:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/24.png)

We don't have permissions to write to other files either, but we see something interesting, the configuration to where it sends the mails.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/25.png)

Continuing to review and list other services, we found a service running on port *8080*:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/26.png)

We run curl on the port and find the **OpenCATS** authentication file (sounds familiar, right?):

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/27.png)

So, we do port forwarding via **SSH** and we manage to run the service from our attacker's computer.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/28.png)

We already reach the resource from our port *9000*. In addition, we identify the **OpenCATS 0.9.5.2** version:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/29.png)

But we don't know the access credentials, remember that we did have db credentials, we will have to get the hashes from the DB.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/30.png)

We couldn't crack the admin user hash, we can't reuse the cookie either, so we tried the credentials of "*jennifer*" and managed to log in to the panel:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/31.png)

Although we are inside, we see that we only have read.... permissions. But if we are inside the database? Why not change the password hash for another one we know? :D

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/32.png)

Yeah!

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/33.png)

#### Interesting Article: [OpenCATS PHP Object Injection to Arbitrary File Write](https://snoopysecurity.github.io/web-application-security/2021/01/16/09_opencats_php_object_injection.html)

Logically, we are not interested in gaining access to the machine, since we have access via **SSH**, what we are interested in is to manage to overwrite the **fail2ban** configuration file, to concatenate vulnerabilities and achieve privilege escalation. 

To generate payloads in the serialization I used the [**phpggc**](https://github.com/ambionics/phpggc) tool.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/34.png)

#### PoC

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/35.png)

We insert it in **Burp** and execute the request:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/36.png)

Now we see that the "*whois.conf*" file did not exist, but now it does and it contains our value, so we would be able to write files (and overwrite):

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/37.png)

The idea would be the following, if we create a payload in the whois configuration, this would be executed after the banning of our IP by **fail2ban**, since it would send an email and would have to make a **DNS** call... It's a bit far-fetched, but it could work. 

I know, you will be thinking why not modify directly a file of the *root user* or **fail2ban**, the problem is that we drag permissions of the service that runs **OpenCATS** and this does not have write permissions for those files.

#### PoC with ping:
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/38.png)

We review the contents of the file and run the "**whois**" binary on our IP address

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/40.png)

We listen with **ncat** and we see that we receive the connection from the machine:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/39.png)

We listen on port *9001* and receive a connection with the *root user* and read the file "*root.txt*".

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/AdmirerToo/41.png)




