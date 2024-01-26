# Ollie TryHackMe Writeup
### Level: `Medium` | OS: `Linux`

![logo](1.jpg)

## Scanning
We run nmap on all ports with scripts and software versions.

![](2.png)

## Enumeration
Enter the IP and the domain olliet.thm in "*/etc/hosts*" file to speed up in case of machine reset.

We access the website, list the software version and a user "*0day*".

![](3.png)

If we search **exploit-db.com**, we find at least two exploits reported in previous versions.

![](4.png)

Both exploits require valid credentials, if we try to do some quick tests we see that the software is protected against automated attacks, blocking our access for 5 minutes.

![](5.png)

We run **wfuzz** tool and we found db folder:

![](6.png)

We have directory listing, we find the default database file.

![](7.png)

If we look at the file "*SCHEMA.sql*" we see some default creds.

![](8.png)

We tried cracking the hash at **hashes.com**:

![](9.png)

The hash takes us to the default credentials, but they are not valid, so we will have to find another way.

We go back to the nmap information, this time we will connect to port 1337, it seems that there is a bot asking questions, as we know the breed of the dog, we answer "*bulldog*" and it gives us some credentials.

![](10.png)


## Exploitation
Log in as administrator, now we will have to find a way to access the server from the CMS.

![](11.png)

I tried to run the exploit of version "*1.4.4*", but it doesn't work (logical, possibly patched). Anyway, it is good practice to check it manually.

![](12.png)

If we do the manual check, we can see that the server response is still deficient to SQL Injection attacks.

![](13.png)

We capture the **Burp** request and run **sqlmap** indicating the file, we can see that we can list the databases.

![](14.png)

We check our privileges, we see that we have many privileges that would allow us to read and write files.

![](15.png)

Extract the file "*/etc/passwd*":

![](16.png)

#### Content passwd file:
![](17.png)

In my case, I used a reverse shell of pentester monkey and uploaded it in the default directory.

![](18.png)

We check if the file exists, we see that it does!

![](19.png)

Now, we go on listen, re-execute the file *m3.php* and gain access.

![](20.png)

We try to read the user flag and we do not have access. We try the password and we see that we can access (remember that we were asked for authentication by key in the SSH and prevented us from connecting), we read the flag of *user.txt*

![](21.png)


## Privilege Escalation
If we look for files with inherited SUID, we check that there is "**pkexec**", although the machine does not have the "**gcc**" binary, we could try to compile it locally, upload it and run it... But let's try to exploit the machine from another attack vector.

![](22.png)

We run the **linpeas** tool, we see that it is running interesting actions:

![](23.png)

We download and run "**pspy**" on the machine, we see that every few minutes the "*feedme*" binary with *UID "0" (root)* is executed.

![](24.png)

We look for the file, check that we have permissions on it so that we can replace it with another malicious binary controlled by us.

![](25.png)

#### Content feedme file:
![](26.png)

We create our malicious "*feedme*" file, in my case I inserted a line in bash to get a reverse shell:

![](27.png)

We put a **netcat** listening, wait a few minutes, we will receive a connection as root and read the flag *root.txt*:

![](28.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)
