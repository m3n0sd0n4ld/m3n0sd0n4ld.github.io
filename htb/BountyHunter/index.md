# BountyHunter HackTheBox Writeup
### Level: `Easy` | OS: `Linux`

![logo](1.png)

## Scanning
We run nmap on all ports with scripts and software versions.

![](2.png)

## Enumeration
We access the web resource and review the source code.

![](3.png)

#### Commented code
![](4.png)

We launch **dirsearch**, list some interesting files and directories.

![](7.png)

#### Files by extension

![](7-2.png)

#### Directory listing

![](5.png)

We review the "*README.txt*" file and find a list of unfinished tasks.

![](6.png)

We read the file "*bountylog.js*", we find the url of the application tracker. Seen these files, it seems that the way is to exploit the application.

![](8.png)

#### File result

![](9.png)

## Exploitation
From the website, we find the "*portal*" section that will take us to this "Beta" form that we will have to exploit. 

Since the application loads "*xml*" tags, it is very likely that we will have to exploit some **XXE** style vulnerability.

![](10.png)

Let's get to it! We capture a request from the form, we see a string in **urlencode + base64**.

We modify the values, insert a variable called "*poc*" with the value "*1*", insert in the field "*title*".

![](11.png)

We encode again in reverse and see that it works.

![](12.png)

#### File read ()
***note: Remember to encode!**

![](14.png)

If we remember the dirsearch log, we find a file called "*db.php*", these files usually have the flat credentials of the database connection. It is also possible that passwords are being reused. (in addition, we also have the users thanks to the reading of */etc/passwd*).

![](15.png)

We connect through the **SSH** service, read the user flag and see that we can execute a script as root.

![](16.png)

## Privilege Escalation
We read the file "*ticketValidator.py*", we do not have permissions to modify it. Inside, we find a conditional that is executed when the variable "*validationNumber*" is greater than *100*, so it returns a "*True*".

![](23.png)

We see an example of failed tickets, this will help us with the structuring.

![](22.png)

We create in a folder where we have read our malicious file "m3.md".

![](24.png)

Now we will call the script as sudo and load our files, we become root and we can read the flag.

![](21.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)
