# Paper HackTheBox Writeup
### Level: `Easy` | OS: `Linux`

![logo](1.png)

## Scanning
We run nmap on all ports with scripts and software versions.

![](2.png)

## Enumeration
We access the web resource on port 80, but find nothing relevant.

![](3.png)

We access the web resource on port 443, check the code, but find nothing interesting either.

![](4.png)

We launch the **whatweb** tool and list the domain "*office.paper*".

![](5.png)

We put it in the file "*/etc/hosts*" and find a new site with **WordPress version 5.2.3**:

![](6.png)

We list a possible **WordPress** user "*Prisionmike*":

![](7.png)

But it seems that the user is not valid:

![](8.png)

If we look at the articles, they mention users and give clues as to what is happening on the site. Apparently, they are asking to delete a post that is in drafts, as it thinks it is not safe to store them there.

![](9.png)


## Exploitation
It can be seen that this version of **WordPress** is vulnerable and it would be possible to read private posts.

![](10.png)

##### Exploit: [WordPress Core < 5.2.3 - Viewing Unauthenticated/Password/Private Posts - Multiple webapps Exploit (exploit-db.com)](https://www.exploit-db.com/exploits/47690)

Using the exploit, we see some posts that we did not know, for example, this one already mentions that there are users leaving posts in drafts with relevant information.

![](11.png)

We use the exploit in descending order, we see a secret registration link for new employees at "*chat.office.paper*...."

![](12.png)

We access the site and find an application called "**rocket.chat**":

![](13.png)

If we look for exploits, we find two interesting ones, a NoSQL and an RCE:

![](14.png)

I tried to exploit some of the vulnerabilities, but it seems that they did not apply to the deployed version. So I registered an account and logged into the site for further enumeration.

![](15.png)

Apparently, there is a bot (*recyblops*) with which you can execute commands, by testing I managed to enumerate the user "*dwight*" when trying to load a file "*test.txt*" from his directory.

![](16.png)

Continuing with the tests, I managed to run a kind of system "**ls***", enumerating the file "*portfolio.txt*".

![](17.png)

It seems that the bot is vulnerable to Path Traversal, we managed to read the "*/etc/passwd*" file:

![](18.png)

It seems to be well sanitized and does not allow to execute commands, but you can enumerate files:

![](19.png)

We read files from the bot, we see the content of the script and that it calls the file "*start_bot.sh*".

![](20.png)

##### Contents of the file "start_bot.sh":

![](21.png)

We check the "*.env*" file and find the **rocket.chat** credentials:

![](22.png)

If we try to access through the browser, we see that the site does not allow the Bots to make connections via the web.

![](23.png)

Let's remember that we knew which users are in the system, so we test the "*dwight*" one, get **SSH** access and read the "*user.txt*" flag.

![](24.png)


## Privilege Escalation
We launched the "**linpeas**" tool to perform a preliminary system reconnaissance and found that the machine is vulnerable to *Polkit*.

![](25.png)

##### Exploit: [GitHub - Almorabea/Polkit-exploit: Privilege escalation with polkit - CVE-2021-3560](https://github.com/Almorabea/Polkit-exploit)

We download the exploit on the victim machine, run it with **Python3** and manage to escalate privileges to root.

![](26.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)