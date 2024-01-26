# Mustacchio TryHackMe Writeup
### Level: `Easy` | OS: `Linux`

![logo](1.png)

## Scanning
We performed an nmap scan of all ports, with scripts and versions.

![](2.png)

## Enumeration
We access the first web resource (port 80), check the website and its source code, but find nothing useful.

![](3.png)

We launch the **dirsearch** tool, list the directory *"/custom/"* which looks interesting.

![](4.png)

We access the directory and find a file *"users.bak"* which usually contains relevant information.

![](5.png)

Download the file, crack the password hash with an online tool and get the password in clear.

![](6.png)

We access the other web resource (port 8765), insert the credentials in the administration panel and access the inside of the application.

![](7.png)

## Exploitation
We see that the site asks us to write **XML code**.

![](8.png)

We do some XML code tests, nothing interesting so far. But on the other hand, we see a new path to a *.bak* file and we get a hint that the user *"Barry"* can connect via **SSH** service with his private key.

![](9.png)

We download the file, we see that we have listed the structure of the XML in question, so we could continue investigating to exploit it.

![](10.png)

#### Testing

![](11.png)

#### PoC XXE/XEE
```XML
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "/etc/passwd"> ]>
<comment>
  <name>Testing</name>
  <author>m3n0sd0n4ld</author>
  <com>&xxe;</com>
</comment> 
```

![](12.png)

We repeat the same process, this time we will read the **id_rsa** file of the user *"Barry"*.

![](13.png)

We copy the key, we see that it is encrypted. We use the tool **ssh2john.py** and crack it with the *rockyou dictionary*.

![](14.png)

We authenticate through the **SSH** service and read the *user.txt* flag.

![](15.png)

We list the binary *"live_log"* in the path of the user *"joe"*.

![](16.png)

#### Use strings in file

![](17.png)

## Privilege Escalation

Since the call to the **"tail"** binary is not made with its absolute path, an attacker could create a malicious binary and change its *PATH* to execute the illegitimate one.

![](18.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)
