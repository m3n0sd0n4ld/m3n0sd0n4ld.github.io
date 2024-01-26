# Mnemonic TryHackMe Writeup
### Level: `Medium` | OS: `Linux`

![logo](1.png)

## Scanning
We launch **nmap** with scripts and software versions.

![](2.png)

## Enumeration
We access the web service, we only see that it is in test mode.

![](3.png)

We access the file *"robots.txt"* and list the directory *"/webmasters/"*.

![](4.png)

We run the **dirsearch** tool with some known extensions and a common dictionary in the directory listed above.

We list some interesting directories.

![](5.png)

We listed an administration panel in the "/webmasters/admin/" directory, but it does not work.

![](6.png)

We continue with **dirsearch** and start searching for files by known extensions in the directories listed above. 

We list a *backups.zip* file:

![](7.png)

We see that the file has a password to decompress, we use **zip2john** and crack the hash with the **rockyou** dictionary.

We use the password and read the file, it gives us the username of the **FTP** service.

![](8.png)

We performed brute force with the enumerated user, the **rockyou** dictionary and the **Hydra** tool. We managed to find the password of the **FTP** service.

![](9.png)

We use the **FTP** service credentials, list several folders and two interesting files *"id_rsa"* and *"not.txt"*.

![](10.png)

#### Content of both files:

![](11.png)

## Exploitation
We use the **ssh2john** tool, crack the hash with john and the wordlist **rockyou** to get the password.

We use the credentials in the **SSH** service to gain access to the machine.

![](12.png)

We see that we have a restricted bash, so we reopen the ssh session with *"bash --noprofile"* and export a couple of environment variables so we can have an interactive shell.

![](13.png)

I search the internet for the words "*Mnemonic crypto*", find this tool on this **[github](https://github.com/MustafaTanguner/Mnemonic)**, download the tool and try the numerical file.

At the moment there is nothing we can do, as we need a photograph.

If we try to list the directories and files, we are able to list a couple of files of the user "Condor", there we see two files with the title in base64.

![](14.png)

#### A file is the flag of user.txt

![](15.png)

#### Content 2nd file

![](16.png)

We go back to the tool, specify the photo and the path to the text file, we will get the password of the user "*condor*".

![](17.png)

## Privilege Escalation
We authenticate as the user "*condor*" and we see that we are able to run a python script with **SUDO**.

![](18.png)

#### Python script in execution

![](19.png)

We see that "**date**" is executed without mentioning the absolute path, this would allow us to replace it and modify the path to execute our malicious binary and gain access.

![](20.png)

But it does not work! So we continue reviewing the code, we see something suspicious, the function with *code 0* allows you to write, so we would still be able to execute commands like root....

![](21.png)

#### Proof of concept

![](22.png)

Well, easy, we call the bash binary with the flag *"-p"* and we will get a shell as root.

![](23.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)
