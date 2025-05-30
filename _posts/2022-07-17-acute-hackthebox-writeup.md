---
title: Acute HackTheBox Writeup
tags: [antivirus, evasion, hackthebox, invoke-command, powershellweb, windows, writeup]
style: border
color: success
description: ""
---

![logo](../assets/img/acute/1.png)

## Scanning
We run nmap on port 443 with scripts and software versions.

![](../assets/img/acute/2.png)

## Enumeration
We put the subdomain name "atserver.acute.local" and *"acute.local"* found in the DNS in the file *"/etc/hosts"*.

We access the website of "*acute.local*", but it is not available.

![](../assets/img/acute/3.png)

We tried accessing the other web resource and it appears that there is a corporate website exposed.

![](../assets/img/acute/4.png)

The website does not seem to be complete, only the "*about.html*" section works, there is a link in the "*New Starter Forms*" section with an office file:

![](../assets/img/acute/5.png)

It looks like we have an office file with internal information, in the document it explains the different areas of the different departments, but it also includes several links that would be very relevant for an attacker.

![](../assets/img/acute/6.png)

We list below another link that takes us to a "*Windows PowerShell Web Access*" portal and the name of a person who appears to be a corporate administrator.

![](../assets/img/acute/7.png)

In addition, we list the **default password** used in the entity:

![](../assets/img/acute/8.png)


## Exploitation
We access the "*Acute_Staff_Access*" site, we list an authentication panel where we could gain access by powershell. But we will not be able to exploit this site without having valid credentials or at least valid users to try password spraying. 


![](../assets/img/acute/9.png)

Remember that we have access to the "*about.html*" file, where we can list several corporate users.

![](../assets/img/acute/10.png)

We also check the metadata of the office file, usually we usually find corporate users (and their format ;)), computer names and software used.

![](../assets/img/acute/11.png)

As there were not many names, I manually generated several users in different ways of the most typical I find in real scenarios:

![](../assets/img/acute/12.png)

They are few, so it is possible to use **Burp's intruder**, we see that the user "*edavies*" appears:

![](../assets/img/acute/13.png)

We see that we can access the **powershell**, but at least we can't find the flag on that user.

![](../assets/img/acute/14.png)

It seems to have the AV, since we can't run ps1, we will have to try to evade it.

![](../assets/img/acute/15.png)

We check if there are any directories that are excluded from the AV, we see that there are two:

![](../assets/img/acute/16.png)

We create an exe file with **msvenom** and *shikata_ga_nai* to bypass EDR:

![](../assets/img/acute/17.png)

Now we transfer and run the file to gain access.

![](../assets/img/acute/18.png)

We get the reverse shell and check our privileges.

![](../assets/img/acute/19.png)

The reverse shell closes every now and then, I can't run, so I upload another binary with a meterpreter to maintain a more stable interactive connection.

![](../assets/img/acute/20.png)

Taking screenshots, we see how someone is using the same session, since the first ss was in the powershell and the 2nd one appears on the desktop (and we have not been).

![](../assets/img/acute/21.png)

We see how it is typing some credentials and passing them in *SecureString*:

![](../assets/img/acute/22.png)

I tried several combinations until I managed to execute commands as the user "*imonks*".

![](../assets/img/acute/23.png)

```powershell
$user = 'acute\imonks'
$password = ConvertTo-SecureString 'W3_4R3_th3_f0rce.' -AsPlainText -Force
$cred = New-Object System.Management.Automation.Pscredential ($user,$password)
Invoke-Command -ComputerName ATSSERVER  -ConfigurationName dc_manage -Cred $cred -ScriptBlock { whoami } 
```


## Privilege Escalation
We see if your directory exists and we see two files, the user flag and "*wm.ps1*".

![](../assets/img/acute/24.png)

It appears that the file is a script running as the user "*jmorgan*".

![](../assets/img/acute/25.png)

We see that we are able to change the "*Invoke-Command*" and insert a malicious binary to be executed by the user "*jmorgan*".

![](../assets/img/acute/26.png)

Now we run the script and get a reverse shell with the user "*jmorgan*":

![](../assets/img/acute/27.png)

Ok, let's create the shell and look at our privileges (which are not few hehehe)

![](../assets/img/acute/28.png)

We see that we are also administrators, so we can still read the administrator flag, but it is not in the directory.

![](../assets/img/acute/29.png)

We try to extract the hashes:

![](../assets/img/acute/30.png)

We cracked with hashcat the hashes, we managed to get the password on the local administrator's plane. 

![](../assets/img/acute/31.png)

I try this password with the rest of the users, it seems to work only with the user "*awallace*":

![](../assets/img/acute/32.png)

We see that we are *users of the domain* and we are in the group "*managers*".

![](../assets/img/acute/33.png)

We are executing system commands to list files, we find a script "*keepmeon.bat*".

![](../assets/img/acute/34.png)

We read the script, we see that there is a comment that "*Lois*" (remember that she is the administrator) is executing every *5 minutes this script*, this makes me think of repeating the same move, writing in it or in another bat file a reverse shell or code execution to read the root flag.

![](../assets/img/acute/35.png)

##### Content "keepmeon.bat":

![](../assets/img/acute/36.png)

We try to list the users and see the user "*lhopkins*", which should belong to the administrator:

![](../assets/img/acute/37.png)

After several unsuccessful tests, we tried to create a malicious **bat** to add the user "*awallace*" to the site_admin group.

We try to read the flag, but we see that we will have to wait a few minutes for the scheduled task to run and get scale privileges.

![](../assets/img/acute/38.png)

After waiting a few minutes, we tried again to read the flag and succeeded.

![](../assets/img/acute/39.png)
