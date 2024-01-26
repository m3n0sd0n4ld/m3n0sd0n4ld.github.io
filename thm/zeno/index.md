# Zeno TryHackMe Writeup
### Level: `Medium` | OS: `Linux`

![logo](1.jpeg)

## Scanning
We run nmap on all ports with scripts and software versions.

![](2.png)


## Enumeration
We access the high web port and find an inactive resource.

![](3.png)

Launch "**dirsearch**" and list the directory "*rms*".
![](4.png)

Accessing the directory, we find a website with "*Restaurant Management System*" displayed.

![](5.png)

## Control panel
We listed the control panel, but it is out of service.

![](6.png)

We create a user and see that it is vulnerable to SQL Injection (Time-Based).

![](9.png)

We use the "**sqlmap**" tool, we manage to enumerate the databases and obtain some credentials, but it does not help us to connect via **SSH**.

### Databases name

![](7.png)

### Members table

![](8.png)

### Columns name

![](10.png)

### Users

![](11.png)


## Exploitation
We reviewed exploits and found this one for Remote Code Execution (RCE).

#### Exploit: [https://www.exploit-db.com/exploits/47520](https://www.exploit-db.com/exploits/47520)

The exploit has some faulty lines, we fix the exploit, run it and we have a command shell via **PHP**.
![](12.png)

### PoC

![](13.png)

We put a Netcat listening and run a reverse shell and gain access to the system.

### Reverse shell

![](14.png)

![](15.png)

We read the "*config.php*" file of the CMS, but the password is not valid for the user "*edward*".

![](16.png)

We do a quick reconnaissance with the "**lse**" script, we find two interesting things:
- A credentials.
- A service file that we have write permissions.

![](17.png)

![](18.png)

We use the password on the user "*edward*" and read the user flag.

![](19.png)


## Privilege Escalation
We check if we can run any script or binary with SUDO, we see that we can restart the system.

![](20.png)

We remember that previously we found a service file that we can modify, we have already done this procedure in other machines, so we modify the file and restart the machine, so we will force the new loading of the service file.

We create a service file with the following content:

```bash
[Unit]
Description=root

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'echo "edward ALL= (root) NOPASSWD: /usr/bin/sudo " >>/etc/sudoers'

[Install]
WantedBy=multi-user.target
```

When the machine restarts, it will grant us to use sudo as root, so we can run a bash, become root and read the flag.

![](21.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)
