# Unicode HackTheBox Writeup
### Level: `Medium` | OS: `Linux`

![logo](1.png)

## Scanning
We run nmap on all ports with scripts and software versions.

![](2.png)

## Enumeration
We access the web service.

![](3.png)

We find a section to authenticate and others to register, we use this one and create an account.

![](4.png)

Click on the "*Upload a threat report*" section and you will find a form to upload files.

![](5.png)

#### Form to upload files:

![](6.png)

It seems to let us upload the file.... But where is it?

![](7.png)

We decode our **JWT** of the registered account and see that the "*jku*" field is calling a "*jwks.json*" file.

![](8.png)

#### Content jwks.json file:

![](9.png)


## Exploitation
For this part, I was helped by the following [article](https://blog.pentesteracademy.com/hacking-jwt-tokens-jku-claim-misuse-2e732109ac1c)

I follow the tutorial and create one public and one private key:

![](10.png)

Now would be the time to build our own "*jwks.json*" file and generate the value of "*n*" and the value of "*e*" and trick the application to load the file from a fraudulent endpoint.

![](12.png)

We create an Python script:

![](13.png)

```python
!#/usr/bin/python3
from Crypto.PublicKey import RSA

fp = open("publickey.crt", "r")
key = RSA.importKey(fp.read())
fp.close()

print("n:", hex(key.n))
print("e:", hex(key.e))

```

We run the script and we will have the value of both letters:

![](14.png)

We modify the file "*jwks.json*" with our values and raise a server with python.

![](15.png)


Trying to enter the url again and leaving the attacker's url behind, we see that it accepts the jwt, although it redirects us to the login and we do not get the server to execute our file.

#### Create JWT:

![](17.png)

#### Use in Burp:

![](16.png)

If we review the fuzzing performed with the **wfuzz** tool, we see that we have listed some actions that we did not have authorization, I was curious about the "*redirect*", as it could be exploited for the server to make the communication with my attacker machine and make it load my malicious "*jwks.json*" file.

![](11.png)

We create our **JWT** by adding the redirect to our machine.

![](18.png)

The server has loaded our malicious file.

![](19.png)

We change our nickname to "*admin*" and repeat the above process.

![](20.png)

We change the cookie, refresh the page and log in as the "*admin*" user:

![](21.png)

We see the "*display*" section, it seems that it loads local files.

![](22.png)

We try to load the file "*/etc/passwd*", but it seems that there is some filter to bypass.

![](23.png)

We intercept in **Burp** and encode in "*unicode*" format (the host name is the clue ;)) and we get to load the file "*/etc/passwd*".

![](24.png)

We read the flag from "*user.txt*".

![](25.png)
.
Viewing the headers, we load the file of available sites in **nginx**, we list commented information from a file "*db.yaml*" stored in the user's folder

![](26.png)

We obtain some creds from the DB:

![](27.png)

We reuse the creds via **SSH** and they work, we see that we can run the "*treport*" binary as root and with **SUDO**.

![](28.png)


## Privilege Escalation
It seems to allow us to create, read and download a report, this could be running some binary underneath that we have access to, or it could be abused to modify some other system file.

![](29.png)

If we try to download, we enter our IP address and it downloads from our machine.

![](30.png)

#### Result on attacker machine:

![](31.png)

I did other tests, I saw that in one of them it makes a **curl**.

![](32.png)

If we see the **curl** options, there is a very interesting one, since it allows us to pass by parameters a configuration file to read it

![](33.png)

I did several tests, in one I did get it to run and read the "*root.txt*" file successfully.

![](34.png)

---
## About

David Utón is Penetration Tester and security auditor for web and mobiles applications, perimeter networks, internal and industrial corporate infrastructures, and wireless networks.

#### Contacted on:

<img src='https://m3n0sd0n4ld.github.io/imgs/linkedin.png' width='40' align='center'> [David-Uton](https://www.linkedin.com/in/david-uton/)
<img src='https://m3n0sd0n4ld.github.io/imgs/twitter.png' width='43' align='center'> [@David_Uton](https://twitter.com/David_Uton)