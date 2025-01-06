---
title: UpDown HackTheBox Writeup
tags: [tgt,ticketer,tickets,kerbrute,yoserial,kerberos,invoke-command,windows,mssql-client,serialization,writeup,hackthebox,psexec,silver-ticket,command-injection,mssql]
style: border
color: success
description: ""
---

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgPbcK1vhyX_GGTpGHFFWgCpeMPHhxwEZT8Jy5S6GzU3aadonr6cgi20dfUQepcIToP57nXXSzd8Gsm9T2HUJgM91CMDz-Lrs2c42th5X7D-jMVu8DYftKg6jwu7KF_qzkFpgET9z-7QSR3DgaXurRnhf4xEZJQ8_JpuOWDxBIBxT82oGSCyKodLfh1jA=w640-h483)](https://blogger.googleusercontent.com/img/a/AVvXsEgPbcK1vhyX_GGTpGHFFWgCpeMPHhxwEZT8Jy5S6GzU3aadonr6cgi20dfUQepcIToP57nXXSzd8Gsm9T2HUJgM91CMDz-Lrs2c42th5X7D-jMVu8DYftKg6jwu7KF_qzkFpgET9z-7QSR3DgaXurRnhf4xEZJQ8_JpuOWDxBIBxT82oGSCyKodLfh1jA)

  

Scanning
========

We run **nmap** tool on ports 53, 80, 88, 135, 139, 389, 445, 464, 593, 636, 1433, 3268, 3269, with script and software versions:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiVYgUraz700E5sjebLmZkmRP29gWg0yoaBufzg2TzkblTTBAD-Bn9VAYBCMEwVUjsu_5psF0oWmvEkwqzHvS0P8zz4Hh6yF9din_vEP-z97wuescowIe7VT9qgtXgiNTUBegKSoA3dNo9tPSIHh6awNk49UK5n5dzL3SVrg9Vei-stzjzmgs6RLAdkeg=w613-h640)](https://blogger.googleusercontent.com/img/a/AVvXsEiVYgUraz700E5sjebLmZkmRP29gWg0yoaBufzg2TzkblTTBAD-Bn9VAYBCMEwVUjsu_5psF0oWmvEkwqzHvS0P8zz4Hh6yF9din_vEP-z97wuescowIe7VT9qgtXgiNTUBegKSoA3dNo9tPSIHh6awNk49UK5n5dzL3SVrg9Vei-stzjzmgs6RLAdkeg)

  

Enumeration
===========

We access the web service, we find the corporate intranet:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhTqw81LPHEOSWh23StKojYX4va9h_MGxDx7PC-oJ5CUVIf0irG0s02_KNRWqIcaONYSaGNjoFlIWwvJbd_2DGieA0ew7QLE5xTwj7UfBz-2AKsrpbQNRFttpo1Q6bFa16xSlaFjhpldgzxbtcjvDw1dozrVdcAtBPN-eaf8kPvBM81sjS-RM13rIqkUQ=w640-h600)](https://blogger.googleusercontent.com/img/a/AVvXsEhTqw81LPHEOSWh23StKojYX4va9h_MGxDx7PC-oJ5CUVIf0irG0s02_KNRWqIcaONYSaGNjoFlIWwvJbd_2DGieA0ew7QLE5xTwj7UfBz-2AKsrpbQNRFttpo1Q6bFa16xSlaFjhpldgzxbtcjvDw1dozrVdcAtBPN-eaf8kPvBM81sjS-RM13rIqkUQ)

  
Here you can see news and alerts, indicating that _NTLM_ access has been disabled.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgggknLRaeCZnkepl_OSMWXTInuXcGxBwTkdbfQNo8QwahHB56RR0gnOtlzMATrGoPmkEAMqFKK906hHL9BUf-yXqi5Dp8rGXRANNNGOMJRSLKHYRlY6r_6N29Mzy2-5zxGZGA6v9QA7K9_HPq3cqDHxg2ooUJQZUCdB4aFYrk0xoKJtIzjcVbM_50R_Q=w640-h614)](https://blogger.googleusercontent.com/img/a/AVvXsEgggknLRaeCZnkepl_OSMWXTInuXcGxBwTkdbfQNo8QwahHB56RR0gnOtlzMATrGoPmkEAMqFKK906hHL9BUf-yXqi5Dp8rGXRANNNGOMJRSLKHYRlY6r_6N29Mzy2-5zxGZGA6v9QA7K9_HPq3cqDHxg2ooUJQZUCdB4aFYrk0xoKJtIzjcVbM_50R_Q)

  

We enumerate a corporate email and domain user:  
  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgXcS56vR_0wjnh6ATBfuiX8Kag6w1asKc2hUzIl3o06jKtB-7vxfBkdrHFrdWWvwjgSI5T-Q8tg5O66sqtNYyDMxuDBVlZmiASB0Y1uCCgI8Ql1qCXK0y7M4s6jqkHtsSdgq165duPxhHEQ5ShUZgyaQPOCvabxyg-AXNLm0jkcYiTB3g7pPgWm3yeew=w600-h640)](https://blogger.googleusercontent.com/img/a/AVvXsEgXcS56vR_0wjnh6ATBfuiX8Kag6w1asKc2hUzIl3o06jKtB-7vxfBkdrHFrdWWvwjgSI5T-Q8tg5O66sqtNYyDMxuDBVlZmiASB0Y1uCCgI8Ql1qCXK0y7M4s6jqkHtsSdgq165duPxhHEQ5ShUZgyaQPOCvabxyg-AXNLm0jkcYiTB3g7pPgWm3yeew)

  

Now, we found a register users forms:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiYk1DdCFfOB5WUtv6tfgkFkmwENjq8TlgdUtK76F68EWvSdgWR5KieSGkGncSFpI4CmqVW04pD2gt2yCy__D1wKFAiDCdwFp1gx_-IXvez7Lb6Xq5yJfEarFy0yeVu1j78SHo4jEGqB-EfsRebH-6EhiQHl9ImhOenM_QClASx3iZTWFZi2SKIGHDBZg=w515-h640)](https://blogger.googleusercontent.com/img/a/AVvXsEiYk1DdCFfOB5WUtv6tfgkFkmwENjq8TlgdUtK76F68EWvSdgWR5KieSGkGncSFpI4CmqVW04pD2gt2yCy__D1wKFAiDCdwFp1gx_-IXvez7Lb6Xq5yJfEarFy0yeVu1j78SHo4jEGqB-EfsRebH-6EhiQHl9ImhOenM_QClASx3iZTWFZi2SKIGHDBZg)

  

Here we are told that we can contact you to change the user's password, the password will be the same as the user's password.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhDS7pIsdF4LsWFljBQO8QGmozRkQ9n8cIvCGF6edIVsBvxpQCim_fWis1h2P58eievMvdYdHrQeqdxsfOhYhNd2GwZmWb_ZcAkEwyNvPotJvPXfv-xhBJOCMs7ijA2bHcZRyE8CpGmemgb9D-5URmbxCljopsQ-4uOJqn6KueRKYdscZOCcYX6Bb9Tag=w640-h332)](https://blogger.googleusercontent.com/img/a/AVvXsEhDS7pIsdF4LsWFljBQO8QGmozRkQ9n8cIvCGF6edIVsBvxpQCim_fWis1h2P58eievMvdYdHrQeqdxsfOhYhNd2GwZmWb_ZcAkEwyNvPotJvPXfv-xhBJOCMs7ijA2bHcZRyE8CpGmemgb9D-5URmbxCljopsQ-4uOJqn6KueRKYdscZOCcYX6Bb9Tag)

  
We review the documentation in the page "_salesorders.html_", we see that it leaves us a software usage guide where it connects to _port 4411_.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEi_lU5oZWHbP3Cv3XzERovWcLUcoFMrGHuzbJJ2eGXEPvxB5nmS_JgQPGMYE3KT7inbmLhOfvcRSs2q8YlXbeWz6Tjqnso__1LgmXWCLboHjFmtgcCZNYnM_esDS2JzYefyot_WywWOMfdNyZn7yv7rAux9dxJcjjv28QKY4svvtXkTlRd_Yby59ppeQA=w493-h640)](https://blogger.googleusercontent.com/img/a/AVvXsEi_lU5oZWHbP3Cv3XzERovWcLUcoFMrGHuzbJJ2eGXEPvxB5nmS_JgQPGMYE3KT7inbmLhOfvcRSs2q8YlXbeWz6Tjqnso__1LgmXWCLboHjFmtgcCZNYnM_esDS2JzYefyot_WywWOMfdNyZn7yv7rAux9dxJcjjv28QKY4svvtXkTlRd_Yby59ppeQA)

  

Exploitation
============

We see that it is indeed operational, but checking the **nmap** we see that the port was not open.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhTYYK-Q5Yyp0GalJIC--8P6hBTm1FPtWmfJMJnaGHzaaeviR4CV4kDUmRlIoldkMuYqpTrKpKzKU68cRnUNAtDoYYI702c6ysfU16j63uLtvs2c7teshhwIAE77cIMAHNzS3b5Epkl5ESyOH-HW25eFH4yZJsTHkYvbR21CB2c6AN5g6YjmvPe-6RHtA=w400-h198)](https://blogger.googleusercontent.com/img/a/AVvXsEhTYYK-Q5Yyp0GalJIC--8P6hBTm1FPtWmfJMJnaGHzaaeviR4CV4kDUmRlIoldkMuYqpTrKpKzKU68cRnUNAtDoYYI702c6ysfU16j63uLtvs2c7teshhwIAE77cIMAHNzS3b5Epkl5ESyOH-HW25eFH4yZJsTHkYvbR21CB2c6AN5g6YjmvPe-6RHtA)

  

We try to use classic commands like "_help_", "_info_", but we get the same error, so we try to try a command injection and we see that we get code execution.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEj53-8OBWpxFlBZrigISwM8uO0TktAc-3ur0INFyZOWpW4Nvx-ncERhX3Y1NRk2SCHCPKHLdRRAAv5zzHntefxripe_vhIYBeaDaPgaBQibjon7u1JldoV9rveFekbb_UXksjUdfI64zcsV1e7DteEHmRf0UtQvqtbh0QsAl2Oyr9TFZlwzALhWFvlIVQ=w640-h248)](https://blogger.googleusercontent.com/img/a/AVvXsEj53-8OBWpxFlBZrigISwM8uO0TktAc-3ur0INFyZOWpW4Nvx-ncERhX3Y1NRk2SCHCPKHLdRRAAv5zzHntefxripe_vhIYBeaDaPgaBQibjon7u1JldoV9rveFekbb_UXksjUdfI64zcsV1e7DteEHmRf0UtQvqtbh0QsAl2Oyr9TFZlwzALhWFvlIVQ)

  

We tried to download and run a reverse shell, but it doesn't seem to work. 

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEga_TRsBFVd8OBSWo33vmBFzbSw7HQS40M4HxBwP-xqqceXfrhBN0nUfbS4jcAj36dF4NKy_Pg4G7tsSgTDxBftd7Rc2KtFJd-tDdFFZH8rigY2MmFOfI1FXU4glERtARE2Tw5RdXUx6vV4zC4Vg2eDgkPSMZqH-eI7AWvvmZb1qKrcTX6pu4Qa7ouvqw=w608-h640)](https://blogger.googleusercontent.com/img/a/AVvXsEga_TRsBFVd8OBSWo33vmBFzbSw7HQS40M4HxBwP-xqqceXfrhBN0nUfbS4jcAj36dF4NKy_Pg4G7tsSgTDxBftd7Rc2KtFJd-tDdFFZH8rigY2MmFOfI1FXU4glERtARE2Tw5RdXUx6vV4zC4Vg2eDgkPSMZqH-eI7AWvvmZb1qKrcTX6pu4Qa7ouvqw)

  

We go back to the previous steps and try to check the user "_ksimpson_", in case he has not changed the password and it is the same as his name. And we see that they work:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjtHQBYn4Fwe8aDKiIv5ASXuN7ZvpEeyQ5mbH8DMdf-qVEXj1gwlYUZX7bGx5r9gyWsH-APLMCOHCH-s9B1HhOqJqmNybMctZzl_0F7NxKclzj_pnTqb8x2Gjl3W1YbtHBYilGt8Fo0WyIQhdga-SuVKIlG5IsKB80Teuwpk1YaT0NNdGy34eviYF9erw=w640-h250)](https://blogger.googleusercontent.com/img/a/AVvXsEjtHQBYn4Fwe8aDKiIv5ASXuN7ZvpEeyQ5mbH8DMdf-qVEXj1gwlYUZX7bGx5r9gyWsH-APLMCOHCH-s9B1HhOqJqmNybMctZzl_0F7NxKclzj_pnTqb8x2Gjl3W1YbtHBYilGt8Fo0WyIQhdga-SuVKIlG5IsKB80Teuwpk1YaT0NNdGy34eviYF9erw)

  
We use the **smbclient.py** tool, but we see that we cannot connect through smb.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhbTTY_G-F5Pq3uIBbu9wbUm8yQHA1BVJ0cIpyXHs8e2I1OdUf9JPLaZ-z73QF76F1WGCcWmA3bDYYipTZTyWpeG5aAmsVWa7TkYcJQpgpnMnVUEAE3xp5B-bqDV6kqQeXi7sQA0Fe-IMKF9TCknuxHlWFEx69N2fvWgJbLE_VfLB1olmItruHv5-gj3Q=w640-h108)](https://blogger.googleusercontent.com/img/a/AVvXsEhbTTY_G-F5Pq3uIBbu9wbUm8yQHA1BVJ0cIpyXHs8e2I1OdUf9JPLaZ-z73QF76F1WGCcWmA3bDYYipTZTyWpeG5aAmsVWa7TkYcJQpgpnMnVUEAE3xp5B-bqDV6kqQeXi7sQA0Fe-IMKF9TCknuxHlWFEx69N2fvWgJbLE_VfLB1olmItruHv5-gj3Q)

  
So I tried to request a TGT for the user, so I could try to connect via Kerberos ticket.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEh2ToTnyi98Napnmo26whgyOPhQc3Q6SWNCQ1nYhbcIOGRgQzJdJ_eCwIhXHH2T6imYbmWlvObJD3Ve_aAikPMwU8UwcQ0kzXXh0oLx0h6CKB5_opJiYj6A4nOhSrsNI79vdwK9ttI2X4Sn7TG-ErQjybcaVARRW0iNLF-XD9aFe6Tcy5iCSdxOYF_uZg=w640-h138)](https://blogger.googleusercontent.com/img/a/AVvXsEh2ToTnyi98Napnmo26whgyOPhQc3Q6SWNCQ1nYhbcIOGRgQzJdJ_eCwIhXHH2T6imYbmWlvObJD3Ve_aAikPMwU8UwcQ0kzXXh0oLx0h6CKB5_opJiYj6A4nOhSrsNI79vdwK9ttI2X4Sn7TG-ErQjybcaVARRW0iNLF-XD9aFe6Tcy5iCSdxOYF_uZg)

  
We tried to connect to the machine with the ticket, but it seems that we cannot write to any resource and we cannot connect to the **psexec.py** tool.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEix_-tj93LSjI1iyzDL7LNW_dRIhOVZ_KE5ZU4PrqHAqiHAqrC_KeRkv_oBh3x_HGiVwWvydPXRkRus0pKAd-qDpGXAHd3QKg3xCc7jbWoZhLc3uTtKD-ZBhkOqwycy2xDbQZiRYej3ljHZjYpOccOUqdn7rO1WIYuKo44YEIgqV7lqed3SLkQM9bmeUA=w640-h172)](https://blogger.googleusercontent.com/img/a/AVvXsEix_-tj93LSjI1iyzDL7LNW_dRIhOVZ_KE5ZU4PrqHAqiHAqrC_KeRkv_oBh3x_HGiVwWvydPXRkRus0pKAd-qDpGXAHd3QKg3xCc7jbWoZhLc3uTtKD-ZBhkOqwycy2xDbQZiRYej3ljHZjYpOccOUqdn7rO1WIYuKo44YEIgqV7lqed3SLkQM9bmeUA)

We try to get the _TGS_ (Ticket Granting Services) tickets and list the user "_sqlsvc_":

[![](https://blogger.googleusercontent.com/img/a/AVvXsEg3Yuxvftkh6Epznvota8ymQ7vDNuhc_bFzJ1IidF40kAAjbmx-l0kVQndIMIbKZMET2P2Ar0BvsSvG3Ux4LohY598M11Rcr5Rz-T91JYaPBhELsn3AlTqcgMkcI-mOT0K-BR50YTGvmT2TNny9ltFBKTl05llk30IecusWjFJvVvYMuBYtcIi57MSaGw=w640-h324)](https://blogger.googleusercontent.com/img/a/AVvXsEg3Yuxvftkh6Epznvota8ymQ7vDNuhc_bFzJ1IidF40kAAjbmx-l0kVQndIMIbKZMET2P2Ar0BvsSvG3Ux4LohY598M11Rcr5Rz-T91JYaPBhELsn3AlTqcgMkcI-mOT0K-BR50YTGvmT2TNny9ltFBKTl05llk30IecusWjFJvVvYMuBYtcIi57MSaGw)

  

We try to crack the hash with the **hashcat** tool and get the plain password::

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhnpepl7pSEaM-O5SoRrM8Vj9iMylJX7noviWYH5Zfo_EydU8ER8W9bJ3z2-5LEwOEUJThNKqbfp3fILMJVsLNsovzhkv2lF9yS2eAKE0MYauACyU10jy7iwLpxjqp-RT-sDgKZQjWDaYkvusDQX-41IuYogpOclqmAw8e1AAAsGgtdnfs-3h8ZEbTfwA=w640-h324)](https://blogger.googleusercontent.com/img/a/AVvXsEhnpepl7pSEaM-O5SoRrM8Vj9iMylJX7noviWYH5Zfo_EydU8ER8W9bJ3z2-5LEwOEUJThNKqbfp3fILMJVsLNsovzhkv2lF9yS2eAKE0MYauACyU10jy7iwLpxjqp-RT-sDgKZQjWDaYkvusDQX-41IuYogpOclqmAw8e1AAAsGgtdnfs-3h8ZEbTfwA)

  

We obtain the ticket of the user "_sqlsvc_", export it to an environment variable and try to connect via Kerberos with the **mssqlclient.py** tool, but we see that it does not work.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjOeqAAzVgivb9eoGjZaALMvI_CI0FsjNYDhL-D384gT-V-pCyn1yeABDJ0IQj2l5F-CUy2gTlsaai02WjHPF38Ol_zzpVS3bQuUl9zgwoo9_nQ_o2-TcWzSDsf0QxsFb1Eyb4TKokH2nJBP_DYerTRtNQec1Zuu9TW_cqwbtRvfqqWPcvD1ewjimz8nw=w640-h164)](https://blogger.googleusercontent.com/img/a/AVvXsEjOeqAAzVgivb9eoGjZaALMvI_CI0FsjNYDhL-D384gT-V-pCyn1yeABDJ0IQj2l5F-CUy2gTlsaai02WjHPF38Ol_zzpVS3bQuUl9zgwoo9_nQ_o2-TcWzSDsf0QxsFb1Eyb4TKokH2nJBP_DYerTRtNQec1Zuu9TW_cqwbtRvfqqWPcvD1ewjimz8nw)

  

We try to generate a _silver ticket_, but for this we will need to convert the password to "_nthash_", get the "_domain sid_", the "_domain_", a _valid SPN_ and set the "_user id_" to _500_. Some of this information we already have, so let's go for what we don't have.

  

Converting the password to _NTLM_ format::

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEikfmGBCu74TP31vZaoNx1TI8sxBH3cEWyyZlSGIz4sOV-p9dVGb6p_vAiREtXR4Hx0EchJbyDU55E-mA3cOMZPclW_SbgF4lvlmz0H9E9m_557k2PlDPW47R2a14nI-OszBUeBGXG9LsBIiEr8jRX-vGA0OaVEQhH5DNV1Fek-9fyBZXBx8JrD3hs-QQ=w640-h280)](https://blogger.googleusercontent.com/img/a/AVvXsEikfmGBCu74TP31vZaoNx1TI8sxBH3cEWyyZlSGIz4sOV-p9dVGb6p_vAiREtXR4Hx0EchJbyDU55E-mA3cOMZPclW_SbgF4lvlmz0H9E9m_557k2PlDPW47R2a14nI-OszBUeBGXG9LsBIiEr8jRX-vGA0OaVEQhH5DNV1Fek-9fyBZXBx8JrD3hs-QQ)

  

Obtaining the "_Domain SID_":

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiMWokyhuQ-NOh1Oe8tHS0YS3AIMteAh4h21QgQGxOPqHAdBP1FP8onDLW9Dc-vHxA9I0xMaxAB9hAXHLUfZuLSC_6kg1DrkTyt4cTE71QNqHiTQtktaVAFE9TvY7ldQGKJXMRHr3jWyX2QnuJ1N2xEv592eBSbi9hmbeuAeoK1bq3CkwODB8c9LlgyyA=w640-h70)](https://blogger.googleusercontent.com/img/a/AVvXsEiMWokyhuQ-NOh1Oe8tHS0YS3AIMteAh4h21QgQGxOPqHAdBP1FP8onDLW9Dc-vHxA9I0xMaxAB9hAXHLUfZuLSC_6kg1DrkTyt4cTE71QNqHiTQtktaVAFE9TvY7ldQGKJXMRHr3jWyX2QnuJ1N2xEv592eBSbi9hmbeuAeoK1bq3CkwODB8c9LlgyyA)

  
With all the data already in hand, we try to create the _Silver Ticket_ and see that it works!

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhDmIX11wfHSr5VLq22TXsdXqXlgsQkyuU-lkPMNEa7iBJgowBl_MH-2otZGqcKnHeJl1fn0kS7Q9grlp5tkwAKqLYYTuKfTdCWBHx4m1-z2pW85russAXnqvBjijQLzMNazpbJQNUBQ1yyCcL6DmH5JAfu4wgXJGI3Ncc7hXmQW-V05FyLntT4kO1yCA=w640-h204)](https://blogger.googleusercontent.com/img/a/AVvXsEhDmIX11wfHSr5VLq22TXsdXqXlgsQkyuU-lkPMNEa7iBJgowBl_MH-2otZGqcKnHeJl1fn0kS7Q9grlp5tkwAKqLYYTuKfTdCWBHx4m1-z2pW85russAXnqvBjijQLzMNazpbJQNUBQ1yyCcL6DmH5JAfu4wgXJGI3Ncc7hXmQW-V05FyLntT4kO1yCA)

  
We now try to connect through the **mssql** service and we see that we are inside. We reconfigure some options to be able to execute "_xp\_cmdshell_" and we are able to execute commands in the machine.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEi125FXRHw76Z_4sCC6BQ5S8e8k96AhzaB_p0PJpe4l0RYCP6K55TpRAWVrvv1qb1QFlCkU99xfWFnMI0dIuoXK9s7eYcAB-kVC9FeYKOrwKVgopk-fSiRU-pymk3-mJvQrNWOBlBSLibgrz4C6uUNwCX3JDy6dsuNudG5VD6N-h0kq8ooWXVU454cL9g=w640-h444)](https://blogger.googleusercontent.com/img/a/AVvXsEi125FXRHw76Z_4sCC6BQ5S8e8k96AhzaB_p0PJpe4l0RYCP6K55TpRAWVrvv1qb1QFlCkU99xfWFnMI0dIuoXK9s7eYcAB-kVC9FeYKOrwKVgopk-fSiRU-pymk3-mJvQrNWOBlBSLibgrz4C6uUNwCX3JDy6dsuNudG5VD6N-h0kq8ooWXVU454cL9g)

  
We try to read the user flag, but we see that we do not have permissions on the files of the user "_miscsvc_".

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiWuU-wQMXWrgACyRwT60rzz0SxHS4nLVS5f35wq2gzNrQJ3A-9Z04qLpSbzyT-mGyH1dGmFq0NgzAo9uvYXRjPjfqRyc1azpJohS93wb-udKXfySQRHZRM5QCjs4sHRDeekETKFsnNJIOb19n0l3TlMiC_J3LqRcysactwOrb4QzRYpfHLYBPDKEVY5g=w400-h337)](https://blogger.googleusercontent.com/img/a/AVvXsEiWuU-wQMXWrgACyRwT60rzz0SxHS4nLVS5f35wq2gzNrQJ3A-9Z04qLpSbzyT-mGyH1dGmFq0NgzAo9uvYXRjPjfqRyc1azpJohS93wb-udKXfySQRHZRM5QCjs4sHRDeekETKFsnNJIOb19n0l3TlMiC_J3LqRcysactwOrb4QzRYpfHLYBPDKEVY5g)

  
We list the different databases, quickly identify the "_ScrambleHR_" database:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgPclq-cYa0cWJTun2bxL7NCCR6J22-di7ROq0xGfZLpUN7aH9JM-PNCozgX5JujHozSAwQ9_r2DFxBx16etAa5PVuI7XN4DnJBNPJlPFRueE74MSvpWJ4hTzBB3jSny1vYkVJoSOTy8QcexenFbhRzmtCWM6-XlsCfB-evD_g8s5UWSRu9x11v9GGwrA=w358-h400)](https://blogger.googleusercontent.com/img/a/AVvXsEgPclq-cYa0cWJTun2bxL7NCCR6J22-di7ROq0xGfZLpUN7aH9JM-PNCozgX5JujHozSAwQ9_r2DFxBx16etAa5PVuI7XN4DnJBNPJlPFRueE74MSvpWJ4hTzBB3jSny1vYkVJoSOTy8QcexenFbhRzmtCWM6-XlsCfB-evD_g8s5UWSRu9x11v9GGwrA)

  
  

We list the tables belonging to the database:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEisTGxHasyoWGRCsivanMZtcYkjgw6DP-udcca6O-hGeT8DjPeOKA22PeE8UnMiFbGaxZKeyEwXXvRCLuPbCGWEj2-0wJ3OsTb1wI-CwesOwFpPHZ2bMHYEj4_IUugrjRrwiKd509_GlWosTaJ0jcJFV7sy0iC2bpIIteV5Oh7Z0wdKYwDfe9eFI6vfDQ=w400-h243)](https://blogger.googleusercontent.com/img/a/AVvXsEisTGxHasyoWGRCsivanMZtcYkjgw6DP-udcca6O-hGeT8DjPeOKA22PeE8UnMiFbGaxZKeyEwXXvRCLuPbCGWEj2-0wJ3OsTb1wI-CwesOwFpPHZ2bMHYEj4_IUugrjRrwiKd509_GlWosTaJ0jcJFV7sy0iC2bpIIteV5Oh7Z0wdKYwDfe9eFI6vfDQ)

  

We list some credentials in the "_UserImport_" table:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEisi6JK-MNgAWLkNqly5p-m0ZwUrBpSUqbok8dJMNXpp8_CazE_qGQoQuGA-Sm0NGsIWi_dSv0IIBtLl6-mbT4h1xH5w0qjvMyi9Cr24jUEmQmHYdtW9OL_1uzcwytkVcvT7OmlJ_GbMZP4hmVMqBzmP7SYE76cVkPGu_2Qro3OOc6T-eU9fJuS3FRT8A=w640-h98)](https://blogger.googleusercontent.com/img/a/AVvXsEisi6JK-MNgAWLkNqly5p-m0ZwUrBpSUqbok8dJMNXpp8_CazE_qGQoQuGA-Sm0NGsIWi_dSv0IIBtLl6-mbT4h1xH5w0qjvMyi9Cr24jUEmQmHYdtW9OL_1uzcwytkVcvT7OmlJ_GbMZP4hmVMqBzmP7SYE76cVkPGu_2Qro3OOc6T-eU9fJuS3FRT8A)

  
We set up a reverse shell (later, I transferred a **netcat** to improve stability):

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhnzzpMuXvkhYoxsCoRLgHh0-H4eUjXTGBB6WEV9ST1lH25hFGj9ID4WXesuDgHfmIhZQ52TLBnEFes1VuLYNJmDobHT3Jd9jxUmvrS6WN-gGNZlYvQNQeo6z9UJjS6cTAYC4TRTTlnwyt4qpaupiYEk0BGTFbHb_hq0JyuiI-8i4lq7XNBHkT3XkXF9g=w640-h112)](https://blogger.googleusercontent.com/img/a/AVvXsEhnzzpMuXvkhYoxsCoRLgHh0-H4eUjXTGBB6WEV9ST1lH25hFGj9ID4WXesuDgHfmIhZQ52TLBnEFes1VuLYNJmDobHT3Jd9jxUmvrS6WN-gGNZlYvQNQeo6z9UJjS6cTAYC4TRTTlnwyt4qpaupiYEk0BGTFbHb_hq0JyuiI-8i4lq7XNBHkT3XkXF9g)

  

So we created credentials in _SecureStrings_ format, executed commands impersonating the identity of the user "_miscsvc_" and managed to read the user flag:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgp2QDauMIeYLNUpVjll4nASRxrfPjWkofR7U0Fp04wa8Ut6b3Tx8IdMUt2WK4EFCrsILeVyJVtqslnnr2jMrFgRMVVsccrcg9IS1UGcOozZF8r-EXdJICaBrZnez0XUwhpM6UVpFXC7kWK71eMFrVc4hTL_jimqtZBV--uIFQDIKA4aWxX0inQbII-zw=w640-h128)](https://blogger.googleusercontent.com/img/a/AVvXsEgp2QDauMIeYLNUpVjll4nASRxrfPjWkofR7U0Fp04wa8Ut6b3Tx8IdMUt2WK4EFCrsILeVyJVtqslnnr2jMrFgRMVVsccrcg9IS1UGcOozZF8r-EXdJICaBrZnez0XUwhpM6UVpFXC7kWK71eMFrVc4hTL_jimqtZBV--uIFQDIKA4aWxX0inQbII-zw)

  

Privilege Escalation
====================

We run a "_whoami /all_" on the user and see that we belong to interesting groups such as "_ITShare_" and "_ITUsers_":

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhJjaeAwI1rC1go5JsE98z_zkqw21FbgJh-Fs8bHidvCFPEBEdbIhoZ7fXlSYtSJBpDnxWqYSDw5SwoOH6ldxbecKUDxhXMkK3c9MQ0vYVveCecOvlruWSWL6258J-S0O4wgH7Rj20wGt67lt-qFq_f_Xmcv45WW-ixBSjRQU5B6a4Q0RJOyDOW19h-rw=w637-h640)](https://blogger.googleusercontent.com/img/a/AVvXsEhJjaeAwI1rC1go5JsE98z_zkqw21FbgJh-Fs8bHidvCFPEBEdbIhoZ7fXlSYtSJBpDnxWqYSDw5SwoOH6ldxbecKUDxhXMkK3c9MQ0vYVveCecOvlruWSWL6258J-S0O4wgH7Rj20wGt67lt-qFq_f_Xmcv45WW-ixBSjRQU5B6a4Q0RJOyDOW19h-rw)

  

We reviewed the shares, found several, but the one from the _IT department_ caught our attention:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjs4vKvhxXTxFFJNv8iJgVppOPX5VTlHbPN8K4X4XD3pvcBww82JPEK8dgyT04257GJ3iUG2Ey1WLEvZFSqArHu47j7j2OAus0BBJMgVgmPfDDZuL15xvKGoBt5952d8A9OrHo7ex53t43_C4NSn5S9MyhzQG5qy0RIBGqjHxDvGc74h3r4EA3sGiEGGg=w400-h216)](https://blogger.googleusercontent.com/img/a/AVvXsEjs4vKvhxXTxFFJNv8iJgVppOPX5VTlHbPN8K4X4XD3pvcBww82JPEK8dgyT04257GJ3iUG2Ey1WLEvZFSqArHu47j7j2OAus0BBJMgVgmPfDDZuL15xvKGoBt5952d8A9OrHo7ex53t43_C4NSn5S9MyhzQG5qy0RIBGqjHxDvGc74h3r4EA3sGiEGGg)

  
Our user does not have privileges, but let's remember that the user "_miscsvc_" does, since he belongs to the _IT group_:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhtpqjdLaFzHfdfW5OEpowWVDPs8IfV7b2CQb3O5SGzs1HV6E2GAnqg8-DP05fiA3fbyhbZ-Rq90KiPGSAsZ7VWGukwyAIHr8ahYxrBPY4g4jJXab1iymjlf-I-Ap64y8MsVSTbgIriHnvtY_zz6JrmS21ko4SSMwvzcLjebI-yUzkX-s6KKrosmt_dLQ=w640-h213)](https://blogger.googleusercontent.com/img/a/AVvXsEhtpqjdLaFzHfdfW5OEpowWVDPs8IfV7b2CQb3O5SGzs1HV6E2GAnqg8-DP05fiA3fbyhbZ-Rq90KiPGSAsZ7VWGukwyAIHr8ahYxrBPY4g4jJXab1iymjlf-I-Ap64y8MsVSTbgIriHnvtY_zz6JrmS21ko4SSMwvzcLjebI-yUzkX-s6KKrosmt_dLQ)

  

Access the "_Apps_" directory and find the software with the same name as the machine (causality? I doubt it very much).

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgCaAjrHBa9Y6-eaUCloRs0tZYG08G9OWgsibsuJoBwVTRnsdvatgvKkbF8iw_wUTi8UqyQmx3Aks0KW0zt6hKuNpLuPi9xGDDyeu48fKkCfl5TuShMdhynXjwQ2vb0BuPCLMpvEjjHdJkvRzDPqfOaz9XgQDPMCKOqUx2I2hMeIgMeSL5hIwA3LTzHfQ=w640-h184)](https://blogger.googleusercontent.com/img/a/AVvXsEgCaAjrHBa9Y6-eaUCloRs0tZYG08G9OWgsibsuJoBwVTRnsdvatgvKkbF8iw_wUTi8UqyQmx3Aks0KW0zt6hKuNpLuPi9xGDDyeu48fKkCfl5TuShMdhynXjwQ2vb0BuPCLMpvEjjHdJkvRzDPqfOaz9XgQDPMCKOqUx2I2hMeIgMeSL5hIwA3LTzHfQ)

  
Reviewing functionalities of the application, it seems that there is a function called "_UploadOrder_", which allows to upload commands and since we saw at the beginning that command injection was possible, we could execute commands remotely in a combined way and with a payload compatible with ._NET_ technology. 

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgIDMqn1fRFxDNxhGilz9nd74jCdoQQkV-NLKQQuYnhFLFOIL5AkF5KcgL8UzUVdZNx6j5xonF6WfpgefgbYYkBg838J-nY41Zzh-Zr3sW2YtO0KLyDzcuZYLOY-qr7TVF6fFLL9FZmCNRlGY2JGRr6wW4Js5tsbBssiHJRnBrPSOnNzJA2pr5rMRmAug=w640-h272)](https://blogger.googleusercontent.com/img/a/AVvXsEgIDMqn1fRFxDNxhGilz9nd74jCdoQQkV-NLKQQuYnhFLFOIL5AkF5KcgL8UzUVdZNx6j5xonF6WfpgefgbYYkBg838J-nY41Zzh-Zr3sW2YtO0KLyDzcuZYLOY-qr7TVF6fFLL9FZmCNRlGY2JGRr6wW4Js5tsbBssiHJRnBrPSOnNzJA2pr5rMRmAug)

  

So I searched among my notes how to generate specific payloads for this technology, I found the [ysoserial](https://github.com/pwntester/ysoserial.net) tool. We use this tool to serialize in base64 the execution of a netcat to our attacker machine (remember, I previously uploaded a netcat to have a more stable session ;)):

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhnaowQZ5y2uvVGjCYiG3bvuxIf8M_-61Ygl7TJkehfqWiRhhtN3pTxbZRoXKWquDQLCZ27jmr3VoVD-XOD-mUCKGl0cOGG48x7PRrs96p53xLhYJqtqcTJpt4ieSBInuHhqx3lNVIBgi-Qd8SUg80TIld7dHLcDJyIxGHZscGR5w96wUmpTvZ0aV9gcQ=w640-h142)](https://blogger.googleusercontent.com/img/a/AVvXsEhnaowQZ5y2uvVGjCYiG3bvuxIf8M_-61Ygl7TJkehfqWiRhhtN3pTxbZRoXKWquDQLCZ27jmr3VoVD-XOD-mUCKGl0cOGG48x7PRrs96p53xLhYJqtqcTJpt4ieSBInuHhqx3lNVIBgi-Qd8SUg80TIld7dHLcDJyIxGHZscGR5w96wUmpTvZ0aV9gcQ)

  

We listen in, try to inject it with **netcat** and get a reverse shell with the user "_nt authority\\system_" and read the root flag.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjYIz-Exr6r6BpvEJxGn4-jk7gnOfqRma3A2Wv7zgKO7bHOrqqiGpuq4qp0yNNW6aKVvklf2VaOlQe8avSHtEPkijtjhn57A6JL05FKBjnhyYQ-FHqf1KzssPfzbp6qh3Kc215EpbWeVx7Z6KlxCJyKxYWIaO3ApdnTxCvZiivIruMwRenjTnwC_sEEnA=w640-h432)](https://blogger.googleusercontent.com/img/a/AVvXsEjYIz-Exr6r6BpvEJxGn4-jk7gnOfqRma3A2Wv7zgKO7bHOrqqiGpuq4qp0yNNW6aKVvklf2VaOlQe8avSHtEPkijtjhn57A6JL05FKBjnhyYQ-FHqf1KzssPfzbp6qh3Kc215EpbWeVx7Z6KlxCJyKxYWIaO3ApdnTxCvZiivIruMwRenjTnwC_sEEnA)

