---
title: OpenSource HackTheBox Writeup
tags: [writeup,fileupload,python,gitea,code,git,hackthebox,path-traversal,linux,hooks]
style: border
color: success
description: ""
---

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhdqCAvZrY6xmHBketz1mvHahtIPPQLyrDUBwdHDsr2qkEmQvvsq56eOdXMXbb_oq7KRNvYdT85tZgJRGmHbTWivpF6lxMMygw8oa9UlzuNue7N1O56xW4D0_AaF76dntCLYSsxJG8rpvRfzpryzsaj5JwS8x_QBHqOO8GybsBrm9WtVR68rZxYjuMuIw=w640-h485)](https://blogger.googleusercontent.com/img/a/AVvXsEhdqCAvZrY6xmHBketz1mvHahtIPPQLyrDUBwdHDsr2qkEmQvvsq56eOdXMXbb_oq7KRNvYdT85tZgJRGmHbTWivpF6lxMMygw8oa9UlzuNue7N1O56xW4D0_AaF76dntCLYSsxJG8rpvRfzpryzsaj5JwS8x_QBHqOO8GybsBrm9WtVR68rZxYjuMuIw)

   

Scanning
========

We launch **nmap** tool with scripts and versions on all ports.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgPl6Py4fKTkoF6iCDZYHRmmXU9oysv1288deWa4lKxWA6T9w0OMntC7U0_MErU8prTIkQLCb4pEyQ13XlkqvAlaIpdLFmZRDuv1AeALt6fhFqCt8jPrRMLRuRL-6nw4ZHZ4ipSp4KMBXz-PTuTFp3rPgoFop7fsVXXf8x5AFGNKCvUHyLvlrYVjizRrw=w640-h418)](https://blogger.googleusercontent.com/img/a/AVvXsEgPl6Py4fKTkoF6iCDZYHRmmXU9oysv1288deWa4lKxWA6T9w0OMntC7U0_MErU8prTIkQLCb4pEyQ13XlkqvAlaIpdLFmZRDuv1AeALt6fhFqCt8jPrRMLRuRL-6nw4ZHZ4ipSp4KMBXz-PTuTFp3rPgoFop7fsVXXf8x5AFGNKCvUHyLvlrYVjizRrw)

  

Enumeration
===========

We access the corporate website:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhpsATpBSiKH5XC_z0SZfUu-V9aFLQUR_0fDZNIVo_LJri9l-8i9ATsnueZ2QEdfNNqgAgfSq8x4ZSVqlueprj_-H5xTy0oXVBcgjaV-7l-n9e-0mTbk8FMeNfuMJ6A02efffw95qYyMezObOXiGqjEbsMzZyIvWWy8XEUs81n9rnbtIKlhcvaI8BiGAQ=w385-h400)](https://blogger.googleusercontent.com/img/a/AVvXsEhpsATpBSiKH5XC_z0SZfUu-V9aFLQUR_0fDZNIVo_LJri9l-8i9ATsnueZ2QEdfNNqgAgfSq8x4ZSVqlueprj_-H5xTy0oXVBcgjaV-7l-n9e-0mTbk8FMeNfuMJ6A02efffw95qYyMezObOXiGqjEbsMzZyIvWWy8XEUs81n9rnbtIKlhcvaI8BiGAQ)

  
Below, we find a button where we can download the source code of an application.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEg288lmN6Q0T2yN8-EqSjdSvVk-5cj_4ec-brvGYYd-9eTmEL_9_cqq97c_k4T6IpwCevqAdcDN1PwLvhiFwWN4IG8TXlVTmKOix5Bq5uti9twTg5dTHXtlapLO2sUs-duXDfEOfNZ4kO0kVq7jGh3Cgi9ZPQpCvG8J0FOLotC66yrYVdvmD91kx25R4g=w640-h571)](https://blogger.googleusercontent.com/img/a/AVvXsEg288lmN6Q0T2yN8-EqSjdSvVk-5cj_4ec-brvGYYd-9eTmEL_9_cqq97c_k4T6IpwCevqAdcDN1PwLvhiFwWN4IG8TXlVTmKOix5Bq5uti9twTg5dTHXtlapLO2sUs-duXDfEOfNZ4kO0kVq7jGh3Cgi9ZPQpCvG8J0FOLotC66yrYVdvmD91kx25R4g)

  
We unzipped the file and reviewed several of the files, in principle we found no hardcoded credentials or relevant information.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiAudDBmdLtTWQNOLogFL-40OMAqeZjCa3zJ4YGKOGy1-Zfe7SSvGhasFaHPMoZXccaQqV_xHgONC3W-vXRBr87O7JJzJ72tT70CWxhqfAnb_3D7fvqXkPfLafm52qYixkflryH023VUZzMOsqbz6W7AgZYoeMW_IKjlPXb8znoQ19p7siLtZV_VF4DBg=w485-h640)](https://blogger.googleusercontent.com/img/a/AVvXsEiAudDBmdLtTWQNOLogFL-40OMAqeZjCa3zJ4YGKOGy1-Zfe7SSvGhasFaHPMoZXccaQqV_xHgONC3W-vXRBr87O7JJzJ72tT70CWxhqfAnb_3D7fvqXkPfLafm52qYixkflryH023VUZzMOsqbz6W7AgZYoeMW_IKjlPXb8znoQ19p7siLtZV_VF4DBg)

  

Exploiting
==========

We continued to review the website, found the application and the file upload form:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgTp69a12p8FR-svstrbzzLoiXVWiDI7ao7IRUCz0AgaYPE1y9yBzfLDAcpkK_-Bwb9FD_XJsxfOOaxiIXmQ0ol6CFLQfBBe18rFAeNAYyuKELrIGaxvnWUCDLhv2-Hqvrp2l9iqubJQNtsOk6cn2a8GLbS5MDXmnZt_ZUS9h6DQfZB_xrpnr66H2_Mog=w397-h400)](https://blogger.googleusercontent.com/img/a/AVvXsEgTp69a12p8FR-svstrbzzLoiXVWiDI7ao7IRUCz0AgaYPE1y9yBzfLDAcpkK_-Bwb9FD_XJsxfOOaxiIXmQ0ol6CFLQfBBe18rFAeNAYyuKELrIGaxvnWUCDLhv2-Hqvrp2l9iqubJQNtsOk6cn2a8GLbS5MDXmnZt_ZUS9h6DQfZB_xrpnr66H2_Mog)

  
We see that it allow us to upload at least files with ._txt extension_:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgxT_a65jK2OfP6wD208O9p31bZlM1OZYv1rDSVJpgnJUDshnr4gq-gSvGuXprpBcyx7UDYjaWVUITJ_r5tWBUcGPWRxDuO0BgJnJDVSDZgrKvTJkMQYJy-jwvxM8sL2_uUGzkJZix6Fm1t0OyZ8euHAc8uCpzsIY_jxtYQl8phg5pGeUX5rbHoLn9QYg=w393-h400)](https://blogger.googleusercontent.com/img/a/AVvXsEgxT_a65jK2OfP6wD208O9p31bZlM1OZYv1rDSVJpgnJUDshnr4gq-gSvGuXprpBcyx7UDYjaWVUITJ_r5tWBUcGPWRxDuO0BgJnJDVSDZgrKvTJkMQYJy-jwvxM8sL2_uUGzkJZix6Fm1t0OyZ8euHAc8uCpzsIY_jxtYQl8phg5pGeUX5rbHoLn9QYg)

  

### Result:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiK3SfJpVKDNXegSfYi0R4FT0GIEgLvxoD-7sIt6p1QKhhVjigXQeQlR7YK4H22LZE18-BQqD8Jzh6IfvXAvbFw2EMTRgciW9hM000BP8K6K1pCB2IVtYpgCAxFUC1gCUZ57VPbT4ca9plMSP2qXHPnR6gadTN6lqAb07HqwvipQTEa8n_3ZC0zk3NuyQ=w400-h78)](https://blogger.googleusercontent.com/img/a/AVvXsEiK3SfJpVKDNXegSfYi0R4FT0GIEgLvxoD-7sIt6p1QKhhVjigXQeQlR7YK4H22LZE18-BQqD8Jzh6IfvXAvbFw2EMTRgciW9hM000BP8K6K1pCB2IVtYpgCAxFUC1gCUZ57VPbT4ca9plMSP2qXHPnR6gadTN6lqAb07HqwvipQTEa8n_3ZC0zk3NuyQ)

  

We see that if we try to check _SSTI_ it returns an error where it shows trace information of the files used and the current working directory where the files will be hosted.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjFnTkH-6JhFyFp-T_ZpexCDap83TU2GTB5OxfVBy4qgFTFQcuyvwygoA_6996Ax2Lb3tVR-pAXH9Jz-vLkDMe1aN9yWfw3VJTCy052Y-m_PNC-qjwtWK0TqrxQgtMRDIxY2poTdcbUWfzuPs55Nx__ZQjSec4CIupryJtt4VuGIz4zQwm-Zs78TrcFnA=w549-h640)](https://blogger.googleusercontent.com/img/a/AVvXsEjFnTkH-6JhFyFp-T_ZpexCDap83TU2GTB5OxfVBy4qgFTFQcuyvwygoA_6996Ax2Lb3tVR-pAXH9Jz-vLkDMe1aN9yWfw3VJTCy052Y-m_PNC-qjwtWK0TqrxQgtMRDIxY2poTdcbUWfzuPs55Nx__ZQjSec4CIupryJtt4VuGIz4zQwm-Zs78TrcFnA)

  
I tried to upload some webshell, but it was not possible. So I went back to check the code, because if they are providing you with the code it is because there will be some function that we can take advantage of... So I found the same error trace "_os.getcwd(), "public..._"..." in the "_views.py_" file, so I tried to upload the file and it didn't complain about the extension and I thought I could reuse the same file with malicious code to get a reverse shell.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgvZ-82-TNCsRptRHblzrCyXo5TXs21zcrnZQSjvuYRELkIJMW8qOPrP2S7HxGnthI3paqzQJo_XUnUgPJXJbsBUpZa-l3kSXD91JYyXYdgevaopzlECiicfb8JEHiWmiU27UkwttcV8XOZZoOFMlIfGEpDs1lCgBbBRpTIaBblAUMauuXEm6L1do5s6Q=w640-h334)](https://blogger.googleusercontent.com/img/a/AVvXsEgvZ-82-TNCsRptRHblzrCyXo5TXs21zcrnZQSjvuYRELkIJMW8qOPrP2S7HxGnthI3paqzQJo_XUnUgPJXJbsBUpZa-l3kSXD91JYyXYdgevaopzlECiicfb8JEHiWmiU27UkwttcV8XOZZoOFMlIfGEpDs1lCgBbBRpTIaBblAUMauuXEm6L1do5s6Q)

  
Here I had another problem, it did not allow me to specify the absolute path, after trying different kinds of ways to move recursively in directories I got this valid one, managing to upload and replace the file "_views.py_" by the malicious one.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEg1JF9qdByA4-vLfQeaSyw1s6HCfsU-XW-KMa9AzAOdocrbufKt1Jcwr6e70SWcKNr8F-QYCrSx9Ymv7PzNn42UUHAZDiMvML_p8_9rV5r21PX8XBvcRZpMYhnQL2u3hmtIgQJ3zFkky9f1Aw_btTDFr4ggZX_AXYxYSkm-48vAdOXKvQfYvo4pQ5BiRA=w640-h418)](https://blogger.googleusercontent.com/img/a/AVvXsEg1JF9qdByA4-vLfQeaSyw1s6HCfsU-XW-KMa9AzAOdocrbufKt1Jcwr6e70SWcKNr8F-QYCrSx9Ymv7PzNn42UUHAZDiMvML_p8_9rV5r21PX8XBvcRZpMYhnQL2u3hmtIgQJ3zFkky9f1Aw_btTDFr4ggZX_AXYxYSkm-48vAdOXKvQfYvo4pQ5BiRA)

  

We get on the listen with **netcat**, we update and we see that we gain access to the machine. We see that we are logged in as _root_, but we are not on the machine as we can see by the _IP_, so we will be in a **docker** or other type of container. 

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiqaiGtseRIhJL572Yuu1faGvsJxZRJuVO0nAwVquGG7lFD5H0lgFBE_mMrc-LwkMAuyAn84_vZrZoIpoA48SLZ0K-anXRT_SPq7wCWcBSmcrQXrvVZ5W9e8Y9VrEIoJnGkzl5nTfZClmVAcEAVDvpj7Arrmuppn97j2t2o5oon4nfjEXeTgcxa7z8G8A=w640-h461)](https://blogger.googleusercontent.com/img/a/AVvXsEiqaiGtseRIhJL572Yuu1faGvsJxZRJuVO0nAwVquGG7lFD5H0lgFBE_mMrc-LwkMAuyAn84_vZrZoIpoA48SLZ0K-anXRT_SPq7wCWcBSmcrQXrvVZ5W9e8Y9VrEIoJnGkzl5nTfZClmVAcEAVDvpj7Arrmuppn97j2t2o5oon4nfjEXeTgcxa7z8G8A)

  

As I am premium and it was giving me a lot of problems, I deployed a **chisel** as a _client_ to maintain persistence and I started to identify ports with **nmap** from my machine.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhucfJPH3HVzhJSqa4H30M-GUHmX6Ysk1a1OcwXBJgERXyplaNWhRDDhDh6oeCSIGKWqcGsX-w4bIRN6sMEbj8piI1wDrEuKwABlWS56bmo2j7QGGIhLhSGzb27ubcAs5xrmFXNMgKllX9bExXrAjscTRE9UsQio-28j-8sRWKjvCZ8hLsno_sJ5Gop4A=w400-h333)](https://blogger.googleusercontent.com/img/a/AVvXsEhucfJPH3HVzhJSqa4H30M-GUHmX6Ysk1a1OcwXBJgERXyplaNWhRDDhDh6oeCSIGKWqcGsX-w4bIRN6sMEbj8piI1wDrEuKwABlWS56bmo2j7QGGIhLhSGzb27ubcAs5xrmFXNMgKllX9bExXrAjscTRE9UsQio-28j-8sRWKjvCZ8hLsno_sJ5Gop4A)

  

### Identified ports:

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiMWR-Ax9rNTXuay0Qyn_iFWA8JKv-NW9JRq36k-aRfmgEzHLb4LNiR8I8ToQZe76I8E-XDKX-s9hQ7e-YG8J0b5MArGja1NBHFxx-hY3vUJqpwVH_JN7qUHWbWkK5meqa3lVIf_SLzMbw406swuLuYUTwTTnWxgloBkBF63L7Kd4xKwyO3eoEV3qopjg=w400-h340)](https://blogger.googleusercontent.com/img/a/AVvXsEiMWR-Ax9rNTXuay0Qyn_iFWA8JKv-NW9JRq36k-aRfmgEzHLb4LNiR8I8ToQZe76I8E-XDKX-s9hQ7e-YG8J0b5MArGja1NBHFxx-hY3vUJqpwVH_JN7qUHWbWkK5meqa3lVIf_SLzMbw406swuLuYUTwTTnWxgloBkBF63L7Kd4xKwyO3eoEV3qopjg)

  
We discovered a service that we already know "**Gitea**" through _port_ _3000_.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjHrdztNdAkgLaqPf_vLuiUfOV0NdwYkNR-7sqKPput7Qc3dcDKLh6xy5wm-7pxKQwu_U6b2vao9QOzU5HVbRtD9Erx3ktw1WVDfd4E2IPIWSDoWjkLGX9xM426jom1hMbZ6SE98V2WCXYXGDqBEvPhPciueIfV-Py8tXDxcpKM-o_VkIRoNjhGXg_2fw=w640-h150)](https://blogger.googleusercontent.com/img/a/AVvXsEjHrdztNdAkgLaqPf_vLuiUfOV0NdwYkNR-7sqKPput7Qc3dcDKLh6xy5wm-7pxKQwu_U6b2vao9QOzU5HVbRtD9Erx3ktw1WVDfd4E2IPIWSDoWjkLGX9xM426jom1hMbZ6SE98V2WCXYXGDqBEvPhPciueIfV-Py8tXDxcpKM-o_VkIRoNjhGXg_2fw)

  

We access the service through the web browser, register and check if there is any repository where we can get information, but nothing.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgJgHQu6RkvPa-tx6FTzvUKk1YVh5OfJWLYwoOsSd0IKj5IPoIV3Wuz_9y-PTJ6OwgItc8H6cyWXdDj9fxxm0UTrdQG0nQGtOMkkW1UwuEH8LiNK3BJc7Z6csq0r9DZxCO8HThlqbYuu-7Qi0TQ9GMUsW2qwLm-KZ5i6_f5yrZ5cEMXJRxvJyBfWpF6Zw=w613-h640)](https://blogger.googleusercontent.com/img/a/AVvXsEgJgHQu6RkvPa-tx6FTzvUKk1YVh5OfJWLYwoOsSd0IKj5IPoIV3Wuz_9y-PTJ6OwgItc8H6cyWXdDj9fxxm0UTrdQG0nQGtOMkkW1UwuEH8LiNK3BJc7Z6csq0r9DZxCO8HThlqbYuu-7Qi0TQ9GMUsW2qwLm-KZ5i6_f5yrZ5cEMXJRxvJyBfWpF6Zw)

  
So I went back to previous steps and realized that there was the "_.git_" folder (hidden OMG!), so we could try to rescue the files to see if we could find some credentials or some information to compromise the machine.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEheqwR7LhifIzQz601LeaNuWWhfxQ48n2tGjQJcHK08UBmxiARwsH3k9jXxOWlrRG_navzaQRPoAhLi5uKnkXn_jKlqR2OpBY0IgjBtkMbJxNl3jhiDpatyf8-qZSJsy4ybOMEZw5pd6Cv9YXdy1wyJ8_o7Ew1woTGiAoBVa3PvBUYYt5PhWW8Z70IAYA=w400-h251)](https://blogger.googleusercontent.com/img/a/AVvXsEheqwR7LhifIzQz601LeaNuWWhfxQ48n2tGjQJcHK08UBmxiARwsH3k9jXxOWlrRG_navzaQRPoAhLi5uKnkXn_jKlqR2OpBY0IgjBtkMbJxNl3jhiDpatyf8-qZSJsy4ybOMEZw5pd6Cv9YXdy1wyJ8_o7Ew1woTGiAoBVa3PvBUYYt5PhWW8Z70IAYA)

  
So I extracted all the information with **gittools dumper** and we found these credentials!

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiIlwhHL6c42h6eToLvPoaenc45oJ-JUwgHwIN6IJ_gP629j4alI5EZrDUvgDGqvf6mMzS4hfTmsh0GLcz4ulw2qKxIYnsWRj-FkO7EELqO0WD85AXhpZBpX2Lpf00b91_179ZykrS8X9yNGwnJMS6vnM81OkVLWk7tt09zKucsRjtDRwa2_a5sYY_XSg=w640-h208)](https://blogger.googleusercontent.com/img/a/AVvXsEiIlwhHL6c42h6eToLvPoaenc45oJ-JUwgHwIN6IJ_gP629j4alI5EZrDUvgDGqvf6mMzS4hfTmsh0GLcz4ulw2qKxIYnsWRj-FkO7EELqO0WD85AXhpZBpX2Lpf00b91_179ZykrS8X9yNGwnJMS6vnM81OkVLWk7tt09zKucsRjtDRwa2_a5sYY_XSg)

We try to log in via **SSH**, but we see that we are denied permission.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEi1F9NXpoq48YOPJQEFgdLtOf8ky1s_ZIMl70hj3zbHQBVynYNvrsOjB7vULwNJJqOSqYEptqrqxSP5at87RMDrmla6uP7PNZwZcRYzHUyHBKLbBvgOZpx9lBTqpafPFp9ZftEVcTO9u9PJBpQACTD3X19z2oc1ZkKGqx_cktXWtvDaGGFpSlWC75tK2w=w640-h132)](https://blogger.googleusercontent.com/img/a/AVvXsEi1F9NXpoq48YOPJQEFgdLtOf8ky1s_ZIMl70hj3zbHQBVynYNvrsOjB7vULwNJJqOSqYEptqrqxSP5at87RMDrmla6uP7PNZwZcRYzHUyHBKLbBvgOZpx9lBTqpafPFp9ZftEVcTO9u9PJBpQACTD3X19z2oc1ZkKGqx_cktXWtvDaGGFpSlWC75tK2w)

So we test the credentials in **gitea** and we see that there is a backup of your _home_, including the _.ssh_ folder.

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgEIQ2AlWmZw3OGC_upWPz_HkdGvDk2Wx3Met_RT0PgtpQawLHte2hoBUqmOIcO8eEFEbsZpmYCAljP1uS1onWyUIhjK5SQ1HzrwgwqADdowVjZ2dILG7vBudobeSbiNDho36bzQw8kOlbC-vqLSJgKhMiqOKTCwIF-nsn5hgBWl3pdHHsb0wztfFARPA=w640-h515)](https://blogger.googleusercontent.com/img/a/AVvXsEgEIQ2AlWmZw3OGC_upWPz_HkdGvDk2Wx3Met_RT0PgtpQawLHte2hoBUqmOIcO8eEFEbsZpmYCAljP1uS1onWyUIhjK5SQ1HzrwgwqADdowVjZ2dILG7vBudobeSbiNDho36bzQw8kOlbC-vqLSJgKhMiqOKTCwIF-nsn5hgBWl3pdHHsb0wztfFARPA)

Access via **SSH** with the private key and read the user flag:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiVvO2TAhUQlobX4sNHNu0oioWaeS69aNpnDi1_EES4vtwHxNyWklotgshCSKLfg7nz8-jm-6jgo_ARo_BQEu8xsYYecRMBeQD9-M7ctC22I2R3wJcpyW9ImUuPRhHF295GMqMRYqDCCjfEmuHFJYgsapVaeOabcM2qimcGbZo-D4lws3LwvpuyR70rVQ=w640-h522)](https://blogger.googleusercontent.com/img/a/AVvXsEiVvO2TAhUQlobX4sNHNu0oioWaeS69aNpnDi1_EES4vtwHxNyWklotgshCSKLfg7nz8-jm-6jgo_ARo_BQEu8xsYYecRMBeQD9-M7ctC22I2R3wJcpyW9ImUuPRhHF295GMqMRYqDCCjfEmuHFJYgsapVaeOabcM2qimcGbZo-D4lws3LwvpuyR70rVQ)

  

Privilege Escalation
====================

We performed an enumeration with the "_linpeas.sh_" tool and listed a couple of interesting **gitlab** paths.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEj9QfM19gLTQLFKiN5pPtunFLDO60viPiNyAUzx7rZcU8Eacn5IWzWSgn9itmczmpTEhkP-z3Pr49HDRHIyb5KNV6Y5PackcNoq9-mxKDMy9xqMgIfM2wYUyrhL59ZwEHV8I2ogkhClD1y9PNbmPKiXnukzYlQrHm-fdcQWSDJzi1zgiCJL4weuAiBJnA=w640-h106)](https://blogger.googleusercontent.com/img/a/AVvXsEj9QfM19gLTQLFKiN5pPtunFLDO60viPiNyAUzx7rZcU8Eacn5IWzWSgn9itmczmpTEhkP-z3Pr49HDRHIyb5KNV6Y5PackcNoq9-mxKDMy9xqMgIfM2wYUyrhL59ZwEHV8I2ogkhClD1y9PNbmPKiXnukzYlQrHm-fdcQWSDJzi1zgiCJL4weuAiBJnA)

  
There is nothing in the **crontab** file, so we run **pspy** to identify possible scheduled tasks. After a few minutes, we see that it is trying to interact with a **git** by entering a _commit_.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjScsbJ1KtK2h0Os_GNM0C0NoXEG8Rrdsw-_6TfxmDIJQPH8rDC0j9SfgnJAQVQkfyhnpDYn5ascGbzV3A3uqJrfGFUzeQnDSYtJQIjJ4MnhC2iVXYvAL770CoSejxThl_Uqd15Wi6Kw15yUziT8U6ML_Zik79VW8ZbhhpmNmx1LuBeVi9zsoiDP6ov9A=w640-h110)](https://blogger.googleusercontent.com/img/a/AVvXsEjScsbJ1KtK2h0Os_GNM0C0NoXEG8Rrdsw-_6TfxmDIJQPH8rDC0j9SfgnJAQVQkfyhnpDYn5ascGbzV3A3uqJrfGFUzeQnDSYtJQIjJ4MnhC2iVXYvAL770CoSejxThl_Uqd15Wi6Kw15yUziT8U6ML_Zik79VW8ZbhhpmNmx1LuBeVi9zsoiDP6ov9A)

  
Searching for information on how to abuse **[gtfobins](https://gtfobins.github.io/)**, I found a way to run a shell through the "_pre-commit.sample_" file with _hooks_:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEja5i0IyssiFXeyoh3FhOVpEik5KGjvY_ciEOMcLgW7DOBhJ5qMQFzfSi00sLmb6p_ECL8p7FTTKUZ9oCJKrkgL3RBP8_iR0upc3TSE-MZgz4-f_BtgHCnHeAA1Zt-DYcHZF0o_6OZWqlenNJvx7GCRk39wVbmAkQ0u9NJGzT5pyPBYHf4UJ773r9f3EQ=w640-h168)](https://blogger.googleusercontent.com/img/a/AVvXsEja5i0IyssiFXeyoh3FhOVpEik5KGjvY_ciEOMcLgW7DOBhJ5qMQFzfSi00sLmb6p_ECL8p7FTTKUZ9oCJKrkgL3RBP8_iR0upc3TSE-MZgz4-f_BtgHCnHeAA1Zt-DYcHZF0o_6OZWqlenNJvx7GCRk39wVbmAkQ0u9NJGzT5pyPBYHf4UJ773r9f3EQ)

Curiously we have the file:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjQ_233DLFvntYOc_mqX6HZsja5UUknHWMEN763IDcTQ3VbgT7-ig9HVBqYro82mUibVodUwTe2t4oxzWn1sycZ6Ctr5yxXkbrVmn3DQJ69r99S795UAD489o65iAtWk1lMVTrdfqbag-d5q8msuxpEbrQdyVW1Ha1r_E8frOpTojt74T-CHJSqG4xRGw=w640-h310)](https://blogger.googleusercontent.com/img/a/AVvXsEjQ_233DLFvntYOc_mqX6HZsja5UUknHWMEN763IDcTQ3VbgT7-ig9HVBqYro82mUibVodUwTe2t4oxzWn1sycZ6Ctr5yxXkbrVmn3DQJ69r99S795UAD489o65iAtWk1lMVTrdfqbag-d5q8msuxpEbrQdyVW1Ha1r_E8frOpTojt74T-CHJSqG4xRGw)

  
Insert the malicious command and rename the file to "_pre-commit_":

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiQKd-p7il3pReCxk_B3rFbyLtwsS79iOcibNrZXs1bmcvL9sUI9ThDry9qf4248Oa6DbGNGCCautThX6NyvPmvgpSaau2VHXtIlG9ghWMwc_VMAMnH80tWiYjJXGKn-Xddhf35T_70gPJQd1nINB2ZrxD9lwsPATntFhQafTp5kAWvpbH92sx-Gz5McQ=w640-h226)](https://blogger.googleusercontent.com/img/a/AVvXsEiQKd-p7il3pReCxk_B3rFbyLtwsS79iOcibNrZXs1bmcvL9sUI9ThDry9qf4248Oa6DbGNGCCautThX6NyvPmvgpSaau2VHXtIlG9ghWMwc_VMAMnH80tWiYjJXGKn-Xddhf35T_70gPJQd1nINB2ZrxD9lwsPATntFhQafTp5kAWvpbH92sx-Gz5McQ)

  

We put ourselves with a **netcat** listening, wait for the scheduled task to run and read the root flag.  
  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjY4DeCvm25HFlNOuTASXImF6mW2TupH15dhnOsUfEP-8gxi3jkXsyXp5Sdo2Z5Wlie0XqVvjlx0k6q5urtv6GKkrv3bKstJardSUg4qdm4cN8ykipL14KksCGUrmB-FROwsVYSza17yBHedMli_An8r-HW8hRWT4Wdn8E0LjOSc637HMCmccPGfGjUMQ=w640-h288)](https://blogger.googleusercontent.com/img/a/AVvXsEjY4DeCvm25HFlNOuTASXImF6mW2TupH15dhnOsUfEP-8gxi3jkXsyXp5Sdo2Z5Wlie0XqVvjlx0k6q5urtv6GKkrv3bKstJardSUg4qdm4cN8ykipL14KksCGUrmB-FROwsVYSza17yBHedMli_An8r-HW8hRWT4Wdn8E0LjOSc637HMCmccPGfGjUMQ)




