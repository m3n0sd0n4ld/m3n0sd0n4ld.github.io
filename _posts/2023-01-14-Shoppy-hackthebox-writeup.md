---
title: Shoppy HackTheBox Writeup
tags: [writeup,hackthebox,linux, fuzzing, mattermost]
style: border
color: success
description: ""
---

[![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEitc6mljegodOvBjmUHuHhvdjsBECBkPM4C2oDbraR_F_VSSoBmmZ8BKAwkNUlHnVOtpU-ZoxlHXRB9QAQU-klRGLFz3z6ao5T98XDqcE-2m_6I7jsPWEE4GyJIm3bCVDFTCd-9_agakqfk2PnRkfHWlBr99uLoZV2Z1n2QWKiQfRDuCZDAFa5Jhip8ig/w640-h484/Shoppy.png)](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEitc6mljegodOvBjmUHuHhvdjsBECBkPM4C2oDbraR_F_VSSoBmmZ8BKAwkNUlHnVOtpU-ZoxlHXRB9QAQU-klRGLFz3z6ao5T98XDqcE-2m_6I7jsPWEE4GyJIm3bCVDFTCd-9_agakqfk2PnRkfHWlBr99uLoZV2Z1n2QWKiQfRDuCZDAFa5Jhip8ig/s700/Shoppy.png)

  

Scanning
========

We performed an **nmap** scan of all ports, including scripts and software versions. We list the domain "_shoppy.htb_" in the nmap information.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhQIESs0KoqdqnUIFPmK8Pb2QbaGLMyqM8wSyv0_xBu3o1jSmantZVD22r2A0ixHaNlWumQafg_XMomtsMZE5A2Vp5RF0G-r-5AsLTpVDyr1bBIxT37g2s_i1uN3VoxcwEAqLULR3r9aSc0-umLgAK-G1kVB5lCM9uCBPGkohq8teHp1OKYFXS-3wKasQ=w640-h336)](https://blogger.googleusercontent.com/img/a/AVvXsEhQIESs0KoqdqnUIFPmK8Pb2QbaGLMyqM8wSyv0_xBu3o1jSmantZVD22r2A0ixHaNlWumQafg_XMomtsMZE5A2Vp5RF0G-r-5AsLTpVDyr1bBIxT37g2s_i1uN3VoxcwEAqLULR3r9aSc0-umLgAK-G1kVB5lCM9uCBPGkohq8teHp1OKYFXS-3wKasQ)

  

Enumeration
===========

We put the domain "_shoppy.htb_" in our "_/etc/hosts_" file and access the website, inside we see a kind of countdown to present the beta of their software.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjAnznwziPa4Of3774dvNVk0sbOAI7z4UZCI9nnQbSSHKeg0XrCfQKTO_-aRgEOo5HW1FSxIEh6LSu75qndc_YHn3xAv1QyeFY1Vem8o0BpGrdmSHVvuGvNeJ3Dg83YWtaKbaRYKTyVXBf9wtUq47gDx38n2OgUxnelgKg1weEGrC5M9V-TUKVgzwDGZA=w376-h401)](https://blogger.googleusercontent.com/img/a/AVvXsEjAnznwziPa4Of3774dvNVk0sbOAI7z4UZCI9nnQbSSHKeg0XrCfQKTO_-aRgEOo5HW1FSxIEh6LSu75qndc_YHn3xAv1QyeFY1Vem8o0BpGrdmSHVvuGvNeJ3Dg83YWtaKbaRYKTyVXBf9wtUq47gDx38n2OgUxnelgKg1weEGrC5M9V-TUKVgzwDGZA)

  

  

We launched **dirsearch** and discovered some interesting routes:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhEtrQe8u21Jv6pb4c2W-UIV1mS7PSfw1kKTvZvPjvGX_aiIYHNw7TvKaYMpqrpmEWmS_bu640d1E6H-QTj2id3O4uZTSBYWkS9e1mPezpaoJymnaOaR9rzCzbpqknxCQouhXkVO_LgQO763KzPeYS5tyfpUCOMnf4j5CeK8F9u-EPBqCUciw40HCGpsQ=w640-h476)](https://blogger.googleusercontent.com/img/a/AVvXsEhEtrQe8u21Jv6pb4c2W-UIV1mS7PSfw1kKTvZvPjvGX_aiIYHNw7TvKaYMpqrpmEWmS_bu640d1E6H-QTj2id3O4uZTSBYWkS9e1mPezpaoJymnaOaR9rzCzbpqknxCQouhXkVO_LgQO763KzPeYS5tyfpUCOMnf4j5CeK8F9u-EPBqCUciw40HCGpsQ)

  
On the other hand, we access the port _9093_ resource, we see a kind of _plugins playbooks_ log:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiTXj5PRj7Pid2KJuxfAnIMyNfYRQXgP1I8Op5a_W7d8I3Iu6HKEBvDzpNlHgQfbBaleiax1ufKDmDZW4_1IcHR52sLs-yLjfPsPCUrwTZt5PkeJnur3i9zPVSMtCPczXAhccCmkhl3G3ygUZVJXvWI7OODgNTHNT2btKqLDZa_6VpJ-cVfpEw68U6YGQ=w600-h640)](https://blogger.googleusercontent.com/img/a/AVvXsEiTXj5PRj7Pid2KJuxfAnIMyNfYRQXgP1I8Op5a_W7d8I3Iu6HKEBvDzpNlHgQfbBaleiax1ufKDmDZW4_1IcHR52sLs-yLjfPsPCUrwTZt5PkeJnur3i9zPVSMtCPczXAhccCmkhl3G3ygUZVJXvWI7OODgNTHNT2btKqLDZa_6VpJ-cVfpEw68U6YGQ)

  

Exploitation
============

But let's go by parts, we continue with the port 80 service, we access an authentication panel of a software called "_Shoppy_".

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgoOE2nIS1IwLtoAyLCaH8RhIvXzAJIVLWR6b9ba-JMXKi71fy0ORIYXOjYoBpAkY6MHNjjugy7TIyWgJqAPenvkPQtFP8AjOQDcpLhfoD6kSC0zqz03GgoJJqX6rXk48CaBZtL6svq6YzzCkGRO5hz1ov0qjBHmndN9C7CkRfl4TKmssxRuNwC_PZT_Q=w605-h640)](https://blogger.googleusercontent.com/img/a/AVvXsEgoOE2nIS1IwLtoAyLCaH8RhIvXzAJIVLWR6b9ba-JMXKi71fy0ORIYXOjYoBpAkY6MHNjjugy7TIyWgJqAPenvkPQtFP8AjOQDcpLhfoD6kSC0zqz03GgoJJqX6rXk48CaBZtL6svq6YzzCkGRO5hz1ov0qjBHmndN9C7CkRfl4TKmssxRuNwC_PZT_Q)

  
Tests on the authentication panel, attempt to bypass the login and we see that we can access with the following payload in user and password "_'||'2'||'_".

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEi5_eAwvci7a2j4b3TUsneFzqJXtaIbYV4C8WiehJq5S2Ugd9bNlQ_PGFMKyOaxHtzVMLBWs_v_OfUzB2tb_si0Mspx0cdXzC9ba8g4XmAieJyqrIb7PaAv1_8z7XUu54COE3OFyFI7dPawN1c-ZHzpTPXV8_Y_uu_YP3VZdWRAHWj2V6YyoD6cOt4uEQ=w640-h497)](https://blogger.googleusercontent.com/img/a/AVvXsEi5_eAwvci7a2j4b3TUsneFzqJXtaIbYV4C8WiehJq5S2Ugd9bNlQ_PGFMKyOaxHtzVMLBWs_v_OfUzB2tb_si0Mspx0cdXzC9ba8g4XmAieJyqrIb7PaAv1_8z7XUu54COE3OFyFI7dPawN1c-ZHzpTPXV8_Y_uu_YP3VZdWRAHWj2V6YyoD6cOt4uEQ)

  

We try to set default users as "_admin_", we see that it exists and it creates a file to download.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhsElEpvXIBdHkUOswlZ2mJZ3Ffusj41f5w7HmoHkI1tt3BFc-cHj3HSjg5aa_CQzbY60Qo0lmEj51n1996Qo3TpBPAGEdolIBHa14hLavMensCYekx2szN95hstxC_UOF_91glvdWD4Vfu1TSJ3TJ5lZmuz7O4tTpjcQgeqvngoKR1qO_x1jh3EHXfmw=w640-h210)](https://blogger.googleusercontent.com/img/a/AVvXsEhsElEpvXIBdHkUOswlZ2mJZ3Ffusj41f5w7HmoHkI1tt3BFc-cHj3HSjg5aa_CQzbY60Qo0lmEj51n1996Qo3TpBPAGEdolIBHa14hLavMensCYekx2szN95hstxC_UOF_91glvdWD4Vfu1TSJ3TJ5lZmuz7O4tTpjcQgeqvngoKR1qO_x1jh3EHXfmw)

  
If we click on it, we see that it exports a json file with the user's hashed credentials:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjVi3UA5HweRn0P8E5G7dk7R3c5FFYvM6y3_ULTUmewxOpwzDcx4GzxTaXMI-QKCj0MfkY6GQZdxd_1zGNca7OMd6stlwFGhWUcVGfm066BHx9qD_-uAt-hoq7uVU6YkJpDdQOPmw5yzhpzXBJS32UIr8PLTxGzo6YqBOlqHK_Ch3tTkYLkwnbvLsdi4g=w640-h258)](https://blogger.googleusercontent.com/img/a/AVvXsEjVi3UA5HweRn0P8E5G7dk7R3c5FFYvM6y3_ULTUmewxOpwzDcx4GzxTaXMI-QKCj0MfkY6GQZdxd_1zGNca7OMd6stlwFGhWUcVGfm066BHx9qD_-uAt-hoq7uVU6YkJpDdQOPmw5yzhpzXBJS32UIr8PLTxGzo6YqBOlqHK_Ch3tTkYLkwnbvLsdi4g)

  

Now we try to search for users, since there are no other options, but something tells me that we are going to have to fuzz with a dictionary of user names:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiEWusGYFvGivS3GG-vOi-X9zWnv5sri9HEiwGrgyfalF7WMj3g8T-eNfS8-B4SucfgB9Fn3YSn7v9dGLPHdnmsBKRHCPiJEICItW8oy4IG5ab5-QACa1HonRuIlxioaGbdb9vBhkRuCycG72-NTZMBq85Ca8K-uRZgsgSwSaGUQh2BHp0_8LqTf5nPRw=w640-h264)](https://blogger.googleusercontent.com/img/a/AVvXsEiEWusGYFvGivS3GG-vOi-X9zWnv5sri9HEiwGrgyfalF7WMj3g8T-eNfS8-B4SucfgB9Fn3YSn7v9dGLPHdnmsBKRHCPiJEICItW8oy4IG5ab5-QACa1HonRuIlxioaGbdb9vBhkRuCycG72-NTZMBq85Ca8K-uRZgsgSwSaGUQh2BHp0_8LqTf5nPRw)

  

We launch an enumeration of users with **wfuzz** and we see that valid users are appearing:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgmaCqxYj_vgL5Q0IP0DY0WYlUSdxES9R6E8LzwxP9zmDZeclD7U8sumNdX6y7g3QO1e1MUoaFXFgIZVz5SjTjJ3cvTiLnadQRiuomCeOCUwHL0G9-Cp5Wi_-HRyN1S_BcJO0Di2oqRYLRbtw4QbpRDiDrOChSs45bgbcaJAF3QNVcSf_1pVzz70OFQ_A=w640-h198)](https://blogger.googleusercontent.com/img/a/AVvXsEgmaCqxYj_vgL5Q0IP0DY0WYlUSdxES9R6E8LzwxP9zmDZeclD7U8sumNdX6y7g3QO1e1MUoaFXFgIZVz5SjTjJ3cvTiLnadQRiuomCeOCUwHL0G9-Cp5Wi_-HRyN1S_BcJO0Di2oqRYLRbtw4QbpRDiDrOChSs45bgbcaJAF3QNVcSf_1pVzz70OFQ_A)

  

We reviewed the information of the user "_Josh_":

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEg3xOFEVDHRsutNA0_aX_55v8x5Adweuq-25DB8TtzrfK-lpDc6ZHQzuxatcOXq2HQIKgpRXmEPtHWeqcejUsbdxlyyE2CFYHuf0WZqCjqT9pjqauMyFBZZPQ0K9i4SXbKCqpcEOw83xElRpSnGN0S_3TCicpBLmIF6_n5FIFMZ_o4Imh72qvKlqOv40A=w640-h262)](https://blogger.googleusercontent.com/img/a/AVvXsEg3xOFEVDHRsutNA0_aX_55v8x5Adweuq-25DB8TtzrfK-lpDc6ZHQzuxatcOXq2HQIKgpRXmEPtHWeqcejUsbdxlyyE2CFYHuf0WZqCjqT9pjqauMyFBZZPQ0K9i4SXbKCqpcEOw83xElRpSnGN0S_3TCicpBLmIF6_n5FIFMZ_o4Imh72qvKlqOv40A)

  
We try to get the password from hashes.com and see that we can get the password in plain text:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEizlsnfHf1ykndyogpJLDGndrLMV9LK0HNlMukvGyw0skUzKBO3_K6giBi6wsdOjvkHecxQFxVDyonBmjsjLw7NV0Sa4btIdfoNYrsKZoWG2PsLiinEW4rulr2Jepsa318S5qVi2IAc66lqnLQsLXEKxsJiapnV70L3OBTDdNhtyjnLNQjtL_zW6Ycmdw=w400-h301)](https://blogger.googleusercontent.com/img/a/AVvXsEizlsnfHf1ykndyogpJLDGndrLMV9LK0HNlMukvGyw0skUzKBO3_K6giBi6wsdOjvkHecxQFxVDyonBmjsjLw7NV0Sa4btIdfoNYrsKZoWG2PsLiinEW4rulr2Jepsa318S5qVi2IAc66lqnLQsLXEKxsJiapnV70L3OBTDdNhtyjnLNQjtL_zW6Ycmdw)

  
  

We try to use the credentials on the **SSH** service, but we see that they don't work, so we must be missing some other web service to enumerate.

  

So we try to enumerate subdomains under "_shoppy.htb_" with the **wfuzz** tool and enumerate the subdomain "_mattermost.shoppy.htb_":

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEi7Imz3erJfl-MmPot4CFK6tNxGAWmwTjpocBzxvFy5MGKlKtT-AOzFjD3pjx_hBdHthdPWHbkdQytME1lfMZeBK0__FY_73u7D-jeRtoLhT0UXxcaJrcDb0gX-GpX5uKqEphPfV33fZI9SLR7uL83x7wZf-VeVfyJRJt4LuOBVYA4X62KfZqznf4-kvA=w640-h430)](https://blogger.googleusercontent.com/img/a/AVvXsEi7Imz3erJfl-MmPot4CFK6tNxGAWmwTjpocBzxvFy5MGKlKtT-AOzFjD3pjx_hBdHthdPWHbkdQytME1lfMZeBK0__FY_73u7D-jeRtoLhT0UXxcaJrcDb0gX-GpX5uKqEphPfV33fZI9SLR7uL83x7wZf-VeVfyJRJt4LuOBVYA4X62KfZqznf4-kvA)

  
Other panel enumerate:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEipbc76_m8xuaoEFe0Af9-prTrirz2iPGSGrul470ZHbJR5elODab23YcYysHLY7vH9KQi2wsc10xQSgb6jkKXYuDH89Cs5JLIUa4blPM4KloqVhXqjfpTDaDzJTBhChA2-xlPSahb1aOmOcsGC_g3itsZ4c75ymy-Ogk5TLL6TgdAWa-XLg7ZZOo9H5w=w640-h510)](https://blogger.googleusercontent.com/img/a/AVvXsEipbc76_m8xuaoEFe0Af9-prTrirz2iPGSGrul470ZHbJR5elODab23YcYysHLY7vH9KQi2wsc10xQSgb6jkKXYuDH89Cs5JLIUa4blPM4KloqVhXqjfpTDaDzJTBhChA2-xlPSahb1aOmOcsGC_g3itsZ4c75ymy-Ogk5TLL6TgdAWa-XLg7ZZOo9H5w)

  
We access with the credentials and find that credentials are being shared through a "_Mattermost_" channel:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiEH8H9DW_-SsqhnYEURmHaaYXH9Rew1moPw6BDa0PmoLryVGTeydKZprssatjf69ghqJqG6XgzgsblCvL2BUsOe4QaS7IaYGX-GVGMs7YZpV57-bsIP3VIpL7lW3YbDFVwR_LaOZOi4EDnhcwOhf_ngVvicWTqAVkE5UMb4f_YfwqMs1HHnEMEo8bw_w=w640-h416)](https://blogger.googleusercontent.com/img/a/AVvXsEiEH8H9DW_-SsqhnYEURmHaaYXH9Rew1moPw6BDa0PmoLryVGTeydKZprssatjf69ghqJqG6XgzgsblCvL2BUsOe4QaS7IaYGX-GVGMs7YZpV57-bsIP3VIpL7lW3YbDFVwR_LaOZOi4EDnhcwOhf_ngVvicWTqAVkE5UMb4f_YfwqMs1HHnEMEo8bw_w)

  
We access by **SSH**, list the files, read the user flag and see that we can execute a binary called "_password-manager_" with the user "_deploy_":

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgHJCYmBTach0sEqw3F7s3oDA-Pkbd7QO5Knl423CYs25aYseBD9g_gdEhu6L8KqyKJ20QFh1-AUh_B9ot_hxW6PW4DHQoimt0KVWiobLxXbgW6pspf_DGMfbzWDBCr_3D7gU7bjm9-5EWGkNz9vY4q6H4825H7ea0TxbIS68p5WFp0Y78eU0dyNUahJw=w515-h640)](https://blogger.googleusercontent.com/img/a/AVvXsEgHJCYmBTach0sEqw3F7s3oDA-Pkbd7QO5Knl423CYs25aYseBD9g_gdEhu6L8KqyKJ20QFh1-AUh_B9ot_hxW6PW4DHQoimt0KVWiobLxXbgW6pspf_DGMfbzWDBCr_3D7gU7bjm9-5EWGkNz9vY4q6H4825H7ea0TxbIS68p5WFp0Y78eU0dyNUahJw)

  

Privilege Escalation
====================

If we try to run the binary, we see that it asks for credentials. So I ran a "**strings**" on the path of the binary and saw that it internally tries to read a file that is supposed to contain the valid credentials.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEh414dmzo0MJQRFQyvSuerHBcfO7adEV7_nLxFF10G3ubJ5OhKtxFg78eRFc_TI6ks5KNKqayjdZgD35hB5NutfWWRJdznL-98CkSXuU_TL1Bd0NwdgIKPSE0LcVpNWbJDvYIRj8iDMILtg69BUFNhFeLNHGIYBWyPRfAG8jSKP84TXWQkZhUKnTrZL_Q=w400-h209)](https://blogger.googleusercontent.com/img/a/AVvXsEh414dmzo0MJQRFQyvSuerHBcfO7adEV7_nLxFF10G3ubJ5OhKtxFg78eRFc_TI6ks5KNKqayjdZgD35hB5NutfWWRJdznL-98CkSXuU_TL1Bd0NwdgIKPSE0LcVpNWbJDvYIRj8iDMILtg69BUFNhFeLNHGIYBWyPRfAG8jSKP84TXWQkZhUKnTrZL_Q)

  

But we do not have access to read the file "_creds.txt_":

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjEr-eD24oZ3MfgbXUSTtmSRFLUCZTZpOGgKQVCMhQ28llpPq6KNWL1juwfN9GmL1lZrudycsg0EaMn1s_rZfjK3SOiCwGwXX2FyIzB2s_V9JvPr-sgA8Tc30u-jtEbmz6QxakYaIkrhYGSHHIYR6UuJeRf4X36v7C0uh19I8tkwPy0vGaxcE1gZV8aKQ=w400-h61)](https://blogger.googleusercontent.com/img/a/AVvXsEjEr-eD24oZ3MfgbXUSTtmSRFLUCZTZpOGgKQVCMhQ28llpPq6KNWL1juwfN9GmL1lZrudycsg0EaMn1s_rZfjK3SOiCwGwXX2FyIzB2s_V9JvPr-sgA8Tc30u-jtEbmz6QxakYaIkrhYGSHHIYR6UuJeRf4X36v7C0uh19I8tkwPy0vGaxcE1gZV8aKQ)

  
We review the permissions and files that exist in the folder of the user "_deploy_":

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjtqLK4YOemrDUPF2r4TZJiv5jwAQxUojzyoBajpJ4Ijugym8asuTkLqp03jawme8VL6dkq76CfaLh5VExcvQONXS4co735e7LW0fYPC55hyDOsCRbHuYp_ZlobMyGQGF9dXLxn1W-S9h4C-Bky04ZozlTufaVBJyH5g6sgelV6aK9DbyFcVe0AeTbshA=w640-h269)](https://blogger.googleusercontent.com/img/a/AVvXsEjtqLK4YOemrDUPF2r4TZJiv5jwAQxUojzyoBajpJ4Ijugym8asuTkLqp03jawme8VL6dkq76CfaLh5VExcvQONXS4co735e7LW0fYPC55hyDOsCRbHuYp_ZlobMyGQGF9dXLxn1W-S9h4C-Bky04ZozlTufaVBJyH5g6sgelV6aK9DbyFcVe0AeTbshA)

  

We try to "**cat**" binary over the "_password-manager_" file and we see that a string that could be the password is being leaked:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEgq0ZugB5D_gSIeSSlO80zIS3OUto3JPHqxeOHzixHqOF1K83WMMvvhokKj4RI6EOQJ_lHODKQqDPx1PBhUehZUY69UvKNLEjeeCr6pWTclnaIuy0QRjAdimIjG-P-SRPgNzlHTNWGaCJUv0m3pjdgnFPNrHPJbZOpMXoa-E76qUofaN61ZMm4wUZX1TA=w640-h46)](https://blogger.googleusercontent.com/img/a/AVvXsEgq0ZugB5D_gSIeSSlO80zIS3OUto3JPHqxeOHzixHqOF1K83WMMvvhokKj4RI6EOQJ_lHODKQqDPx1PBhUehZUY69UvKNLEjeeCr6pWTclnaIuy0QRjAdimIjG-P-SRPgNzlHTNWGaCJUv0m3pjdgnFPNrHPJbZOpMXoa-E76qUofaN61ZMm4wUZX1TA)

  
We test the password and obtain the credentials of the "_deploy_" user:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEjFE-blKd7-fiYA3pp5vFL37vVtSnJR-M6WdQtvLvU8M4_ObKF2qKKrfTMpDARe205B7mxCLp0H8rq5Td2p07ePIBxkJI0WQiYSDBma9pfCKNRW2aNGf40Heh2u0qsWLeVj8sHgvBDhG7Bzo1TWHxLibxI9A-oPs0mhsi--knk-YmIXz81HRzhCFoI2tQ=w400-h138)](https://blogger.googleusercontent.com/img/a/AVvXsEjFE-blKd7-fiYA3pp5vFL37vVtSnJR-M6WdQtvLvU8M4_ObKF2qKKrfTMpDARe205B7mxCLp0H8rq5Td2p07ePIBxkJI0WQiYSDBma9pfCKNRW2aNGf40Heh2u0qsWLeVj8sHgvBDhG7Bzo1TWHxLibxI9A-oPs0mhsi--knk-YmIXz81HRzhCFoI2tQ)

  
  
We authenticate as the "_deploy_" user and see that we are in relevant groups to read files or do privilege escalations:

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEiCr0fLc-a96iXPNpb-BOvaCASFyiM-QlMoAVDyiO1qoU4TmT51QCzNSuClKAUI4Lv5tzvctt7OFmJpm0DNm-rsAgSTCofHKRc-aRQgmDAVu7RYgKcKS1PRzBB2HsdwnnF3YzOQO6xunAtGTbgI4688uLq27qUIGjc2AojfQU5OzDYinADcpZQ0dKteVQ=w640-h346)](https://blogger.googleusercontent.com/img/a/AVvXsEiCr0fLc-a96iXPNpb-BOvaCASFyiM-QlMoAVDyiO1qoU4TmT51QCzNSuClKAUI4Lv5tzvctt7OFmJpm0DNm-rsAgSTCofHKRc-aRQgmDAVu7RYgKcKS1PRzBB2HsdwnnF3YzOQO6xunAtGTbgI4688uLq27qUIGjc2AojfQU5OzDYinADcpZQ0dKteVQ)

  

So we don't complicate things, we run docker to raise a shell and we manage to read the root flag.

  

[![](https://blogger.googleusercontent.com/img/a/AVvXsEhKQ5cjJd4Ra_yDF_maGd6vjRwdH4_6YupFBHKpfEwn3ooOlajxKiiJ4cumoApKzjBz7b3UbUYD_OsRPdBq9VkYEyZQE3jxd8zk0-02VWTarQ4HKdaC1_9j_sYx9iF077FsibxMmKO-v1BmI2dAeruNu_pXtvmHac9D_Rooz776-kjyE1L5Mx9nTzSmKQ=w640-h120)](https://blogger.googleusercontent.com/img/a/AVvXsEhKQ5cjJd4Ra_yDF_maGd6vjRwdH4_6YupFBHKpfEwn3ooOlajxKiiJ4cumoApKzjBz7b3UbUYD_OsRPdBq9VkYEyZQE3jxd8zk0-02VWTarQ4HKdaC1_9j_sYx9iF077FsibxMmKO-v1BmI2dAeruNu_pXtvmHac9D_Rooz776-kjyE1L5Mx9nTzSmKQ)