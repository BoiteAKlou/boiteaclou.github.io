---
layout: post
title:  "cyBRICS CTF Writeups"
date:   2019-07-21 09:00:00 +0100
comments: true
author: BoiteAKlou
categories:
- "Writeup"
- "Web"
- "Network"
- "Stegano"
- "Misc"
---

![cyBRICS logo]({{ "/assets/2019-07-21/ctf.png" | absolute_url }} "cyBRICS logo"){:width="40%"}

**Final rank:** 112/775 with 7 challenges solved
<!--excerpt-->


## Table of Contents
{:.no_toc}

* TOC
{:toc}


## [Web] Warmup
### Statement
> Warmup (Web, Baby, 10 pts)
>
>Author: George Zaytsev (groke)
>
>E_TOO_EASY
>
>Just get the [flag](http://45.32.148.106/)


### Resolution

When browsing to the link in the sentence, we were instantly redirected to **/final.html**, which displays a very long text but no flag.

Using Burpsuite, we could intercept the redirection and grab the flag lcoated in **/index.html**.

![Warmup flag]({{ "/assets/2019-07-21/warmup-flag.png" | absolute_url }} "Warmup flag")

Once base64-decoded, we could read the following flag: `cybrics{4b646c7985fec6189dadf8822955b034}`.

## [Web] Bitkoff Bank
### Statement
>Bitkoff Bank (Web, Easy, 50 pts)
>
>Author: Alexander Menshchikov (n0str)
>
>Need more money! Need the flag!
>
>http://45.77.201.191/index.php
>
>Mirror: http://95.179.148.72:8083/index.php

### Resolution

I'm pretty sure I didn't solve this challenge the intended way because my method was pretty dumb. Judge by yourself! :wink:

After registering an account, you were greeted with the following php page:

![Bitkoff home]({{ "/assets/2019-07-21/bitkoff-home.png" | absolute_url }} "Bitkoff home")

Everytime you clicked on "MINE BTC", `0.0000000001` was added to your BTC counter. It was, then, possible to **convert BTC to USD** in order to **buy the flag when you reached 1$**.

An auto-miner costed 0.01$ and would click for you every second... not so worth it.

What I did is pretty simple: I've **automated the mining request** thanks to a python script and ran 6 instances of it in parallel until I got enough BTC to buy the flag. Absolutely nothing was optimized but I had a few other things to do so I've left the script run in background for approximately 2 hours and I could buy the flag!

```python
import requests,re

payload = {'mine': '1'}
cook = {'name' : 'boiteaklou', 'password' : 'boiteaklou'}

while 1:
    r = requests.post('http://95.179.148.72:8083/index.php',data=payload,cookies=cook)
    btc = re.findall('Your BTC: <b>([^<]*)</b>',r.text)
    print("BTC: %s"%btc[0])
```

Here is the cheapest bitcoin mining farm ever:

![Mining farm]({{ "/assets/2019-07-21/bitkoff-farm.png" | absolute_url }} "Mining farm")

A minor difficulty consisted in the fact that we could not enter a value lower than 0.0001 in the change field because of some HTML client-side check. However, we could forge the request using Burpsuite and it worked like a charm.

![Bitkoff 1 dollar]({{ "/assets/2019-07-21/bitkoff-one_dollar.png" | absolute_url }} "Bitkoff 1$")

And the flag:

![Bitkoff flag]({{ "/assets/2019-07-21/bitkoff-flag.png" | absolute_url }} "Bitkoff flag")

`flag: cybrics{50_57R4n93_pR3c1510n}`

## [Web] Caesaref
### Statement
>Caesaref (Web, Hard, 50 pts)
>
>Author: Alexander Menshchikov (n0str)
>
>There is an additional one: Fixaref
>
>This web resource is highly optimized:
>
>http://45.77.218.242/


### Resolution

After register a new account, we were greeted with the following web page where we could ask questions to the support:

![Caesaref home]({{ "/assets/2019-07-21/caesaref-home.png" | absolute_url }} "Caesaref home")

At first, I lost a lot of time trying to redirect the support guy to my website via XSS payloads like `<img src="http://mywebsite" />`.

Actually, it was not necessary. We only had to paste an HTTP link in the text box and a bot would visit it instantly.

Using this information, we could **paste the link to a webhook instance** and surprisingly find the **PHPSESSID cookie of the bot** sent with the request.

![Caesaref request]({{ "/assets/2019-07-21/caesaref-request.png" | absolute_url }} "Caesaref request")

Then, we could replace our own PHPSESSID cookie by the retrieved one and refresh the page in order to access the bot account. Once connected, a new button was here to give us the flag.

`Flag: cybrics{k4Ch3_C4N_83_vuln3R48l3}`

## [Network] Sender
### Statement
>Sender (Network, Baby, 10 pts)
>
>Author: Vlad Roskov (vos)
>
>We've intercepted this text off the wire of some conspirator, but we have no idea what to do with that.
>
>[intercepted_text.txt]({{ "/assets/2019-07-21/intercepted_text.txt" | absolute_url }})

>
>Get us their secret documents


### Resolution

The given text file shows a SMTP trace from which we could extract some credentials as well as the password of an archive.

```
220 ugm.cybrics.net ESMTP Postfix (Ubuntu)
EHLO localhost
250-ugm.cybrics.net
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-AUTH PLAIN LOGIN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250 DSN
AUTH LOGIN
334 VXNlcm5hbWU6      
ZmF3a2Vz
334 UGFzc3dvcmQ6                        # Username
Q29tYmluNHQxb25YWFk=                    # Password
235 2.7.0 Authentication successful
MAIL FROM: <fawkes@ugm.cybrics.net>
250 2.1.0 Ok
RCPT TO: <area51@af.mil>
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
From: fawkes <fawkes@ugm.cybrics.net>
To: Area51 <area51@af.mil>
Subject: add - archive pw
Content-Type: text/plain; charset="iso-8859-1"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0

=62=74=77=2E=0A=0A=70=61=73=73=77=6F=72=64 =66=6F=72 =74=68=65 =61=72=63=
=68=69=76=65 =77=69=74=68 =66=6C=61=67=3A =63=72=61=63=6B=30=57=65=73=74=
=6F=6E=38=38=76=65=72=74=65=62=72=61=0A=0A=63=68=65=65=72=73=21=0A
.
250 2.0.0 Ok: queued as C4D593E8B6
QUIT
221 2.0.0 Bye
```


Base64-decoded credentials: `fawkes / Combin4t1onXXY`

Mail content (quoted-printable decoded):

>btw.
>
>password for the archive with flag: crack0Weston88vertebra
>
>cheers!

A NMAP scan showed us that the pop3 port (tcp 110) was open so we could connect to it and authentify ourselves using the retrieved credentials.

```bash
$ telnet ugm.cybrics.net 110
Trying 136.244.67.129...
Connected to ugm.cybrics.net.
Escape character is '^]'.
+OK Dovecot ready.
USER fawkes
+OK
PASS Combin4t1onXXY
+OK Logged in.
LIST
+OK 1 messages:
1 138808
.
+OK 138808 octets
Return-Path: <fawkes@ugm.cybrics.net>
X-Original-To: fawkes@ugm.cybrics.net
Delivered-To: fawkes@ugm.cybrics.net
Received: by sender (Postfix, from userid 1000)
        id B83843EBFF; Thu, 18 Jul 2019 16:41:23 +0000 (UTC)
Date: Thu, 18 Jul 2019 16:41:23 +0000
From: fawkes <fawkes@ugm.cybrics.net>
To: Area51 <area51@af.mil>, fawkes <fawkes@ugm.cybrics.net>
Subject: interesting archive
Message-ID: <20190718164123.GA9631@ugm.cybrics.net>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="J2SCkAp4GZ/dPZZf"
Content-Disposition: inline
User-Agent: Mutt/1.5.24 (2015-08-30)


--J2SCkAp4GZ/dPZZf
Content-Type: text/plain; charset=us-ascii
Content-Disposition: inline

take a look. dont share. secret.

--J2SCkAp4GZ/dPZZf
Content-Type: application/zip
Content-Disposition: attachment; filename="secret_flag.zip"
Content-Transfer-Encoding: base64

UEsDBBQACQBjAMua8k6A+vIXUogBAA+iAQAPAAsAc2VjcmV0X2ZsYWcucGRmAZkHAAEAQUUD
CAC1GtwFWQRy7mwXUpknBhOJ3hpnDv1ei1Kf+knOhoW61yeyPdnML4vSrff+GUxQYCGKz6SB
[...]
AAAAAHNlY3JldF9mbGFnLnBkZgoAIAAAAAAAAQAYAGA6RPuEPdUBoKjPA4U91QGgqM8DhT3V           
AQGZBwABAEFFAwgAUEsFBgAAAAABAAEAbAAAAJqIAQAAAA==

--J2SCkAp4GZ/dPZZf--
```

Then, we could extract the content of the retrieved archive using the previously found password: `7z e -pcrack0Weston88vertebra archive.zip`

And we could finally read the flag inside the extracted PDF: `cybrics{Y0uV3_G0T_m41L}`.


## [Network] Paranoid
### Statement
> Paranoid (Network, Easy, 113 pts)
>
>Author: Vlad Roskov (vos)
>
>Added at 14:40 UTC: to save some guessing, flag is the current password. Flag format is still cybrics{...}, so you'll know when you find it.
>
>My neighbors are always very careful about their security. For example they've just bought a new home Wi-Fi router, and instead of just leaving it open, they instantly are setting passwords!
>
>Don't they trust me? I feel offended.
>
>[paranoid.zip]({{ "/assets/2019-07-21/paranoid.zip" | absolute_url }})
>
>Can you give me their current router admin pw?

### Resolution

The zip archive contained a pcap that I opened in Wireshark. Since the capture was quite big, I used **Statistics > Protocol Hierarchy** in order to get the big picture.

The packet capture was composed of **802.11 traffic** and thanks to the protocol hierarchy, I could spot some **HTTP requests**.

As the statement was mentioning a password change, I decided to examine **HTTP POST requests** only thanks to the wireshark filter: `http.request.method == "POST"`.

Inside the payload of HTTP POST request n°19173, we could find `WLAN_AP_WEP_KEY1=Xi1nvy5KGSgI2&`. Then, I added this wep key to **wireshark decryption keys** and it allowed us to find more HTTP requests.

Still filtering HTTP POST requests, I found a new password change request with this payload: `WLAN_AP_WPA_PSK=2_RGR_xO-uiJFiAxdA33-PsdanuK&` that I immediately set as **WPA decryption key**.

Once again, we had access to more decrypted HTTP traffic inside which the flag was located.

![Paranoid flag]({{ "/assets/2019-07-21/paranoid-flag.png" | absolute_url }} "Paranoid flag")

Flag: `cybrics{n0_w4Y_7o_h1d3_fR0m_Y0_n316hb0R}`

## [Misc] ProCTF
### Statement
>ProCTF (CTB, Baby, 10 pts)
>
>Author: Vlad Roskov (vos)
>
>We Provide you a Login for your scientific researches. Don't try to find the flag.
>
>ssh pro@95.179.148.72
>Password: iamthepr0

### Resolution

After connecting to the machine via SSH, we were trapped inside **a SWI-Prolog interactive interpreter**. We could verify this assumption by pressing TAB twice, which would display the list of available functions.

```bash
$ ssh pro@95.179.148.72
pro@95.179.148.72\'s password:
Welcome to Ubuntu 19.04 (GNU/Linux 5.0.0-15-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Jul 20 12:28:39 UTC 2019

  System load:                    4.15
  Usage of /:                     2.4% of 220.08GB
  Memory usage:                   10%
  Swap usage:                     0%
  Processes:                      508
  Users logged in:                3
  IP address for enp1s0:          95.179.148.72
  IP address for docker0:         172.17.0.1
  IP address for br-62bc0c6d2f97: 172.19.0.1


84 updates can be installed immediately.
48 of these updates are security updates.


WARNING: Your kernel does not support swap limit capabilities or the cgroup is not mounted. Memory limited without swap.
?-
abort                           built_in_procedure              current_output                  erf
abs                             busy                            cut                             erfc
access                          byte                            cut_call                        error
access_level                    c_stack                         cut_exit                        eval
acos                            call                            cut_parent                      evaluable
acosh                           call_continuation               cycle                           evaluation_error
active                          callable                        cycles                          event_hook
acyclic_term                    canceled                        cyclic_term                     exception
add_import                      case_insensitive                date                            exclusive
address                         case_preserving                 db_reference                    execute
... skipped 54 rows
```

After some googling, I found an easy way to get a shell and to display the flag:

```bash
?- shell('sh').
$
$ cd /home
$ ls
user
$ cd user
$ ls
flag.txt
$ cat flag.txt
cybrics{feeling_like_a_PRO?_that_sounds_LOGical_to_me!____g3t_it?_G37_1T?!?!_ok_N3v3Rm1nd...}
```

Flag: `cybrics{feeling_like_a_PRO?_that_sounds_LOGical_to_me!____g3t_it?_G37_1T?!?!_ok_N3v3Rm1nd...}`

## [Stegano] Honey, Help!
### Statement
>Honey, Help! (rebyC, Baby, 10 pts)
>
>Author: Vlad Roskov (vos)
>
>Added at 10:50 UTC: there was a typo in the flag. Please re-submit.
>
>HONEY HELP!!!
>
>I was working in my Kali MATE, pressed something, AND EVERYTHING DISAPPEARED!

![honeyHELP]({{ "/assets/2019-07-21/honey_help.png" | absolute_url }} "honey help")

### Resolution

This challenge was very easy but a bit painful for my eyes because I solved it late in the night.

The idea is to **compare the clear and the encoded output** in order to **establish a match for each character**.

Using this technique and a tiny bit of guessing (because it's stega), I could build the following matching table and reconstruct the flag.

```
240C : c
< : y
2409 : b
23BC : r
240B : i
23BD : s
Pi : {
2424 : h
half-T : l
23BB : p
Cross : n
low T : w
|- : t
Pound : }
grey square : a
```

`cybrics{h0ly_cr4p_1s_this_al13ni$h_0r_w4t?}`


The CTF was pretty fun, thanks CyBRICS for the event!

<p id="signature">BoiteAKlou :hammer:</p>
