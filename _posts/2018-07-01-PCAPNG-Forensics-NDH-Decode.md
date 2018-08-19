---
layout: post
title:  "PCAPNG Forensics: Decode - NDH16"
date:   2018-07-01 18:00:00 +0200
comments: true
author: BoiteAKlou
categories:
- "Writeup"
- "Forensic"
---

A warm-up forensic challenge proposed by NDH16...
 <!--excerpt-->

# Table of Contents
{:.no_toc}

* TOC
{:toc}

## Challenge description
We are given [a packet capture]({{"/assets/2018-07-01/decode.pcapng"}}) and [a zip archive]({{".assets/2018-07-01/Decode_.zip"}}) which have to be investigated.

## Wireshark's power
Let's open this packet capture with Wireshark, it's simply one of the best and easiest-to-use tool for analyzing network captures.

![Wireshark screen capture]({{ "/assets/2018-07-01/wireshark.png" | absolute_url }} "Wireshark"){:width="80%"}

Each request is sent to localhost (127.0.0.1) so this capture probably shows interactions between the client and the local  in-development server.

We can see that **HTTP** is used over **TCP** so the best thing to do is to use the *"Follow HTTP stream"* option in order to undesrtand the nature of the resquets shown here.

The GET request at destination of **/wp-login.php** indicates us that we are dealing with a **wordpress** site. The next HTTP POST request seems very interesting because it should contain the authentication parameters of the website's administrator.

![HTTP stream screen capture]({{ "/assets/2018-07-01/httpstream.png" | absolute_url }} "HTTP stream"){:width="80%"}

Indeed, we see the following admin credentials in the request parameters.

```
log=decode&pwd=95%2F%40Jywf5R%40666
```

This password gives **95/@Jywf5R@666** once URL-decoded.
However, the challenge is not over since we don't have the flag yet...

## What about the zip?

When trying to unzip the given archive, we face the following error:

```bash
boiteaklou@kali:~$ unzip Decode_.zip
Archive:  Decode_.zip
   skipping: Decode_/Decode0         need PK compat. v5.1 (can do v4.6)
   creating: Decode_/
```

It looks like we need another tool to extract the content of this zip. **7z** should be fine.

```bash
boiteaklou@kali:~$ 7z e Decode_.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=C.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs Intel(R) Core(TM) i5-6200U CPU @ 2.30GHz (406E3),ASM,AES-NI)

Scanning the drive for archives:
1 file, 366 bytes (1 KiB)

Extracting archive: Decode_.zip
--
Path = Decode_.zip
Type = zip
Physical Size = 366


Enter password (will not be echoed):
```

We're so lucky to have found a password in the pcapng capture! Let's try it!

```bash
Enter password (will not be echoed):
Everything is Ok        

Folders: 1
Files: 1
Size:       442
Compressed: 366
```

The file "Decode0" is extracted. What does it contain?

```bash
boiteaklou@kali:~$ cat Decode0
01101110 01100100 01101000 00110001 00110110 01011111 01100011 01100010 01100110 01100011 01100101 00110101 01100101 00110011 00110110 01100100 01100100 00110011 00110011 01100011 00110110 01100001 01100100 01100011 01100101 00110011 00110010 01100001 00110110 01100010 00110101 00110111 00110111 01100010 01100101 00110001 00110110 00110001 01100010 00111001 00111000 00110001 00110101 00111000 00111001 00110011 00100000 00100000 00101101
```

This little one-liner removes spaces in the binary flow and convert it to ASCII:

```
boiteaklou@kali:~$ sed -e "s/ //g" < Decode0 |perl -lpe '$_=pack"B*",$_'
ndh16_cbfce5e36dd33c6adce32a6b577be161b9815893  -
```

The job is done! :triangular_flag_on_post:

<p id="signature">BoiteAKlou :hammer:</p>
