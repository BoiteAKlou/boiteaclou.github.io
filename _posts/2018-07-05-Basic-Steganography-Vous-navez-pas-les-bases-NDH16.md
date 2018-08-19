---
layout: post
title:  "Basic Steganography: Vous n'avez pas les bases - NDH16"
date:   2018-07-05 23:30:00 +0200
comments: true
author: BoiteAKlou
categories:
- "Writeup"
- "Stegano"
---

A steganographic challenge showing the essential tools for PNG analysis and manipulating encoding bases.

 <!--excerpt-->

# Table of Contents
{:.no_toc}

* TOC
{:toc}

## Challenge description

The PNG file [OREILLES_SALES.png]({{ "/assets/2018-07-05/OREILLES_SALES.png" | absolute_url }}) (named after the famous french rapper "Orelsan") is provided without more instructions.

![PNG preview]({{ "/assets/2018-07-05/OREILLES_SALES.png" | absolute_url }} "PNG file preview"){:width="40%"}

## Never gonna give you up

Since we're never too careful when it comes to steganography, I verified that the provided file was indeed a PNG.

```bash
boiteaklou@kali:~$ file OREILLES_SALES.png
OREILLES_SALES.png: PNG image data, 680 x 520, 8-bit/color RGBA, non-interlaced
```

Even though this check isn't infallible, we'll suppose it tells the truth.

Why don't we start by checking metadata ? *\*grabs exiftool\**

```bash
boiteaklou@kali:~$ exiftool OREILLES_SALES.png
ExifTool Version Number         : 11.03
File Name                       : OREILLES_SALES.png
Directory                       : .
File Size                       : 396 kB
File Modification Date/Time     : 2018:07:01 00:11:07+02:00
File Access Date/Time           : 2018:07:05 22:34:23+02:00
File Inode Change Date/Time     : 2018:07:01 00:11:24+02:00
File Permissions                : rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 680
Image Height                    : 520
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Exif Byte Order                 : Little-endian (Intel, II)
User Comment                    : aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1kUXc0dzlXZ1hjUQ==
Thumbnail Offset                : 154
Thumbnail Length                : 5176
Gamma                           : 2.2222
White Point X                   : 0.3127
White Point Y                   : 0.329
Red X                           : 0.64
Red Y                           : 0.33
Green X                         : 0.3
Green Y                         : 0.6
Blue X                          : 0.15
Blue Y                          : 0.06
Background Color                : 255 255 255
Modify Date                     : 2017:09:22 11:41:16
Datecreate                      : 2017-09-22T13:41:16+02:00
Datemodify                      : 2017-09-22T13:41:16+02:00
Signature                       : f0140da3c2e1bf77c4183d771f341d8f3a8e3afc4c7c3b1b65917e8678b16b3e
Software                        : Adobe ImageReady
Warning                         : [minor] Trailer data after PNG IEND chunk
Image Size                      : 680x520
Megapixels                      : 0.354
Thumbnail Image                 : (Binary data 5176 bytes, use -b option to extract)
```

The **User Comment** caught my attention, it was at this moment that I severely underestimated this challenge...

Decoding this base64-encoded comment gives us the following URL:

```bash
boiteaklou@kali:~$ echo "aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1kUXc0dzlXZ1hjUQ==" | base64 -d
https://www.youtube.com/watch?v=dQw4w9WgXcQ
```

I let you visit this link... Don't worry, nothing dangerous. :sob:

## Never gonna let you down

After this bitter failure, I decided to change my approach and to start looking for any dissimulated file inside the picture. To complete this task, I recommend the "**Foremost**" tool, which is one of the best in its category.

```bash
boiteaklou@kali:~$ foremost OREILLES_SALES.png
Processing: OREILLES_SALES.png
|*|
```
The result of the extraction is stored in the "output" folder by default. Here, it gives two PNG files:

```bash
boiteaklou@kali:~$ ls output/png/
00000000.png  00000370.png
```

**00000000.png** is the original picture provided with the challenge, but [00000370.png]({{ "/assets/2018-07-05/00000370.png" | absolute_url }}) is way more interesting:

![00000370.png]({{ "/assets/2018-07-05/00000370.png" | absolute_url }} "00000370.png preview"){:width="40%"}

We will call this file "basiq.png" for more readability.

Driven by my desire for revenge, I've had a look at metadata in this new file.

```bash
boiteaklou@kali:~$ exiftool basiq.png
ExifTool Version Number         : 11.03
File Name                       : basiq.png
Directory                       : .
File Size                       : 210 kB
File Modification Date/Time     : 2018:07:01 00:16:42+02:00
File Access Date/Time           : 2018:07:05 23:12:37+02:00
File Inode Change Date/Time     : 2018:07:01 00:18:01+02:00
File Permissions                : rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 680
Image Height                    : 510
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Special Instructions            : 4D4A57564533324E4B524E474D5A4A544F5256553436544850424844455354494A555A4653364B5A474A4D5445544B584C453255344D5356474E475855514C5A4A555A4555334B5049524354435753584A4A5755365632474E5247573252544B4A56564655323232495247584F574C4E4A553245325243534E42484732534A524A5A4346534D433249354C47595453454E4D32453656324F4E4A4E4649554C324A564C565336434F4E4A4558515753584B4532553652434B4E564E4549554C594C4A57554B4E434E495241584F54544E4A553245365632534E4A4D5855524A544C4A4B464B36535A4B5249584F5432454C4A554655334B4B4E4A4D564F534C324C455A455532535049354954475454324A555A553256434B4E524846495A5A534A555A54434F493D
Gamma                           : 2.2222
White Point X                   : 0.31269
White Point Y                   : 0.32899
Red X                           : 0.63999
Red Y                           : 0.33001
Green X                         : 0.3
Green Y                         : 0.6
Blue X                          : 0.15
Blue Y                          : 0.05999
Background Color                : 255 255 255
Pixels Per Unit X               : 15748
Pixels Per Unit Y               : 15748
Pixel Units                     : meters
Modify Date                     : 2017:09:22 12:01:42
Datecreate                      : 2017-09-22T14:01:42+02:00
Datemodify                      : 2017-09-22T14:01:42+02:00
Signature                       : 5e6790047fb3e3c8a74d63cdf6e91766d0ba9f513f8d5ea2020e51514bc3ee05
Image Size                      : 680x510
Megapixels                      : 0.347
```

And once again, a special field caught my attention. Guess which one...

Well, let's give it a second chance, knowing that the Rick Roll threat was hanging over me.

The message surely is encoded, but how ? We will figure this out by trying all of the potential encoding:
* Base64 gave nothing relevant.
* Can't be Base32 because of invalid characters such as "0" and "1".
* **Base16**? The most likely possibility. Python will help us verify it.

```python
boiteaklou@kali:~$ python
Python 2.7.14+ (default, Apr  2 2018, 04:16:25)
[GCC 7.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> "4D4A5756[...]4F493D".decode("hex")
'MJWVE32NKRNGMZJTORVU46THPBHDESTIJUZFS6KZGJMTETKXLE2U4MSVGNGXUQLZJUZEU3KPIRCTCWSXJJWU6V2GNRGW2RTKJVVFU222IRGXOWLNJU2E2RCSNBHG2SJRJZCFSMC2I5LGYTSENM2E6V2ONJNFIUL2JVLVS6CONJEXQWSXKE2U6RCKNVNEIULYLJWUKNCNIRAXOTTNJU2E6V2SNJMXURJTLJKFK6SZKRIXOT2ELJUFU3KKNJMVOSL2LEZEU2SPI5ITGTT2JUZU2VCKNRHFIZZSJUZTCOI='
```

Great! We have another base-encoded message! I'll skip the determination process for this one, we're dealing with **base32**.

```bash
boiteaklou@kali:~$ echo "MJWVE32NKR[...]ZSJUZTCOI=" | base32 -d
bmRoMTZfe3tkNzgxN2JhM2YyY2Y2MWY5N2U3MzAyM2JmODE1ZWJmOWFlMmFjMjZkZDMwYmM4MDRhNmI1NDY0ZGVlNDk4OWNjZTQzMWYxNjIxZWQ5ODJmZDQxZmE4MDAwNmM4OWRjYzE3ZTUzYTQwODZhZmJjYWIzY2JjOGQ3NzM3MTJlNTg2M319
```

One more! Let me guess, **base64** this time?

```bash
boiteaklou@kali:~$ echo "bmRoMTZf[...]NTg2M319" | base64 -d
ndh16_{d7817ba3f2cf61f97e73023bf815ebf9ae2ac26dd30bc804a6b5464dee4989cce431f1621ed982fd41fa80006c89dcc17e53a4086afbcab3cbc8d773712e5863}
```

Alright, this was the final step! Congratz' :triangular_flag_on_post:

<p id="signature">BoiteAKlou :hammer:</p>
