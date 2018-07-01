---
layout: post
title:  "PCAPNG Forensics: Decode - NDH16"
date:   2018-07-01 18:00:00 +0200
comments: true
author: BoiteAKlou
categories:
- "Forensic"
---

A warm-up forensic challenge proposed by NDH16...
 <!--excerpt-->

## Challenge description
We are given a packet capture (decode.pcapng) and a zip archive (Decode_.zip) which have to be investigated.

The Zip file isn't necessary for this challenge since I found the flag in the packet capture, without any intervention of the zip's content.

## Wireshark's power
Let's open this packet capture with Wireshark, it's simply one of the best and easiest-to-use tool for analyzing network captures.

![Wireshark screen capture]({{ "/assets/2018-07-01/wireshark.png" | absolute_url }} "Wireshark"){:width="80%"}

Each request is sent to localhost (127.0.0.1) so this capture probably shows interactions between the client and the local  in-development server.

We can see that **HTTP** is user over **TCP** so the best thing to do is to use the *"Follow HTTP stream"* option in order to undesrtand the nature of the resquets shown here.

The GET request at destination of **/wp-login.php** indicates us that we are dealing with a **wordpress** site. The next HTTP POST request seems very interesting because it should contain the authentication parameters of the website's administrator.

![HTTP stream screen capture]({{ "/assets/2018-07-01/httpstream.png" | absolute_url }} "HTTP stream"){:width="80%"}

Indeed, we see the following admin credentials in the request parameters.

```
log=decode&pwd=95%2F%40Jywf5R%40666
```

However, the challenge is not over since the password is URL-encoded.
After decoding, we have: ```95/@Jywf5R@666``` which is the flag! :triangular_flag_on_post:

BoiteAKlou :hammer:
