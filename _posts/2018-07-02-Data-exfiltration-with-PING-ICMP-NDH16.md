---
layout: post
title:  "Data exfiltration with PING: ICMP - NDH16"
date:   2018-07-02 22:00:00 +0200
comments: true
author: BoiteAKlou
categories:
- "Forensic"
---

An interesting forensic challenge covering a famous method of data exfiltration...
 <!--excerpt-->

## Challenge description

We are given [a packet capture]({{"/assets/2018-07-02/analysis.pcap" | absolute_url }}) showing lots of **Echo Requests / Replies** between the same two computers and we're supposed to investigate.

![Wireshark screen capture]({{ "/assets/2018-07-02/wireshark.png" | absolute_url }} "Wireshark")

## Pretty heavy for a ping...

The ICMP protocol is pretty simple and does not contain a lot of information. However, it includes a **data field** used notably in error messages. This data field can also be used for creating an **ICMP tunnel** between two remote computers where hosts inject data into icmp echo packets. This method is often used to **bypass firewall rules** in the aim of **exfiltrating data**.
Such process can be detected by analyzing ICMP echo packets' size. These packets usually don't exceed 100 bytes. Here, each of them is 542 bytes long.

![ICMP packet size]({{ "/assets/2018-07-02/icmp_packet_size.png" | absolute_url }} "ICMP Packet size"){:width="80%"}

We definitively should have a look at what takes so much space.

## Gimme your data!

I wrote a simple python script **extracting the data section** of ICMP echo request packets. For this, I used the **Scapy** module, which is for me the best tool when it comes to handling packet captures, due to its effectiveness and simplicity of use. My script also **converts extracted data to ASCII** because it occured to be base64 encoded, which is not surprising since it avoids encoding errors during the transmission.

```python
from scapy.all import *
import base64

capture = rdpcap('analysis.pcap')
ping_data = ""

for packet in capture:
   if packet[ICMP].type == 8: # Echo request
       ping_data += packet.load

print base64.b64decode(ping_data)
```
>NOTE: I only kept request packets since replies send back same data and can cause errors when recovering exfiltrated data.

The hidden text reveals to be a part of the very famous *"Hacker Manifesto"* followed by the man page of the "ping" tool.
Right between the two texts lies our reward... :triangular_flag_on_post:

```
I am a hacker, and this is my manifesto.  You may stop this individual,
but you can't stop us all... after all, we're all alike.

                              +++The Mentor+++


Congratulations, ICMP exfiltatration is awesome! The flag is : ndh2k18_017395f4c6312759



Now let's read the manual of one of the best tools you never had!

PING(8)                                  System Manager's Manual: iputils                                  PING(8)

NAME
      ping - send ICMP ECHO_REQUEST to network hosts
```


BoiteAKlou :hammer:
