---
layout: post
title:  "Introduction to Buffer Overflows: CookieJar - AngstromCTF"
date:   2018-06-05 08:35:00 +0200
comments: true
author: BoiteAKlou
categories:
- "Pwning"
---
For my first article on this blog, I'll present you my write-up of "CookieJar" from the AngstromCTF. This challenge was accessible and very straight-forward, which constitutes the prefect opportunity to introduce **Buffer Overflows**...
 <!--excerpt-->

# Table of Contents
{:.no_toc}

* TOC
{:toc}

## Pre-requisites
* A very basic understanding of **x86 or x64 architectures** will help you to grasp the concept of buffer overflow.

## Challenge description
![challenge statement]({{ "/assets/2018-06-05/challenge.png" | absolute_url }} "Statement"){:width="80%"}

 We have [a binary]({{"/assets/2018-06-05/cookiePublic.c"}}) and the corresponding [source code]({{"/assets/2018-06-05/cookiePublic64"}}) given for this challenge. The objective is to find a way to exploit this binary locally and to re-use the same exploit on the remote server in order to get the flag.



 The first thing we should do in this case is to analyze the program and its source code.

## Program analysis
### Let's run it !

Here is a standard execution:

```bash
boiteaklou@csb:~$ ./cookiePublic64
Welcome to the Cookie Jar program!

In order to get the flag, you will need to have 100 cookies!

So, how many cookies are there in the cookie jar:
> 100
Sorry, you only had 0 cookies, try again!
```

The program asks for an number of cookies in the jar but no matter what we submit, it seems that we are stuck with 0 cookies.

Alright, now let's dive into the code!

### Source code dissection

The code is pretty simple so the vulnerability should jump out.

Don't pay attention to the first part of the main function, it only sets the execution rights of the program.

```c
gid_t gid = getegid();
setresgid(gid, gid, gid);
```
Here are the noticeable parts:

* A variable named **numCookies** is declared and initialized with 0.
```c
int numCookies = 0;
```
* A buffer is declared with a size of 64 characters for storing the user input.
```c
char buffer[64];
```
* A simple check is done on **numCookies** and displays the **flag** if numCookies>=100.
```c
if (numCookies >= 100){
		printf("Congrats, you have %d cookies!\n", numCookies);
		printf("Here's your flag: %s\n", FLAG);
	} else {
		printf("Sorry, you only had %d cookies, try again!\n",numCookies);
}
```


All of this seems pretty legit but there's no way to increment this variable... We're probably missing something.

## Vulnerabilty explanation

I'll give you a hint:
```
gets(buffer);
```

At this moment, you must be like "Yeah... OK... tell me more" and it's normal if you've never encountered this kind of vulnerability.

However, this is probably one of the most common exploit and it's called **buffer overflow**.

### What is a buffer overflow?

When a variable is declared, space is allocated on the stack according to the size of our variable.

Let's take the example of the buffer from the challenge:

```c
char buffer[64];
```

After this instruction, **64 bytes are allocated on the stack** in order to store the value contained in the buffer (A char is coded on a single byte in C).

In compiled languages such as C, the memory is allocated at the compilation time and this process is sequential. It means that the next variable found in the code will be located above the previous one on the stack.

Also keep in mind that **the highest addresses are located at the bottom of the stack** in our architecture.

In the source code of the challenge, the very interesting variable **numCookies** is declared just before the buffer. In other words, **the buffer will be stored right above numCookies on the stack.**

```c
int numCookies = 0;
char buffer[64];
```


Let's represent the hypotetical state of the stack:

![State of the stack]({{ "/assets/2018-06-05/stack-draw.png"}} "State of the stack"){:width="70%"}

At this point, you should be able to start guessing the impact of such vulnerability.

Indeed, we have 64 bytes of memory allocated to our buffer, but what happens if we try to write more than 64 bytes?

Any idea? ... It simply **overwrites the values** stored in variables that are located below the buffer on the stack.


### What does it involve?

Overwriting variables in the stack can result in random effects if the attacker doesn't control the impacted variables.

However, if the stack is perfectly controlled, the attack can occur a **program crash** or **provide full-rights on the machine** to the attacker by executing a shellcode.

Buffer overflows only act as **vectors of attack**, they represent a way of gaining access or executing code on the machine but they often don't symbolize the attack in its entirety. Once the access is granted on the machine, the funny things can start...

We will see more advanced exploits based on buffer overflows in future articles, don't worry about that :wink:.


## Detection of the vulnerable code

Alright, this vulnerability seems really powerful but is there a way to prevent it? How do we identify the vulnerable piece of code?

In our case, the vulnerability is simple to exploit because of the lack of user input control. The following part of the code is vulnerable because the developper didn't verify the length of the user input.

```c
gets(buffer);
```

A simple ```man gets``` warns us about the usage of this function and its level of risk.

> Never use gets().  Because it is impossible to tell without knowing the data in advance how many characters gets() will read,  and  because gets()  will continue to store characters past the end of the buffer, it is extremely dangerous to use.  It has been used to break computer security. Use fgets() instead.


Here is what a careful developer should have written:

```c
fgets(buffer,64,stdin);
OR
fgets(buffer, sizeof buffer, stdin);
```
If you were to retain one thing from this article, as a developer, it would be this: **NEVER TRUST USER INPUT**.

## Exploit

Now that we have identified the **vector of attack** and the piece of **vulnerable code**, we can write the exploit!

Our objective is to bypass this "if statement": ```if (numCookies >= 100){```.

In order to do that, we have to set **numCookies** to **100 or greater**.

**Let's get our hands dirty!**

You get it, we have to submit more than 64 characters to the program.


There are 2 methods:

* You can enter the 64 characters manually when the program asks for a number of cookies.
* Or you can **use a scripting language** such as python or perl to do it for you (Highly recommended).

To make sure the value of **numCookies** is overwritten, we can write 80 characters thanks to the following command:

```bash
boiteaklou@csb:~$ perl -e 'print "A"x80' | ./cookiePublic64
Welcome to the Cookie Jar program!

In order to get the flag, you will need to have 100 cookies!

So, how many cookies are there in the cookie jar:
Congrats, you have 1094795585 cookies!
Here's your flag: ----------REDACTED----------
```

It's working! Now, we just have to execute our exploit on the remote server in order to get the flag :blush:.


I hope you now have a clearer idea of what is a buffer overflow. Do not hesitate to leave a comment or to contact me if you have any question or suggestion.



BoiteAKlou :hammer:
