---
layout: post
title:  "Upgrading to a fully interactive reverse shell"
date:   2018-12-27 10:00:00 +0100
comments: true
author: BoiteAKlou
categories:
- "Article"
- "Pentest"
---

Let's say you're in the middle of a hacking challenge or pentesting assessment and you finally manage to get a **reverse shell** on your target. This short article will explain you how to obtain <span style="color:Green">a fully interactive version of your reverse shell</span>, that will allow commands like `su`, `vi`, `nano`, `ssh`, etc... but also **CTRL+C** and **tab completion**.
 <!--excerpt-->

## Table of Contents
{:.no_toc}

* TOC
{:toc}


## Spawning a PTY

It doesn't matter which way you got your initial reverse shell, it should approximately look like this:

```bash
boiteaklou@LAB-Blog:~$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 40610
id
uid=1001(www-data) gid=1001(www-data) groups=1001(www-data)
```

A lot of Unix commands require to be executed from a terminal. But, the classical netcat reverse shell you obtain at first has no TTY associated. If you wish to know a bit more about the internal working of TTYs, I recommend you this great article [The TTY demystified](http://www.linusakesson.net/programming/tty/) from Linus Akesson.

In order to overcome this difficulty, we will use **python PTY module** and especially the **spawn** function:
> **pty.spawn**(argv[, master_read[, stdin_read]])
>
>    Spawn a process, and connect its controlling terminal with the current process’s standard io. This is often used to >baffle programs which insist on reading from the controlling terminal.

Python is one of the best option because it is almost always installed on the target machine. If by any chance it's not the case, you can still try python3.

The command to execute is the following:

```bash
$ python -c 'import pty; pty.spawn("/bin/bash");'
```

It should give the following output:

```bash
python -c 'import pty; pty.spawn("/bin/bash");'
www-data@TARGET:~$
```

Now you can use commands that require to be executed from a terminal.

## Resizing and tab completion

If by mistake, you run an endless command and hit **CTRL+C**, your reverse shell will disappear as well as your *joie de vivre*.
Also, you could see the output of the `ps` command truncated because the size of the reverse shell on the remote machine doesn't suit the size of your host terminal.

These two issues can be solved following this procedure:

* Background your reverse shell with **CTRL+Z**.
* Print the size of your host terminal: `stty -a |cut -d';' -f2-3 | head -n1`.
* Transfer local hotkeys to the remote shell: `stty raw -echo`.

> If you're using zsh or another custom shell different from bash, this command may not work properly.

* Bring the reverse shell back to foreground: `fg`. You may need to hit **ENTER** after this command.
* Inside the remote shell, adjust the size: `stty rows <ROWS> cols <COLS>`.

You should now have an interactive reverse shell with **tab completion**, **signals handling**, **no truncated outputs**.

## Adding some color

Now the icing on the cake, let's add some color!

Simply echo the value of $TERM environment variable in your local terminal and set it to the same value in the remote shell:
```bash
boiteaklou@LAB-Blog:~$ echo $TERM
xterm-256color

www-data@TARGET:~$ export TERM=xterm-256color
```

You need to `reset` the shell in order for the changes to take place.

You should now feel at home inside your reverse shell! :smile:


<p id="signature">BoiteAKlou :hammer:</p>
