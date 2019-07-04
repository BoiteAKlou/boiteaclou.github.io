---
layout: post
title:  "INS'HACK CTF Writeups"
date:   2019-05-08 09:00:00 +0100
comments: true
author: BoiteAKlou
categories:
- "Writeup"
- "Web"
- "Pwn"
- "Reverse"
- "Programming"
---

![INSHACK logo]({{ "/assets/2019-05-08/inshack-logo.png" | absolute_url }} "INSHACK logo"){:width="40%"}

<!--excerpt-->


## Table of Contents
{:.no_toc}

* TOC
{:toc}


## [Web] Exploring the universe

### Statement

>Will you be able to find the `flag` in the `universe/` ?
>
>I've been told that the guy who wrote this nice application called server.py is a huge fan of nano (yeah... he knows vim is better).
>
>http://exploring-the-universe.ctf.insecurity-insa.fr/

Here is a screen capture of the website in question:

![Exploring the universe]({{ "/assets/2019-05-08/exploringtheuniverse.png" | absolute_url }} "Exploring the universe")

The page was quite empty apart from this funny JS game named "JSLander" where you had to land a rocket by controlling its speed and trajectory. Unfortunately, a successful landing gave no flag.

### Resolution

A huge hint was given by the challenge statement about a file named `server.py` which would be edited by `nano`. After a few guesses, we managed to retrieve the file `.server.py.swp` automatically created by `nano` when the original file is being edited.

server.py:
```python
from pathlib import Path
from mimetypes import guess_type
from aiohttp import web

ROOT = Path().resolve()
print(ROOT)
PUBLIC = ROOT.joinpath('public')

async def stream_file(request, filepath):
    '''Streams a regular file
    '''
    filepath = PUBLIC.joinpath(filepath).resolve()
    if filepath.is_dir():
        return web.Response(headers={'DT': 'DT_DIR'})
    if not filepath.is_file():
        raise web.HTTPNotFound(headers={'DT': 'DT_UNKNOWN'})
    try:
        filepath.relative_to(ROOT)
    except:
        raise web.HTTPForbidden(reason="You can't go beyond the universe...")
    mime, encoding = guess_type(str(filepath))
    headers = {
        'DT': 'DT_REG',
        'Content-Type': mime or 'application/octet-stream',
        'Content-Length': str(filepath.stat().st_size)
    }
    if encoding:
        headers['Content-Encoding'] = encoding
    resp = web.StreamResponse(headers=headers)
    await resp.prepare(request)
    with filepath.open('rb') as resource:
        while True:
            data = resource.read(4096)
            if not data: break
            await resp.write(data)
    return resp

async def handle_403(request):
    '''Stream 403 HTML file
    '''
    return await stream_file(request, '403.html')

async def handle_404(request):
    '''Stream 404 HTML file
    '''
    return await stream_file(request, '404.html')

def create_error_middleware(overrides):
    '''Create an error middleware for aiohttp
    '''
    @web.middleware
    async def error_middleware(request, handler):
        '''Handles specific web exceptions based on overrides
        '''
        try:
            response = await handler(request)
            override = overrides.get(response.status)
            if override:
                return await override(request)
            return response
        except web.HTTPException as ex:
            override = overrides.get(ex.status)
            if override:
                return await override(request)
            raise
    return error_middleware

def setup_error_middlewares(app):
    '''Setup error middleware on given application
    '''
    error_middleware = create_error_middleware({
        403: handle_403,
        404: handle_404
    })
    app.middlewares.append(error_middleware)

async def root(request):
    '''Web server root handler
    '''
    path = request.match_info['path']
    if not path:
        path = 'index.html'
    path = Path(path)
    print(f"client requested: {path}")
    return await stream_file(request, path)

def app():
    app = web.Application()
    setup_error_middlewares(app)
    app.add_routes([web.get(r'/{path:.*}', root)])
    web.run_app(app)

if __name__ == '__main__':
    app()
```

The `stream_file` function is not protected against **directory path traversal** so it allows us to exploit a **Local File Inclusion** vulnerability in order to read the file containing the flag.

Using `../` as a payload, it will be interpreted by our browser which will request the root of the webserver. That's not what we want so we need to **URL-encode** our payload, such as: `..%2f`.

As suggested by the challenge statement, the flag file is stored in the `universe/` folder. We can verify the LFI thanks to the following payload: `..%2funiverse`.

![LFI PoC]({{ "/assets/2019-05-08/universe.png" | absolute_url }} "LFI PoC")

The `DT_DIR` inside the response headers indicates that we are accessing an existing directory. Now, let's retrieve the flag thanks to the following payload: `..%2funiverse%2fflag`.

The flag is inside the downloaded file:

```bash
$ cat _universe_flag
INSA{3e508f6e93fb2b6de561d5277f2a9b26bc79c5f349c467a91dd12769232c1a29}
```


## [Web] Almost Tchap

### Statement
>This is a message to all ATchap employees. Our new communication software is now in a beta mode. To register, just enter you email address, you'll receive shortly the activation code.
>
>https://atchap.ctf.insecurity-insa.fr

This challenge was in the era of time since it exploited [a vulnerabilty](https://medium.com/@fs0c131y/tchap-the-super-not-secure-app-of-the-french-government-84b31517d144) found by [@fs0c131y](https://twitter.com/fs0c131y) a few weeks ago inside the `Tchap` application.

### Resolution

The website offers to register using an email address.

![Almost Tchap]({{ "/assets/2019-05-08/almosttchap.png" | absolute_url }} "Almost Tchap"){:width="80%"}

However, email addresses are filtered and only an address ending with `@almosttchap.fr` would be accepted.

Thanks to the footer of the website, it was easy to guess a valid email address, as you can see on the following picture:

![Real emails]({{ "/assets/2019-05-08/real_mail.png" | absolute_url }} "Real email")

Registering with the address `maud.erateur@almosttchap.fr` was authorized and we could then intercept the request with `Burp` in order to modify the submitted email address.

Actually, forging an email address in the following format will pass the filter and send the confirmation code to our personal address: `personal@mail.fr@maud.erateur@almosttchap.fr`.

For this challenge, I used a temporary email address provided by [https://temp-mail.org/](https://temp-mail.org/). Below, the screen capture of the request interception inside `Burp`:

![Burp]({{ "/assets/2019-05-08/burp.png" | absolute_url }} "Burp")

After forwarding the modified request, the code has been sent to us.

![Flag]({{ "/assets/2019-05-08/at-flag.png" | absolute_url }} "Flag")

`INSA{1fd9fa56444a424d}`

## [Programming] HackCode-01/02

### Statement

>This challenge gives 4 flags of increasing difficulty.
>
>[This file]({{ "/assets/2019-05-08/routes.txt" | absolute_url }} "Routes.txt") contains 10 000 network routes. We want to have at least one network tap on each route. Find a list of routers to intercept, and keep the number of taps low ! You will get the first flag for any solution with at most 150 taps.

#### Example

If we have the following routes :
```
c,b,a
d,a,g
b,c,e
f,d,g
```
One solution could be :
```
g
b
```

The aim of this challenge was to find a minimum set of routers that covers all network routes inside routes.txt.

My strategy was very naive and only allowed me to reach the second flag of this challenge, but still, it was fun to do so I'll share it here. If you want complete writeup of the 4 steps, I recommand you to read [this one](https://www.aperikube.fr/docs/inshack_2019/proggenius/) from Aperikube.

### Strategy

This piece of pseudo-code will help you understanding my approach:

```c
occurences_set = count_occurences_of_each_router()
solution = []
init_routes_coverage() // Tells which routes are already covered by a router

while not all routes are covered {
  foreach line of routes.txt{
    if (line is not already covered) {
        best_router = get_the_best_router_of_the_line(line) // The best in term of number of occurences
        solution.append(best_router)
    }
  }
}
```

### Part 01

I wrote [the following script]({{ "/assets/2019-05-08/script01.py" | absolute_url }} "HackCode 01 script"), implementing the approach explained before, giving a solution of **141 routers**. This was enough for the first flag!

```python
def finished(coverage):
    for i in range(1,10001):
        if not coverage[i]:
            return False
    return True

def solution_covers(solution,line):
    for router in solution:
        if router in line:
            return True
    return False

def get_unique_routers_list():
    routers = []
    lines = open('routes.txt','r').readlines()
    for line in lines:
        splitted = line.strip().split(',')
        for router in splitted:
            if router not in routers:
                routers.append(router)
    #print(routers)
    print(str(len(routers))+" unique routers")
    return routers

def count_router_occurences(routers_list):
    occurences = {}
    f = open('routes.txt','r')
    lines = f.read()
    for router in routers_list:
        occurences[router] = lines.count(router)
    f.close()
    sorted_occurences = [(k, occurences[k]) for k in sorted(occurences, key=occurences.get, reverse=True)]
    return sorted_occurences

def get_best_router_of_line(router_occurences,routers_list):
    best_router = ('router',0)
    for router in routers_list:
        if router_occurences.get(router)>best_router[1]:
            best_router = (router,router_occurences.get(router))
    return best_router



if __name__ == "__main__":
    solution = []
    is_covered = {}

    unique_routers = get_unique_routers_list()
    router_occurences = count_router_occurences(unique_routers)

    #init is_covered
    for i in range(1,10001):
        is_covered[i] = False


    with open('routes.txt','r') as f:
        lines = f.readlines()
        while not finished(is_covered):
            i = 1
            for line in lines:
                splitted = line.strip().split(',')
                if not is_covered[i]:
                    if solution_covers(solution,line):
                        is_covered[i] = True
                    else:
                        best_score_of_line = get_best_router_of_line(dict(router_occurences),splitted)
                        print('Adding '+best_score_of_line[0]+' for line: '+str(i))
                        solution.append(best_score_of_line[0])
                        is_covered[i] = True
                i += 1
    f.close()

    print("Solution size: "+str(len(solution)))
    for router in solution:
        print(router)
```

`The first flag is INSA{N0t_bad_f0r_a_start}. The next flag will be awarded at <= 135.`

### Part 02

The second flag required a solution containing at most 135 routers. In order to get the 4 flags, I had to completely change of strategy but I hadn't so much time left and wanted to work on other challenges so I did something very dirty.

Pre-filling my solution array with certain routers would sometimes give better solutions than my previous script. Guess what, I did that until having a 135 routers solution. Pretty lame I agree...

Here is the modification I brought to script of part 1:

```
BEFORE:
solution = []

AFTER:
solution = ['100284b7','57e483e5','326ceb8a','9793198c','5cc167e0','85ea0d43']
```

And here I am with my 135 routers solution!

`INSA{135_is_pretty_g0Od_but_how_l0w_c4n_u_gO}. Get your next flag at <= 128`

## [Reverse] Dashlame

### Statement

>Can you try our new [password manager]({{ "/assets/2019-05-08/dashlame.pyc" | absolute_url }} "Password manager") ? There's a free flag in every password archive created !
>
>This challenge contains a second part in the Crypto category.


### Uncompyle

As indicated by `file`, the given file is actually some compiled python bytecode.

```bash
$ file dashlame.pyc
dashlame.pyc: python 2.7 byte-compiled
```

Luckily, it is trivial to recover the source code from python bytecode. I used `uncompyle` for this:

```bash
$ uncompyle2 -o dashlame.py dashlame.pyc
$ file dashlame.py
dashlame.py: Python script, ASCII text executable, with very long lines
```

### Understanding the script

The [script]({{ "/assets/2019-05-08/dashlame.py" | absolute_url }} "Password manager") defines the following functions:

```bash
$ grep def dashlame.py
def pad(s):
def unpad(s):
def get_random_passphrase():
def get_pearson_hash(passphrase):
def encrypt_stream(data, passphrase):
def decrypt_stream(data, passphrase):
def encrypt_archive(archive_filename, passphraseA, passphraseB):
def decrypt_archive(archive_filename, passphraseA, passphraseB):
def createArchive():
def updateArchive():
def accessArchive():
```

We see nothing strange for a password manager. Let's dig into the `createArchive()` function since the challenge statement mentions *a flag in every password archive created*.

```python
def createArchive():
    archive_name = raw_input('Please enter your archive name: ')
    passphraseA, passphraseB = get_random_passphrase()
    print 'This is your passphrase :', passphraseA, passphraseB
    print 'Please remember it or you will lose all your passwords.'
    archive_filename = archive_name + '.db'
    with open(archive_filename, 'wb') as db_fd:
        db_fd.write(zlib.decompress('x\x9c\x0b\x0e\xf4\xc9,IUH\xcb/\xcaM,Q0f`a`ddpPP````\x82b\x18`\x04b\x164>!\xc0\xc4\xa0\xfb\x8c\x9b\x17\xa4\x98y.\x03\x10\x8d\x82Q0\n\x88\x05\x89\x8c\xec\xe2\xf2\xf2\x8c\x8d\x82%\x89I9\xa9\x01\x89\xc5\xc5\xe5\xf9E)\xc5p\x06\x93s\x90\xabc\x88\xabB\x88\xa3\x93\x8f\xab\x02\\X\xa3<5\xa9\x18\x94\xabC\\#Bt\x14J\x8bS\x8b\xf2\x12sa\xdc\x02\xa820W\x13\x927\xcf0\x00\xd1(\x18\x05\xa3`\x08\x03#F\x16mYkh\xe6\x8fO\xadH\xcc-\xc8I\x85\xe5~O\xbf`\xc7\xea\x90\xcc\xe2\xf8\xa4\xd0\x92\xf8\xc4\xf8`\xe7"\x93\x92\xe4\x8cZ\x00\xa8&=\x8f'))
    encrypt_archive(archive_filename, passphraseA, passphraseB)
    print 'Archive created successfully.'
```

We can see the content of the password archive stored unencrypted inside the script.

### Resolution

Since the archive content is written in zlib-compressed plaintext inside the script, we can simply decompress it and print the output in order to get the content of the password archive.

```python
$ python
Python 2.7.15+ (default, Nov 28 2018, 16:27:22)
[GCC 8.2.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.                                                                 
>>> import zlib
>>> print zlib.decompress('x\x9c\x0b\x0e\xf4\xc9,IUH\xcb/\xcaM,Q0f`a`ddpPP````\x82b\x18`\x04b\x164>!\xc0\xc4\xa0\xfb\x8c\x9b\x17\xa4\x98y.\x03\x10\x8d\x82Q0\n\x88\x05\x89\x8c\xec\xe2\xf2\xf2\x8c\x8d\x82%\x89I9\xa9\x01\x89\xc5\xc5\xe5\xf9E)\xc5p\x06\x93s\x90\xabc\x88\xabB\x88\xa3\x93\x8f\xab\x02\\X\xa3<5\xa9\x18\x94\xabC\\#Bt\x14J\x8bS\x8b\xf2\x12sa\xdc\x02\xa820W\x13\x927\xcf0\x00\xd1(\x18\x05\xa3`\x08\x03#F\x16mYkh\xe6\x8fO\xadH\xcc-\xc8I\x85\xe5~O\xbf`\xc7\xea\x90\xcc\xe2\xf8\xa4\xd0\x92\xf8\xc4\xf8`\xe7"\x93\x92\xe4\x8cZ\x00\xa8&=\x8f')
SQLite format 3@  -
2+;website_exampleusernameINSA{Tis_bUt_a_SCr4tch}bsite TEXT, username TEXT, password TEXT)
```

Flag: **INSA{Tis_bUt_a_SCr4tch}**.

### Alternative way using decrypt_archive()

While listing the script functions, we could see a **decrypt_archive()** function. However, this function was not available from the user interface of the program.

```bash
$ python dashlame.py
      /.m.\
     /.mnnm.\                                              ___
    |.mmnvvnm.\.                                     .,,,/`mmm.\
    |.mmnnvvnm.\:;,.                           ..,,;;;/.mmnnnmm.\
    \ mmnnnvvnm.\::;;,                    .,;;;;;;;;/.mmmnnvvnnm.|
     \`mmnnnvvnm.\::;::.sSSs      sSSs ,;;;;;;;;;;/.mmmnnvvvnnmm'/
       \`mmnnnvnm.\:::::SSSS,,,,,,SSSS:::::::;;;/.mmmnnvvvnnmmm'/
          \`mnvvnm.\::%%%;;;;;;;;;;;%%%%:::::;/.mnnvvvvnnmmmmm'/
             \`mmmm.%%;;;;;%%%%%%%%%%%%%%%::/.mnnvvvnnmmmmm'/ '
                \`%%;;;;%%%%s&&&&&&&&&s%%%%mmmnnnmmmmmm'/ '
     |           `%;;;%%%%s&&.%%%%%%.%&&%mmmmmmmmmm'/ '
\    |    /       %;;%%%%&&.%;`    '%.&&%%%////// '
  \  |  /         %%%%%%s&.%%   x   %.&&%%%%%//%
    \  .:::::.  ,;%%%%s&&&&.%;     ;.&&%%%%%%%%/,
-!!!- ::#:::::%%%%%%s&&&&&&&&&&&&&&&&&%%%%%%%%%%%
    / :##:::::&&&&&&&&&&&&&&&&&&&&&%%%%%%%%%%%%%%,
  /  | `:#:::&&&&&&&&&&&&&&&&&&&&&&&&%%%%%%%%%%%%%
     |       `&&&&&&&&&,&&&&&&&&&&&&SS%%%%%%%%%%%%%
               `~~~~~'~~        SSSSSSS%%%%%%%%%%%%%
                               SSSSSSSS%%%%%%%%%%%%%%
                              SSSSSSSSSS%%%%%%%%%%%%%.
                            SSSSSSSSSSSS%%%%%%%%%%%%%%
                          SSSSSSSSSSSSS%%%%%%%%%%%%%%%.
                        SSSSSSSSSSSSSSS%%%%%%%%%%%%%%%%
                      SSSSSSSSSSSSSSSS%%%%%%%%%%%%%%%%%.
                    SSSSSSSSSSSSSSSSS%%%%%%%%%%%%%%%%%%%
                  SSSSSSSSSSSSSSSSSS%%%%%%%%%%%%%%%%%%%%.

                          WELCOME TO DASHLAME

1. Create a new password archive
2. Add a password to an archive
3. Access a password from an existing archive
```

An alternative way of decrypting an archive would be to:
1. Create a password archive.
2. Note passphraseA and passphraseB.
3. Modify the script in order to call decrypt_archive(archive,passphraseA,passphraseB).

```bash
                      WELCOME TO DASHLAME

1. Create a new password archive
2. Add a password to an archive
3. Access a password from an existing archive
1
Please enter your archive name: boiteaklou
Getting random data from atmospheric noise and mouse movements..........                                                               
This is your passphrase : pruden patties
Please remember it or you will lose all your passwords.
Archive created successfully.
```

Here is the slight modification I brought to the *main* function of the script:

```python
if __name__ == '__main__':
    print HEADER
    print '1. Create a new password archive'
    print '2. Add a password to an archive'
    print '3. Access a password from an existing archive'
    try:
        res = raw_input()
        if res == '1':
            createArchive()
        elif res == '2':
            updateArchive()
        elif res == '3':
            accessArchive()
        elif res == '4':
            decrypt_archive('boiteaklou.dla','pruden','patties') # HERE
        else:
            print 'Wrong choice'
    except:
        print 'Error.'
```

Now, the password archive should be decrypted:

```bash
$ strings boiteaklou.db
SQLite format 3
tablePasswordsPasswords
CREATE TABLE Passwords(website TEXT, username TEXT, password TEXT)
;website_exampleusernameINSA{Tis_bUt_a_SCr4tch}
```

## [Pwn] Intergover

### Statement

>I hope you know how integers are stored.
>
>`ssh -i <your_keyfile> -p 2223 user@intergover.ctf.insecurity-insa.fr`
>To find your keyfile, look into your profile on this website.
>
>[Binary]({{ "/assets/2019-05-08/intergover" | absolute_url }} "intergover")
>
>[https://www.youtube.com/watch?v=_BgblvF90UE](https://www.youtube.com/watch?v=_BgblvF90UE)


### Spotting the vulnerabilty

Let's see what we can get from this binary.

```bash
$ file intergover
intergover: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8a1089cd9d189ee37904eaf6edfb3ce59652a881, not stripped
```

Ok, it's a 64-bit executable, not stripped. We can quickly reverse-engineer the binary in order to get a fine understanding of its behavior.

Here is the pseudo-code generated by IDA Pro:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+1Bh] [rbp-15h]
  int v5; // [rsp+1Ch] [rbp-14h]
  int i; // [rsp+20h] [rbp-10h]
  int v7; // [rsp+24h] [rbp-Ch]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  printf("Give me one param: ", argv, envp, argv);
  fflush(0LL);
  v7 = __isoc99_scanf("%d", &v5);
  if ( v7 != 1 )
  {
    puts("I expect a number.");
    fflush(0LL);
  }
  v4 = 0;
  for ( i = 0; i < v5; ++i )
    ++v4;
  if ( v4 == -14 )
  {
    gimmeFlagPliz();
  }
  else
  {
    printf("No, I can't give you the flag: %d\n", (unsigned int)v4);
    fflush(0LL);
  }
  return 0;
}
```

We can see that our input is stored in an unsigned 64-bit int (v5). As indicated by the file **limits.h**, this type of variable can hold values between 0 and 4,294,967,295.
Then, a signed 64-bit int is incremented until reaching the value we submitted. 64-bit signed integers can hold value between −2,147,483,648 and +2,147,483,647.

The for loop forces us to submit a positive integer, at least when this one is unsigned.

Let me explain. The following byte: *1111 1111* will be seen as **255 in the unsigned world** and as **-1 in the signed world**.
So if we submit 2147483647, the program should return -1 because 2147483647 (unsigned) == 1111111111111111111111111111111 (binary) == -1 (signed).

Let's verify this:
```bash
$ ./intergover
Give me one param: 2147483647
No, I can't give you the flag: -1
```

Great! The pseudo-code taught us that **v4** had to be equal to **-14** in order to call **gimmeFlagPliz()**, so all we have to do is to submit (2147483647-13) == **2147483634** and to grab the flag!

```bash
$ ssh -i ssh_inshack -p 2223 user@intergover.ctf.insecurity-insa.fr
Warning: Permanently added the ECDSA host key for IP address '[XX.XX.XX.XXX]:2223' to the list of known hosts.
 ___           _   _            _      ____   ___  _  ___
|_ _|_ __  ___| | | | __ _  ___| | __ |___ \ / _ \/ |/ _ \
| || '_ \/ __| |_| |/ _` |/ __| |/ /   __) | | | | | (_) |
| || | | \__ \  _  | (_| | (__|   <   / __/| |_| | |\__, |
|___|_| |_|___/_| |_|\__,_|\___|_|\_\ |_____|\___/|_|  /_/

===========================================================

      You are accessing a sandbox challenge over SSH
        This sandbox will be killed soon enough.
       Please wait while we launch your sandbox...

===========================================================

Give me one param: 2147483634
INSA{B3_v3rY_c4r3fUL_w1tH_uR_1nt3g3r_bR0}
Connection to intergover.ctf.insecurity-insa.fr closed.
```

## [Pwn] Signed or unsigned

### Statement

>Signed or not signed, this is the question :)
>[Binary]({{ "/assets/2019-05-08/signed_or_not_signed" | absolute_url }} "signed or not signed")
>
>`ssh -i <your_keyfile> -p 2228 user@signed-or-not-signed.ctf.insecurity-insa.fr`
>To find your keyfile, look into your profile on this website.
>
>[https://www.youtube.com/watch?v=inXC_lab-34](https://www.youtube.com/watch?v=inXC_lab-34)

### Spotting the vulnerability

As this challenge is in the same vein as the previous one, I'll go straight to the solution.

We have a 64-bit ELF which can be translated in the following pseudo-code:

![Pseudo code]({{ "/assets/2019-05-08/code48.png" | absolute_url }} "code signed or not signed")

If the user input is inferior to 10, we call the **vuln()** function.

![Vuln]({{ "/assets/2019-05-08/vuln.png" | absolute_url }} "Vuln")

The user input is stored in a signed integer so we can submit **-666** directly and get the flag.

```bash
$ ssh -i ssh_inshack -p 2228 user@signed-or-not-signed.ctf.insecurity-insa.fr

 ___           _   _            _      ____   ___  _  ___
|_ _|_ __  ___| | | | __ _  ___| | __ |___ \ / _ \/ |/ _ \
| || '_ \/ __| |_| |/ _` |/ __| |/ /   __) | | | | | (_) |
| || | | \__ \  _  | (_| | (__|   <   / __/| |_| | |\__, |
|___|_| |_|___/_| |_|\__,_|\___|_|\_\ |_____|\___/|_|  /_/

===========================================================

      You are accessing a sandbox challenge over SSH
        This sandbox will be killed soon enough.
       Please wait while we launch your sandbox...

===========================================================
Please give me a number:-666
INSA{Th3_qU3sTi0n_1s_S1gN3d_0r_x90}
Connection to signed-or-not-signed.ctf.insecurity-insa.fr closed.
```

Not too much difficulty in this one but well it's still a flag :)

<p id="signature">BoiteAKlou :hammer:</p> 
