---
layout: post
title:  "A very fine cipher: Warmup - AngstromCTF"
date:   2018-06-24 23:00:00 +0200
comments: true
mathjax: true
author: BoiteAKlou
categories:
- "Writeup"
- "Crypto"
---
Here comes the first Cryptographic challenge! We'll start with an easy one but nonetheless useful. We will establish the mathematical foundations needed for understanding more complicated codes such as RSA...
 <!--excerpt-->

# Table of Contents
{:.no_toc}

* TOC
{:toc}

## Challenge description

The challenge statement is very explicit:

>Just a quick warm-up cipher for everyone. Honestly, I think it's **a fine** cipher.

>**myjd{ij_fkwizq}**

The sentence in bold has to be decoded in order to get the flag and to validate the challenge.

If you're already familiar with affine cipher or just want to read the challenge's write-up, you can jump straight to the *Breaking the code* section.

## Information gathering

The information gathering part of the analysis is probably the most important as it can be really time-saving. That's why we'll try to gather as much information as possible.

The first thing that jumps out is the format of the ciphered text. Each CTF contest has its own flag format so participants know when they have solved the challenge.
In the context of AngstromCTF, each flag respects the following convention: **actf{...}**, which is suspiciously close to our ciphered text.

Cryptanalysis can be greatly simplified when the plain text language is known. Since AngstromCTF is an international event, the language used is probably english.

The most useful information turns out to be the discrete hint given in the challenge description. Indeed, "a fine" is in bold for a reason. It's actually a wordplay with **affine cipher**... These funny organizers decided to save us a lot of time!

## Affine cipher

The affine cipher is a type of **monoalphabetic substitution cipher** based on a simple mathematical function. It has only been used for its educational purposes due to its weaknesses. We'll study the functionning of this cipher and how to break it in order to decode our mistery sentence.

### Monoalphabetic substitution cipher

A **substitution cipher** is a method of encrypting which replaces each letter of the plain text by a letter of the ciphered text. In most of the case, the replacement unit is a single letter but it could also be a group of three letters. The **plain text** and the **ciphered** one will have **the exact same length** when using a substitution cipher.

**Monoalphabetic** means that the same alphabet is used for encrypting the whole message. On the contrary, **Polyalphabetic** substitution ciphers will use multiple alphabets for encrypting the same message. They are generally much **stronger** than **Monoalphabetic ciphers** because each letter of the plaintext is usually mapped to multiple different letters in the ciphered text.

### Encryption

* The first step of the encryption process consists in assigning an integer in the range 0 to \\(m-1\\) to each letter, where **m is the size of the alphabet** (usually 26).

|a|b|c|d|e|f|g|h|...|w|x|y|z|
|0|1|2|3|4|5|6|7|...|22|23|24|25|

* Then we have to define a pair of integers \\(\(a,b\)\\) which will represent **the key**. In order to be able to decipher the message, **a must be coprime with m**. If it's not the case, the same integer will be associated with more than one letter in our table.
This gives the following list of possibilities for \\(a\\): 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25.

For the example, we will choose the couple \\(\(a = 5, b = 8\)\\) as the key.

* Now that each letter is associated with an integer and that we have defined the key, we are ready to encrypt the message. In order to do this, we simply have to apply the mathematical formula that defines the affine cipher, with \\(x\\) being the **integer associated with the letter** we want to encrypt:

$$E(x) = (ax + b)\mod{m}$$


To give you an example, let's say we want to encrypt the following sentence using the key defined above:

CRYPTOISLOVE

We will get the integers associated with each letter as the following:

|C|R|Y|P|T|O|I|S|L|O|V|E|
|2|17|24|15|19|14|8|18|11|14|21|4|

Then, we will apply the encryption function for each letter resulting in the following:

|2|17|24|15|19|14|8|18|11|14|21|4|
|18|15|24|5|25|0|22|20|11|0|9|2|

>Detail of the first column:
$$
\begin{eqnarray}
E(2) &=& 2\times 5 + 8\mod{26}\\
E(2) &=& 18
\end{eqnarray}
$$

And convert back the obtained integers into letters to get the ciphered message:

|18|15|24|5|25|0|22|20|11|0|9|2|
|S|P|Y|F|Z|A|W|U|L|A|J|C|

The encryption is done!

>*NOTE: We can notice that some popular shift ciphers such as **Caesar cipher** or **ROT13** are basically affine ciphers with the **a coefficient set to 1** and the **b coefficient representing the shift**. We can describe these ciphers as affine ciphers using the following keys: **Caesar(1,3)** & **ROT13(1,13)**.*

### Decryption

* The first step of the decryption process consists in replacing each letter of the ciphered text with the corresponding integer.

|S|P|Y|F|Z|A|W|U|L|A|J|C|
|18|15|24|5|25|0|22|20|11|0|9|2|

* Then we have to find the **modular multiplicative inverse** of \\(a\\). There are different ways to do it which won't be detailed here. If you're interested in knowing how to compute it, you should have a look at [Extended Euclidean algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm) and [Euler's theorem](https://en.wikipedia.org/wiki/Euler%27s_theorem).

In our previous example, the **modular multiplicative inverse** of \\(a\\) is 21. We will call it \\(a'\\).

* Now can apply the following decryption function to each integer of the table and convert the result back into letter to get the deciphered message.

$$D(x) = a'(x-b)\mod{m}$$

|18|15|24|5|25|0|22|20|11|0|9|2|
|2|17|24|15|19|14|8|18|11|14|21|4|

After converting the integers back into letters we will recover the original plain text.

## Breaking the code

Now that we have a clearer idea of the mechanisms involved by affine cipher, we can eventually spot the weaknesses. In order to decode the ciphered sentence, we have to either find the key or find another way to recover the plain text.

### Kerckhoffs' Principle

Kerckhoffs' Principle is a basic design principle of modern cryptography formulated by Auguste Kerckhoffs in 1883.

It goes as follows:
>A cryptographic system should be secure even if everything about the system, except the key, is public knowledge.

The affine cipher often uses an alphabet of 26 letters including 12 numbers which are coprime with 26. This gives us a total of \\(12 \times 26 = 312\\) possible keys.

This is something we can easily bruteforce so this cipher is considered as highly insecure in the light of Kerckhoffs' Principle.

### Frequency Analysis

Frequency Analysis is a very popular method of cryptanalysis. It consists in studying the frequency of letters in a ciphertext.
For example, if the most occurent letter in a ciphered text is "Z", you can suppose that "Z" replaces the most common letter of the source language (which is "E" in the English language).

Every monoalphabetic substitution cipher is vulnerable to this method of cryptanalysis. However, it requires a long ciphered text for the frequency analysis to be relevant. In the context of this challenge, we only have a single sentence, which is clearly not sufficient. Let's save this method for another challenge... :wink:

### Not even funny

We said earlier that the key was easily crackable thanks to a fine **bruteforce algorithm**. This is the dumb but efficient way to achieve the challenge.
Feel free to write a small **script** which will **test the 312 possible keys** and decode the message. It's always good to practice our scripting skills.

However, this may not be necessary to write a script for solving this challenge, as we will see in the next part.

### Smart way - Known plain attack

This is where the *information gathering* part becomes interesting. We've noticed the suspiceous beginning of the ciphered text which is very close to the flag format of this CTF.

It is quite likely that **actf{...}** becomes **myjd{...}** when encrypted. If we find the key that gives such ciphered text, we will be able to decrypt the rest of the flag.

This is called a **known plain attack**. We know a part of the plain text and it's corresponding ciphered text. From that, we can guess the key and decode the whole message. This type of attack is not always possible but it works perfectly in our case.

#### Demonstration

Once again, we assign an integer to each letter of the plain and the ciphered text:

|a|c|t|f|
|0|2|19|5|

|m|y|j|d|
|12|24|9|3|

According to our hypothesis that the beginning of the ciphered text corresponds to **actf{**, we have:

$$
\begin{eqnarray}
	E(0) &=& 12\\
	E(2) &=& 24\\
	E(19) &=& 9\\
	E(5) &=& 3\\
\end{eqnarray}
$$

The first equation means that when we encrypt the letter number 0, it gives the letter number 12.
We won't need more than the first two equations in order to find the key.

This gives the following system:

$$
\left\{
\begin{array}{r c l}
0a + b &\equiv& \boxed{12}\mod{26}\\
2a + b &\equiv& 24\mod{26}\\
\end{array}
\right.
$$

$$
\begin{array}{r c l}
\Leftrightarrow 2a &\equiv& 12\mod{26}\\
\Leftrightarrow 2a &\equiv& 38\mod{26}\\
\Leftrightarrow a &\equiv& \boxed{19}\mod{26}\\
\end{array}
$$

Here is the key!

$$
key (19,12)
$$

#### Decryption

Using the key and the previously explained process of decryption, we are able to recover the plain text, which was indeed a magnificent flag!

**actf{it_begins}**

That's it for this challenge but don't worry, it was only the warm-up! :blush: Do not hesitate to leave a comment or to contact me for any question or inquiry.

<p id="signature">BoiteAKlou :hammer:</p>
