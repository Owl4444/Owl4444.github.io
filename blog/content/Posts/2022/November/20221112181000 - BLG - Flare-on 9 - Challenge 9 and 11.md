---
ID: 20221112181000
tags:
  - Blogging
  - Writeup
  - Cryptography
Created: 2022-11-12 18:10:00
Last Modified: 2022-11-12 18:10:00
date: 2022/11/12
---

![[Pasted image 20241111170440.png]]
## Introduction
Flare-on 9 has officially been declared over!

![[Pasted image 20241111170512.png]]

This year of flare-on is the third try and the first that I have ever completed so far! Definitely did have my share of pain and joy during this time of challenges. For this post, I will share my writeup on challenge 9 and 11.
## **Challenge 9 - Encryptor**

This challenge took me quite a bit of time to realise what algorithms were used. The two main algorithms that we have to familiarize ourselves with are RSA and ChaCha20. ChaCha20’s key was used to encrypt files in the specified directory for files extension `.EncryptMe`. However, it is a common practice as well to encrypt the key with asymmetric encryption. In this case it was using RSA to do so. 

Here is the high level view of the main function with some reversing and renaming.


![[Pasted image 20241111170520.png]]

### **RSA initialization**

The reason that there were much trouble in figuring out that this is RSA is due to the fact that c/c++ does not handle very huge numbers. Therefore, it makes sense to have functions that can deal with them. Since RSA is more secure with very very large random prime numbers, this code section would looked a little more cryptic than the formula we would see online.

Here is the renamed `init_RSA_sub_4021d0` which is responsible for the initialization of RSA needed for asymmetric encryption. 

![[Pasted image 20241111170525.png]]

In `init_RSA_sub_4021d0`, RSA key values including:
-       `p`
-       `q`
-       `N` -> `p*q` 
-       phi(N) ->  `(p-1)*(q-1)` 
-       Decryption Key ->  `d` 
-       Exponent `e` -> 0x10001

### **EncryptFunction**

Next, in the Encrypt function that I labeled in main function, we can see that chacha20 was used to encrypt the content of the sample buffer before the key is being encrypted with RSA.

![[Pasted image 20241111170531.png]]

### **Solution**

To solve this, we have to understand how RSA encryption algorithm works. To encrypt : 

```python
# Encryption
cipher = (msg ^ exponent) % N

# Decryption
msg = (cipher ^ decrypt_key) % N
```

Additionally, in the ransom note given, we are given some hardcoded values, the N value, the encrypted content and the encrypted chacha20 key. However, during the encryption of the file content, the encryption was calculated mistakenly.

```python
cipher = (msg ^ decrypt_key) % N
```

Instead of encryption, this has just turned into a “verification” where you encrypt the content with the decrypt key rather than the exponent to “prove” that you are the legitimate. But since this was done this way and that the exponent is hardcoded to 0x10001, we can decrypt with the following:
```python
Chacha20_key = (enc_chacha20_key ^ exponent) % N
```

This works mainly because of the condition in RSA since the computation of exponent according to https://www.di-mgt.com.au/rsa_theory.html states that ` ed≡1(modϕ(n))` .
This means that with the mistaken encryption
```python
cipher = (msg ^ decrypt_key) % N
```
Therefore, to get back `msg`, we need to xor the cipher with the hardcoded exponent
```python
Cipher ^ exponent = (msg ^ decrypt_key ^ exponent) % N
Cipher ^ exponent = (msg ^ 1(modϕ(n))) % N
(Cipher ^ exponent) % N = (msg ^ 1(modϕ(n))) % N
(Cipher ^ exponent) % N = msg
```

Now to obtain the chacha20 keystream, we can make use of the given values from the ransom note.

![[Pasted image 20241111170603.png]]

The keystream shown in the above image should be read as little endian.

Now that we get the decrypted keystream, we can start the actual decryption of the ` SuspiciousFile.txt.Encrypted` file. 
What I did to decrypt the encrypted file was to manually insert the bytes of the initial state of ChaCha20 cipher. 

![[Pasted image 20241111170609.png]]

During the actual solve, I have done this dynamically by replacing the data after the `expand 32-byte k` string. However, we can solve it in a script as well since the decrypted state contains both the key and the nonce.

![[Pasted image 20241111170614.png]]

Running this should give us the flag : 

> [!note] Challenge 9 Flag 
>  `R$A_$16n1n6_15_0pp0$17e_0f_3ncryp710n@flare-on.com`

### *Troubles Faced*

One of the troubles I faced was confusing Salsa20 with ChaCha20 since this was the first time hearing about these. After googling the `expand 32-byte k` keyword, Salsa20 was the first algorithm I saw.

![[Pasted image 20241111170636.png]]

However, after some time, I noticed that during the hashing, the rotate values were not the same as the source implementation of salsa20. Therefore, it has to be ChaCha20 and they did match as seen in the following image.

![[Pasted image 20241111170640.png]]

As for RSA functions, it took some actual trial and errors to confirm them since I was only familiar with the simpler implementation of RSA and not considering generation of prime numbers and more.

At the end of the challenge, though the logic is pretty easy to understand, I think that the thing about this is to be able to have some intuition about relevant functions.

---

## Challenge 11 - The challenge that shall not be named

This challenge took me a pretty long time due to quite a number of rabbit holes. Even so, I think that what I did was not the intended solution, that is by memory inspection to look for the flag which should also make sense once I explain things. 

This challenge binary is actually a PE32+ that was compiled via PyInstaller. Upon extraction with `pyinstxtractor`, we can guess that `11.pyc` is the main function for the executable. Using decompyle3, we can see that the decompiled shows that the main function was compiled with pyarmor in strong mode (the value 2 after the encrypted byte codes).

![[Pasted image 20241111170645.png]]

To run the main function, I have compiled python3.7.exe ( more about this later ) and placed it in the `PYZ-00.pyz_extracted` directory as the extracted data so that we can run python in it and that many of the modules are contained in the same directory. Running 11.pyc with python outside `PYZ-00.pyz_extracted` would give an error if run outside of this directory indicating that the module `_crypt` is not found.

If you want to see the solution straight without going through what I have failed, then feel free to jump straight to the solution segment.

### **The Different Attempts**

At this point, I have tried quite a number of methods to attempt to get the bytecode. 

#### **Dumping Python serialized Code Object**

First thing I have tried was to look at `_PyEval_EvalFrameDefault` function in python 3.7 source. This is because pyarmor would decrypt the bytecode so that this function could run it before encrypting it back. I have also attempted to dump the bytecodes that were my separately compiled python executable ( the reason why I compiled Python 3.7)

![[Pasted image 20241111170651.png]]

In this added code, `PyMarsahl_WriteObjectToFile` function is used to serialize python object. The ones that we are interested are the ones that are the `PyCodeObject` or Code Objects as seen in http://www.goldsborough.me/python/low-level/2016/10/04/00-31-30-disassembling_python_bytecode/. However, after extracting all the bytecodes from both going on in 11.pyc in x64Dbg and the stored `code_object` text file, we see that the pyarmor code object was returned and I was not able to step into it just like that. 

![[Pasted image 20241111170656.png]]

Furthermore, I read that pyarmor has their own implementation of PyEval which suggest that this method would not work or is just not marshallable back to its original code.

#### **API Monitor**

It gave a really good overview (though not complete) about what the program was doing.

![[Pasted image 20241111170659.png]]

We first see that there is an attempt to resolve for `www.evil.flare-on.com`. After that, I have setup a server with resolvable IP address. 

Since, I did not know what the server actually does, i thought we have to interact with the server somehow and to do that, I have tried to create a server that can send bytes back assuming it is some form of a server.

![[Pasted image 20241111170702.png]]

With the server setup as follows and editing the Windows Host file, we receive the base64 encrypted flag via post request.

![[Pasted image 20241111170708.png]]

However, api monitor did not have any other information about this. But it did give us some important information about the program.

#### **Patching pytransform.pyd**

I was thinking of patching `pytransform.pyd` mainly because this is mostly responsible for the obfuscation and restriction of pyarmor code. While I think this is possible, I did not manage to successfully do this before getting the flag.  The restriction comes mainly from trying to edit pyarmor code.


### **Solution - challenge 11**

Firstly, I have decompiled both 11.pyc and crypt.pyc (after noticing that it was pyarmor’d) into 11.py and crypt.py

Next, I configured the environment so that it would run with the python.exe from the pyz_extracted folder. I have also used the following configuration in Visual Studio Code to allow stepping in of functions by setting `justMyCode`.

![[Pasted image 20241111170714.png]]

After some things were done, the “encrypted” flag was passed into base64 function.

![[Pasted image 20241111170717.png]]

After which requests.post function was used to send a POST request with the encrypted flag.

![[Pasted image 20241111170720.png]]

Once that is over, there no more operations done. Therefore, I made a guess that the flag generation has to be somewhere before the base64 operation. That said, I tried to do a memory dump to see if we can find the flag anywhere on the heap in WinDbg. Turns out after attaching to the python process, and searching in the heap with the following commands, it is possible to find the full flag within the memory space.
Commands used were `!heap -a` and `s -a <start address> <end address> “@flare-on.com”` which shows positive traces of the flag and eventually, we can dump the flag out.


![[Pasted image 20241111170724.png]]


> [!note] Challenge 11 Flag
> Pyth0n_Prot3ction_tuRn3d_Up_t0_11@flare-on.com

---

## Conclusion

NGL, but after this challenge, I have invested quite a fair bit of time (24 days) to solving these challenges. I have definitely see some improvements that I have made over the past two to three years and am absolutely delighted with my progress. I would also like to thank the FLARE team for creating challenges like these. Not only is it fun, I did learn quite a lot also especially during challenge 8, including learning C# programming and scripting.

---