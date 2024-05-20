---
layout: post
title: A quick Look at a Dropper and Downloader
description: Just a random quick analysis of a recent sample that was uploaded on VirusTotal. The first ever in this blog at least ...
date: 2023-03-11 17:54:00 +0800
image:  '/images/flash_analysis_1/326d26f624af4b02bae8b528cdce9752.png'
tags:   [QuickPeek,MalwareAnalysis]
---

# Quick Malware Analysis 

## Sample 

As of 11 March 2023, I have tried the following search in VirusTotal
![bb183d4fe39440a8a01cfff28f8520dc.png](/images/flash_analysis_1/bb183d4fe39440a8a01cfff28f8520dc.png)

### Hash:

<div class="table-container">
  <table> 
    <tr><th>Name : </th><th>dttcodexgigas.fe8ce2ec2b71cc3ddceb1ddee6ee7cdcf311bfc3.exe</th></tr>
    <tr><th> Hash : </th><th>7703278ce4c812de42c720928689b5cd5976270057dcfb512c9905d1ae7307d3</th></tr>
  </table>
</div>

<br/>

![7db4dd9bfc334a69a35c545c79f6e607.png](/images/flash_analysis_1/7db4dd9bfc334a69a35c545c79f6e607.png)

## Static Analysis

### FLOSS
Firstly, from Flare's Floss program it shows some interesting strings that might give an insight to what this malware might be doing.

It seems to indicate some things:
1. Persistence via the Run key
2. Commands are run within this binary via `ShellExecuteExA` from `Shell32.dll`
3. Internet Requests are made since headers are found  
```
Accept: */*
0x06065 Content-Type: application/x-www-form-urlencoded
0x06096 Accept-Language: zh-cn
0x060ae Connection: Keep-Alive
0x060c8 Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; CIBA; .NET CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022)
```
4. Language Accepted : Chinese
5. MAC address may be collected due to `%s?mac=%02X-%02X-%02X-%02X-%02X-%02X`
6. `pomdfghrt` which is actually the mutex name.
7. `a.exe` string may be obfuscated for some reason since this value is found in the stack string after analysis by FLOSS.
8. It looks like some usersname were targetted including :
	1. Steve
	2. George
	3. r.vult
	4. Joe Cage
	5. Azure
	6. Linky
	7. Maxine
9. It seems like it contains hashes for other malware with the same name `microsofthelp.exe` which sounds like another variant
	1. `microsofthelp.exe` - https://www.virustotal.com/gui/file/55426c9354510bb58c019a650dad82cb7b98defab142216ddc304656b95ff227/details
	2. `9b5e3f2ea0756b11df0cef72d7d9d2ac.virus` - https://www.virustotal.com/gui/file/9c79a9fb8823c0cc3a7bfd5b64d16ab500d4149710d00cf8a9ed0482328c2e9d/details
```
0x13680 C:\b54f9e2c8cef73c8aa7d0f460440473750131b7d204d3c01462aa8c0cb72e1c6
0x13784 C:\99c053e614af4cea25d1d767f81808b3addb07e356392383c6e4cb706bb98736
0x13888 C:\18becc5102637cdfdfd664cc0c4fee3033a146ba8d86dbf1c36c4b84f3b380d3
0x1398c C:\Users\maxine\AppData\Local\Temp\file.exe
0x13a90 C:\Users\azure\Downloads\cee266d388403e0dfbfdf00003c005b1.virus.exe
0x13b94 C:\940ed5075fc8ae3a4d61e08016d11c66f72dee5330a8f17a8e581a39f0d6d72f
0x13c98 C:\Users\george\Desktop\microsofthelp.exe
0x13d9c C:\Users\r.vult\AppData\Local\Temp\acb7049b9bf5be1991491685c7fddd1b.exe
0x13ea0 C:\Users\george\Desktop\microsofthelp.exe
0x13fa4 C:\Users\r.vult\AppData\Local\Temp\acb7049b9bf5be1991491685c7fddd1b.exe
0x140a8 C:\Users\george\Desktop\microsofthelp.exe
0x141ac C:\Users\Steve\AppData\Local\Temp\47c2e9ad6d8748ae8987.exe
0x142b0 C:\Users\r.vult\AppData\Local\Temp\f6a91ed10db4f8ee38f97e21f091004f.deda3a5d16ec9e2db06f8704628917335556e29b
0x143b4 C:\12c04286dd6b93d09e883f873b3aece8d5ca2e2caeece785aed7ef1e684b0e4e
0x144b8 C:\Users\azure\Downloads\microsofthelp.exe
0x145bc C:\WINDOWS\STUB.exe
0x146c0 C:\Users\Joe Cage\Desktop\rl_file.exe
0x147c4 C:\Users\azure\Downloads\9f1b0514f2f8ef670de7f0ea22a78d23.virus.exe
0x148c8 C:\WINDOWS\STUB.exe
0x149cc C:\Users\george\Desktop\software.exe
0x14ad0 C:\WINDOWS\STUB.exe
0x14bd4 C:\Users\george\Desktop\program.exe
0x14cd8 C:\WINDOWS\STUB.exe
0x14ddc C:\Users\george\Desktop\software.exe
0x14ee0 C:\WINDOWS\STUB.exe
0x14fe4 C:\Users\Steve\AppData\Local\Temp\8af45fe33ca1a5558b10.exe
0x150e8 C:\Users\azure\Downloads\dttcodexgigas.fe8ce2ec2b71cc3ddceb1ddee6ee7cdcf311bfc3.exe
0x151ec C:\1974a6409179db72018c3a8cebc1b9f1ecc4b70b1965171a70d5b301b48dc8ef
0x152f0 C:\Users\Linky\AppData\Local\Temp\6e30ca9d7c176fad4ea1.exe
0x153f4 C:\WINDOWS\STUB.exe
0x154f8 C:\Users\azure\Downloads\e8706ac38626fff3fa2194cbce2a0e63.virus.exe
0x155fc C:\WINDOWS\STUB.exe
0x15700 C:\9c79a9fb8823c0cc3a7bfd5b64d16ab500d4149710d00cf8a9ed0482328c2e9d
0x15804 C:\55426c9354510bb58c019a650dad82cb7b98defab142216ddc304656b95ff227
0x15908 C:\Users\azure\Downloads\microsofthelp.exe
0x15a0c C:\WINDOWS\STUB.exe
0x15b10 C:\Users\azure\Downloads\2e9f7f2aa4113e839694cd89635b28ff.virus.exe
0x15c14 C:\WINDOWS\STUB.exe
0x15d18 C:\Users\r.vult\AppData\Local\Temp\7bbf2a3df85e498d4e19cfbe99795f52.virus
0x15e1c C:\Users\azure\Downloads\microsofthelp.exe
0x15f20 C:\Users\Linky\AppData\Local\Temp\4e5a7716714edc08e4e9.exe
```

Some other interesting strings that may be used for hunting includes 
```
Software\motherFucker

GetStringTypeALCMapStringWWaitForSingleObjectCreateThreadHeapFreeDeleteFileAExitProcesslstrcmpiAlstrcatAGetWindowsDirectoryAHeapAllocGetProcessHeapSleepGetModuleFileNameACloseHandleGetLastErrorCreateMutexAGetProcAddressLoadLibraryAHeapReAllocGetTickCountFindCloseFindFirstFileATerminateProcessCreateProcessACreateFileAReadFileWriteFileFlushFileBuffersGetFileSizeLCMapStringAGetStringTypeWMultiByteToWideCharGetOEMCPGetACPGetCPInfoRtlUnwindSetUnhandledExceptionFilterIsBadReadPtrIsBadWritePtrIsBadCodePtrGetCurrentProcessGetStdHandleWideCharToMultiByteRegSetValueExARegQueryValueExARegOpenKeyExARegCreateKeyARegOpenKeyARegCloseKeyGetAdaptersInfoInternetOpenAInternetSetOptionExAInternetOpenUrlAInternetCloseHandleInternetReadFilewsprintfA

B&C:\Documents and Settings\Administrator\My Documents\My Music\QvodSetup5.exe

C:\_dWlLXez.exe

C:\runme.exe

C:\vshsn.exe

0x13680 C:\b54f9e2c8cef73c8aa7d0f460440473750131b7d204d3c01462aa8c0cb72e1c6
0x13784 C:\99c053e614af4cea25d1d767f81808b3addb07e356392383c6e4cb706bb98736
0x13888 C:\18becc5102637cdfdfd664cc0c4fee3033a146ba8d86dbf1c36c4b84f3b380d3
0x1398c C:\Users\maxine\AppData\Local\Temp\file.exe
0x13a90 C:\Users\azure\Downloads\cee266d388403e0dfbfdf00003c005b1.virus.exe
0x13b94 C:\940ed5075fc8ae3a4d61e08016d11c66f72dee5330a8f17a8e581a39f0d6d72f
0x13c98 C:\Users\george\Desktop\microsofthelp.exe
0x13d9c C:\Users\r.vult\AppData\Local\Temp\acb7049b9bf5be1991491685c7fddd1b.exe
0x13ea0 C:\Users\george\Desktop\microsofthelp.exe
0x13fa4 C:\Users\r.vult\AppData\Local\Temp\acb7049b9bf5be1991491685c7fddd1b.exe
0x140a8 C:\Users\george\Desktop\microsofthelp.exe
0x141ac C:\Users\Steve\AppData\Local\Temp\47c2e9ad6d8748ae8987.exe
0x142b0 C:\Users\r.vult\AppData\Local\Temp\f6a91ed10db4f8ee38f97e21f091004f.deda3a5d16ec9e2db06f8704628917335556e29b
0x143b4 C:\12c04286dd6b93d09e883f873b3aece8d5ca2e2caeece785aed7ef1e684b0e4e
0x144b8 C:\Users\azure\Downloads\microsofthelp.exe
0x145bc C:\WINDOWS\STUB.exe
0x146c0 C:\Users\Joe Cage\Desktop\rl_file.exe
0x147c4 C:\Users\azure\Downloads\9f1b0514f2f8ef670de7f0ea22a78d23.virus.exe
0x148c8 C:\WINDOWS\STUB.exe
0x149cc C:\Users\george\Desktop\software.exe
0x14ad0 C:\WINDOWS\STUB.exe
0x14bd4 C:\Users\george\Desktop\program.exe
0x14cd8 C:\WINDOWS\STUB.exe
0x14ddc C:\Users\george\Desktop\software.exe
0x14ee0 C:\WINDOWS\STUB.exe
0x14fe4 C:\Users\Steve\AppData\Local\Temp\8af45fe33ca1a5558b10.exe
0x150e8 C:\Users\azure\Downloads\dttcodexgigas.fe8ce2ec2b71cc3ddceb1ddee6ee7cdcf311bfc3.exe
0x151ec C:\1974a6409179db72018c3a8cebc1b9f1ecc4b70b1965171a70d5b301b48dc8ef
0x152f0 C:\Users\Linky\AppData\Local\Temp\6e30ca9d7c176fad4ea1.exe
0x153f4 C:\WINDOWS\STUB.exe
0x154f8 C:\Users\azure\Downloads\e8706ac38626fff3fa2194cbce2a0e63.virus.exe
0x155fc C:\WINDOWS\STUB.exe
0x15700 C:\9c79a9fb8823c0cc3a7bfd5b64d16ab500d4149710d00cf8a9ed0482328c2e9d
0x15804 C:\55426c9354510bb58c019a650dad82cb7b98defab142216ddc304656b95ff227
0x15908 C:\Users\azure\Downloads\microsofthelp.exe
0x15a0c C:\WINDOWS\STUB.exe
0x15b10 C:\Users\azure\Downloads\2e9f7f2aa4113e839694cd89635b28ff.virus.exe
0x15c14 C:\WINDOWS\STUB.exe
0x15d18 C:\Users\r.vult\AppData\Local\Temp\7bbf2a3df85e498d4e19cfbe99795f52.virus
0x15e1c C:\Users\azure\Downloads\microsofthelp.exe
0x15f20 C:\Users\Linky\AppData\Local\Temp\4e5a7716714edc08e4e9.exe

```

### CAPA
With Flare's CAPA, we can quickly identify that there is some unusual section name with the following format `nspX` where `X` is a number.
![1b4aedd436fa4cbabb0536ba115d8e0e.png](/images/flash_analysis_1/1b4aedd436fa4cbabb0536ba115d8e0e.png)

This is the first time I have ever heard and came across NSP Packer.

###  PE Bear
Off all the nsp section names, only nsp2 consists of all zeros. At this juncture, I believe that this is where the unpacked bytes would be located at. I may be wrong.

![eab3071ac99e4b529e312194aaa6f297.png](/images/flash_analysis_1/eab3071ac99e4b529e312194aaa6f297.png)




We see that from this output, there are attempt to set persistence and also get common api like `GetProcessAddress` and `LoadLibrary`.

## Static Analysis
### Persistence
As we suspected, it places the path of microsofthelp.exe into the run key in the registry
![runkey.png](/images/flash_analysis_1/b037901cf4ed4c25804d2003b722816e.png)

### To Further debug, 

Have to set settings to the path that it is looking out for. Or we can always patch. In this case, we choose the former.

![2_settings_to_debug_further.png](/images/flash_analysis_1/f5bf1db494ce44e095b5da6a18fbf6ad.png)

Only then will we be able to see the mutex being created.


### Fakenet-ng
Using Fake net, we see that it attempts to connect to 239.255.255.250:3702. 


![3. outbound_traffic_attempt.png](/images/flash_analysis_1/5e9a953f9a89425fb3b12684a61ae715.png)


According to Mandiant, this URL has been found being used by Russian Speaking Threat Actor advertising access to South Korean Metal Company on exploit.in (Underground hacking forum that has been around and active since 2005) primarily targgeting customer's data and Intellectual Properties. Just from this, it is still unclear that this sample has any corelation to that incident.

According to Virus Total, it has been marked as malicious.

![9f864cdb27d34a95840a5debdea39e1e.png](/images/flash_analysis_1/9f864cdb27d34a95840a5debdea39e1e.png)

Some information about what we are going to see :
> Downloaded files: latest files that have been retrieved from URLs sitting at the domain or IP address under study. Note that the date recorded in this section is not the date at which the file was downloaded but rather the date of the last report that we have for the resource.
> 
> latest files that, through their execution in a sandboxed virtual environment, have been seen to perform some kind of communication with the IP address or domain under consideration. 
> 
> Files referring: VirusTotal will inspect the strings contained in files submitted to the service and apply certain regular expressions to these in order to identify domains and IP addresses. This section records files that have referenced the domain or IP address under consideration. Note that the date recorded in this section is not the date at which the file that give raise to the relationship was submitted but rather the date of the last report that we have for the resource.

![ffa5a2462bc94407acfb90fa30e8918b.png](/images/flash_analysis_1/ffa5a2462bc94407acfb90fa30e8918b.png)

Note that this IP is not new. In the lower group of files, they are all marked with `Olympic Destroyer` . 

The upper group consists of many different types of malware:
- Grayware
- Phishing PDFs
- Downloaders
- Spreaders


# Summary

As I do not have communication with C2 server, I am not able to retrieve the data from it and therefore am not able to go perform a deep dive into the payload :( However, we are still able to suggest that this sample specifically acts as both dropper and downloader!.

Based on VirusTotal relation graph, there is a high probability that this can be used to drop `Olympic Destroyer` malware into the Victim's PC.

To end it off, here is the rough flow of event :

![326d26f624af4b02bae8b528cdce9752.png](/images/flash_analysis_1/326d26f624af4b02bae8b528cdce9752.png)

1. If current file modules is not the same as `C:/windows/microsofthelp.exe` then create it there. if it fails, then it will attempt to copy itself into that directory and set registry key for persistence
2. if it fails, sleep and try again
3. if it passes, then create a mutex `pomdfghrt` and find if there are similar samples. If there are, then delete them
4. Decrypt 0x80 bytes of data with xor key within `.nsp0` section
5. Check if `HidePlugin.dll` exists in same directory. If not, it will decrypt data and write into it. 
6. Load the `HidePlugin.dll`
7. Connect to internet and get back encrypted response
8. Decrypt and ultimately run via `ShellExecute` command.

---




