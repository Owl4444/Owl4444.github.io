---
layout: post
title: DudeLocker (Flare-on 2016) - RVA and Import Descriptors
description: Learning how PE files get imported function names from headers. Cleared up concepts on Relative Virtual Address and learnt some Important data structures pertaining to imports.
image: '/images/DudeLocker_background.png'
date: 2022-09-07 04:23:00 +0800
tags: [Writeups]
---

# DudeLocker

## Description

Recently, I was tasked to try out challenge 2 `DudeLocker` in Flare-on from the year 2016. Since there are already many writeups, this post aims to help the reader understand a concept that was really hazy to me. The concept that I have questions about is how PE files deal with import functions and how they resolve them.

## TL;DR (DudeLocker)
What DudeLocker does is that it will attempt to generate the IV and Key and use that for AES-CBC Mode Cipher to encrypt every document in the Briefcase folder stored in the Desktop. However, what we really want is decrypt the file instead to get back the original jpg file content. One of the  ways to do so is to mess with the Import descriptors and calling CryptDecrypt rather than CryptEncrypt. This will still work because AES-CBC uses symmetric encryption.

If you have not tried this yet, you can download the challenge files from [github](https://github.com/fareedfauzi/Flare-On-Challenges/blob/master/Challenges/2016/Flare-on%203/2/). Give it a try and you can try to follow along as well!


## Finding Imports from PE File Headers

During this time, I wil be using `pe-bear` and `pestudio` to inspect the PE File structure of the ransomware. Within the NT Headers, there is an `Optional Header` that points to the Import Directory at raw file offset 0x160 which contains the address 0x21A8. 

![import_directory_RVA.png](/images/import_directory_RVA.png)
*Address of Import Directory*

 While this address looks pretty much normal, however, when we look at the data in the last section, realize that there is no such address as it ends at 0x19FF. WHAT?!

 ![end_of_data.png](/images/end_of_data.png)

To understand this, we have to understand what Relative Virtual Address is! According to [Wikipedia](https://en.wikipedia.org/wiki/COFF) :

> Relative virtual addresses (RVAs) are not to be confused with standard virtual addresses. A relative virtual address is the virtual address of an object from the file once it is loaded into memory, minus the base address of the file image.

That said, to find out the directory information from the PE File, we need to calculate the File Offset Address (FOA) so that we can parse the data.

Before going deeper, let us first take a look and understand the Section Headers that can be seen in PE-bear.

![section_headers.png](/images/section_headers.png)
*Section Headers*


## Calculating File Offset Address from RVA

We are interested in the `.rdata` section since the the RVA of value 0x21A8 is within range. We see that there are quite a number of fields in this Section Headers.

This actually corresponds with the [`_IMAGE_SECTION_HEADER`](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header) struct.

```c
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

The two main fields that we are interested in are :
1. Virtual Address
    - the address of the **FIRST** byte of the section when loaded into memory, relative to the image base!
    - In this case, when DudeLocker is loaded in memory, the first byte of the .rdata section is 0x2000 excluding the image base.
2. PointerToRawData
    - A file pointer to the first page within the COFF file, referring to the PE file.
    - In this case,  Raw Data of .rdata section is at offset 0x1000 of the PE file.

Now, the value 0x21A8 represents the Relative Virtual Address (RVA) of the Import Directory which refers to the address when loaded in memory at that specific location relative to the image base. 

Therefore, to figure out the File Offset Address with relations to the Relative Virtual Address (RVA), we can do the following calculation.

```
FileOffsetAddress =  PointerToRawData + (RVA - VirtualAddressOfSection)

FileOffsetAddress =  0x1000 + ( 0x21A8 - 0x2000 )

FileOffsetAddress = 0x11a8
```

`(RVA - VirtualAddressOfSection)` acts like the delta between the address and the first byte which will then be added to Pointer to Raw Data where the first byte of that section is located in the PE File. Thus, getting the File offset Address.

Checking the first entry in the imports tab in PE-bear should confirm our calculations!

![import_calculation.png](/images/import_calculation.png)
*At file offset 0x11a8 lies the first import entry*


## Studying Important Structs related to Imports 

Referencing this [PDF](http://www.cse.tkk.fi/fi/opinnot/T-110.6220/2010_Spring_Malware_Analysis_and_Antivirus_Tchnologies/luennot-files/Erdelyi-Reverse_engineering_2.pdf), the Import Descriptors contain the fields as seen in the previous image. [This old MSDN Post](https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2) supports that as well. It turns out there are different ways to resolve the imported function address. For this post, I will only focus on resolution when bound value is set to FALSE.

The following image is taken from the aforementioned PDF

![important_data_structures.png](/images/important_data_structures.png)

Using this data structure, we should be able to parse and get back the same result. 

![image_import_descriptor.png](/images/image_import_descriptor.png)
*Mapping from memory to structure*


Now that we see this mapping, there is still something that did not make sense. To get the name, we can look at the Image thunk data which is a RVA to the original unbounded IAT. 

Notice how the value of NameRVA 0x242c gets resolved to the symbol name `KERNEL32.dll`? We can confirm that with the same calculations as before to find out the File Offset Address.


```
FileOffsetAddress =  PointerToRawData + (RVA - VirtualAddressOfSection)

FileOffsetAddress =  0x1000 + ( 0x242c - 0x2000 )

FileOffsetAddress = 0x142c
```

![rva_name.png](/images/rva_name.png)

Finally, to list out the import functions, we can trace through the Original first Thunk. Since we have the value fo 0x223c, we have the FileOffsetAddress of 0x123c which contains the RVA of 0x2360 which points to IMAGE_IMPORT_BY_NAME structure with the hint and byte pointer field at 0x1360!
 
![import_name.png](/images/import_name.png)

The hint in this data structure is actually a "hint" to the loader as to what ordinal of the imported API might be. Also, the reason why we can tell that the RVA of 0x2360 points to the IMAGE_THUNK_ DATA value is because the high bit of the IMAGE_THUNK_DATA value is not set. If it is set, the bottom 31 bits (or 63 bits for a 64-bit executable) is treated as an ordinal value. 

Another important detail is that this "hint" is there to help improve performance when attempting to resolve a function, however, if it is unable to find the function, it will still search the normal way as before. This means that if we were to change the name of the function, the hint may fail and still continue to search up the DLL export table.


# Changing CryptEncrypt to CryptDecrypt

If you have done the challenge, you would have been familiar with the following two functions.

```c
//  7 parameters
BOOL CryptEncrypt(
  [in]      HCRYPTKEY  hKey,
  [in]      HCRYPTHASH hHash,
  [in]      BOOL       Final,
  [in]      DWORD      dwFlags,
  [in, out] BYTE       *pbData,
  [in, out] DWORD      *pdwDataLen,
  [in]      DWORD      dwBufLen
);

// 6 parameters
BOOL CryptDecrypt(
  [in]      HCRYPTKEY  hKey,
  [in]      HCRYPTHASH hHash,
  [in]      BOOL       Final,
  [in]      DWORD      dwFlags,
  [in, out] BYTE       *pbData,
  [in, out] DWORD      *pdwDataLen
);
```



For this, since we are now familiar with how the program resolves the name, we can attempt to find and patch the binary so that.

First thing I did was to change the name using CFF Explorer. I changed the name of CryptEncrypt to CryptDecrypt.

![alter_to_decrypt.png](/images/alter_to_decrypt.png)

We can now load the binary into IDA and see the changes.

![now_decrypt.png](/images/now_decrypt.png)

Since that CryptDecrypt has the exact same parameters except for the absence of the parameter `dwBufLen`, we can replace the `push eax` instruction with NOPs at address 0040165A.

 Let's patch it in x32dbg and see the result. Remember to change the volume serial number with VolumeId64.exe from sysinternal tools suite. Also, put the BusinessPapers.doc file into the Briefcase as well for decryption.

![nop.png](/images/nop.png)

## Flagging

After running the decryption, we can now double check the BusinessPapers.doc in HxD. We see that it has the JFIF header with Exif information which suggest strongly that this is a JPG file.

![HxD_output_jfif.png](/images/HxD_output_jfif.png)

Changing the extension to Jpg and we should see the following image containing the flag.

![flag.png](/images/flag.png)

---


