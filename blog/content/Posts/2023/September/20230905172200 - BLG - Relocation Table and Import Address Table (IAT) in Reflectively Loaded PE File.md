---
ID: 20230905172200
tags:
  - Blogging
  - Malware_Analysis/technique
  - Reflective_Loading
Created: 2023-09-05 17:22:00
Last Modified: 2023-09-05 17:22:00
date: 2023/09/05
---

![[Pasted image 20241111164332.png]]

## Description

Reflective loading is a powerful technique used by malware authors to evade detection and execute malicious code. By loading a Dynamic-Link Library (DLL) or Portable Executable (PE) file directly into memory, without relying on the operating system's loader, reflective loading can bypass traditional security measures that are designed to prevent unauthorized code execution. According to the MITRE ATT&CK Framework, it identifies reflective loading as a commonly used technique by adversaries [[#^0e4ddd|(MITRE, 2022)]].

This post demonstrates would not provide the full code on how reflective loading works but partial ones on the more important concepts that I have been wanting to learn. To be able to create my own reflective loader, it is crucial to understand what relocation table is and how IAT (I am trying to load a PE file instead of DLL instead) should be fixed for Windows to understand how to run the file. 

The first few steps includes:
1. Reading RAW PE file content to a memory buffer
2. Parsing the PE Header to get important loader information. For instance:
    - Section RVA
    - Section sizes
    - Image Size
    - EntryPoint
    - etc
3. Create another buffer for loading based on information of PE header
4. Copy all the sections to the respective Virtual Addresses
5. Fix the relocation table
6. Fix the Import Address Table (IAT)

For this post, I will jump straight to point 5 and 6.

## Relocation Table

To better understand this section, it is recommended to read the `.reloc` Section(Image Only) from windows [documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

When binary file is loaded, the preferred image base address is not guaranteed to be available all the time. This is especially true for our case since we are loading this on top of another binary in the same memory address space. To fix this, the `FixReloc` function is responsible for fixing relocation errors in the shellcode that may occur during the loading process. For this to happen, the delta value is calculated to offset the current image base address from the preferred address.

## Fixing the Reloc Table
A `FixReloc` function was created to fix relocation table. It begins by calculating the delta value as mentioned. Recall that during the loading of the PE file, we needed to create a heap with RWX permission. Heap address allocated is not fixed and its address is stored in `pCustomLoaderInfo->ImageBase`. The `pCustomLoaderInfo` is just a struct containing the relevant PE header data. This value is usually not the preferred image base. To correct this, the delta offset is calculated. The `shellcode` in these code snippets refers to the PE file that we are trying to load.

```c
void FixReloc(PBYTE shellcode_load_address, PCUSTOM_LOADER_INFO pCustomLoaderInfo) {
    // Calculate the delta for offseting 
    DWORD delta = shellcode_load_address - pCustomLoaderInfo->ImageBase;
    // If delta is 0 then the image is already at the preferred image base address
    if (delta == 0) {
        return;
    }
    ...
    ...
```

Next in line, the function searches for the relocation section in the shellcode using virtual address specified in the loader configuration, `pCustomLoaderInfo->VA_Reloc`. Adding this Virtual Address to the `shellcode_load_address` would point us to `PIMAGE_BASE_RELOCATION` structure.

```c
    // Find the reloc section
    PIMAGE_BASE_RELOCATION pRelocTable = (PIMAGE_BASE_RELOCATION)(pCustomLoaderInfo->VA_Reloc + shellcode_load_address);
    if (pRelocTable->SizeOfBlock == 0) {
        return TRUE; 
    }
```

Each base relocation block starts with the following structure:

```c
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
//  WORD    TypeOffset[1];
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;
```

The block size from the Base Relocation Block refers to an entry in the relocation table. To calculate the number of entries, obtain the size of the entire relocation table subtracting the bytes taken for the `VirtualAddress` and `SizeOfBlock` and divide by the size of WORD which is used in TypeOffset.

![[Pasted image 20241111164342.png]]

Next, the`FixReloc` function iterates through each entry in the relocation block, checking whether the type of relocation is `IMAGE_REL_BASED_HIGHLOW` or `IMAGE_REL_BASED_DIR64` which are the most common type based on how the shellcode is compiled.

The Block Size field is then followed by any number of Type or Offset field entries. Each entry is a WORD (2 bytes) and has the following structure as seen in the same windows documentation:

![[Pasted image 20241111164347.png]]

If the types are `IMAGE_REL_BASED_HIGHLOW` or `IMAGE_REL_BASED_DIR64`, the the delta offset is added to the addresses from the entry.

```c
void FixReloc(PBYTE shellcode_load_address, PCUSTOM_LOADER_INFO pCustomLoaderInfo) {
    // Calculate the delta for offseting 
    DWORD delta = shellcode_load_address - pCustomLoaderInfo->ImageBase;
    // If delta is 0 then the image is already at the preferred image base address
    if (delta == 0) {
        return;
    }

    // For each of the entry
    while (pRelocTable->VirtualAddress != 0) {
        
        DWORD entriesCount = (pRelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD pRelocationData = (PWORD)(pRelocTable + 1);

        for (int j = 0; j < entriesCount; j++) {
            WORD type = pRelocationData[j] >> 12;
            WORD offset = pRelocationData[j] & 0xfff;

            // Check relation if IMAGE_REL_BASED_HIGHLOW (3) or IMAGE_REL_BASED_DIR64
            if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                // Adjust the values here
                // IMAGE_BASE_RELOCATION.VirtualAddress + offset + shellcode loaded address
                DWORD* address_to_relocate = shellcode_load_address + pRelocTable->VirtualAddress + offset; // The pRelocTable is really the RVA
                *address_to_relocate = *address_to_relocate + delta; // Notice that all values at address_to_relocate are actual addresses
            }
        }
        
        // Move to next relocatin block 
        pRelocTable = (PIMAGE_BASE_RELOCATION)((PBYTE)pRelocTable + pRelocTable->SizeOfBlock);
    }
}
```

One thing learnt during this study is that reloc entries contains offsets to jumpable addresses. Therefore it is crucial to fix these relocations should the preferred image base address is not available.

## Import Address Table (IAT)

The Import Address Table (IAT) is a structure that contains addresses of functions imported by the shellcode. In order to properly execute the shellcode, the `FixIAT` function is created to fix the Import Address Table of the shellcode to point to the correct addresses of the imported functions.

To help understand the code to come, here is what the structures look like in the PE file. The IAT can contain multiple `IMAGE_IMPORT_DESCRIPTOR`.

```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
```

Note that it contains Relative Virtual Addresses to

1.  Original First Thunk (imported function name table which is dubbed as Import Name Table throughout this study)
2.  First Thunk which points to the ordinal table.
3.  Name which is the name of the DLL.

The following shows the struct of the thunk data. Focus on both ordinal and Address of Data which a points to `IMAGE_IMPORT_BY_NAME`.

```c
typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;  // PBYTE 
        ULONGLONG Function;         // PDWORD
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64 * PIMAGE_THUNK_DATA64;
```

To resolve all the functions, the function iterates through each Import Descriptor after every`_IMAGE_IMPORT_BY_NAME` is visited. Upon visitation, `GetProcAddress` resolves function name to function addresses.

The following presents the struct of `IMAGE_IMPORT_BY_NAME`:

```c
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

Hint here is used for quicker resolution but is not necessary in our study.

In this study, the function name table is used because the `IMAGE_ORDINAL_FLAG` is not set. This probably happens because of how the shellcode is compiled.

The next figure shows how the data structure would look like in a PE file.

![[Pasted image 20241111164506.png]]

## Fixing the IAT 

The following snippet shows how the fixing of IAT is possible.

```c
void FixIAT(BYTE* shellcode_load_address, PCUSTOM_LOADER_INFO pCustomLoaderInfo) {
    // Contains Virtual Address that points to Import Descriptor
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(shellcode_load_address + pCustomLoaderInfo->VA_Import);
    
    while (pImportDescriptor->Name != 0) {
        // Import the modules that we need
        PBYTE dllname = (pImportDescriptor->Name + shellcode_load_address);
        printf("\n\nLoading from %s ", dllname);
        
        HMODULE dllModule = LoadLibraryA(dllname);
        if (!dllModule) {
            printf("[x] Error : Unable to load %s\n", dllname);
            return -1;
        }
        // Click into definition for PIMAGE_THUNK_DATA and you will find interesting helper functions
        PIMAGE_THUNK_DATA pIat = shellcode_load_address + pImportDescriptor->FirstThunk;
        PIMAGE_THUNK_DATA pInt = shellcode_load_address + pImportDescriptor->OriginalFirstThunk;

        //iterate through the IAT and INT
        while (pInt->u1.AddressOfData != 0) {
            if (pInt->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                // Search by ordinal
                WORD ordinal = IMAGE_ORDINAL(*(shellcode_load_address + pInt->u1.AddressOfData));

                //TODO Compile one that uses ordinals
                printf("\nHavent implemented this yet");
            }
            else {
                // By name and not ordinal
                IMAGE_IMPORT_BY_NAME* pImageImportByName = (IMAGE_IMPORT_BY_NAME*)(pIat->u1.AddressOfData + shellcode_load_address);
                BYTE* apiName = pImageImportByName->Name;
                WORD hint = pImageImportByName->Hint;
                FARPROC function_ptr = GetProcAddress(dllModule,(LPCSTR)apiName);
                // we take advantage of the fact that ordinal + function address location from IAT and function name index are the same each time.
                pIat->u1.Function = function_ptr;
                printf("\n\tHint : 0x%X\t\t - %s  " ,hint,apiName);
                int kk = 0;
            }
            pIat++;
            pInt++;
        }

        // Next Descriptor 
        pImportDescriptor++;
        // go to the next descriptor
    }
}
```

It should be noted however, that for real world malware, malware authors tend to indirectly resolve `GetProcAddress` since this is usually one of the first few places malware analysts would look at. Furthermore, they would try to remove as many dependencies as possible to make the shellcode work more independently. Nonetheless, this study is more of a proof of concept and thus, no attempt has been made to mimic that behaviour.

### 3.3.6. Execute Shellcode

With the relocations and function addresses fixed and resolved, the entry point can be calculated before jumping to it. Entry Point address can be calculated by adding the loaded shellcode's base address + Virtual Address of entry point stored in cusom loader information. The permission of the page is then altered to `PAGE_EXECUTE_READWRITE`. After running the shellcode, the permission is then set back to its original value.

```c
// Jump to entry point
    LPVOID address = ((BYTE*)shellcode_load_address + customLoaderInfo.VA_EntryPoint);
    void (*load_entry_point)() = address;
    VirtualProtect(shellcode_load_address, customLoaderInfo.ImageSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    load_entry_point();
    VirtualProtect(shellcode_load_address, customLoaderInfo.ImageSize, oldProtect, &oldProtect);
```

## Results

A test was done on a simple program and it worked!

![[Pasted image 20241111164516.png]]

## Discussions

Memory forensics techniques can be employed to detect the use of reflective loading, even if the PE file does not exist on disk. Tools such as Volatility can be used to analyze the memory of the compromised system.Volatility's `malfind` module or plugin can detect **common** patterns of reflective loader \[1\]. The plugin is capable of scanning for regions with `PAGE_EXECUTE_READWRITE` memory protection and check for the magic bytes MZ at the beginning of those regions (This is with the assumption that the header content are intact. In this study, since the headers are stripped, it is trickier to detect with `malfind` alone ).

## References
1.  https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection
2.  https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
3.  (Benjamin Sølberg n.d.), ReflectivePELoader, <https://github.com/BenjaminSoelberg/ReflectivePELoader>
4.  MITRE. (2022, April 21). Reflective Code Loading. MITRE ATT&CK. https://attack.mitre.org/techniques/T1620/ ^0e4ddd

---