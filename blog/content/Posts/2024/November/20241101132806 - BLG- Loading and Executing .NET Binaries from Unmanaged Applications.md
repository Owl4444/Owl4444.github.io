---
ID: 20241101132806
tags:
  - Blogging
  - Malware_Analysis/CloudScout
Created: 2024-11-01:13:28:01
Last Modified: 2024-11-01:13:28:06
date: 2024/11/01
---
![[loading_background.png]]

# Introduction

Recently, [welivesecurity](https://www.welivesecurity.com/en/eset-research/cloudscout-evasive-panda-scouting-cloud-services/) published a post introducing `CloudScout` by Evasive Panda - a post-exploitation toolset designed to exfiltrate data from various cloud services using stolen web cookies from different browsers. This revelation piqued my interest in understanding how `.NET` binaries (managed code) can be dynamically loaded and executed from unmanaged C/C++ code. Such techniques are not only used in malware operations but also  have legitimate applications in software development, such as plugin architectures and hooking mechanisms.

In this blogpost, we'll delve into the mechanics of hosting the Common Language Runtime (CLR) within unmanaged applications, exploring the necessary COM interfaces and methods. We'll then look at the malware sample, understand its approach, and provide comprehensive code examples to demonstrate how managed code can be seamlessly integrated into unmanaged environments.
# Understanding Managed vs. Unmanaged Code

## Managed Code
Managed code is executed by the Common Runtime Library (CLR) in the .NET framework. Languages like C#, VB.NET, and F# compile into Intermediate Languages (IL), which the CLR Just-In-Time (JIT) compiles into native code at runtime. 

Managed code benefits from features like:
- Garbage Collection which is an automatic memory management.
- Type Safety which ensures type integrity, reducing runtime error.
- Exception Handling making use of structured exception management.

## Unmanaged Code
Unmanaged code is executed directly by the operating system. Languages like C and C++ compile into machine code specific to target architecture. 

Unmanaged code requires:
- Manual memory management where developers are responsible for allocating and freeing memory
- Attention to potential type-related errors

## Why Integrate Managed and Unmanaged Code?
Integrating managed code into unmanaged applications allows developers to leverage the rich ecosystem of .NET libraries while maintaining performance-critical components in C/C++. This fusion is beneficial in scenarios like:

- Plugin Architecture where developers deal with dynamic loading of managed plugins into an unmanaged host.
- Hooking mechanism which deals with injecting managed code into unmanaged processes for extended functionality.
- <span style="color: #00ff00">Malware Operations which allows threat actor to execute malicious managed payloads from unmanaged stubs.</span>
## Key COM Objects and Interfaces for CLR Hosting

Hosting the CLR within an unmanaged application involves interacting with several COM interfaces provided by the .NET framework. Understanding these interfaces is crucial for effectively managing the CLR lifecycle and executing managed code.

### ICLRMetaHost

The purpose for `ICLRMetaHost` is to provide information about the installed CLR versions on a system. It allows the host to enumerate and select the desired CLR version for execution. 

Key Method:
- `GetRuntime` retrieves the `ICLRRuntimInfo` interface for a specified CLR version.
#### Sample Usage:
```cpp
	ICLRMetaHost* pMetaHost = nullptr;
	HRESULT hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost));
	if (SUCCEEDED(hr) && pMetaHost) {
	    // Successfully created MetaHost instance
	}
```
#### References
- [ICLRMetaHost Interface - .NET Framework | Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/iclrmetahost-interface)
- [reactos/dll/win32/mscoree/metahost.c at master · reactos/reactos · GitHub](https://github.com/reactos/reactos/blob/master/dll/win32/mscoree/metahost.c#L1035)

### ICLRRuntimeInfo
The purpose for `ICLRRuntimeInfo` is to provide information about a specific CLR version, including its loadability and access to runtime interfaces.

Key Methods:
- `IsLoadable` checks if CLR can be loaded into the process.
- `GetInterface` retrieves the `ICLRRuntimeHost` interface for runtime management.
#### Sample Usage
```cpp
	ICLRRuntimeInfo* pRuntimeInfo = nullptr;
	hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_PPV_ARGS(&pRuntimeInfo));
	if (SUCCEEDED(hr) && pRuntimeInfo) {
	    // Successfully retrieved RuntimeInfo
	}
```
#### References
- [ICLRRuntimeInfo Interface - .NET Framework | Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/iclrruntimeinfo-interface)
- [deepin-wine-ubuntu/deepin-libwine-dev\_2.18-12\_i386/usr/include/deepin-wine/windows/metahost.h at master · wszqkzqk/deepin-wine-ubuntu · GitHub](https://github.com/wszqkzqk/deepin-wine-ubuntu/blob/master/deepin-libwine-dev_2.18-12_i386/usr/include/deepin-wine/windows/metahost.h#L265)


### ICLRRuntimeHost

The purpose for `ICLRRuntimeHost` is to manage the CLR's lifecycle within the host process. It allows starting and stopping the CLR, accessing application domains, and executing managed methods.

Key Methods:
- `Start` which initializes and start the CLR.
- `ExecuteInDefaultAppDomain` which executes a specified managed method within the default `AppDomain`.
#### Sample Usage

```cpp
ICLRRuntimeHost* pRuntimeHost = nullptr;
hr = pRuntimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_PPV_ARGS(&pRuntimeHost));
if (SUCCEEDED(hr) && pRuntimeHost) {
    hr = pRuntimeHost->Start();
    if (SUCCEEDED(hr)) {
        DWORD result = 0;
        hr = pRuntimeHost->ExecuteInDefaultAppDomain(
            L"path\\to\\MyManagedCode.dll",
            L"HAHAHA.ManagedClass",
            L"callme",
            L"Hello from C++!",
            &result
        );
        // Handle result
    }
}
```
#### References
- [ICLRRuntimeHost Interface - .NET Framework | Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/iclrruntimehost-interface)
- [deepin-wine-ubuntu/deepin-libwine-dev\_2.18-12\_i386/usr/include/deepin-wine/windows/metahost.h at master · wszqkzqk/deepin-wine-ubuntu · GitHub](https://github.com/wszqkzqk/deepin-wine-ubuntu/blob/master/deepin-libwine-dev_2.18-12_i386/usr/include/deepin-wine/windows/metahost.h#L264)

## Real-World Use Case: CloudScout Malware

### Analyzed Sample Overview
In analyzing the `CloudScout` malware, specifically the `gmck.dll` component with SHA256 `729AEE2C684B05484719199FF2250217B7ACE97671416E6949C496688A777A6F`, we observe that it drops a .NET binary named `msvc_4.dll` (also referred to as `CGM`) before executing it. This behavior aligns with the technique of dynamically loading and executing managed code from an unmanaged stub.

| Malware    | SHA256                                                           | Remarks                                                         |
| ---------- | ---------------------------------------------------------------- | --------------------------------------------------------------- |
| `gmck.dll` | 729AEE2C684B05484719199FF2250217B7ACE97671416E6949C496688A777A6F | This drops .NET Binary `msvc_4.dll` AKA `CGM` before running it |
#### Sample Behavior:
1. Drop Managed Binary
	1. The unmanaged `gmck.dll` writes the `msvc_4.dll` to disk
2. Determine CLR Version based on Windows version.
	1. It decides which method the sample is going to use for hosting the CLR.
3. Execute Managed Code by utilizing either `CLRCreateInstance` or `CorBindToRuntime`
4. Invoke Managed Method by calling `CGM.Program.ModuleStart` method within the managed assembly, passing necessary arguments.
6. Steal Cookies from different types of browsers.

### Decompilation Analysis

To gain deeper insights into the malware's operation, let's examine the decompiled `ModuleStart` function. This function orchestrates the loading and execution of the manage `.NET` binary based on the system's CLR version.
```cpp
int ModuleStart()
{
  // Variable declarations and initializations
  Sleep(0x2BF20u); // Initial sleep to evade quick analysis
  v31 = 7;
  v30 = 0;
  LOWORD(Block) = 0;
  mw_query_memory_sub_1003E030();
  windows_version_identifier = mw_Check_Windows_version_sub_1003DE20(); // Retrieves Windows version
  mw_NVIDLA_path_creation_sub_1002B190(Src); // Creates necessary paths
  mw_drop_gmck_msvc_4_sub_1002B2D0(Src); // Drops the managed DLL (msvc_4.dll aka CGM)

  // Decision to load CLR based on Windows version
  if ( windows_version_identifier < 0x60002 )
    mw_CorBindToRuntimeEx_sub_1002B650(Src); // Uses CorBindToRuntimeEx for older versions
  else
    mw_CLRCreateInstance_sub_1002B580(Src); // Uses CLRCreateInstance for newer versions

  // Extended sleep post-CLR loading
  Sleep(0xEA60u);

  if ( m_CreatePathForMalware_sub_1001B6F0() )
  {
    CreateThread(0, 0, StartAddress, 0, 0, 0); // Spawns a new thread to execute the payload
    while (1)
    {
      // This includes handling different browsers like Chrome, Edge, and Firefox
  
    }
  }

  if ( v31 >= 8 )
    free_1(Block);
  return 0;
}

```
## Hosting CLR in Unmanaged C/C++ Applications

To execute managed `.NET` code from an unmanaged C/C++ application, the malware leverages COM interfaces to host the CLR. Depending on the targeted `.NET Framework` version, it uses different methods: `CLRCreateInstance` for `.NET 4.0+` and `CorBindToRuntime` for earlier versions.

### Method 1 : Using `CLRCreateInstance
`
Applicable for: .NET Framework 4.0 and above.
`CLRCreateInstance` initializes and retrieves runtime interfaces necessary for hosting the CLR.

The following shows the function prototype:
```cpp
HRESULT CLRCreateInstance(
  REFCLSID clsid,
  REFIID   riid,
  LPVOID   *ppInterface
);
```
#### Sample Functionality Flow:

1. Initialize COM library to prepare application for COM interactions
```cpp
hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
```
2. Create CLR `MetaHost` Instance to access information about the installed CLR version
```cpp
hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost));
```
3. Retrieve the Runtime Information about the desired CLR version

```cpp
hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_PPV_ARGS(&pRuntimeInfo));
```

4. Check if CLR can be loaded without conflicts
```cpp
hr = pRuntimeInfo->IsLoadable(&isLoadable);
```
5. Obtain the `ICLRRuntimeHost` interface to start and manage the CLR
```cpp
hr = pRuntimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_PPV_ARGS(&pRuntimeHost));
```
6. Start the CLR
```cpp
hr = pRuntimeHost->Start();
```
7. Execute the manage code by calling specific method within the managed assembly.
```cpp
hr = pRuntimeHost->ExecuteInDefaultAppDomain(
    L"path\\to\\MyManagedCode.dll",
    L"HAHAHA.ManagedClass",
    L"callme",
    L"Hello from C++!",
    &result
);
```
8. Clean up by releasing interfaces and uninitlialize COM
```cpp
pRuntimeHost->Stop();
pRuntimeHost->Release();
pRuntimeInfo->Release();
pMetaHost->Release();
CoUninitialize();
```

### Method 2 : Using CorBindToRuntime
`
Applicable for: .NET Framework 2.0, 3.0, and 3.5.
`CorBindToRuntime` binds the CLR to the host process, allowing the execution of managed code.

Function prototype is as follows:
```cpp
HRESULT CorBindToRuntimeEx(
  LPCWSTR pwzVersion,
  LPCWSTR pwzFlavor,
  DWORD   dwStartupFlags,
  REFCLSID rclsid,
  REFIID   riid,
  LPVOID   *ppv
);
```

Sample Functionality Flow:

1. Initialize the COM library
```cpp
hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
```
2. Bind to CLR runtime which associates the specified CLR version with the process.
```cpp
hr = CorBindToRuntimeEx(
    L"v2.0.50727",
    L"wks",
    0,
    CLSID_CorRuntimeHost,
    IID_ICorRuntimeHost,
    (void**)&pCorRuntimeHost
);
```
3. Start the CLR
```cpp
hr = pCorRuntimeHost->Start();
```
4. Execute Managed Code by calling specific method within the managed assembly.
```cpp
hr = pCorRuntimeHost->ExecuteInDefaultAppDomain(
    L"path\\to\\MyManagedCode.dll",
    L"HAHAHA.ManagedClass",
    L"callme",
    L"NOTICE MEEEE",
    &result
);
```
5. Clean up by releasing interfaces and uninitialize COM
```cpp
pCorRuntimeHost->Stop();
pCorRuntimeHost->Release();
CoUninitialize();
```
Note: In the analyzed malware sample, the choice between `CLRCreateInstance` and `CorBindToRuntime` is based on the detected Windows version, ensuring compatibility with the installed `.NET Framework`.

## Detailed Code Example

To solidify the understanding on how managed code is executed from unmanaged applications, let's examine the following code example for both hosting methods.

### C# Managed Code Sample

Before executing managed code from C++, we need a `.NET` assembly that exposes a method to be invoked. I have compiled the following code as a library exposing the `callme` function.

```cs
// HAHAHA/ManagedClass.cs
using System;
namespace HAHAHA
{
    public class ManagedClass
    {
        public static int callme(string argument)
        {
            Console.WriteLine("Hello from C# method! Argument: " + argument);
            return 42;
        }
    }
}
```
### C++ Hosting Code for Method 1 : Using `ICLRCreateInstance`

```cpp
// HostCLR_Method1.cpp

#include <Windows.h>
#include <metahost.h>
#include <comdef.h>
#include <iostream>
#include <string>

#pragma comment(lib, "mscoree.lib") // Link against mscoree.lib

// Helper function to convert HRESULT to readable string
std::wstring GetHRMessage(HRESULT hr) {
    _com_error err(hr);
    return std::wstring(err.ErrorMessage());
}

bool HostCLRUsingMetaHost() {


    HRESULT hr;

    ICLRMetaHost* pMetaHost = nullptr;
    ICLRRuntimeInfo* pRuntimeInfo = nullptr;
    ICLRRuntimeHost* pRuntimeHost = nullptr;

    // Initialize COM
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        std::wcerr << L"COM Initialization Failed: 0x" << std::hex << hr
            << L" - " << GetHRMessage(hr) << std::endl;
        return -1;
    }
    else {
        std::wcout << L"Successfully initialized COM library." << std::endl;
    }

    // Create CLR MetaHost
    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost));
    if (FAILED(hr) || !pMetaHost) {
        std::wcerr << L"Failed to create CLR MetaHost instance. HRESULT: 0x"
            << std::hex << hr << L" - " << GetHRMessage(hr) << std::endl;
        CoUninitialize();
        return -2;
    }
    else {
        std::wcout << L"Created CLR MetaHost instance successfully." << std::endl;
    }

    // Get the ICLRRuntimeInfo for CLR version 4.0.30319
    std::wcout << L"Retrieving CLR runtime information for v4.0.30319..." << std::endl;
    hr = pMetaHost->GetRuntime(
        L"v4.0.30319",                // CLR version to load
        IID_PPV_ARGS(&pRuntimeInfo)    // Receive ICLRRuntimeInfo
    );
    if (FAILED(hr) || !pRuntimeInfo) {
        std::wcerr << L"Failed to retrieve CLR runtime information. HRESULT: 0x"
            << std::hex << hr << L" - " << GetHRMessage(hr) << std::endl;
        pMetaHost->Release();
        CoUninitialize();
        return -3;
    }
    else {
        std::wcout << L"Retrieved CLR runtime information successfully." << std::endl;
    }

    // Check if the CLR is loadable
    BOOL isLoadable = FALSE;
    std::wcout << L"Checking if CLR runtime is loadable..." << std::endl;
    hr = pRuntimeInfo->IsLoadable(&isLoadable);
    if (FAILED(hr) || !isLoadable) {
        std::wcerr << L"CLR runtime is not loadable. HRESULT: 0x"
            << std::hex << hr << L" - " << GetHRMessage(hr) << std::endl;
        pRuntimeInfo->Release();
        pMetaHost->Release();
        CoUninitialize();
        return -4;
    }
    else {
        std::wcout << L"CLR runtime is loadable." << std::endl;
    }

    // Get the ICLRRuntimeHost interface
    std::wcout << L"Obtaining ICLRRuntimeHost interface..." << std::endl;
    hr = pRuntimeInfo->GetInterface(
        CLSID_CLRRuntimeHost,           // CLSID of the CLR runtime host
        IID_PPV_ARGS(&pRuntimeHost)     // Receive ICLRRuntimeHost
    );
    if (FAILED(hr) || !pRuntimeHost) {
        std::wcerr << L"Failed to obtain ICLRRuntimeHost interface. HRESULT: 0x"
            << std::hex << hr << L" - " << GetHRMessage(hr) << std::endl;
        pRuntimeInfo->Release();
        pMetaHost->Release();
        CoUninitialize();
        return -5;
    }
    else {
        std::wcout << L"Obtained ICLRRuntimeHost interface successfully." << std::endl;
        // Start the CLR
        std::wcout << L"Starting the CLR..." << std::endl;
        hr = pRuntimeHost->Start();

    }


    if (FAILED(hr)) {
        std::wcerr << L"Failed to start the CLR. HRESULT: 0x"
            << std::hex << hr << L" - " << GetHRMessage(hr) << std::endl;
        pRuntimeHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        CoUninitialize();
        return -6;
    }
    else {
        std::wcout << L"CLR started successfully." << std::endl;
    }

    // Executing the managed function from the DLL
    DWORD result = 0;
    std::wcout << L"Executing managed method 'HAHAHA.ManagedClass.callme'..." << std::endl;
    hr = pRuntimeHost->ExecuteInDefaultAppDomain(
        L"R:\\MAT\\Visual Studio Projects\\learn_dnlib_1\\learn_dnlib_1\\MyManagedCode.dll",                   // Path to the assembly
        L"HAHAHA.ManagedClass",          // Fully qualified class name
        L"callme",                       // Method name
        L"NOTICE MEEEE",                 // Argument
        &result                          // Result
    );

    if (FAILED(hr)) {
        std::wcerr << L"Failed to execute managed method in default AppDomain. HRESULT: 0x"
            << std::hex << hr << L" - " << GetHRMessage(hr) << std::endl;
    }
    else {
        std::wcout << L"Successfully executed managed method in default AppDomain." << std::endl;
        std::wcout << L"The result from the program is: " << result << std::endl;
    }

    // Release COM interfaces

    if (pRuntimeHost) {
        pRuntimeHost->Stop();
        pRuntimeHost->Release();
    }
    if (pRuntimeInfo) pRuntimeInfo->Release();
    if (pMetaHost) pMetaHost->Release();

    // Uninitialize COM
    CoUninitialize();

    return 0;
}
```
### C++ Hosting Code for Method 2 : Using `CorBindToRuntime`
This method should be used for .NET Framework version 2.0, 3.0 or 3.5. To test this out on a Windows 10 machine, I have [download Microsoft .NET Framework 3.5 from Official Microsoft Download Center](https://www.microsoft.com/en-us/download/details.aspx?id=21&msockid=001080bf98796b8323fb9478993c6afd).

```cpp
bool HostCLRUsingRuntimeHost() {
    HRESULT hr;
    ICLRRuntimeHost* pCorRunTimeHost;


    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        std::wcerr << L"COM Initialization Failed: 0x" << std::hex << hr
            << L" - " << GetHRMessage(hr) << std::endl;
        return -1;
    }
    else {
        std::wcout << L"Successfully initialized COM library." << std::endl;
    }

    hr = CorBindToRuntimeEx(
        L"v2.0.50727",              // CLR Version
        L"wks",                     // Workstation Build
        0,                          // Startup Flag
        CLSID_CorRuntimeHost,       // CLSID
        IID_ICorRuntimeHost,        // IID
        (PVOID*)&pCorRunTimeHost    //Pointer to receive the interface
    );

    if (FAILED(hr) || !pCorRunTimeHost) {
        if (pCorRunTimeHost) {
            hr = pCorRunTimeHost->Start();
            if (FAILED(hr)) {
                std::wcerr << L"Failed to start CLR RuntimeHost. HRESULT: 0x" << std::hex << hr << L" - " << GetHRMessage(hr) << std::endl;
            }
        }
        else {
            std::wcerr << L"pCorRunTimeHost is null." << std::endl;
        }
        std::wcerr << L"Failed to create CLR RuntimeHost instance. HRESULT: 0x"
            << std::hex << hr << L" - " << GetHRMessage(hr) << std::endl;
        CoUninitialize();
        return -2;
    }
    else {
        std::wcout << L"Created CLR RuntimeHost instance successfully." << std::endl;
    }

    if (FAILED(hr)) {
        std::wcerr << L"Failed to start the CLR. HRESULT: 0x"
            << std::hex << hr << L" - " << GetHRMessage(hr) << std::endl;
        pCorRunTimeHost->Release();
        CoUninitialize();
        return -6;
    }
    else {
        std::wcout << L"CLR started successfully." << std::endl;
    }

    // Executing the managed function from the DLL
    DWORD result = 0;
    std::wcout << L"Executing managed method 'HAHAHA.ManagedClass.callme'..." << std::endl;
    hr = pCorRunTimeHost->ExecuteInDefaultAppDomain(
        L"R:\\MAT\\Visual Studio Projects\\learn_dnlib_1\\learn_dnlib_1\\MyManagedCode.dll",    // Path to the assembly
        L"HAHAHA.ManagedClass",                                                                 // Fully qualified class name
        L"callme",                                                                              // Method name
        L"NOTICE MEEEE",                                                                        // Argument
        &result                                                                                 // Result
    );

    if (FAILED(hr)) {
        std::wcerr << L"Failed to execute managed method in default AppDomain. HRESULT: 0x"
            << std::hex << hr << L" - " << GetHRMessage(hr) << std::endl;
    }
    else {
        std::wcout << L"Successfully executed managed method in default AppDomain." << std::endl;
        std::wcout << L"The result from the program is: " << result << std::endl;
    }
    // Release COM interfaces

    if (pCorRunTimeHost) {
        pCorRunTimeHost->Stop(); // stop hosting the CLR
        pCorRunTimeHost->Release(); //release if data is still present
    }

    // Uninitialize COM
    CoUninitialize();

    return true;
}
```
# Full Code Listing

The full code can be found from the `Github` link that was associated with this blogpost.
# GMCK.dll Rough Outline

## mw_NVIDLA_path_creation_sub_1002B190

Previously expanded environment variable : `%ProgramData%` from  [[#sub_1003E130]], 

1. Creates the `C:\\ProgramData\\NVIDlA\\gmck` directory if it does not exist.
	1. Interesting to note is that NVIDlA is actually spelt as `(N)ovember (V)ictor (I)ndia (D)elta (L)IMA (A)lfa`

![[Pasted image 20241104115514.png]]
2. Creates the `C:\\ProgramData\\NVIDlA\\gmck\\TEMP` directory if it does not exist.

## mw_drop_gmck_msvc_4_sub_1002B2D0

1. Create the filename `C:\\ProgramData\\NVIDlA\\gmck\\msvc_4.dll`
2. Passed this filename to `mw_drop_GMCK_sub_1002B3D0` 
	1. `mw_drop_GMCK_sub_1002B3D0` contains the decryption and file dropping logic
## mw_drop_GMCK_sub_1002B3D0

1. It would write `0x3c1000` bytes of encrypted bytes into buffer
2. It stores the hardcoded RC4 key `8def870f31cf390c0cf2`
3. It decrypts the encrypted `.NET` malware  with the key
4. Write decrypted content to `C:\\ProgramData\\NVIDlA\\gmck\\msvc_4.dll`
### Decryption

The `encrypted_buffer.bin` contains encrypted buffer that was extracted from IDA. The following was used to extract and decrypt the encrypted buffer. The decrypted buffer is the content of the `CGM` which is a `.NET` module.
#### Encrypted Buffer Extraction
```python
with open("ENCRYPTED_MSVC_4.bin","wb") as f:
  f.write(get_bytes(0x10130490, 0x3C1000))
```
#### Decrypting with Malduck
```python
from malduck import rc4

# Decryption key as bytes
key = b'8def870f31cf390c0cf2'

with open('ENCRYPTED_MSVC_4.bin', 'rb') as file:
    encrypted_buffer = unhexlify(file.read())

# Decrypt the buffer using RC4
decrypted_data = rc4(key, encrypted_buffer)

# Save the decrypted data
with open('DECRYPTED_MSVC_4.bin', 'wb') as file:
    file.write(decrypted_data)
```
## mw_CorCreateInstance_sub_1002B580
This is what we have covered previously [[#C++ Hosting Code for Method 1 Using `ICLRCreateInstance`]]

```cpp
BOOL __thiscall mw_CorCreateInstance_sub_1002B580(void *this)
{
  int pRuntimeInfo; // [esp+4h] [ebp-14h] BYREF
  int MetaHostObj; // [esp+8h] [ebp-10h] BYREF
  int v5; // [esp+Ch] [ebp-Ch] BYREF
  int v6; // [esp+10h] [ebp-8h] BYREF

  MetaHostObj = 0;
  v5 = 0;
  pRuntimeInfo = 0;
  if ( CLRCreateInstance(&clsid, &REFIID, &MetaHostObj) < 0
    || (*(*MetaHostObj + 12))(MetaHostObj, L"v4.0.30319", &unk_104F65FC, &pRuntimeInfo) < 0
    || (*(*pRuntimeInfo + 36))(pRuntimeInfo, &CLSID_CorRuntimeHost, &IID_ICorRuntimeHost, &v5) < 0
    || (*(*v5 + 12))(v5) < 0 )
  {
    return 0;
  }
  v6 = 0;
  return (*(*v5 + 44))(v5, this, L"CGM.Program", L"ModuleStart", L" ", &v6) >= 0;
}
```
We can see the `ModuleStart` from `CGM.Program` without any parameters. The following shows the screenshot for the actual function that it would invoke from the unmanaged application.

![[Pasted image 20241104124604.png]]

## mw_CorBindToRuntimeEx_sub_1002B650
This is also what was previously covered in [[#Method 2 Using `CorBindToRuntime]]

```cpp
BOOL __thiscall mw_CorBindToRuntimeEx_sub_1002B650(void *dll_path)
{
  void *pCorRunTimeHost; // [esp+4h] [ebp-Ch] BYREF
  int v4; // [esp+8h] [ebp-8h] BYREF

  pCorRunTimeHost = 0;
  if ( CorBindToRuntimeEx(L"v2.0.50727", L"wks", 0, &CLSID_CorRuntimeHost, &IID_ICorRuntimeHost, &pCorRunTimeHost) < 0
    || (*(*pCorRunTimeHost + 0xC))(pCorRunTimeHost) < 0 )
  {
    return 0;
  }
  v4 = 0;
  return (*(*pCorRunTimeHost + 44))(pCorRunTimeHost, dll_path, L"CGM.Program", L"ModuleStart", L" ", &v4) >= 0;
}
```
## CreatePathForMalware_sub_1001B6F0
This function stores some name of what look like configurations file names.

1. Create `Gmck` directory at the same directory as the current running malware if it does not exist.
2. Store `<sameDir>\\Gmck.nom.cfg` string
3. Store `<sameDir\\Gmck.stp.cfg` string ^835aa9
4. Based on Windows Version:
	1. `< 0x60001`
		- `C:\\Documents and Settings\\All Users\\Application Data\\Microsoft\\PStatus\\Gmck.nom`
		- `C:\\Documents and Settings\\All Users\\Application Data\\Microsoft\\PStatus\\Gmck.stp`
	2. `>= 0x60001`
		- `C:\\Users\\Public\\AppData\\Local\\Windows\\ODBC\\PStatus\\Gmck.nom`
		- `C:\\Users\\Public\\AppData\\Local\\Windows\\ODBC\\PStatus\\Gmck.stp`
		- 
5. On my Windows 10 machine, I have the following directory created.

![[Pasted image 20241104133840.png]]

6. Find all the files relevant to Google Chrome `C:\Users\user\AppData\Local\Google\Chrome\User Data\*.*`
	1. `C:\Users\user\AppData\Local\Google\Chrome\User Data\AutofillStates\Cookies`
		1. If tit exists, delete it

## StartAddress (Separate Thread)

1. `mw_delete_files_sub_1001B990` for every 300000 ms or 300 s or 5 mins
	1. Delete `<sameDir>\\Gmck.nom.cfg` if exists
	2. Delete `<sameDir>\\Gmck.stp.cfg` if exists
	3. Delete`C:\\users\\public\\appdata\\local\\windows\\odbc\\PStatus\\Gmck.nom` if exists
	4. Delete `C:\\users\\public\\appdata\\local\\windows\\odbc\\PStatus\\Gmck.stp` if exists

## Cookies Log Files

These are some host-based IOCs:
```
C:/ProgramData/NVIDlA/gmck/ff_cke<YYYYMMDD_HHMMSS>.dat
C:/ProgramData/NVIDlA/gmck/ff_cke_cfg.dat
C:/ProgramData/NVIDlA/gmck/im_cke_<YYYYMMDD_HHMMSS>.dat
C:/ProgramData/NVIDlA/gmck/im_cke_cfg.dat
C:/ProgramData/NVIDlA/gmck/cm_cke_cfg_<YYYYMMDD_HHMMSS>.dat
C:/ProgramData/NVIDlA/gmck/cm_cke_cfg_<YYYYMMDD_HHMMSS>1.dat
…/TEMP/eg_cke_%s.dat
…/eg_cke_cfg_%s1.dat
```
### Sample Config files
![[Pasted image 20241104141543.png]]

### Cookies Stealing Locations

- `C:/Users/user/AppData/Local/Google/Chrome/User Data`
- `C:/Users/user/AppData/Local/Google/Chrome/User Data/<filename>/Cookies`
- `C:/Users/user/AppData/Local/Google/Chrome/User Data/Local State`
- `.../Network/Cookies`
- `/Microsoft/Edge/User Data/%s/Cookies`
- `/Microsoft/Edge/User Data/Local State`

After cookies are stolen, they are decrypted before being parsed.
#### Decryption of Cookies

Data obtained from here may be decrypted via `CryptUnprotectData`. 

Signs of Cookie data were also manipulated and stolen here. It is most likely that stolen cookies data from chrome were also stored within configuration files as well after being parsed.
This stealing happens every `3600000ms` which is every hour and stored in configuration files which would be used in the dropped and executed `.NET` binary.

#### Method for Cookie Stealing No Longer Effective
It should be noted that this method is not effective against the new App Bound Encryption Feature in starting from Chrome 127 [Google Online Security Blog: Improving the security of Chrome cookies on Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html) which was designed to make it harder and to prevent threat actor from stealing cookies the way this sample did.

![[Pasted image 20241104144812.png]]

# Conclusion

Integration of managed `.NET` binaries within unmanaged C/C++ applications presents a powerful mechanism for both legitimate software development and malicious activities. Through the analysis of the sample, we have uncovered how threat actors adeptly utilizes COM interfaces like `ICLRMetaHost`, `ICLRRuntimeInfo`, and `ICLRRuntimeHost` to host the CLR and execute managed code dynamically.

As per the analyzed sample, we see that it was able to select between methods based on system's CLR version (guessed). This dual-method approach ensures compatibility across wide range of Windows versions and `.NET` Framework installations.

Some strategies for development could be to create a .NET Plugin Loaders for enhanced modularity and stealth. Threat actor could design malware that is highly modular. Each plugin, be it for data exfiltration, system reconnaissance, or persistence, can be developed, deployed, and updated independently. This allows for rapid adaptation to new environments and targets without overhauling the entire malware framework. 

