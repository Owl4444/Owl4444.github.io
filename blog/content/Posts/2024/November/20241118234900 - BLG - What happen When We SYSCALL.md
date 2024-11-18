---
ID: 20241118234900
Dateline: 2024-11-18
tags:
  - Blogging
  - Intel_Architecture
Created: 2023-06-13 09:27:00
Last Modified: 2023-06-13 09:27:00
date: 2023/06/13
---
# Description

This post is a mini research on how SYSCALL is done under the hood. We will see how the different privilege levels would be adjusted to kernel mode.
## TL;DR
Check if 64-bit mode, long mode, and syscalls are enabled; otherwise, terminate. Save state in RCX, RIP, R11, and mask RFLAGS. Configure Code (CS) and Stack (SS) segments with proper limits, types, and privilege levels. Wait for expected instructions if CET is supported. Finalize syscall by transitioning to target RIP.
## SYSCALL - Fast System Call

- `SYSCALL` is intended for Privilege Level 3 to access OS or executive procedures running at Privilege level 0.
- `SYSCALL`/`SYSRET` saves and restore RFLAGS register.

> [!success] Searching the Intel Manual
> We can search for "Fast System Calls in 64-Bit Mode"

| Opcode | Instruction | Op/En | 64-Bit Mode | Compat/Leg Mode | Description                                       |
| ------ | ----------- | ----- | ----------- | --------------- | ------------------------------------------------- |
| 0F 05  | SYSCALL     | ZO    | Valid       | Invalid         | Fast call to privilege level 0 system procedures. |
## Instruction Operand Encoding

| Op/En | Operand 1 | Operand 2 | Operand 3 | Operand 4 |
| ----- | --------- | --------- | --------- | --------- |
| ZO    | N/A       | N/A       | N/A       | N/A       |


![[Pasted image 20241118212139.png]]

![[Pasted image 20241118212152.png]]
![[Pasted image 20241118212204.png]]


# SYSCALL Flow
## Step 1: Check Preconditions
```
IF NOT (is_64bit_mode AND Long_Mode_Active AND syscall_enabled) THEN
    Undefined_Operation
ENDIF
```
## Step 2: Save Current State

```
RCX = Current_Instruction_Pointer # Save RIP to RCX
RIP = Target_Instruction_Pointer  # Populate RIP with the 64-bit target instruction pointer
R11 = RFLAGS                     # Save current RFLAGS to R11
RFLAGS = RFLAGS AND ~IA32_FMASK  # Mask RFLAGS using IA32_FMASK from MSR (C000_0084)
```

More about [[#EFLAGS Register|RFLAG which is extended of EFLAG]].
## Step 3: Setup Code Segment (CS)
```
CS.Selector = IA32_STAR[47:32] AND 0xFFFC  # Extract selector and clear TI and RPL bits
CS.Base = 0                               # Set CS base to 0
CS.Limit = 0xFFFF                         # Set CS limit for 4GB (granularity enabled)
CS.Type = 0b1011                          # Set Type: Execute/Read, Accessed, Non-Conforming
CS.S = 1                                  # Mark as Code/Data Segment
CS.DPL = 0                                # Descriptor Privilege Level = 0 (Kernel Mode)
CS.P = 1                                  # Mark as Present
CS.L = 1                                  # Enable 64-bit mode
CS.D = 0                                  # Clear Default Operand Size
CS.G = 1                                  # Set 4K Granularity
```
## Step 4: Check for Shadow Stack and CET
```

IF ShadowStackEnabled THEN
    SSP = Canonicalize(IA32_PL3_SSP)      # Canonicalize Linear Address for SSP
ENDIF

IF CET_Enabled THEN
    IF EndBranch_Enabled THEN
        CET.Tracker = WAIT_FOR_ENDBRANCH # Set CET Tracker to WAIT_FOR_ENDBRANCH
        CET.Suppress = 0                 # Clear CET Suppress (Enable CET Enforcement)
    ELSE
        CET.Tracker = IDLE               # Set CET Tracker to IDLE
        CET.Suppress = 0                 # Clear CET Suppress (Enable CET Enforcement)
    ENDIF
ENDIF
```
## Step 5: Setup Stack Segment (SS)
```
SS.Selector = IA32_STAR[47:32] + 8        # Extract SS selector
SS.Base = 0                               # Set SS base to 0
SS.Limit = 0xFFFF                         # Set SS limit for 4GB (granularity enabled)
SS.Type = 0b0011                          # Set Type: Read/Write, Accessed, Expand-Up Data
SS.DPL = 0                                # Descriptor Privilege Level = 0 (Kernel Mode)
SS.P = 1                                  # Mark as Present
SS.B = 1                                  # Mark as Big (32-bit stack operations)
SS.G = 1                                  # Set 4K Granularity
```


---
# Long Winded with Reference to Intel Manual
- - [[#^d26e06|IA32_EFER.SCE/SYSCALL Enable flag]] is not set  OR  [[#^11f1ef|IA32_EFER.LMA/IA-32 mode is active]] is not set or `CS.L` (Not in 64 bits)  then exist.
	- To do so, we can check `(CPUID.80000001H.EDX[bit 11] = 1)`.
	- According to Intel Manual `If CS.L = 0 and IA-32e mode is active`, the processor is running in compatibility mode.
- RCX stores RIP (next instruction from current)
- RIP populated with 64 bits Target Instruction Pointer
- R11 get RFLAGS value
	- More about [[#EFLAGS Register|RFLAG which is extended of EFLAG]].
- RFLAGS updated with and ~IA32_FMASK
	- `IA32_FMASK` can be taken via `C000_0084` from IA-32 MSR. `IA32_FMASK (R/W)` is AKA System Call Flag Mask (R/W) from Table 2-2. IA-32 Architectural MSRs . we should have it:`If CPUID.80000001:EDX.[29] = 1`
	- This is used to clear out bits that should not be carried over during transitions 
		![[Pasted image 20241118215435.png]]
- The Code Segment Selector value is taken from `IA32_STAR[47:32] & 0xFFFC`
	- The following shows the `IA32_STAR` layout
	- ![[Pasted image 20241118220048.png]]
- The reason to clear the first two bits is because they are `TI` and `RPL`
	- `TI` refers to Table Indicator (0 -> GDT, 1-> LDT)
	- `RPL` refers to Requested Privilege Level 
	- ![[Pasted image 20241118221041.png]]
- Set the base of CS to 0 - Search Intel Manual with "Code-Segment Descriptor in 64-bit Mode"
- Set the limit to 0xFFFF - Check "Limit Checking" in Section 5.3
	- 0xFFFF means that the G Flag is set with 4 KByte page granularity
		- $2^{12} = 4096$ and therefore, the lower 12 bits of segment offset (address) are not checked against the limit.
		- Limit: `FFFH (4 KBytes) to FFFFFFFFH (4 GBytes)`.
- Sets the Type as well to numerical value 11 whose binary is `0b1011`
	- TL;DR - This sets the code segment to be non-conforming but executable and marking the segment as (A)ccessed making it wr
	- According to Intel Manual : `CS.Type is set to 11 (execute/read, accessed, non-conforming code segment).`
	- `C` (0) refers to this being a non-conforming segment.
		- Non conforming segment will require the DPL to equal its RPL
			- According to Intel Manual `If the selected code segment is at a different privilege level and the code segment is non-conforming,a general-protection exception is generated.`
		- Note that conforming segment grants far CALL or far JMP instruction access to its segment descriptor. It also allows access from any privilege level that is equal to or greater (less privileged) than the `DPL` of the conforming code segment. 
	- `R` (1)is set to Readable
	- `A`(1) refers to Accessed (Executable)

- ![[Pasted image 20241118225053.png]]

- Can check out more from "PRIVILEGE LEVEL CHECKING WHEN ACCESSING DATA SEGMENTS"
- `CS.S` here refers to the Descriptor type (S) Flag for bit 12
	- See if the segment descriptor is for a system segment or a code or data segment
	- `The CS register only can be loaded with a selector for a code segment.` This is set to define this segment as code or data segment.
- `CS.DPL` is set to 0
	- `DPL` is Descriptor Privilege Level which is the privilege level of a segment or gate.
	- This sets the privilege to the lowest (Kernel mode)
- `CS.P` is set to be present
- `CS.L` is set as 64 bits mode
- `CS.D` is set to 0 as required
- `CS.G` is set to 1 for 4Kbyte granularity
- Checks if `ShadowStackEnabled` with the current privilege level 
- This is used for CET if enabled.
- There is a Shadow Stack Pointer (SSP) which contains task's shadow stack pointer.
	- `IA32_PL3_SSP` is used to store the canonicalized address via `LA_adjust` where LA stands for Linear Address. 
		- is present `If CPUID.(EAX=07H,ECX=0H):ECX.CET_SS[07] = 1`
		- This means that we can see if this is enabled from CPUID
		- PL3 refers to Privilege Level (User Mode) which is used to load the linear address into SSP on transition to privilege level 3 (R/W).
		- Find the sequence of near indirect CALL instruction by searching:
			- `Instructions sequentially following a near indirect CALL instruction (i.e., those not at the target) may be executed speculatively.`
			- It will adjust` 64:48` in 64 bits with 4kbytes Page in a 4 level paging.![[Pasted image 20241118151045.png]]
	- `CPL` - Current Privilege Level is set to 0 (Kernel Mode)
	- If the ShadowStack is enabled with CPL level of 0, then set to 0
	- If [End Branch 64 bit](https://www.felixcloutier.com/x86/endbr64) (`ENDBR64`) is enabled with current `CPL`(Kernel)
	- This is the  instruction terminates an indirect branch in 64 bit mode. Since the `CPL` at this point is 0, then it would set an IDLE state for kernel mode. The Supervisor CET suppress bit is cleared, enabling CET enforcement for supervisor (kernel) mode.
	- ![[Pasted image 20241118232546.png]]
	- If the endbranch is enabled, then the CET Tracker would be changed to `WAIT_FOR_ENDBRANCH`. The `TRACKER` refers to CET's ability to track Control Flow like indirect branch tracking.
		- `WAIT_FOR_ENDBRANCH` is important for CET since it is responsible for throwing  `Control Protection Exception` or  Mnemonic`#CP` when there is a missing `ENDBRANCH` instruction at target of an indirect call or jump.
- `SS` - Stack Segment is retrieved from `IA32_STAR[47:32]+8`
- Similar to `CS`, `SS.Base` is set to 0 and `SS.Limit` to 4Gb limit by setting to 1
- The `SS.Type` is set to numerical value `3` which is `0b0011`
	- This is according to documentation and set Descriptor type (S) Flag for bit 12
	- `(read/write, accessed, expand-up data segment).`
- `SS.DPL` is set to 0 (Kernel mode)
- `SS.P` is set to 1 is set to present
- `SS.B` refers to `Big` 
	- `Stacks in expand-up segments with the G (granularity) and B (big) flags in the stack-segment descriptor clear.`
- `SS.G` to 4KByte Granularity
- Transition to the Target Instruction Pointer in `RIP`


# Appendix
## EFER - Extended Feature Enable Register

IA32_EFER MSR provides several field related to IA-32e mode enabling and operation. There are four bytes that are important:
1. IA32_EFER.SCE (R/W) --  <strong style="color:#00ffff"> (Pos 0)</strong> ^d26e06
	- SYSCALL Enable     
2. IA32_EFER.LME (R) -- <strong style="color:#00ffff"> (Pos 8)</strong>
	- IA-32e Mode Enable 
3. IA-32_EFER.LMA - IA-32e Mode -- Active <strong style="color:#00ffff"> (Pos 10)</strong> ^11f1ef
	1. IA-32e mode is active when set
4. IA32_EFER.NXE (R/W) - Execute Disable Bit Enable -- <strong style="color:#00ffff"> (Pos 11)</strong>
	1. Enable page access restrictions by preventing instruction fetches from PAE pages with the XD bit set 

## EFLAGS Register
2-10 Vol. 3A

![[Pasted image 20241118213235.png]]

# Conclusion
Definitely had a better appreciation of the Intel Manual when it comes to searching up information about the architecture. It is definitely good to open the combined version and search up based on keywords as well. With that, it has helped me understand the syscall instructions a little better.