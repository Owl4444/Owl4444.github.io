---
ID: 20240618221206
date: 2024-06-18
tags:
  - Blogging
  - Malware_Analysis
Created: 2025-02-26:22:11:58
Last Modified: 2025-02-26:22:12:03
---
![[Pasted image 20250226221823.png]]
# Description
This post aim to just remove obvious opaque predicates in control flow graph. Using Binary Ninja, it is possible to patch to de-obfuscate the sample since the strategy used is the same.

> HASH : 0581f0bf260a11a5662d58b99a82ec756c9365613833bce8f102ec1235a7d4f7
## The Pattern

Firstly, the basic blocks are really fragmented which are glued together via conditional and unconditional jumps. For unconditional jump statements, there are instances where ONLY one path is taken for all cases. Notice how there are a few comparisons whereby left equals right via `cmp` instruction which would always set zero flag to zero. Depending on the jump conditions, it would only go down ONE path.

![[Pasted image 20250226221338.png]]

To understand this, we can reference the instruction graph for this comparison. The main IL Operation is `LLIL_IF` to check for the condition of `LLIL_CMP_E`. In the script, we should cover all the different IL related to `CMP`. The pattern exists where the left and right operands are of `LLIL_REG` which we can double check. Finally, to detect this, we can also make sure that the `src` for both `left` and `right` are the same which is the pre-requisites for the opaque predicate.

![[Pasted image 20250226221401.png]]
## Changing Control Flow

We can make use of the `always_branch` and `never_branch` from the patch menu which can also be done so programmatically.

```python
bv.always_branch(<instr>.address)
bv.never_branch(<instr>.address)
```

What it does is to patch to become an unconditional jump to the true statement (`always_branch`) or false statement (`never_branch`).## Writing the Script

We have to keep track of the locations to patch with the `*_branch` API.

```python
for f in bv.functions:
    func = f.low_level_il
    patch_locations = []

    for bb in func:
        for instr in bb:
            if handle_cmp_same_regs(instr):
                print()
```

Next, we can parse the instruction in Low Level IL as per the IL Graph shown in the previous section. Note that when appending the patch location, I have added another value (1 or 0) to indicate if we should always branch or to never branch. This ensures that the unconditional jump statement would jump to the correct location. Also, the different `CMP` conditions are accounted for as well.

```python
def handle_cmp_same_regs(instr):
    if instr.operation == LowLevelILOperation.LLIL_IF:
        comparison_statement = instr.operands[0]
        print("Operation : ", comparison_statement.operation)
        print(hex(instr.address))
        try:
            left_comparator = comparison_statement.left
            right_comparator = comparison_statement.right
            false_instr = instr.false
            true_instr = instr.true
        except:
            print("Skipping instruction " , instr , "@",  hex(instr.address))
            return False
    
        if hasattr(left_comparator, 'src') == False or hasattr(right_comparator, 'src') == False:
            return False
        
        # Testing agains the following
        """
        LLIL_CMP_NE - not equal
        LLIL_CMP_SLT - signed less than
        LLIL_CMP_ULT - unsigned less than
        LLIL_CMP_SLE - signed less than or equal
        LLIL_CMP_ULE - unsigned less than or equal
        LLIL_CMP_SGE - signed greater than or equal
        LLIL_CMP_UGE - unsigned greater than or equal
        LLIL_CMP_SGT - signed greater than
        LLIL_CMP_UGT - unsigned greater than
        """
        if left_comparator.src == right_comparator.src and right_comparator.operation == LowLevelILOperation.LLIL_REG and left_comparator.operation == LowLevelILOperation.LLIL_REG:
            if comparison_statement.operation == LowLevelILOperation.LLIL_CMP_E:
                patch_locations.append((instr.address, 1))
                return True
            elif comparison_statement.operation == LowLevelILOperation.LLIL_CMP_NE:
                patch_locations.append((instr.address,0))
                return True
            elif comparison_statement.operation == LowLevelILOperation.LLIL_CMP_SLE:
                patch_locations.append(instr.address, 1)
                return True
            elif comparison_statement.operation == LowLevelILOperation.LLIL_CMP_UGE:
                patch_locations.append(instr.address,1)
                return True
            elif comparison_statement.operation == LowLevelILOperation.LLIL_CMP_ULE:
                patch_locations.append(instr.address,1)
                return True
            elif comparison_statement.operation == LowLevelILOperation.LLIL_CMP_SGE:
                patch_locations.append(instr.address,1)
                return True
            elif comparison_statement.operation == LowLevelILOperation.LLIL_CMP_SGT:
                patch_locations.append(instr.address,0)
                return True
            elif comparison_statement.operation == LowLevelILOperation.LLIL_CMP_UGT:
                patch_locations.append(instr.address,0)
                return True
            elif comparison_statement.operation == LowLevelILOperation.LLIL_CMP_SLT:
                patch_locations.append(instr.address,0)
                return True
            elif comparison_statement.operation == LowLevelILOperation.LLIL_CMP_ULT:
                patch_locations.append(instr.address,0)
                return True
            return False
```

Next, we can do the actual manipulation of the control flow graph via patching.

```python
    for i in patch_locations:
        if i[1] == 1 and bv.is_always_branch_patch_available(i[0]):
            bv.always_branch(i[0])
        elif i[1] == 0 and bv.is_always_branch_patch_available(i[0]):
            bv.never_branch(i[0])
```

## Before and After

### `DllRegisterServer` (BEFORE)

![[Pasted image 20250226221503.png]]
### `DllRegisterServer` (AFTER)

![[Pasted image 20250226221514.png]]
### Resolve Function (BEFORE)
![[Pasted image 20250226221534.png]]
### Resolve Function (AFTER)

![[Pasted image 20250226221543.png]]

