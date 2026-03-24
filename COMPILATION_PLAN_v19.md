# SvmDebug v19 Pure VMEXIT Compilation Plan

## Status
✅ All source code merges complete (Files 71 & 72)
✅ HvCpuidWithRbx ASM functions added to both SvmDebug and DBKKernel
✅ Bug fixes integrated:
   - BUG #1: CPUID_HV_BATCH_READ RBX register now set via HvCpuidWithRbx
   - BUG #2: CPUID_HV_MEMORY_OP RBX overwrite removed (Guest passes context PA)
   - BUG #3: NPT Hook protection attribute masking fixed (kernel handle + UserMode check)
   - BUG #4: Guest R0 fallback paths removed (pure VMEXIT architecture)

## Compilation Targets

### 1. SvmDebug.sys (Primary VMM)
**Project**: C:\Users\yejinzhao\source\repos\SvmDebug\SvmDebug.sln
**Key changes**:
- Asm.asm: Added HvCpuidWithRbx function (lines 144-182)
- SVM.cpp: Removed RBX overwrite in CPUID_HV_MEMORY_OP handler
- HvMemory.cpp: Using HvCpuidWithRbx instead of __cpuidex
- Hide.cpp: Added ExGetPreviousMode() == UserMode check (line 1460)

**Build command**:
```bash
msbuild SvmDebug.sln /p:Configuration=Release /p:Platform=x64
```

**Output**: SvmDebug/x64/Release/SvmDebug.sys

### 2. DBKDrvr.sys (Cheat Engine Bridge)
**Project**: D:\工具\cheat-engine-7.5\DBKKernel\DBKKernel.sln
**Key changes**:
- amd64/dbkfunca.asm: Added HvCpuidWithRbx PUBLIC function (lines 158-194)
- HvBatchRead_Guest.c: Using HvCpuidWithRbx for CPUID_HV_BATCH_READ (line 237)
- HvMemBridge.c: Using HvCpuidWithRbx for CPUID_HV_MEMORY_OP (line 156)
- IOPLDispatcher.c: Pure VMEXIT architecture
  - Read failures: Fill zero (no StealthDirectRead)
  - Write operations: Use HvBridge_WriteProcessMemory (VMEXIT)
  - Query operations: Use ObOpenObjectByPointer kernel handle

**Build command**:
```bash
msbuild D:\工具\cheat-engine-7.5\DBKKernel\DBKKernel.sln /p:Configuration=Release /p:Platform=x64
```

**Output**: D:\工具\cheat-engine-7.5\DBKKernel\x64\Release\DBKDrvr.sys

## Compilation Order
1. **First**: Compile DBKKernel (no dependencies on SvmDebug)
2. **Second**: Compile SvmDebug (ready to interact with updated DBKKernel)

## Expected Compiler Warnings/Errors
- None (all code changes are structurally identical to v18)
- HvCpuidWithRbx functions are standard ASM patterns, no special warnings expected

## Pre-Compilation Checklist
- [x] Visual Studio 2019+ installed
- [x] Windows Driver Kit (WDK) installed
- [x] SvmDebug.sln and DBKKernel.sln both valid
- [x] No uncommitted changes in SvmDebug project
- [x] All source files present and readable

## Post-Compilation Steps
1. Verify SvmDebug.sys exists: `SvmDebug/x64/Release/SvmDebug.sys`
2. Verify DBKDrvr.sys exists: `D:\工具\cheat-engine-7.5\DBKKernel\x64\Release\DBKDrvr.sys`
3. Deploy drivers (see DEPLOYMENT.md)
4. Test with Cheat Engine
5. Monitor DebugView for diagnostic logs

## Expected Runtime Behavior (v19)

### Memory Read (IOCTL_CE_READMEMORY)
**Expected logs**:
```
[SVM-CE] VMEXIT READ OK #N: PID=... addr=... size=... data[0..7]=...
```
NOT:
```
[SVM-CE] !! FALLBACK #N: StealthDirectRead ...
```

### Memory Write (IOCTL_CE_WRITEMEMORY)
**Expected logs**:
```
[SVM-CE] WRITE VMEXIT #N: PID=... addr=... size=...
```
NOT:
```
[SVM-CE] WRITE #N (Guest R0 StealthDirectWrite, NOT VMEXIT): ...
```

### Virtual Memory Query (IOCTL_CE_QUERY_VIRTUAL_MEMORY)
**Expected behavior**:
- CE Memory Viewer displays correct data (no ???)
- First Scan returns valid memory regions
- Protection attributes show correctly (EXECUTE_READWRITE, not READONLY)

## Rollback Plan
If compilation fails:
1. Check build log for specific error
2. Verify ASM syntax: HvCpuidWithRbx follows x64 ABI (RBX is callee-saved)
3. Verify includes: HvMemBridge.h in IOPLDispatcher.c
4. If needed, compare with reference implementation in files (72)
