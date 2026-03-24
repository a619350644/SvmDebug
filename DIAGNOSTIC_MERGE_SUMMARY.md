# SvmDebug Diagnostic Channel Merge - Summary

## Objective
Integrate diagnostic reporting from DBKKernel (Guest R0) to SvmDebug (VMM Host) via CPUID supercalls, enabling visibility into:
1. SVM activation status
2. Batch read initialization state  
3. Which memory read path is taken (VMEXIT_OK vs FALLBACK vs LEGACY)

## Changes Applied to SvmDebug Project

### 1. New File: HvBatchRead.h
**Location:** `SvmDebug/SvmDebug/HvBatchRead.h`

Shared header with constant definitions and data structures for batch scatter-gather reads:

```c
#define CPUID_HV_BATCH_READ     0x41414151
#define CPUID_HV_DIAG           0x41414152  /* Diagnostic channel */

/* Diagnostic subcommands */
#define HV_DIAG_INIT_STATUS     0x01  /* Report initialization state */
#define HV_DIAG_READ_ENTER      0x02  /* Report read operation entry */
#define HV_DIAG_READ_RESULT     0x03  /* Report which path was taken */
```

Contains structure definitions for:
- `HV_SCATTER_ENTRY` - individual read request
- `HV_BATCH_CONTEXT` - batch operation context
- `BATCH_READ_INPUT/OUTPUT` - IOCTL message structures

### 2. Updated File: SvmDebug/SVM.cpp

#### Include Addition
Added `#include "HvBatchRead.h"` after other includes to access diagnostic constants.

#### VMEXIT Handler Addition
Inserted CPUID_HV_DIAG handler (lines 539-589) between CPUID_HV_BATCH_READ and CPUID_HV_DEBUG_OP handlers:

```c
else if (leaf == CPUID_HV_DIAG) {
    /* Decodes diagnostic data from Guest RCX */
    UINT32 rcxVal = (UINT32)vpData->Guest_gpr.Rcx;
    UINT32 diagCmd = rcxVal & 0xFF;           /* Subcommand */
    BOOLEAN svmActive = (rcxVal >> 8) & 1;    /* Is SVM on? */
    BOOLEAN batchInit = (rcxVal >> 9) & 1;    /* Is BatchRead initialized? */
    UINT32 pathCode = (rcxVal >> 10) & 0x3F;  /* Path taken: 0/1/2/3 */
    
    switch (diagCmd) {
    case HV_DIAG_INIT_STATUS:
        /* DriverEntry reports initialization state */
        SvmDebugPrint("[DIAG-DBK] DriverEntry INIT: SvmActive=%d BatchInit=%d\n", ...);
        break;
    case HV_DIAG_READ_ENTER:
        /* Each memory read reports entry */
        SvmDebugPrint("[DIAG-DBK] CE_READMEMORY #%d: SvmActive=%d BatchInit=%d\n", ...);
        break;
    case HV_DIAG_READ_RESULT:
        /* Reports which read path was used: VMEXIT_OK, FALLBACK_Stealth, LEGACY_noSVM, VMEXIT_FAIL */
        SvmDebugPrint("[DIAG-DBK] CE_READ_RESULT #%d: path=%s\n", ...);
        break;
    }
    vmcb->StateSaveArea.Rax = 0; /* ACK */
}
```

All output is throttled to first 20 occurrences plus every 5000th occurrence to avoid log spam.

## Diagnostic Read Path Codes
```
0 = VMEXIT_OK         - Optimal: Used CPUID VMEXIT → VMM physical read
1 = FALLBACK_Stealth  - SVM active but batch read unavailable → Guest R0 physical read
2 = LEGACY_noSVM      - No SVM → Used KeAttachProcess (slow, unsafe path)
3 = VMEXIT_FAIL       - VMEXIT triggered but VMM returned error
```

## How to Diagnose with These Changes

1. **Launch SvmDebug debugger** on target with DBKKernel loaded
2. **Watch the Qt log window** for [DIAG-DBK] messages:
   - On DBKKernel driver load: `[DIAG-DBK] DriverEntry INIT: SvmActive=1 BatchInit=1`
   - On each CE memory scan:
     - `[DIAG-DBK] CE_READMEMORY #1: SvmActive=1 BatchInit=1`
     - `[DIAG-DBK] CE_READ_RESULT #1: path=VMEXIT_OK` (good)
     - or `path=FALLBACK_Stealth` (SVM active but no batch read)
     - or `path=LEGACY_noSVM` (SVM not activated)

3. **Interpretation:**
   - If seeing `LEGACY_noSVM` on most reads: SVM hypervisor load failed, or DBKKernel not loaded
   - If seeing `FALLBACK_Stealth`: SVM is active but HvBatchRead_Init() may have failed
   - If seeing `VMEXIT_OK`: optimal path, batch read working through hypervisor

## Remaining Work (DBKKernel Project)

These changes are in the external CE/DBKKernel project, not SvmDebug:
- DBKDrvr.c: Call HvBatchRead_IsInitialized() in DriverEntry diagnostic CPUID
- IOPLDispatcher.c: Add CPUID_HV_DIAG calls with path tracking to IOCTL_CE_READMEMORY
- HvBatchRead_Guest.c: Enhanced logging for batch read initialization and CPUID triggers

The diagnostic channel is now ready on the VMM side to receive and display these reports.
