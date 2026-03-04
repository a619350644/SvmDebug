#pragma once
#include "Common.h"

// 前向声明 SVM_CORE，避免循环包含
typedef struct _SVM_CORE* PSVM_CORE;

#define NPT_FLAGS 0x07          // Present | RW | User
#define NPT_LARGE_FLAGS 0x87    // Present | RW | User | LargePage(Bit 7)

extern ULONG64 g_GlobalNptCr3;

typedef union _NPT_ENTRY {
    ULONG64 AsUInt64;
    struct {
        ULONG64 Valid : 1;          // [0] Present
        ULONG64 Write : 1;          // [1] Read/Write
        ULONG64 User : 1;           // [2] User/Supervisor
        ULONG64 Reserved1 : 4;      // [3-6]
        ULONG64 LargePage : 1;      // [7] Page Size (对于 2MB PD 表项填 1)
        ULONG64 Reserved2 : 1;      // [8] 
        ULONG64 Available : 3;      // [9-11] 
        ULONG64 PageFrameNumber : 40; // [12-51] PFN (物理地址右移 12 位)
        ULONG64 Reserved3 : 11;     // [52-62]
        ULONG64 NoExecute : 1;      // [63] NX bit
    } Bits;
} NPT_ENTRY, * PNPT_ENTRY;

BOOLEAN IsSupportNPT();
NTSTATUS InitNPT(PSVM_CORE vpData);
ULONG64 PrepareNPT();
VOID FreeGlobalNPT();
PVOID AllocateAlignedZeroedMemory(SIZE_T NumberOfBytes);
