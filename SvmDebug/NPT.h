/**
 * @file NPT.h
 * @brief 嵌套页表(NPT)管理头文件 - NPT条目结构体与函数声明
 * @author yewilliam
 * @date 2026/03/16
 */

#pragma once
#include "Common.h"

typedef struct _VCPU_CONTEXT* PVCPU_CONTEXT;

#define NPT_FLAGS 0x07
#define NPT_LARGE_FLAGS 0x87
#define NPT_PERM_READ_ONLY      1
#define NPT_PERM_EXECUTE        2
#define NPT_PERM_NOT_PRESENT    3


extern ULONG64 g_GlobalNptCr3;

typedef struct _New_Pd_Pa_Arr {
    ULONG64 new_pd_pa[4096];
    UINT64 index;
}New_Pd_Pa_Arr, * PNew_Pd_Pa_Arr;

typedef union _NPT_ENTRY {
    ULONG64 AsUInt64;
    struct {
        ULONG64 Valid : 1;
        ULONG64 Write : 1;
        ULONG64 User : 1;
        ULONG64 Reserved1 : 4;
        ULONG64 LargePage : 1;
        ULONG64 Reserved2 : 1;
        ULONG64 Available : 3;
        ULONG64 PageFrameNumber : 40;
        ULONG64 Reserved3 : 11;
        ULONG64 NoExecute : 1;
    } Bits;
} NPT_ENTRY, * PNPT_ENTRY;


typedef struct _NPT_CONTEXT{
    PVOID TargetAddress;
    ULONG64 TargetPa = 0;

    ULONG64 pdpt_idx = 0;
    ULONG64 pd_idx = 0;
    ULONG64 pt_idx = 0;
    ULONG64 pd_linear = 0;

    PULONG64 TargetPtTable = nullptr;

} NPT_CONTEXT, *PNPT_CONTEXT;

BOOLEAN IsSupportNPT();
NTSTATUS InitNPT(PVCPU_CONTEXT vpData);
static PULONG64 CachePtVa(ULONG64 PtPa);
ULONG64 PrepareNPT(PVCPU_CONTEXT vpData);
VOID FreePvCPUNPT(PVCPU_CONTEXT vpData);
PVOID AllocateAlignedZeroedMemory(SIZE_T NumberOfBytes);
NTSTATUS SpliteLargePage(PVCPU_CONTEXT vpData, UINT64 pd_index, PULONG64* OutPtTableVa);

// 在 PASSIVE_LEVEL 下为指定目标 VA 预先拆分大页
// 必须在进入虚拟化之前调用
NTSTATUS PreSplitLargePageForHook(PVCPU_CONTEXT vpData, PVOID TargetAddress);

// Hook 辅助函数（操作已拆分好的页表——在任意 IRQL 下都安全）
NTSTATUS ApplyNptHook_NoPerm(PVCPU_CONTEXT vpData, PVOID TargetAddress, ULONG64 PagePa);
NTSTATUS ApplyNptHookByPa(PVCPU_CONTEXT vpData, ULONG64 TargetPa, ULONG64 NewPagePa);
NTSTATUS SetNptPagePermissions(PVCPU_CONTEXT vpData, ULONG64 TargetPa, ULONG PermissionType);
NTSTATUS GPaToHostPa(PNPT_CONTEXT npt_context);
PNPT_ENTRY GetNptPteByHostPa(PVCPU_CONTEXT vpData, ULONG64 TargetPa);
NTSTATUS PreSplitLargePageByPa(PVCPU_CONTEXT vpData, ULONG64 TargetPa);


// 确保所有 VMEXIT 中需要访问的 PT 表 VA 都已缓存
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID PrewarmPtVaCache(PVCPU_CONTEXT vpData);
