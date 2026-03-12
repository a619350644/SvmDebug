#pragma once
#include "Common.h"     
#include "winApiDef.h"
#include "NPT.h"
#include "Hook.h"
#include "Hide.h"

#ifdef __cplusplus
extern "C" {
#endif

    // 声明外部的 C 函数
    BOOLEAN FakeProcessByPid(PEPROCESS fakeProcess, HANDLE SrcPid);
    
#ifdef __cplusplus
}
#endif

typedef struct _VCPU_CONTEXT {
    BOOLEAN isExit;                                     // 0x00
    // 填充到页边界（0x1000）
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB Guestvmcb;           // 0x1000
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB Hostvmcb;            // 0x2000
    GUEST_GPR Guest_gpr;                                // 0x3000
    GUEST_GPR Hosts_gpr;                                // 0x3078
    UINT64 GuestVmcbPa;                                 // 0x30F0
    UINT64 HostVmcbPa;                                  // 0x30F8
    HANDLE Guest_Thread;                                // 0x3100

    DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostSaveArea[PAGE_SIZE];
    PVOID  GuestStackBase;
    UINT64 GuestStackTop;
    PVOID  GuestCodeBase;
    PVOID  HostStackBase;
    UINT64 HostStackTop;

    ULONG32 ProcessorIndex;     // 当前核心编号
    ULONG64 NptCr3;             // 当前核心专属的 NPT 顶级页表(PML4)基址
    ULONG64* pml4_table = nullptr;
    ULONG64* pdpt_table = nullptr;
    ULONG64* pd_tables = nullptr;
    ULONG64* New_pd_tables = nullptr;
    PVOID SplitPtPages[4096];
    ULONG SplitPtCount;
    PVOID ActiveHook;
    PVOID SuspendedHook;
} VCPU_CONTEXT, * PVCPU_CONTEXT;

EXTERN_C VOID SvLaunchVm(PVCPU_CONTEXT VpData);


NTSTATUS InitSVMCORE(PVCPU_CONTEXT vpData);
NTSTATUS PrepareVMCB(PVCPU_CONTEXT vpData, CONTEXT context);
UINT16 GetSegmentAttribute(UINT16 SegmentSelector, UINT64 GdtBase);
UINT64 GetSegmentBase(UINT16 SegmentSelector, UINT64 GdtBase);
BOOLEAN IsSvmHypervisorInstalled();
void SvHandleVmExit(PVCPU_CONTEXT vpData);
//void SVMLauchRun(PVCPU_CONTEXT vpData);
EXTERN_C void HostLoop(PVCPU_CONTEXT vpData);
EXTERN_C void SvEnterVmmOnNewStack(PVCPU_CONTEXT VpData);
EXTERN_C void SvSwitchStack(PVCPU_CONTEXT VpData);
EXTERN_C UINT16 GetTrSelector();
EXTERN_C UINT16 GetLdtrSelector();
