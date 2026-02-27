#pragma once
#include "Common.h"
#include "winApiDef.h"


typedef struct _SVM_CORE {
    BOOLEAN isHost;                                     // 0x00
    // 填充到页边界（0x1000）
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB Guestvmcb;           // 0x1000
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB Hostvmcb;            // 0x2000
    GUEST_GPR Guest_gpr;                                // 0x3000
    GUEST_GPR Hosts_gpr;                                // 0x3078
    UINT64 GuestVmcbPa;                                 // 0x30F0
    UINT64 HostVmcbPa;                                  // 0x30F8
    HANDLE Guest_Thread;                                // 0x3100
    // [BUG FIX #2] 新增：VM_HSAVE_PA 需要的页对齐保存区域
    // VMRUN 指令用它来保存/恢复 host 状态
    DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostSaveArea[PAGE_SIZE];
    PVOID  GuestStackBase;
    UINT64 GuestStackTop;
    PVOID  GuestCodeBase;
    PVOID  HostStackBase;
    UINT64 HostStackTop;
} SVM_CORE, * PSVM_CORE;

EXTERN_C VOID SvLaunchVm(PSVM_CORE VpData);


NTSTATUS InitSVMCORE(PSVM_CORE vpData);
NTSTATUS PrepareVMCB(PSVM_CORE vpData, CONTEXT context);
UINT16 GetSegmentAttribute(UINT16 SegmentSelector, UINT64 GdtBase);
UINT64 GetSegmentBase(UINT16 SegmentSelector, UINT64 GdtBase);
BOOLEAN IsSvmHypervisorInstalled();
void SvHandleVmExit(PSVM_CORE vpData);
void SVMLauchRun(PSVM_CORE vpData);
EXTERN_C void HostLoop(PSVM_CORE vpData);
EXTERN_C void SvEnterVmmOnNewStack(PSVM_CORE VpData);

