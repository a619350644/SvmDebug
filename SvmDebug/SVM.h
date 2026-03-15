/**
 * @file SVM.h
 * @brief SVM虚拟化引擎头文件 - VCPU上下文结构体与函数声明
 * @author yewilliam
 * @date 2026/02/06
 *
 * [BUGFIX] 新增 SplitPtPas[] 数组，与 SplitPtPages[] 一一对应，
 *          在 PASSIVE_LEVEL 拆分时记录 PA，消除 VMEXIT 路径中的
 *          MmGetPhysicalAddress 调用。
 */

#pragma once
#include "Common.h"     
#include "winApiDef.h"
#include "NPT.h"
#include "Hook.h"
#include "Hide.h"

#ifdef __cplusplus
extern "C" {
#endif

    BOOLEAN FakeProcessByPid(PEPROCESS fakeProcess, HANDLE SrcPid);
    
#ifdef __cplusplus
}
#endif

typedef struct _VCPU_CONTEXT {
    BOOLEAN isExit;                                     // 0x00
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

    ULONG32 ProcessorIndex;
    ULONG64 NptCr3;
    ULONG64* pml4_table;
    ULONG64* pdpt_table;
    ULONG64* pd_tables;
    ULONG64* New_pd_tables;

    /**
     * [BUGFIX] SplitPtPages 和 SplitPtPas 必须一一对应：
     *   SplitPtPages[i] = 拆分后PT页的虚拟地址 (VA)
     *   SplitPtPas[i]   = 拆分后PT页的物理地址 (PA)
     * 这样在 VMEXIT (高IRQL) 中查找PT页时直接比较PA，
     * 无需调用 MmGetPhysicalAddress。
     */
    PVOID   SplitPtPages[4096];
    ULONG64 SplitPtPas[4096];      /* [BUGFIX] 新增：预存PA，消除VMEXIT中的API调用 */
    ULONG   SplitPtCount;

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
EXTERN_C void HostLoop(PVCPU_CONTEXT vpData);
EXTERN_C void SvEnterVmmOnNewStack(PVCPU_CONTEXT VpData);
EXTERN_C void SvSwitchStack(PVCPU_CONTEXT VpData);
EXTERN_C UINT16 GetTrSelector();
EXTERN_C UINT16 GetLdtrSelector();
