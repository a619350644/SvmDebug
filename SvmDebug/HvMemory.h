/**
 * @file HvMemory.h
 * @brief 超级调用内存操作头文件 - 通信结构体与接口声明
 * @author yewilliam
 * @date 2026/03/16
 */

#pragma once
#include <ntifs.h>
#include "Common.h"

 /* ========================================================================
  *  Hypervisor Memory R/W Interface
  * ======================================================================== */

#define CPUID_HV_MEMORY_OP          0x41414150

#define HV_MEM_OP_READ              0x01
#define HV_MEM_OP_WRITE             0x02
#define HV_MEM_OP_GET_MODULE_BASE   0x03
#define HV_MEM_OP_GET_PEB           0x04

  /* ---- IOCTL codes ---- */
#define IOCTL_HV_READ_MEMORY   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_WRITE_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_GET_MODULE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* [FIX-v4] 新增: 通过物理页表遍历实现 VirtualQuery, 零 KeStackAttachProcess */
#define IOCTL_HV_QUERY_VM     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ---- R3 <-> R0 通信结构 ---- */
typedef struct _HV_MEMORY_REQUEST {
    ULONG64 TargetPid;
    ULONG64 Address;
    ULONG64 Size;
    ULONG64 BufferAddress;
} HV_MEMORY_REQUEST, * PHV_MEMORY_REQUEST;

/* [FIX-v4] QUERY_VM 请求/响应 */
typedef struct _HV_QUERY_VM_REQUEST {
    ULONG64 TargetPid;
    ULONG64 StartAddress;
} HV_QUERY_VM_REQUEST, * PHV_QUERY_VM_REQUEST;

typedef struct _HV_QUERY_VM_RESPONSE {
    ULONG64 BaseAddress;    /* 区域起始地址 */
    ULONG64 RegionSize;
    ULONG   Protection;     /* PAGE_READWRITE, PAGE_READONLY, etc. */
    ULONG   State;          /* MEM_COMMIT, MEM_FREE, MEM_RESERVE */
    ULONG   Type;           /* MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE */
} HV_QUERY_VM_RESPONSE, * PHV_QUERY_VM_RESPONSE;

/* ---- VMM 共享上下文 ---- */
typedef struct _HV_RW_CONTEXT {
    ULONG64 TargetCr3;
    ULONG64 SourceVa;
    ULONG64 DestPa;
    ULONG64 Size;
    ULONG64 IsWrite;
    volatile LONG Status;
} HV_RW_CONTEXT, * PHV_RW_CONTEXT;

typedef struct _VCPU_CONTEXT VCPU_CONTEXT, * PVCPU_CONTEXT;

/* VMM-level */
VOID HvHandleMemoryOp(PVCPU_CONTEXT vpData);

/* Driver-level */
NTSTATUS HvReadProcessMemory(ULONG64 TargetPid, PVOID Address, PVOID Buffer, SIZE_T Size);
NTSTATUS HvWriteProcessMemory(ULONG64 TargetPid, PVOID Address, PVOID Buffer, SIZE_T Size);

/* [FIX-v4] 真正的 ZwQueryVirtualMemory — 通过 SvmDebug 上下文调用 */
NTSTATUS HvQueryVirtualMemory(ULONG64 TargetPid, ULONG64 StartAddress,
    PULONG64 OutBaseAddress, PULONG64 OutRegionSize,
    PULONG OutProtection, PULONG OutState, PULONG OutType);

extern PHV_RW_CONTEXT g_HvSharedContext;
extern ULONG64 g_HvSharedContextPa;

NTSTATUS HvInitSharedContext();
VOID HvFreeSharedContext();

ULONG64 TranslateGuestVaToPa_Ext(ULONG64 GuestCr3, ULONG64 GuestVa);

/* ========================================================================
 * [FIX-v14] Per-CPU bypass flag
 *
 * 当 SvmDebug 自身执行 HvRead/Write/Query 时, 置位当前 CPU 的标志。
 * Hide.cpp / DeepHook 中的 Hook 函数在检查 g_ElevatedPIDs 之前先调用
 * HvIsInternalOp() — 如果返回 TRUE, 直接调用原始函数, 跳过升权逻辑。
 *
 * 这样 SvmDebug 自己的 KeStackAttachProcess → ZwQueryVirtualMemory 调用链
 * 不会被自己的 Fake_ObReferenceObjectByHandleWithTag 拦截。
 * ======================================================================== */
#define HV_MAX_CPU 256
extern volatile LONG g_HvInternalOp[HV_MAX_CPU];

/* 在 Hook 中调用: 如果返回 TRUE, 表示当前是 SvmDebug 内部操作, 跳过升权 */
__forceinline BOOLEAN HvIsInternalOp(void)
{
    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    if (cpu >= HV_MAX_CPU) return FALSE;
    return (g_HvInternalOp[cpu] != 0);
}