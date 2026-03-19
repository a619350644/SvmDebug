/**
 * @file DeepHook.h
 * @brief 深度内核拦截头文件 - 特征码扫描引擎、内部函数typedef、Fake函数声明
 * @author yewilliam
 * @date 2026/03/18
 *
 * Hyper-Vanguard 深度拦截层:
 *   将防线从 SSDT "系统调用大门" 推进到内核功能核心 (Psp/Obp/Mi/Ki)。
 *   通过特征码扫描定位 ntoskrnl.exe 中的未导出函数,
 *   然后注入到 NPT FakePage 槽位中实现硬件级无痕 Hook。
 *
 * 拦截维度:
 *   Phase 1 (原有):
 *     3.1 对象管理 (Obp/Obf):  ObReferenceObjectByHandleWithTag, ObfDereferenceObject
 *     3.2 进程/线程 (Psp):     PspInsertThread, PspCallThreadNotifyRoutines, PspExitThread
 *     3.3 内存/VAD (Mi):       MmProtectVirtualMemory(内部), MiObtainReferencedVadEx
 *     3.4 异常/调度 (Ki):      KiDispatchException, KiStackAttachProcess
 *
 *   Phase 2 (新增):
 *     3.5 APC 注入防御:        KiInsertQueueApc
 *     3.6 物理内存防御:        MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPagesSpecifyCache
 *     3.7 句柄表隐藏:          ExpLookupHandleTableEntry
 *     3.8 进程生命周期:        PspInsertProcess
 *     3.9 硬件断点隐藏:        PspGetContextThreadInternal
 */

#pragma once

#include <ntifs.h>
#include "Common.h"
#include "Hook.h"
#include "Hide.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 *  Section 1: 特征码扫描引擎
 * ======================================================================== */

PVOID PatternScan(PVOID Base, SIZE_T Size, const UCHAR* Pattern, const char* Mask, SIZE_T PatternLen);
BOOLEAN GetNtoskrnlBaseAndSize(PVOID* OutBase, PSIZE_T OutSize);
BOOLEAN GetNtoskrnlTextSection(PVOID ImageBase, PVOID* OutTextBase, PSIZE_T OutTextSize);
PVOID ResolveRelativeAddress(PVOID InstructionAddr, ULONG InstructionLen, ULONG OffsetPos);


/* ========================================================================
 *  Section 2: 内部函数 typedef — Phase 1 (Psp/Obp/Mi/Ki)
 * ======================================================================== */

typedef NTSTATUS(NTAPI* FnPspInsertThread)(
    PETHREAD Thread, PEPROCESS Process,
    KPROCESSOR_MODE PreviousMode, PVOID Reserved);

typedef VOID(NTAPI* FnPspCallThreadNotifyRoutines)(
    PETHREAD Thread, BOOLEAN Create);

typedef VOID(NTAPI* FnPspExitThread)(NTSTATUS ExitStatus);

typedef NTSTATUS(NTAPI* FnObReferenceObjectByHandleWithTag)(
    HANDLE Handle, ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode,
    ULONG Tag, PVOID* Object,
    POBJECT_HANDLE_INFORMATION HandleInformation);

typedef LONG_PTR(FASTCALL* FnObfDereferenceObject)(PVOID Object);
typedef LONG_PTR(FASTCALL* FnObfDereferenceObjectWithTag)(PVOID Object, ULONG Tag);

typedef NTSTATUS(NTAPI* FnMmProtectVirtualMemory)(
    PEPROCESS Process, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);

typedef PVOID(NTAPI* FnMiObtainReferencedVadEx)(
    PEPROCESS Process, PVOID VirtualAddr, ULONG PoolTag);

typedef VOID(NTAPI* FnKiDispatchException)(
    PEXCEPTION_RECORD ExceptionRecord,
    PVOID ExceptionFrame, PVOID TrapFrame,
    KPROCESSOR_MODE PreviousMode, BOOLEAN FirstChance);

typedef VOID(NTAPI* FnKiStackAttachProcess)(
    PEPROCESS Process, PKAPC_STATE ApcState);


/* ========================================================================
 *  Section 2b: 内部函数 typedef — Phase 2 (新增)
 * ======================================================================== */

/**
 * @brief KiInsertQueueApc — 所有APC插入队列的必经之路
 *
 * KeInsertQueueApc 的底层实现。
 * KAPC 结构体中 Thread 字段 (x64 offset 0x08) 包含目标线程。
 */
typedef BOOLEAN(NTAPI* FnKiInsertQueueApc)(
    PKAPC Apc, KPRIORITY Increment);

/** @brief MmGetPhysicalAddress — 导出, 虚拟→物理地址转换 */
typedef PHYSICAL_ADDRESS(NTAPI* FnMmGetPhysicalAddress)(PVOID BaseAddress);

/** @brief MmMapIoSpace — 导出, 物理地址→系统虚拟地址映射 */
typedef PVOID(NTAPI* FnMmMapIoSpace)(
    PHYSICAL_ADDRESS PhysicalAddress,
    SIZE_T NumberOfBytes,
    MEMORY_CACHING_TYPE CacheType);

/** @brief MmMapLockedPagesSpecifyCache — 导出, MDL锁定页映射 */
typedef PVOID(NTAPI* FnMmMapLockedPagesSpecifyCache)(
    PMDL MemoryDescriptorList,
    KPROCESSOR_MODE AccessMode,
    MEMORY_CACHING_TYPE CacheType,
    PVOID RequestedAddress,
    ULONG BugCheckOnFailure,
    ULONG Priority);

/**
 * @brief ExpLookupHandleTableEntry — 句柄表项查找底层核心 (未导出)
 *
 * PspCidTable (全局CID表) 中: Handle = PID/TID, Entry → EPROCESS/ETHREAD
 */
typedef PVOID(NTAPI* FnExpLookupHandleTableEntry)(
    PVOID HandleTable, HANDLE Handle);

/**
 * @brief PspInsertProcess — 进程插入全局链表 (未导出)
 *
 * NtCreateUserProcess 底层, 在进程暴露给系统前的最后一站。
 */
typedef NTSTATUS(NTAPI* FnPspInsertProcess)(
    PEPROCESS Process, PVOID Parent,
    ACCESS_MASK DesiredAccess, ULONG ObjectAttributeFlags);

/**
 * @brief PspGetContextThreadInternal — 底层线程上下文获取 (未导出)
 *
 * 内核驱动可绕过 NtGetContextThread 直接调用此函数读取 DR0-DR7。
 */
typedef NTSTATUS(NTAPI* FnPspGetContextThreadInternal)(
    PETHREAD Thread, PCONTEXT ThreadContext,
    KPROCESSOR_MODE PreviousMode, PVOID Reserved,
    ULONG ContextFlags);


/* ========================================================================
 *  Section 3: Hook 数量统计
 * ======================================================================== */

#define DEEP_HOOK_PHASE1_COUNT  11
#define DEEP_HOOK_PHASE2_COUNT  7
#define DEEP_HOOK_COUNT         (DEEP_HOOK_PHASE1_COUNT + DEEP_HOOK_PHASE2_COUNT)


/* ========================================================================
 *  Section 4: 扫描定位函数声明
 * ======================================================================== */

/* Phase 1 扫描器 */
PVOID ScanForPspInsertThread();
PVOID ScanForPspCallThreadNotifyRoutines();
PVOID ScanForPspExitThread();
PVOID ScanForObReferenceObjectByHandleWithTag();
PVOID ScanForObfDereferenceObject();
PVOID ScanForObfDereferenceObjectWithTag();
PVOID ScanForMmProtectVirtualMemory();
PVOID ScanForMiObtainReferencedVadEx();
PVOID ScanForKiDispatchException();
PVOID ScanForKiStackAttachProcess();
PVOID ScanForObpReferenceObjectByHandleWithTag();

/* Phase 2 扫描器 */
PVOID ScanForKiInsertQueueApc();
PVOID ScanForMmGetPhysicalAddress();
PVOID ScanForMmMapIoSpace();
PVOID ScanForMmMapLockedPagesSpecifyCache();
PVOID ScanForExpLookupHandleTableEntry();
PVOID ScanForPspInsertProcess();
PVOID ScanForPspGetContextThreadInternal();


/* ========================================================================
 *  Section 5: Fake 函数声明
 * ======================================================================== */

/* Phase 1 */
NTSTATUS NTAPI Fake_ObReferenceObjectByHandleWithTag(
    HANDLE Handle, ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode,
    ULONG Tag, PVOID* Object,
    POBJECT_HANDLE_INFORMATION HandleInformation);
LONG_PTR FASTCALL Fake_ObfDereferenceObject(PVOID Object);
LONG_PTR FASTCALL Fake_ObfDereferenceObjectWithTag(PVOID Object, ULONG Tag);
NTSTATUS NTAPI Fake_PspInsertThread(
    PETHREAD Thread, PEPROCESS Process,
    KPROCESSOR_MODE PreviousMode, PVOID Reserved);
VOID NTAPI Fake_PspCallThreadNotifyRoutines(PETHREAD Thread, BOOLEAN Create);
VOID NTAPI Fake_PspExitThread(NTSTATUS ExitStatus);
NTSTATUS NTAPI Fake_MmProtectVirtualMemory_Deep(
    PEPROCESS Process, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);
PVOID NTAPI Fake_MiObtainReferencedVadEx(
    PEPROCESS Process, PVOID VirtualAddr, ULONG PoolTag);
VOID NTAPI Fake_KiDispatchException(
    PEXCEPTION_RECORD ExceptionRecord,
    PVOID ExceptionFrame, PVOID TrapFrame,
    KPROCESSOR_MODE PreviousMode, BOOLEAN FirstChance);
VOID NTAPI Fake_KiStackAttachProcess(PEPROCESS Process, PKAPC_STATE ApcState);

/* Phase 2 */
BOOLEAN NTAPI Fake_KiInsertQueueApc(PKAPC Apc, KPRIORITY Increment);
PHYSICAL_ADDRESS NTAPI Fake_MmGetPhysicalAddress_Deep(PVOID BaseAddress);
PVOID NTAPI Fake_MmMapIoSpace_Deep(
    PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes,
    MEMORY_CACHING_TYPE CacheType);
PVOID NTAPI Fake_MmMapLockedPages_Deep(
    PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode,
    MEMORY_CACHING_TYPE CacheType, PVOID RequestedAddress,
    ULONG BugCheckOnFailure, ULONG Priority);
PVOID NTAPI Fake_ExpLookupHandleTableEntry(
    PVOID HandleTable, HANDLE Handle);
NTSTATUS NTAPI Fake_PspInsertProcess(
    PEPROCESS Process, PVOID Parent,
    ACCESS_MASK DesiredAccess, ULONG ObjectAttributeFlags);
NTSTATUS NTAPI Fake_PspGetContextThreadInternal(
    PETHREAD Thread, PCONTEXT ThreadContext,
    KPROCESSOR_MODE PreviousMode, PVOID Reserved,
    ULONG ContextFlags);


/* ========================================================================
 *  Section 6: 集成接口
 * ======================================================================== */

NTSTATUS PrepareDeepHookResources(PULONG OutOkCount);
VOID LinkDeepTrampolineAddresses();


/* ========================================================================
 *  Section 7: 辅助函数
 * ======================================================================== */

/** @brief 获取 PspCidTable 全局指针 (通过扫描 PsLookupProcessByProcessId 定位) */
PVOID GetPspCidTable();


#ifdef __cplusplus
}
#endif
