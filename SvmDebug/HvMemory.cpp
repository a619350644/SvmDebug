/**
 * @file HvMemory.cpp
 * @brief 超级调用内存操作 - 基于物理内存的跨进程读写
 *
 * [v2 - Lock-Free PTE Slot]
 * VMEXIT 期间使用预分配 PTE 槽位映射物理页, 不调用任何 Windows API:
 *   - 不用 MmGetVirtualForPhysical (Bug 8: 自引用 PTE 在 Host CR3 下错误)
 *   - 不用 MmMapIoSpace (Bug 9: VMEXIT 期间 IF=0 导致自旋锁死锁)
 *
 * 替代方案: VmxMapPhys() 直接写 PTE + INVLPG, 零锁零 API。
 */

#include "HvMemory.h"
#include "SVM.h"
#include "HvMapSlot.h"

 /* ========================================================================
  * HvBatchRead 类型定义 — 内联 (避免 extern "C" 编译问题)
  * ======================================================================== */
#ifndef CPUID_HV_BATCH_READ
#define CPUID_HV_BATCH_READ     0x41414151
#endif
#ifndef HV_BATCH_MAX_ENTRIES
#define HV_BATCH_MAX_ENTRIES    512
#endif

#pragma pack(push, 8)
typedef struct _HV_SCATTER_ENTRY {
    ULONG64 GuestVa;
    ULONG   Size;
    ULONG   OutputOffset;
    ULONG   Status;
    ULONG   Reserved;
} HV_SCATTER_ENTRY, * PHV_SCATTER_ENTRY;

typedef struct _HV_BATCH_CONTEXT {
    ULONG64 TargetCr3;
    ULONG   EntryCount;
    ULONG   TotalOutputSize;
    ULONG64 EntriesPa;
    ULONG64 OutputPa;
    ULONG   SuccessCount;
    volatile LONG Status;
} HV_BATCH_CONTEXT, * PHV_BATCH_CONTEXT;
#pragma pack(pop)

/* ========================================================================
 * Shared context for Guest <-> VMM communication
 * ======================================================================== */
PHV_RW_CONTEXT g_HvSharedContext = nullptr;
ULONG64 g_HvSharedContextPa = 0;
FAST_MUTEX g_HvMutex;

#ifndef HV_MAX_CPU
#define HV_MAX_CPU 256
#endif
volatile LONG g_HvInternalOp[HV_MAX_CPU] = { 0 };

NTSTATUS HvInitSharedContext()
{
    ExInitializeFastMutex(&g_HvMutex);
    PHYSICAL_ADDRESS highAddr;
    highAddr.QuadPart = ~0ULL;

    g_HvSharedContext = (PHV_RW_CONTEXT)MmAllocateContiguousMemory(
        PAGE_SIZE, highAddr);

    if (!g_HvSharedContext) {
        SvmDebugPrint("[HvMem] Failed to allocate shared context\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_HvSharedContext, PAGE_SIZE);
    g_HvSharedContextPa = MmGetPhysicalAddress(g_HvSharedContext).QuadPart;

    SvmDebugPrint("[HvMem] Shared context at VA=%p, PA=0x%llX\n",
        g_HvSharedContext, g_HvSharedContextPa);

    return STATUS_SUCCESS;
}

VOID HvFreeSharedContext()
{
    if (g_HvSharedContext) {
        MmFreeContiguousMemory(g_HvSharedContext);
        g_HvSharedContext = nullptr;
        g_HvSharedContextPa = 0;
    }
}

/* ========================================================================
 * Guest VA -> Guest PA: 遍历 x64 四级页表
 *
 * [v2] 使用 VmxMapPhys(SLOT_PML4) 串行复用: 映射→读→取消→下一级
 * ======================================================================== */
static ULONG64 TranslateGuestVaToPa(ULONG cpuId, ULONG64 GuestCr3, ULONG64 GuestVa)
{
    ULONG64 pml4Idx = (GuestVa >> 39) & 0x1FF;
    ULONG64 pdptIdx = (GuestVa >> 30) & 0x1FF;
    ULONG64 pdIdx = (GuestVa >> 21) & 0x1FF;
    ULONG64 ptIdx = (GuestVa >> 12) & 0x1FF;
    ULONG64 offset = GuestVa & 0xFFF;

    /* PML4 */
    ULONG64 pml4Base = GuestCr3 & ~0xFFFULL;
    PULONG64 pml4Page = (PULONG64)VmxMapPhys(cpuId, SLOT_PML4, pml4Base);
    if (!pml4Page) return 0;
    ULONG64 pml4e = pml4Page[pml4Idx];
    VmxUnmapPhys(cpuId, SLOT_PML4);

    if (!(pml4e & 1)) return 0;

    /* PDPT */
    ULONG64 pdptBase = pml4e & 0x000FFFFFFFFFF000ULL;
    PULONG64 pdptPage = (PULONG64)VmxMapPhys(cpuId, SLOT_PML4, pdptBase);
    if (!pdptPage) return 0;
    ULONG64 pdpte = pdptPage[pdptIdx];
    VmxUnmapPhys(cpuId, SLOT_PML4);

    if (!(pdpte & 1)) return 0;

    /* 1GB huge page */
    if (pdpte & (1ULL << 7)) {
        return (pdpte & 0x000FFFFFC0000000ULL) | (GuestVa & 0x3FFFFFFF);
    }

    /* PD */
    ULONG64 pdBase = pdpte & 0x000FFFFFFFFFF000ULL;
    PULONG64 pdPage = (PULONG64)VmxMapPhys(cpuId, SLOT_PML4, pdBase);
    if (!pdPage) return 0;
    ULONG64 pde = pdPage[pdIdx];
    VmxUnmapPhys(cpuId, SLOT_PML4);

    if (!(pde & 1)) {
        if ((pde & 0xC00) == 0x400) { /* Transition PDE */ }
        else { return 0; }
    }

    /* 2MB large page */
    if (pde & (1ULL << 7)) {
        return (pde & 0x000FFFFFFFE00000ULL) | (GuestVa & 0x1FFFFF);
    }

    /* PT */
    ULONG64 ptBase = pde & 0x000FFFFFFFFFF000ULL;
    PULONG64 ptPage = (PULONG64)VmxMapPhys(cpuId, SLOT_PML4, ptBase);
    if (!ptPage) return 0;
    ULONG64 pte = ptPage[ptIdx];
    VmxUnmapPhys(cpuId, SLOT_PML4);

    if (!(pte & 1)) {
        if ((pte & 0xC00) == 0x400) { /* Transition PTE */
            return (pte & 0x000FFFFFFFFFF000ULL) | offset;
        }
        return 0;
    }

    return (pte & 0x000FFFFFFFFFF000ULL) | offset;
}

ULONG64 TranslateGuestVaToPa_Ext(ULONG64 GuestCr3, ULONG64 GuestVa)
{
    ULONG cpuId = KeGetCurrentProcessorNumber();
    return TranslateGuestVaToPa(cpuId, GuestCr3, GuestVa);
}

/* ========================================================================
 * 物理地址间内存拷贝
 *
 * [v2] 使用 VmxMapPhys SLOT_SRC(4) / SLOT_DST(5)
 * VmxMapPhys 返回 VA + 页内偏移, 可直接拷贝。
 * ======================================================================== */
static BOOLEAN PhysicalMemoryCopy(
    ULONG cpuId,
    ULONG64 DestPa,
    ULONG64 SrcPa,
    SIZE_T Size,
    BOOLEAN IsWrite)
{
    UNREFERENCED_PARAMETER(IsWrite);
    if (Size == 0 || Size > PAGE_SIZE) return FALSE;

    PVOID srcMap = VmxMapPhys(cpuId, SLOT_SRC, SrcPa);
    if (!srcMap) return FALSE;

    PVOID dstMap = VmxMapPhys(cpuId, SLOT_DST, DestPa);
    if (!dstMap) {
        VmxUnmapPhys(cpuId, SLOT_SRC);
        return FALSE;
    }

    /* 计算本页内可拷贝的最大字节数 */
    SIZE_T srcAvail = PAGE_SIZE - (SIZE_T)(SrcPa & 0xFFF);
    SIZE_T dstAvail = PAGE_SIZE - (SIZE_T)(DestPa & 0xFFF);
    SIZE_T copyLen = Size;
    if (copyLen > srcAvail) copyLen = srcAvail;
    if (copyLen > dstAvail) copyLen = dstAvail;

    /* VmxMapPhys 返回值已含页内偏移, 直接拷贝 */
    RtlCopyMemory(dstMap, srcMap, copyLen);

    VmxUnmapPhys(cpuId, SLOT_DST);
    VmxUnmapPhys(cpuId, SLOT_SRC);

    return TRUE;
}

/* ========================================================================
 * VMM 侧: 单次读/写处理器
 * ======================================================================== */
VOID HvHandleMemoryOp(PVCPU_CONTEXT vpData)
{
    if (!vpData) return;

    ULONG cpuId = vpData->ProcessorIndex;
    ULONG64 contextPa = vpData->Guest_gpr.Rbx;
    if (contextPa == 0) {
        vpData->Guest_gpr.Rax = (UINT64)-1;
        return;
    }

    PHV_RW_CONTEXT pCtx = (PHV_RW_CONTEXT)VmxMapPhys(cpuId, SLOT_CTX, contextPa);
    if (!pCtx) {
        vpData->Guest_gpr.Rax = (UINT64)-2;
        return;
    }

    ULONG64 targetCr3 = pCtx->TargetCr3;
    ULONG64 targetVa = pCtx->SourceVa;
    ULONG64 bufferPa = pCtx->DestPa;
    ULONG64 totalSize = pCtx->Size;
    BOOLEAN isWrite = (pCtx->IsWrite != 0);

    if (totalSize == 0 || totalSize > 0x100000) {
        pCtx->Status = -3;
        VmxUnmapPhys(cpuId, SLOT_CTX);
        vpData->Guest_gpr.Rax = (UINT64)-3;
        return;
    }

    ULONG64 bytesProcessed = 0;

    while (bytesProcessed < totalSize) {
        SIZE_T pageRemain = PAGE_SIZE - (SIZE_T)((targetVa + bytesProcessed) & 0xFFF);
        SIZE_T chunkSize = (SIZE_T)(totalSize - bytesProcessed);
        if (chunkSize > pageRemain) chunkSize = pageRemain;

        ULONG64 targetPa = TranslateGuestVaToPa(cpuId, targetCr3, targetVa + bytesProcessed);
        if (targetPa == 0) {
            bytesProcessed += chunkSize;
            continue;
        }

        ULONG64 currentBufferPa = bufferPa + bytesProcessed;
        BOOLEAN ok = isWrite
            ? PhysicalMemoryCopy(cpuId, targetPa, currentBufferPa, chunkSize, TRUE)
            : PhysicalMemoryCopy(cpuId, currentBufferPa, targetPa, chunkSize, FALSE);

        if (!ok) {
            bytesProcessed += chunkSize;
            continue;
        }
        bytesProcessed += chunkSize;
    }

    pCtx->Status = 0;
    VmxUnmapPhys(cpuId, SLOT_CTX);

    vpData->Guest_gpr.Rax = bytesProcessed;
}

/* ========================================================================
 * VMM 侧: Batch Scatter-Gather Read
 *
 * 槽位使用:
 *   SLOT_CTX (6)   — BatchContext 页
 *   SLOT_ENTRY (7) — ScatterEntry 页
 *   SLOT_PML4 (0)  — 页表遍历 (TranslateGuestVaToPa)
 *   SLOT_SRC (4), SLOT_DST (5) — PhysicalMemoryCopy
 * ======================================================================== */
VOID HvHandleBatchRead(PVCPU_CONTEXT vpData)
{
    if (!vpData) return;

    ULONG cpuId = vpData->ProcessorIndex;
    ULONG64 ctxPa = vpData->Guest_gpr.Rbx;
    if (ctxPa == 0) {
        vpData->Guest_gpr.Rax = (UINT64)-1;
        return;
    }

    /* 映射上下文, 读取字段, 立即释放槽位 */
    PHV_BATCH_CONTEXT pCtx = (PHV_BATCH_CONTEXT)VmxMapPhys(cpuId, SLOT_CTX, ctxPa);
    if (!pCtx) {
        vpData->Guest_gpr.Rax = (UINT64)-2;
        return;
    }

    ULONG64 targetCr3 = pCtx->TargetCr3;
    ULONG entryCount = pCtx->EntryCount;
    ULONG64 entriesPa = pCtx->EntriesPa;
    ULONG64 outputPa = pCtx->OutputPa;

    if (entryCount == 0 || entryCount > HV_BATCH_MAX_ENTRIES ||
        entriesPa == 0 || outputPa == 0 || targetCr3 == 0) {
        pCtx->Status = -3;
        pCtx->SuccessCount = 0;
        VmxUnmapPhys(cpuId, SLOT_CTX);
        vpData->Guest_gpr.Rax = (UINT64)-3;
        return;
    }
    VmxUnmapPhys(cpuId, SLOT_CTX);

    ULONG successCount = 0;

    for (ULONG i = 0; i < entryCount; i++) {
        ULONG64 entryPa = entriesPa + i * sizeof(HV_SCATTER_ENTRY);
        PHV_SCATTER_ENTRY pEntry = (PHV_SCATTER_ENTRY)VmxMapPhys(cpuId, SLOT_ENTRY, entryPa);
        if (!pEntry)
            continue;

        ULONG64 guestVa = pEntry->GuestVa;
        ULONG size = pEntry->Size;
        ULONG outOffset = pEntry->OutputOffset;

        if (size == 0 || size > PAGE_SIZE) {
            pEntry->Status = (ULONG)-1;
            VmxUnmapPhys(cpuId, SLOT_ENTRY);
            continue;
        }

        ULONG bytesRead = 0;
        BOOLEAN anyFailed = FALSE;

        while (bytesRead < size) {
            SIZE_T pageRemain = PAGE_SIZE - (SIZE_T)((guestVa + bytesRead) & 0xFFF);
            SIZE_T chunkSize = (SIZE_T)(size - bytesRead);
            if (chunkSize > pageRemain) chunkSize = pageRemain;

            ULONG64 srcPa = TranslateGuestVaToPa(cpuId, targetCr3, guestVa + bytesRead);
            if (srcPa == 0) {
                anyFailed = TRUE;
                bytesRead += (ULONG)chunkSize;
                continue;
            }

            ULONG64 dstPa = outputPa + outOffset + bytesRead;
            if (!PhysicalMemoryCopy(cpuId, dstPa, srcPa, chunkSize, FALSE)) {
                anyFailed = TRUE;
                bytesRead += (ULONG)chunkSize;
                continue;
            }

            bytesRead += (ULONG)chunkSize;
        }

        pEntry->Status = anyFailed ? (ULONG)-1 : 0;
        if (!anyFailed) successCount++;

        VmxUnmapPhys(cpuId, SLOT_ENTRY);
    }

    /* 重新映射上下文写回结果 */
    pCtx = (PHV_BATCH_CONTEXT)VmxMapPhys(cpuId, SLOT_CTX, ctxPa);
    if (pCtx) {
        pCtx->SuccessCount = successCount;
        pCtx->Status = 0;
        VmxUnmapPhys(cpuId, SLOT_CTX);
    }

    vpData->Guest_gpr.Rax = (UINT64)successCount;
}

/* ========================================================================
 * Guest-side functions (PASSIVE_LEVEL, 不受 VMEXIT 约束)
 * ======================================================================== */

static ULONG64 GetProcessCr3(ULONG64 TargetPid)
{
    PEPROCESS targetProc = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)TargetPid, &targetProc);
    if (!NT_SUCCESS(status) || !targetProc) return 0;
    ULONG64 cr3 = *(PULONG64)((PUCHAR)targetProc + 0x28);
    ObDereferenceObject(targetProc);
    return cr3;
}

static VOID ForcePagePresent(ULONG64 TargetPid, PVOID Address, SIZE_T Size, BOOLEAN ForWrite)
{
    PEPROCESS targetProc = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)TargetPid, &targetProc);
    if (!NT_SUCCESS(status) || !targetProc) return;

    KAPC_STATE apcState;
    KeStackAttachProcess(targetProc, &apcState);

    __try {
        PUCHAR base = (PUCHAR)Address;
        SIZE_T offset = 0;
        while (offset < Size) {
            if (ForWrite) {
                InterlockedOr8((volatile char*)(base + offset), 0);
            }
            else {
                volatile UCHAR dummy = *(volatile UCHAR*)(base + offset);
                UNREFERENCED_PARAMETER(dummy);
            }
            SIZE_T pageRemain = PAGE_SIZE - (((ULONG_PTR)(base + offset)) & 0xFFF);
            offset += pageRemain;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(targetProc);
}

NTSTATUS HvReadProcessMemory(ULONG64 TargetPid, PVOID Address, PVOID Buffer, SIZE_T Size)
{
    if (!g_HvSharedContext || !Buffer || Size == 0)
        return STATUS_INVALID_PARAMETER;

    ULONG64 targetCr3 = GetProcessCr3(TargetPid);
    if (targetCr3 == 0) return STATUS_NOT_FOUND;

    ForcePagePresent(TargetPid, Address, Size, FALSE);

    PVOID kernelBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, 'HvRd');
    if (!kernelBuffer) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(kernelBuffer, Size);

    ULONG64 kernelBufferPa = MmGetPhysicalAddress(kernelBuffer).QuadPart;
    if (kernelBufferPa == 0) {
        ExFreePoolWithTag(kernelBuffer, 'HvRd');
        return STATUS_UNSUCCESSFUL;
    }

    ExAcquireFastMutex(&g_HvMutex);
    g_HvSharedContext->TargetCr3 = targetCr3;
    g_HvSharedContext->SourceVa = (ULONG64)Address;
    g_HvSharedContext->DestPa = kernelBufferPa;
    g_HvSharedContext->Size = Size;
    g_HvSharedContext->IsWrite = 0;
    g_HvSharedContext->Status = 1;

    int regs[4] = { 0 };
    __cpuidex(regs, CPUID_HV_MEMORY_OP, HV_MEM_OP_READ);

    NTSTATUS status;
    if (g_HvSharedContext->Status == 0) {
        __try {
            RtlCopyMemory(Buffer, kernelBuffer, Size);
            status = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_ACCESS_VIOLATION;
        }
    }
    else {
        status = STATUS_UNSUCCESSFUL;
    }
    ExReleaseFastMutex(&g_HvMutex);

    ExFreePoolWithTag(kernelBuffer, 'HvRd');
    return status;
}

NTSTATUS HvWriteProcessMemory(ULONG64 TargetPid, PVOID Address, PVOID Buffer, SIZE_T Size)
{
    if (!g_HvSharedContext || !Buffer || Size == 0)
        return STATUS_INVALID_PARAMETER;

    ULONG64 targetCr3 = GetProcessCr3(TargetPid);
    if (targetCr3 == 0) return STATUS_NOT_FOUND;

    ForcePagePresent(TargetPid, Address, Size, TRUE);

    PVOID kernelBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, 'HvWr');
    if (!kernelBuffer) return STATUS_INSUFFICIENT_RESOURCES;

    __try {
        RtlCopyMemory(kernelBuffer, Buffer, Size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ExFreePoolWithTag(kernelBuffer, 'HvWr');
        return STATUS_ACCESS_VIOLATION;
    }

    ULONG64 kernelBufferPa = MmGetPhysicalAddress(kernelBuffer).QuadPart;
    if (kernelBufferPa == 0) {
        ExFreePoolWithTag(kernelBuffer, 'HvWr');
        return STATUS_UNSUCCESSFUL;
    }

    ExAcquireFastMutex(&g_HvMutex);
    g_HvSharedContext->TargetCr3 = targetCr3;
    g_HvSharedContext->SourceVa = (ULONG64)Address;
    g_HvSharedContext->DestPa = kernelBufferPa;
    g_HvSharedContext->Size = Size;
    g_HvSharedContext->IsWrite = 1;
    g_HvSharedContext->Status = 1;

    int regs[4] = { 0 };
    __cpuidex(regs, CPUID_HV_MEMORY_OP, HV_MEM_OP_WRITE);

    NTSTATUS status = (g_HvSharedContext->Status == 0) ?
        STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    ExReleaseFastMutex(&g_HvMutex);

    ExFreePoolWithTag(kernelBuffer, 'HvWr');
    return status;
}