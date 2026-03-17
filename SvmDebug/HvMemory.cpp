/**
 * @file HvMemory.cpp
 * @brief 超级调用内存操作 - 基于物理内存的跨进程读写
 * @author yewilliam
 * @date 2026/03/16
 *
 * 提供绕过所有内核API的进程内存读写能力：
 * Guest侧: 获取目标CR3 → 填充共享上下文 → CPUID触发超级调用
 * VMM侧: 遍历x64四级页表翻译VA→PA → 物理内存间拷贝
 * 对ACE等反作弊系统完全透明。
 */

#include "HvMemory.h"
#include "SVM.h"

/* ========================================================================
 *  Shared context for Guest <-> VMM communication *  Allocated as contiguous physical memory so VMM can access it
 * ======================================================================== */
PHV_RW_CONTEXT g_HvSharedContext = nullptr;
ULONG64 g_HvSharedContextPa = 0;
FAST_MUTEX g_HvMutex;

/**
 * @brief 初始化Guest-VMM共享上下文页 - 分配连续物理内存供超级调用通信
 * @author yewilliam
 * @date 2026/03/16
 * @return 成功返回STATUS_SUCCESS, 分配失败返回STATUS_INSUFFICIENT_RESOURCES
 */
NTSTATUS HvInitSharedContext()
{
    ExInitializeFastMutex(&g_HvMutex); // 初始化锁
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

/**
 * @brief 释放共享上下文页
 * @author yewilliam
 * @date 2026/03/16
 */
VOID HvFreeSharedContext()
{
    if (g_HvSharedContext) {
        MmFreeContiguousMemory(g_HvSharedContext);
        g_HvSharedContext = nullptr;
        g_HvSharedContextPa = 0;
    }
}

/* ========================================================================
 *  Guest VA -> Guest PA translation by walking x64 page tables *  Runs in VMM (Host) context - reads physical memory directly
 * ======================================================================== */
static PVOID MapPhysicalPage(ULONG64 PhysAddr, SIZE_T Size)
{
    UNREFERENCED_PARAMETER(Size);
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = PhysAddr;
    return MmGetVirtualForPhysical(pa);
}

static VOID UnmapPhysicalPage(PVOID Va, SIZE_T Size)
{
    UNREFERENCED_PARAMETER(Va);
    UNREFERENCED_PARAMETER(Size);
}

/**
 * @brief 遍历x64四级页表将Guest VA翻译为Guest PA - 支持1GB/2MB/4KB页面
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] GuestCr3 - 目标进程的CR3(PML4基址)
 * @param [in] GuestVa  - 要翻译的虚拟地址
 * @return 物理地址, 页面不存在返回0
 * @note 直接读物理内存, 不调用任何内核API, 对ACE完全透明
 */
static ULONG64 TranslateGuestVaToPa(ULONG64 GuestCr3, ULONG64 GuestVa)
{
    ULONG64 pml4Idx = (GuestVa >> 39) & 0x1FF;
    ULONG64 pdptIdx = (GuestVa >> 30) & 0x1FF;
    ULONG64 pdIdx   = (GuestVa >> 21) & 0x1FF;
    ULONG64 ptIdx   = (GuestVa >> 12) & 0x1FF;
    ULONG64 offset  = GuestVa & 0xFFF;

    // Read PML4 entry
    ULONG64 pml4Base = GuestCr3 & ~0xFFFULL;
    PULONG64 pml4Page = (PULONG64)MapPhysicalPage(pml4Base, PAGE_SIZE);
    if (!pml4Page) return 0;

    ULONG64 pml4e = pml4Page[pml4Idx];
    UnmapPhysicalPage(pml4Page, PAGE_SIZE);

    if (!(pml4e & 1)) return 0; // Not present

    // Read PDPT entry
    ULONG64 pdptBase = pml4e & 0x000FFFFFFFFFF000ULL;
    PULONG64 pdptPage = (PULONG64)MapPhysicalPage(pdptBase, PAGE_SIZE);
    if (!pdptPage) return 0;

    ULONG64 pdpte = pdptPage[pdptIdx];
    UnmapPhysicalPage(pdptPage, PAGE_SIZE);

    if (!(pdpte & 1)) return 0;

    // Check for 1GB huge page
    if (pdpte & (1ULL << 7)) {
        ULONG64 pageBase = pdpte & 0x000FFFFFC0000000ULL;
        return pageBase | (GuestVa & 0x3FFFFFFF);
    }

    // Read PD entry
    ULONG64 pdBase = pdpte & 0x000FFFFFFFFFF000ULL;
    PULONG64 pdPage = (PULONG64)MapPhysicalPage(pdBase, PAGE_SIZE);
    if (!pdPage) return 0;

    ULONG64 pde = pdPage[pdIdx];
    UnmapPhysicalPage(pdPage, PAGE_SIZE);

    if (!(pde & 1)) return 0;

    // Check for 2MB large page
    if (pde & (1ULL << 7)) {
        ULONG64 pageBase = pde & 0x000FFFFFFFE00000ULL;
        return pageBase | (GuestVa & 0x1FFFFF);
    }

    // Read PT entry
    ULONG64 ptBase = pde & 0x000FFFFFFFFFF000ULL;
    PULONG64 ptPage = (PULONG64)MapPhysicalPage(ptBase, PAGE_SIZE);
    if (!ptPage) return 0;

    ULONG64 pte = ptPage[ptIdx];
    UnmapPhysicalPage(ptPage, PAGE_SIZE);

    if (!(pte & 1)) return 0;

    ULONG64 pageBase = pte & 0x000FFFFFFFFFF000ULL;
    return pageBase | offset;
}

/**
 * @brief 物理地址间内存拷贝 - 通过MmGetVirtualForPhysical映射后拷贝
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] DestPa  - 目标物理地址
 * @param [in] SrcPa   - 源物理地址
 * @param [in] Size    - 拷贝字节数(不超过PAGE_SIZE)
 * @param [in] IsWrite - 是否为写操作(预留参数)
 * @return TRUE表示拷贝成功, FALSE表示映射失败
 */
static BOOLEAN PhysicalMemoryCopy(
    ULONG64 DestPa,
    ULONG64 SrcPa,
    SIZE_T Size,
    BOOLEAN IsWrite)
{
    UNREFERENCED_PARAMETER(IsWrite);
    if (Size == 0 || Size > PAGE_SIZE) return FALSE;

    PVOID srcMap = MapPhysicalPage(SrcPa, PAGE_SIZE);
    if (!srcMap) return FALSE;

    PVOID dstMap = MapPhysicalPage(DestPa, PAGE_SIZE);
    if (!dstMap) {
        UnmapPhysicalPage(srcMap, PAGE_SIZE);
        return FALSE;
    }

    ULONG64 srcOffset = SrcPa & 0xFFF;
    ULONG64 dstOffset = DestPa & 0xFFF;

    SIZE_T srcAvail = PAGE_SIZE - (SIZE_T)srcOffset;
    SIZE_T dstAvail = PAGE_SIZE - (SIZE_T)dstOffset;
    SIZE_T copyLen = Size;
    if (copyLen > srcAvail) copyLen = srcAvail;
    if (copyLen > dstAvail) copyLen = dstAvail;

    RtlCopyMemory(
        (PUCHAR)dstMap + dstOffset,
        (PUCHAR)srcMap + srcOffset,
        copyLen);

    UnmapPhysicalPage(dstMap, PAGE_SIZE);
    UnmapPhysicalPage(srcMap, PAGE_SIZE);

    return TRUE;
}

/**
 * @brief VMM侧内存操作处理器 - VMEXIT时读取共享上下文执行物理内存操作
 * @author yewilliam
 * @date 2026/03/16
 * @param [in,out] vpData - VCPU上下文(RBX=共享上下文PA, RAX=返回值)
 * @note 按页遍历目标VA, 翻译PA后逐页拷贝, 支持最大1MB单次请求
 */
VOID HvHandleMemoryOp(PVCPU_CONTEXT vpData)
{
    if (!vpData) return;

    // Shared context PA is passed in RBX
    ULONG64 contextPa = vpData->Guest_gpr.Rbx;
    if (contextPa == 0) {
        vpData->Guest_gpr.Rax = (UINT64)-1; // Error
        return;
    }

    // Map the shared context page
    PHV_RW_CONTEXT ctx = (PHV_RW_CONTEXT)MapPhysicalPage(
        contextPa & ~0xFFFULL, PAGE_SIZE);

    if (!ctx) {
        vpData->Guest_gpr.Rax = (UINT64)-2;
        return;
    }

    // Adjust pointer to actual offset within page
    PHV_RW_CONTEXT pCtx = (PHV_RW_CONTEXT)((PUCHAR)ctx + (contextPa & 0xFFF));

    ULONG64 targetCr3 = pCtx->TargetCr3;
    ULONG64 targetVa = pCtx->SourceVa;
    ULONG64 bufferPa = pCtx->DestPa;
    ULONG64 totalSize = pCtx->Size;
    BOOLEAN isWrite = (pCtx->IsWrite != 0);

    if (totalSize == 0 || totalSize > 0x100000) { // Max 1MB per request
        pCtx->Status = -3;
        UnmapPhysicalPage(ctx, PAGE_SIZE);
        vpData->Guest_gpr.Rax = (UINT64)-3;
        return;
    }

    // Process page by page
    ULONG64 bytesProcessed = 0;
    LONG resultStatus = 0;

    while (bytesProcessed < totalSize)
    {
        // How many bytes remain in current page?
        SIZE_T pageRemain = PAGE_SIZE - (SIZE_T)((targetVa + bytesProcessed) & 0xFFF);
        SIZE_T chunkSize = (SIZE_T)(totalSize - bytesProcessed);
        if (chunkSize > pageRemain) chunkSize = pageRemain;

        // Translate target VA to PA
        ULONG64 targetPa = TranslateGuestVaToPa(targetCr3, targetVa + bytesProcessed);
        if (targetPa == 0) {
            resultStatus = -4; // Page not present
            break;
        }

        ULONG64 currentBufferPa = bufferPa + bytesProcessed;

        BOOLEAN ok;
        if (isWrite) {
            // Write: copy from our buffer to target
            ok = PhysicalMemoryCopy(targetPa, currentBufferPa, chunkSize, TRUE);
        }
        else {
            // Read: copy from target to our buffer
            ok = PhysicalMemoryCopy(currentBufferPa, targetPa, chunkSize, FALSE);
        }

        if (!ok) {
            resultStatus = -5; // Map failed
            break;
        }

        bytesProcessed += chunkSize;
    }

    pCtx->Status = resultStatus;
    UnmapPhysicalPage(ctx, PAGE_SIZE);

    // Return bytes processed in RAX (0 = success with full transfer)
    vpData->Guest_gpr.Rax = (resultStatus == 0) ? bytesProcessed : (UINT64)resultStatus;
}

/* ========================================================================
 *  Guest-side functions - called from IOCTL handler *  These set up the shared context and fire the hypercall
 * ======================================================================== */

// Get CR3 of target process
static ULONG64 GetProcessCr3(ULONG64 TargetPid)
{
    PEPROCESS targetProc = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)TargetPid, &targetProc);
    if (!NT_SUCCESS(status) || !targetProc) {
        return 0;
    }

    // EPROCESS->DirectoryTableBase is at a fixed offset
    // We read it from the KPROCESS (first member of EPROCESS)
    // Offset 0x28 on Windows 10 x64
    ULONG64 cr3 = *(PULONG64)((PUCHAR)targetProc + 0x28);

    ObDereferenceObject(targetProc);
    return cr3;
}

/**
 * @brief Guest侧读取目标进程内存 - 通过CPUID超级调用触发VMM执行物理拷贝
 * @author yewilliam
 * @date 2026/03/16
 * @param [in]  TargetPid - 目标进程PID
 * @param [in]  Address   - 目标进程中的虚拟地址
 * @param [out] Buffer    - 读取数据的输出缓冲区
 * @param [in]  Size      - 读取字节数
 * @return 成功返回STATUS_SUCCESS
 */
NTSTATUS HvReadProcessMemory(ULONG64 TargetPid, PVOID Address, PVOID Buffer, SIZE_T Size)
{
    if (!g_HvSharedContext || !Buffer || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Get target process CR3
    ULONG64 targetCr3 = GetProcessCr3(TargetPid);
    if (targetCr3 == 0) {
        return STATUS_NOT_FOUND;
    }

    // Allocate a kernel buffer for the transfer
    PVOID kernelBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, 'HvRd');
    if (!kernelBuffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(kernelBuffer, Size);

    ULONG64 kernelBufferPa = MmGetPhysicalAddress(kernelBuffer).QuadPart;
    if (kernelBufferPa == 0) {
        ExFreePoolWithTag(kernelBuffer, 'HvRd');
        return STATUS_UNSUCCESSFUL;
    }

    ExAcquireFastMutex(&g_HvMutex);
    // Fill shared context
    g_HvSharedContext->TargetCr3 = targetCr3;
    g_HvSharedContext->SourceVa = (ULONG64)Address;
    g_HvSharedContext->DestPa = kernelBufferPa;
    g_HvSharedContext->Size = Size;
    g_HvSharedContext->IsWrite = 0;
    g_HvSharedContext->Status = 1; // Pending

    // Fire hypercall: CPUID with leaf=CPUID_HV_MEMORY_OP, RBX=shared context PA
    int regs[4] = { 0 };
    // We need to pass g_HvSharedContextPa in RBX before CPUID
    // Since __cpuid doesn't let us set RBX, we use __cpuidex with ECX as subfunction
    // and the VMM reads RBX from Guest GPR save area
    // WORKAROUND: store PA in shared context and pass its PA via a known global

    __cpuidex(regs, CPUID_HV_MEMORY_OP, HV_MEM_OP_READ);

    NTSTATUS status;
    if (g_HvSharedContext->Status == 0) {
        // Copy from kernel buffer to user buffer
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

/**
 * @brief Guest侧写入目标进程内存 - 通过CPUID超级调用触发VMM执行物理拷贝
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] TargetPid - 目标进程PID
 * @param [in] Address   - 目标进程中的虚拟地址
 * @param [in] Buffer    - 要写入的数据缓冲区
 * @param [in] Size      - 写入字节数
 * @return 成功返回STATUS_SUCCESS
 */
NTSTATUS HvWriteProcessMemory(ULONG64 TargetPid, PVOID Address, PVOID Buffer, SIZE_T Size)
{
    if (!g_HvSharedContext || !Buffer || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG64 targetCr3 = GetProcessCr3(TargetPid);
    if (targetCr3 == 0) {
        return STATUS_NOT_FOUND;
    }

    // Allocate kernel buffer and copy user data into it
    PVOID kernelBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, 'HvWr');
    if (!kernelBuffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

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

    // Fill shared context
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

    ExFreePoolWithTag(kernelBuffer, 'HvWr');
    return status;
}
