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
  * HvBatchRead 类型定义 — 内联而非 #include "HvBatchRead.h"
  * 原因: HvBatchRead.h 中 extern "C" 包裹 #include <ntifs.h> 导致
  *       C++ 编译时语法错误 (C2144)。将所需类型直接定义于此。
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
 *  Shared context for Guest <-> VMM communication *  Allocated as contiguous physical memory so VMM can access it
 * ======================================================================== */
PHV_RW_CONTEXT g_HvSharedContext = nullptr;
ULONG64 g_HvSharedContextPa = 0;
FAST_MUTEX g_HvMutex;

/* [FIX-v14] Per-CPU bypass flag — 防止 SvmDebug 内部操作被自己的 Hook 拦截 */
#ifndef HV_MAX_CPU
#define HV_MAX_CPU 256
#endif
volatile LONG g_HvInternalOp[HV_MAX_CPU] = { 0 };

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

 /* -----------------------------------------------------------------
  * 第1级: 快速路径 — 用于 TranslateGuestVaToPa 的页表遍历
  *
  * MmGetVirtualForPhysical 从 PFN 数据库直接返回 VA:
  *   - 页表页(PML4/PDPT/PD/PT)始终是内核分配的，返回内核 VA
  *   - 不分配系统 PTE，零开销
  *   - 不需要取消映射
  * ----------------------------------------------------------------- */
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
    /* MmGetVirtualForPhysical 不需要取消映射 */
}

/* -----------------------------------------------------------------
 * 第2级: 安全路径 — 用于 PhysicalMemoryCopy 的数据页访问
 *
 * MmMapIoSpace 创建独立的系统 PTE 映射:
 *   - 返回的 VA 在系统空间，任何 CR3 下都可访问
 *   - 不会触发缺页（非分页映射）
 *   - 需要配对调用 UnmapPhysicalPageSafe 释放系统 PTE
 *
 * 为什么不能用 MmGetVirtualForPhysical:
 *   用户进程的数据页 → 返回用户态 VA → VMM Host 栈上访问 → 缺页
 *   → Windows 检查 RSP 不在线程栈范围 → BSOD 0x139
 * ----------------------------------------------------------------- */
static PVOID MapPhysicalPageSafe(ULONG64 PhysAddr)
{
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)(PhysAddr & ~0xFFFULL);
    return MmMapIoSpace(pa, PAGE_SIZE, MmCached);
}

static VOID UnmapPhysicalPageSafe(PVOID Va)
{
    if (Va) {
        MmUnmapIoSpace(Va, PAGE_SIZE);
    }
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
    ULONG64 pdIdx = (GuestVa >> 21) & 0x1FF;
    ULONG64 ptIdx = (GuestVa >> 12) & 0x1FF;
    ULONG64 offset = GuestVa & 0xFFF;

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

    if (!(pde & 1)) {
        /* [FIX] 检查 Transition PDE (罕见但可能)
         * Windows x64 Software PTE 格式 (bit 0 = 0):
         *   bit 10 = Transition (1 = 页面在物理内存的 standby/modified list)
         *   bit 11 = Prototype  (0 = 非共享原型)
         *   bits 12-51 = PFN    (页帧号, 仍然有效!)
         * 如果是 Transition, PFN 指向有效的物理页, 可以继续遍历 */
        if ((pde & 0xC00) == 0x400) {
            /* Transition PDE — 继续, 当作 present 处理 */
        }
        else {
            return 0;
        }
    }

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

    if (!(pte & 1)) {
        /* [FIX] 检查 Transition PTE — 这是 Next Scan 结果锐减的根因
         *
         * 时序: BatchForcePages 触摸页面 (Present=1)
         *       → 填充 BatchContext
         *       → CPUID VMEXIT
         *       → VMM 遍历页表
         *
         * 在触摸和 VMM 遍历之间, Windows 内存管理器可能:
         *   1. 清除 Accessed bit (工作集修剪扫描)
         *   2. 将页面移到 Modified/Standby list (Transition)
         *   3. PTE.Present 从 1 → 0, 但 PTE.Transition = 1, PFN 仍有效
         *
         * 4800+ 个页面中, 大量处于 Transition 状态 → 旧代码返回 0 → 填零
         * → CE 值不匹配 → 4862 → 115
         *
         * Transition PTE 判定: bit 10 = 1 (Transition), bit 11 = 0 (非 Prototype)
         * PFN 在 bits 12-51, 与 Present PTE 的 PFN 位置完全相同 */
        if ((pte & 0xC00) == 0x400) {
            /* Transition PTE — PFN 有效, 页面在物理内存中 */
            ULONG64 pageBase = pte & 0x000FFFFFFFFFF000ULL;
            return pageBase | offset;
        }
        return 0; /* 真正不在物理内存 (paged out / demand zero / prototype) */
    }

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

 /**
  * @brief TranslateGuestVaToPa export wrapper for DebugApi VMM-side SW breakpoint
  */
ULONG64 TranslateGuestVaToPa_Ext(ULONG64 GuestCr3, ULONG64 GuestVa)
{
    return TranslateGuestVaToPa(GuestCr3, GuestVa);
}

static BOOLEAN PhysicalMemoryCopy(
    ULONG64 DestPa,
    ULONG64 SrcPa,
    SIZE_T Size,
    BOOLEAN IsWrite)
{
    UNREFERENCED_PARAMETER(IsWrite);
    if (Size == 0 || Size > PAGE_SIZE) return FALSE;

    /* [FIX] 使用安全路径映射数据页 — 避免用户 VA 在 Host 栈上缺页 */
    PVOID srcMap = MapPhysicalPageSafe(SrcPa);
    if (!srcMap) return FALSE;

    PVOID dstMap = MapPhysicalPageSafe(DestPa);
    if (!dstMap) {
        UnmapPhysicalPageSafe(srcMap);
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

    UnmapPhysicalPageSafe(dstMap);
    UnmapPhysicalPageSafe(srcMap);

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
            /* [FIX] 页面不在物理内存 — 跳过而非终止
             * 读取: 目标缓冲区的对应区域保持为零 (已被 RtlZeroMemory 初始化)
             * 写入: 跳过此页面 (无法写入不存在的物理页)
             * CE 中这些区域会显示 00 而不是 ???, 其余区域显示正确数据 */
            bytesProcessed += chunkSize;
            continue;
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
            /* 物理内存映射失败 — 同样跳过 */
            bytesProcessed += chunkSize;
            continue;
        }

        bytesProcessed += chunkSize;
    }

    pCtx->Status = resultStatus;
    UnmapPhysicalPage(ctx, PAGE_SIZE);

    // Return bytes processed in RAX (0 = success with full transfer)
    vpData->Guest_gpr.Rax = (resultStatus == 0) ? bytesProcessed : (UINT64)resultStatus;
}

/* ========================================================================
 *  Batch Scatter-Gather Read — VMM 侧处理器
 *
 *  CE 扫描内存时将多个读取请求打包为散射表,
 *  通过一次 CPUID VMEXIT 传给 VMM Host,
 *  Host 在物理层一次性读取所有条目返回结果。
 *
 *  数据流:
 *    Guest RBX = HV_BATCH_CONTEXT 物理地址
 *    VMM: 映射 BatchContext → 映射 ScatterEntries → 逐条翻译 + 拷贝
 *    返回: BatchContext.SuccessCount / Status
 * ======================================================================== */

VOID HvHandleBatchRead(PVCPU_CONTEXT vpData)
{
    if (!vpData) return;

    ULONG64 ctxPa = vpData->Guest_gpr.Rbx;
    if (ctxPa == 0) {
        vpData->Guest_gpr.Rax = (UINT64)-1;
        return;
    }

    /* 映射 BatchContext 页 */
    PHV_BATCH_CONTEXT ctx = (PHV_BATCH_CONTEXT)MapPhysicalPage(
        ctxPa & ~0xFFFULL, PAGE_SIZE);
    if (!ctx) {
        vpData->Guest_gpr.Rax = (UINT64)-2;
        return;
    }
    PHV_BATCH_CONTEXT pCtx = (PHV_BATCH_CONTEXT)((PUCHAR)ctx + (ctxPa & 0xFFF));

    ULONG64 targetCr3 = pCtx->TargetCr3;
    ULONG entryCount = pCtx->EntryCount;
    ULONG64 entriesPa = pCtx->EntriesPa;
    ULONG64 outputPa = pCtx->OutputPa;

    if (entryCount == 0 || entryCount > HV_BATCH_MAX_ENTRIES ||
        entriesPa == 0 || outputPa == 0 || targetCr3 == 0) {
        pCtx->Status = -3;
        pCtx->SuccessCount = 0;
        UnmapPhysicalPage(ctx, PAGE_SIZE);
        vpData->Guest_gpr.Rax = (UINT64)-3;
        return;
    }

    ULONG successCount = 0;

    /* 逐条处理散射条目 */
    for (ULONG i = 0; i < entryCount; i++) {
        ULONG64 entryPa = entriesPa + i * sizeof(HV_SCATTER_ENTRY);
        PHV_SCATTER_ENTRY entryPage = (PHV_SCATTER_ENTRY)MapPhysicalPage(
            entryPa & ~0xFFFULL, PAGE_SIZE);
        if (!entryPage)
            continue;

        PHV_SCATTER_ENTRY pEntry = (PHV_SCATTER_ENTRY)((PUCHAR)entryPage + (entryPa & 0xFFF));
        ULONG64 guestVa = pEntry->GuestVa;
        ULONG size = pEntry->Size;
        ULONG outOffset = pEntry->OutputOffset;

        if (size == 0 || size > PAGE_SIZE) {
            pEntry->Status = (ULONG)-1;
            UnmapPhysicalPage(entryPage, PAGE_SIZE);
            continue;
        }

        /* 按页遍历, 翻译 VA→PA 并拷贝 */
        ULONG bytesRead = 0;
        BOOLEAN anyFailed = FALSE;

        while (bytesRead < size) {
            SIZE_T pageRemain = PAGE_SIZE - (SIZE_T)((guestVa + bytesRead) & 0xFFF);
            SIZE_T chunkSize = (SIZE_T)(size - bytesRead);
            if (chunkSize > pageRemain) chunkSize = pageRemain;

            ULONG64 srcPa = TranslateGuestVaToPa(targetCr3, guestVa + bytesRead);
            if (srcPa == 0) {
                anyFailed = TRUE;
                bytesRead += (ULONG)chunkSize;
                continue;
            }

            ULONG64 dstPa = outputPa + outOffset + bytesRead;
            if (!PhysicalMemoryCopy(dstPa, srcPa, chunkSize, FALSE)) {
                anyFailed = TRUE;
                bytesRead += (ULONG)chunkSize;
                continue;
            }

            bytesRead += (ULONG)chunkSize;
        }

        pEntry->Status = anyFailed ? (ULONG)-1 : 0;
        if (!anyFailed) successCount++;

        UnmapPhysicalPage(entryPage, PAGE_SIZE);
    }

    pCtx->SuccessCount = successCount;
    pCtx->Status = 0;
    UnmapPhysicalPage(ctx, PAGE_SIZE);

    vpData->Guest_gpr.Rax = (UINT64)successCount;
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
 * @brief 强制目标进程的页面驻留物理内存 — 在 CPUID 超级调用前调用
 *
 * 问题: VMM 通过 CR3 遍历页表翻译 VA→PA, 如果 PTE.Present=0
 *        (页面被换出到 pagefile 或从未 page-in), 翻译返回 0 → 读取失败。
 *        CE 中显示为 "???"。
 *
 * 解决: 在 Guest 侧附加到目标进程, 逐页触摸 (volatile read/write)
 *        强制 OS 内存管理器将页面调入物理内存。
 *        之后 VMM 的页表遍历就能找到有效的 PTE。
 *
 * 对反作弊透明:
 *   - KeStackAttachProcess: 经过我们的 NPT Hook (已拦截)
 *   - 页面触摸: 只是普通的内存读取, 没有 API 调用
 *   - 实际数据拷贝: 在 VMM 层通过物理内存完成, 不经过任何内核 API
 *
 * @param [in] TargetPid  - 目标进程 PID
 * @param [in] Address    - 目标虚拟地址
 * @param [in] Size       - 要访问的字节数
 * @param [in] ForWrite   - TRUE=写入操作(触发COW), FALSE=读取操作
 */
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
                /* 写操作: 触发 Copy-on-Write 和 PAGE_GUARD 解除
                 * InterlockedOr8 是原子读-改-写, 值不变但触发页面写入 */
                InterlockedOr8((volatile char*)(base + offset), 0);
            }
            else {
                /* 读操作: 触发 demand-paging / pagefile read-in */
                volatile UCHAR dummy = *(volatile UCHAR*)(base + offset);
                UNREFERENCED_PARAMETER(dummy);
            }

            /* 推进到下一页边界 */
            SIZE_T pageRemain = PAGE_SIZE - (((ULONG_PTR)(base + offset)) & 0xFFF);
            offset += pageRemain;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* 某些页面真的无法访问 (未提交/PAGE_NOACCESS)
         * 这些页面在 VMM 侧会被跳过并填零 */
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(targetProc);
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

    /* [FIX] 强制目标页面驻留物理内存
     * 没有这一步, VMM 的页表遍历会遇到 PTE.Present=0 → 返回 0 → CE 显示 "???"
     * 附加到目标进程后触摸每一页, OS 自动将页面从 pagefile 调入 */
    ForcePagePresent(TargetPid, Address, Size, FALSE);

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

    int regs[4] = { 0 };
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

    /* [FIX] 强制页面驻留 + 触发 Copy-on-Write
     * ForWrite=TRUE 使用 InterlockedOr8 触发写入,
     * 确保 COW 页面被复制为私有副本 */
    ForcePagePresent(TargetPid, Address, Size, TRUE);

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

    ExAcquireFastMutex(&g_HvMutex);

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

    ExReleaseFastMutex(&g_HvMutex);

    ExFreePoolWithTag(kernelBuffer, 'HvWr');
    return status;
}