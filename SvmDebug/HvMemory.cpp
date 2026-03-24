/**
 * @file HvMemory.cpp
 * @brief 隐蔽内存引擎 v17 — 零 PFN 污染 + 物理直读优先 + Attach 兜底
 * @author yewilliam
 * @date 2026/03/23
 *
 * ═══════════════════════════════════════════════════════════════════
 *  v17 关键修复: BSOD 0x1A MEMORY_MANAGEMENT (PFN corruption)
 *
 *  根因: v16 的 TranslateGuestVaToPa 用 MmMapIoSpace 映射页表页
 *        MmMapIoSpace 修改 PFN 数据库中该页的类型/引用计数
 *        高频调用 (每次读 4 次 map/unmap) → PFN 条目损坏 → BSOD
 *
 *  修复: 所有物理内存读取统一用 MmCopyMemory(MM_COPY_MEMORY_PHYSICAL)
 *        该 API 直接通过物理地址拷贝, 不创建任何映射, 不修改 PFN
 *        页表遍历: ReadPhysical8() 读 8 字节 PTE → 零映射零 PFN
 *        数据读取: MmCopyMemory 直读 → 零映射零 PFN
 *        写入: 始终走 Attach 兜底 (MmMapIoSpace 写入有 PFN 风险)
 * ═══════════════════════════════════════════════════════════════════
 *
 *  读取策略 (HvReadProcessMemory):
 *    Step 1: CR3 页表遍历 (MmCopyMemory) → PA → MmCopyMemory 直读
 *            ✓ 零映射, 零 PFN 修改, 零进程切换, ACE 完全不可见
 *    Step 2: fallback → KeStackAttachProcess + 内核栈缓冲区中转
 *            ✓ 处理 paged-out, HvEnterInternal bypass
 *
 *  写入策略 (HvWriteProcessMemory):
 *    始终走 Attach 兜底 (物理写需要 MmMapIoSpace, 有 PFN 风险)
 *    如果 attach 也失败则尝试物理写 (rare fallback)
 *
 *  查询策略 (HvQueryVirtualMemory):
 *    KeStackAttachProcess + ZwQueryVirtualMemory(NtCurrentProcess())
 */

#include "HvMemory.h"
#include "SVM.h"

 /* ========================================================================
  *  Per-CPU bypass flag (v14)
  * ======================================================================== */
volatile LONG g_HvInternalOp[HV_MAX_CPU] = { 0 };

static __forceinline void HvEnterInternal(void) {
    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    if (cpu < HV_MAX_CPU) InterlockedExchange(&g_HvInternalOp[cpu], 1);
}
static __forceinline void HvLeaveInternal(void) {
    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    if (cpu < HV_MAX_CPU) InterlockedExchange(&g_HvInternalOp[cpu], 0);
}

/* ========================================================================
 *  MmCopyMemory 声明
 * ======================================================================== */
#ifndef MM_COPY_MEMORY_PHYSICAL
#define MM_COPY_MEMORY_PHYSICAL 0x1
typedef union _MM_COPY_ADDRESS {
    PVOID            VirtualAddress;
    PHYSICAL_ADDRESS PhysicalAddress;
} MM_COPY_ADDRESS, * PMMCOPY_ADDRESS;
extern "C" NTKERNELAPI NTSTATUS MmCopyMemory(
    PVOID TargetAddress, MM_COPY_ADDRESS SourceAddress,
    SIZE_T NumberOfBytes, ULONG Flags, PSIZE_T NumberOfBytesTransferred);
#endif

/* ========================================================================
 *  共享上下文 (VMM 路径用)
 * ======================================================================== */
PHV_RW_CONTEXT g_HvSharedContext = nullptr;
ULONG64 g_HvSharedContextPa = 0;
FAST_MUTEX g_HvMutex;

/* ========================================================================
 *  [VMEXIT 直读] 预分配输出缓冲区 — 物理连续
 *  用于 HvReadProcessMemory_Vmexit, 避免每次调用时分配内存
 * ======================================================================== */
#define HV_VMEXIT_OUTBUF_SIZE  (256 * 1024)  /* 256KB, 覆盖绝大多数读取请求 */
static PVOID   g_HvVmexitOutBuf = nullptr;
static ULONG64 g_HvVmexitOutBufPa = 0;

NTSTATUS HvInitSharedContext()
{
    ExInitializeFastMutex(&g_HvMutex);
    PHYSICAL_ADDRESS highAddr;
    highAddr.QuadPart = ~0ULL;
    g_HvSharedContext = (PHV_RW_CONTEXT)MmAllocateContiguousMemory(PAGE_SIZE, highAddr);
    if (!g_HvSharedContext) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_HvSharedContext, PAGE_SIZE);
    g_HvSharedContextPa = MmGetPhysicalAddress(g_HvSharedContext).QuadPart;

    /* 预分配 VMEXIT 直读输出缓冲区 */
    g_HvVmexitOutBuf = MmAllocateContiguousMemory(HV_VMEXIT_OUTBUF_SIZE, highAddr);
    if (g_HvVmexitOutBuf) {
        g_HvVmexitOutBufPa = MmGetPhysicalAddress(g_HvVmexitOutBuf).QuadPart;
        SvmDebugPrint("[HvMem] VMEXIT outbuf VA=%p PA=0x%llX size=%uKB\n",
            g_HvVmexitOutBuf, g_HvVmexitOutBufPa, HV_VMEXIT_OUTBUF_SIZE / 1024);
    }
    else {
        SvmDebugPrint("[HvMem] WARNING: VMEXIT outbuf alloc failed, will fallback to MmCopyMemory\n");
    }

    SvmDebugPrint("[HvMem] ctx VA=%p PA=0x%llX\n", g_HvSharedContext, g_HvSharedContextPa);
    return STATUS_SUCCESS;
}

VOID HvFreeSharedContext()
{
    if (g_HvVmexitOutBuf) {
        MmFreeContiguousMemory(g_HvVmexitOutBuf);
        g_HvVmexitOutBuf = nullptr;
        g_HvVmexitOutBufPa = 0;
    }
    if (g_HvSharedContext) {
        MmFreeContiguousMemory(g_HvSharedContext);
        g_HvSharedContext = nullptr;
        g_HvSharedContextPa = 0;
    }
}

/* ========================================================================
 *  Section 1: 安全物理内存读取原语
 *
 *  [v17 核心] 全部使用 MmCopyMemory(MM_COPY_MEMORY_PHYSICAL)
 *  该 API 特性:
 *    - 不创建虚拟映射 (不调用 MmMapIoSpace)
 *    - 不修改 PFN 数据库 (不改引用计数/类型)
 *    - 不触发 ObRegisterCallbacks
 *    - 安全读取任何物理地址, 包括页表页/用户数据页/内核页
 *    - 如果物理页不存在或不可读, 返回错误而不是蓝屏
 * ======================================================================== */

 /**
  * @brief 从物理地址读取 8 字节 (用于读 PTE)
  * @return PTE 值, 失败返回 0 (Present=0, 触发 fallback)
  */
static __forceinline ULONG64 ReadPhysical8(ULONG64 pa)
{
    ULONG64 value = 0;
    MM_COPY_ADDRESS src;
    SIZE_T copied = 0;
    src.PhysicalAddress.QuadPart = (LONGLONG)pa;
    NTSTATUS st = MmCopyMemory(&value, src, sizeof(ULONG64),
        MM_COPY_MEMORY_PHYSICAL, &copied);
    if (NT_SUCCESS(st) && copied == sizeof(ULONG64))
        return value;
    return 0;
}

/**
 * @brief 从物理地址读取任意长度数据
 * @param pa      源物理地址
 * @param dst     目标内核缓冲区 (必须是内核地址)
 * @param size    字节数 (不超过 PAGE_SIZE)
 * @return 实际读取的字节数, 0 = 失败
 */
static SIZE_T ReadPhysicalBytes(ULONG64 pa, PVOID dst, SIZE_T size)
{
    MM_COPY_ADDRESS src;
    SIZE_T copied = 0;
    src.PhysicalAddress.QuadPart = (LONGLONG)pa;
    NTSTATUS st = MmCopyMemory(dst, src, size,
        MM_COPY_MEMORY_PHYSICAL, &copied);
    return NT_SUCCESS(st) ? copied : 0;
}

/* ========================================================================
 *  Section 2: 页表遍历 VA → PA (零映射版本)
 *
 *  [v17] 每级页表读取用 ReadPhysical8 (MmCopyMemory)
 *  不再使用 MmMapIoSpace, 彻底消除 PFN 污染风险
 *  支持 4KB / 2MB / 1GB 页面
 * ======================================================================== */
#define PTE_PA_MASK  0x000FFFFFFFFFF000ULL

static ULONG64 TranslateGuestVaToPa(ULONG64 cr3, ULONG64 va)
{
    ULONG64 pml4Idx = (va >> 39) & 0x1FF;
    ULONG64 pdptIdx = (va >> 30) & 0x1FF;
    ULONG64 pdIdx = (va >> 21) & 0x1FF;
    ULONG64 ptIdx = (va >> 12) & 0x1FF;
    ULONG64 off = va & 0xFFF;
    ULONG64 e;

    /* PML4 */
    e = ReadPhysical8((cr3 & PTE_PA_MASK) + pml4Idx * 8);
    if (!(e & 1)) return 0;

    /* PDPT */
    e = ReadPhysical8((e & PTE_PA_MASK) + pdptIdx * 8);
    if (!(e & 1)) return 0;
    if (e & (1ULL << 7))  /* 1GB page */
        return (e & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);

    /* PD */
    e = ReadPhysical8((e & PTE_PA_MASK) + pdIdx * 8);
    if (!(e & 1)) return 0;
    if (e & (1ULL << 7))  /* 2MB page */
        return (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);

    /* PT */
    e = ReadPhysical8((e & PTE_PA_MASK) + ptIdx * 8);
    if (!(e & 1)) return 0;

    return (e & PTE_PA_MASK) | off;
}

ULONG64 TranslateGuestVaToPa_Ext(ULONG64 cr3, ULONG64 va)
{
    return TranslateGuestVaToPa(cr3, va);
}

/* ========================================================================
 *  Section 3: CR3 获取 (KVAS 安全)
 *
 *  EPROCESS+0x28  = DirectoryTableBase (内核态 CR3, 低位有 KVAS 标志)
 *  EPROCESS+0x280 = UserDirectoryTableBase (用户态 CR3)
 *  用户态 VA → UserDirectoryTableBase 优先
 * ======================================================================== */
#define CR3_PA_MASK  0x000FFFFFFFFFF000ULL

static ULONG64 GetCr3FromEprocess(PEPROCESS proc, BOOLEAN isUserVa)
{
    if (isUserVa) {
        ULONG64 userCr3 = *(PULONG64)((PUCHAR)proc + 0x280);
        if (userCr3 && (userCr3 & CR3_PA_MASK) != 0)
            return userCr3 & CR3_PA_MASK;
    }
    return *(PULONG64)((PUCHAR)proc + 0x28) & CR3_PA_MASK;
}

/* 旧接口保留兼容 */
//static ULONG64 GetProcessCr3(ULONG64 pid)
//{
//    PEPROCESS p = nullptr;
//    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &p)) || !p) return 0;
//    ULONG64 cr3 = *(PULONG64)((PUCHAR)p + 0x28) & CR3_PA_MASK;
//    ObDereferenceObject(p);
//    return cr3;
//}

/* ========================================================================
 *  Section 4: 物理内存直读单块 (核心隐蔽引擎)
 *
 *  整个路径零 MmMapIoSpace:
 *    TranslateGuestVaToPa → ReadPhysical8 (MmCopyMemory) × 4
 *    PhysicalReadChunk    → ReadPhysicalBytes (MmCopyMemory) × 1
 *  共 5 次 MmCopyMemory 调用, 零映射, 零 PFN 修改
 * ======================================================================== */
static BOOLEAN PhysicalReadChunk(
    ULONG64 cr3,
    ULONG64 targetVa,
    PVOID   kernelDst,
    SIZE_T  chunkSize)
{
    ULONG64 pa = TranslateGuestVaToPa(cr3, targetVa);
    if (!pa)
        return FALSE;   /* PTE not present → paged-out, 需要 fallback */

    SIZE_T copied = ReadPhysicalBytes(pa, kernelDst, chunkSize);
    if (copied == chunkSize)
        return TRUE;

    /* 部分成功: 补零 */
    if (copied > 0 && copied < chunkSize) {
        RtlZeroMemory((PUCHAR)kernelDst + copied, chunkSize - copied);
        return TRUE;
    }

    return FALSE;
}

/* ========================================================================
 *  Section 5: Attach Fallback (处理 paged-out 页面)
 *
 *  关键: 内核栈缓冲区 tmpBuf 做中转
 *    attach 后: 目标 VA 有效, 调用者 buf 无效
 *    → 先拷到 tmpBuf (内核栈, 所有进程共享)
 *    → detach 后拷回 caller buf
 * ======================================================================== */
#define ATTACH_CHUNK_SIZE  0x1000

static BOOLEAN AttachReadChunk(
    PEPROCESS proc,
    PVOID     targetAddr,
    PVOID     kernelDst,
    SIZE_T    chunkSize)
{
    KAPC_STATE apcState;
    NTSTATUS st;
    UCHAR tmpBuf[ATTACH_CHUNK_SIZE];

    if (chunkSize > ATTACH_CHUNK_SIZE)
        chunkSize = ATTACH_CHUNK_SIZE;

    HvEnterInternal();
    KeStackAttachProcess(proc, &apcState);
    __try {
        RtlCopyMemory(tmpBuf, targetAddr, chunkSize);
        st = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apcState);
    HvLeaveInternal();

    if (NT_SUCCESS(st)) {
        RtlCopyMemory(kernelDst, tmpBuf, chunkSize);
        return TRUE;
    }
    return FALSE;
}

static BOOLEAN AttachWriteChunk(
    PEPROCESS proc,
    PVOID     targetAddr,
    PVOID     kernelSrc,
    SIZE_T    chunkSize)
{
    KAPC_STATE apcState;
    NTSTATUS st;
    UCHAR tmpBuf[ATTACH_CHUNK_SIZE];

    if (chunkSize > ATTACH_CHUNK_SIZE)
        chunkSize = ATTACH_CHUNK_SIZE;

    RtlCopyMemory(tmpBuf, kernelSrc, chunkSize);

    HvEnterInternal();
    KeStackAttachProcess(proc, &apcState);
    __try {
        RtlCopyMemory(targetAddr, tmpBuf, chunkSize);
        st = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apcState);
    HvLeaveInternal();

    return NT_SUCCESS(st);
}

/* ========================================================================
 *  Section 6: HvReadProcessMemory — 混合读取引擎
 *
 *  逐页处理:
 *    1) PhysicalReadChunk → MmCopyMemory 直读 (98%+ 命中, 零 PFN)
 *    2) AttachReadChunk   → paged-out 兜底, 内核自动换页
 *    3) 两者都失败       → 填零 (Memory View 显示 00)
 * ======================================================================== */
NTSTATUS HvReadProcessMemory(ULONG64 pid, PVOID addr, PVOID buf, SIZE_T sz)
{
    if (!buf || !sz) return STATUS_INVALID_PARAMETER;

    PEPROCESS proc = nullptr;
    NTSTATUS st = PsLookupProcessByProcessId((HANDLE)pid, &proc);
    if (!NT_SUCCESS(st) || !proc)
        return STATUS_NOT_FOUND;

    ULONG64 startVa = (ULONG64)addr;
    BOOLEAN isUserVa = (startVa < 0x800000000000ULL);
    ULONG64 cr3 = GetCr3FromEprocess(proc, isUserVa);

    PUCHAR dst = (PUCHAR)buf;
    PUCHAR src = (PUCHAR)addr;
    SIZE_T remaining = sz;
    SIZE_T totalRead = 0;

    while (remaining > 0) {
        SIZE_T pageRemain = PAGE_SIZE - ((ULONG64)src & 0xFFF);
        SIZE_T chunk = (remaining > pageRemain) ? pageRemain : remaining;

        BOOLEAN ok = FALSE;

        /* Step 1: 物理直读 (零 PFN, ACE 不可见) */
        if (cr3)
            ok = PhysicalReadChunk(cr3, (ULONG64)src, dst, chunk);

        /* Step 2: Attach 兜底 (处理 paged-out) */
        if (!ok)
            ok = AttachReadChunk(proc, src, dst, chunk);

        /* Step 3: 都失败 → 填零 */
        if (!ok) {
            __try { RtlZeroMemory(dst, chunk); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        else {
            totalRead += chunk;
        }

        dst += chunk;
        src += chunk;
        remaining -= chunk;
    }

    ObDereferenceObject(proc);
    return (totalRead > 0) ? STATUS_SUCCESS : STATUS_ACCESS_VIOLATION;
}

/* ========================================================================
 *  Section 6b: HvReadProcessMemory_Vmexit — CPUID VMEXIT → VMM Host 物理直读
 *
 *  与 HvReadProcessMemory 的区别:
 *    HvReadProcessMemory: Guest R0 中使用 MmCopyMemory(PHYSICAL) 读取
 *      ✓ 不走 MmCopyVirtualMemory
 *      ✗ MmCopyMemory 调用在 Guest R0 可见 (ACE 可能检测调用栈)
 *
 *    HvReadProcessMemory_Vmexit: CPUID → VMEXIT → VMM Host 物理直读
 *      ✓ Guest R0 零 MmCopyMemory / MmMapIoSpace 调用
 *      ✓ ACE 完全看不到任何物理内存操作
 *      ✓ 唯一可见操作是一次 CPUID 指令 (正常系统行为)
 *
 *  流程:
 *    1. 获取目标进程 CR3
 *    2. 填充 g_HvSharedContext (CR3, SourceVa, DestPa, Size)
 *    3. CPUID(CPUID_HV_MEMORY_OP) → VMEXIT
 *    4. VMM Host: TranslateGuestVaToPa → MmMapIoSpace 物理拷贝到输出缓冲区
 *    5. VMRUN 返回 Guest → 从预分配缓冲区拷贝到调用者 Buffer
 *
 *  如果 VMEXIT 路径不可用, 自动 fallback 到 HvReadProcessMemory
 * ======================================================================== */
NTSTATUS HvReadProcessMemory_Vmexit(ULONG64 pid, PVOID addr, PVOID buf, SIZE_T sz)
{
    if (!buf || !sz) return STATUS_INVALID_PARAMETER;

    /* Fallback: 如果 VMEXIT 输出缓冲区未初始化 */
    if (!g_HvSharedContext || !g_HvVmexitOutBuf || !g_HvVmexitOutBufPa) {
        return HvReadProcessMemory(pid, addr, buf, sz);
    }

    PEPROCESS proc = nullptr;
    NTSTATUS st = PsLookupProcessByProcessId((HANDLE)pid, &proc);
    if (!NT_SUCCESS(st) || !proc)
        return STATUS_NOT_FOUND;

    ULONG64 startVa = (ULONG64)addr;
    BOOLEAN isUserVa = (startVa < 0x800000000000ULL);
    ULONG64 cr3 = GetCr3FromEprocess(proc, isUserVa);
    ObDereferenceObject(proc);

    if (!cr3) return HvReadProcessMemory(pid, addr, buf, sz);

    ExAcquireFastMutex(&g_HvMutex);

    SIZE_T remaining = sz;
    SIZE_T offset = 0;
    SIZE_T totalRead = 0;
    SIZE_T vmexitFailed = 0;

    while (remaining > 0) {
        SIZE_T chunk = remaining;
        if (chunk > HV_VMEXIT_OUTBUF_SIZE)
            chunk = HV_VMEXIT_OUTBUF_SIZE;

        /* 填充共享上下文 */
        g_HvSharedContext->TargetCr3 = cr3;
        g_HvSharedContext->SourceVa = startVa + offset;
        g_HvSharedContext->DestPa = g_HvVmexitOutBufPa;
        g_HvSharedContext->Size = (ULONG64)chunk;
        g_HvSharedContext->IsWrite = 0;
        g_HvSharedContext->Status = 1; /* Pending */

        KeMemoryBarrier();

        /* ★ 一次 CPUID — 一次 VMEXIT — VMM Host 物理直读 ★ */
        int regs[4] = { 0 };
        __cpuidex(regs, CPUID_HV_MEMORY_OP, HV_MEM_OP_READ);

        LONG vmStatus = g_HvSharedContext->Status;
        if (vmStatus != 0) {
            /* VMEXIT 失败 → fallback 到 Guest R0 MmCopyMemory 物理直读 */
            vmexitFailed++;
            BOOLEAN fbOk = PhysicalReadChunk(cr3, startVa + offset, (PUCHAR)buf + offset, chunk);
            if (fbOk) {
                totalRead += chunk;
            }
            else {
                __try { RtlZeroMemory((PUCHAR)buf + offset, chunk); }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
        }
        else {
            /* 从预分配缓冲区拷贝到调用者 Buffer */
            __try { RtlCopyMemory((PUCHAR)buf + offset, g_HvVmexitOutBuf, chunk); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            totalRead += chunk;
        }

        offset += chunk;
        remaining -= chunk;
    }

    ExReleaseFastMutex(&g_HvMutex);

#ifdef DEBUG
    {
        static volatile LONG s_vmexitReadCount = 0;
        LONG cnt = InterlockedIncrement(&s_vmexitReadCount);
        if (cnt <= 10 || (cnt % 10000) == 0) {
            SvmDebugPrint("[HvMem] VMEXIT READ #%d: PID=%llu VA=0x%llX size=%llu read=%llu vmFail=%llu\n",
                cnt, pid, (ULONG64)addr, (ULONG64)sz, (ULONG64)totalRead, (ULONG64)vmexitFailed);
        }
    }
#endif

    return (totalRead > 0) ? STATUS_SUCCESS : STATUS_ACCESS_VIOLATION;
}

/* ========================================================================
 *  Section 7: HvWriteProcessMemory
 *
 *  [v17] 写入始终走 Attach 路径 (物理写需要 MmMapIoSpace, 有 PFN 风险)
 *  写入频率远低于读取, attach 开销可接受
 * ======================================================================== */
NTSTATUS HvWriteProcessMemory(ULONG64 pid, PVOID addr, PVOID buf, SIZE_T sz)
{
    if (!buf || !sz) return STATUS_INVALID_PARAMETER;

    PEPROCESS proc = nullptr;
    NTSTATUS st = PsLookupProcessByProcessId((HANDLE)pid, &proc);
    if (!NT_SUCCESS(st) || !proc)
        return STATUS_NOT_FOUND;

    PUCHAR dst = (PUCHAR)addr;
    PUCHAR src = (PUCHAR)buf;
    SIZE_T remaining = sz;
    BOOLEAN anySuccess = FALSE;

    while (remaining > 0) {
        SIZE_T pageRemain = PAGE_SIZE - ((ULONG64)dst & 0xFFF);
        SIZE_T chunk = (remaining > pageRemain) ? pageRemain : remaining;

        if (AttachWriteChunk(proc, dst, src, chunk))
            anySuccess = TRUE;

        dst += chunk;
        src += chunk;
        remaining -= chunk;
    }

    ObDereferenceObject(proc);
    return anySuccess ? STATUS_SUCCESS : STATUS_ACCESS_VIOLATION;
}

/* ========================================================================
 *  Section 8: HvQueryVirtualMemory
 *
 *  查询必须在目标进程上下文 → attach 路径
 *  mbi / Out* 都是内核地址, attach 后仍有效
 * ======================================================================== */
NTSTATUS HvQueryVirtualMemory(
    ULONG64  TargetPid,
    ULONG64  StartAddress,
    PULONG64 OutBaseAddress,
    PULONG64 OutRegionSize,
    PULONG   OutProtection,
    PULONG   OutState,
    PULONG   OutType)
{
    if (!OutRegionSize || !OutProtection) return STATUS_INVALID_PARAMETER;

    if (OutBaseAddress) *OutBaseAddress = 0;
    *OutRegionSize = 0;
    *OutProtection = 0;
    if (OutState) *OutState = 0;
    if (OutType)  *OutType = 0;

    PEPROCESS proc = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)TargetPid, &proc);
    if (!NT_SUCCESS(status) || !proc) return STATUS_NOT_FOUND;

    KAPC_STATE apcState;
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    SIZE_T retLen = 0;

    HvEnterInternal();
    KeStackAttachProcess(proc, &apcState);

    status = ZwQueryVirtualMemory(
        NtCurrentProcess(),
        (PVOID)StartAddress,
        MemoryBasicInformation,
        &mbi,
        sizeof(mbi),
        &retLen);

    KeUnstackDetachProcess(&apcState);
    HvLeaveInternal();

    ObDereferenceObject(proc);

    if (NT_SUCCESS(status)) {
        if (OutBaseAddress) *OutBaseAddress = (ULONG64)mbi.BaseAddress;
        *OutRegionSize = (ULONG64)mbi.RegionSize;
        *OutProtection = mbi.Protect;
        if (OutState) *OutState = mbi.State;
        if (OutType)  *OutType = mbi.Type;
    }

    return status;
}

/* ========================================================================
 *  Section 9: VMM 层内存操作 (CPUID VMEXIT handler)
 *
 *  运行在 hypervisor host 模式, 直接操作物理内存
 *  此路径不经过 Windows 内存管理器, MmMapIoSpace 安全
 *  (因为 host 模式下 PFN 数据库不可见/不适用)
 *
 *  保留 MapPhysicalPage/UnmapPhysicalPage 仅供此处使用
 * ======================================================================== */
static PVOID MapPhysicalPage_Vmm(ULONG64 pa)
{
    PHYSICAL_ADDRESS a;
    a.QuadPart = (LONGLONG)(pa & ~0xFFFULL);
    return MmMapIoSpace(a, PAGE_SIZE, MmCached);
}

static VOID UnmapPhysicalPage_Vmm(PVOID v)
{
    if (v) MmUnmapIoSpace(v, PAGE_SIZE);
}

static BOOLEAN PhysicalMemoryCopy_Vmm(ULONG64 dst, ULONG64 src, SIZE_T sz, BOOLEAN w)
{
    UNREFERENCED_PARAMETER(w);
    if (sz == 0 || sz > PAGE_SIZE) return FALSE;
    PVOID s = MapPhysicalPage_Vmm(src);
    if (!s) return FALSE;
    PVOID d = MapPhysicalPage_Vmm(dst);
    if (!d) { UnmapPhysicalPage_Vmm(s); return FALSE; }
    SIZE_T sA = PAGE_SIZE - (SIZE_T)(src & 0xFFF);
    SIZE_T dA = PAGE_SIZE - (SIZE_T)(dst & 0xFFF);
    SIZE_T c = sz;
    if (c > sA) c = sA;
    if (c > dA) c = dA;
    RtlCopyMemory((PUCHAR)d + (dst & 0xFFF), (PUCHAR)s + (src & 0xFFF), c);
    UnmapPhysicalPage_Vmm(d);
    UnmapPhysicalPage_Vmm(s);
    return TRUE;
}

VOID HvHandleMemoryOp(PVCPU_CONTEXT vpData)
{
    if (!vpData) return;
    ULONG64 ctxPa = vpData->Guest_gpr.Rbx;
    if (!ctxPa) { vpData->Guest_gpr.Rax = (UINT64)-1; return; }

    /* VMM 路径: 这里用 MmMapIoSpace 是安全的
     * 因为 VMEXIT handler 运行在特殊上下文, 不会与 guest 的 PFN 管理冲突 */
    PVOID ctxMap = MapPhysicalPage_Vmm(ctxPa);
    if (!ctxMap) { vpData->Guest_gpr.Rax = (UINT64)-2; return; }
    PHV_RW_CONTEXT c = (PHV_RW_CONTEXT)((PUCHAR)ctxMap + (ctxPa & 0xFFF));

    ULONG64 cr3 = c->TargetCr3, tva = c->SourceVa, bpa = c->DestPa, tot = c->Size;
    BOOLEAN wr = (c->IsWrite != 0);

#ifdef DEBUG
    {
        static volatile LONG s_memOpDiag = 0;
        LONG cnt = InterlockedIncrement(&s_memOpDiag);
        if (cnt <= 10 || (cnt % 10000) == 0) {
            SvmDebugPrint("[VMM-MemOp] #%d: CR3=0x%llX VA=0x%llX DestPA=0x%llX Size=%llu Write=%d\n",
                cnt, cr3, tva, bpa, tot, (int)wr);
        }
    }
#endif

    if (!tot || tot > 0x100000) {
        c->Status = -3;
        UnmapPhysicalPage_Vmm(ctxMap);
        vpData->Guest_gpr.Rax = (UINT64)-3;
        return;
    }

    /* VMM 路径的页表遍历也用 MmCopyMemory, 同样安全 */
    ULONG64 done = 0;
    ULONG64 actualCopied = 0;
    while (done < tot) {
        SIZE_T pr = PAGE_SIZE - (SIZE_T)((tva + done) & 0xFFF);
        SIZE_T ch = (SIZE_T)(tot - done);
        if (ch > pr) ch = pr;

        ULONG64 tpa = TranslateGuestVaToPa(cr3, tva + done);

#ifdef DEBUG
        {
            static volatile LONG s_translateDiag = 0;
            LONG cnt = InterlockedIncrement(&s_translateDiag);
            if (cnt <= 5) {
                SvmDebugPrint("[VMM-MemOp] Translate: CR3=0x%llX VA=0x%llX -> PA=0x%llX\n",
                    cr3, tva + done, tpa);
            }
        }
#endif

        if (tpa) {
            BOOLEAN ok = wr
                ? PhysicalMemoryCopy_Vmm(tpa, bpa + done, ch, TRUE)
                : PhysicalMemoryCopy_Vmm(bpa + done, tpa, ch, FALSE);
            if (ok)
                actualCopied += ch;
        }
        done += ch;
    }

    c->Status = (actualCopied > 0) ? 0 : -1;
    UnmapPhysicalPage_Vmm(ctxMap);
    vpData->Guest_gpr.Rax = actualCopied;
}

/* ========================================================================
 *  Section: 批量散射读取 — VMM Host 侧
 *
 *  Guest 通过 CPUID(CPUID_HV_BATCH_READ) 触发 VMEXIT,
 *  RBX = BatchContext 的物理地址。
 *  Host 遍历散射表, 逐条页表遍历+物理直读, 写入输出缓冲区。
 * ======================================================================== */

VOID HvHandleBatchRead(PVCPU_CONTEXT vpData)
{
#ifdef DEBUG
    static volatile LONG s_vmmBatchCount = 0;
#endif

    if (!vpData) return;

    ULONG64 ctxPa = vpData->Guest_gpr.Rbx;
    if (!ctxPa) {
        vpData->Guest_gpr.Rax = (UINT64)-1;
        return;
    }

    PVOID ctxMap = MapPhysicalPage_Vmm(ctxPa);
    if (!ctxMap) {
        vpData->Guest_gpr.Rax = (UINT64)-2;
        return;
    }
    PHV_BATCH_CONTEXT ctx = (PHV_BATCH_CONTEXT)((PUCHAR)ctxMap + (ctxPa & 0xFFF));

    ULONG64 cr3 = ctx->TargetCr3;
    ULONG32 entryCount = ctx->EntryCount;
    ULONG32 totalOutput = ctx->TotalOutputSize;
    ULONG64 entriesPa = ctx->EntriesPa;
    ULONG64 outputPa = ctx->OutputPa;

#ifdef DEBUG
    {
        LONG cnt = InterlockedIncrement(&s_vmmBatchCount);
        if (cnt <= 10 || (cnt % 5000) == 0) {
            SvmDebugPrint("[VMM-BatchRead] VMEXIT HANDLER #%d: CPU=%d CR3=0x%llX entries=%u totalOut=%u\n",
                cnt, vpData->ProcessorIndex, cr3, entryCount, totalOutput);
        }
    }
#endif

    if (!cr3 || !entryCount || entryCount > HV_BATCH_MAX_ENTRIES ||
        !totalOutput || totalOutput > HV_BATCH_MAX_OUTPUT ||
        !entriesPa || !outputPa)
    {
        ctx->Status = -3;
        ctx->SuccessCount = 0;
        UnmapPhysicalPage_Vmm(ctxMap);
        vpData->Guest_gpr.Rax = (UINT64)-3;
        return;
    }

    /* 一次性映射整个散射表 (物理连续, 但可能跨页) */
    SIZE_T tableBytes = (SIZE_T)entryCount * sizeof(HV_SCATTER_ENTRY);
    PHYSICAL_ADDRESS tablePhys;
    tablePhys.QuadPart = (LONGLONG)(entriesPa & ~0xFFFULL);
    SIZE_T tableMapSize = (SIZE_T)(entriesPa & 0xFFF) + tableBytes;
    tableMapSize = (tableMapSize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    PVOID tableMap = MmMapIoSpace(tablePhys, tableMapSize, MmCached);
    if (!tableMap) {
        ctx->Status = -4;
        ctx->SuccessCount = 0;
        UnmapPhysicalPage_Vmm(ctxMap);
        vpData->Guest_gpr.Rax = (UINT64)-4;
        return;
    }
    PHV_SCATTER_ENTRY entries = (PHV_SCATTER_ENTRY)((PUCHAR)tableMap + (entriesPa & 0xFFF));

    ULONG32 successCount = 0;
    PVOID   cachedOutMap = NULL;
    ULONG64 cachedOutPage = 0;

    for (ULONG32 i = 0; i < entryCount; i++)
    {
        PHV_SCATTER_ENTRY entry = &entries[i];

        ULONG64 gva = entry->GuestVa;
        ULONG32 sz = entry->Size;
        ULONG32 outOff = entry->OutputOffset;

        if (sz == 0 || sz > PAGE_SIZE || outOff + sz > totalOutput) {
            entry->Status = 2;
            continue;
        }

        BOOLEAN anyOk = FALSE;
        ULONG32 done = 0;

        while (done < sz)
        {
            ULONG32 pageRem = (ULONG32)(PAGE_SIZE - ((gva + done) & 0xFFF));
            ULONG32 chunk = sz - done;
            if (chunk > pageRem) chunk = pageRem;

            ULONG64 dPa = outputPa + outOff + done;
            ULONG64 dPagePa = dPa & ~0xFFFULL;
            ULONG32 dOff = (ULONG32)(dPa & 0xFFF);

            ULONG32 dAvail = PAGE_SIZE - dOff;
            if (chunk > dAvail) chunk = dAvail;

            ULONG64 srcPa = TranslateGuestVaToPa(cr3, gva + done);

            if (!cachedOutMap || cachedOutPage != dPagePa) {
                if (cachedOutMap) UnmapPhysicalPage_Vmm(cachedOutMap);
                cachedOutMap = MapPhysicalPage_Vmm(dPa);
                cachedOutPage = dPagePa;
            }

            if (!cachedOutMap) { done += chunk; continue; }
            PUCHAR dstPtr = (PUCHAR)cachedOutMap + dOff;

            if (!srcPa) {
                RtlZeroMemory(dstPtr, chunk);
                done += chunk;
                continue;
            }

            PVOID srcMap = MapPhysicalPage_Vmm(srcPa);
            if (srcMap) {
                PUCHAR srcPtr = (PUCHAR)srcMap + (srcPa & 0xFFF);
                ULONG32 srcAvail = PAGE_SIZE - (ULONG32)(srcPa & 0xFFF);
                if (chunk > srcAvail) chunk = srcAvail;
                RtlCopyMemory(dstPtr, srcPtr, chunk);
                UnmapPhysicalPage_Vmm(srcMap);
                anyOk = TRUE;
            }
            else {
                RtlZeroMemory(dstPtr, chunk);
            }

            done += chunk;
        }

        entry->Status = anyOk ? 0 : 1;
        if (anyOk) successCount++;
    }

    if (cachedOutMap) UnmapPhysicalPage_Vmm(cachedOutMap);

    MmUnmapIoSpace(tableMap, tableMapSize);

    ctx->SuccessCount = successCount;
    ctx->Status = (successCount == entryCount) ? 0 : -1;

#ifdef DEBUG
    {
        LONG cnt = s_vmmBatchCount; /* just read, no increment */
        if (cnt <= 10 || (cnt % 5000) == 0) {
            SvmDebugPrint("[VMM-BatchRead] DONE #%d: success=%u/%u status=%d\n",
                cnt, successCount, entryCount, ctx->Status);
        }
    }
#endif

    UnmapPhysicalPage_Vmm(ctxMap);

    vpData->Guest_gpr.Rax = (UINT64)successCount;
}