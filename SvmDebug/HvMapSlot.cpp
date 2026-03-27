/**
 * @file HvMapSlot.cpp
 * @brief 无锁 PTE 槽位池实现 — VMEXIT 期间安全映射物理页
 *
 * 核心思路:
 *   1. 初始化时分配 N 页连续物理内存 (内核空间 VA)
 *   2. 获取每页对应的 PTE 地址 (通过 PTE_BASE 自映射计算)
 *   3. VMEXIT 期间直接修改 PTE + INVLPG 映射任意物理页
 *   4. 内核空间 PTE 是所有进程共享的, Host CR3 (System) 下修改也有效
 *
 * 这整个过程零锁、零 API 调用, 只有 MOV + INVLPG 两条指令。
 */

#include "HvMapSlot.h"
#include <intrin.h>

 /* PTE flags: Present | Read/Write | Accessed | Dirty | NX */
#define PTE_PRESENT_RW  0x8000000000000063ULL

/* ========================================================================
 * 全局实例
 * ======================================================================== */
static HV_MAP_POOL g_MapPool = { 0 };

/* ========================================================================
 * PTE_BASE 动态获取
 *
 * Win10 1607+ 随机化 PTE_BASE, 不再固定为 0xFFFFF68000000000。
 * 方法: 扫描 nt!MiGetPteAddress 函数取 MOV RAX, imm64 中的立即数。
 *
 * MiGetPteAddress 的典型代码:
 *   48 C1 E9 09     shr rcx, 9
 *   48 B8 xx...     mov rax, PTE_BASE
 *   48 23 C8        and rcx, rax
 *
 * 提取方法 (按优先级):
 *   1. 扫描 MmIsAddressValid — 必含 PTE_BASE (遍历 PXE→PPE→PDE→PTE)
 *   2. 扫描 MiGetPteAddress — 直接包含常量 (未导出, 可能获取不到)
 *   3. 读 CR3 找 PML4 自引用条目, 数学推导 PTE_BASE
 * ======================================================================== */
 /**
  * 从导出函数中扫描 MOV RAX/RCX/RDX, imm64 指令提取 PTE_BASE
  *
  * 在 shr reg, 9 (页表索引计算) 附近查找, 更精确。
  * PTE_BASE 特征: 0xFFFFxxxxxxxx0000, 且 bit[47]=1 (canonical高半)
  */
static ULONG64 ScanFuncForPteBase(PUCHAR func, int range)
{
    if (!func) return 0;

    /* 策略1: 找 48 C1 E9 09 (shr rcx, 9), 然后往后找最近的 48 B8 */
    for (int i = 0; i < range - 12; i++) {
        if (func[i] == 0x48 && func[i + 1] == 0xC1 &&
            func[i + 2] == 0xE9 && func[i + 3] == 0x09) {
            /* 找到 shr rcx, 9 — 向后搜索 MOV RAX, imm64 */
            for (int j = i + 4; j < i + 30 && j < range - 10; j++) {
                if (func[j] == 0x48 && func[j + 1] == 0xB8) {
                    ULONG64 val = *(PULONG64)(func + j + 2);
                    /* PTE_BASE = sign_extend(N<<39): canonical高半 + 低39位全零 */
                    if ((val & 0xFFFF800000000000ULL) == 0xFFFF800000000000ULL &&
                        (val & 0x7FFFFFFFFFULL) == 0 &&
                        val != 0xFFFF800000000000ULL) {
                        return val;
                    }
                }
            }
        }
    }

    /* 策略2: 收集所有 48 B8 立即数, 用严格条件过滤 PTE_BASE
     * PTE_BASE = sign_extend(N << 39), 所以低 39 位全为 0
     * 这排除了 PDE_BASE/PPE_BASE/PXE_BASE/MmPfnDatabase 等 */
    for (int i = 0; i < range - 10; i++) {
        if ((func[i] == 0x48 || func[i] == 0x49) && func[i + 1] == 0xB8) {
            ULONG64 val = *(PULONG64)(func + i + 2);
            /* PTE_BASE: canonical高半 + 低39位全零 */
            if ((val & 0xFFFF800000000000ULL) == 0xFFFF800000000000ULL &&
                (val & 0x7FFFFFFFFFULL) == 0 &&
                val != 0xFFFF800000000000ULL) {  /* 排除极端值 */
                return val;
            }
        }
    }

    return 0;
}

/**
 * 方法3: 通过 CR3 PML4 自引用条目推导 PTE_BASE
 *
 * Windows 内核页表有一个 PML4 条目指向 PML4 页自身 (自引用),
 * 该条目的索引 N 决定了 PTE_BASE:
 *   PTE_BASE  = sign_extend(N << 39 | N << 30 | N << 21 | N << 12)
 *
 * 在 PASSIVE_LEVEL 下 MmGetVirtualForPhysical(CR3) 能安全返回 PML4 VA。
 */
static ULONG64 DerivePteBaseFromCr3(void)
{
    ULONG64 cr3 = __readcr3() & ~0xFFFULL;
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)cr3;

    PULONG64 pml4 = (PULONG64)MmGetVirtualForPhysical(pa);
    if (!pml4) return 0;

    for (int i = 0; i < 512; i++) {
        ULONG64 entry = pml4[i];
        if (!(entry & 1)) continue; /* not present */
        ULONG64 entryPfn = (entry & 0x000FFFFFFFFFF000ULL);
        if (entryPfn == cr3) {
            /* 找到自引用! 索引 = i
             * PTE_BASE = sign_extend(idx << 39)
             * (不是 PXE_BASE 那个带多级索引的公式) */
            ULONG64 pteBase = (ULONG64)i << 39;
            /* sign-extend bit 47 → bits 48..63 */
            if (pteBase & (1ULL << 47))
                pteBase |= 0xFFFF000000000000ULL;
            DbgPrint("[HvMapSlot] PML4 self-ref index=%d, derived PTE_BASE=0x%llX\n", i, pteBase);
            return pteBase;
        }
    }

    return 0;
}

static ULONG64 FindPteBase(void)
{
    UNICODE_STRING name;
    PUCHAR func;
    ULONG64 result;

    /* 方法1: 扫描 MmIsAddressValid — 它遍历 PXE→PPE→PDE→PTE, 必含 PTE_BASE */
    RtlInitUnicodeString(&name, L"MmIsAddressValid");
    func = (PUCHAR)MmGetSystemRoutineAddress(&name);
    result = ScanFuncForPteBase(func, 256);
    if (result) {
        DbgPrint("[HvMapSlot] PTE_BASE from MmIsAddressValid: 0x%llX\n", result);
        return result;
    }

    /* 方法2: 扫描 MiGetPteAddress (未导出但某些版本可获取) */
    RtlInitUnicodeString(&name, L"MiGetPteAddress");
    func = (PUCHAR)MmGetSystemRoutineAddress(&name);
    result = ScanFuncForPteBase(func, 64);
    if (result) {
        DbgPrint("[HvMapSlot] PTE_BASE from MiGetPteAddress: 0x%llX\n", result);
        return result;
    }

    /* 方法3: 通过 PML4 自引用推导 */
    result = DerivePteBaseFromCr3();
    if (result) return result;

    return 0;
}

/**
 * @brief 通过 PTE_BASE 计算给定 VA 的 PTE 地址
 *
 * x64 分页: PTE_BASE + (VA >> 12) * 8
 * 等价于:   PTE_BASE + ((VA >> 9) & 0x7FFFFFFFF8)
 */
static __forceinline PULONG64 GetPteForVa(ULONG64 PteBase, PVOID Va)
{
    ULONG64 va = (ULONG64)Va;
    return (PULONG64)(PteBase + ((va >> 9) & 0x7FFFFFFFF8ULL));
}

/* ========================================================================
 * 初始化
 * ======================================================================== */
NTSTATUS HvMapSlotInit(ULONG CpuCount)
{
    PHYSICAL_ADDRESS highAddr;
    highAddr.QuadPart = ~0ULL;

    if (g_MapPool.Initialized) return STATUS_SUCCESS;
    if (CpuCount == 0 || CpuCount > HV_MAX_CPUS) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(&g_MapPool, sizeof(g_MapPool));
    g_MapPool.CpuCount = CpuCount;

    /* 1. 获取 PTE_BASE */
    g_MapPool.PteBase = FindPteBase();
    if (!g_MapPool.PteBase) {
        DbgPrint("[HvMapSlot] ERROR: Cannot find PTE_BASE\n");
        return STATUS_NOT_FOUND;
    }
    DbgPrint("[HvMapSlot] PTE_BASE = 0x%llX\n", g_MapPool.PteBase);

    /* 2. 分配连续物理内存作为映射窗口 */
    g_MapPool.TotalPages = CpuCount * HV_SLOTS_PER_CPU;
    SIZE_T poolSize = (SIZE_T)g_MapPool.TotalPages * PAGE_SIZE;

    g_MapPool.PoolVa = MmAllocateContiguousMemory(poolSize, highAddr);
    if (!g_MapPool.PoolVa) {
        DbgPrint("[HvMapSlot] ERROR: Cannot allocate %lu pages\n", g_MapPool.TotalPages);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_MapPool.PoolVa, poolSize);
    g_MapPool.PoolPa = MmGetPhysicalAddress(g_MapPool.PoolVa).QuadPart;

    DbgPrint("[HvMapSlot] Pool: VA=%p PA=0x%llX pages=%lu (%lu CPUs x %d slots)\n",
        g_MapPool.PoolVa, g_MapPool.PoolPa, g_MapPool.TotalPages,
        CpuCount, HV_SLOTS_PER_CPU);

    /* 3. 获取每页的 PTE 地址并保存原始值 */
    for (ULONG cpu = 0; cpu < CpuCount; cpu++) {
        for (ULONG slot = 0; slot < HV_SLOTS_PER_CPU; slot++) {
            ULONG pageIdx = cpu * HV_SLOTS_PER_CPU + slot;
            PVOID va = (PUCHAR)g_MapPool.PoolVa + (SIZE_T)pageIdx * PAGE_SIZE;

            /* 触摸页面确保 PTE 存在 (页面已经是 committed 的) */
            volatile UCHAR dummy = *(volatile UCHAR*)va;
            (void)dummy;

            PULONG64 pte = GetPteForVa(g_MapPool.PteBase, va);
            ULONG64 origPte = *pte;

            g_MapPool.Slots[cpu][slot].Va = va;
            g_MapPool.Slots[cpu][slot].Pte = pte;
            g_MapPool.Slots[cpu][slot].OrigPte = origPte;
        }
    }

    /* 4. 验证: 检查第一个槽位的 PTE 是否有效 */
    {
        PULONG64 pte0 = g_MapPool.Slots[0][0].Pte;
        ULONG64 pte0Val = *pte0;
        ULONG64 expectedPa = MmGetPhysicalAddress(g_MapPool.PoolVa).QuadPart;
        ULONG64 ptePhys = pte0Val & 0x000FFFFFFFFFF000ULL;

        DbgPrint("[HvMapSlot] Verify: PTE[0]=%p val=0x%llX physFromPte=0x%llX expected=0x%llX %s\n",
            pte0, pte0Val, ptePhys, expectedPa,
            (ptePhys == expectedPa) ? "OK" : "MISMATCH!");

        if (ptePhys != expectedPa) {
            DbgPrint("[HvMapSlot] ERROR: PTE verification failed! PTE_BASE may be wrong.\n");
            MmFreeContiguousMemory(g_MapPool.PoolVa);
            g_MapPool.PoolVa = NULL;
            return STATUS_UNSUCCESSFUL;
        }
    }

    g_MapPool.Initialized = TRUE;
    DbgPrint("[HvMapSlot] Init OK: %lu slots ready\n", g_MapPool.TotalPages);
    return STATUS_SUCCESS;
}

/* ========================================================================
 * 清理
 * ======================================================================== */
VOID HvMapSlotCleanup(void)
{
    if (!g_MapPool.Initialized) return;
    g_MapPool.Initialized = FALSE;

    /* 恢复所有 PTE 到原始值 */
    for (ULONG cpu = 0; cpu < g_MapPool.CpuCount; cpu++) {
        for (ULONG slot = 0; slot < HV_SLOTS_PER_CPU; slot++) {
            HV_MAP_SLOT* s = &g_MapPool.Slots[cpu][slot];
            if (s->Pte && s->OrigPte) {
                *s->Pte = s->OrigPte;
                __invlpg(s->Va);
            }
        }
    }

    if (g_MapPool.PoolVa) {
        MmFreeContiguousMemory(g_MapPool.PoolVa);
        g_MapPool.PoolVa = NULL;
    }
}

/* ========================================================================
 * VMEXIT 期间映射 — 核心函数, 零锁
 * ======================================================================== */
PVOID VmxMapPhys(ULONG CpuId, ULONG Slot, ULONG64 PhysAddr)
{
    if (!g_MapPool.Initialized) return NULL;
    if (CpuId >= g_MapPool.CpuCount || Slot >= HV_SLOTS_PER_CPU) return NULL;

    HV_MAP_SLOT* s = &g_MapPool.Slots[CpuId][Slot];

    /* 直接写 PTE — 将此 VA 映射到目标物理页 */
    ULONG64 newPte = (PhysAddr & ~0xFFFULL) | PTE_PRESENT_RW;
    *s->Pte = newPte;

    /* 刷新此 VA 的 TLB 缓存 */
    __invlpg(s->Va);

    /* 返回 VA + 页内偏移 */
    return (PUCHAR)s->Va + (PhysAddr & 0xFFF);
}

/* ========================================================================
 * VMEXIT 期间取消映射 — 恢复原始 PTE
 * ======================================================================== */
VOID VmxUnmapPhys(ULONG CpuId, ULONG Slot)
{
    if (!g_MapPool.Initialized) return;
    if (CpuId >= g_MapPool.CpuCount || Slot >= HV_SLOTS_PER_CPU) return;

    HV_MAP_SLOT* s = &g_MapPool.Slots[CpuId][Slot];

    /* 恢复原始 PTE (指向预分配的连续物理页) */
    *s->Pte = s->OrigPte;
    __invlpg(s->Va);
}

/* ========================================================================
 * 获取全局池指针
 * ======================================================================== */
HV_MAP_POOL* HvGetMapPool(void)
{
    return &g_MapPool;
}