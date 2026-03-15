// Disable C4819 (codepage 936 encoding warning) BEFORE any other content
#pragma warning(disable: 4819)

/**
 * @file NPT.cpp
 * @brief Nested Page Table (NPT) management - init, large page split, permissions, PFN swap
 * @author yewilliam
 * @date 2026/02/06
 *
 * [BUGFIX 2026/03/15] pd_linear calculation fixed globally:
 *   Old: pd_linear = pdpt_idx * 512 + pd_idx
 *   Only correct for PML4[0] (< 512GB). Physical machine MMIO devices
 *   mapped above 512GB caused pdpt_idx wrap-around, corrupting NPT
 *   entries for kernel code pages -> wrong content executed -> BSOD.
 *   New: pd_linear = (pml4_idx * 512 + pdpt_idx) * 512 + pd_idx
 *
 * [BUGFIX preserved] PrepareNPT covers 2TB (PML4[0..3])
 * [BUGFIX preserved] SplitPtPas[] eliminates MmGetPhysicalAddress in VMEXIT
 * [BUGFIX preserved] GetNptPteByHostPa_Cached PA-based lookup
 */

#pragma once
#include "NPT.h"
#include "SVM.h"

 /* ========================================================================
  *  Emergency PT page pool + PT VA cache
  * ======================================================================== */

static PVOID g_EmergencyPtPages[256] = { 0 };
static volatile LONG g_EmergencyPtCount = 0;
static volatile LONG g_PoolInitialized = 0;

typedef struct _PT_VA_CACHE_ENTRY {
    ULONG64 PtPa;
    PULONG64 PtVa;
    volatile LONG InUse;
} PT_VA_CACHE_ENTRY, * PPT_VA_CACHE_ENTRY;

#define PT_VA_CACHE_SIZE 512
static PT_VA_CACHE_ENTRY g_PtVaCache[PT_VA_CACHE_SIZE] = { 0 };
static volatile LONG g_PtVaCacheCount = 0;

/* NPT coverage: 4 PML4 entries = 4 * 512GB = 2TB */
#define NPT_PML4_COUNT  4

/* ========================================================================
 *  [BUGFIX 2026/03/15] Unified pd_linear calculation
 *
 *  Old formula (missing PML4 index):
 *    pd_linear = pdpt_idx * 512 + pd_idx
 *    Only correct within PML4[0]. For PA > 512GB, pdpt_idx wraps to
 *    0..511, colliding with PML4[0] entries.
 *
 *  New formula:
 *    pml4_idx  = (PA >> 39) & (NPT_PML4_COUNT-1)
 *    pdpt_idx  = (PA >> 30) & 0x1FF
 *    pd_idx    = (PA >> 21) & 0x1FF
 *    pd_linear = (pml4_idx * 512 + pdpt_idx) * 512 + pd_idx
 * ======================================================================== */
static __forceinline ULONG64 CalcPdLinear(ULONG64 PhysAddr)
{
    ULONG64 pml4_idx = (PhysAddr >> 39) & (NPT_PML4_COUNT - 1);
    ULONG64 pdpt_idx = (PhysAddr >> 30) & 0x1FF;
    ULONG64 pd_idx = (PhysAddr >> 21) & 0x1FF;
    return (pml4_idx * 512 + pdpt_idx) * 512 + pd_idx;
}

static __forceinline ULONG64 CalcPtIdx(ULONG64 PhysAddr)
{
    return (PhysAddr >> 12) & 0x1FF;
}

BOOLEAN IsSupportNPT()
{
    int vector[4];
    __cpuid(vector, CPUID_FN8000_000A_EDX_NP);
    BOOLEAN bNTP = vector[3] & 1;
    return bNTP;
}

NTSTATUS InitNPT(PVCPU_CONTEXT vpData)
{
    if (IsSupportNPT() == 0) {
        SvmDebugPrint("[ERROR][InitNPT] NPT not supported\n");
        return STATUS_NOT_SUPPORTED;
    }
    vpData->Guestvmcb.ControlArea.NpEnable = vpData->Guestvmcb.ControlArea.NpEnable | 0x1;

    if (vpData->NptCr3 == 0) {
        return STATUS_NOT_FOUND;
    }

    vpData->Guestvmcb.ControlArea.NCr3 = vpData->NptCr3;
    return STATUS_SUCCESS;
}

static PULONG64 CachePtVa(ULONG64 PtPa)
{
    LONG count = g_PtVaCacheCount;
    for (LONG i = 0; i < count && i < PT_VA_CACHE_SIZE; i++) {
        if (g_PtVaCache[i].PtPa == PtPa && g_PtVaCache[i].PtVa != NULL) {
            return g_PtVaCache[i].PtVa;
        }
    }

    LONG idx = InterlockedIncrement(&g_PtVaCacheCount) - 1;
    if (idx >= PT_VA_CACHE_SIZE) {
        InterlockedDecrement(&g_PtVaCacheCount);
        PHYSICAL_ADDRESS pa;
        pa.QuadPart = PtPa;
        return (PULONG64)MmGetVirtualForPhysical(pa);
    }

    PHYSICAL_ADDRESS pa;
    pa.QuadPart = PtPa;
    g_PtVaCache[idx].PtPa = PtPa;
    g_PtVaCache[idx].PtVa = (PULONG64)MmGetVirtualForPhysical(pa);
    InterlockedExchange(&g_PtVaCache[idx].InUse, 1);

    return g_PtVaCache[idx].PtVa;
}

static PULONG64 LookupPtVaFromCache(ULONG64 PtPa)
{
    LONG count = g_PtVaCacheCount;
    for (LONG i = 0; i < count && i < PT_VA_CACHE_SIZE; i++) {
        if (g_PtVaCache[i].PtPa == PtPa && g_PtVaCache[i].InUse) {
            return g_PtVaCache[i].PtVa;
        }
    }
    return NULL;
}

ULONG64 PrepareNPT(PVCPU_CONTEXT vpData)
{
    /* pml4_table: 1 page (4KB) — MmAllocateContiguousMemory OK */
    vpData->pml4_table = (ULONG64*)AllocateAlignedZeroedMemory(1 * PAGE_SIZE);

    /* pdpt_table: NPT_PML4_COUNT pages (16KB) — MmAllocateContiguousMemory OK */
    vpData->pdpt_table = (ULONG64*)AllocateAlignedZeroedMemory(NPT_PML4_COUNT * PAGE_SIZE);

    /* [BUGFIX] pd_tables: NPT_PML4_COUNT * 512 pages (8MB)
     * MmAllocateContiguousMemory 要求 8MB 物理连续内存, 在 VM 或内存碎片化时几乎必定失败。
     * 改用 ExAllocatePool2(NON_PAGED): 虚拟地址连续, 物理地址不要求连续。
     * 每个 PD page (4KB) 内物理连续(页本身的属性), PDPT 条目逐页查 PA 即可。 */
    SIZE_T pdTablesSize = (SIZE_T)NPT_PML4_COUNT * 512 * PAGE_SIZE;
    vpData->pd_tables = (ULONG64*)ExAllocatePool2(POOL_FLAG_NON_PAGED, pdTablesSize, 'NPDT');

    if (vpData->pml4_table == 0 || vpData->pdpt_table == 0 || vpData->pd_tables == 0) {
        if (vpData->pml4_table) MmFreeContiguousMemory(vpData->pml4_table);
        if (vpData->pdpt_table) MmFreeContiguousMemory(vpData->pdpt_table);
        if (vpData->pd_tables)  ExFreePoolWithTag(vpData->pd_tables, 'NPDT');
        vpData->pml4_table = vpData->pdpt_table = vpData->pd_tables = nullptr;
        SvmDebugPrint("[ERROR][PrepareNPT] NPT table alloc failed\n");
        return 0;
    }

    /* pd_tables 通过 ExAllocatePool2 分配, 内容不保证清零(Pool2 默认清零, 但显式确保) */
    RtlZeroMemory(vpData->pd_tables, pdTablesSize);

    if (InterlockedCompareExchange(&g_PoolInitialized, 1, 0) == 0) {
        for (int i = 0; i < 256; i++) {
            g_EmergencyPtPages[i] = AllocateAlignedZeroedMemory(PAGE_SIZE);
        }
        g_EmergencyPtCount = 256;
        RtlZeroMemory(g_PtVaCache, sizeof(g_PtVaCache));
        g_PtVaCacheCount = 0;
    }

    ULONG64 pml4_pa = MmGetPhysicalAddress((PVOID)vpData->pml4_table).QuadPart;

    /* PML4 → PDPT: pdpt_table 是连续分配, 可用偏移计算 PA */
    ULONG64 pdpt_pa = MmGetPhysicalAddress((PVOID)vpData->pdpt_table).QuadPart;

    for (UINT64 pml4_idx = 0; pml4_idx < NPT_PML4_COUNT; pml4_idx++) {
        NPT_ENTRY pml4_entry = { 0 };
        pml4_entry.Bits.Valid = 1;
        pml4_entry.Bits.Write = 1;
        pml4_entry.Bits.User = 1;
        pml4_entry.Bits.PageFrameNumber = (pdpt_pa + pml4_idx * PAGE_SIZE) >> 12;
        vpData->pml4_table[pml4_idx] = pml4_entry.AsUInt64;
    }

    /* PDPT → PD: pd_tables 物理不连续, 必须逐页查 PA */
    for (UINT64 pml4_idx = 0; pml4_idx < NPT_PML4_COUNT; pml4_idx++) {
        for (UINT64 i = 0; i < 512; i++) {
            UINT64 pdpt_slot = pml4_idx * 512 + i;

            /* [BUGFIX] 逐页查物理地址, 不假设物理连续 */
            ULONG64 pd_page_va = (ULONG64)vpData->pd_tables + pdpt_slot * PAGE_SIZE;
            ULONG64 pd_page_pa = MmGetPhysicalAddress((PVOID)pd_page_va).QuadPart;

            NPT_ENTRY pdpt_entry = { 0 };
            pdpt_entry.Bits.Valid = 1;
            pdpt_entry.Bits.Write = 1;
            pdpt_entry.Bits.User = 1;
            pdpt_entry.Bits.PageFrameNumber = pd_page_pa >> 12;
            vpData->pdpt_table[pdpt_slot] = pdpt_entry.AsUInt64;
        }
    }

    ULONG64 current_hpa = 0;
    UINT64 total_pd_entries = (UINT64)NPT_PML4_COUNT * 512 * 512;
    for (UINT64 i = 0; i < total_pd_entries; i++) {
        NPT_ENTRY pd_entry = { 0 };
        pd_entry.Bits.Valid = 1;
        pd_entry.Bits.Write = 1;
        pd_entry.Bits.User = 1;
        pd_entry.Bits.LargePage = 1;
        pd_entry.Bits.PageFrameNumber = current_hpa >> 12;
        current_hpa += 0x200000;
        vpData->pd_tables[i] = pd_entry.AsUInt64;
    }

    SvmDebugPrint("[NPT] PrepareNPT: %d PML4 entries, covering %llu GB\n",
        NPT_PML4_COUNT, (ULONG64)NPT_PML4_COUNT * 512);

    return pml4_pa;
}

NTSTATUS SpliteLargePage(PVCPU_CONTEXT vpData, UINT64 pd_index, PULONG64* OutPtTableVa)
{
    UINT64 max_pd_index = (UINT64)NPT_PML4_COUNT * 512 * 512;
    if (pd_index >= max_pd_index) {
        return STATUS_INVALID_PARAMETER;
    }

    PNPT_ENTRY pd_entry = (PNPT_ENTRY)&vpData->pd_tables[pd_index];

    if (pd_entry->Bits.LargePage == 0) {
        ULONG64 pt_pa = pd_entry->Bits.PageFrameNumber << 12;

        PULONG64 pt_va = LookupPtVaFromCache(pt_pa);
        if (pt_va == NULL) {
            if (KeGetCurrentIrql() <= APC_LEVEL) {
                pt_va = CachePtVa(pt_pa);
            }
            else {
                for (ULONG i = 0; i < vpData->SplitPtCount; i++) {
                    if (vpData->SplitPtPas[i] == pt_pa) {
                        pt_va = (PULONG64)vpData->SplitPtPages[i];
                        break;
                    }
                }
                if (!pt_va) {
                    SvmDebugPrint("[ERROR][SpliteLargePage] Cache miss at high IRQL! pd_index=%llu\n", pd_index);
                    return STATUS_UNSUCCESSFUL;
                }
            }
        }

        if (!pt_va) {
            SvmDebugPrint("[ERROR][SpliteLargePage] VA lookup failed for PA 0x%llX\n", pt_pa);
            return STATUS_UNSUCCESSFUL;
        }
        *OutPtTableVa = pt_va;
        return STATUS_SUCCESS;
    }

    PULONG64 new_pt_table = nullptr;

    LONG idx = InterlockedDecrement(&g_EmergencyPtCount);
    if (idx >= 0 && idx < 256) {
        new_pt_table = (PULONG64)g_EmergencyPtPages[idx];
        g_EmergencyPtPages[idx] = NULL;
    }
    else {
        InterlockedIncrement(&g_EmergencyPtCount);
        if (KeGetCurrentIrql() <= APC_LEVEL) {
            new_pt_table = (PULONG64)AllocateAlignedZeroedMemory(PAGE_SIZE);
        }
    }

    if (new_pt_table == nullptr) {
        SvmDebugPrint("[ERROR][SpliteLargePage] PT alloc failed (pd_index=%llu)\n", pd_index);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG64 new_pt_pa = MmGetPhysicalAddress((PVOID)new_pt_table).QuadPart;
    ULONG64 original_hpa_base = pd_entry->Bits.PageFrameNumber << 12;

    NPT_ENTRY pt_entry_temp = { 0 };
    for (UINT64 i = 0; i < 512; i++) {
        pt_entry_temp.AsUInt64 = pd_entry->AsUInt64;
        pt_entry_temp.Bits.LargePage = 0;
        pt_entry_temp.Bits.PageFrameNumber = (original_hpa_base + PAGE_SIZE * i) >> 12;
        new_pt_table[i] = pt_entry_temp.AsUInt64;
    }

    if (KeGetCurrentIrql() <= APC_LEVEL) {
        CachePtVa(new_pt_pa);
    }

    if (vpData->SplitPtCount < ARRAYSIZE(vpData->SplitPtPages)) {
        vpData->SplitPtPages[vpData->SplitPtCount] = new_pt_table;
        vpData->SplitPtPas[vpData->SplitPtCount] = new_pt_pa;
        vpData->SplitPtCount++;
    }

    pd_entry->Bits.LargePage = 0;
    pd_entry->Bits.PageFrameNumber = new_pt_pa >> 12;

    *OutPtTableVa = new_pt_table;
    return STATUS_SUCCESS;
}

NTSTATUS PreSplitLargePageForHook(PVCPU_CONTEXT vpData, PVOID TargetAddress)
{
    if (!vpData || !TargetAddress) {
        return STATUS_INVALID_PARAMETER;
    }

    NPT_CONTEXT context = { 0 };
    context.TargetAddress = TargetAddress;

    NTSTATUS status = GPaToHostPa(&context);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PULONG64 dummy = nullptr;
    status = SpliteLargePage(vpData, context.pd_linear, &dummy);
    return status;
}

/* [BUGFIX 2026/03/15] Uses CalcPdLinear() */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS PreSplitLargePageByPa(PVCPU_CONTEXT vpData, ULONG64 TargetPa)
{
    if (!vpData || TargetPa == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG64 pd_linear = CalcPdLinear(TargetPa);

    PULONG64 dummy = nullptr;
    return SpliteLargePage(vpData, pd_linear, &dummy);
}

/* [BUGFIX 2026/03/15] Uses CalcPdLinear() / CalcPtIdx() */
static PNPT_ENTRY GetNptPteByHostPa_Cached(PVCPU_CONTEXT vpData, ULONG64 TargetPa)
{
    ULONG64 pd_linear = CalcPdLinear(TargetPa);
    ULONG64 pt_idx = CalcPtIdx(TargetPa);

    UINT64 max_pd_index = (UINT64)NPT_PML4_COUNT * 512 * 512;
    if (pd_linear >= max_pd_index) {
        return nullptr;
    }

    PNPT_ENTRY pd_entry = (PNPT_ENTRY)&vpData->pd_tables[pd_linear];
    if (pd_entry->Bits.LargePage == 1) {
        return nullptr;
    }

    ULONG64 pt_pa = pd_entry->Bits.PageFrameNumber << 12;

    PULONG64 pt_va = LookupPtVaFromCache(pt_pa);
    if (pt_va == NULL) {
        for (ULONG i = 0; i < vpData->SplitPtCount; i++) {
            if (vpData->SplitPtPas[i] == pt_pa) {
                pt_va = (PULONG64)vpData->SplitPtPages[i];
                break;
            }
        }
    }

    if (!pt_va) return nullptr;
    return (PNPT_ENTRY)&pt_va[pt_idx];
}

/* [BUGFIX 2026/03/15] Uses CalcPdLinear() */
NTSTATUS ApplyNptHookByPa(PVCPU_CONTEXT vpData, ULONG64 TargetPa, ULONG64 NewPagePa)
{
    if (TargetPa == 0 || NewPagePa == 0 || !vpData) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG64 pd_linear = CalcPdLinear(TargetPa);

    UINT64 max_pd_index = (UINT64)NPT_PML4_COUNT * 512 * 512;
    if (pd_linear >= max_pd_index) {
        return STATUS_INVALID_PARAMETER;
    }

    PNPT_ENTRY pd_entry = (PNPT_ENTRY)&vpData->pd_tables[pd_linear];
    if (pd_entry->Bits.LargePage == 1) {
        if (KeGetCurrentIrql() <= APC_LEVEL) {
            PULONG64 ptTable = nullptr;
            NTSTATUS status = SpliteLargePage(vpData, pd_linear, &ptTable);
            if (!NT_SUCCESS(status) || !ptTable) {
                return status;
            }
        }
        else {
            SvmDebugPrint("[ERROR] ApplyNptHookByPa: Large page not pre-split at high IRQL (pd_linear=%llu)\n",
                pd_linear);
            return STATUS_UNSUCCESSFUL;
        }
    }

    PNPT_ENTRY pte = GetNptPteByHostPa_Cached(vpData, TargetPa);
    if (pte == nullptr) {
        return STATUS_UNSUCCESSFUL;
    }

    pte->Bits.PageFrameNumber = NewPagePa >> 12;
    return STATUS_SUCCESS;
}

NTSTATUS ApplyNptHook_NoPerm(PVCPU_CONTEXT vpData, PVOID TargetAddress, ULONG64 PagePa)
{
    if (!TargetAddress || !PagePa) {
        return STATUS_INVALID_PARAMETER;
    }
    NPT_CONTEXT context = { 0 };
    context.TargetAddress = TargetAddress;
    NTSTATUS status = GPaToHostPa(&context);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SpliteLargePage(vpData, context.pd_linear, &context.TargetPtTable);
    if (!NT_SUCCESS(status) || !context.TargetPtTable) {
        SvmDebugPrint("[ERROR][ApplyNptHook_NoPerm] SpliteLargePage failed\n");
        return status;
    }

    PNPT_ENTRY pte = (PNPT_ENTRY)&context.TargetPtTable[context.pt_idx];
    pte->Bits.PageFrameNumber = PagePa >> 12;
    return STATUS_SUCCESS;
}

NTSTATUS ActivateNptHookInNpt(PVCPU_CONTEXT vpData, PNPT_HOOK_CONTEXT HookContext)
{
    if (!vpData || !HookContext || !HookContext->ResourcesReady) {
        return STATUS_INVALID_PARAMETER;
    }

    if (HookContext->TargetPa == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = ApplyNptHookByPa(vpData, HookContext->TargetPa, HookContext->OriginalPagePa);
    if (!NT_SUCCESS(status)) return status;

    status = SetNptPagePermissions(vpData, HookContext->TargetPa, NPT_PERM_READ_ONLY);
    if (!NT_SUCCESS(status)) return status;

    vpData->Guestvmcb.ControlArea.VmcbClean = 0;
    vpData->Guestvmcb.ControlArea.NCr3 = vpData->NptCr3;
    vpData->Guestvmcb.ControlArea.TlbControl = 1;
    return STATUS_SUCCESS;
}

NTSTATUS SetNptPagePermissions(PVCPU_CONTEXT vpData, ULONG64 TargetPa, ULONG PermissionType)
{
    if (TargetPa == 0) return STATUS_INVALID_PARAMETER;

    PNPT_ENTRY pte = GetNptPteByHostPa_Cached(vpData, TargetPa);
    if (pte == nullptr) return STATUS_UNSUCCESSFUL;

    if (PermissionType == NPT_PERM_READ_ONLY) {
        pte->Bits.Valid = 1;
        pte->Bits.Write = 1;
        pte->Bits.User = 1;
        pte->Bits.NoExecute = 1;
    }
    else if (PermissionType == NPT_PERM_EXECUTE) {
        pte->Bits.Valid = 1;
        pte->Bits.Write = 1;
        pte->Bits.User = 1;
        pte->Bits.NoExecute = 0;
    }
    else if (PermissionType == NPT_PERM_NOT_PRESENT) {
        pte->Bits.Valid = 0;
    }
    else {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

/* [BUGFIX 2026/03/15] Uses CalcPdLinear() / CalcPtIdx() */
NTSTATUS GPaToHostPa(PNPT_CONTEXT npt_context)
{
    if (npt_context == nullptr || npt_context->TargetAddress == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    npt_context->TargetPa = MmGetPhysicalAddress(npt_context->TargetAddress).QuadPart;

    if (npt_context->TargetPa == 0)
    {
        PMDL mdl = IoAllocateMdl(npt_context->TargetAddress, PAGE_SIZE, FALSE, FALSE, NULL);
        if (mdl != nullptr)
        {
            __try {
                MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
                PPFN_NUMBER pfnArray = MmGetMdlPfnArray(mdl);
                if (pfnArray != nullptr) {
                    npt_context->TargetPa = ((ULONG64)pfnArray[0] << PAGE_SHIFT) | BYTE_OFFSET(npt_context->TargetAddress);
                }
                MmUnlockPages(mdl);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                npt_context->TargetPa = 0;
            }
            IoFreeMdl(mdl);
        }
    }

    if (npt_context->TargetPa == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    npt_context->pdpt_idx = (npt_context->TargetPa >> 30) & 0x1FF;
    npt_context->pd_idx = (npt_context->TargetPa >> 21) & 0x1FF;
    npt_context->pt_idx = CalcPtIdx(npt_context->TargetPa);
    npt_context->pd_linear = CalcPdLinear(npt_context->TargetPa);

    return STATUS_SUCCESS;
}

PNPT_ENTRY GetNptPteByHostPa(PVCPU_CONTEXT vpData, ULONG64 TargetPa)
{
    PNPT_ENTRY cached = GetNptPteByHostPa_Cached(vpData, TargetPa);
    if (cached) return cached;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        SvmDebugPrint("[ERROR] GetNptPteByHostPa called at high IRQL without cache!\n");
        return nullptr;
    }

    ULONG64 pd_linear = CalcPdLinear(TargetPa);
    ULONG64 pt_idx = CalcPtIdx(TargetPa);

    UINT64 max_pd_index = (UINT64)NPT_PML4_COUNT * 512 * 512;
    if (pd_linear >= max_pd_index) {
        return nullptr;
    }

    PNPT_ENTRY pd_entry = (PNPT_ENTRY)&vpData->pd_tables[pd_linear];
    if (pd_entry->Bits.LargePage == 1) {
        return nullptr;
    }

    PHYSICAL_ADDRESS pt_pa;
    pt_pa.QuadPart = pd_entry->Bits.PageFrameNumber << 12;

    PULONG64 pt_va = CachePtVa(pt_pa.QuadPart);
    if (!pt_va) return nullptr;

    return (PNPT_ENTRY)&pt_va[pt_idx];
}

VOID FreePvCPUNPT(PVCPU_CONTEXT vpData)
{
    if (vpData->pml4_table) MmFreeContiguousMemory(vpData->pml4_table);
    if (vpData->pdpt_table) MmFreeContiguousMemory(vpData->pdpt_table);
    /* [BUGFIX] pd_tables 现在用 ExAllocatePool2 分配 */
    if (vpData->pd_tables)  ExFreePoolWithTag(vpData->pd_tables, 'NPDT');

    for (ULONG i = 0; i < vpData->SplitPtCount; i++) {
        if (vpData->SplitPtPages[i] != nullptr) {
            MmFreeContiguousMemory(vpData->SplitPtPages[i]);
            vpData->SplitPtPages[i] = nullptr;
            vpData->SplitPtPas[i] = 0;
        }
    }
    vpData->SplitPtCount = 0;
    vpData->pml4_table = vpData->pdpt_table = vpData->pd_tables = nullptr;
}

PVOID AllocateAlignedZeroedMemory(SIZE_T NumberOfBytes)
{
    PHYSICAL_ADDRESS HighestAcceptableAddress;
    HighestAcceptableAddress.QuadPart = ~0ULL;

    PVOID pMemory = MmAllocateContiguousMemory(NumberOfBytes, HighestAcceptableAddress);
    if (pMemory) {
        RtlZeroMemory(pMemory, NumberOfBytes);
    }
    return pMemory;
}

VOID PrewarmPtVaCache(PVCPU_CONTEXT vpData)
{
    for (ULONG i = 0; i < vpData->SplitPtCount; i++) {
        if (vpData->SplitPtPages[i]) {
            CachePtVa(vpData->SplitPtPas[i]);
        }
    }
    SvmDebugPrint("[NPT] Prewarmed %ld PT VA cache entries\n", g_PtVaCacheCount);
}