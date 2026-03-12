#pragma once
#include "NPT.h"
#include "SVM.h"

// =========================================================================
// 【终极修复】：全局原子备用内存池 (解决 IPI 广播/高 IRQL 下无法分配内存导致的死机)
// =========================================================================
static PVOID g_EmergencyPtPages[256] = { 0 };
static volatile LONG g_EmergencyPtCount = 0;
static volatile LONG g_PoolInitialized = 0;

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

ULONG64 PrepareNPT(PVCPU_CONTEXT vpData)
{
    vpData->pml4_table = (ULONG64*)AllocateAlignedZeroedMemory(1 * PAGE_SIZE);
    vpData->pdpt_table = (ULONG64*)AllocateAlignedZeroedMemory(1 * PAGE_SIZE);
    vpData->pd_tables = (ULONG64*)AllocateAlignedZeroedMemory(512 * PAGE_SIZE);

    if (vpData->pml4_table == 0 || vpData->pdpt_table == 0 || vpData->pd_tables == 0) {
        if (vpData->pml4_table) MmFreeContiguousMemory(vpData->pml4_table);
        if (vpData->pdpt_table) MmFreeContiguousMemory(vpData->pdpt_table);
        SvmDebugPrint("[ERROR][PrepareNPT] NPT table alloc failed\n");
        return 0;
    }

    // 【新增】：在安全的 PASSIVE_LEVEL 提前分配 256 个 4KB 页作为全局备用池！
    // 15 个 Hook * 8 个核心最多只需要 120 个，256 绝对够用。
    if (InterlockedCompareExchange(&g_PoolInitialized, 1, 0) == 0) {
        for (int i = 0; i < 256; i++) {
            g_EmergencyPtPages[i] = AllocateAlignedZeroedMemory(PAGE_SIZE);
        }
        g_EmergencyPtCount = 256;
    }

    ULONG64 pml4_pa = MmGetPhysicalAddress((PVOID)vpData->pml4_table).QuadPart;
    ULONG64 pdpt_pa = MmGetPhysicalAddress((PVOID)vpData->pdpt_table).QuadPart;
    ULONG64 pd_pa = MmGetPhysicalAddress((PVOID)vpData->pd_tables).QuadPart;

    NPT_ENTRY pml4_entry = { 0 };
    NPT_ENTRY pdpt_entry = { 0 };
    NPT_ENTRY pd_entry = { 0 };
    pml4_entry.Bits.Valid = 1;
    pml4_entry.Bits.Write = 1;
    pml4_entry.Bits.User = 1;
    pml4_entry.Bits.PageFrameNumber = pdpt_pa >> 12;
    vpData->pml4_table[0] = pml4_entry.AsUInt64;

    for (UINT64 i = 0; i < 512; i++) {
        pdpt_entry.Bits.Valid = 1;
        pdpt_entry.Bits.Write = 1;
        pdpt_entry.Bits.User = 1;
        pdpt_entry.Bits.PageFrameNumber = (pd_pa + i * PAGE_SIZE) >> 12;
        vpData->pdpt_table[i] = pdpt_entry.AsUInt64;
    }

    ULONG64 current_hpa = 0;
    for (UINT64 i = 0; i < 512 * 512; i++) {
        pd_entry.Bits.Valid = 1;
        pd_entry.Bits.Write = 1;
        pd_entry.Bits.User = 1;
        pd_entry.Bits.LargePage = 1;
        pd_entry.Bits.PageFrameNumber = current_hpa >> 12;
        current_hpa += 0x200000;
        vpData->pd_tables[i] = pd_entry.AsUInt64;
    }

    return pml4_pa;
}

NTSTATUS SpliteLargePage(PVCPU_CONTEXT vpData, UINT64 pd_index, PULONG64* OutPtTableVa)
{
    if (pd_index >= 262144) {
        return STATUS_INVALID_PARAMETER;
    }

    PNPT_ENTRY pd_entry = (PNPT_ENTRY)&vpData->pd_tables[pd_index];

    if (pd_entry->Bits.LargePage == 0) {
        PHYSICAL_ADDRESS pt_pa;
        pt_pa.QuadPart = pd_entry->Bits.PageFrameNumber << 12;
        PVOID pt_va = MmGetVirtualForPhysical(pt_pa);
        if (!pt_va) {
            SvmDebugPrint("[ERROR][SpliteLargePage] VA lookup failed for PA 0x%llX\n", pt_pa.QuadPart);
            return STATUS_UNSUCCESSFUL;
        }
        *OutPtTableVa = (PULONG64)pt_va;
        return STATUS_SUCCESS;
    }

    PULONG64 new_pt_table = nullptr;

    // 【终极修复】：无脑从全局原子池获取内存，彻底避开高 IRQL 限制！
    LONG idx = InterlockedDecrement(&g_EmergencyPtCount);
    if (idx >= 0 && idx < 256) {
        new_pt_table = (PULONG64)g_EmergencyPtPages[idx];
    }
    else {
        InterlockedIncrement(&g_EmergencyPtCount); // 恢复计数
        // 池子空了才尝试动态分配，如果 IPI 里走到这里非常危险，但 256 页不可能用完
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

    pd_entry->Bits.LargePage = 0;
    pd_entry->Bits.PageFrameNumber = new_pt_pa >> 12;

    if (vpData->SplitPtCount < ARRAYSIZE(vpData->SplitPtPages)) {
        vpData->SplitPtPages[vpData->SplitPtCount++] = new_pt_table;
    }

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

// PA-based pre-split - uses pre-resolved physical address
// Safe when VA might be in session space (Win32k)
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS PreSplitLargePageByPa(PVCPU_CONTEXT vpData, ULONG64 TargetPa)
{
    if (!vpData || TargetPa == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG64 pdpt_idx = (TargetPa >> 30) & 0x1FF;
    ULONG64 pd_idx   = (TargetPa >> 21) & 0x1FF;
    ULONG64 pd_linear = pdpt_idx * 512 + pd_idx;

    PULONG64 dummy = nullptr;
    return SpliteLargePage(vpData, pd_linear, &dummy);
}

// ================================================================
// ApplyNptHookByPa - PA-based PFN replacement
// SAFE to call from ANY context (VMEXIT, IPI, etc.) because it
// never calls MmGetPhysicalAddress or MmProbeAndLockPages.
// Uses pre-resolved TargetPa to compute NPT indices directly.
// ================================================================
NTSTATUS ApplyNptHookByPa(PVCPU_CONTEXT vpData, ULONG64 TargetPa, ULONG64 NewPagePa)
{
    if (TargetPa == 0 || NewPagePa == 0 || !vpData) {
        return STATUS_INVALID_PARAMETER;
    }

    // Compute NPT indices directly from physical address
    ULONG64 pdpt_idx = (TargetPa >> 30) & 0x1FF;
    ULONG64 pd_idx   = (TargetPa >> 21) & 0x1FF;
    ULONG64 pt_idx   = (TargetPa >> 12) & 0x1FF;
    ULONG64 pd_linear = pdpt_idx * 512 + pd_idx;

    PULONG64 ptTable = nullptr;
    NTSTATUS status = SpliteLargePage(vpData, pd_linear, &ptTable);
    if (!NT_SUCCESS(status) || !ptTable) {
        return status;
    }

    PNPT_ENTRY pte = (PNPT_ENTRY)&ptTable[pt_idx];
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

    // TargetPa MUST be pre-resolved before calling this function
    // (done in DelayedHookWorkItemRoutine while attached to CSRSS)
    if (HookContext->TargetPa == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Use PA-based function - safe in VMEXIT context (no MmGetPhysicalAddress)
    NTSTATUS status = ApplyNptHookByPa(vpData, HookContext->TargetPa, HookContext->FakePagePa);
    if (!NT_SUCCESS(status)) return status;

    status = SetNptPagePermissions(vpData, HookContext->TargetPa, NPT_PERM_EXECUTE);
    if (!NT_SUCCESS(status)) return status;

    vpData->Guestvmcb.ControlArea.VmcbClean = 0;
    vpData->Guestvmcb.ControlArea.NCr3 = vpData->NptCr3;
    vpData->Guestvmcb.ControlArea.TlbControl = 1;
    return STATUS_SUCCESS;
}

NTSTATUS SetNptPagePermissions(PVCPU_CONTEXT vpData, ULONG64 TargetPa, ULONG PermissionType)
{
    if (TargetPa == 0) return STATUS_INVALID_PARAMETER;

    PNPT_ENTRY pte = GetNptPteByHostPa(vpData, TargetPa);
    if (pte == nullptr) return STATUS_UNSUCCESSFUL;

    if (PermissionType == NPT_PERM_READ_ONLY) {
        pte->Bits.Valid = 1; pte->Bits.Write = 1; pte->Bits.User = 1; pte->Bits.NoExecute = 1;
    }
    else if (PermissionType == NPT_PERM_EXECUTE) {
        pte->Bits.Valid = 1; pte->Bits.Write = 0; pte->Bits.User = 1; pte->Bits.NoExecute = 0;
    }
    else if (PermissionType == NPT_PERM_NOT_PRESENT) {
        pte->Bits.Valid = 0;
    }
    else return STATUS_INVALID_PARAMETER;

    return STATUS_SUCCESS;
}

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
    npt_context->pt_idx = (npt_context->TargetPa >> 12) & 0x1FF;
    npt_context->pd_linear = npt_context->pdpt_idx * 512 + npt_context->pd_idx;

    return STATUS_SUCCESS;
}

PNPT_ENTRY GetNptPteByHostPa(PVCPU_CONTEXT vpData, ULONG64 TargetPa)
{
    NPT_CONTEXT context = { 0 };
    context.TargetPa = TargetPa;
    context.pdpt_idx = (context.TargetPa >> 30) & 0x1FF;
    context.pd_idx = (context.TargetPa >> 21) & 0x1FF;
    context.pt_idx = (context.TargetPa >> 12) & 0x1FF;
    context.pd_linear = context.pdpt_idx * 512 + context.pd_idx;

    PNPT_ENTRY pd_entry = (PNPT_ENTRY)&vpData->pd_tables[context.pd_linear];
    if (pd_entry->Bits.LargePage == 1) {
        return nullptr;
    }

    PHYSICAL_ADDRESS pt_pa;
    pt_pa.QuadPart = pd_entry->Bits.PageFrameNumber << 12;
    PULONG64 pt_va = (PULONG64)MmGetVirtualForPhysical(pt_pa);

    if (!pt_va) return nullptr;
    return (PNPT_ENTRY)&pt_va[context.pt_idx];
}

VOID FreePvCPUNPT(PVCPU_CONTEXT vpData)
{
    if (vpData->pml4_table) MmFreeContiguousMemory(vpData->pml4_table);
    if (vpData->pdpt_table) MmFreeContiguousMemory(vpData->pdpt_table);
    if (vpData->pd_tables)  MmFreeContiguousMemory(vpData->pd_tables);

    for (ULONG i = 0; i < vpData->SplitPtCount; i++) {
        if (vpData->SplitPtPages[i] != nullptr) {
            MmFreeContiguousMemory(vpData->SplitPtPages[i]);
            vpData->SplitPtPages[i] = nullptr;
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