#pragma once﻿
#include "NPT.h"
#include "SVM.h"

ULONG64 g_GlobalNptCr3 = 0;
ULONG64* g_pml4_table = nullptr;
ULONG64* g_pdpt_table = nullptr;
ULONG64* g_pd_tables = nullptr;
ULONG64* g_New_pd_tables = nullptr;



BOOLEAN IsSupportNPT()
{
    //CPUID指令Fn8000_000A_EDX[NP] = 1表示支持嵌套分页。
    //CPUID_FN8000_000A_EDX_NP
    int vector[4];
    __cpuid(vector, CPUID_FN8000_000A_EDX_NP);
    //RAX
    BOOLEAN bNTP = vector[3] & 1;
    return bNTP;
}

NTSTATUS InitNPT(PSVM_CORE vpData)
{
    //判断是否支持NPT分页
    if (IsSupportNPT() == 0) {
        SvmDebugPrint("[ERROR][InitNPT]不支持NPT嵌套分页\n");
        return STATUS_NOT_SUPPORTED;
    }
    //当VMCB中的NP_ENABLE位设置为1时，VMRUN指令将启用嵌套分页。VMCB包含用于额外转换的页表hCR3值。该额外转换采用与VMM执行最近一次VMRUN时相同的分页模式。
    //第0位是NpEnable
    vpData->Guestvmcb.ControlArea.NpEnable = vpData->Guestvmcb.ControlArea.NpEnable | 0x1;

    if (g_GlobalNptCr3 == 0) {
        return STATUS_NOT_FOUND;
    }

    vpData->Guestvmcb.ControlArea.NCr3 = g_GlobalNptCr3;
    if (nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

ULONG64 PrepareNPT()
{
    //创建空间一般来说可分为9 9 9 21的方式比较常见就是4kb 4kb 4kb 2mb
    //如果你是按页申请的，请替换为你获取虚拟地址的逻辑。

    g_pml4_table = (ULONG64*)AllocateAlignedZeroedMemory(1 * PAGE_SIZE);    // 申请 1 页
    g_pdpt_table = (ULONG64*)AllocateAlignedZeroedMemory(1 * PAGE_SIZE);     // 申请 1 页
    g_pd_tables = (ULONG64*)AllocateAlignedZeroedMemory(512 * PAGE_SIZE);   // 申请 512 页

    //判空
    if (g_pml4_table == 0 || g_pdpt_table == 0 || g_pd_tables == 0) {

        if (g_pml4_table == 0) {
            SvmDebugPrint("[ERROR][PrepareNPT]pml4_table申请分页资源失败\n");
            return 0;
        }
        if (g_pdpt_table == 0) {
            SvmDebugPrint("[ERROR][PrepareNPT]pdpt_table申请分页资源失败\n");
            MmFreeContiguousMemory(g_pml4_table);
            return 0;
        }
        if (g_pd_tables == 0) {
            SvmDebugPrint("[ERROR][PrepareNPT]pdpt_table申请分页资源失败\n");
            MmFreeContiguousMemory(g_pml4_table);
            MmFreeContiguousMemory(g_pdpt_table);
            return 0;
        }
        return 0;
    }

    // 获取这三个表的宿主物理地址 (HPA)
    ULONG64 pml4_pa = MmGetPhysicalAddress((PVOID)g_pml4_table).QuadPart;
    ULONG64 pdpt_pa = MmGetPhysicalAddress((PVOID)g_pdpt_table).QuadPart;
    ULONG64 pd_pa = MmGetPhysicalAddress((PVOID)g_pd_tables).QuadPart;

    //初始化entry结构体
    NPT_ENTRY pml4_entry = { 0 };
    NPT_ENTRY pdpt_entry = { 0 };
    NPT_ENTRY pd_entry = { 0 };
    pml4_entry.Bits.Valid = 1;
    pml4_entry.Bits.Write = 1;
    pml4_entry.Bits.User = 1;
    pml4_entry.Bits.PageFrameNumber = pdpt_pa >> 12;
    g_pml4_table[0] = pml4_entry.AsUInt64;

    for (UINT64 i = 0; i < 512; i++) {

        pdpt_entry.Bits.Valid = 1;
        pdpt_entry.Bits.Write = 1;
        pdpt_entry.Bits.User = 1;
        pdpt_entry.Bits.PageFrameNumber = (pd_pa + i * PAGE_SIZE) >> 12;
        g_pdpt_table[i] = pdpt_entry.AsUInt64;
    }

    //映射全部的物理地址 512mb * 512 
    ULONG64 current_hpa = 0;
    for (UINT64 i = 0; i < 512 * 512; i++) {

        pd_entry.Bits.Valid = 1;
        pd_entry.Bits.Write = 1;
        pd_entry.Bits.User = 1;
        //大页2mb
        pd_entry.Bits.LargePage = 1;
        pd_entry.Bits.PageFrameNumber = current_hpa >> 12;
        current_hpa += 0x200000;
        g_pd_tables[i] = pd_entry.AsUInt64;
    }

    return pml4_pa;
}

//将大页分割成512份4kb
NTSTATUS SpliteLargePage(UINT64 pd_index)
{
    g_New_pd_tables = (ULONG64*)AllocateAlignedZeroedMemory(1 * PAGE_SIZE);    // 申请 1 页
    ULONG64 new_pd_pa = MmGetPhysicalAddress((PVOID)g_New_pd_tables).QuadPart;
    if (g_New_pd_tables == nullptr) {
        SvmDebugPrint("[ERROR][SpliteLargePage]g_New_pd_tables申请分页资源失败\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    NPT_ENTRY new_pd_entry = { 0 };
    PNPT_ENTRY old_pd_entry = (PNPT_ENTRY)&g_pd_tables[pd_index];
    ULONG64 original_hpa_base = old_pd_entry->Bits.PageFrameNumber << 12;

    for (UINT64 i = 0; i < 512; i++) {
        new_pd_entry.AsUInt64 = old_pd_entry->AsUInt64;
        new_pd_entry.Bits.LargePage = 0;
        new_pd_entry.Bits.PageFrameNumber = (original_hpa_base + PAGE_SIZE * i) >> 12;
        g_New_pd_tables[i] = new_pd_entry.AsUInt64;
    }
    //重定向新pd
    old_pd_entry->Bits.LargePage = 0;                    // 摘掉大页标志
    old_pd_entry->Bits.PageFrameNumber = new_pd_pa >> 12; // PFN 指向新表

    return STATUS_SUCCESS;
}

// 释放资源，防止内存泄漏
VOID FreeGlobalNPT()
{
    if (g_pml4_table) MmFreeContiguousMemory(g_pml4_table);
    if (g_pdpt_table) MmFreeContiguousMemory(g_pdpt_table);
    if (g_pd_tables)  MmFreeContiguousMemory(g_pd_tables);
    if (g_New_pd_tables)  MmFreeContiguousMemory(g_New_pd_tables);
    g_pml4_table = g_pdpt_table = g_pd_tables = g_New_pd_tables = nullptr;
}

PVOID AllocateAlignedZeroedMemory(SIZE_T NumberOfBytes)
{
    PHYSICAL_ADDRESS HighestAcceptableAddress;
    HighestAcceptableAddress.QuadPart = ~0ULL; // 允许在任何物理地址分配

    // 申请物理连续的内存
    PVOID pMemory = MmAllocateContiguousMemory(NumberOfBytes, HighestAcceptableAddress);
    if (pMemory) {
        // 务必清零
        RtlZeroMemory(pMemory, NumberOfBytes);
    }

    return pMemory;
}