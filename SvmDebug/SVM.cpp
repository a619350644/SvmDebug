// Disable C4819 (codepage 936 encoding warning) BEFORE any other content
#pragma warning(disable: 4819)

/**
 * @file SVM.cpp
 * @brief SVM Virtualization Engine - VMCB config, VMEXIT dispatch, hypercall handling
 * @author yewilliam
 * @date 2026/02/06
 *
 * [BUGFIX 2026/03/15] NPF handler: check ApplyNptHookByPa/SetNptPagePermissions
 *   return values. On failure, ForceNptFlush for consistency. Don't set
 *   SuspendedHook if page table ops failed, preventing bad restoration.
 *
 * [BUGFIX preserved] Removed RDTSC/RDTSCP interception
 * [BUGFIX preserved] NPF handler for unknown pages
 */

#include "SVM.h"
#include "HvMemory.h"

extern ULONG64 g_SystemCr3;

static inline VOID ForceNptFlush(PVCPU_CONTEXT vpData)
{
    vpData->Guestvmcb.ControlArea.VmcbClean = 0;
    vpData->Guestvmcb.ControlArea.NCr3 = vpData->NptCr3;
    vpData->Guestvmcb.ControlArea.TlbControl = 1;
}

static __forceinline BOOLEAN IsKernelAddressLikely(UINT64 Address)
{
    return (Address >= 0xFFFF800000000000ULL && Address <= 0xFFFFFFFFFFFFFFFFULL);
}

static BOOLEAN DecodeCrInstructionFromRip(
    UINT64 GuestRip,
    PULONG crNum,
    PULONG gprNum,
    PULONG instrLen,
    PBOOLEAN isWrite)
{
    if (!IsKernelAddressLikely(GuestRip)) return FALSE;

    __try {
        PUCHAR instr = (PUCHAR)GuestRip;
        ULONG pos = 0;
        BOOLEAN rexB = FALSE, rexR = FALSE;

        for (int i = 0; i < 5; i++) {
            UCHAR b = instr[pos];
            if (b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x66 ||
                b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
                b == 0x64 || b == 0x65 || b == 0x67) {
                pos++;
            }
            else break;
        }

        if ((instr[pos] & 0xF0) == 0x40) {
            rexB = (instr[pos] & 0x01) != 0;
            rexR = (instr[pos] & 0x04) != 0;
            pos++;
        }

        if (instr[pos] == 0x0F && (instr[pos + 1] == 0x22 || instr[pos + 1] == 0x20)) {
            UCHAR modrm = instr[pos + 2];
            *crNum = (modrm >> 3) & 7;
            *gprNum = modrm & 7;
            if (rexR) *crNum += 8;
            if (rexB) *gprNum += 8;
            *instrLen = pos + 3;
            *isWrite = (instr[pos + 1] == 0x22);
            return TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return FALSE;
}

static UINT64 ReadGuestGpr(PVCPU_CONTEXT vpData, PVMCB vmcb, ULONG gprIndex)
{
    switch (gprIndex) {
    case 0:  return vmcb->StateSaveArea.Rax;
    case 1:  return vpData->Guest_gpr.Rcx;
    case 2:  return vpData->Guest_gpr.Rdx;
    case 3:  return vpData->Guest_gpr.Rbx;
    case 4:  return vmcb->StateSaveArea.Rsp;
    case 5:  return vpData->Guest_gpr.Rbp;
    case 6:  return vpData->Guest_gpr.Rsi;
    case 7:  return vpData->Guest_gpr.Rdi;
    case 8:  return vpData->Guest_gpr.R8;
    case 9:  return vpData->Guest_gpr.R9;
    case 10: return vpData->Guest_gpr.R10;
    case 11: return vpData->Guest_gpr.R11;
    case 12: return vpData->Guest_gpr.R12;
    case 13: return vpData->Guest_gpr.R13;
    case 14: return vpData->Guest_gpr.R14;
    case 15: return vpData->Guest_gpr.R15;
    default: return 0;
    }
}

static VOID WriteGuestGpr(PVCPU_CONTEXT vpData, PVMCB vmcb, ULONG gprIndex, UINT64 value)
{
    switch (gprIndex) {
    case 0:  vmcb->StateSaveArea.Rax = value; break;
    case 1:  vpData->Guest_gpr.Rcx = value; break;
    case 2:  vpData->Guest_gpr.Rdx = value; break;
    case 3:  vpData->Guest_gpr.Rbx = value; break;
    case 4:  vmcb->StateSaveArea.Rsp = value; break;
    case 5:  vpData->Guest_gpr.Rbp = value; break;
    case 6:  vpData->Guest_gpr.Rsi = value; break;
    case 7:  vpData->Guest_gpr.Rdi = value; break;
    case 8:  vpData->Guest_gpr.R8 = value; break;
    case 9:  vpData->Guest_gpr.R9 = value; break;
    case 10: vpData->Guest_gpr.R10 = value; break;
    case 11: vpData->Guest_gpr.R11 = value; break;
    case 12: vpData->Guest_gpr.R12 = value; break;
    case 13: vpData->Guest_gpr.R13 = value; break;
    case 14: vpData->Guest_gpr.R14 = value; break;
    case 15: vpData->Guest_gpr.R15 = value; break;
    }
}

NTSTATUS InitSVMCORE(PVCPU_CONTEXT vpData)
{
    if (vpData == nullptr) return STATUS_INVALID_PARAMETER;
    CONTEXT contextRecord = { 0 };
    RtlCaptureContext(&contextRecord);
    if (IsSvmHypervisorInstalled()) return STATUS_SUCCESS;
    NTSTATUS status = PrepareVMCB(vpData, contextRecord);
    if (!NT_SUCCESS(status)) {
        SvmDebugPrint("[ERROR] CPU %d: PrepareVMCB failed\n", KeGetCurrentProcessorNumber());
        return status;
    }
    if (g_SystemCr3 != 0) __writecr3(g_SystemCr3);
    SvEnterVmmOnNewStack(vpData);
    return STATUS_SUCCESS;
}

NTSTATUS PrepareVMCB(PVCPU_CONTEXT vpData, CONTEXT contextRecord)
{
    if (vpData == nullptr) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(&vpData->Guestvmcb, sizeof(VMCB));
    RtlZeroMemory(&vpData->Hostvmcb, sizeof(VMCB));

    NTSTATUS status = InitNPT(vpData);
    if (!NT_SUCCESS(status)) return STATUS_NOT_SUPPORTED;

    vpData->Guestvmcb.StateSaveArea.Cr0 = __readcr0();
    vpData->Guestvmcb.StateSaveArea.Cr2 = __readcr2();
    vpData->Guestvmcb.StateSaveArea.Cr3 = __readcr3();
    vpData->Guestvmcb.StateSaveArea.Cr4 = __readcr4();
    vpData->Guestvmcb.StateSaveArea.Dr6 = __readdr(6);
    vpData->Guestvmcb.StateSaveArea.Dr7 = __readdr(7);

    UINT8 gdtBuffer[10] = { 0 }, idtBuffer[10] = { 0 };
    __sidt(idtBuffer);
    _sgdt(gdtBuffer);
    UINT16 gdtLimit = *(UINT16*)(gdtBuffer);
    UINT64 gdtBase = *(UINT64*)(gdtBuffer + 2);
    UINT16 idtLimit = *(UINT16*)(idtBuffer);
    UINT64 idtBase = *(UINT64*)(idtBuffer + 2);

    vpData->Guestvmcb.StateSaveArea.GdtrLimit = gdtLimit;
    vpData->Guestvmcb.StateSaveArea.GdtrBase = gdtBase;
    vpData->Guestvmcb.StateSaveArea.IdtrLimit = idtLimit;
    vpData->Guestvmcb.StateSaveArea.IdtrBase = idtBase;
    vpData->Guestvmcb.StateSaveArea.Rax = contextRecord.Rax;

    vpData->Guestvmcb.StateSaveArea.CsSelector = contextRecord.SegCs;
    vpData->Guestvmcb.StateSaveArea.CsLimit = GetSegmentLimit(contextRecord.SegCs);
    vpData->Guestvmcb.StateSaveArea.CsAttrib = GetSegmentAttribute(contextRecord.SegCs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.CsBase = GetSegmentBase(contextRecord.SegCs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.DsSelector = contextRecord.SegDs;
    vpData->Guestvmcb.StateSaveArea.DsLimit = GetSegmentLimit(contextRecord.SegDs);
    vpData->Guestvmcb.StateSaveArea.DsAttrib = GetSegmentAttribute(contextRecord.SegDs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.DsBase = GetSegmentBase(contextRecord.SegDs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.EsSelector = contextRecord.SegEs;
    vpData->Guestvmcb.StateSaveArea.EsLimit = GetSegmentLimit(contextRecord.SegEs);
    vpData->Guestvmcb.StateSaveArea.EsAttrib = GetSegmentAttribute(contextRecord.SegEs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.EsBase = GetSegmentBase(contextRecord.SegEs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.SsSelector = contextRecord.SegSs;
    vpData->Guestvmcb.StateSaveArea.SsLimit = GetSegmentLimit(contextRecord.SegSs);
    vpData->Guestvmcb.StateSaveArea.SsAttrib = GetSegmentAttribute(contextRecord.SegSs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.SsBase = GetSegmentBase(contextRecord.SegSs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.FsSelector = contextRecord.SegFs;
    vpData->Guestvmcb.StateSaveArea.FsLimit = GetSegmentLimit(contextRecord.SegFs);
    vpData->Guestvmcb.StateSaveArea.FsAttrib = GetSegmentAttribute(contextRecord.SegFs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.FsBase = __readmsr(MSR_IA32_FS_BASE);
    vpData->Guestvmcb.StateSaveArea.GsSelector = contextRecord.SegGs;
    vpData->Guestvmcb.StateSaveArea.GsLimit = GetSegmentLimit(contextRecord.SegGs);
    vpData->Guestvmcb.StateSaveArea.GsAttrib = GetSegmentAttribute(contextRecord.SegGs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.GsBase = __readmsr(MSR_IA32_GS_BASE);

    vpData->Guestvmcb.StateSaveArea.Rflags = __readeflags();
    vpData->Guestvmcb.StateSaveArea.Cpl = 0;
    vpData->Guestvmcb.StateSaveArea.GPat = __readmsr(IA32_MSR_PAT);
    vpData->Guestvmcb.StateSaveArea.Rsp = contextRecord.Rsp;
    vpData->Guestvmcb.StateSaveArea.Rip = contextRecord.Rip;
    vpData->Guestvmcb.ControlArea.VIntr = 0;
    vpData->Guestvmcb.ControlArea.InterruptShadow = 0;

    vpData->GuestVmcbPa = MmGetPhysicalAddress(&vpData->Guestvmcb).QuadPart;
    vpData->HostVmcbPa = MmGetPhysicalAddress(&vpData->Hostvmcb).QuadPart;

    vpData->Guest_gpr.Rax = contextRecord.Rax;
    vpData->Guest_gpr.Rbx = contextRecord.Rbx;
    vpData->Guest_gpr.Rcx = contextRecord.Rcx;
    vpData->Guest_gpr.Rdx = contextRecord.Rdx;
    vpData->Guest_gpr.Rsi = contextRecord.Rsi;
    vpData->Guest_gpr.Rdi = contextRecord.Rdi;
    vpData->Guest_gpr.Rbp = contextRecord.Rbp;
    vpData->Guest_gpr.R8 = contextRecord.R8;
    vpData->Guest_gpr.R9 = contextRecord.R9;
    vpData->Guest_gpr.R10 = contextRecord.R10;
    vpData->Guest_gpr.R11 = contextRecord.R11;
    vpData->Guest_gpr.R12 = contextRecord.R12;
    vpData->Guest_gpr.R13 = contextRecord.R13;
    vpData->Guest_gpr.R14 = contextRecord.R14;
    vpData->Guest_gpr.R15 = contextRecord.R15;

    vpData->Guestvmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_CPUID;
    vpData->Guestvmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMRUN | SVM_INTERCEPT_MISC2_VMCALL;

    vpData->Guestvmcb.ControlArea.InterceptException |= (1UL << 1);   /* #DB */
    vpData->Guestvmcb.ControlArea.InterceptException |= (1UL << 13);  /* #GP */

    /* Do NOT intercept RDTSC/RDTSCP - causes physical machine freeze */

    __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) | EFER_SVME);
    vpData->Guestvmcb.StateSaveArea.Efer = __readmsr(IA32_MSR_EFER);
    vpData->Guestvmcb.ControlArea.GuestAsid = 1;

    PHYSICAL_ADDRESS hostSaveAreaPa = MmGetPhysicalAddress(vpData->HostSaveArea);
    __writemsr(SVM_MSR_VM_HSAVE_PA, hostSaveAreaPa.QuadPart);
    if ((vpData->GuestVmcbPa & 0xFFF) != 0 || (hostSaveAreaPa.QuadPart & 0xFFF) != 0) {
        return STATUS_UNSUCCESSFUL;
    }
    __svm_vmsave(vpData->GuestVmcbPa);
    __svm_vmsave(vpData->HostVmcbPa);
    return STATUS_SUCCESS;
}

UINT16 GetSegmentAttribute(UINT16 SegmentSelector, UINT64 GdtBase)
{
    SEGMENT_ATTRIBUTE attribute = { 0 };
    if ((SegmentSelector & ~RPL_MASK) == 0) return attribute.AsUInt16;
    PSEGMENT_DESCRIPTOR descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(GdtBase + (SegmentSelector & ~RPL_MASK));
    attribute.Fields.Type = descriptor->Fields.Type;
    attribute.Fields.System = descriptor->Fields.System;
    attribute.Fields.Dpl = descriptor->Fields.Dpl;
    attribute.Fields.Present = descriptor->Fields.Present;
    attribute.Fields.Avl = descriptor->Fields.Avl;
    attribute.Fields.LongMode = descriptor->Fields.LongMode;
    attribute.Fields.DefaultBit = descriptor->Fields.DefaultBit;
    attribute.Fields.Granularity = descriptor->Fields.Granularity;
    attribute.Fields.Reserved1 = 0;
    return attribute.AsUInt16;
}

UINT64 GetSegmentBase(UINT16 SegmentSelector, UINT64 GdtBase)
{
    UINT16 index = SegmentSelector >> 3;
    if (index == 0) return 0;
    PSEGMENT_DESCRIPTOR descriptor = (PSEGMENT_DESCRIPTOR)(GdtBase + index * sizeof(SEGMENT_DESCRIPTOR));
    ULONG_PTR base = ((ULONG_PTR)descriptor->Fields.BaseHigh << 24) |
        ((ULONG_PTR)descriptor->Fields.BaseMiddle << 16) | descriptor->Fields.BaseLow;
    return base;
}

BOOLEAN IsSvmHypervisorInstalled()
{
    int regs[4] = { 0 };
    char vendorId[13] = { 0 };
    __cpuid(regs, CPUID_HV_VENDOR_AND_MAX_FUNCTIONS);
    RtlCopyMemory(vendorId, &regs[1], 4);
    RtlCopyMemory(vendorId + 4, &regs[2], 4);
    RtlCopyMemory(vendorId + 8, &regs[3], 4);
    vendorId[12] = ANSI_NULL;
    return (strcmp(vendorId, "VtDebugView ") == 0);
}

static BOOLEAN HandleHypercallCommand(PVCPU_CONTEXT vpData, PVMCB vmcb, UINT32 cmd)
{
    if (cmd == 0x12345678) {
        HANDLE pid = (HANDLE)vpData->Guest_gpr.Rcx;
        AddProtectedPid(pid);
        extern HANDLE g_PendingProtectPID;
        g_PendingProtectPID = pid;
        vmcb->StateSaveArea.Rax = 1;
        vpData->Guest_gpr.Rax = 1;
        SvmDebugPrint("[HyperCall] HIDE_PID: %llu, added to protection list\n", (ULONG64)pid);
        return TRUE;
    }
    else if (cmd == 0x12345679) {
        AddProtectedHwnd((SVM_HWND)vpData->Guest_gpr.Rcx);
        vmcb->StateSaveArea.Rax = 1;
        vpData->Guest_gpr.Rax = 1;
        SvmDebugPrint("[HyperCall] HIDE_HWND: 0x%llX\n", vpData->Guest_gpr.Rcx);
        return TRUE;
    }
    else if (cmd == 0x1234567A) {
        AddProtectedChildHwnd((SVM_HWND)vpData->Guest_gpr.Rcx);
        vmcb->StateSaveArea.Rax = 1;
        vpData->Guest_gpr.Rax = 1;
        return TRUE;
    }
    else if (cmd == 0x1234567F) {
        ClearAllProtectedTargets();
        vmcb->StateSaveArea.Rax = 1;
        vpData->Guest_gpr.Rax = 1;
        return TRUE;
    }
    else if (cmd == 0x12345680) {
        /* [BUGFIX 2026/03/15] 不在 VMEXIT 上下文执行回调操作！
         * VMEXIT 处于等效 HIGH_LEVEL IRQL，直接操作 EX_FAST_REF
         * 回调数组会导致池分配器红黑树损坏 → BSOD 0x139 (Arg1=0x1d)
         * 改为设置标志，由 CommunicationThread 在 PASSIVE_LEVEL 执行 */
        vmcb->StateSaveArea.Rax = 1;
        vpData->Guest_gpr.Rax = 1;
        return TRUE;
    }
    else if (cmd == 0x12345681) {
        /* [BUGFIX 2026/03/15] 同上：延迟到 PASSIVE_LEVEL */
        vmcb->StateSaveArea.Rax = 1;
        vpData->Guest_gpr.Rax = 1;
        return TRUE;
    }
    return FALSE;
}

/**
 * @brief VMEXIT dispatch center
 *
 * [BUGFIX 2026/03/15] NPF handler checks return values of
 *   ApplyNptHookByPa / SetNptPagePermissions. On failure, still
 *   flushes TLB for consistency. SuspendedHook only set on success.
 */
void SvHandleVmExit(PVCPU_CONTEXT vpData)
{
    if (vpData == nullptr) return;
    PVMCB vmcb = &vpData->Guestvmcb;

    /* SuspendedHook restoration: when RIP leaves the hook page, restore normal state */
    if (vpData->SuspendedHook != nullptr) {
        PNPT_HOOK_CONTEXT suspCtx = (PNPT_HOOK_CONTEXT)vpData->SuspendedHook;
        ULONG64 ripPage = vmcb->StateSaveArea.Rip & ~0xFFFULL;
        ULONG64 hookVaPage = ((ULONG64)suspCtx->TargetAddress) & ~0xFFFULL;

        if (ripPage != hookVaPage) {
            /* [BUGFIX 2026/03/15] 检查 RIP 是否落在同物理页的另一个 Hook 上
             * 如果是，切换 SuspendedHook 而不是恢复原始页 */
            BOOLEAN switchedToOtherHook = FALSE;
            ULONG64 suspPagePa = suspCtx->TargetPa & ~0xFFFULL;

            for (int hh = 0; hh < HOOK_MAX_COUNT; hh++) {
                if (!g_HookList[hh].IsUsed || &g_HookList[hh] == suspCtx) continue;
                ULONG64 otherVaPage = ((ULONG64)g_HookList[hh].TargetAddress) & ~0xFFFULL;
                if (ripPage == otherVaPage &&
                    (g_HookList[hh].TargetPa & ~0xFFFULL) == suspPagePa)
                {
                    vpData->SuspendedHook = &g_HookList[hh];
                    switchedToOtherHook = TRUE;
                    break;
                }
            }

            if (!switchedToOtherHook) {
                /* [BUGFIX 2026/03/15] Check return values, always flush */
                ApplyNptHookByPa(vpData, suspCtx->TargetPa, suspCtx->OriginalPagePa);
                SetNptPagePermissions(vpData, suspCtx->TargetPa, NPT_PERM_READ_ONLY);
                ForceNptFlush(vpData);
                vpData->SuspendedHook = nullptr;
            }
        }
    }

    UINT64 exitCode = vmcb->ControlArea.ExitCode;
    UINT32 leaf = (UINT32)vmcb->StateSaveArea.Rax;

    switch (exitCode)
    {
    case VMEXIT_CPUID:
    {
        if (leaf == CPUID_HV_VENDOR_AND_MAX_FUNCTIONS) {
            vmcb->StateSaveArea.Rax = CPUID_HV_INTERFACE;
            vpData->Guest_gpr.Rbx = 0x65447456;
            vpData->Guest_gpr.Rcx = 0x56677562;
            vpData->Guest_gpr.Rdx = 0x20776569;
        }
        else if (leaf == CPUID_UNLOAD_SVM_DEBUG) {
            extern volatile BOOLEAN g_DriverUnloading;
            g_DriverUnloading = TRUE;
            MemoryBarrier();
            vpData->isExit = 1;
        }
        else if (leaf == CPUID_UNLOAD_SVM_INSTALL_HOOK) {
            ForceNptFlush(vpData);
        }
        else if (leaf == CPUID_UNLOAD_SVM_UNINSTALL_HOOK) {
            /* [BUGFIX 2026/03/15] 卸载前恢复所有 NPT 条目到原始物理页，
             * 确保 SVM 退出后 Guest 直接执行原始代码，
             * 避免 RawInputThread 等永久线程仍在执行 FakePage 代码
             * 导致 PAGE_FAULT_IN_NONPAGED_AREA (0x50) BSOD。 */
            for (int i = 0; i < HOOK_MAX_COUNT; i++) {
                if (g_HookList[i].IsUsed && g_HookList[i].TargetPa != 0
                    && g_HookList[i].OriginalPagePa != 0) {
                    ApplyNptHookByPa(vpData, g_HookList[i].TargetPa, g_HookList[i].OriginalPagePa);
                    SetNptPagePermissions(vpData, g_HookList[i].TargetPa, NPT_PERM_EXECUTE);
                }
            }
            vpData->SuspendedHook = nullptr;
            vpData->ActiveHook = nullptr;
            ForceNptFlush(vpData);
            vpData->Guest_gpr.Rax = 0;
        }
        else if (leaf == CPUID_HV_MEMORY_OP) {
            vpData->Guest_gpr.Rbx = g_HvSharedContextPa;
            HvHandleMemoryOp(vpData);
        }
        else if (HandleHypercallCommand(vpData, vmcb, leaf)) {
            /* handled */
        }
        else {
            int cpuInfo[4] = { 0 };
            __cpuidex(cpuInfo, leaf, (int)vpData->Guest_gpr.Rcx);
            vmcb->StateSaveArea.Rax = (UINT64)cpuInfo[0];
            vpData->Guest_gpr.Rbx = (UINT64)cpuInfo[1];
            vpData->Guest_gpr.Rcx = (UINT64)cpuInfo[2];
            vpData->Guest_gpr.Rdx = (UINT64)cpuInfo[3];
        }
        vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
        break;
    }

    case VMEXIT_VMRUN:
        vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
        break;

        /*
         * NPF handler - No TF model (Execution/Read split)
         *
         * [BUGFIX 2026/03/15] All page table operations check return values.
         * SuspendedHook only set when both ops succeed.
         */
    case VMEXIT_NPF:
    {
        UINT64 faultHpa = vmcb->ControlArea.ExitInfo2;
        UINT64 errorCode = vmcb->ControlArea.ExitInfo1;
        BOOLEAN isExecFault = (errorCode & 0x10) != 0;
        PNPT_HOOK_CONTEXT hookCtx = FindHookByFaultPa(faultHpa);

        if (hookCtx != nullptr) {
            if (isExecFault) {
                NTSTATUS s1, s2;
                if (vmcb->StateSaveArea.Rip == (ULONG64)hookCtx->TargetAddress) {
                    s1 = ApplyNptHookByPa(vpData, hookCtx->TargetPa, hookCtx->FakePagePa);
                }
                else {
                    s1 = ApplyNptHookByPa(vpData, hookCtx->TargetPa, hookCtx->OriginalPagePa);
                }
                s2 = SetNptPagePermissions(vpData, hookCtx->TargetPa, NPT_PERM_EXECUTE);
                ForceNptFlush(vpData);

                /* Only set SuspendedHook if both operations succeeded */
                if (NT_SUCCESS(s1) && NT_SUCCESS(s2)) {
                    vpData->SuspendedHook = hookCtx;
                }
            }
            else {
                /* Read/write fault - show original page */
                ApplyNptHookByPa(vpData, hookCtx->TargetPa, hookCtx->OriginalPagePa);
                SetNptPagePermissions(vpData, hookCtx->TargetPa, NPT_PERM_READ_ONLY);
                ForceNptFlush(vpData);
            }
        }
        else {
            /* Non-hook NPF - possibly MMIO or NPT coverage gap */
            SvmDebugPrint("[WARN] Unhandled NPF: HPA=0x%llX RIP=0x%llX err=0x%llX\n",
                faultHpa, vmcb->StateSaveArea.Rip, errorCode);
        }
        break;
    }

    case VMEXIT_EXCEPTION_DB:
    {
        EVENTINJ reinject = { 0 };
        reinject.Fields.Vector = 1;
        reinject.Fields.Type = 3;
        reinject.Fields.Valid = 1;
        vmcb->ControlArea.EventInj = reinject.AsUInt64;
        break;
    }

    case VMEXIT_EXCEPTION_GP:
    {
        ULONG crNum = 0, gprNum = 0, instrLen = 0;
        BOOLEAN isCrWrite = FALSE;

        if (DecodeCrInstructionFromRip(vmcb->StateSaveArea.Rip, &crNum, &gprNum, &instrLen, &isCrWrite))
        {
            if (isCrWrite) {
                UINT64 value = ReadGuestGpr(vpData, vmcb, gprNum);
                switch (crNum) {
                case 0: vmcb->StateSaveArea.Cr0 = value; break;
                case 2: vmcb->StateSaveArea.Cr2 = value; break;
                case 3: vmcb->StateSaveArea.Cr3 = value; break;
                case 4: vmcb->StateSaveArea.Cr4 = value; break;
                default: break;
                }
            }
            else {
                UINT64 value = 0;
                switch (crNum) {
                case 0: value = vmcb->StateSaveArea.Cr0; break;
                case 2: value = vmcb->StateSaveArea.Cr2; break;
                case 3: value = vmcb->StateSaveArea.Cr3; break;
                case 4: value = vmcb->StateSaveArea.Cr4; break;
                default: break;
                }
                WriteGuestGpr(vpData, vmcb, gprNum, value);
            }
            vmcb->StateSaveArea.Rip += instrLen;
        }
        else {
            EVENTINJ reinject = { 0 };
            reinject.Fields.Vector = 13;
            reinject.Fields.Type = 3;
            reinject.Fields.ErrorCodeValid = 1;
            reinject.Fields.Valid = 1;
            reinject.Fields.ErrorCode = (UINT32)vmcb->ControlArea.ExitInfo1;
            vmcb->ControlArea.EventInj = reinject.AsUInt64;
        }
        break;
    }

    case VMEXIT_VMMCALL:
    {
        leaf = (UINT32)vmcb->StateSaveArea.Rax;

        if ((leaf & 0xFFFFFF00) == VMMCALL_CR_WRITE_BASE) {
            ULONG crNum = leaf & 0xFF;
            UINT64 value = vpData->Guest_gpr.Rcx;
            switch (crNum) {
            case 0: vmcb->StateSaveArea.Cr0 = value; break;
            case 2: vmcb->StateSaveArea.Cr2 = value; break;
            case 3: vmcb->StateSaveArea.Cr3 = value; break;
            case 4: vmcb->StateSaveArea.Cr4 = value; break;
            default: break;
            }
            vmcb->StateSaveArea.Rax = 0;
        }
        else if ((leaf & 0xFFFFFF00) == VMMCALL_CR_READ_BASE) {
            ULONG crNum = leaf & 0xFF;
            UINT64 value = 0;
            switch (crNum) {
            case 0: value = vmcb->StateSaveArea.Cr0; break;
            case 2: value = vmcb->StateSaveArea.Cr2; break;
            case 3: value = vmcb->StateSaveArea.Cr3; break;
            case 4: value = vmcb->StateSaveArea.Cr4; break;
            default: break;
            }
            vpData->Guest_gpr.Rcx = value;
            vmcb->StateSaveArea.Rax = 0;
        }
        else if (HandleHypercallCommand(vpData, vmcb, leaf)) {
            /* handled */
        }
        else {
            vpData->Guest_gpr.Rax = 0xFFFFFFFFFFFFFFFFull;
        }
        vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
        break;
    }

    default:
        vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
        break;
    }
}

void SVMLauchRun(PVCPU_CONTEXT vpData)
{
    if (vpData == nullptr) return;
    SvLaunchVm(vpData);
}

EXTERN_C void HostLoop(PVCPU_CONTEXT vpData)
{
    while (!vpData->isExit) {
        SVMLauchRun(vpData);
        vpData->Guest_gpr.Rax = vpData->Guestvmcb.StateSaveArea.Rax;
        SvHandleVmExit(vpData);
    }
    SvSwitchStack(vpData);
}

VOID PrintGuestGpr(PGUEST_GPR Gpr)
{
    if (Gpr == NULL) { SvmDebugPrint("GUEST_GPR is NULL\n"); return; }
    SvmDebugPrint("RAX=%016I64X RBX=%016I64X RCX=%016I64X RDX=%016I64X\n",
        Gpr->Rax, Gpr->Rbx, Gpr->Rcx, Gpr->Rdx);
}