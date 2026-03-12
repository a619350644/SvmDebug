#include "SVM.h"
#include "HvMemory.h"

extern ULONG64 g_SystemCr3;

static inline VOID ForceNptFlush(PVCPU_CONTEXT vpData)
{
	vpData->Guestvmcb.ControlArea.VmcbClean = 0;
	vpData->Guestvmcb.ControlArea.NCr3 = vpData->NptCr3;
	vpData->Guestvmcb.ControlArea.TlbControl = 1;
}

// ================================================================
// 【FIX】从 Guest RIP 直接读取指令字节并解码 MOV CRn
//
// AMD SVM 对 exception intercepts（如 #GP）不填充
// GuestInstructionBytes / NumOfBytesFetched！
// 因此必须从 Guest RIP 直接读取。
//
// 在我们的 hypervisor 中，Host 和 Guest 共享内核地址空间，
// 且内核代码页始终驻留（non-paged），所以可以直接访问。
// ================================================================
static BOOLEAN DecodeCrInstructionFromRip(
	UINT64 GuestRip,
	PULONG crNum,
	PULONG gprNum,
	PULONG instrLen,
	PBOOLEAN isWrite)
{
	// 安全检查：只处理内核地址
	if (GuestRip < 0xFFFF800000000000ULL) return FALSE;
	if (!MmIsAddressValid((PVOID)GuestRip)) return FALSE;

	PUCHAR instr = (PUCHAR)GuestRip;
	ULONG pos = 0;
	BOOLEAN rexB = FALSE, rexR = FALSE;

	// 跳过 Legacy prefixes (最多扫描 5 个前缀)
	for (int i = 0; i < 5 && MmIsAddressValid((PVOID)(GuestRip + pos)); i++) {
		UCHAR b = instr[pos];
		if (b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x66 ||
			b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
			b == 0x64 || b == 0x65 || b == 0x67) {
			pos++;
		}
		else break;
	}

	// 检测 REX prefix (0x40-0x4F)
	if (MmIsAddressValid((PVOID)(GuestRip + pos)) && (instr[pos] & 0xF0) == 0x40) {
		rexB = (instr[pos] & 0x01) != 0;
		rexR = (instr[pos] & 0x04) != 0;
		pos++;
	}

	// 需要至少 3 个字节: 0F + 22/20 + ModRM
	if (!MmIsAddressValid((PVOID)(GuestRip + pos + 2))) return FALSE;

	// MOV CRn, GPR = 0F 22 /r    MOV GPR, CRn = 0F 20 /r
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

	// 拦截 #DB (Hook单步) + #GP (模拟 mov crN)
	vpData->Guestvmcb.ControlArea.InterceptException |= (1UL << 1);   // #DB
	vpData->Guestvmcb.ControlArea.InterceptException |= (1UL << 13);  // #GP

	// RDTSC/RDTSCP
	vpData->Guestvmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_RDTSC;
	vpData->Guestvmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_RDTSCP;

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

void SvHandleVmExit(PVCPU_CONTEXT vpData)
{
	if (vpData == nullptr) return;
	PVMCB vmcb = &vpData->Guestvmcb;

	// 暗影恢复
	if (vpData->SuspendedHook != nullptr) {
		PNPT_HOOK_CONTEXT suspCtx = (PNPT_HOOK_CONTEXT)vpData->SuspendedHook;
		ULONG64 ripPage = vmcb->StateSaveArea.Rip & ~0xFFFULL;
		ULONG64 hookVaPage = ((ULONG64)suspCtx->TargetAddress) & ~0xFFFULL;
		if (ripPage != hookVaPage) {
			ApplyNptHookByPa(vpData, suspCtx->TargetPa, suspCtx->OriginalPagePa);
			SetNptPagePermissions(vpData, suspCtx->TargetPa, NPT_PERM_READ_ONLY);
			ForceNptFlush(vpData);
			vpData->SuspendedHook = nullptr;
		}
	}

	UINT64 exitCode = vmcb->ControlArea.ExitCode;
	UINT32 leaf = (UINT32)vmcb->StateSaveArea.Rax;

	switch (exitCode)
	{
	case VMEXIT_CPUID:
	{
		if (leaf == CPUID_HV_VENDOR_AND_MAX_FUNCTIONS) {
			extern HANDLE g_PendingProtectPID;
			g_PendingProtectPID = (HANDLE)vpData->Guest_gpr.Rcx;
			vmcb->StateSaveArea.Rax = CPUID_HV_INTERFACE;
			vpData->Guest_gpr.Rbx = 0x65447456;
			vpData->Guest_gpr.Rcx = 0x56677562;
			vpData->Guest_gpr.Rdx = 0x20776569;
		}
		else if (leaf == CPUID_UNLOAD_SVM_DEBUG) {
			extern volatile BOOLEAN g_DriverUnloading;
			g_DriverUnloading = TRUE;
			     
			// 在广播 IPI 之前先恢复 DKOM
			RestoreProcessByDkom();
			RestoreAllProcessCallbacks();

			// 当前核心退出
			vpData->isExit = 1;
		}
		else if (leaf == CPUID_UNLOAD_SVM_INSTALL_HOOK) {
			ActivateAllNptHooks(vpData);
			ForceNptFlush(vpData);
		}
		else if (leaf == CPUID_UNLOAD_SVM_UNINSTALL_HOOK) {
			vpData->Guest_gpr.Rax = 0;
			break;
		}
		else if (leaf == CPUID_HV_MEMORY_OP) {
			vpData->Guest_gpr.Rbx = g_HvSharedContextPa;
			HvHandleMemoryOp(vpData);
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

	case VMEXIT_NPF:
	{
		UINT64 faultHpa = vmcb->ControlArea.ExitInfo2;
		UINT64 errorCode = vmcb->ControlArea.ExitInfo1;
		BOOLEAN isExecFault = (errorCode & 0x10) != 0;
		PNPT_HOOK_CONTEXT hookCtx = FindHookByFaultPa(faultHpa);
		if (hookCtx != nullptr) {
			if (isExecFault) {
				if (vmcb->StateSaveArea.Rip == (ULONG64)hookCtx->TargetAddress) {
					ApplyNptHookByPa(vpData, hookCtx->TargetPa, hookCtx->FakePagePa);
					SetNptPagePermissions(vpData, hookCtx->TargetPa, NPT_PERM_EXECUTE);
					vpData->ActiveHook = hookCtx;
					vmcb->StateSaveArea.Rflags |= 0x100;
					ForceNptFlush(vpData);
				}
				else {
					ApplyNptHookByPa(vpData, hookCtx->TargetPa, hookCtx->OriginalPagePa);
					SetNptPagePermissions(vpData, hookCtx->TargetPa, NPT_PERM_EXECUTE);
					vpData->SuspendedHook = hookCtx;
					ForceNptFlush(vpData);
				}
			}
			else {
				ApplyNptHookByPa(vpData, hookCtx->TargetPa, hookCtx->OriginalPagePa);
				SetNptPagePermissions(vpData, hookCtx->TargetPa, NPT_PERM_READ_ONLY);
				ForceNptFlush(vpData);
			}
		}
		break;
	}

	case VMEXIT_EXCEPTION_DB:
	{
		if (vpData->ActiveHook != nullptr) {
			PNPT_HOOK_CONTEXT hookCtx = (PNPT_HOOK_CONTEXT)vpData->ActiveHook;
			vmcb->StateSaveArea.Rflags &= ~(UINT64)0x100;
			ApplyNptHookByPa(vpData, hookCtx->TargetPa, hookCtx->OriginalPagePa);
			SetNptPagePermissions(vpData, hookCtx->TargetPa, NPT_PERM_READ_ONLY);
			vpData->ActiveHook = nullptr;
			ForceNptFlush(vpData);
		}
		else {
			EVENTINJ reinject = { 0 };
			reinject.Fields.Vector = 1;
			reinject.Fields.Type = 3;
			reinject.Fields.Valid = 1;
			vmcb->ControlArea.EventInj = reinject.AsUInt64;
		}
		break;
	}

	// ================================================================
	// #GP 处理：从 Guest RIP 读取指令，模拟 MOV CRn
	// ================================================================
	case VMEXIT_EXCEPTION_GP:
	{
		ULONG crNum = 0, gprNum = 0, instrLen = 0;
		BOOLEAN isCrWrite = FALSE;

		// 【关键修复】从 Guest RIP 读取指令字节，不依赖 GuestInstructionBytes
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
			// 非 MOV CRn，重新注入 #GP
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

	case VMEXIT_RDTSC:
	{
		UINT64 tsc = __rdtsc();
		tsc -= 2000;
		vmcb->StateSaveArea.Rax = tsc & 0xFFFFFFFF;
		vpData->Guest_gpr.Rdx = tsc >> 32;
		vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
		break;
	}

	case VMEXIT_RDTSCP:
	{
		UINT64 tsc = __rdtsc();
		tsc -= 2000;
		vmcb->StateSaveArea.Rax = tsc & 0xFFFFFFFF;
		vpData->Guest_gpr.Rdx = tsc >> 32;
		vpData->Guest_gpr.Rcx = (UINT64)(__readmsr(0xC0000103) & 0xFFFFFFFF);
		vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
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
		else if (leaf == 0x12345678) {
			extern HANDLE g_PendingProtectPID;
			g_PendingProtectPID = (HANDLE)vpData->Guest_gpr.Rcx;
			vmcb->StateSaveArea.Rax = 1;
			vpData->Guest_gpr.Rax = 1;
			SvmDebugPrint("g_PendingProtectPID:%lu\n", g_PendingProtectPID);
		}
		else if (leaf == 0x12345679) {
			AddProtectedHwnd((SVM_HWND)vpData->Guest_gpr.Rcx);
			vpData->Guest_gpr.Rax = 1;
		}
		else if (leaf == 0x1234567A) {
			AddProtectedChildHwnd((SVM_HWND)vpData->Guest_gpr.Rcx);
			vpData->Guest_gpr.Rax = 1;
		}
		else if (leaf == 0x1234567F) {
			ClearAllProtectedTargets();
			vpData->Guest_gpr.Rax = 1;
		}
		else if (leaf == 0x12345680) {
			DisableAllProcessCallbacks();
			vpData->Guest_gpr.Rax = 1;
		}
		else if (leaf == 0x12345681) {
			RestoreAllProcessCallbacks();
			vpData->Guest_gpr.Rax = 1;
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