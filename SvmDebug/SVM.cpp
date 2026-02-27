#include "SVM.h"


NTSTATUS GuestEntry()
{

	int cpuInfo[4];
	
	LARGE_INTEGER timeout;
	timeout.QuadPart = -10000; // 等待1毫秒
	while (TRUE)
	{
		__cpuid(cpuInfo, 0);
		KeDelayExecutionThread(KernelMode, FALSE, &timeout);
	}
	return STATUS_SUCCESS;
}


NTSTATUS InitSVMCORE(PSVM_CORE vpData)
{
	if (vpData == nullptr) {
		return STATUS_INVALID_PARAMETER;
	}

	CONTEXT contextRecord = { 0 };
	RtlCaptureContext(&contextRecord);

	if (IsSvmHypervisorInstalled()) {
		// Guest 模式：正常返回，让 OS 继续运行
		SvmDebugPrint("[INFO] CPU %d: 已进入 guest 模式\n",
			KeGetCurrentProcessorNumber());
		DbgBreakPoint();
		int cpuInfo[4];

		LARGE_INTEGER timeout;
		timeout.QuadPart = -10000; // 等待1毫秒
		while (TRUE)
		{
			__cpuid(cpuInfo, 0);
			KeDelayExecutionThread(KernelMode, FALSE, &timeout);
		}
		return STATUS_SUCCESS;  
	}

	NTSTATUS status = PrepareVMCB(vpData, contextRecord);
	if (!NT_SUCCESS(status)) {
		SvmDebugPrint("[ERROR] PrepareVMCB 失败\n");
		return status;
	}

	SvEnterVmmOnNewStack(vpData);

	return STATUS_SUCCESS;
}

//准备VMCB
NTSTATUS PrepareVMCB(PSVM_CORE vpData, CONTEXT contextRecord)
{
	if (vpData == nullptr) {
		SvmDebugPrint("[ERROR][PrepareVMCB]vmcb为空\n");
		return STATUS_INVALID_PARAMETER;
	}

	RtlZeroMemory(&vpData->Guestvmcb, sizeof(VMCB));
	RtlZeroMemory(&vpData->Hostvmcb, sizeof(VMCB));
	//先获得cr系列的寄存器
	vpData->Guestvmcb.StateSaveArea.Cr0 = __readcr0();
	vpData->Guestvmcb.StateSaveArea.Cr2 = __readcr2();
	vpData->Guestvmcb.StateSaveArea.Cr3 = __readcr3();
	vpData->Guestvmcb.StateSaveArea.Cr4 = __readcr4();
	vpData->Guestvmcb.StateSaveArea.Dr6 = __readdr(6);
	vpData->Guestvmcb.StateSaveArea.Dr7 = __readdr(7);
	//获取IDTR、GDTR。
	UINT8 gdtBuffer[10] = { 0 };
	UINT8 idtBuffer[10] = { 0 };

	__sidt(idtBuffer);
	_sgdt(gdtBuffer);

	UINT16 gdtLimit = *(UINT16*)(gdtBuffer + 0);
	UINT64 gdtBase = *(UINT64*)(gdtBuffer + 2);
	UINT16 idtLimit = *(UINT16*)(idtBuffer + 0);
	UINT64 idtBase = *(UINT64*)(idtBuffer + 2);

	vpData->Guestvmcb.StateSaveArea.GdtrLimit = gdtLimit;
	vpData->Guestvmcb.StateSaveArea.GdtrBase = gdtBase;
	vpData->Guestvmcb.StateSaveArea.IdtrLimit = idtLimit;
	vpData->Guestvmcb.StateSaveArea.IdtrBase = idtBase;

	vpData->Guestvmcb.StateSaveArea.Rax = contextRecord.Rax;
	//获取cs ds es ss寄存器
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

	vpData->Guestvmcb.StateSaveArea.Rflags = __readeflags();
	vpData->Guestvmcb.StateSaveArea.Cpl = 0;
	//这里我直接给Rsp一个独立的空间,栈是递减的所以栈顶是反过来的
	//SIZE_T stackSize = PAGE_SIZE * 0x10;  // 64KB
	//vpData->GuestStackBase = ExAllocatePool2(POOL_FLAG_NON_PAGED, stackSize, 'GSTK');
	//if (vpData->GuestStackBase == nullptr) {
	//	return STATUS_INSUFFICIENT_RESOURCES;
	//}
	//RtlZeroMemory(vpData->GuestStackBase, stackSize);
	//vpData->GuestStackTop = (UINT64)vpData->GuestStackBase + stackSize;

	//// ============================================================
	//// Guest stub: 纯机器码，没有任何相对地址，可以在任意地址执行
	////
	//// loop:
	////     mov eax, 0x40000000    ; CPUID hypervisor leaf
	////     cpuid                  ; → 触发 #VMEXIT
	////     jmp loop               ; #VMEXIT 处理完 VMRUN 回来后继续循环
	//// ============================================================
	//UINT8 guestStub[] = {
	//	0xB8, 0x00, 0x00, 0x00, 0x40,   // mov eax, 0x40000000
	//	0x0F, 0xA2,                      // cpuid
	//	0xEB, 0xF7                       // jmp -9 (回到 mov eax)
	//};
	//DbgBreakPoint();
	//vpData->GuestCodeBase = ExAllocatePool2(
	//	POOL_FLAG_NON_PAGED_EXECUTE,
	//	PAGE_SIZE, 'GCOD');
	//if (vpData->GuestCodeBase == nullptr) {
	//	ExFreePoolWithTag(vpData->GuestStackBase, 'GSTK');
	//	return STATUS_INSUFFICIENT_RESOURCES;
	//}
	//RtlZeroMemory(vpData->GuestCodeBase, PAGE_SIZE);
	//RtlCopyMemory(vpData->GuestCodeBase, guestStub, sizeof(guestStub));

	//vpData->Guestvmcb.StateSaveArea.Rsp = vpData->GuestStackTop;
	//vpData->Guestvmcb.StateSaveArea.Rip = (UINT64)vpData->GuestCodeBase;
	vpData->Guestvmcb.StateSaveArea.Rsp = contextRecord.Rsp;
	vpData->Guestvmcb.StateSaveArea.Rip = contextRecord.Rip;
	vpData->Guestvmcb.ControlArea.VIntr = 0;
	vpData->Guestvmcb.ControlArea.InterruptShadow = 0;


	vpData->GuestVmcbPa = MmGetPhysicalAddress(&vpData->Guestvmcb).QuadPart;
	vpData->HostVmcbPa = MmGetPhysicalAddress(&vpData->Hostvmcb).QuadPart;
	//将通用寄存器保存起来

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

	//拦截cpuid指令和拦截vmrun指令
	vpData->Guestvmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_CPUID;
	vpData->Guestvmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMRUN;

	//根据文档要写入MSRC000_0080[SVME]=1才可以算是启动安全虚拟机
	__writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) | EFER_SVME);
	vpData->Guestvmcb.StateSaveArea.Efer = __readmsr(IA32_MSR_EFER);
	//asid不能为0
	vpData->Guestvmcb.ControlArea.GuestAsid = 1;
	
	//手动分配HostVMM独立栈
	vpData->HostStackBase = ExAllocatePool2(POOL_FLAG_NON_PAGED, KERNEL_STACK_SIZE, 'HSTK');
	if (vpData->HostStackBase == nullptr) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(vpData->HostStackBase, KERNEL_STACK_SIZE);
	vpData->HostStackTop = (UINT64)vpData->HostStackBase + KERNEL_STACK_SIZE;

	// ====================================================================
	// AMD 手册要求：在执行 VMRUN 之前，软件必须设置 VM_HSAVE_PA MSR
	// 指向一个页对齐的 4KB 物理地址块，处理器会在此保存 host 状态。
	// 如果不设置，VMRUN 会将 host 状态保存到物理地址 0（或 MSR 中的随机值），
	// 导致 #VMEXIT 时无法正确恢复 host 状态。
	// ====================================================================
	PHYSICAL_ADDRESS hostSaveAreaPa = MmGetPhysicalAddress(vpData->HostSaveArea);
	__writemsr(SVM_MSR_VM_HSAVE_PA, hostSaveAreaPa.QuadPart);

	__svm_vmsave(vpData->GuestVmcbPa);
	__svm_vmsave(vpData->HostVmcbPa);

	return STATUS_SUCCESS;
}

//获得段描述符
UINT16 GetSegmentAttribute(UINT16 SegmentSelector, UINT64 GdtBase)
{
	SEGMENT_ATTRIBUTE attribute = { 0 };
	if ((SegmentSelector & ~RPL_MASK) == 0)
		return attribute.AsUInt16;

	PSEGMENT_DESCRIPTOR descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(
		GdtBase + (SegmentSelector & ~RPL_MASK));

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

//获取段基址
UINT64 GetSegmentBase(UINT16 SegmentSelector, UINT64 GdtBase)
{
	UINT16 index = SegmentSelector >> 3;
	if (index == 0)
		return 0;

	PSEGMENT_DESCRIPTOR descriptor = (PSEGMENT_DESCRIPTOR)(GdtBase + index * sizeof(SEGMENT_DESCRIPTOR));

	ULONG_PTR base = ((ULONG_PTR)descriptor->Fields.BaseHigh << 24) |
		((ULONG_PTR)descriptor->Fields.BaseMiddle << 16) |
		descriptor->Fields.BaseLow;
	return base;
}

//区分vmm是否安装
BOOLEAN IsSvmHypervisorInstalled()
{
	int regs[4] = { 0 };
	char vendorId[13] = { 0 };

	__cpuid(regs, CPUID_HV_VENDOR_AND_MAX_FUNCTIONS);
	RtlCopyMemory(vendorId + 0, &regs[1], 4);
	RtlCopyMemory(vendorId + 4, &regs[2], 4);
	RtlCopyMemory(vendorId + 8, &regs[3], 4);
	vendorId[12] = ANSI_NULL;

	return (strcmp(vendorId, "VtDebugView ") == 0);
}

void SvHandleVmExit(PSVM_CORE vpData)
{
	if (vpData == nullptr) {
		SvmDebugPrint("[ERROR][SvHandleVmExitC]VMData为空\n");
		return;
	}
	PVMCB vmcb = &vpData->Guestvmcb;
	UINT64 exitCode = vmcb->ControlArea.ExitCode;
	UINT32 leaf = (UINT32)vmcb->StateSaveArea.Rax;
	switch (exitCode)
	{
	case VMEXIT_CPUID:

		if (leaf == CPUID_HV_VENDOR_AND_MAX_FUNCTIONS)
		{
			vmcb->StateSaveArea.Rax = CPUID_HV_INTERFACE;
			vpData->Guest_gpr.Rbx = 0x65447456;  // "VtDe"
			vpData->Guest_gpr.Rcx = 0x56677562;  // "bugV"
			vpData->Guest_gpr.Rdx = 0x20776569;  // "iew "
		}
		else
		{
			// 对于普通CPUID，执行真实的CPUID并返回结果给guest
			int cpuInfo[4] = { 0 };
			__cpuidex(cpuInfo, leaf, (int)vpData->Guest_gpr.Rcx);
			vmcb->StateSaveArea.Rax = (UINT64)cpuInfo[0];
			vpData->Guest_gpr.Rbx = (UINT64)cpuInfo[1];
			vpData->Guest_gpr.Rcx = (UINT64)cpuInfo[2];
			vpData->Guest_gpr.Rdx = (UINT64)cpuInfo[3];
		}
		vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
		break;

	case VMEXIT_VMRUN:
		// Guest 尝试执行 VMRUN（被拦截），跳过该指令
		vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
		break;

	default:

		vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
		break;
	}

}

void SVMLauchRun(PSVM_CORE vpData)
{
	if (vpData == nullptr) {
		SvmDebugPrint("[ERROR][SVMLauchRun]VMData为空\n");
		return;
	}
	//SvmDebugPrint("[SVMLauchRun]StateSaveArea.Rsp:%llx\n", vpData->Guestvmcb.StateSaveArea.Rsp);
	SvLaunchVm(vpData);

	return;
}

EXTERN_C void HostLoop(PSVM_CORE vpData)
{
	while (TRUE) {


		SVMLauchRun(vpData);
		vpData->Guest_gpr.Rax = vpData->Guestvmcb.StateSaveArea.Rax;

		SvHandleVmExit(vpData);
	}
}


VOID PrintGuestGpr(PGUEST_GPR Gpr)
{
	if (Gpr == NULL)
	{
		SvmDebugPrint("GUEST_GPR is NULL\n");
		return;
	}

	SvmDebugPrint("GUEST_GPR contents:\n");
	SvmDebugPrint("RAX = %016I64X\n", Gpr->Rax);
	SvmDebugPrint("RBX = %016I64X\n", Gpr->Rbx);
	SvmDebugPrint("RCX = %016I64X\n", Gpr->Rcx);
	SvmDebugPrint("RDX = %016I64X\n", Gpr->Rdx);
	SvmDebugPrint("RSI = %016I64X\n", Gpr->Rsi);
	SvmDebugPrint("RDI = %016I64X\n", Gpr->Rdi);
	SvmDebugPrint("RBP = %016I64X\n", Gpr->Rbp);
	SvmDebugPrint("R8  = %016I64X\n", Gpr->R8);
	SvmDebugPrint("R9  = %016I64X\n", Gpr->R9);
	SvmDebugPrint("R10 = %016I64X\n", Gpr->R10);
	SvmDebugPrint("R11 = %016I64X\n", Gpr->R11);
	SvmDebugPrint("R12 = %016I64X\n", Gpr->R12);
	SvmDebugPrint("R13 = %016I64X\n", Gpr->R13);
	SvmDebugPrint("R14 = %016I64X\n", Gpr->R14);
	SvmDebugPrint("R15 = %016I64X\n", Gpr->R15);
}
