#include <ntifs.h>
#include "SVM.h"

// 给虚拟核64个
SVM_CORE g_nVMCB[64] = { 0 };
HANDLE g_ProtectedPID = NULL;
// IPI广播回调函数，在每个核心的 IPI_LEVEL (IRQL 29) 级别执行
ULONG_PTR IpiInstallBroadcastCallback(ULONG_PTR Argument) {
	UNREFERENCED_PARAMETER(Argument);

	ULONG processorNumber = KeGetCurrentProcessorNumber();
	if (processorNumber >= 64) {
		return 0;
	}
	PSVM_CORE vpData = &g_nVMCB[processorNumber];

	// 检查当前核是否支持SVM
	BOOLEAN Support = CommCheckAMDsupport();
	if (!Support) {
		return 0;
	}
	// 执行SVM虚拟化接管
	NTSTATUS status = InitSVMCORE(vpData);

	return NT_SUCCESS(status) ? 1 : 0;
}

ULONG_PTR IpiUnloadBroadcastCallback(ULONG_PTR Argument) {
	UNREFERENCED_PARAMETER(Argument);
	int regs[4] = { 0 };

	__cpuid(regs, CPUID_UNLOAD_SVM_DEBUG);
	
	return 0;
}

void UnloadDriver(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	// 卸载逻辑：需要发送卸载 IPI 广播、执行 VMMCALL 让虚拟机退出，并释放内存
	ULONG n_cout = KeQueryActiveProcessorCount(0);
	if (n_cout > 64) {
		n_cout = 64;
	}

	KeIpiGenericCall(IpiUnloadBroadcastCallback, 0);
	for (ULONG i = 0; i < n_cout; i++) {
		if (g_nVMCB[i].HostStackBase) {
			// 释放已经分配的内存
			ExFreePoolWithTag(g_nVMCB[i].HostStackBase, 'HSTK');
		}
		
		g_nVMCB[i].HostStackTop = 0;
	}
	//释放npt
	FreeGlobalNPT();
	SvmDebugPrint("[DrvMain] 开始 IPI 广播卸载 SVM...\n");

	return;
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath) {
	UNREFERENCED_PARAMETER(RegPath);
	DriverObject->DriverUnload = UnloadDriver;

	char vendor[13] = { 0 };
	CommGetCPUName(vendor, sizeof(vendor));
	SvmDebugPrint("CPUName:%s\n", vendor);

	if (strcmp(vendor, "AuthenticAMD") != 0) {
		SvmDebugPrint("[ERROR] 当前处理器不是AMD\n");
		return STATUS_NOT_SUPPORTED;
	}

	// 获取多少个核心
	ULONG n_cout = KeQueryActiveProcessorCount(0);
	if (n_cout > 64) {
		n_cout = 64;
	}

	// 1.核心步骤：必须在 PASSIVE_LEVEL 预先分配内存！
	// 因为 KeIpiGenericCall 运行在 IPI_LEVEL，绝对不允许调用 ExAllocatePool2
	for (ULONG i = 0; i < n_cout; i++) {
		g_nVMCB[i].HostStackBase = ExAllocatePool2(POOL_FLAG_NON_PAGED, KERNEL_STACK_SIZE, 'HSTK');
		if (g_nVMCB[i].HostStackBase == nullptr) {
			SvmDebugPrint("[DrvMain] CPU %lu: HostStackBase 分配失败\n", i);
			// 释放已经分配的内存
			for (ULONG j = 0; j < i; j++) {
				ExFreePoolWithTag(g_nVMCB[j].HostStackBase, 'HSTK');
			}
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		RtlZeroMemory(g_nVMCB[i].HostStackBase, KERNEL_STACK_SIZE);
		g_nVMCB[i].HostStackTop = (UINT64)g_nVMCB[i].HostStackBase + KERNEL_STACK_SIZE;
	}
	// 2.构建npt页表，原因多态竞争问题+ipi等级问题
	SvmDebugPrint("[DrvMain] 开始在安全级别构建全局 NPT 页表...\n");
	g_GlobalNptCr3 = PrepareNPT();
	SvmDebugPrint("[DrvMain] 开始 IPI 广播初始化 SVM...\n");

	// 3.发起 IPI 广播，所有 CPU 核心将同时执行 IpiBroadcastCallback
	KeIpiGenericCall(IpiInstallBroadcastCallback, 0);

	SvmDebugPrint("[DrvMain] IPI 广播初始化完成！系统现在运行在 Guest 中。\n");

	return STATUS_SUCCESS;
}