#include <ntifs.h>
#include "SVM.h"
//要用多线程给多个核心使用。
//我们给虚拟核64个，所以留下size=64个数组
SVM_CORE g_nVMCB[64] = { 0 };

KSTART_ROUTINE KstartRoutine;

VOID KstartRoutine(PVOID StartContext) {

	char vendor[13] = { 0 };
	//先判断是amd还是intel
	CommGetCPUName(vendor, sizeof(vendor));
	SvmDebugPrint("CPUName:%s\n", vendor);
	NTSTATUS STATUS = 0;
	if (strcmp(vendor, "AuthenticAMD") == 0) {
		//我们先绑核
		KAFFINITY OldAffinity;
		KAFFINITY affinity = (KAFFINITY)1 << (ULONG_PTR)StartContext;
		OldAffinity = KeSetSystemAffinityThreadEx(affinity);
		//先判断支不支持svm功能
		BOOLEAN Support = CommCheckAMDsupport();
		if (!Support) {
			SvmDebugPrint("[ERROR][DriverEntry][CommCheckAMDsupport]不支持SVM功能\n");
			STATUS = STATUS_UNSUCCESSFUL;
			KeRevertToUserAffinityThreadEx(OldAffinity);
		}
		else {
			STATUS = InitSVMCORE(&(g_nVMCB[(ULONG_PTR)StartContext]));
			//if (NT_SUCCESS(STATUS)) {
			//	HostLoop(&(g_nVMCB[(ULONG_PTR)StartContext]));
			//}
		}

		KeRevertToUserAffinityThreadEx(OldAffinity);
	}
	
	PsTerminateSystemThread(STATUS);
	return;
}

void UnloadDriver(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	

	return;
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath) {
	UNREFERENCED_PARAMETER(RegPath);
	DriverObject->DriverUnload = UnloadDriver;

	//获取多少个核心
	ULONG n_cout = KeQueryActiveProcessorCount(0);
	if (n_cout > 128) {
		n_cout = 128;
	}
	for (ULONG i = 0; i < n_cout; i++) {
		NTSTATUS status;
		HANDLE  ThreadHandle;
		CLIENT_ID ClientID;
		PVOID StartContext = (PVOID)(ULONG_PTR)i;
		//这里面写每个虚拟核的代码，要创建线程和事件来完成
		status = PsCreateSystemThread(&ThreadHandle,
			THREAD_ALL_ACCESS,
			nullptr,
			nullptr,
			&ClientID,
			KstartRoutine,
			StartContext
		);
		
		if (!NT_SUCCESS(status)) {
			SvmDebugPrint("[DrvMain] CPU %lu: PsCreateSystemThread FAILED: 0x%08X\n", i, status);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		else {
			g_nVMCB[i].Guest_Thread = ThreadHandle;
			
		}

	}


	return STATUS_SUCCESS;
}
