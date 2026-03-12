#include "MDL.h"

NTSTATUS MmLockVaForWrite(PVOID Va, ULONG Length, __out PREPROTECT_CONTEXT ReprotectContext)
{
	
	NTSTATUS status;
	status = STATUS_SUCCESS;

	ReprotectContext->Mdl = 0;
	ReprotectContext->LockedVa = 0;

	// IRP (i/o request packet) 
	ReprotectContext->Mdl= IoAllocateMdl(Va, Length, FALSE, FALSE, NULL);   //分配缓冲区

	if (!ReprotectContext->Mdl) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try {

		//非分页内存 分页内存
		MmProbeAndLockPages(ReprotectContext->Mdl, KernelMode, IoReadAccess);

	}
	__except (EXCEPTION_EXECUTE_HANDLER){
		return GetExceptionCode();
	}
	//真正实现映射 分配虚拟地址
	ReprotectContext->LockedVa=(PUCHAR)MmMapLockedPagesSpecifyCache(ReprotectContext->Mdl,
								KernelMode, MmCached, NULL, FALSE, NormalPagePriority);

	if (!ReprotectContext->LockedVa) {

		IoFreeMdl(ReprotectContext->Mdl);
		ReprotectContext->Mdl = 0;
		return STATUS_UNSUCCESSFUL;
	}

	status =MmProtectMdlSystemAddress(ReprotectContext->Mdl, PAGE_EXECUTE_READWRITE);

	if (!NT_SUCCESS(status)) {
		MmUnmapLockedPages(ReprotectContext->LockedVa, ReprotectContext->Mdl);
		MmUnlockPages(ReprotectContext->Mdl);
		IoFreeMdl(ReprotectContext->Mdl);
		ReprotectContext->Mdl = 0;
		ReprotectContext->LockedVa = 0;
	}



	return status;
}





void MmUnLockVaForWrite(__out PREPROTECT_CONTEXT ReprotectContext)
{
	NTSTATUS status;
	status = STATUS_SUCCESS;

	MmUnmapLockedPages(ReprotectContext->LockedVa, ReprotectContext->Mdl);
	MmUnlockPages(ReprotectContext->Mdl);
	IoFreeMdl(ReprotectContext->Mdl);

	ReprotectContext->Mdl = 0;
	ReprotectContext->LockedVa = 0;


}
