#pragma once
#include <ntifs.h>
#include <ntddk.h>

typedef struct _REPROTECT_CONTEXT {
	PMDL Mdl;
	PUCHAR LockedVa;

}REPROTECT_CONTEXT,*PREPROTECT_CONTEXT;

NTSTATUS MmLockVaForWrite(
	PVOID Va,
	ULONG Length,
	__out PREPROTECT_CONTEXT ReprotectContext
);



void MmUnLockVaForWrite(
	__out PREPROTECT_CONTEXT ReprotectContext
);