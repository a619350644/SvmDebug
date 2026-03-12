#pragma once
#include <ntifs.h>

EXTERN_C
VOID
_sgdt(
    _Out_ PVOID Descriptor
);

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessInformation = 5,
    SystemHandleInformation = 16,
    SystemExtendedHandleInformation = 64,
} SYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS_EX {
    ProcessBasicInformation_Ex = 0,
    ProcessDebugPort_Ex = 7,
    ProcessWow64Information_Ex = 26,
    ProcessImageFileName_Ex = 27,
    ProcessBreakOnTermination_Ex = 29,
    ProcessDebugObjectHandle_Ex = 30,
    ProcessDebugFlags_Ex = 31,
    ProcessHandleInformation_Ex = 51,
    ProcessImageFileNameWin32_Ex = 43,
} PROCESSINFOCLASS_EX;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

// SystemHandleInformation (Class 16)
typedef struct _SVM_HANDLE_ENTRY {
    USHORT OwnerPid;
    USHORT BackTraceIndex;
    UCHAR  ObjTypeIdx;
    UCHAR  Attribs;
    USHORT Value;
    PVOID  ObjectPtr;
    ULONG  GrantedAcc;
} SVM_HANDLE_ENTRY, * PSVM_HANDLE_ENTRY;

typedef struct _SVM_HANDLE_INFO {
    ULONG NumberOfHandles;
    SVM_HANDLE_ENTRY Handles[1];
} SVM_HANDLE_INFO, * PSVM_HANDLE_INFO;

// SystemExtendedHandleInformation (Class 64)
typedef struct _SVM_HANDLE_ENTRY_EX {
    PVOID      ObjectPtr;
    ULONG_PTR  OwnerPid;
    ULONG_PTR  Value;
    ULONG      GrantedAcc;
    USHORT     BackTraceIndex;
    USHORT     ObjTypeIdx;
    ULONG      Attribs;
    ULONG      Reserved;
} SVM_HANDLE_ENTRY_EX, * PSVM_HANDLE_ENTRY_EX;

typedef struct _SVM_HANDLE_INFO_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SVM_HANDLE_ENTRY_EX Handles[1];
} SVM_HANDLE_INFO_EX, * PSVM_HANDLE_INFO_EX;

// ================================================================
// SSDT function pointer typedefs
// ================================================================

typedef NTSTATUS(NTAPI* FnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* FnNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
    );

typedef NTSTATUS(NTAPI* FnNtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead
    );

typedef NTSTATUS(NTAPI* FnNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
    );

typedef NTSTATUS(NTAPI* FnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* FnNtQueryVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
    );

typedef NTSTATUS(NTAPI* FnNtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
    );

typedef NTSTATUS(NTAPI* FnNtGetNextProcess)(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewProcessHandle
    );

typedef NTSTATUS(NTAPI* FnNtGetNextThread)(
    HANDLE ProcessHandle,
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewThreadHandle
    );

typedef NTSTATUS(NTAPI* FnPsLookupProcessByProcessId)(
    _In_ HANDLE ProcessId,
    _Out_ PEPROCESS* Process
    );

typedef NTSTATUS(NTAPI* FnPsLookupThreadByThreadId)(
    _In_ HANDLE ThreadId,
    _Out_ PETHREAD* Thread
    );

typedef NTSTATUS(NTAPI* FnObReferenceObjectByHandle)(
    _In_ HANDLE Handle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PVOID* Object,
    _Out_opt_ POBJECT_HANDLE_INFORMATION HandleInformation
    );

typedef NTSTATUS(NTAPI* FnMmCopyVirtualMemory)(
    _In_ PEPROCESS FromProcess,
    _In_ PVOID FromAddress,
    _In_ PEPROCESS ToProcess,
    _Out_ PVOID ToAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T NumberOfBytesCopied
    );

typedef VOID(NTAPI* FnKeStackAttachProcess)(
    _Inout_ PRKPROCESS Process,
    _Out_ PRKAPC_STATE ApcState
    );

typedef PETHREAD(NTAPI* FnPsGetNextProcessThread)(
    _In_ PEPROCESS Process,
    _In_opt_ PETHREAD Thread
    );

// ================================================================
// SSSDT (Shadow SSDT / Win32k) function pointer typedefs
// ================================================================
#ifndef SVM_HWND_DEFINED
#define SVM_HWND_DEFINED
typedef HANDLE SVM_HWND;
#endif

// NtUserFindWindowEx - shadow syscall for window enumeration
typedef SVM_HWND(NTAPI* FnNtUserFindWindowEx)(
    _In_opt_ SVM_HWND hwndParent,
    _In_opt_ SVM_HWND hwndChildAfter,
    _In_opt_ PUNICODE_STRING lpszClass,
    _In_opt_ PUNICODE_STRING lpszWindow,
    _In_ ULONG dwType
    );

// NtUserWindowFromPoint - shadow syscall for point-to-window lookup
typedef SVM_HWND(NTAPI* FnNtUserWindowFromPoint)(
    _In_ LONG x,
    _In_ LONG y
    );

// ValidateHwnd - win32k internal, validates HWND and returns tagWND*
typedef PVOID(NTAPI* FnValidateHwnd)(
    _In_ SVM_HWND hwnd
    );

// ================================================================
// Unexported ntoskrnl function typedefs
// ================================================================

// PspReferenceCidTableEntry - internal CID table lookup
// Used by PsLookupProcessByProcessId / PsLookupThreadByThreadId internally
typedef PVOID(NTAPI* FnPspReferenceCidTableEntry)(
    _In_ HANDLE Id,
    _In_ BOOLEAN IsThread
    );

// ================================================================
// Extern declarations
// ================================================================
EXTERN_C NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
EXTERN_C NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(PEPROCESS Process);
