/**
 * @file winApiDef.h
 * @brief Windows API定义 - 函数指针typedef、系统信息结构体、Win32k窗口结构体
 * @author yewilliam
 * @date 2026/02/06
 *
 * 包含所有Hook目标函数的函数指针类型定义，
 * SystemProcessInformation/HandleInformation等系统信息结构体，
 * 以及Win32k tagWND/THREADINFO等最小窗口结构体定义。
 */

#pragma once
#include <ntifs.h>

EXTERN_C
VOID
_sgdt(
    _Out_ PVOID Descriptor
);

/* ========================================================================
 *  SVM_HWND ���� �� ȫ��Ψһ����
 * ======================================================================== */
#ifndef SVM_HWND_DEFINED
#define SVM_HWND_DEFINED
typedef HANDLE SVM_HWND;
#endif

/* ========================================================================
 *  ϵͳ��Ϣö��
 * ======================================================================== */
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessInformation = 5,
    SystemHandleInformation = 16,
    SystemExtendedHandleInformation = 64,
} SYSTEM_INFORMATION_CLASS;

/* ========================================================================
 *  ϵͳ������Ϣ�ṹ��
 * ======================================================================== */
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

/* ========================================================================
 *  SSDT ����ָ��
 * ======================================================================== */
typedef NTSTATUS(NTAPI* FnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

typedef NTSTATUS(NTAPI* FnNtOpenProcess)(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

typedef NTSTATUS(NTAPI* FnNtQueryInformationProcess)(
    HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

typedef NTSTATUS(NTAPI* FnNtQueryVirtualMemory)(
    HANDLE ProcessHandle, PVOID BaseAddress, ULONG MemoryInformationClass,
    PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

typedef NTSTATUS(NTAPI* FnNtDuplicateObject)(
    HANDLE SourceProcessHandle, HANDLE SourceHandle,
    HANDLE TargetProcessHandle, PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);

typedef NTSTATUS(NTAPI* FnNtGetNextProcess)(
    HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle);

typedef NTSTATUS(NTAPI* FnNtGetNextThread)(
    HANDLE ProcessHandle, HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes,
    ULONG Flags, PHANDLE NewThreadHandle);

typedef NTSTATUS(NTAPI* FnNtReadVirtualMemory)(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T Size, PSIZE_T NumberOfBytesRead);

typedef NTSTATUS(NTAPI* FnNtWriteVirtualMemory)(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T Size, PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS(NTAPI* FnNtProtectVirtualMemory)(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

typedef NTSTATUS(NTAPI* FnNtTerminateProcess)(
    HANDLE ProcessHandle, NTSTATUS ExitStatus);

typedef NTSTATUS(NTAPI* FnNtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
    PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits,
    SIZE_T StackSize, SIZE_T MaximumStackSize,
    PVOID AttributeList);

/* ========================================================================
 *  �ں˵�������ָ��
 * ======================================================================== */
typedef NTSTATUS(NTAPI* FnPsLookupProcessByProcessId)(
    HANDLE ProcessId, PEPROCESS* Process);

typedef NTSTATUS(NTAPI* FnPsLookupThreadByThreadId)(
    HANDLE ThreadId, PETHREAD* Thread);

typedef NTSTATUS(NTAPI* FnObReferenceObjectByHandle)(
    HANDLE Handle, ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode,
    PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation);

typedef NTSTATUS(NTAPI* FnMmCopyVirtualMemory)(
    PEPROCESS FromProcess, PVOID FromAddress,
    PEPROCESS ToProcess, PVOID ToAddress,
    SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
    PSIZE_T NumberOfBytesCopied);

typedef PETHREAD(NTAPI* FnPsGetNextProcessThread)(
    PEPROCESS Process, PETHREAD Thread);

typedef VOID(NTAPI* FnKeStackAttachProcess)(
    PEPROCESS Process, PKAPC_STATE ApcState);

/* ========================================================================
 *  SSSDT (Win32k) ����ָ��
 * ======================================================================== */
typedef SVM_HWND(NTAPI* FnNtUserFindWindowEx)(
    SVM_HWND hwndParent, SVM_HWND hwndChildAfter,
    PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, ULONG dwType);

typedef SVM_HWND(NTAPI* FnNtUserWindowFromPoint)(
    LONG x, LONG y);

typedef PVOID(NTAPI* FnValidateHwnd)(
    SVM_HWND hwnd);

// NtUserBuildHwndList (Win10 8������)
typedef NTSTATUS(NTAPI* FnNtUserBuildHwndList)(
    HANDLE hdesk, SVM_HWND hwndNext, ULONG fEnumChildren,
    ULONG bRemoveImmersive, ULONG idThread,
    ULONG cHwndMax, SVM_HWND* phwndFirst, ULONG* pcHwndNeeded);

/* ========================================================================
 *  �ڲ�δ��������ָ��
 * ======================================================================== */
typedef PVOID(NTAPI* FnPspReferenceCidTableEntry)(
    HANDLE Id, BOOLEAN IsThread);

/* ========================================================================
 *  Extern ����
 * ======================================================================== */

/* ========================================================================
 *  Win32k minimal structures for ValidateHwnd Hook *  tagWND+0x10 -> pti (THREADINFO*), pti+0x00 -> pEThread
 * ======================================================================== */
#pragma pack(push, 8)
typedef struct _SVM_W32THREAD {
    PETHREAD pEThread;           // +0x00
} SVM_W32THREAD, *PSVM_W32THREAD;

typedef struct _SVM_WND {
    PVOID           hHandle;     // +0x00 HEAD.h
    ULONG           cLockObj;    // +0x08 HEAD.cLockObj
    ULONG           _pad;        // +0x0C
    PSVM_W32THREAD  pti;         // +0x10 THROBJHEAD.pti
} SVM_WND, *PSVM_WND;
#pragma pack(pop)

EXTERN_C NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
EXTERN_C NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(PEPROCESS Process);