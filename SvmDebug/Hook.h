/**
 * @file Hook.h
 * @brief NPT Hook框架头文件 - Hook上下文结构体、索引枚举与函数声明
 * @author yewilliam
 * @date 2026/02/06
 */

#pragma once
#include <ntifs.h>

#define HOOK_MAX_COUNT 64
#pragma warning(disable: 4201)

// Undocumented exports
EXTERN_C NTKERNELAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);
EXTERN_C NTKERNELAPI PUCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);

// PEB structures (partial)
typedef struct _RTL_USER_PROCESS_PARAMETERS_LITE {
    UCHAR Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS_LITE, * PRTL_USER_PROCESS_PARAMETERS_LITE;

typedef struct _PEB_LITE {
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PRTL_USER_PROCESS_PARAMETERS_LITE ProcessParameters;
} PEB_LITE, * PPEB_LITE;

typedef struct _VCPU_CONTEXT VCPU_CONTEXT, * PVCPU_CONTEXT;

typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    PVOID GpValue;
    PVOID NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef struct _NPT_HOOK_CONTEXT {
    BOOLEAN IsUsed;
    BOOLEAN ResourcesReady;
    PVOID TargetAddress;
    ULONG64 TargetPa;
    PVOID ProxyFunction;
    PVOID OriginalPageBase;
    ULONG64 OriginalPagePa;
    PVOID FakePage;
    ULONG64 FakePagePa;
    PVOID TrampolinePage;
    SIZE_T HookedBytes;
    ULONG TrampolineLength;
    ULONG StolenBytesLength;
} NPT_HOOK_CONTEXT, * PNPT_HOOK_CONTEXT;

extern NPT_HOOK_CONTEXT g_HookList[HOOK_MAX_COUNT];

#pragma pack(push, 1)
typedef struct _REGISTER_CONTEXT {
    ULONG64 Rax;
    ULONG64 Rcx;
    ULONG64 Rdx;
    ULONG64 Rbx;
    ULONG64 Rsp;
    ULONG64 Rbp;
    ULONG64 Rsi;
    ULONG64 Rdi;
    ULONG64 R8;
    ULONG64 R9;
    ULONG64 R10;
    ULONG64 R11;
    ULONG64 R12;
    ULONG64 R13;
    ULONG64 R14;
    ULONG64 R15;
    ULONG64 Rflags;
} REGISTER_CONTEXT, * PREGISTER_CONTEXT;
#pragma pack(pop)

// 声明全局跳床地址（供汇编使用）
#ifdef __cplusplus
extern "C" ULONG64 g_Trampoline_NtUserBuildHwndList;
#else
extern ULONG64 g_Trampoline_NtUserBuildHwndList;
#endif

/* ========================================================================
 *  HOOK 索引枚举 — 唯一定义点，所有文件通过 Hook.h 引用
 * ======================================================================== */
typedef enum _HOOK_INDEX {
    // ---- SSDT 系统调用 ----
    HOOK_NtQuerySystemInformation = 0,
    HOOK_NtOpenProcess,
    HOOK_NtQueryInformationProcess,
    HOOK_NtQueryVirtualMemory,
    HOOK_NtDuplicateObject,
    HOOK_NtGetNextProcess,
    HOOK_NtGetNextThread,
    HOOK_NtReadVirtualMemory,
    HOOK_NtWriteVirtualMemory,
    HOOK_NtProtectVirtualMemory,
    HOOK_NtTerminateProcess,
    HOOK_NtCreateThreadEx,

    // ---- 内核导出函数 ----
    HOOK_PsLookupProcessByProcessId,
    HOOK_PsLookupThreadByThreadId,
    HOOK_ObReferenceObjectByHandle,
    HOOK_MmCopyVirtualMemory,
    HOOK_PsGetNextProcessThread,
    HOOK_KeStackAttachProcess,

    // ---- SSSDT (Win32k shadow syscall) ----
    HOOK_NtUserFindWindowEx,
    HOOK_NtUserWindowFromPoint,
    HOOK_NtUserBuildHwndList,
    HOOK_ValidateHwnd,            // win32kbase 内部导出

    // ---- 内部函数 (模式扫描) ----
    HOOK_PspReferenceCidTableEntry,

    HOOK_MAX_ENUM_COUNT
} HOOK_INDEX;

NTSTATUS RegisterNptHook(PVOID TargetAddress, PVOID ProxyFunction);
NTSTATUS PrepareAllNptHooks(void);
NTSTATUS ActivateAllNptHooks(PVCPU_CONTEXT vpData);
VOID CleanupAllNptHooks(void);
PNPT_HOOK_CONTEXT FindHookByFaultPa(ULONG64 FaultPa);

NTSTATUS BuildPage(PNPT_HOOK_CONTEXT HookContext);
NTSTATUS BuildTrampoline(PNPT_HOOK_CONTEXT HookContext);
NTSTATUS HookPage(PNPT_HOOK_CONTEXT HookContext);
NTSTATUS PrepareNptHookResources(PVOID TargetAddress, PVOID ProxyFunction, PNPT_HOOK_CONTEXT HookContext);
NTSTATUS ActivateNptHookInNpt(PVCPU_CONTEXT vpData, PNPT_HOOK_CONTEXT HookContext);
VOID FreeNptHook(PNPT_HOOK_CONTEXT HookContext);
NTSTATUS HideDriver(PDRIVER_OBJECT DriverObject);
PVOID GetRealNtAddress(PCWSTR ZwName);

typedef union {
    struct {
        unsigned char jmp_opcode[6];
        unsigned char imm64[8];
    } parts;
    unsigned char bytes[14];
} RedirectInstruction;

typedef union {
    struct {
        unsigned char push_opcode;
        unsigned char push_imm;
        unsigned char mov1_opcode;
        unsigned char mov1_modrm;
        unsigned char mov1_sib;
        unsigned char mov1_imm[4];
        unsigned char mov2_opcode;
        unsigned char mov2_modrm;
        unsigned char mov2_sib;
        unsigned char mov2_disp;
        unsigned char mov2_imm[4];
        unsigned char ret_opcode;
    } parts;
    unsigned char bytes[18];
} TrampolineStackZero;