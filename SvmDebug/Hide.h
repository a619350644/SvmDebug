#pragma once
#include <ntifs.h>
#include "Common.h"
#include "Hook.h"
#include "winApiDef.h"

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ            (0x0010)
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE           (0x0020)
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION       (0x0008)
#endif

#define IOCTL_SET_PROTECT_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000

// ================================================================
// Multi-target protection arrays
// Supports up to MAX_PROTECTED_PIDS processes and MAX_PROTECTED_HWNDS windows
// ================================================================
#define MAX_PROTECTED_PIDS   20
#define MAX_PROTECTED_HWNDS  20
#define MAX_PROTECTED_CHILD_HWNDS 256
extern PEPROCESS g_CsrssProcess;
extern HANDLE  g_ProtectedPIDs[MAX_PROTECTED_PIDS];
extern volatile LONG g_ProtectedPidCount;

extern SVM_HWND g_ProtectedHwnds[MAX_PROTECTED_HWNDS];
extern volatile LONG g_ProtectedHwndCount;

extern SVM_HWND g_ProtectedChildHwnds[MAX_PROTECTED_CHILD_HWNDS];
extern volatile LONG g_ProtectedChildHwndCount;

// Legacy single-PID interface (first entry in array, for backward compat)
extern HANDLE g_ProtectedPID;
extern WCHAR g_ProtectedProcessName[260];

extern HANDLE g_PendingProtectPID;
extern HANDLE g_WorkerThreadHandle;
extern volatile BOOLEAN g_DriverUnloading;


// 1. 定义底层函数指针
// 更新函数指针定义，增加 Windows 10 专属参数 bRemoveImmersive
typedef NTSTATUS(NTAPI* FnNtUserBuildHwndList)(
    HANDLE hdesk,
    SVM_HWND hwndNext,
    ULONG fEnumChildren,
    ULONG bRemoveImmersive, // <--- 微软暗改的第 4 个参数
    ULONG idThread,
    ULONG cHwndMax,
    SVM_HWND* phwndFirst,
    ULONG* pcHwndNeeded     // 真正的第 8 个参数
    );

static FnNtUserBuildHwndList g_OrigNtUserBuildHwndList = nullptr;

// Windows 底层回调结构
typedef struct _EX_FAST_REF {
    union {
        PVOID Object;
        ULONG_PTR RefCnt : 4;
        ULONG_PTR Value;
    };
} EX_FAST_REF, * PEX_FAST_REF;

typedef struct _EX_CALLBACK_ROUTINE_BLOCK {
    EX_RUNDOWN_REF RundownProtect;
    PVOID Function; // 这个就是回调函数的真实地址
    PVOID Context;
} EX_CALLBACK_ROUTINE_BLOCK, * PEX_CALLBACK_ROUTINE_BLOCK;

// 全局变量，用于保存被我们暂时“拔掉”的回调指针，方便后续恢复
#define MAX_CALLBACKS 64

extern PVOID g_SavedCallbacks[MAX_CALLBACKS];
extern PEX_FAST_REF g_PspCreateProcessNotifyRoutine;
// R3 <-> R0 communication structure
typedef struct _PROTECT_INFO {
    ULONG64 Pid;
    WCHAR ProcessName[260];
} PROTECT_INFO, * PPROTECT_INFO;

// Extended communication structure with HWND support
typedef struct _PROTECT_INFO_EX {
    ULONG64 Pid;
    ULONG64 Hwnd;           // Main window handle
    ULONG64 ChildHwnds[8];  // Up to 8 child windows per request
    ULONG   ChildHwndCount;
    WCHAR   ProcessName[260];
} PROTECT_INFO_EX, * PPROTECT_INFO_EX;

// Global Hook array (defined in Hook.cpp)
extern NPT_HOOK_CONTEXT g_HookList[HOOK_MAX_COUNT];

// Forward declarations
typedef struct _VCPU_CONTEXT VCPU_CONTEXT, * PVCPU_CONTEXT;

// ================================================================
// Multi-target management
// ================================================================
BOOLEAN AddProtectedPid(HANDLE Pid);
BOOLEAN RemoveProtectedPid(HANDLE Pid);
VOID ClearAllProtectedTargets();

BOOLEAN AddProtectedHwnd(SVM_HWND Hwnd);
BOOLEAN AddProtectedChildHwnd(SVM_HWND Hwnd);

static BOOLEAN IsStringMatch(PCSTR s1, PCSTR s2);

ULONG GetSssdtIndexDynamic(PCSTR FunctionName);

// ================================================================
// Phase 1: Called at PASSIVE_LEVEL in DriverEntry
// ================================================================
NTSTATUS PrepareAllNptHookResources();
NTSTATUS InitializeProcessHideHooks();
VOID LinkTrampolineAddresses();

// Phase 2: Called in VMEXIT handler
NTSTATUS ActivateAllNptHooks(PVCPU_CONTEXT vpData);

// Cleanup
VOID CleanupAllNptHooks();

// ================================================================
// Helper functions
// ================================================================
BOOLEAN IsProtectedProcessHandle(HANDLE ProcessHandle);
BOOLEAN IsProtectedPid(HANDLE Pid);
BOOLEAN IsProtectedHwnd(SVM_HWND Hwnd);
BOOLEAN IsCallerProtected();
PVOID GetTrueSsdtAddress(PCWSTR ZwName);

// ================================================================
// SSSDT (Shadow SSDT) resolver
// Locates Win32k shadow syscall addresses by index via CSRSS thread
// ================================================================
PVOID GetSssdtFunctionAddress(ULONG SssdtIndex);
NTSTATUS InitSssdtResolver();

// ================================================================
// DKOM
// ================================================================
NTSTATUS HideProcessByDkom(HANDLE Pid);
VOID RestoreProcessByDkom();

// ================================================================
// Unexported function scanner
// ================================================================
PVOID ScanForPspReferenceCidTableEntry();

// ================================================================
// Process operations
// ================================================================
VOID CommunicationThread(PVOID Context);
NTSTATUS DisguiseProcess(HANDLE Pid);
NTSTATUS HideDriver(PDRIVER_OBJECT DriverObject);

// ================================================================
// Driver file self-delete
// ================================================================
NTSTATUS DeleteDriverFile(PDRIVER_OBJECT DriverObject);

PEX_FAST_REF FindPspCreateProcessNotifyRoutine();
NTSTATUS InitNotifyRoutineResolver();
void DisableAllProcessCallbacks();
void RestoreAllProcessCallbacks();