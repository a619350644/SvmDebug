/**
 * @file Hide.h
 * @brief 进程保护逻辑头文件 - 保护配置、全局变量、回调管理结构体
 * @author yewilliam
 * @date 2026/02/06
 */

#pragma once

#include <ntifs.h>

#include "Common.h"

#include "Hook.h"        // HOOK_INDEX, NPT_HOOK_CONTEXT, REGISTER_CONTEXT 都在这里

#include "winApiDef.h"   // 所有函数指针 typedef 都在这里



/* ========================================================================
 *  权限常量
 * ======================================================================== */

#ifndef PROCESS_VM_READ

#define PROCESS_VM_READ            (0x0010)

#endif

#ifndef PROCESS_VM_WRITE

#define PROCESS_VM_WRITE           (0x0020)

#endif

#ifndef PROCESS_VM_OPERATION

#define PROCESS_VM_OPERATION       (0x0008)

#endif

#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000

#ifndef THREAD_SUSPEND_RESUME

#define THREAD_SUSPEND_RESUME      0x0002

#endif

#ifndef THREAD_TERMINATE

#define THREAD_TERMINATE           0x0001

#endif

#ifndef THREAD_GET_CONTEXT

#define THREAD_GET_CONTEXT         0x0008

#endif

#ifndef THREAD_SET_CONTEXT

#define THREAD_SET_CONTEXT         0x0010

#endif



/* ========================================================================
 *  多目标保护配置
 * ======================================================================== */

#define MAX_PROTECTED_PIDS          20

#define MAX_PROTECTED_HWNDS         20

#define MAX_PROTECTED_CHILD_HWNDS   256

#define MAX_CALLBACKS               64



/* ========================================================================
 *  全局变量
 * ======================================================================== */

extern PEPROCESS g_CsrssProcess;



extern HANDLE  g_ProtectedPIDs[MAX_PROTECTED_PIDS];

extern volatile LONG g_ProtectedPidCount;



extern SVM_HWND g_ProtectedHwnds[MAX_PROTECTED_HWNDS];

extern volatile LONG g_ProtectedHwndCount;



extern SVM_HWND g_ProtectedChildHwnds[MAX_PROTECTED_CHILD_HWNDS];

extern volatile LONG g_ProtectedChildHwndCount;



extern HANDLE g_ProtectedPID;

extern WCHAR g_ProtectedProcessName[260];



extern HANDLE g_PendingProtectPID;

extern HANDLE g_WorkerThreadHandle;

extern volatile BOOLEAN g_DriverUnloading;

/* [BUGFIX 2026/03/15] 延迟回调操作标志 */
extern volatile LONG g_PendingCallbackOp;



/* ========================================================================
 *  回调管理结构体
 * ======================================================================== */

typedef struct _EX_FAST_REF {

    union {

        PVOID Object;

        ULONG_PTR RefCnt : 4;

        ULONG_PTR Value;

    };

} EX_FAST_REF, * PEX_FAST_REF;



typedef struct _EX_CALLBACK_ROUTINE_BLOCK {

    EX_RUNDOWN_REF RundownProtect;

    PVOID Function;

    PVOID Context;

} EX_CALLBACK_ROUTINE_BLOCK, * PEX_CALLBACK_ROUTINE_BLOCK;



extern PVOID g_SavedCallbacks[MAX_CALLBACKS];

extern PEX_FAST_REF g_PspCreateProcessNotifyRoutine;



/* ========================================================================
 *  R3 通信结构体
 * ======================================================================== */

typedef struct _PROTECT_INFO {

    ULONG64 Pid;

    WCHAR ProcessName[260];

} PROTECT_INFO, * PPROTECT_INFO;



typedef struct _PROTECT_INFO_EX {

    ULONG64 Pid;

    ULONG64 Hwnd;

    ULONG64 ChildHwnds[8];

    ULONG   ChildHwndCount;

    WCHAR   ProcessName[260];

} PROTECT_INFO_EX, * PPROTECT_INFO_EX;



/* ========================================================================
 *  注意：HOOK_INDEX 枚举在 Hook.h 中定义，不要在这里重复定义！ *  ================================================================ *  ================================================================ *  函数声明
 * ======================================================================== */

BOOLEAN AddProtectedPid(HANDLE Pid);

BOOLEAN RemoveProtectedPid(HANDLE Pid);

VOID ClearAllProtectedTargets();

BOOLEAN AddProtectedHwnd(SVM_HWND Hwnd);

BOOLEAN AddProtectedChildHwnd(SVM_HWND Hwnd);



BOOLEAN IsProtectedPid(HANDLE Pid);

BOOLEAN IsProtectedHwnd(SVM_HWND Hwnd);

BOOLEAN IsCallerProtected();

BOOLEAN IsProtectedProcessHandle(HANDLE ProcessHandle);



PVOID GetTrueSsdtAddress(PCWSTR ZwName);

PVOID GetSssdtFunctionAddress(ULONG SssdtIndex);

NTSTATUS InitSssdtResolver();

ULONG GetSssdtIndexDynamic(PCSTR FunctionName);

PVOID ScanForPspReferenceCidTableEntry();



NTSTATUS PrepareAllNptHookResources();

NTSTATUS InitializeProcessHideHooks();

VOID LinkTrampolineAddresses();

NTSTATUS ActivateAllNptHooks(PVCPU_CONTEXT vpData);

VOID CleanupAllNptHooks();



NTSTATUS HideProcessByDkom(HANDLE Pid);

VOID RestoreProcessByDkom();



VOID CommunicationThread(PVOID Context);

NTSTATUS DisguiseProcess(HANDLE Pid);

NTSTATUS HideDriver(PDRIVER_OBJECT DriverObject);

NTSTATUS DeleteDriverFile(PDRIVER_OBJECT DriverObject);



PEX_FAST_REF FindPspCreateProcessNotifyRoutine();

NTSTATUS InitNotifyRoutineResolver();

void DisableAllProcessCallbacks();

void RestoreAllProcessCallbacks();