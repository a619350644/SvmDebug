/**
 * @file Hide.h
 * @brief 进程保护逻辑头文件 - 保护配置、全局变量、回调管理结构体
 * @author yewilliam
 * @date 2026/03/16
 */

#pragma once

#include <ntifs.h>

#include "Common.h"

#include "Hook.h"        // HOOK_INDEX, NPT_HOOK_CONTEXT, REGISTER_CONTEXT 都在这里

#include "winApiDef.h"   // 所有函数指针 typedef 都在这里

#define MAX_ELEVATED_PIDS  10

extern HANDLE   g_ElevatedPIDs[MAX_ELEVATED_PIDS];
extern volatile LONG g_ElevatedPidCount;

BOOLEAN AddElevatedPid(HANDLE Pid);
BOOLEAN RemoveElevatedPid(HANDLE Pid);
BOOLEAN IsElevatedPid(HANDLE Pid);
VOID    ClearAllElevatedPids();

 /* ========================================================================
  *  权限常量 — 进程/线程访问权限掩码, 用于句柄权限裁剪
  * ======================================================================== */

#ifndef PROCESS_VM_READ
  /** @brief 读取目标进程虚拟内存的权限 (ReadProcessMemory所需) */
#define PROCESS_VM_READ            (0x0010)
#endif

#ifndef PROCESS_VM_WRITE
/** @brief 写入目标进程虚拟内存的权限 (WriteProcessMemory所需) */
#define PROCESS_VM_WRITE           (0x0020)
#endif

#ifndef PROCESS_VM_OPERATION
/** @brief 对目标进程虚拟内存执行操作的权限 (VirtualAllocEx/VirtualProtectEx所需) */
#define PROCESS_VM_OPERATION       (0x0008)
#endif

/** @brief 查询进程有限信息的权限 (降权时使用, 只能获取PID/退出码等基本信息) */
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000

#ifndef THREAD_SUSPEND_RESUME
/** @brief 挂起/恢复线程的权限 (SuspendThread/ResumeThread所需) */
#define THREAD_SUSPEND_RESUME      0x0002
#endif

#ifndef THREAD_TERMINATE
/** @brief 终止线程的权限 (TerminateThread所需) */
#define THREAD_TERMINATE           0x0001
#endif

#ifndef THREAD_GET_CONTEXT
/** @brief 获取线程上下文(寄存器)的权限 (GetThreadContext所需, 可读取DR0-DR7) */
#define THREAD_GET_CONTEXT         0x0008
#endif

#ifndef THREAD_SET_CONTEXT
/** @brief 设置线程上下文(寄存器)的权限 (SetThreadContext所需, 可篡改RIP/DR寄存器) */
#define THREAD_SET_CONTEXT         0x0010
#endif



/* ========================================================================
 *  多目标保护配置 — 最大保护数量限制
 * ======================================================================== */

 /** @brief 最大同时保护的进程PID数量 */
#define MAX_PROTECTED_PIDS          20

/** @brief 最大同时保护的主窗口句柄数量 */
#define MAX_PROTECTED_HWNDS         20

/** @brief 最大同时保护的子窗口句柄数量 (一个主窗口可能有大量子窗口) */
#define MAX_PROTECTED_CHILD_HWNDS   256

/** @brief PspCreateProcessNotifyRoutine数组的最大回调槽位数 */
#define MAX_CALLBACKS               64



/* ========================================================================
 *  全局变量 — 运行时状态
 * ======================================================================== */

 /** @brief csrss.exe的EPROCESS指针, 用于SSSDT/Win32k函数解析时附加到GUI进程上下文 */
extern PEPROCESS g_CsrssProcess;

/** @brief 受保护进程PID数组, 最多MAX_PROTECTED_PIDS个 */
extern HANDLE  g_ProtectedPIDs[MAX_PROTECTED_PIDS];

/** @brief 当前受保护PID数量, 原子操作保证多核安全 */
extern volatile LONG g_ProtectedPidCount;

/** @brief 受保护主窗口句柄数组 (顶层窗口) */
extern SVM_HWND g_ProtectedHwnds[MAX_PROTECTED_HWNDS];

/** @brief 当前受保护主窗口数量, 原子操作 */
extern volatile LONG g_ProtectedHwndCount;

/** @brief 受保护子窗口句柄数组 (按钮/编辑框/列表等子控件) */
extern SVM_HWND g_ProtectedChildHwnds[MAX_PROTECTED_CHILD_HWNDS];

/** @brief 当前受保护子窗口数量, 原子操作 */
extern volatile LONG g_ProtectedChildHwndCount;

/** @brief 主保护目标PID (第一个添加的PID, 兼容旧接口) */
extern HANDLE g_ProtectedPID;

/** @brief 主保护目标进程名 (如 L"game.exe"), 用于日志和进程识别 */
extern WCHAR g_ProtectedProcessName[260];

/** @brief 待保护的PID (R3通过IOCTL设置, 工作线程异步处理) */
extern HANDLE g_PendingProtectPID;

/** @brief 工作线程句柄, 负责异步执行保护/伪装等耗时操作 */
extern HANDLE g_WorkerThreadHandle;

/** @brief 驱动卸载标志, 置TRUE时工作线程应退出循环 */
extern volatile BOOLEAN g_DriverUnloading;

/** @brief 待处理的回调操作类型 (原子变量, 工作线程轮询检查) */
extern volatile LONG g_PendingCallbackOp;



/* ========================================================================
 *  回调管理结构体 — 用于禁用/恢复进程创建通知回调
 * ======================================================================== */

 /**
  * @brief EX_FAST_REF — Windows内核快速引用结构体
  *
  * 将对象指针和引用计数压缩在同一个ULONG_PTR中:
  *   - 低4位: 引用计数 (RefCnt)
  *   - 高位:  对象指针 (需 & ~0xF 提取)
  *
  * PspCreateProcessNotifyRoutine数组的每个元素就是一个EX_FAST_REF,
  * 指向EX_CALLBACK_ROUTINE_BLOCK。
  */
typedef struct _EX_FAST_REF {
    union {
        PVOID Object; // 完整值(指针+引用计数混合)
        ULONG_PTR RefCnt : 4; // 低4位: 快速引用计数
        ULONG_PTR Value; // 原始ULONG_PTR值, 用于原子操作
    };
} EX_FAST_REF, * PEX_FAST_REF;

/**
 * @brief EX_CALLBACK_ROUTINE_BLOCK — 内核回调例程块
 *
 * 每个已注册的进程创建回调对应一个此结构体:
 *   - RundownProtect: 运行时保护, 确保回调执行期间不被释放
 *   - Function:       实际回调函数指针 (PCREATE_PROCESS_NOTIFY_ROUTINE)
 *   - Context:        回调上下文 (Ex版本使用)
 *
 * 禁用回调时将Function替换为NoopCallback, 恢复时换回原值。
 * 注意: 绝不能清零EX_FAST_REF, 否则破坏引用计数→BSOD 0x139。
 */
typedef struct _EX_CALLBACK_ROUTINE_BLOCK {
    EX_RUNDOWN_REF RundownProtect; // 运行保护引用, 防止回调执行中被释放
    PVOID Function; // 回调函数指针, 可原子替换为Noop实现禁用
    PVOID Context; // 回调上下文参数 (PsSetCreateProcessNotifyRoutineEx使用)
} EX_CALLBACK_ROUTINE_BLOCK, * PEX_CALLBACK_ROUTINE_BLOCK;

/** @brief 保存的原始回调函数指针数组, 用于恢复 */
extern PVOID g_SavedCallbacks[MAX_CALLBACKS];

/** @brief PspCreateProcessNotifyRoutine全局数组指针 (通过模式扫描定位) */
extern PEX_FAST_REF g_PspCreateProcessNotifyRoutine;



/* ========================================================================
 *  R3 通信结构体 — 用户态驱动通信IOCTL数据格式
 * ======================================================================== */

 /**
  * @brief PROTECT_INFO — 基础保护请求结构体 (R3→R0)
  *
  * 用户态程序通过DeviceIoControl发送此结构体,
  * 告知驱动要保护哪个进程。
  */
typedef struct _PROTECT_INFO {
    ULONG64 Pid; // 要保护的目标进程PID
    WCHAR ProcessName[260]; // 进程名称 (如 L"game.exe"), 用于日志和验证
} PROTECT_INFO, * PPROTECT_INFO;

/**
 * @brief PROTECT_INFO_EX — 扩展保护请求结构体 (R3→R0)
 *
 * 在基础版本上增加窗口句柄信息,
 * 支持同时保护进程和其窗口(防止窗口枚举/查找发现)。
 */
typedef struct _PROTECT_INFO_EX {
    ULONG64 Pid; // 要保护的目标进程PID
    ULONG64 Hwnd; // 主窗口句柄 (顶层窗口)
    ULONG64 ChildHwnds[8]; // 子窗口句柄数组 (按钮/编辑框等, 最多8个)
    ULONG   ChildHwndCount; // 实际子窗口数量
    WCHAR   ProcessName[260]; // 进程名称
} PROTECT_INFO_EX, * PPROTECT_INFO_EX;



/* ========================================================================
 *  多目标保护 — PID/HWND管理函数
 * ======================================================================== */

 /**
  * @brief 添加PID到保护列表 (原子递增, 去重)
  * @param [in] Pid - 要保护的进程ID
  * @return TRUE=成功/已存在, FALSE=列表已满或Pid无效
  */
BOOLEAN AddProtectedPid(HANDLE Pid);

/**
 * @brief 从保护列表移除PID (数组前移压缩)
 * @param [in] Pid - 要移除的进程ID
 * @return TRUE=移除成功, FALSE=未找到
 */
BOOLEAN RemoveProtectedPid(HANDLE Pid);

/**
 * @brief 清除所有保护目标 — PID/HWND/子窗口列表全部清零
 */
VOID ClearAllProtectedTargets();

/**
 * @brief 添加主窗口句柄到保护列表
 * @param [in] Hwnd - 主窗口句柄
 * @return TRUE=成功, FALSE=列表已满
 */
BOOLEAN AddProtectedHwnd(SVM_HWND Hwnd);

/**
 * @brief 添加子窗口句柄到保护列表
 * @param [in] Hwnd - 子窗口句柄
 * @return TRUE=成功, FALSE=列表已满
 */
BOOLEAN AddProtectedChildHwnd(SVM_HWND Hwnd);



/* ========================================================================
 *  保护状态查询函数
 * ======================================================================== */

 /**
  * @brief 检查PID是否在保护列表中
  * @param [in] Pid - 要检查的进程ID
  * @return TRUE=受保护, FALSE=未保护
  */
BOOLEAN IsProtectedPid(HANDLE Pid);

/**
 * @brief 检查窗口句柄是否在保护列表中 (含主窗口和子窗口)
 * @param [in] Hwnd - 要检查的窗口句柄
 * @return TRUE=受保护, FALSE=未保护
 */
BOOLEAN IsProtectedHwnd(SVM_HWND Hwnd);

/**
 * @brief 检查当前调用者进程是否为受保护进程
 * @return TRUE=调用者是保护进程(应放行), FALSE=外部进程(应拦截)
 */
BOOLEAN IsCallerProtected();

/**
 * @brief 检查进程句柄是否指向受保护进程 (通过ObpRefByHandleWithTag解析)
 * @param [in] ProcessHandle - 进程句柄
 * @return TRUE=指向保护进程, FALSE=不是
 */
BOOLEAN IsProtectedProcessHandle(HANDLE ProcessHandle);



/* ========================================================================
 *  SSDT/SSSDT 解析函数
 * ======================================================================== */

 /**
  * @brief 通过Zw导出函数名解析SSDT中对应Nt函数的真实地址
  * @param [in] ZwName - Zw函数名 (如 L"ZwOpenProcess")
  * @return Nt函数虚拟地址, 失败返回NULL
  */
PVOID GetTrueSsdtAddress(PCWSTR ZwName);

/**
 * @brief 通过索引获取SSSDT(Win32k影子系统调用表)中的函数地址
 * @param [in] SssdtIndex - SSSDT函数索引
 * @return 函数虚拟地址, 索引越界返回NULL
 */
PVOID GetSssdtFunctionAddress(ULONG SssdtIndex);

/**
 * @brief 初始化SSSDT解析器 — 解析Shadow SSDT获取W32pServiceTable
 * @return STATUS_SUCCESS成功, STATUS_NOT_FOUND未找到
 */
NTSTATUS InitSssdtResolver();

/**
 * @brief 动态获取SSSDT函数索引 — 映射win32u.dll解析导出表
 * @param [in] FunctionName - 函数名(如"NtUserFindWindowEx")
 * @return SSSDT索引(低12位), 失败返回0
 */
ULONG GetSssdtIndexDynamic(PCSTR FunctionName);

/**
 * @brief 模式扫描定位PspReferenceCidTableEntry内部函数
 * @return 函数虚拟地址, 未找到返回NULL
 */
PVOID ScanForPspReferenceCidTableEntry();

/**
 * @brief 通过ntdll导出表解析syscall索引, 再查SSDT获取Nt函数内核地址
 * @param [in] NtFuncName - Nt函数名(如 "NtCreateDebugObject")
 * @return Nt函数虚拟地址, 失败返回NULL
 */
PVOID GetSsdtAddressByNtdllName(PCSTR NtFuncName);



/* ========================================================================
 *  NPT Hook 生命周期管理
 * ======================================================================== */

 /**
  * @brief 准备所有NPT Hook资源 — 两阶段解析(普通+CSRSS上下文中的Win32k)
  * @return 至少1个Hook就绪返回STATUS_SUCCESS
  */
NTSTATUS PrepareAllNptHookResources();

/**
 * @brief 初始化进程隐藏Hook系统 — 解析SSSDT和进程创建回调
 * @return 始终返回STATUS_SUCCESS
 */
NTSTATUS InitializeProcessHideHooks();

/**
 * @brief 链接Trampoline地址到原函数指针 — 填充所有g_Orig*
 */
VOID LinkTrampolineAddresses();

/**
 * @brief 在NPT页表中激活所有已准备的Hook
 * @param [in] vpData - 当前vCPU上下文
 * @return STATUS_SUCCESS
 */
NTSTATUS ActivateAllNptHooks(PVCPU_CONTEXT vpData);

/**
 * @brief 清理所有NPT Hook资源 — 释放FakePage/TrampolinePage等
 */
VOID CleanupAllNptHooks();



/* ========================================================================
 *  DKOM / 进程伪装 / 驱动隐藏
 * ======================================================================== */

 /**
  * @brief 通过DKOM从ActiveProcessLinks链表中摘除进程 (已注释禁用)
  * @param [in] Pid - 要隐藏的进程PID
  * @return STATUS_SUCCESS
  */
NTSTATUS HideProcessByDkom(HANDLE Pid);

/**
 * @brief 恢复DKOM摘除的进程 — 将保存的Flink/Blink重新链接
 */
VOID RestoreProcessByDkom();

/**
 * @brief 通信工作线程 — 异步处理保护请求和伪装操作
 * @param [in] Context - 线程上下文(未使用)
 */
VOID CommunicationThread(PVOID Context);

/**
 * @brief 伪装目标进程为explorer.exe — 复制进程身份信息
 * @param [in] Pid - 要伪装的目标进程PID
 * @return STATUS_SUCCESS
 */
NTSTATUS DisguiseProcess(HANDLE Pid);

/**
 * @brief 从内核模块链表中隐藏驱动 — DKOM摘除InLoadOrderLinks
 * @param [in] DriverObject - 驱动对象指针
 * @return STATUS_SUCCESS
 */
NTSTATUS HideDriver(PDRIVER_OBJECT DriverObject);

/**
 * @brief 删除驱动文件 — 清除磁盘上的驱动文件痕迹
 * @param [in] DriverObject - 驱动对象指针
 * @return STATUS_SUCCESS
 */
NTSTATUS DeleteDriverFile(PDRIVER_OBJECT DriverObject);



/* ========================================================================
 *  进程创建回调管理
 * ======================================================================== */

 /**
  * @brief 定位PspCreateProcessNotifyRoutine全局数组 — 模式扫描PsSetCreateProcessNotifyRoutine
  * @return 数组指针, 未找到返回NULL
  */
PEX_FAST_REF FindPspCreateProcessNotifyRoutine();

/**
 * @brief 初始化进程创建回调解析器
 * @return STATUS_SUCCESS成功, STATUS_NOT_FOUND未找到
 */
NTSTATUS InitNotifyRoutineResolver();

/**
 * @brief 禁用所有进程创建回调 — 将回调函数替换为Noop (当前版本已跳过,NPT Hook覆盖)
 */
void DisableAllProcessCallbacks();

/**
 * @brief 恢复所有进程创建回调 — 将Noop替换回原始函数 (当前版本已跳过)
 */
void RestoreAllProcessCallbacks();