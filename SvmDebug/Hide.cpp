/**
 * @file Hide.cpp
 * @brief 进程保护逻辑实现 - 22个Fake函数、SSDT/SSSDT解析、窗口隐藏
 * @author yewilliam
 * @date 2026/03/16
 *
 * 实现四类NPT Hook拦截函数:
 *   SSDT系统调用Hook (12个): 进程发现/访问/操控全面拦截
 *   内核导出函数Hook (6个): PsLookup/ObReference/MmCopy等内核级拦截
 *   Win32k SSSDT Hook (3个): 窗口查找/枚举过滤
 *   Win32kbase内部导出Hook (1个): ValidateHwnd底层窗口验证拦截
 *
 * 采用per-CPU Guard防递归, 系统白名单保证桌面稳定。
 * 全局数据置于显式可写段(.drv_rw), 避免只读页写入导致BSOD。
 */
#include "Hide.h"
#include "DebugApi.h"       // IsDebugger() — 区分调试器(CE)与被保护游戏进程
#include <ntstrsafe.h>
#include <ntimage.h>
#pragma warning(disable: 4505)

#define SEC_IMAGE 0x01000000


#pragma section(".drv_rw", read, write)
#pragma comment(linker, "/SECTION:.drv_rw,RW")

__declspec(allocate(".drv_rw")) static volatile LONG g_Guard[64] = { 0 };
__declspec(allocate(".drv_rw")) static volatile LONG g_FakePrintOnce[HOOK_MAX_COUNT] = { 0 };

#if DEBUG
#define FAKE_PRINT_ONCE_FOR(hookIdx) \
    do { \
        if ((hookIdx) < HOOK_MAX_COUNT && \
            InterlockedCompareExchange(&g_FakePrintOnce[(hookIdx)], 1, 0) == 0) \
            SvmDebugPrint("[Fake] %s called\n", __FUNCTION__); \
    } while (0)
#else
#define FAKE_PRINT_ONCE_FOR(hookIdx) (void)0
#endif

/* ========================================================================
 *  全局变量
 * ======================================================================== */
HANDLE   g_ProtectedPIDs[MAX_PROTECTED_PIDS] = { 0 };
volatile LONG g_ProtectedPidCount = 0;

SVM_HWND g_ProtectedHwnds[MAX_PROTECTED_HWNDS] = { 0 };
volatile LONG g_ProtectedHwndCount = 0;

SVM_HWND g_ProtectedChildHwnds[MAX_PROTECTED_CHILD_HWNDS] = { 0 };
volatile LONG g_ProtectedChildHwndCount = 0;

HANDLE   g_ProtectedPID = (HANDLE)0;
WCHAR    g_ProtectedProcessName[260] = { 0 };
PEPROCESS g_CsrssProcess = NULL;

PVOID        g_SavedCallbacks[MAX_CALLBACKS] = { 0 };
PEX_FAST_REF g_PspCreateProcessNotifyRoutine = NULL;

EXTERN_C NTSTATUS NTAPI ObReferenceObjectByName(
    __in PUNICODE_STRING ObjectName,
    __in ULONG Attributes,
    __in_opt PACCESS_STATE AccessState,
    __in_opt ACCESS_MASK DesiredAccess,
    __in POBJECT_TYPE ObjectType,
    __in KPROCESSOR_MODE AccessMode,
    __inout_opt PVOID ParseContext,
    __out PVOID* Object
);
extern POBJECT_TYPE* IoFileObjectType;


/* ========================================================================
 *  Hook Guard — 轻量级防递归（不修改 IRQL） *   *
 * ======================================================================== */

 /**
  * @brief 进入Hook防递归保护 - per-CPU原子锁, 不修改IRQL
  * @author yewilliam
  * @date 2026/03/16
  * @param [out] OldIrql - 输出当前IRQL(仅记录, 不提升)
  * @return TRUE表示成功获取Guard, FALSE表示当前CPU已在Guard中(递归)
  */
static __forceinline BOOLEAN EnterHookGuard(PKIRQL OldIrql)
{
    *OldIrql = KeGetCurrentIrql();  // 只记录，不提升

    ULONG cpu = KeGetCurrentProcessorNumber();
    if (cpu >= 64) return FALSE;

    if (InterlockedCompareExchange(&g_Guard[cpu], 1, 0) != 0)
        return FALSE;

    return TRUE;
}

/**
 * @brief 离开Hook防递归保护 - 释放per-CPU原子锁
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] OldIrql - EnterHookGuard时记录的IRQL(未使用)
 */
static __forceinline VOID LeaveHookGuard(KIRQL OldIrql)
{
    UNREFERENCED_PARAMETER(OldIrql);
    ULONG cpu = KeGetCurrentProcessorNumber();
    if (cpu < 64)
        InterlockedExchange(&g_Guard[cpu], 0);
}


/* ========================================================================
 *  多目标保护 — PID / HWND 管理
 * ======================================================================== */

 /* [DIAG-v23] 前向声明 */
void ResetScanDiagCounters();

BOOLEAN AddProtectedPid(HANDLE Pid)
{
    if (!Pid) return FALSE;

    for (LONG i = 0; i < g_ProtectedPidCount; i++) {
        if (g_ProtectedPIDs[i] == Pid)
            return TRUE;
    }

    LONG idx = InterlockedIncrement(&g_ProtectedPidCount) - 1;
    if (idx >= MAX_PROTECTED_PIDS) {
        InterlockedDecrement(&g_ProtectedPidCount);
        return FALSE;
    }

    g_ProtectedPIDs[idx] = Pid;
    if (idx == 0)
        g_ProtectedPID = Pid;

    /* [DIAG-v23] 重置扫描诊断计数器, 新的保护session开始 */
    ResetScanDiagCounters();

    return TRUE;
}

/**
 * @brief 从保护列表中移除PID
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] Pid - 要移除的进程ID
 * @return TRUE表示移除成功, FALSE表示未找到
 */
BOOLEAN RemoveProtectedPid(HANDLE Pid)
{
    for (LONG i = 0; i < g_ProtectedPidCount; i++) {
        if (g_ProtectedPIDs[i] == Pid) {
            for (LONG j = i; j < g_ProtectedPidCount - 1; j++)
                g_ProtectedPIDs[j] = g_ProtectedPIDs[j + 1];

            LONG newCount = InterlockedDecrement(&g_ProtectedPidCount);
            g_ProtectedPIDs[newCount] = 0;
            g_ProtectedPID = (newCount > 0) ? g_ProtectedPIDs[0] : 0;
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN AddProtectedHwnd(SVM_HWND Hwnd)
{
    if (!Hwnd) return FALSE;

    for (LONG i = 0; i < g_ProtectedHwndCount; i++) {
        if (g_ProtectedHwnds[i] == Hwnd)
            return TRUE;
    }

    LONG idx = InterlockedIncrement(&g_ProtectedHwndCount) - 1;
    if (idx >= MAX_PROTECTED_HWNDS) {
        InterlockedDecrement(&g_ProtectedHwndCount);
        return FALSE;
    }

    g_ProtectedHwnds[idx] = Hwnd;
    return TRUE;
}

BOOLEAN AddProtectedChildHwnd(SVM_HWND Hwnd)
{
    if (!Hwnd) return FALSE;

    for (LONG i = 0; i < g_ProtectedChildHwndCount; i++) {
        if (g_ProtectedChildHwnds[i] == Hwnd)
            return TRUE;
    }

    LONG idx = InterlockedIncrement(&g_ProtectedChildHwndCount) - 1;
    if (idx >= MAX_PROTECTED_CHILD_HWNDS) {
        InterlockedDecrement(&g_ProtectedChildHwndCount);
        return FALSE;
    }

    g_ProtectedChildHwnds[idx] = Hwnd;
    return TRUE;
}

/**
 * @brief 清除所有保护目标 - PID/HWND/子窗口列表全部清零
 * @author yewilliam
 * @date 2026/03/16
 */
VOID ClearAllProtectedTargets()
{
    RtlZeroMemory(g_ProtectedPIDs, sizeof(g_ProtectedPIDs));
    InterlockedExchange(&g_ProtectedPidCount, 0);

    RtlZeroMemory(g_ProtectedHwnds, sizeof(g_ProtectedHwnds));
    InterlockedExchange(&g_ProtectedHwndCount, 0);

    RtlZeroMemory(g_ProtectedChildHwnds, sizeof(g_ProtectedChildHwnds));
    InterlockedExchange(&g_ProtectedChildHwndCount, 0);

    g_ProtectedPID = 0;

    /* [NEW] 联动清除升权列表, 防止 PID 复用导致错误升权 */
    ClearAllElevatedPids();
}

/* ========================================================================
 *  [DIAG-v23] 扫描诊断计数器 — 只在保护激活后计数, 可重置
 *
 *  解决问题: 前100条日志被系统其他进程在保护激活前消耗完
 *  方案: 计数器只在 g_ProtectedPidCount>0 时递增
 *        PROTECT_PID 时自动重置, 每次扫描session都有新的配额
 * ======================================================================== */
static volatile LONG s_diag_NtRVM = 0;
static volatile LONG s_diag_MmCVM = 0;
static volatile LONG s_diag_QVM = 0;

void ResetScanDiagCounters()
{
    InterlockedExchange(&s_diag_NtRVM, 0);
    InterlockedExchange(&s_diag_MmCVM, 0);
    InterlockedExchange(&s_diag_QVM, 0);
    SvmDebugPrint("[DIAG] Scan counters reset\n");
}


/* 只在保护激活时计数, 前500条 + 每2000条 */
/* [DIAG-v24] CE-only 计数器 — 只在 IsCallerProtected() 时调用
 * 系统进程的调用不消耗配额, 确保 Next Scan 的日志可见 */
static __forceinline BOOLEAN DiagShouldLog_CE(volatile LONG* counter) {
    LONG n = InterlockedIncrement(counter);
    /* 前2000条 + 每5000条 */
    return (n <= 2000) || ((n % 5000) == 0);
}


/* ========================================================================
 *  Trampoline 原函数指针（由 LinkTrampolineAddresses 填充）
 * ======================================================================== */
static FnNtQuerySystemInformation      g_OrigNtQuerySystemInformation = NULL;
static FnNtOpenProcess                 g_OrigNtOpenProcess = NULL;
static FnNtQueryInformationProcess     g_OrigNtQueryInformationProcess = NULL;
static FnNtQueryVirtualMemory          g_OrigNtQueryVirtualMemory = NULL;
static FnNtDuplicateObject             g_OrigNtDuplicateObject = NULL;
static FnNtGetNextProcess              g_OrigNtGetNextProcess = NULL;
static FnNtGetNextThread               g_OrigNtGetNextThread = NULL;
static FnNtReadVirtualMemory           g_OrigNtReadVirtualMemory = NULL;
static FnNtWriteVirtualMemory          g_OrigNtWriteVirtualMemory = NULL;
static FnNtProtectVirtualMemory        g_OrigNtProtectVirtualMemory = NULL;
static FnNtTerminateProcess            g_OrigNtTerminateProcess = NULL;
static FnNtCreateThreadEx              g_OrigNtCreateThreadEx = NULL;
static FnNtSuspendThread               g_OrigNtSuspendThread = NULL;
static FnNtResumeThread                g_OrigNtResumeThread = NULL;
static FnNtGetContextThread            g_OrigNtGetContextThread = NULL;
static FnNtSetContextThread            g_OrigNtSetContextThread = NULL;
static FnNtQueryInformationThread      g_OrigNtQueryInformationThread = NULL;
static FnPsLookupProcessByProcessId    g_OrigPsLookupProcessByProcessId = NULL;
static FnPsLookupThreadByThreadId      g_OrigPsLookupThreadByThreadId = NULL;
static FnObReferenceObjectByHandle     g_OrigObReferenceObjectByHandle = NULL;

typedef NTSTATUS(NTAPI* FnObpRefByHandleWithTag)(
    ULONG_PTR Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode, ULONG Tag, PVOID* Object,
    POBJECT_HANDLE_INFORMATION HandleInformation, ULONG_PTR Flags);
static FnObpRefByHandleWithTag g_OrigObpRefByHandleWithTag = NULL;
static FnMmCopyVirtualMemory           g_OrigMmCopyVirtualMemory = NULL;
static FnKeStackAttachProcess          g_OrigKeStackAttachProcess = NULL;

/* [FIX] NtSetInformationThread — 拦截 ThreadHideFromDebugger */
typedef NTSTATUS(NTAPI* FnNtSetInformationThread)(
    HANDLE ThreadHandle, ULONG ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength);
static FnNtSetInformationThread        g_OrigNtSetInformationThread = NULL;

static FnNtUserFindWindowEx            g_OrigNtUserFindWindowEx = NULL;
static FnNtUserWindowFromPoint         g_OrigNtUserWindowFromPoint = NULL;
static FnNtUserBuildHwndList           g_OrigNtUserBuildHwndList = NULL;
static FnValidateHwnd                  g_OrigValidateHwnd = NULL;


/* ========================================================================
 *  系统进程白名单 — 这些进程必须能访问所有窗口，否则桌面崩溃
 * ======================================================================== */
static PCWSTR g_WhitelistProcesses[] = {
    L"csrss.exe",
    L"dwm.exe",
    L"explorer.exe",
    L"svchost.exe",
    L"services.exe",
    L"lsass.exe",
    L"smss.exe",
    L"ctfmon.exe",
    L"dllhost.exe",
    L"WmiPrvSE.exe",
    L"conhost.exe",
    L"sihost.exe",
    L"taskhostw.exe",
};

static BOOLEAN IsWhitelistedCaller()
{
    PUCHAR name = PsGetProcessImageFileName(PsGetCurrentProcess());
    if (!name) return FALSE;

    ANSI_STRING ansiCurrent;
    RtlInitAnsiString(&ansiCurrent, (PCSZ)name);

    for (ULONG i = 0; i < ARRAYSIZE(g_WhitelistProcesses); i++) {
        UNICODE_STRING uniWhite;
        RtlInitUnicodeString(&uniWhite, g_WhitelistProcesses[i]);

        ANSI_STRING ansiWhite;
        if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiWhite, &uniWhite, TRUE))) {
            BOOLEAN match = RtlEqualString(&ansiCurrent, &ansiWhite, TRUE);
            RtlFreeAnsiString(&ansiWhite);
            if (match) return TRUE;
        }
    }
    return FALSE;
}

/* ========================================================================
 *  窗口所属进程判断 — 通过 ValidateHwnd 获取内核窗口对象 *  参考 DbgkSysWin10 的 ShouldAllowAccess 设计
 * ======================================================================== */
static BOOLEAN IsWindowOwnedByProtectedProcess(SVM_HWND hwnd)
{
    if (!hwnd || !g_OrigValidateHwnd || g_ProtectedPidCount == 0)
        return FALSE;

    __try {
        PSVM_WND pwnd = (PSVM_WND)g_OrigValidateHwnd(hwnd);
        if (!pwnd) return FALSE;

        // pwnd+0x10 = pti (THREADINFO*), pti+0x00 = pEThread
        PSVM_W32THREAD pti = pwnd->pti;
        if (!pti) return FALSE;

        PETHREAD pEThread = pti->pEThread;
        if (!pEThread) return FALSE;

        PEPROCESS ownerProcess = PsGetThreadProcess(pEThread);
        if (!ownerProcess) return FALSE;

        HANDLE ownerPid = PsGetProcessId(ownerProcess);
        return IsProtectedPid(ownerPid);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

/* ========================================================================
 *  win32kbase.sys 导出解析（在 CSRSS 上下文中调用）
 * ======================================================================== */
typedef struct _SVM_RTL_MODULE_INFO {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} SVM_RTL_MODULE_INFO;

typedef struct _SVM_RTL_MODULES {
    ULONG NumberOfModules;
    SVM_RTL_MODULE_INFO Modules[1];
} SVM_RTL_MODULES;

static PVOID FindWin32kbaseExport(PCSTR ExportName)
{
    // 1. 通过 SystemModuleInformation 找到 win32kbase.sys 基址
    ULONG infoSize = 0;
    // SystemModuleInformation = 11
    NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, NULL, 0, &infoSize);
    if (!infoSize) return NULL;

    infoSize += PAGE_SIZE;
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, infoSize, 'w32b');
    if (!buffer) return NULL;

    NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11,
        buffer, infoSize, &infoSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, 'w32b');
        return NULL;
    }

    SVM_RTL_MODULES* modules = (SVM_RTL_MODULES*)buffer;
    PVOID moduleBase = NULL;
    ULONG moduleSize = 0;

    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        PCSTR modName = (PCSTR)(modules->Modules[i].FullPathName +
            modules->Modules[i].OffsetToFileName);
        if (_stricmp(modName, "win32kbase.sys") == 0) {
            moduleBase = modules->Modules[i].ImageBase;
            moduleSize = modules->Modules[i].ImageSize;
            break;
        }
    }
    ExFreePoolWithTag(buffer, 'w32b');

    if (!moduleBase) {
        SvmDebugPrint("[WARN] win32kbase.sys not found in module list\n");
        return NULL;
    }

    // 2. 遍历 PE 导出表找到目标函数（需在 CSRSS 上下文中，session 页可访问）
    __try {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PUCHAR)moduleBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return NULL;

        ULONG exportRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exportRva) return NULL;

        PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)moduleBase + exportRva);
        PULONG pNames = (PULONG)((PUCHAR)moduleBase + pExp->AddressOfNames);
        PULONG pFunctions = (PULONG)((PUCHAR)moduleBase + pExp->AddressOfFunctions);
        PUSHORT pOrdinals = (PUSHORT)((PUCHAR)moduleBase + pExp->AddressOfNameOrdinals);

        for (ULONG i = 0; i < pExp->NumberOfNames; i++) {
            PCSTR name = (PCSTR)((PUCHAR)moduleBase + pNames[i]);
            if (strcmp(name, ExportName) == 0) {
                PVOID funcAddr = (PVOID)((PUCHAR)moduleBase + pFunctions[pOrdinals[i]]);
                SvmDebugPrint("[INFO] win32kbase!%s -> %p\n", ExportName, funcAddr);
                return funcAddr;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SvmDebugPrint("[ERROR] Exception walking win32kbase exports\n");
    }

    return NULL;
}

/**
 * @brief 检查PID是否在保护列表中
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] Pid - 要检查的进程ID
 * @return TRUE表示受保护, FALSE表示未保护
 */
BOOLEAN IsProtectedPid(HANDLE Pid)
{
    if (g_ProtectedPidCount == 0 || !Pid)
        return FALSE;

    LONG count = g_ProtectedPidCount;
    for (LONG i = 0; i < count && i < MAX_PROTECTED_PIDS; i++) {
        if (g_ProtectedPIDs[i] == Pid)
            return TRUE;
    }
    return FALSE;
}

BOOLEAN IsProtectedHwnd(SVM_HWND Hwnd)
{
    if (!Hwnd)
        return FALSE;
    if (g_ProtectedHwndCount == 0 && g_ProtectedChildHwndCount == 0)
        return FALSE;

    LONG count1 = g_ProtectedHwndCount;
    for (LONG i = 0; i < count1 && i < MAX_PROTECTED_HWNDS; i++) {
        if (g_ProtectedHwnds[i] == Hwnd)
            return TRUE;
    }

    LONG count2 = g_ProtectedChildHwndCount;
    for (LONG i = 0; i < count2 && i < MAX_PROTECTED_CHILD_HWNDS; i++) {
        if (g_ProtectedChildHwnds[i] == Hwnd)
            return TRUE;
    }

    return FALSE;
}

/**
 * @brief 检查当前调用者进程是否为受保护进程
 * @author yewilliam
 * @date 2026/03/16
 * @return TRUE表示调用者受保护, FALSE表示不受保护
 */
BOOLEAN IsCallerProtected()
{
    if (g_ProtectedPidCount == 0)
        return FALSE;
    return IsProtectedPid(PsGetCurrentProcessId());
}

/**
 * @brief 检查进程句柄是否指向受保护进程 - 通过ObReferenceObjectByHandle解析
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] ProcessHandle - 进程句柄
 * @return TRUE表示句柄指向受保护进程, FALSE表示不是
 */
BOOLEAN IsProtectedProcessHandle(HANDLE ProcessHandle)
{
    if (g_ProtectedPidCount == 0)
        return FALSE;
    if (!ProcessHandle || ProcessHandle == (HANDLE)-1 ||
        ProcessHandle == NtCurrentProcess())
        return FALSE;

    /* 通过 ObpReferenceObjectByHandleWithTag 的 trampoline 解析句柄
     * Tag = 'tlfD' (0x44666C54) 是 ObReferenceObjectByHandle 的默认 tag */
    if (!g_OrigObpRefByHandleWithTag)
        return FALSE;

    PEPROCESS target = NULL;
    NTSTATUS status = g_OrigObpRefByHandleWithTag(
        (ULONG_PTR)ProcessHandle, 0, *PsProcessType, KernelMode, 0x44666C54, (PVOID*)&target, NULL, 0);

    if (!NT_SUCCESS(status) || !target)
        return FALSE;

    HANDLE pid = PsGetProcessId(target);
    ObDereferenceObject(target);
    return IsProtectedPid(pid);
}

/**
 * @brief 检查线程句柄是否属于受保护进程
 * @note 通过 ObpReferenceObjectByHandleWithTag trampoline 解析线程句柄的 Owner PID
 */
BOOLEAN IsProtectedThreadHandle(HANDLE ThreadHandle)
{
    if (g_ProtectedPidCount == 0)
        return FALSE;
    if (!ThreadHandle || ThreadHandle == NtCurrentThread())
        return FALSE;
    if (!g_OrigObpRefByHandleWithTag)
        return FALSE;

    PETHREAD thread = NULL;
    NTSTATUS status = g_OrigObpRefByHandleWithTag(
        (ULONG_PTR)ThreadHandle, 0, *PsThreadType, KernelMode, 0x44666C54, (PVOID*)&thread, NULL, 0);

    if (!NT_SUCCESS(status) || !thread)
        return FALSE;

    HANDLE ownerPid = PsGetThreadProcessId(thread);
    ObDereferenceObject(thread);
    return IsProtectedPid(ownerPid);
}


/* ========================================================================
 *  SSDT 解析 — 通用版
 * ======================================================================== */

PVOID GetTrueSsdtAddress(PCWSTR ZwName)
{
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, ZwName);

    PVOID funcAddr = MmGetSystemRoutineAddress(&routineName);
    if (!funcAddr) return NULL;

    PUCHAR ptr = (PUCHAR)funcAddr;
    ULONG syscallIndex = 0;
    for (int i = 0; i < 50; i++) {
        if (ptr[i] == 0xB8) {
            ULONG candidate = *(PULONG)(&ptr[i + 1]);
            if (candidate > 0 && candidate < 0x1000) {
                syscallIndex = candidate;
                break;
            }
        }
    }
    if (!syscallIndex) return NULL;

    PUCHAR kiSysCall = (PUCHAR)__readmsr(MSR_LSTAR);
    PVOID ssdtPtr = NULL;
    for (int i = 0; i < 1000; i++) {
        if (kiSysCall[i] == 0x4C && kiSysCall[i + 1] == 0x8D &&
            (kiSysCall[i + 2] == 0x15 || kiSysCall[i + 2] == 0x1D))
        {
            LONG offset = *(PLONG)(&kiSysCall[i + 3]);
            ssdtPtr = (PVOID)(kiSysCall + i + 7 + offset);
            break;
        }
    }
    if (!ssdtPtr) return NULL;

    PLONG table = *(PLONG*)ssdtPtr;
    return (PVOID)((UINT64)table + (table[syscallIndex] >> 4));
}


/* ========================================================================
 *  通过 ntdll.dll 手动解析 SSDT 索引
 * ======================================================================== */

static PVOID g_SsdtBase = NULL;

static PVOID EnsureSsdtBase()
{
    if (g_SsdtBase) return g_SsdtBase;

    PUCHAR kiSysCall = (PUCHAR)__readmsr(MSR_LSTAR);
    for (int i = 0; i < 1000; i++) {
        if (kiSysCall[i] == 0x4C && kiSysCall[i + 1] == 0x8D && kiSysCall[i + 2] == 0x15) {
            LONG offset = *(PLONG)(&kiSysCall[i + 3]);
            g_SsdtBase = (PVOID)(kiSysCall + i + 7 + offset);
            break;
        }
    }
    return g_SsdtBase;
}

static BOOLEAN IsStringMatchLocal(PCSTR a, PCSTR b)
{
    while (*a && *b) {
        if (*a != *b) return FALSE;
        a++; b++;
    }
    return (*a == *b);
}

PVOID GetSsdtAddressByNtdllName(PCSTR NtFuncName)
{
    UNICODE_STRING uniName;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE hFile = NULL, hSection = NULL;
    PVOID baseAddress = NULL;
    SIZE_T viewSize = 0;
    ULONG syscallIndex = 0;

    RtlInitUnicodeString(&uniName, L"\\SystemRoot\\System32\\ntdll.dll");
    InitializeObjectAttributes(&objAttr, &uniName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    NTSTATUS status = ZwOpenFile(&hFile,
        FILE_EXECUTE | SYNCHRONIZE, &objAttr, &iosb,
        FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) return NULL;

    status = ZwCreateSection(&hSection, SECTION_MAP_READ,
        NULL, NULL, PAGE_EXECUTE_READ, SEC_IMAGE, hFile);
    if (NT_SUCCESS(status)) {
        status = ZwMapViewOfSection(hSection, (HANDLE)-1, &baseAddress,
            0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READ);
        if (NT_SUCCESS(status)) {
            PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)baseAddress;
            if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PUCHAR)baseAddress + pDos->e_lfanew);
                if (pNt->Signature == IMAGE_NT_SIGNATURE) {
                    ULONG expRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                    if (expRva) {
                        PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)baseAddress + expRva);
                        PULONG pNames = (PULONG)((PUCHAR)baseAddress + pExp->AddressOfNames);
                        PULONG pFunctions = (PULONG)((PUCHAR)baseAddress + pExp->AddressOfFunctions);
                        PUSHORT pOrdinals = (PUSHORT)((PUCHAR)baseAddress + pExp->AddressOfNameOrdinals);

                        for (ULONG i = 0; i < pExp->NumberOfNames; i++) {
                            PCSTR name = (PCSTR)((PUCHAR)baseAddress + pNames[i]);
                            if (IsStringMatchLocal(name, NtFuncName)) {
                                PUCHAR func = (PUCHAR)baseAddress + pFunctions[pOrdinals[i]];
                                if (func[0] == 0x4C && func[1] == 0x8B &&
                                    func[2] == 0xD1 && func[3] == 0xB8)
                                    syscallIndex = *(PULONG)(&func[4]);
                                break;
                            }
                        }
                    }
                }
            }
            ZwUnmapViewOfSection((HANDLE)-1, baseAddress);
        }
        ZwClose(hSection);
    }
    ZwClose(hFile);

    if (syscallIndex == 0) return NULL;

    PVOID ssdtBase = EnsureSsdtBase();
    if (!ssdtBase) return NULL;

    PLONG table = *(PLONG*)ssdtBase;
    PVOID result = (PVOID)((UINT64)table + (table[syscallIndex] >> 4));
    SvmDebugPrint("[SSDT-ntdll] %s -> syscall 0x%X -> %p\n",
        NtFuncName, syscallIndex, result);
    return result;
}


/* ========================================================================
 *  SSSDT 解析
 * ======================================================================== */

static PVOID g_SssdtBase = NULL;
static ULONG g_SssdtLimit = 0;

static PEPROCESS FindGuiProcess()
{
    PEPROCESS proc = NULL;
    for (ULONG pid = 4; pid < 65536; pid += 4) {
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
        if (NT_SUCCESS(status) && proc) {
            PUCHAR name = PsGetProcessImageFileName(proc);
            if (name && _stricmp((const char*)name, "explorer.exe") == 0)
                return proc;
            ObDereferenceObject(proc);
        }
    }
    return NULL;
}

/**
 * @brief 初始化SSSDT(Win32k影子系统调用表)解析器
 * @author yewilliam
 * @date 2026/03/16
 * @return 成功返回STATUS_SUCCESS, 未找到返回STATUS_NOT_FOUND
 * @note 解析Shadow SSDT获取W32pServiceTable基址和函数数量限制
 */
NTSTATUS InitSssdtResolver()
{
    PUCHAR kiSysCall = (PUCHAR)__readmsr(MSR_LSTAR);
    PVOID keSDT = NULL, keSDTShadow = NULL;

    for (int i = 0; i < 1000; i++) {
        if (kiSysCall[i] == 0x4C && kiSysCall[i + 1] == 0x8D) {
            if (kiSysCall[i + 2] == 0x15) {
                LONG offset = *(PLONG)(&kiSysCall[i + 3]);
                keSDT = (PVOID)(kiSysCall + i + 7 + offset);
            }
            else if (kiSysCall[i + 2] == 0x1D) {
                LONG offset = *(PLONG)(&kiSysCall[i + 3]);
                keSDTShadow = (PVOID)(kiSysCall + i + 7 + offset);
            }
        }
        if (keSDT && keSDTShadow) break;
    }

    if (!keSDTShadow)
        return STATUS_NOT_FOUND;

    PUCHAR pShadow = (PUCHAR)keSDTShadow;
    g_SssdtBase = *(PVOID*)(pShadow + 0x20);
    g_SssdtLimit = *(PULONG)(pShadow + 0x20 + 0x10);

    PEPROCESS guiProcess = FindGuiProcess();
    if (!g_SssdtBase || !g_SssdtLimit) {
        if (!guiProcess)
            return STATUS_NOT_FOUND;

        KAPC_STATE apcState;
        KeStackAttachProcess(guiProcess, &apcState);
        g_SssdtBase = *(PVOID*)(pShadow + 0x20);
        g_SssdtLimit = *(PULONG)(pShadow + 0x20 + 0x10);
        KeUnstackDetachProcess(&apcState);
    }

    if (guiProcess)
        g_CsrssProcess = guiProcess;

    if (!g_SssdtBase || !g_SssdtLimit)
        return STATUS_NOT_FOUND;

    SvmDebugPrint("[SSSDT] W32pServiceTable=%p, Limit=%lu\n",
        g_SssdtBase, g_SssdtLimit);
    return STATUS_SUCCESS;
}

/**
 * @brief 通过索引获取SSSDT中的函数地址
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] Index - SSSDT函数索引
 * @return 函数虚拟地址, 索引越界返回NULL
 */
PVOID GetSssdtFunctionAddress(ULONG Index)
{
    if (!g_SssdtBase || Index >= g_SssdtLimit)
        return NULL;
    PLONG table = (PLONG)g_SssdtBase;
    return (PVOID)((UINT64)table + (table[Index] >> 4));
}

/**
 * @brief 模式扫描定位PspReferenceCidTableEntry - 从PsLookupProcessByProcessId中查找CALL指令
 * @author yewilliam
 * @date 2026/03/16
 * @return PspReferenceCidTableEntry的虚拟地址, 未找到返回NULL
 */
PVOID ScanForPspReferenceCidTableEntry()
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsLookupProcessByProcessId");

    PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&name);
    if (!func) return NULL;

    for (int i = 0; i < 80; i++) {
        if (func[i] == 0xE8) {
            LONG rel32 = *(PLONG)(func + i + 1);
            PVOID target = (PVOID)(func + i + 5 + rel32);
            if ((UINT64)target > 0xFFFFF80000000000ULL)
                return target;
        }
    }
    return NULL;
}

/**
 * @brief 检查目标地址是否像一个大函数(非 CFG thunk / retpoline stub)
 */
static BOOLEAN IsLargeKernelFunction(PUCHAR target)
{
    if (!target) return FALSE;
    __try {
        for (int j = 0; j < 16; j++) {
            if (target[j] == 0xC3 || target[j] == 0xCB)  return FALSE;
            if (target[j] == 0xE9)                         return FALSE;
            if (target[j] == 0xFF && (target[j + 1] & 0x38) == 0x20) return FALSE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return FALSE; }
    return TRUE;
}

/**
 * @brief 在包装函数中扫描 LEA/CALL 模式定位内部目标函数
 */
static PVOID ScanWrapperForInternalTarget(PUCHAR func, int range)
{
    if (!func) return NULL;

    /* 策略 1: LEA Rxx, [rip+disp32] — retpoline/CFG 版本
     *   4C 8D 1D/15  =  LEA R11/R10, [rip+disp32]
     *   48 8D 05/0D  =  LEA RAX/RCX, [rip+disp32]
     */
    for (int i = 0; i < range - 7; i++) {
        if ((func[i] == 0x4C || func[i] == 0x48) && func[i + 1] == 0x8D) {
            UCHAR modrm = func[i + 2];
            if ((modrm & 0xC7) == 0x05) {
                LONG disp32 = *(PLONG)(func + i + 3);
                PUCHAR target = func + i + 7 + disp32;
                if ((UINT64)target > 0xFFFFF80000000000ULL && IsLargeKernelFunction(target)) {
                    SvmDebugPrint("[SCAN] ObpRef found via LEA at +0x%X -> %p\n", i, target);
                    return (PVOID)target;
                }
            }
        }
    }

    /* 策略 2: 直接 E8 CALL rel32 — 非 retpoline 版本 */
    for (int i = 0; i < range - 5; i++) {
        if (func[i] == 0xE8) {
            LONG rel32 = *(PLONG)(func + i + 1);
            PUCHAR target = func + i + 5 + rel32;
            if ((UINT64)target > 0xFFFFF80000000000ULL && IsLargeKernelFunction(target)) {
                SvmDebugPrint("[SCAN] ObpRef found via CALL at +0x%X -> %p\n", i, target);
                return (PVOID)target;
            }
        }
    }

    return NULL;
}

/**
 * @brief 扫描找到内部函数 ObpReferenceObjectByHandleWithTag
 *
 *
 * 新策略: 优先查找 LEA [rip+disp] 模式, 验证目标是大函数
 */
static PVOID ScanForObpReferenceObjectByHandleWithTag()
{
    /* 参考开源项目的扫描方式: 从导出函数 ObReferenceObjectByHandleWithTag 开始,
     * 找第一个 E8 CALL rel32, 目标就是内部 ObpReferenceObjectByHandleWithTag。
     * 不做 IsLargeKernelFunction 过滤 (某些 build 会误判) */

    UNICODE_STRING name1;
    RtlInitUnicodeString(&name1, L"ObReferenceObjectByHandleWithTag");
    PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&name1);
    if (!func) {
        /* 回退到 ObReferenceObjectByHandle */
        UNICODE_STRING name2;
        RtlInitUnicodeString(&name2, L"ObReferenceObjectByHandle");
        func = (PUCHAR)MmGetSystemRoutineAddress(&name2);
    }
    if (!func) {
        SvmDebugPrint("[ERROR] ObReferenceObjectByHandleWithTag export not found!\n");
        return NULL;
    }

    /* 简单扫描: 找第一个 E8 (CALL rel32) — 与参考代码一致 */
    __try {
        for (int i = 0; i < 128; i++) {
            if (func[i] == 0xE8) {
                LONG rel32 = *(PLONG)(func + i + 1);
                PVOID target = (PVOID)(func + i + 5 + rel32);
                if ((UINT64)target > 0xFFFFF80000000000ULL) {
                    SvmDebugPrint("[SCAN] ObpReferenceObjectByHandleWithTag -> %p (via E8 at +0x%X)\n",
                        target, i);
                    return target;
                }
            }
        }

        /* 回退: LEA [rip+disp32] — retpoline 版本 */
        for (int i = 0; i < 128; i++) {
            if ((func[i] == 0x4C || func[i] == 0x48) && func[i + 1] == 0x8D) {
                UCHAR modrm = func[i + 2];
                if ((modrm & 0xC7) == 0x05) {
                    LONG disp32 = *(PLONG)(func + i + 3);
                    PUCHAR target = func + i + 7 + disp32;
                    if ((UINT64)target > 0xFFFFF80000000000ULL) {
                        SvmDebugPrint("[SCAN] ObpReferenceObjectByHandleWithTag -> %p (via LEA at +0x%X)\n",
                            target, i);
                        return (PVOID)target;
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SvmDebugPrint("[ERROR] Exception in ObpRef scan\n");
    }

    SvmDebugPrint("[ERROR] ObpReferenceObjectByHandleWithTag NOT FOUND! Handle elevation will not work.\n");
    return NULL;
}

/**
 * @brief 动态获取SSSDT函数索引 - 映射win32u.dll解析导出表中的syscall号
 * @param [in] FunctionName - 函数名(如"NtUserFindWindowEx")
 * @return SSSDT索引(低12位), 失败返回0
 */
ULONG GetSssdtIndexDynamic(PCSTR FunctionName)
{
    UNICODE_STRING uniName;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE hFile = NULL, hSection = NULL;
    PVOID baseAddress = NULL;
    SIZE_T viewSize = 0;
    ULONG syscallIndex = 0;

    RtlInitUnicodeString(&uniName, L"\\SystemRoot\\System32\\win32u.dll");
    InitializeObjectAttributes(&objAttr, &uniName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    NTSTATUS status = ZwOpenFile(&hFile,
        FILE_EXECUTE | SYNCHRONIZE, &objAttr, &iosb,
        FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) return 0;

    status = ZwCreateSection(&hSection, SECTION_MAP_READ,
        NULL, NULL, PAGE_EXECUTE_READ, SEC_IMAGE, hFile);
    if (NT_SUCCESS(status)) {
        status = ZwMapViewOfSection(hSection, (HANDLE)-1, &baseAddress,
            0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READ);
        if (NT_SUCCESS(status)) {
            PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)baseAddress;
            if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PUCHAR)baseAddress + pDos->e_lfanew);
                if (pNt->Signature == IMAGE_NT_SIGNATURE) {
                    ULONG expRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                    if (expRva) {
                        PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)baseAddress + expRva);
                        PULONG pNames = (PULONG)((PUCHAR)baseAddress + pExp->AddressOfNames);
                        PULONG pFunctions = (PULONG)((PUCHAR)baseAddress + pExp->AddressOfFunctions);
                        PUSHORT pOrdinals = (PUSHORT)((PUCHAR)baseAddress + pExp->AddressOfNameOrdinals);

                        for (ULONG i = 0; i < pExp->NumberOfNames; i++) {
                            PCSTR name = (PCSTR)((PUCHAR)baseAddress + pNames[i]);
                            if (IsStringMatchLocal(name, FunctionName)) {
                                PUCHAR fn = (PUCHAR)baseAddress + pFunctions[pOrdinals[i]];
                                if (fn[0] == 0x4C && fn[1] == 0x8B &&
                                    fn[2] == 0xD1 && fn[3] == 0xB8)
                                    syscallIndex = *(PULONG)(&fn[4]);
                                break;
                            }
                        }
                    }
                }
            }
            ZwUnmapViewOfSection((HANDLE)-1, baseAddress);
        }
        ZwClose(hSection);
    }
    ZwClose(hFile);

    if (syscallIndex) {
        SvmDebugPrint("[SSSDT] %s index: 0x%X\n", FunctionName, syscallIndex & 0xFFF);
        return syscallIndex & 0xFFF;
    }
    return 0;
}

/**
 * @brief Hook: NtQuerySystemInformation - 从系统信息查询结果中过滤受保护进程
 * @author yewilliam
 * @date 2026/03/16
 * @param [in]  SystemInformationClass  - 信息类型(Process/Handle/ExtendedHandle)
 * @param [out] SystemInformation       - 系统信息输出缓冲区
 * @param [in]  SystemInformationLength - 缓冲区大小
 * @param [out] ReturnLength            - 实际数据大小
 * @return NTSTATUS - 透传原函数返回值
 * @note 过滤三种信息类: SystemProcessInformation(链表摘除),
 *        SystemHandleInformation(句柄数组压缩), SystemExtendedHandleInformation(同上)
 */
 /**
  * @brief Hook: NtQuerySystemInformation - 过滤进程/句柄列表 + 隐藏内核调试器
  *
  * [FIX] 新增 SystemKernelDebuggerInformation (class 0x23) 伪装:
  *   无论保护是否激活, 始终报告"无内核调试器"。
  *   这防止反作弊通过此查询检测 WinDbg/KD 连接。
  *
  * 过滤三种信息类: SystemProcessInformation(链表摘除),
  *  SystemHandleInformation(句柄数组压缩), SystemExtendedHandleInformation(同上)
  */
static NTSTATUS NTAPI Fake_NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtQuerySystemInformation);
    if (!g_OrigNtQuerySystemInformation)
        return STATUS_UNSUCCESSFUL;

    /* 先调用原函数获取数据 */
    NTSTATUS status = g_OrigNtQuerySystemInformation(
        SystemInformationClass, SystemInformation,
        SystemInformationLength, ReturnLength);
    if (!NT_SUCCESS(status) || !SystemInformation)
        return status;

    /* ============================================================
     * [FIX] 全局伪装: SystemKernelDebuggerInformation (class 0x23)
     * 无论保护是否激活, 始终报告"无内核调试器"
     * 结构体: { BOOLEAN KernelDebuggerEnabled; BOOLEAN KernelDebuggerNotPresent; }
     * ============================================================ */
    if (SystemInformationClass == (SYSTEM_INFORMATION_CLASS)0x23) {
        __try {
            if (SystemInformationLength >= 2) {
                PUCHAR info = (PUCHAR)SystemInformation;
                info[0] = FALSE; /* KernelDebuggerEnabled = FALSE */
                info[1] = TRUE;  /* KernelDebuggerNotPresent = TRUE */
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        return status;
    }

    /* SystemKernelDebuggerInformationEx (class 0x95) — 扩展版本, 同样伪装 */
    if (SystemInformationClass == (SYSTEM_INFORMATION_CLASS)0x95) {
        __try {
            if (SystemInformationLength >= 2) {
                PUCHAR info = (PUCHAR)SystemInformation;
                info[0] = FALSE;
                info[1] = TRUE;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        return status;
    }

    /* 进程/句柄过滤仅在保护激活且调用者非受保护进程时生效 */
    if (g_ProtectedPidCount == 0 || IsCallerProtected())
        return status;

    __try {
        if (SystemInformationClass == SystemProcessInformation) {
            PSYSTEM_PROCESS_INFORMATION current = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
            PSYSTEM_PROCESS_INFORMATION previous = NULL;
            ULONG_PTR bufferEnd = (ULONG_PTR)SystemInformation + SystemInformationLength;

            while (TRUE) {
                if ((ULONG_PTR)current + sizeof(SYSTEM_PROCESS_INFORMATION) > bufferEnd)
                    break;

                if (IsProtectedPid(current->UniqueProcessId)) {
                    if (!previous) {
                        if (!current->NextEntryOffset) {
                            RtlZeroMemory(SystemInformation, SystemInformationLength);
                            break;
                        }
                        RtlMoveMemory(current,
                            (PUCHAR)current + current->NextEntryOffset,
                            (ULONG)(bufferEnd - (ULONG_PTR)current - current->NextEntryOffset));
                        continue;
                    }
                    else {
                        if (!current->NextEntryOffset)
                            previous->NextEntryOffset = 0;
                        else
                            previous->NextEntryOffset += current->NextEntryOffset;      //这里是关键把偏移增加上去，然后就相当于跳过了我们保护的进程

                        if (!current->NextEntryOffset)
                            break;
                        current = (PSYSTEM_PROCESS_INFORMATION)(
                            (PUCHAR)previous + previous->NextEntryOffset);
                        continue;
                    }
                }

                if (!current->NextEntryOffset)
                    break;
                previous = current;
                current = (PSYSTEM_PROCESS_INFORMATION)(
                    (PUCHAR)current + current->NextEntryOffset);
            }
        }
        else if (SystemInformationClass == SystemHandleInformation) {
            PSVM_HANDLE_INFO handleInfo = (PSVM_HANDLE_INFO)SystemInformation;
            ULONG dest = 0;
            for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
                if (!IsProtectedPid((HANDLE)(ULONG_PTR)handleInfo->Handles[i].OwnerPid)) {
                    if (dest != i)
                        handleInfo->Handles[dest] = handleInfo->Handles[i];
                    dest++;
                }
            }
            handleInfo->NumberOfHandles = dest;
        }
        else if (SystemInformationClass == SystemExtendedHandleInformation) {
            PSVM_HANDLE_INFO_EX handleInfoEx = (PSVM_HANDLE_INFO_EX)SystemInformation;
            ULONG_PTR dest = 0;
            for (ULONG_PTR i = 0; i < handleInfoEx->NumberOfHandles; i++) {
                if (!IsProtectedPid((HANDLE)handleInfoEx->Handles[i].OwnerPid)) {
                    if (dest != i)
                        handleInfoEx->Handles[dest] = handleInfoEx->Handles[i];//这里可以跳过句柄表中的句柄
                    dest++;
                }
            }
            handleInfoEx->NumberOfHandles = dest;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return status;
}

/**
 * @brief Hook: NtOpenProcess - 阻止外部进程打开受保护进程
 * @author yewilliam
 * @date 2026/03/16
 * @param [out] ProcessHandle   - 输出的进程句柄
 * @param [in]  DesiredAccess   - 请求的访问权限
 * @param [in]  ObjectAttributes - 对象属性
 * @param [in]  ClientId         - 包含目标PID的结构体
 * @return STATUS_ACCESS_DENIED(拒绝) 或原函数返回值
 * @note 受保护进程自身打开非保护进程时降权为PROCESS_QUERY_LIMITED_INFORMATION
 */
static NTSTATUS NTAPI Fake_NtOpenProcess(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtOpenProcess);
    if (!g_OrigNtOpenProcess) return STATUS_UNSUCCESSFUL;

    if (g_ProtectedPidCount == 0)
        return g_OrigNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

    /* 外部进程打开受保护进程 → 拒绝 */
    if (ClientId && ClientId->UniqueProcess &&
        IsProtectedPid(ClientId->UniqueProcess) && !IsCallerProtected())
    {
        if (ProcessHandle) {
            __try { *ProcessHandle = NULL; }
            __except (1) {}
        }
        return STATUS_INVALID_CID;
    }

    /* ================================================================
     *  CE 打开升权目标 → 绕过 ACE, 创建完整权限句柄
     *
     *  ACE 的 ObRegisterCallbacks 在句柄 CREATE 时降权。
     *  OBJ_KERNEL_HANDLE → ACE 回调看到 KernelHandle=TRUE → 跳过
     *  ZwDuplicateObject → 转为用户句柄 → CE 拿到完整权限
     * ================================================================ */
    if (IsCallerProtected() && ClientId && ClientId->UniqueProcess &&
        g_ElevatedPidCount > 0 && IsElevatedPid(ClientId->UniqueProcess))
    {
        PEPROCESS targetProc = NULL;
        NTSTATUS status;

        /* Step 1: 直接拿 EPROCESS, 不走句柄 */
        status = PsLookupProcessByProcessId(ClientId->UniqueProcess, &targetProc);
        if (!NT_SUCCESS(status) || !targetProc)
            return g_OrigNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

        /* Step 2: 创建内核句柄 (OBJ_KERNEL_HANDLE → ACE 回调跳过) */
        HANDLE kernelHandle = NULL;
        status = ObOpenObjectByPointer(
            targetProc,
            OBJ_KERNEL_HANDLE,          /* ACE: KernelHandle=TRUE → skip */
            NULL,
            PROCESS_ALL_ACCESS,
            *PsProcessType,
            KernelMode,
            &kernelHandle);

        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(targetProc);
            return g_OrigNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
        }

        /* Step 3: 复制为用户句柄到 CE 的句柄表 */
        HANDLE userHandle = NULL;
        status = ZwDuplicateObject(
            NtCurrentProcess(), kernelHandle,
            NtCurrentProcess(), &userHandle,
            PROCESS_ALL_ACCESS, 0, 0);

        ZwClose(kernelHandle);
        ObDereferenceObject(targetProc);

        if (NT_SUCCESS(status) && userHandle && ProcessHandle) {
            __try {
                *ProcessHandle = userHandle;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                ZwClose(userHandle);
                return STATUS_ACCESS_VIOLATION;
            }
            SvmDebugPrint("[Elevate] NtOpenProcess: CE got ALL_ACCESS handle for PID %llu\n",
                (ULONG64)ClientId->UniqueProcess);
            return STATUS_SUCCESS;
        }

        /* 回退 */
        if (userHandle) ZwClose(userHandle);
        return g_OrigNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }

    /* CE 打开非升权进程 → 透传 */
    if (IsCallerProtected())
        return g_OrigNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

    return g_OrigNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

/**
 * @brief Hook: NtQueryInformationProcess - 反调试伪装 + 保护进程隐藏
 *
 * [FIX] 三层策略:
 *   1. 外部进程访问保护进程 → STATUS_INVALID_PARAMETER
 *   2. 保护进程(CE)查询自身或目标 → 透传, 不干扰调试流程
 *   3. 非保护进程查询自身的调试状态 → 伪装:
 *        - ProcessDebugPort    (class 0x07) → 返回 0
 *        - ProcessDebugObjectHandle (class 0x1E) → STATUS_PORT_NOT_SET
 *        - ProcessDebugFlags   (class 0x1F) → 返回 1 (未被调试)
 */
static NTSTATUS NTAPI Fake_NtQueryInformationProcess(
    HANDLE ProcessHandle, ULONG ProcessInfoClass,
    PVOID ProcessInfo, ULONG ProcessInfoLength, PULONG ReturnLength)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtQueryInformationProcess);
    if (!g_OrigNtQueryInformationProcess) return STATUS_UNSUCCESSFUL;

    if (g_ProtectedPidCount == 0)
        return g_OrigNtQueryInformationProcess(
            ProcessHandle, ProcessInfoClass, ProcessInfo, ProcessInfoLength, ReturnLength);

    /* 外部访问保护进程 → STATUS_INVALID_PARAMETER */
    if (IsProtectedProcessHandle(ProcessHandle) && !IsCallerProtected())
        return STATUS_INVALID_PARAMETER;

    /* 保护进程(CE)自身的调用 → 全部透传 */
    if (IsCallerProtected())
        return g_OrigNtQueryInformationProcess(
            ProcessHandle, ProcessInfoClass, ProcessInfo, ProcessInfoLength, ReturnLength);

    /* ================================================================
     * [FIX] 反调试伪装: 仅对"正在被我们调试的目标进程"生效
     *
     * 原代码问题:
     *   保护CE后, 所有非保护进程(包括ACE登录器)查询自身调试状态
     *   都被伪装 → ACE 自检流程被破坏 → 登录器拒绝启动
     *
     * 修复后:
     *   CE attach game.exe → game.exe 是 DebugTarget
     *   game.exe 反作弊查 ProcessDebugPort → 返回 0 (隐藏调试)
     *   launcher.exe 查 ProcessDebugPort → 原样返回 (不干扰)
     * ================================================================ */

     /* 仅对自查场景 (进程查自己) 做判断 */
    if (ProcessHandle == NtCurrentProcess() || ProcessHandle == (HANDLE)-1) {
        PDEBUG_PROCESS dbgProc = NULL;
        BOOLEAN isTarget = IsDebugTargetProcess(PsGetCurrentProcess(), &dbgProc);

        if (isTarget) {
            /* === 调试目标进程: 执行反调试伪装 === */

            /* ProcessDebugObjectHandle (0x1E) → "无调试对象" */
            if (ProcessInfoClass == 0x1E) {
                g_OrigNtQueryInformationProcess(
                    ProcessHandle, ProcessInfoClass, ProcessInfo,
                    ProcessInfoLength, ReturnLength);
                return (NTSTATUS)0xC0000353; /* STATUS_PORT_NOT_SET */
            }

            NTSTATUS status = g_OrigNtQueryInformationProcess(
                ProcessHandle, ProcessInfoClass, ProcessInfo,
                ProcessInfoLength, ReturnLength);

            if (NT_SUCCESS(status) && ProcessInfo) {
                __try {
                    switch (ProcessInfoClass) {
                    case 7: /* ProcessDebugPort → 0 */
                        if (ProcessInfoLength >= sizeof(ULONG_PTR))
                            *(PULONG_PTR)ProcessInfo = 0;
                        break;
                    case 0x1F: /* ProcessDebugFlags → 1 */
                        if (ProcessInfoLength >= sizeof(ULONG))
                            *(PULONG)ProcessInfo = 1;
                        break;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
            return status;
        }
    }

    /* 非调试目标 → 正常透传, 不伪装 */
    return g_OrigNtQueryInformationProcess(
        ProcessHandle, ProcessInfoClass, ProcessInfo, ProcessInfoLength, ReturnLength);
}

HANDLE   g_ElevatedPIDs[MAX_ELEVATED_PIDS] = { 0 };
volatile LONG g_ElevatedPidCount = 0;

BOOLEAN AddElevatedPid(HANDLE Pid)
{
    if (!Pid) return FALSE;
    for (LONG i = 0; i < g_ElevatedPidCount; i++)
        if (g_ElevatedPIDs[i] == Pid) return TRUE;
    LONG idx = InterlockedIncrement(&g_ElevatedPidCount) - 1;
    if (idx >= MAX_ELEVATED_PIDS) {
        InterlockedDecrement(&g_ElevatedPidCount);
        return FALSE;
    }
    g_ElevatedPIDs[idx] = Pid;
    SvmDebugPrint("[Elevate] PID %llu added (count=%ld)\n", (ULONG64)Pid, idx + 1);
    return TRUE;
}

BOOLEAN RemoveElevatedPid(HANDLE Pid)
{
    for (LONG i = 0; i < g_ElevatedPidCount; i++) {
        if (g_ElevatedPIDs[i] == Pid) {
            for (LONG j = i; j < g_ElevatedPidCount - 1; j++)
                g_ElevatedPIDs[j] = g_ElevatedPIDs[j + 1];
            LONG n = InterlockedDecrement(&g_ElevatedPidCount);
            g_ElevatedPIDs[n] = 0;
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN IsElevatedPid(HANDLE Pid)
{
    if (g_ElevatedPidCount == 0 || !Pid) return FALSE;
    LONG count = g_ElevatedPidCount;
    for (LONG i = 0; i < count && i < MAX_ELEVATED_PIDS; i++)
        if (g_ElevatedPIDs[i] == Pid) return TRUE;
    return FALSE;
}

VOID ClearAllElevatedPids()
{
    RtlZeroMemory(g_ElevatedPIDs, sizeof(g_ElevatedPIDs));
    InterlockedExchange(&g_ElevatedPidCount, 0);
}


/**
 * @brief Hook: NtQueryVirtualMemory - 阻止外部探测受保护进程的内存布局
 * @author yewilliam
 * @date 2026/03/16
 * @param [in]  ProcessHandle  - 进程句柄
 * @param [in]  BaseAddress     - 查询基地址
 * @param [in]  MemInfoClass   - 信息类型
 * @param [out] MemInfo         - 输出缓冲区
 * @param [in]  MemInfoLength  - 缓冲区大小
 * @param [out] ReturnLength    - 实际大小
 * @return STATUS_ACCESS_DENIED 或原函数返回值
 */
static NTSTATUS NTAPI Fake_NtQueryVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, ULONG MemInfoClass,
    PVOID MemInfo, SIZE_T MemInfoLength, PSIZE_T ReturnLength)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtQueryVirtualMemory);

    /* [TRACE] 无条件入口 — Release 也打印，只打一次 */
    {
        static volatile LONG _tEntry = 0;
        if (InterlockedCompareExchange(&_tEntry, 1, 0) == 0)
            SvmDebugPrint("[QVM-TRACE] ENTRY: handle=0x%p caller=%llu protected=%d elevated=%d\n",
                ProcessHandle, (ULONG64)PsGetCurrentProcessId(),
                (int)IsCallerProtected(),
                (int)(g_ElevatedPidCount > 0 && IsElevatedPid(PsGetCurrentProcessId())));
    }

    if (!g_OrigNtQueryVirtualMemory) return STATUS_UNSUCCESSFUL;

    /* [DIAG-v24] 只计数 CE 调用 */
    BOOLEAN qvmIsCE = (g_ProtectedPidCount > 0) && IsCallerProtected();
    BOOLEAN qvmLog = qvmIsCE && DiagShouldLog_CE(&s_diag_QVM);
    LONG qvmSeq = s_diag_QVM;
    if (qvmLog)
        SvmDebugPrint("[QVM] #%d h=%p addr=%p caller=%llu prot=%d\n",
            qvmSeq, ProcessHandle, BaseAddress,
            (ULONG64)PsGetCurrentProcessId(), (int)IsCallerProtected());

    /* [PATH A] ElevatedPid 调用者直接放行 */
    if (g_ElevatedPidCount > 0 && IsElevatedPid(PsGetCurrentProcessId())) {
        static volatile LONG _tA = 0;
        if (InterlockedCompareExchange(&_tA, 1, 0) == 0)
            SvmDebugPrint("[QVM-TRACE] PATH-A: ElevatedPid passthrough\n");
        return g_OrigNtQueryVirtualMemory(
            ProcessHandle, BaseAddress, MemInfoClass, MemInfo, MemInfoLength, ReturnLength);
    }

    /* [PATH B] CE (Protected caller) 查询目标进程
     * 用临时 OBJ_KERNEL_HANDLE 绕过 ObRegisterCallbacks 降权 */
    if (IsCallerProtected() &&
        ProcessHandle && ProcessHandle != NtCurrentProcess())
    {
        PEPROCESS targetProc = NULL;
        NTSTATUS status = ObReferenceObjectByHandle(
            ProcessHandle, 0, *PsProcessType, KernelMode,
            (PVOID*)&targetProc, NULL);

        {
            static volatile LONG _tB1 = 0;
            if (InterlockedCompareExchange(&_tB1, 1, 0) == 0)
                SvmDebugPrint("[QVM-TRACE] PATH-B: CE caller, ObRefByHandle status=0x%X\n", status);
        }

        if (NT_SUCCESS(status) && targetProc) {
            HANDLE kernelHandle = NULL;
            status = ObOpenObjectByPointer(
                targetProc, OBJ_KERNEL_HANDLE, NULL,
                0x0400, /* PROCESS_QUERY_INFORMATION */
                *PsProcessType, KernelMode, &kernelHandle);
            ObDereferenceObject(targetProc);

            if (NT_SUCCESS(status) && kernelHandle) {
                status = g_OrigNtQueryVirtualMemory(
                    kernelHandle, BaseAddress, MemInfoClass,
                    MemInfo, MemInfoLength, ReturnLength);
                ZwClose(kernelHandle);
                {
                    static volatile LONG _tB2 = 0;
                    if (InterlockedCompareExchange(&_tB2, 1, 0) == 0)
                        SvmDebugPrint("[QVM-TRACE] PATH-B: kernel handle query status=0x%X\n", status);
                }
                return status;
            }
        }
    }

    /* [PATH C] 外部进程查询受保护进程 → 拒绝 */
    if (g_ProtectedPidCount > 0 &&
        IsProtectedProcessHandle(ProcessHandle) && !IsCallerProtected()) {
        static volatile LONG _tC = 0;
        if (InterlockedCompareExchange(&_tC, 1, 0) == 0)
            SvmDebugPrint("[QVM-TRACE] PATH-C: ACCESS_DENIED\n");
        return STATUS_ACCESS_DENIED;
    }

    /* [PATH D] 默认透传 */
    {
        static volatile LONG _tD = 0;
        if (InterlockedCompareExchange(&_tD, 1, 0) == 0)
            SvmDebugPrint("[QVM-TRACE] PATH-D: default passthrough\n");
    }
    return g_OrigNtQueryVirtualMemory(
        ProcessHandle, BaseAddress, MemInfoClass, MemInfo, MemInfoLength, ReturnLength);
}

/**
 * @brief Hook: NtDuplicateObject - 阻止通过句柄复制间接获取受保护进程访问权
 * @author yewilliam
 * @date 2026/03/16
 * @param [in]  SourceProcessHandle  - 源进程句柄
 * @param [in]  SourceHandle         - 要复制的句柄
 * @param [in]  TargetProcessHandle  - 目标进程句柄
 * @param [out] TargetHandle         - 输出复制后的句柄
 * @param [in]  DesiredAccess        - 请求权限
 * @param [in]  HandleAttributes     - 句柄属性
 * @param [in]  Options              - 操作选项
 * @return STATUS_ACCESS_DENIED 或原函数返回值
 */
static NTSTATUS NTAPI Fake_NtDuplicateObject(
    HANDLE SourceProcessHandle, HANDLE SourceHandle,
    HANDLE TargetProcessHandle, PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtDuplicateObject);
    if (!g_OrigNtDuplicateObject) return STATUS_UNSUCCESSFUL;

    /* [FIX] 系统白名单进程放行 (csrss/svchost等做SxS/句柄继承时必须能复制句柄) */
    if (g_ProtectedPidCount > 0 && !IsCallerProtected() &&
        !IsWhitelistedCaller() &&
        IsProtectedProcessHandle(SourceProcessHandle))
        return STATUS_ACCESS_DENIED;

    return g_OrigNtDuplicateObject(
        SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle,
        DesiredAccess, HandleAttributes, Options);
}

/**
 * @brief Hook: NtGetNextProcess - 在进程遍历中自动跳过受保护进程
 * @author yewilliam
 * @date 2026/03/16
 * @param [in]  ProcessHandle    - 当前进程句柄
 * @param [in]  DesiredAccess    - 请求权限
 * @param [in]  HandleAttributes - 句柄属性
 * @param [in]  Flags            - 标志
 * @param [out] NewProcessHandle - 输出下一个进程句柄
 * @return NTSTATUS - 循环跳过受保护进程直到找到非保护进程或遍历结束
 */
static NTSTATUS NTAPI Fake_NtGetNextProcess(
    HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtGetNextProcess);
    if (!g_OrigNtGetNextProcess) return STATUS_UNSUCCESSFUL;

    NTSTATUS status = g_OrigNtGetNextProcess(
        ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);

    if (g_ProtectedPidCount == 0 || IsCallerProtected())
        return status;

    while (NT_SUCCESS(status) && NewProcessHandle) {
        HANDLE hNext = NULL;
        __try { hNext = *NewProcessHandle; }
        __except (1) { break; }
        if (!hNext) break;

        if (IsProtectedProcessHandle(hNext)) {
            HANDLE hSkip = hNext;
            __try { *NewProcessHandle = NULL; }
            __except (1) {}
            status = g_OrigNtGetNextProcess(
                hSkip, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);//这里选择了跳过
            ZwClose(hSkip);
            if (!NT_SUCCESS(status)) break;
            continue;
        }
        break;
    }
    return status;
}

/**
 * @brief Hook: NtGetNextThread - 阻止枚举受保护进程的线程
 * @author yewilliam
 * @date 2026/03/16
 * @param [in]  ProcessHandle    - 进程句柄
 * @param [in]  ThreadHandle     - 当前线程句柄
 * @param [in]  DesiredAccess    - 请求权限
 * @param [in]  HandleAttributes - 句柄属性
 * @param [in]  Flags            - 标志
 * @param [out] NewThreadHandle  - 输出下一个线程句柄
 * @return STATUS_ACCESS_DENIED 或原函数返回值
 */
static NTSTATUS NTAPI Fake_NtGetNextThread(
    HANDLE ProcessHandle, HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes,
    ULONG Flags, PHANDLE NewThreadHandle)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtGetNextThread);
    if (!g_OrigNtGetNextThread) return STATUS_UNSUCCESSFUL;

    if (g_ProtectedPidCount > 0 && !IsCallerProtected() &&
        IsProtectedProcessHandle(ProcessHandle))
        return STATUS_NO_MORE_ENTRIES; /* [FIX] 伪装"没有更多线程" */

    return g_OrigNtGetNextThread(
        ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes,
        Flags, NewThreadHandle);
}

/**
 * @brief Hook: NtReadVirtualMemory - 对受保护进程返回全零数据欺骗读取
 * @author yewilliam
 * @date 2026/03/16
 * @param [in]  ProcessHandle     - 进程句柄
 * @param [in]  BaseAddress        - 读取地址
 * @param [out] Buffer            - 输出缓冲区
 * @param [in]  Size               - 读取大小
 * @param [out] NumberOfBytesRead - 实际读取字节数
 * @return STATUS_SUCCESS(返回全零数据) 或原函数返回值
 * @note 不返回ACCESS_DENIED, 而是返回空数据使调用者无法感知被拦截
 */
static NTSTATUS NTAPI Fake_NtReadVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T Size, PSIZE_T NumberOfBytesRead)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtReadVirtualMemory);
    if (!g_OrigNtReadVirtualMemory) return STATUS_UNSUCCESSFUL;

    /* [DIAG-v24] 只计数 CE 进程的调用, 系统进程不消耗配额 */
    BOOLEAN isCE = (g_ProtectedPidCount > 0) && IsCallerProtected();
    BOOLEAN doLog = isCE && DiagShouldLog_CE(&s_diag_NtRVM);
    LONG seq = s_diag_NtRVM;
    /* CE 每1000次读取打印一次总数摘要 */
    static volatile LONG s_ceReadTotal = 0;
    if (isCE) {
        LONG t = InterlockedIncrement(&s_ceReadTotal);
        if (t == 1 || (t % 1000) == 0)
            SvmDebugPrint("[NtRVM-SUM] CE total reads: %d\n", t);
    }

    /* CE 读升权目标 → 直接 MmCopyVirtualMemory 绕过句柄 */
    if (IsCallerProtected() && g_ElevatedPidCount > 0 &&
        g_OrigMmCopyVirtualMemory &&
        ProcessHandle && ProcessHandle != NtCurrentProcess())
    {
        PEPROCESS targetProc = NULL;
        NTSTATUS status = ObReferenceObjectByHandle(
            ProcessHandle, 0, *PsProcessType, KernelMode,
            (PVOID*)&targetProc, NULL);

        if (NT_SUCCESS(status) && targetProc) {
            if (IsElevatedPid(PsGetProcessId(targetProc))) {
                SIZE_T bytesCopied = 0;
                status = g_OrigMmCopyVirtualMemory(
                    targetProc, BaseAddress,
                    PsGetCurrentProcess(), Buffer,
                    Size, KernelMode, &bytesCopied);
                ObDereferenceObject(targetProc);
                if (NumberOfBytesRead) {
                    __try { *NumberOfBytesRead = bytesCopied; }
                    __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
                if (doLog) SvmDebugPrint("[NtRVM] #%d ELEV-MMCOPY: addr=%p size=%llu st=0x%X\n",
                    seq, BaseAddress, (ULONG64)Size, status);
                return status;
            }
            ObDereferenceObject(targetProc);
        }
    }

    /* ElevatedPid 调用者放行 */
    if (g_ElevatedPidCount > 0 && IsElevatedPid(PsGetCurrentProcessId())) {
        if (doLog) SvmDebugPrint("[NtRVM] #%d ELEVPID-PASS\n", seq);
        return g_OrigNtReadVirtualMemory(
            ProcessHandle, BaseAddress, Buffer, Size, NumberOfBytesRead);
    }

    /* 外部对保护进程 → 填零 */
    if (g_ProtectedPidCount > 0 &&
        IsProtectedProcessHandle(ProcessHandle) && !IsCallerProtected())
    {
        if (doLog) SvmDebugPrint("[NtRVM] #%d BLOCK-ZERO: addr=%p size=%llu caller=%llu\n",
            seq, BaseAddress, (ULONG64)Size, (ULONG64)PsGetCurrentProcessId());
        __try {
            RtlZeroMemory(Buffer, Size);
            if (NumberOfBytesRead) *NumberOfBytesRead = Size;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        return STATUS_SUCCESS;
    }

    /* 默认透传 */
    {
        NTSTATUS st = g_OrigNtReadVirtualMemory(
            ProcessHandle, BaseAddress, Buffer, Size, NumberOfBytesRead);
        if (doLog) {
            ULONG f4 = 0;
            __try { if (Buffer && Size >= 4) f4 = *(PULONG)Buffer; }
            __except (1) {}
            SvmDebugPrint("[NtRVM] #%d PASS: h=%p addr=%p sz=%llu st=0x%X f4=0x%08X c=%llu\n",
                seq, ProcessHandle, BaseAddress, (ULONG64)Size, st, f4, (ULONG64)PsGetCurrentProcessId());
        }
        return st;
    }
}

/**
 * @brief Hook: NtWriteVirtualMemory - 阻止向受保护进程写入内存
 * @author yewilliam
 * @date 2026/03/16
 * @param [in]  ProcessHandle        - 进程句柄
 * @param [in]  BaseAddress           - 写入地址
 * @param [in]  Buffer               - 数据缓冲区
 * @param [in]  Size                  - 写入大小
 * @param [out] NumberOfBytesWritten - 实际写入字节数
 * @return STATUS_ACCESS_DENIED 或原函数返回值
 */
static NTSTATUS NTAPI Fake_NtWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T Size, PSIZE_T NumberOfBytesWritten)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtWriteVirtualMemory);
    if (!g_OrigNtWriteVirtualMemory) return STATUS_UNSUCCESSFUL;

    /* CE 写升权目标 → 直接 MmCopyVirtualMemory, 绕过句柄系统 */
    if (IsCallerProtected() && g_ElevatedPidCount > 0 &&
        g_OrigMmCopyVirtualMemory &&
        ProcessHandle && ProcessHandle != NtCurrentProcess())
    {
        PEPROCESS targetProc = NULL;
        NTSTATUS status = ObReferenceObjectByHandle(
            ProcessHandle, 0, *PsProcessType, KernelMode,
            (PVOID*)&targetProc, NULL);

        if (NT_SUCCESS(status) && targetProc) {
            if (IsElevatedPid(PsGetProcessId(targetProc))) {
                SIZE_T bytesCopied = 0;
                status = g_OrigMmCopyVirtualMemory(
                    PsGetCurrentProcess(), Buffer,
                    targetProc, BaseAddress,
                    Size, KernelMode, &bytesCopied);

                ObDereferenceObject(targetProc);

                if (NumberOfBytesWritten) {
                    __try { *NumberOfBytesWritten = bytesCopied; }
                    __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
                return status;
            }
            ObDereferenceObject(targetProc);
        }
    }

    /* ElevatedPid 调用者放行 */
    if (g_ElevatedPidCount > 0 && IsElevatedPid(PsGetCurrentProcessId()))
        return g_OrigNtWriteVirtualMemory(
            ProcessHandle, BaseAddress, Buffer, Size, NumberOfBytesWritten);

    if (g_ProtectedPidCount > 0 &&
        IsProtectedProcessHandle(ProcessHandle) && !IsCallerProtected())
        return STATUS_ACCESS_DENIED;

    return g_OrigNtWriteVirtualMemory(
        ProcessHandle, BaseAddress, Buffer, Size, NumberOfBytesWritten);
}

/**
 * @brief Hook: NtProtectVirtualMemory - 阻止修改受保护进程的内存保护属性
 * @author yewilliam
 * @date 2026/03/16
 * @param [in]     ProcessHandle - 进程句柄
 * @param [in,out] BaseAddress    - 目标地址
 * @param [in,out] RegionSize    - 区域大小
 * @param [in]     NewProtect     - 新保护属性
 * @param [out]    OldProtect    - 旧保护属性
 * @return STATUS_ACCESS_DENIED 或原函数返回值
 */
static NTSTATUS NTAPI Fake_NtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtProtectVirtualMemory);
    if (!g_OrigNtProtectVirtualMemory) return STATUS_UNSUCCESSFUL;

    /* [NEW] ElevatedPid 调用者直接放行 */
    if (g_ElevatedPidCount > 0 && IsElevatedPid(PsGetCurrentProcessId()))
        return g_OrigNtProtectVirtualMemory(
            ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

    if (g_ProtectedPidCount > 0 &&
        IsProtectedProcessHandle(ProcessHandle) && !IsCallerProtected())
        return STATUS_ACCESS_DENIED;

    return g_OrigNtProtectVirtualMemory(
        ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

/**
 * @brief Hook: NtTerminateProcess - 阻止外部进程终止受保护进程
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] ProcessHandle - 进程句柄
 * @param [in] ExitStatus - 退出状态码
 * @return STATUS_ACCESS_DENIED 或原函数返回值
 * @note 排除自杀场景(ProcessHandle == NtCurrentProcess)
 */
static NTSTATUS NTAPI Fake_NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtTerminateProcess);
    if (!g_OrigNtTerminateProcess) return STATUS_UNSUCCESSFUL;

    if (ProcessHandle != NtCurrentProcess() && ProcessHandle &&
        g_ProtectedPidCount > 0 &&
        IsProtectedProcessHandle(ProcessHandle) && !IsCallerProtected())
        return STATUS_ACCESS_DENIED;

    return g_OrigNtTerminateProcess(ProcessHandle, ExitStatus);
}

/**
 * @brief Hook: NtCreateThreadEx - 阻止在受保护进程中创建远程线程
 * @author yewilliam
 * @date 2026/03/16
 * @param [out] ThreadHandle     - 输出线程句柄
 * @param [in]  DesiredAccess    - 访问权限
 * @param [in]  ObjectAttributes - 对象属性
 * @param [in]  ProcessHandle    - 目标进程句柄
 * @param [in]  StartRoutine     - 线程入口
 * @param [in]  Argument         - 线程参数
 * @param [in]  CreateFlags      - 创建标志
 * @param [in]  ZeroBits/StackSize/MaximumStackSize/AttributeList - 其他参数
 * @return STATUS_ACCESS_DENIED 或原函数返回值
 */
static NTSTATUS NTAPI Fake_NtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
    PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits,
    SIZE_T StackSize, SIZE_T MaximumStackSize,
    PVOID AttributeList)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtCreateThreadEx);
    if (!g_OrigNtCreateThreadEx) return STATUS_UNSUCCESSFUL;

    /* ================================================================
     * CE 在升权目标中创建线程 (DbgUiIssueRemoteBreakin 注入断点线程)
     *
     * 问题: CE 调 DebugActiveProcess → 内部最后一步 DbgUiIssueRemoteBreakin
     *       → NtCreateThreadEx(gameHandle, ...) → 内部 ObpRef 解析 handle
     *       → ACE 剥了句柄权限 + ObpRef trampoline 不稳定 → error 5
     *
     * 方案: 不依赖 ObpRef trampoline,
     *       创建 OBJ_KERNEL_HANDLE + 临时切 PreviousMode=KernelMode
     *       完全绕过句柄权限检查和 ACE 回调
     *
     * KTHREAD.PreviousMode offset:
     *   Win10 19041-19045 (20H1-22H2): 0x232
     * ================================================================ */
    if (IsCallerProtected() && g_ElevatedPidCount > 0 &&
        ProcessHandle && ProcessHandle != NtCurrentProcess())
    {
        PEPROCESS targetProc = NULL;
        /* 用导出函数解析句柄, 不走 trampoline */
        NTSTATUS st = ObReferenceObjectByHandle(
            ProcessHandle, 0, *PsProcessType, KernelMode,
            (PVOID*)&targetProc, NULL);

        if (NT_SUCCESS(st) && targetProc) {
            if (IsElevatedPid(PsGetProcessId(targetProc))) {
                /* 创建 kernel handle — ACE 的 ObCallback 跳过 */
                HANDLE kHandle = NULL;
                st = ObOpenObjectByPointer(
                    targetProc, OBJ_KERNEL_HANDLE, NULL,
                    PROCESS_ALL_ACCESS, *PsProcessType,
                    KernelMode, &kHandle);
                ObDereferenceObject(targetProc);

                if (NT_SUCCESS(st) && kHandle) {
                    /* 临时切 PreviousMode = KernelMode, 让 kernel handle 可用
                     * 同时跳过内部所有安全检查 */
                    PUCHAR kthread = (PUCHAR)PsGetCurrentThread();
                    CCHAR savedMode = *(CCHAR*)(kthread + 0x232);
                    *(CCHAR*)(kthread + 0x232) = KernelMode;

                    st = g_OrigNtCreateThreadEx(
                        ThreadHandle, DesiredAccess, ObjectAttributes,
                        kHandle, StartRoutine, Argument,
                        CreateFlags, ZeroBits, StackSize, MaximumStackSize,
                        AttributeList);

                    /* 恢复 PreviousMode */
                    *(CCHAR*)(kthread + 0x232) = savedMode;
                    ZwClose(kHandle);

                    SvmDebugPrint("[Elevate] NtCreateThreadEx: CE thread in elevated PID, status=0x%X\n", st);
                    return st;
                }
                /* ObOpenObjectByPointer 失败, 回退正常路径 */
            }
            else {
                ObDereferenceObject(targetProc);
            }
        }
    }

    if (g_ProtectedPidCount > 0 &&
        IsProtectedProcessHandle(ProcessHandle) && !IsCallerProtected())
        return STATUS_ACCESS_DENIED;

    return g_OrigNtCreateThreadEx(
        ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
        StartRoutine, Argument, CreateFlags, ZeroBits,
        StackSize, MaximumStackSize, AttributeList);
}

/* ========================================================================
 *  线程保护 Hook (参考 EptHook demo)
 *  ACE 常用攻击路径: SuspendThread → GetContext(读DR) → ReadMemory → Resume
 * ======================================================================== */

 /**
  * @brief Hook: NtSuspendThread — 阻止挂起受保护进程的线程
  * @note ACE 先冻结目标线程再扫描内存
  */
static NTSTATUS NTAPI Fake_NtSuspendThread(
    HANDLE ThreadHandle, PULONG PreviousSuspendCount)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtSuspendThread);
    if (!g_OrigNtSuspendThread) return STATUS_UNSUCCESSFUL;
    if (g_ProtectedPidCount == 0)
        return g_OrigNtSuspendThread(ThreadHandle, PreviousSuspendCount);

    KIRQL oldIrql;
    if (!EnterHookGuard(&oldIrql))
        return g_OrigNtSuspendThread(ThreadHandle, PreviousSuspendCount);

    if (!IsCallerProtected() && IsProtectedThreadHandle(ThreadHandle)) {
        LeaveHookGuard(oldIrql);
        return STATUS_ACCESS_DENIED;
    }

    LeaveHookGuard(oldIrql);
    return g_OrigNtSuspendThread(ThreadHandle, PreviousSuspendCount);
}

/**
 * @brief Hook: NtResumeThread — 阻止外部恢复受保护线程
 */
static NTSTATUS NTAPI Fake_NtResumeThread(
    HANDLE ThreadHandle, PULONG PreviousSuspendCount)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtResumeThread);
    if (!g_OrigNtResumeThread) return STATUS_UNSUCCESSFUL;
    if (g_ProtectedPidCount == 0)
        return g_OrigNtResumeThread(ThreadHandle, PreviousSuspendCount);

    KIRQL oldIrql;
    if (!EnterHookGuard(&oldIrql))
        return g_OrigNtResumeThread(ThreadHandle, PreviousSuspendCount);

    if (!IsCallerProtected() && IsProtectedThreadHandle(ThreadHandle)) {
        LeaveHookGuard(oldIrql);
        return STATUS_ACCESS_DENIED;
    }

    LeaveHookGuard(oldIrql);
    return g_OrigNtResumeThread(ThreadHandle, PreviousSuspendCount);
}

/**
 * @brief Hook: NtGetContextThread — 隐藏受保护线程的硬件断点
 * @note 不直接拒绝, 而是擦除 DR0-DR7 后返回, ACE 看到"无硬件断点"而非"被拦截"
 */
static NTSTATUS NTAPI Fake_NtGetContextThread(
    HANDLE ThreadHandle, PCONTEXT ThreadContext)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtGetContextThread);
    if (!g_OrigNtGetContextThread) return STATUS_UNSUCCESSFUL;
    if (g_ProtectedPidCount == 0)
        return g_OrigNtGetContextThread(ThreadHandle, ThreadContext);

    KIRQL oldIrql;
    if (!EnterHookGuard(&oldIrql))
        return g_OrigNtGetContextThread(ThreadHandle, ThreadContext);

    if (!IsCallerProtected() && IsProtectedThreadHandle(ThreadHandle)) {
        LeaveHookGuard(oldIrql);
        NTSTATUS status = g_OrigNtGetContextThread(ThreadHandle, ThreadContext);
        if (NT_SUCCESS(status) && ThreadContext) {
            __try {
                if (ThreadContext->ContextFlags & CONTEXT_DEBUG_REGISTERS) {
                    ThreadContext->Dr0 = 0;
                    ThreadContext->Dr1 = 0;
                    ThreadContext->Dr2 = 0;
                    ThreadContext->Dr3 = 0;
                    ThreadContext->Dr6 = 0;
                    ThreadContext->Dr7 = 0;
                    //这里是关键我们把所有的dr清零还有ContextFlags的权限
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        return status;
    }

    LeaveHookGuard(oldIrql);
    return g_OrigNtGetContextThread(ThreadHandle, ThreadContext);
}

/**
 * @brief Hook: NtSetContextThread — 阻止修改受保护线程上下文
 * @note ACE 可能清除硬件断点或篡改 RIP 劫持执行流
 */
static NTSTATUS NTAPI Fake_NtSetContextThread(
    HANDLE ThreadHandle, PCONTEXT ThreadContext)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtSetContextThread);
    if (!g_OrigNtSetContextThread) return STATUS_UNSUCCESSFUL;
    if (g_ProtectedPidCount == 0)
        return g_OrigNtSetContextThread(ThreadHandle, ThreadContext);

    KIRQL oldIrql;
    if (!EnterHookGuard(&oldIrql))
        return g_OrigNtSetContextThread(ThreadHandle, ThreadContext);

    if (!IsCallerProtected() && IsProtectedThreadHandle(ThreadHandle)) {
        LeaveHookGuard(oldIrql);
        return STATUS_ACCESS_DENIED;
    }

    LeaveHookGuard(oldIrql);
    return g_OrigNtSetContextThread(ThreadHandle, ThreadContext);
}

/**
 * @brief [FIX] Hook: NtSetInformationThread — 拦截 ThreadHideFromDebugger
 *
 * 反作弊常用技术: 调用 NtSetInformationThread(hThread, ThreadHideFromDebugger, ...)
 * 设置 ETHREAD.HideFromDebugger = TRUE, 使该线程的调试事件 (断点/异常) 不再
 * 通过 Dbgk 路径投递。由于我们的影子调试端口依赖 Dbgk hook 接收事件,
 * ThreadHideFromDebugger 会使反作弊线程对调试器完全不可见。
 *
 * 策略: 对 ThreadHideFromDebugger (class 0x11) 直接返回 STATUS_SUCCESS,
 *        但不实际调用原函数, 使线程保持可见。
 *        反作弊认为操作成功, 但线程未被隐藏。
 */
static NTSTATUS NTAPI Fake_NtSetInformationThread(
    HANDLE ThreadHandle, ULONG ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength)
{
    if (!g_OrigNtSetInformationThread) return STATUS_UNSUCCESSFUL;

    /* 无保护 或 保护进程(CE)自身调用 → 全部透传 */
    if (g_ProtectedPidCount == 0 || IsCallerProtected())
        return g_OrigNtSetInformationThread(
            ThreadHandle, ThreadInformationClass,
            ThreadInformation, ThreadInformationLength);

    /* [FIX] 仅对调试目标进程的线程拦截, 不全局拦截 */
    if (ThreadInformationClass == 0x11 || ThreadInformationClass == 0x12)
    {
        PDEBUG_PROCESS dbgProc = NULL;
        if (IsDebugTargetProcess(PsGetCurrentProcess(), &dbgProc)) {
            /* 调试目标进程的线程 → 静默成功, 不执行
             * 防止反作弊隐藏自己的线程或设置 BreakOnTermination */
            return STATUS_SUCCESS;
        }
        /* 非调试目标(如 ACE 登录器) → 正常执行, 不干扰 */
    }

    return g_OrigNtSetInformationThread(
        ThreadHandle, ThreadInformationClass,
        ThreadInformation, ThreadInformationLength);
}

/**
 * @brief Hook: NtQueryInformationThread — 过滤受保护线程的信息查询
 * @note ThreadBasicInformation(class 0)暴露OwnerPID, class 9暴露线程入口
 */
static NTSTATUS NTAPI Fake_NtQueryInformationThread(
    HANDLE ThreadHandle, ULONG ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength,
    PULONG ReturnLength)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtQueryInformationThread);
    if (!g_OrigNtQueryInformationThread) return STATUS_UNSUCCESSFUL;
    if (g_ProtectedPidCount == 0)
        return g_OrigNtQueryInformationThread(
            ThreadHandle, ThreadInformationClass,
            ThreadInformation, ThreadInformationLength, ReturnLength);

    KIRQL oldIrql;
    if (!EnterHookGuard(&oldIrql))
        return g_OrigNtQueryInformationThread(
            ThreadHandle, ThreadInformationClass,
            ThreadInformation, ThreadInformationLength, ReturnLength);

    if (!IsCallerProtected() && IsProtectedThreadHandle(ThreadHandle)) {
        LeaveHookGuard(oldIrql);
        return STATUS_ACCESS_DENIED;
    }

    LeaveHookGuard(oldIrql);
    return g_OrigNtQueryInformationThread(
        ThreadHandle, ThreadInformationClass,
        ThreadInformation, ThreadInformationLength, ReturnLength);
}

/**
 * @brief Hook: PsLookupProcessByProcessId - 阻止外部通过PID查找受保护进程对象
 * @author yewilliam
 * @date 2026/03/16
 * @param [in]  ProcessId - 进程PID
 * @param [out] Process   - 输出PEPROCESS指针
 * @return STATUS_INVALID_PARAMETER(拒绝) 或原函数返回值
 * @note 使用per-CPU Guard防递归
 */
static NTSTATUS NTAPI Fake_PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process)
{
    FAKE_PRINT_ONCE_FOR(HOOK_PsLookupProcessByProcessId);
    if (!g_OrigPsLookupProcessByProcessId) return STATUS_UNSUCCESSFUL;
    if (g_ProtectedPidCount == 0)
        return g_OrigPsLookupProcessByProcessId(ProcessId, Process);

    KIRQL oldIrql;
    if (!EnterHookGuard(&oldIrql))
        return g_OrigPsLookupProcessByProcessId(ProcessId, Process);

    if (IsProtectedPid(ProcessId) && !IsCallerProtected()) {
        LeaveHookGuard(oldIrql);
        if (Process) *Process = NULL;
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS result = g_OrigPsLookupProcessByProcessId(ProcessId, Process);
    LeaveHookGuard(oldIrql);
    return result;
}

/**
 * @brief Hook: PsLookupThreadByThreadId - 阻止通过线程ID获取受保护进程的线程对象
 * @author yewilliam
 * @date 2026/03/16
 * @param [in]  ThreadId - 线程ID
 * @param [out] Thread   - 输出PETHREAD指针
 * @return STATUS_INVALID_PARAMETER(拒绝) 或原函数返回值
 * @note 先调用原函数再检查线程所属进程是否受保护
 */
static NTSTATUS NTAPI Fake_PsLookupThreadByThreadId(HANDLE ThreadId, PETHREAD* Thread)
{
    FAKE_PRINT_ONCE_FOR(HOOK_PsLookupThreadByThreadId);
    if (!g_OrigPsLookupThreadByThreadId) return STATUS_UNSUCCESSFUL;
    if (g_ProtectedPidCount == 0)
        return g_OrigPsLookupThreadByThreadId(ThreadId, Thread);

    KIRQL oldIrql;
    if (!EnterHookGuard(&oldIrql))
        return g_OrigPsLookupThreadByThreadId(ThreadId, Thread);

    NTSTATUS status = g_OrigPsLookupThreadByThreadId(ThreadId, Thread);
    if (NT_SUCCESS(status) && Thread && *Thread &&
        IsProtectedPid(PsGetThreadProcessId(*Thread)) && !IsCallerProtected())
    {
        ObDereferenceObject(*Thread);
        *Thread = NULL;
        LeaveHookGuard(oldIrql);
        return STATUS_INVALID_PARAMETER;
    }

    LeaveHookGuard(oldIrql);
    return status;
}

/**
 * @brief Hook: ObpReferenceObjectByHandleWithTag - 降低外部对受保护进程/线程句柄的权限
 * @author yewilliam
 * @date 2026/03/15
 *
 */
static NTSTATUS NTAPI Fake_ObpRefByHandleWithTag(
    ULONG_PTR Handle, ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode,
    ULONG Tag, PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInfo,
    ULONG_PTR Flags)
{
    FAKE_PRINT_ONCE_FOR(HOOK_ObReferenceObjectByHandle);
    if (!g_OrigObpRefByHandleWithTag) return STATUS_UNSUCCESSFUL;

    if (g_ProtectedPidCount == 0 && g_ElevatedPidCount == 0)
        return g_OrigObpRefByHandleWithTag(
            Handle, DesiredAccess, ObjectType, AccessMode,
            Tag, Object, HandleInfo, Flags);

    KIRQL oldIrql;
    if (!EnterHookGuard(&oldIrql))
        return g_OrigObpRefByHandleWithTag(
            Handle, DesiredAccess, ObjectType, AccessMode,
            Tag, Object, HandleInfo, Flags);

    /*
     * CE(受保护进程)的所有 ObpRef 调用: 无条件 DesiredAccess=0, KernelMode
     *
     * 与参考代码完全一致:
     *   return ori_ObpReferenceObjectByHandleWithTag(
     *       Handle, 0, ObjectType, KernelMode, Tag, Object, HandleInformation, WriteSize);
     *
     * 原理:
     *   DesiredAccess=0 → 绕过 (GrantedAccess & Desired) != Desired 检查
     *   KernelMode      → 绕过 UserMode 安全检查 (SeAccessCheck 等)
     *   两个必须同时改!
     *
     * 对升权目标额外设置 GrantedAccess = ALL_ACCESS,
     * 让 CE 获取完整句柄权限 (读写内存/挂起线程/调试附加)
     */
    if (IsCallerProtected()) {
        NTSTATUS status = g_OrigObpRefByHandleWithTag(
            Handle, 0, ObjectType, KernelMode, Tag, Object, HandleInfo, Flags);

        if (NT_SUCCESS(status) && Object && *Object && HandleInfo && g_ElevatedPidCount > 0) {
            __try {
                if (ObjectType == *PsProcessType) {
                    if (IsElevatedPid(PsGetProcessId((PEPROCESS)*Object)))
                        HandleInfo->GrantedAccess = PROCESS_ALL_ACCESS;
                }
                else if (ObjectType == *PsThreadType) {
                    if (IsElevatedPid(PsGetThreadProcessId((PETHREAD)*Object)))
                        HandleInfo->GrantedAccess = THREAD_ALL_ACCESS;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        LeaveHookGuard(oldIrql);
        return status;
    }

    /* [NEW] 被调试程序(ElevatedPid)自身的句柄升权
     * 等价于 demo: DesiredAccess=0, KernelMode
     * 绕过 ACE ObRegisterCallbacks 的 GrantedAccess 裁剪 */
    if (g_ElevatedPidCount > 0 && IsElevatedPid(PsGetCurrentProcessId())) {
        NTSTATUS status = g_OrigObpRefByHandleWithTag(
            Handle, 0, ObjectType, KernelMode, Tag, Object, HandleInfo, Flags);
        if (NT_SUCCESS(status) && HandleInfo) {
            __try {
                if (ObjectType == *PsProcessType)
                    HandleInfo->GrantedAccess = PROCESS_ALL_ACCESS;
                else if (ObjectType == *PsThreadType)
                    HandleInfo->GrantedAccess = THREAD_ALL_ACCESS;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        /* [DIAG] 前10次打印日志, 之后静默 (ObpRef 极高频, 不能无限打印) */
        {
            static volatile LONG s_ElevHitCount = 0;
            LONG n = InterlockedIncrement(&s_ElevHitCount);
            if (n <= 10) {
                SvmDebugPrint("[DIAG-Hide] ElevatedPid branch HIT! PID=%llu, Handle=0x%llX, status=0x%X (hit#%ld)\n",
                    (ULONG64)PsGetCurrentProcessId(), (ULONG64)Handle, status, n);
            }
        }

        LeaveHookGuard(oldIrql);
        return status;
    }

    /* 外部进程访问受保护进程 → 降权 (原有逻辑) */
    NTSTATUS status = g_OrigObpRefByHandleWithTag(
        Handle, DesiredAccess, ObjectType, AccessMode,
        Tag, Object, HandleInfo, Flags);

    if (NT_SUCCESS(status) && Object && *Object) {
        __try {
            if (ObjectType == *PsProcessType &&
                IsProtectedPid(PsGetProcessId((PEPROCESS)*Object)))
            {
                if (HandleInfo)
                    HandleInfo->GrantedAccess &=
                    ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
            }
            else if (ObjectType == *PsThreadType &&
                IsProtectedPid(PsGetThreadProcessId((PETHREAD)*Object)))
            {
                if (HandleInfo)
                    HandleInfo->GrantedAccess &=
                    ~(THREAD_SUSPEND_RESUME | THREAD_TERMINATE |
                        THREAD_GET_CONTEXT | THREAD_SET_CONTEXT);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    LeaveHookGuard(oldIrql);
    return status;
}


/**
 * @brief Hook: MmCopyVirtualMemory - 阻止通过内核内存拷贝读写受保护进程
 * @author yewilliam
 * @date 2026/03/16
 * @param [in]  FromProcess          - 源进程
 * @param [in]  FromAddress          - 源地址
 * @param [in]  ToProcess            - 目标进程
 * @param [in]  ToAddress            - 目标地址
 * @param [in]  BufferSize           - 拷贝大小
 * @param [in]  PreviousMode         - 之前模式
 * @param [out] NumberOfBytesCopied  - 实际拷贝字节数
 * @return STATUS_ACCESS_DENIED 或原函数返回值
 * @note 先释放Guard再调用原函数, 因MmCopyVirtualMemory可能触发缺页需<=APC_LEVEL
 */
static NTSTATUS NTAPI Fake_MmCopyVirtualMemory(
    PEPROCESS FromProcess, PVOID FromAddress,
    PEPROCESS ToProcess, PVOID ToAddress,
    SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
    PSIZE_T NumberOfBytesCopied)
{
    FAKE_PRINT_ONCE_FOR(HOOK_MmCopyVirtualMemory);
    if (!g_OrigMmCopyVirtualMemory) return STATUS_UNSUCCESSFUL;

    /* [DIAG-v24] 只计数 CE 调用, 系统进程不消耗配额 */
    BOOLEAN mmIsCE = (g_ProtectedPidCount > 0) && IsCallerProtected();
    BOOLEAN doLog = mmIsCE && DiagShouldLog_CE(&s_diag_MmCVM);
    LONG seq = s_diag_MmCVM;

    if (g_ProtectedPidCount == 0) {
        /* [DIAG] 如果保护曾经激活过又变成0, 说明 CLEAR_ALL 发生了 */
        static volatile LONG s_earlyExit = 0;
        LONG n = InterlockedIncrement(&s_earlyExit);
        if (n <= 5)
            SvmDebugPrint("[MmCVM] EARLY-EXIT #%d: g_ProtectedPidCount==0! (保护已清除?)\n", n);
        return g_OrigMmCopyVirtualMemory(
            FromProcess, FromAddress, ToProcess, ToAddress,
            BufferSize, PreviousMode, NumberOfBytesCopied);
    }

    KIRQL oldIrql;
    if (!EnterHookGuard(&oldIrql)) {
        /* [DIAG-v24] Guard 失败也要记录 CE 的调用 */
        if (mmIsCE) {
            static volatile LONG s_guardFail = 0;
            LONG gf = InterlockedIncrement(&s_guardFail);
            if (gf <= 20 || (gf % 1000) == 0)
                SvmDebugPrint("[MmCVM] GUARD-FAIL #%d: CE call bypassed guard!\n", gf);
        }
        return g_OrigMmCopyVirtualMemory(
            FromProcess, FromAddress, ToProcess, ToAddress,
            BufferSize, PreviousMode, NumberOfBytesCopied);
    }

    if (IsCallerProtected()) {
        LeaveHookGuard(oldIrql);
        NTSTATUS st = g_OrigMmCopyVirtualMemory(
            FromProcess, FromAddress, ToProcess, ToAddress,
            BufferSize, PreviousMode, NumberOfBytesCopied);
        /* [DIAG-v24] CE-PASS 摘要 */
        {
            static volatile LONG s_ceMmTotal = 0;
            LONG mt = InterlockedIncrement(&s_ceMmTotal);
            if (mt <= 50 || (mt % 1000) == 0)
                SvmDebugPrint("[MmCVM-SUM] CE-PASS #%d: from=%p sz=%llu st=0x%X\n",
                    mt, FromAddress, (ULONG64)BufferSize, st);
        }
        return st;
    }

    /* [NEW] ElevatedPid 调用者直接放行 */
    if (g_ElevatedPidCount > 0 && IsElevatedPid(PsGetCurrentProcessId())) {
        LeaveHookGuard(oldIrql);
        return g_OrigMmCopyVirtualMemory(
            FromProcess, FromAddress, ToProcess, ToAddress,
            BufferSize, PreviousMode, NumberOfBytesCopied);
    }

    BOOLEAN touchesProtected =
        (FromProcess && IsProtectedPid(PsGetProcessId(FromProcess))) ||
        (ToProcess && IsProtectedPid(PsGetProcessId(ToProcess)));

    LeaveHookGuard(oldIrql);

    if (touchesProtected) {
        if (doLog)
            SvmDebugPrint("[MmCVM] #%d BLOCKED: fromPid=%llu toPid=%llu caller=%llu\n",
                seq,
                (ULONG64)(FromProcess ? PsGetProcessId(FromProcess) : 0),
                (ULONG64)(ToProcess ? PsGetProcessId(ToProcess) : 0),
                (ULONG64)PsGetCurrentProcessId());
        if (NumberOfBytesCopied) *NumberOfBytesCopied = 0;
        return STATUS_ACCESS_VIOLATION;
    }

    return g_OrigMmCopyVirtualMemory(
        FromProcess, FromAddress, ToProcess, ToAddress,
        BufferSize, PreviousMode, NumberOfBytesCopied);
}

/**
 * @brief Hook: KeStackAttachProcess - 当前版本直接透传, 不再重定向
 * @author yewilliam
 * @date 2026/03/16
 * @param [in]  Process  - 目标进程EPROCESS
 * @param [out] ApcState - APC状态保存结构
 * @note 早期版本将attach重定向到System进程导致BSOD,直接透传
 */
static VOID NTAPI Fake_KeStackAttachProcess(PEPROCESS Process, PKAPC_STATE ApcState)
{
    if (!g_OrigKeStackAttachProcess) return;
    g_OrigKeStackAttachProcess(Process, ApcState);
}

/**
 * @brief Hook: ValidateHwnd - 对外部进程隐藏受保护进程的窗口对象
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] hwnd - 窗口句柄
 * @return 窗口对象指针(PVOID), 受保护窗口对外返回NULL
 * @note 通过pwnd->pti->pEThread获取窗口所属进程, 白名单进程始终放行
 */
static PVOID NTAPI Fake_ValidateHwnd(SVM_HWND hwnd)
{
    FAKE_PRINT_ONCE_FOR(HOOK_ValidateHwnd);
    if (!g_OrigValidateHwnd) return NULL;

    PVOID pwnd = g_OrigValidateHwnd(hwnd);
    if (!pwnd) return NULL;

    // 无保护目标 → 放行
    if (g_ProtectedPidCount == 0) return pwnd;

    // 被保护进程自身访问 → 放行
    if (IsCallerProtected()) return pwnd;

    // 系统白名单进程 → 放行（csrss/dwm/explorer 必须能访问所有窗口）
    if (IsWhitelistedCaller()) return pwnd;

    // 判断窗口所属进程：pwnd+0x10 → pti, pti+0x00 → pEThread
    __try {
        PSVM_WND wnd = (PSVM_WND)pwnd;
        PSVM_W32THREAD pti = wnd->pti;
        if (pti && pti->pEThread) {
            PEPROCESS ownerProcess = PsGetThreadProcess(pti->pEThread);
            if (ownerProcess) {
                HANDLE ownerPid = PsGetProcessId(ownerProcess);
                if (IsProtectedPid(ownerPid)) {
                    return NULL;  // 外部进程看不到这个窗口
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return pwnd;
}

/**
 * @brief Hook: NtUserFindWindowEx - 在窗口查找中跳过受保护进程的窗口
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] hwndParent     - 父窗口句柄
 * @param [in] hwndChildAfter - 子窗口起点
 * @param [in] lpszClass      - 窗口类名
 * @param [in] lpszWindow     - 窗口标题
 * @param [in] dwType         - 查找类型
 * @return 找到的非保护窗口句柄, 未找到返回NULL
 * @note 循环跳过属于受保护进程的窗口直到找到非保护窗口
 */
static SVM_HWND NTAPI Fake_NtUserFindWindowEx(
    SVM_HWND hwndParent, SVM_HWND hwndChildAfter,
    PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, ULONG dwType)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtUserFindWindowEx);
    if (!g_OrigNtUserFindWindowEx) return NULL;

    SVM_HWND result = g_OrigNtUserFindWindowEx(
        hwndParent, hwndChildAfter, lpszClass, lpszWindow, dwType);

    if (!result || g_ProtectedPidCount == 0 || IsCallerProtected() || IsWhitelistedCaller())
        return result;

    // 如果找到的窗口属于受保护进程，跳过并继续查找
    while (result && IsWindowOwnedByProtectedProcess(result)) {
        result = g_OrigNtUserFindWindowEx(
            hwndParent, result, lpszClass, lpszWindow, dwType);
    }
    return result;
}

/**
 * @brief Hook: NtUserWindowFromPoint - 屏蔽受保护进程窗口的坐标点查找
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] x - 屏幕X坐标
 * @param [in] y - 屏幕Y坐标
 * @return 窗口句柄, 受保护窗口返回NULL
 */
static SVM_HWND NTAPI Fake_NtUserWindowFromPoint(LONG x, LONG y)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtUserWindowFromPoint);
    if (!g_OrigNtUserWindowFromPoint) return NULL;

    SVM_HWND result = g_OrigNtUserWindowFromPoint(x, y);

    if (!result || g_ProtectedPidCount == 0 || IsCallerProtected() || IsWhitelistedCaller())
        return result;

    return IsWindowOwnedByProtectedProcess(result) ? NULL : result;
}

// ---- ASM 入口回调（保持兼容）----
extern "C" BOOLEAN Cpp_Fake_NtUserBuildHwndList(PREGISTER_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
    return TRUE;
}

/**
 * @brief Hook: NtUserBuildHwndList - 从窗口枚举列表中移除受保护进程的窗口
 * @author yewilliam
 * @date 2026/03/16
 * @param [in]     hDesktop         - 桌面句柄
 * @param [in]     hwndNext         - 起始窗口
 * @param [in]     fEnumChildren    - 是否枚举子窗口
 * @param [in]     bRemoveImmersive - 移除沉浸式窗口
 * @param [in]     idThread         - 线程ID过滤
 * @param [in]     cHwndMax         - 最大窗口数
 * @param [in,out] phwndFirst       - 窗口句柄数组
 * @param [in,out] pcHwndNeeded     - 窗口计数
 * @return NTSTATUS - 透传原函数返回值
 * @note 遍历phwndFirst数组, 按窗口所属进程过滤后压缩数组并更新计数
 */
static NTSTATUS NTAPI Fake_NtUserBuildHwndList(
    HANDLE hDesktop, SVM_HWND hwndNext, ULONG fEnumChildren,
    ULONG bRemoveImmersive, ULONG idThread,
    ULONG cHwndMax, SVM_HWND* phwndFirst, ULONG* pcHwndNeeded)
{
    FAKE_PRINT_ONCE_FOR(HOOK_NtUserBuildHwndList);
    if (!g_OrigNtUserBuildHwndList) return STATUS_UNSUCCESSFUL;

    NTSTATUS status = g_OrigNtUserBuildHwndList(
        hDesktop, hwndNext, fEnumChildren, bRemoveImmersive,
        idThread, cHwndMax, phwndFirst, pcHwndNeeded);

    if (!NT_SUCCESS(status) || !phwndFirst || !pcHwndNeeded)
        return status;
    if (g_ProtectedPidCount == 0 || IsCallerProtected() || IsWhitelistedCaller())
        return status;

    __try {
        ULONG count = *pcHwndNeeded;
        if (count > cHwndMax) count = cHwndMax;

        // 按窗口所属进程过滤
        ULONG validCount = 0;
        for (ULONG i = 0; i < count; i++) {
            if (!IsWindowOwnedByProtectedProcess(phwndFirst[i])) {
                if (validCount != i)
                    phwndFirst[validCount] = phwndFirst[i];
                validCount++;
            }
        }

        for (ULONG i = validCount; i < count; i++)
            phwndFirst[i] = NULL;

        *pcHwndNeeded = validCount;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return status;
}


/* ========================================================================
 *  Trampoline 全局变量 / 初始化 / 链接
 * ======================================================================== */
extern "C" ULONG64 g_Trampoline_NtUserBuildHwndList = 0;

/**
 * @brief 初始化进程隐藏Hook系统 - 解析SSSDT和进程创建回调
 * @author yewilliam
 * @date 2026/03/16
 * @return 始终返回STATUS_SUCCESS
 */
NTSTATUS InitializeProcessHideHooks()
{
    SvmDebugPrint("[Hide] InitializeProcessHideHooks\n");
    RtlZeroMemory((PVOID)g_Guard, sizeof(g_Guard));
    InitNotifyRoutineResolver();
    NTSTATUS status = InitSssdtResolver();
    if (!NT_SUCCESS(status))
        SvmDebugPrint("[Hide] SSSDT failed (0x%X)\n", status);
    return STATUS_SUCCESS;
}

/**
 * @brief 链接Trampoline地址到原函数指针 - 填充所有g_Orig*函数指针
 * @author yewilliam
 * @date 2026/03/16
 * @note 遍历g_HookList, 将TrampolinePage地址赋给对应的原函数指针
 */
VOID LinkTrampolineAddresses()
{
#define LH(i, p, t) \
    if (g_HookList[i].IsUsed && g_HookList[i].TrampolinePage) \
        p = (t)g_HookList[i].TrampolinePage;

    LH(HOOK_NtQuerySystemInformation, g_OrigNtQuerySystemInformation, FnNtQuerySystemInformation);
    LH(HOOK_NtOpenProcess, g_OrigNtOpenProcess, FnNtOpenProcess);
    LH(HOOK_NtQueryInformationProcess, g_OrigNtQueryInformationProcess, FnNtQueryInformationProcess);
    LH(HOOK_NtQueryVirtualMemory, g_OrigNtQueryVirtualMemory, FnNtQueryVirtualMemory);
    LH(HOOK_NtDuplicateObject, g_OrigNtDuplicateObject, FnNtDuplicateObject);
    LH(HOOK_NtGetNextProcess, g_OrigNtGetNextProcess, FnNtGetNextProcess);
    LH(HOOK_NtGetNextThread, g_OrigNtGetNextThread, FnNtGetNextThread);
    LH(HOOK_NtReadVirtualMemory, g_OrigNtReadVirtualMemory, FnNtReadVirtualMemory);
    LH(HOOK_NtWriteVirtualMemory, g_OrigNtWriteVirtualMemory, FnNtWriteVirtualMemory);
    LH(HOOK_NtProtectVirtualMemory, g_OrigNtProtectVirtualMemory, FnNtProtectVirtualMemory);
    LH(HOOK_NtTerminateProcess, g_OrigNtTerminateProcess, FnNtTerminateProcess);
    LH(HOOK_NtCreateThreadEx, g_OrigNtCreateThreadEx, FnNtCreateThreadEx);
    LH(HOOK_NtSuspendThread, g_OrigNtSuspendThread, FnNtSuspendThread);
    LH(HOOK_NtResumeThread, g_OrigNtResumeThread, FnNtResumeThread);
    LH(HOOK_NtGetContextThread, g_OrigNtGetContextThread, FnNtGetContextThread);
    LH(HOOK_NtSetContextThread, g_OrigNtSetContextThread, FnNtSetContextThread);
    LH(HOOK_NtQueryInformationThread, g_OrigNtQueryInformationThread, FnNtQueryInformationThread);
    LH(HOOK_PsLookupProcessByProcessId, g_OrigPsLookupProcessByProcessId, FnPsLookupProcessByProcessId);
    LH(HOOK_PsLookupThreadByThreadId, g_OrigPsLookupThreadByThreadId, FnPsLookupThreadByThreadId);
    LH(HOOK_ObReferenceObjectByHandle, g_OrigObpRefByHandleWithTag, FnObpRefByHandleWithTag);
    LH(HOOK_MmCopyVirtualMemory, g_OrigMmCopyVirtualMemory, FnMmCopyVirtualMemory);
    LH(HOOK_KeStackAttachProcess, g_OrigKeStackAttachProcess, FnKeStackAttachProcess);
    LH(HOOK_NtUserFindWindowEx, g_OrigNtUserFindWindowEx, FnNtUserFindWindowEx);
    LH(HOOK_NtUserWindowFromPoint, g_OrigNtUserWindowFromPoint, FnNtUserWindowFromPoint);
    LH(HOOK_NtUserBuildHwndList, g_OrigNtUserBuildHwndList, FnNtUserBuildHwndList);
    LH(HOOK_ValidateHwnd, g_OrigValidateHwnd, FnValidateHwnd);

    /* [FIX] 新增 NtSetInformationThread trampoline */
    LH(HOOK_NtSetInformationThread, g_OrigNtSetInformationThread, FnNtSetInformationThread);

    if (g_HookList[HOOK_NtUserBuildHwndList].IsUsed && g_HookList[HOOK_NtUserBuildHwndList].TrampolinePage)
        g_Trampoline_NtUserBuildHwndList = (ULONG64)g_HookList[HOOK_NtUserBuildHwndList].TrampolinePage;
#undef LH
}

/**
 * @brief 准备所有NPT Hook资源 - 两阶段解析(普通函数 + CSRSS上下文中的Win32k函数)
 * @author yewilliam
 * @date 2026/03/16
 * @return 至少1个Hook就绪返回STATUS_SUCCESS
 * @note Pass1: SSDT/ntdll/内核导出; Pass2: 在CSRSS上下文中解析SSSDT和win32kbase
 */
NTSTATUS PrepareAllNptHookResources()
{
    NTSTATUS status;
    PVOID pTarget = NULL;

    enum ResolveMethod { RESOLVE_SSDT, RESOLVE_NTDLL, RESOLVE_EXPORT, RESOLVE_SSSDT, RESOLVE_WIN32KBASE, RESOLVE_SCAN_OBP };

    struct HookDef {
        PCWSTR ZwName; PCSTR NtdllName; PVOID Proxy;
        HOOK_INDEX Index; BOOLEAN Required; ResolveMethod Method; ULONG SssdtIdx;
    };

    const ULONG SI_FindWnd = GetSssdtIndexDynamic("NtUserFindWindowEx");
    const ULONG SI_WndPoint = GetSssdtIndexDynamic("NtUserWindowFromPoint");
    const ULONG SI_BuildHwnd = GetSssdtIndexDynamic("NtUserBuildHwndList");

    HookDef hooks[] = {
        // SSDT (Zw 导出)
        { L"ZwQuerySystemInformation",  NULL, (PVOID)Fake_NtQuerySystemInformation,  HOOK_NtQuerySystemInformation, TRUE,  RESOLVE_SSDT, 0 },
        { L"ZwOpenProcess",             NULL, (PVOID)Fake_NtOpenProcess,             HOOK_NtOpenProcess,            TRUE,  RESOLVE_SSDT, 0 },
        { L"ZwQueryInformationProcess", NULL, (PVOID)Fake_NtQueryInformationProcess, HOOK_NtQueryInformationProcess,TRUE,  RESOLVE_SSDT, 0 },
        { L"ZwDuplicateObject",         NULL, (PVOID)Fake_NtDuplicateObject,         HOOK_NtDuplicateObject,        TRUE,  RESOLVE_SSDT, 0 },
        { L"ZwQueryVirtualMemory",      NULL, (PVOID)Fake_NtQueryVirtualMemory,      HOOK_NtQueryVirtualMemory,     FALSE, RESOLVE_SSDT, 0 },
        { L"ZwGetNextProcess",          NULL, (PVOID)Fake_NtGetNextProcess,          HOOK_NtGetNextProcess,         FALSE, RESOLVE_SSDT, 0 },
        { L"ZwGetNextThread",           NULL, (PVOID)Fake_NtGetNextThread,           HOOK_NtGetNextThread,          FALSE, RESOLVE_SSDT, 0 },
        { L"ZwProtectVirtualMemory",    NULL, (PVOID)Fake_NtProtectVirtualMemory,    HOOK_NtProtectVirtualMemory,   FALSE, RESOLVE_SSDT, 0 },
        { L"ZwTerminateProcess",        NULL, (PVOID)Fake_NtTerminateProcess,        HOOK_NtTerminateProcess,       FALSE, RESOLVE_SSDT, 0 },
        // NTDLL 映射
        { NULL, "NtReadVirtualMemory",  (PVOID)Fake_NtReadVirtualMemory,  HOOK_NtReadVirtualMemory,  FALSE, RESOLVE_NTDLL, 0 },
        { NULL, "NtWriteVirtualMemory", (PVOID)Fake_NtWriteVirtualMemory, HOOK_NtWriteVirtualMemory, FALSE, RESOLVE_NTDLL, 0 },
        { NULL, "NtCreateThreadEx",     (PVOID)Fake_NtCreateThreadEx,     HOOK_NtCreateThreadEx,     FALSE, RESOLVE_NTDLL, 0 },
        // 线程保护 (参考 EptHook demo)
        { NULL, "NtSuspendThread",          (PVOID)Fake_NtSuspendThread,          HOOK_NtSuspendThread,          FALSE, RESOLVE_NTDLL, 0 },
        { NULL, "NtResumeThread",           (PVOID)Fake_NtResumeThread,           HOOK_NtResumeThread,           FALSE, RESOLVE_NTDLL, 0 },
        { NULL, "NtGetContextThread",       (PVOID)Fake_NtGetContextThread,       HOOK_NtGetContextThread,       FALSE, RESOLVE_NTDLL, 0 },
        { NULL, "NtSetContextThread",       (PVOID)Fake_NtSetContextThread,       HOOK_NtSetContextThread,       FALSE, RESOLVE_NTDLL, 0 },
        { NULL, "NtQueryInformationThread", (PVOID)Fake_NtQueryInformationThread, HOOK_NtQueryInformationThread, FALSE, RESOLVE_NTDLL, 0 },
        /* [FIX] 反调试防御: 拦截 ThreadHideFromDebugger */
        { NULL, "NtSetInformationThread",   (PVOID)Fake_NtSetInformationThread,   HOOK_NtSetInformationThread,   FALSE, RESOLVE_NTDLL, 0 },
        // 内核导出
        { L"PsLookupProcessByProcessId", NULL, (PVOID)Fake_PsLookupProcessByProcessId, HOOK_PsLookupProcessByProcessId, TRUE, RESOLVE_EXPORT, 0 },
        { L"PsLookupThreadByThreadId",   NULL, (PVOID)Fake_PsLookupThreadByThreadId,   HOOK_PsLookupThreadByThreadId,   TRUE, RESOLVE_EXPORT, 0 },
        { L"ObpReferenceObjectByHandleWithTag", NULL, (PVOID)Fake_ObpRefByHandleWithTag, HOOK_ObReferenceObjectByHandle, FALSE, RESOLVE_SCAN_OBP, 0 },
        { L"MmCopyVirtualMemory",        NULL, (PVOID)Fake_MmCopyVirtualMemory,        HOOK_MmCopyVirtualMemory,        TRUE, RESOLVE_EXPORT, 0 },
        { L"KeStackAttachProcess",       NULL, (PVOID)Fake_KeStackAttachProcess,       HOOK_KeStackAttachProcess,       FALSE, RESOLVE_EXPORT, 0 },
        // SSSDT (win32kfull)
        { L"NtUserFindWindowEx",    NULL, (PVOID)Fake_NtUserFindWindowEx,    HOOK_NtUserFindWindowEx,    FALSE, RESOLVE_SSSDT, SI_FindWnd },
        { L"NtUserWindowFromPoint", NULL, (PVOID)Fake_NtUserWindowFromPoint, HOOK_NtUserWindowFromPoint, FALSE, RESOLVE_SSSDT, SI_WndPoint },
        { L"NtUserBuildHwndList",   NULL, (PVOID)Fake_NtUserBuildHwndList,   HOOK_NtUserBuildHwndList,   FALSE, RESOLVE_SSSDT, SI_BuildHwnd },
        // win32kbase 导出（ValidateHwnd — 窗口隐藏的核心）
        { L"ValidateHwnd",          "ValidateHwnd", (PVOID)Fake_ValidateHwnd, HOOK_ValidateHwnd, FALSE, RESOLVE_WIN32KBASE, 0 },
    };

    ULONG total = ARRAYSIZE(hooks), ok = 0;

    // Pass 1: 非 SSSDT 且非 WIN32KBASE
    for (ULONG i = 0; i < total; i++) {
        if (hooks[i].Method == RESOLVE_SSSDT || hooks[i].Method == RESOLVE_WIN32KBASE) continue;
        pTarget = NULL;
        switch (hooks[i].Method) {
        case RESOLVE_SSDT:   pTarget = GetTrueSsdtAddress(hooks[i].ZwName); break;
        case RESOLVE_NTDLL:  pTarget = GetSsdtAddressByNtdllName(hooks[i].NtdllName); break;
        case RESOLVE_EXPORT: {
            UNICODE_STRING rn;
            RtlInitUnicodeString(&rn, hooks[i].ZwName);
            pTarget = MmGetSystemRoutineAddress(&rn);
            break;
        }
        case RESOLVE_SCAN_OBP: pTarget = ScanForObpReferenceObjectByHandleWithTag(); break;
        default: break;
        }
        if (!pTarget) {
            const char* nameA = hooks[i].NtdllName ? hooks[i].NtdllName : "";
            if (hooks[i].Required) {
                SvmDebugPrint("[ERROR] Required: %ws %s NOT FOUND\n",
                    hooks[i].ZwName ? hooks[i].ZwName : L"(ntdll)", nameA);
                CleanupAllNptHooks();
                return STATUS_NOT_FOUND;
            }
            SvmDebugPrint("[WARN] Optional: %ws %s not found, skipping\n",
                hooks[i].ZwName ? hooks[i].ZwName : L"(ntdll)", nameA);
            continue;
        }

        PCWSTR displayName = hooks[i].ZwName ? hooks[i].ZwName : L"(via ntdll)";
        SvmDebugPrint("[INFO] %ws %s -> %p\n", displayName,
            hooks[i].NtdllName ? hooks[i].NtdllName : "", pTarget);

        g_HookList[hooks[i].Index].IsUsed = TRUE;
        g_HookList[hooks[i].Index].TargetAddress = pTarget;
        g_HookList[hooks[i].Index].ProxyFunction = hooks[i].Proxy;

        status = PrepareNptHookResources(pTarget, hooks[i].Proxy, &g_HookList[hooks[i].Index]);
        if (!NT_SUCCESS(status)) {
            if (hooks[i].Required) { CleanupAllNptHooks(); return status; }
            g_HookList[hooks[i].Index].IsUsed = FALSE;
            continue;
        }
        ok++;
    }

    // Pass 2: SSSDT + WIN32KBASE（需在 GUI 进程上下文中）
    if (g_CsrssProcess) {
        KAPC_STATE a;
        KeStackAttachProcess(g_CsrssProcess, &a);

        // 2a: SSSDT
        for (ULONG i = 0; i < total; i++) {
            if (hooks[i].Method != RESOLVE_SSSDT) continue;
            pTarget = GetSssdtFunctionAddress(hooks[i].SssdtIdx);
            if (!pTarget) continue;
            SvmDebugPrint("[INFO] %ws -> %p (SSSDT)\n", hooks[i].ZwName, pTarget);

            g_HookList[hooks[i].Index].IsUsed = TRUE;
            g_HookList[hooks[i].Index].TargetAddress = pTarget;
            g_HookList[hooks[i].Index].ProxyFunction = hooks[i].Proxy;

            status = PrepareNptHookResources(pTarget, hooks[i].Proxy, &g_HookList[hooks[i].Index]);
            if (!NT_SUCCESS(status)) { g_HookList[hooks[i].Index].IsUsed = FALSE; continue; }
            ok++;
        }

        // 2b: WIN32KBASE 导出（ValidateHwnd）— 必须在 GUI 进程上下文
        for (ULONG i = 0; i < total; i++) {
            if (hooks[i].Method != RESOLVE_WIN32KBASE) continue;
            pTarget = FindWin32kbaseExport(hooks[i].NtdllName);  // NtdllName 字段复用存 export name
            if (!pTarget) {
                SvmDebugPrint("[WARN] win32kbase!%s not found, skipping\n", hooks[i].NtdllName);
                continue;
            }
            SvmDebugPrint("[INFO] win32kbase!%s -> %p\n", hooks[i].NtdllName, pTarget);

            g_HookList[hooks[i].Index].IsUsed = TRUE;
            g_HookList[hooks[i].Index].TargetAddress = pTarget;
            g_HookList[hooks[i].Index].ProxyFunction = hooks[i].Proxy;

            status = PrepareNptHookResources(pTarget, hooks[i].Proxy, &g_HookList[hooks[i].Index]);
            if (!NT_SUCCESS(status)) { g_HookList[hooks[i].Index].IsUsed = FALSE; continue; }
            ok++;
        }

        KeUnstackDetachProcess(&a);
    }

    SvmDebugPrint("[Phase1] %lu/%lu hooks ready\n", ok, total);
    return ok > 0 ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}


/* ========================================================================
 *  DKOM + 进程伪装 + 回调管理
 * ======================================================================== */

static LIST_ENTRY* g_SavedFlink = NULL;
static LIST_ENTRY* g_SavedBlink = NULL;
static LIST_ENTRY* g_UnlinkedEntry = NULL;
static ULONG g_ActiveProcessLinksOffset = 0;

static ULONG FindActiveProcessLinksOffset()
{
    PEPROCESS current = PsGetCurrentProcess();
    HANDLE currentPid = PsGetCurrentProcessId();
    PUCHAR base = (PUCHAR)current;

    for (ULONG offset = 0x200; offset < 0x600; offset += 8) {
        if (*(PHANDLE)(base + offset) == currentPid) {
            ULONG linksOff = offset + 8;
            PLIST_ENTRY links = (PLIST_ENTRY)(base + linksOff);
            if (links->Flink && links->Blink && links->Flink != links)
                return linksOff;
        }
    }
    return 0;
}

//NTSTATUS HideProcessByDkom(HANDLE Pid)
//{
//    if (!Pid) return STATUS_INVALID_PARAMETER;
//
//    if (!g_ActiveProcessLinksOffset) {
//        g_ActiveProcessLinksOffset = FindActiveProcessLinksOffset();
//        if (!g_ActiveProcessLinksOffset) return STATUS_NOT_FOUND;
//    }
//
//    PEPROCESS target = NULL;
//    NTSTATUS status = PsLookupProcessByProcessId(Pid, &target);
//    if (!NT_SUCCESS(status) || !target) return STATUS_NOT_FOUND;
//
//    PLIST_ENTRY links = (PLIST_ENTRY)((PUCHAR)target + g_ActiveProcessLinksOffset);
//    g_SavedFlink = links->Flink;
//    g_SavedBlink = links->Blink;
//    g_UnlinkedEntry = links;
//
//    links->Blink->Flink = links->Flink;
//    links->Flink->Blink = links->Blink;
//    links->Flink = links;
//    links->Blink = links;
//
//    ObDereferenceObject(target);
//    return STATUS_SUCCESS;
//}

VOID RestoreProcessByDkom()
{
    if (!g_UnlinkedEntry || !g_SavedFlink || !g_SavedBlink)
        return;

    g_UnlinkedEntry->Flink = g_SavedFlink;
    g_UnlinkedEntry->Blink = g_SavedBlink;
    g_SavedBlink->Flink = g_UnlinkedEntry;
    g_SavedFlink->Blink = g_UnlinkedEntry;

    g_UnlinkedEntry = NULL;
    g_SavedFlink = NULL;
    g_SavedBlink = NULL;
}

/**
 * @brief 进程伪装主函数 - 将目标进程的所有身份信息替换为源进程的信息
 * @author yewilliam
 * @date 2026/03/16
 * @param [in,out] fakeProcess - 要伪装的目标进程EPROCESS
 * @param [in]     SrcPid      - 源进程PID(通常为explorer.exe)
 * @return TRUE表示伪装成功, FALSE表示源进程查找失败或已退出
 * @note 依次执行: ImageFileName -> 全路径 -> FileObject -> Token -> PEB64参数/模块 -> PEB32参数/模块
 */
extern "C" BOOLEAN FakeProcessByPid(PEPROCESS fakeProcess, HANDLE SrcPid);

static HANDLE GetExplorerPid()
{
    PEPROCESS proc = NULL;
    for (ULONG pid = 4; pid < 65536; pid += 4) {
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
        if (NT_SUCCESS(status) && proc) {
            PUCHAR name = PsGetProcessImageFileName(proc);
            if (name && _stricmp((const char*)name, "explorer.exe") == 0) {
                HANDLE result = (HANDLE)(ULONG_PTR)pid;
                ObDereferenceObject(proc);
                return result;
            }
            ObDereferenceObject(proc);
        }
    }
    return (HANDLE)0;
}

/**
 * @brief 伪装目标进程为explorer.exe - 调用FakeProcessByPid复制进程身份信息
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] Pid - 要伪装的目标进程PID
 * @return 成功返回STATUS_SUCCESS
 */
NTSTATUS DisguiseProcess(HANDLE Pid)
{
    PEPROCESS target = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(Pid, &target);
    if (!NT_SUCCESS(status) || !target) return status;

    HANDLE explorerPid = GetExplorerPid();
    if (explorerPid)
        FakeProcessByPid(target, explorerPid);

    ObDereferenceObject(target);
    return STATUS_SUCCESS;
}

/**
 * @brief 删除驱动文件 - 清除磁盘上的驱动文件痕迹
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] DriverObject - 驱动对象指针
 * @return 成功返回STATUS_SUCCESS
 * @note 若文件被占用则清除SectionObject后重试ZwDeleteFile
 */
NTSTATUS DeleteDriverFile(PDRIVER_OBJECT DriverObject)
{
    if (!DriverObject || !DriverObject->DriverSection)
        return STATUS_INVALID_PARAMETER;

    PKLDR_DATA_TABLE_ENTRY ldrEntry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!ldrEntry->FullDllName.Buffer || !ldrEntry->FullDllName.Length)
        return STATUS_NOT_FOUND;

    UNICODE_STRING filePath = ldrEntry->FullDllName;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &filePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status = ZwOpenFile(&hFile, DELETE | SYNCHRONIZE,
        &objAttr, &iosb, FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(status)) {
        PFILE_OBJECT fileObj = NULL;
        status = ObReferenceObjectByName(&filePath,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL, 0, *IoFileObjectType, KernelMode, NULL, (PVOID*)&fileObj);

        if (NT_SUCCESS(status) && fileObj) {
            PSECTION_OBJECT_POINTERS secObj = fileObj->SectionObjectPointer;
            if (secObj) {
                secObj->ImageSectionObject = NULL;
                secObj->DataSectionObject = NULL;
            }
            ObDereferenceObject(fileObj);
            status = ZwDeleteFile(&objAttr);
        }
        return status;
    }

    FILE_DISPOSITION_INFORMATION dispInfo;
    dispInfo.DeleteFile = TRUE;
    status = ZwSetInformationFile(hFile, &iosb, &dispInfo, sizeof(dispInfo),
        FileDispositionInformation);
    ZwClose(hFile);
    return status;
}

/**
 * @brief 定位PspCreateProcessNotifyRoutine全局数组 - 通过模式扫描PsSetCreateProcessNotifyRoutine
 * @author yewilliam
 * @date 2026/03/16
 * @return PspCreateProcessNotifyRoutine数组指针, 未找到返回NULL
 */
PEX_FAST_REF FindPspCreateProcessNotifyRoutine()
{
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"PsSetCreateProcessNotifyRoutine");
    PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&routineName);
    if (!func) return NULL;

    for (int i = 0; i < 0x100; i++) {
        if (func[i] == 0x48 && func[i + 1] == 0x8D && func[i + 2] == 0x0D) {
            LONG offset = *(PLONG)(func + i + 3);
            return (PEX_FAST_REF)(func + i + 7 + offset);
        }
    }
    return NULL;
}

/**
 * @brief 初始化进程创建回调解析器
 * @author yewilliam
 * @date 2026/03/16
 * @return 成功返回STATUS_SUCCESS, 未找到返回STATUS_NOT_FOUND
 */
NTSTATUS InitNotifyRoutineResolver()
{
    g_PspCreateProcessNotifyRoutine = FindPspCreateProcessNotifyRoutine();
    return g_PspCreateProcessNotifyRoutine ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/**
 * @brief 空回调 — 替换被禁用的回调，签名兼容两种注册方式
 */
static VOID NTAPI NoopProcessNotifyCallback(PVOID a1, PVOID a2, PVOID a3)
{
    UNREFERENCED_PARAMETER(a1);
    UNREFERENCED_PARAMETER(a2);
    UNREFERENCED_PARAMETER(a3);
}

/**
 * @brief 禁用所有进程创建回调 — 安全方式
 * @note 绝不清零 EX_FAST_REF！那会破坏引用计数 → LIST_ENTRY 损坏 → BSOD 0x139
 *       正确做法：替换 EX_CALLBACK_ROUTINE_BLOCK.Function 为 Noop
 *
 */
void DisableAllProcessCallbacks()
{
    //if (!g_PspCreateProcessNotifyRoutine) return;

    //KIRQL oldIrql;
    //KeRaiseIrql(APC_LEVEL, &oldIrql);

    //for (int i = 0; i < MAX_CALLBACKS; i++) {
    //    ULONG_PTR val = g_PspCreateProcessNotifyRoutine[i].Value;
    //    if (val == 0) {
    //        g_SavedCallbacks[i] = NULL;
    //        continue;
    //    }

    //    PEX_CALLBACK_ROUTINE_BLOCK block =
    //        (PEX_CALLBACK_ROUTINE_BLOCK)(val & ~(ULONG_PTR)0xF);

    //    if (!MmIsAddressValid(block) || !MmIsAddressValid(&block->Function)) {
    //        g_SavedCallbacks[i] = NULL;
    //        continue;
    //    }

    //    g_SavedCallbacks[i] = block->Function;
    //    InterlockedExchangePointer(&block->Function, (PVOID)NoopProcessNotifyCallback);
    //}

    //KeLowerIrql(oldIrql);

    ///* Drain: 等待所有正在执行中的回调安全返回 */
    //LARGE_INTEGER drainDelay;
    //drainDelay.QuadPart = -30000000LL; // 3 秒
    //KeDelayExecutionThread(KernelMode, FALSE, &drainDelay);
    SvmDebugPrint("[INFO] DisableAllProcessCallbacks: SKIPPED (NPT hooks provide full coverage)\n");
}

/**
 * @brief 恢复所有进程创建回调
 */
void RestoreAllProcessCallbacks()
{
    //if (!g_PspCreateProcessNotifyRoutine) return;

    //KIRQL oldIrql;
    //KeRaiseIrql(APC_LEVEL, &oldIrql);

    //for (int i = 0; i < MAX_CALLBACKS; i++) {
    //    if (!g_SavedCallbacks[i]) continue;

    //    ULONG_PTR val = g_PspCreateProcessNotifyRoutine[i].Value;
    //    if (val == 0) { g_SavedCallbacks[i] = NULL; continue; }

    //    PEX_CALLBACK_ROUTINE_BLOCK block =
    //        (PEX_CALLBACK_ROUTINE_BLOCK)(val & ~(ULONG_PTR)0xF);

    //    if (MmIsAddressValid(block) && MmIsAddressValid(&block->Function))
    //        InterlockedExchangePointer(&block->Function, g_SavedCallbacks[i]);

    //    g_SavedCallbacks[i] = NULL;
    //}

    //KeLowerIrql(oldIrql);
    SvmDebugPrint("[INFO] RestoreAllProcessCallbacks: SKIPPED (nothing to restore)\n");
}