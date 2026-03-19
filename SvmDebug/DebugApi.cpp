/**
 * @file DebugApi.cpp
 * @brief SVM受保护调试器实现 - 调试对象管理、事件队列、断点控制、NPT Fake函数
 * @author yewilliam
 * @date 2026/03/17
 *
 * 核心架构:
 *   Guest (R3调试器) -> IOCTL -> Guest (R0驱动) -> CPUID超级调用 -> VMM (VMEXIT handler)
 *   调试事件: 系统Dbgk* -> NPT Hook -> Fake_Dbgk* -> 影子DebugPort -> 自定义事件队列
 *
 * 对ACE等反作弊系统完全透明:
 *   - EPROCESS.DebugPort 始终为NULL
 *   - PEB.BeingDebugged 始终为0
 *   - 所有调试API被NPT Hook拦截, 走自定义路径
 *   - DR0-DR3通过VMM设置, 用户态无法读取
 *   - INT3通过NPT Execute/Read分离, 内存校验不可见
 */

#include "DebugApi.h"
#include "SVM.h"
#include "HvMemory.h"

 /* ========================================================================
  *  全局变量定义
  * ======================================================================== */

FAST_MUTEX g_DbgkpProcessDebugPortMutex;
LIST_ENTRY g_DebugProcessListHead;
FAST_MUTEX g_DebugProcessListMutex;
LIST_ENTRY g_DebuggerListHead;
FAST_MUTEX g_DebuggerListMutex;

PHV_DEBUG_CONTEXT g_HvDebugContext = nullptr;
ULONG64 g_HvDebugContextPa = 0;
FAST_MUTEX g_HvDebugMutex;

/* NPT 隐形断点全局表 */
NPT_BREAKPOINT g_NptBreakpoints[MAX_NPT_BREAKPOINTS] = { 0 };
volatile LONG  g_NptBreakpointCount = 0;

/* Dynamic-resolved NT internals */
FnPsGetNextProcess  g_pfnPsGetNextProcess = NULL;

/* Pool-based handle table */
PDEBUG_OBJECT g_DbgHandleTable[DBG_MAX_HANDLES] = { 0 };
FAST_MUTEX    g_DbgHandleTableMutex;

/* 原函数指针 (由LinkDebugTrampolineAddresses填充) — 当前版本通过影子链表
   绕过原函数, 部分场景需要回调原函数时使用 */
typedef NTSTATUS(NTAPI* FnNtCreateDebugObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS(NTAPI* FnNtDebugActiveProcess)(HANDLE, HANDLE);
typedef NTSTATUS(NTAPI* FnNtWaitForDebugEvent)(HANDLE, BOOLEAN, PLARGE_INTEGER, PDBGUI_WAIT_STATE_CHANGE);
typedef NTSTATUS(NTAPI* FnNtDebugContinue)(HANDLE, PCLIENT_ID, NTSTATUS);
typedef NTSTATUS(NTAPI* FnNtRemoveProcessDebug)(HANDLE, HANDLE);
typedef BOOLEAN(NTAPI* FnDbgkForwardException)(PEXCEPTION_RECORD, BOOLEAN, BOOLEAN);
typedef VOID(NTAPI* FnDbgkCreateThread)(PETHREAD);
typedef VOID(NTAPI* FnDbgkExitThread)(NTSTATUS);
typedef VOID(NTAPI* FnDbgkExitProcess)(NTSTATUS);
typedef VOID(NTAPI* FnDbgkMapViewOfSection)(PEPROCESS, PVOID, PVOID, ULONG, ULONG_PTR);
typedef VOID(NTAPI* FnDbgkUnMapViewOfSection)(PEPROCESS, PVOID);
typedef NTSTATUS(NTAPI* FnDbgkpQueueMessage)(PEPROCESS, PETHREAD, PDBGKM_APIMSG, ULONG, PDEBUG_OBJECT);

static FnNtCreateDebugObject     g_OrigNtCreateDebugObject = NULL;
static FnNtDebugActiveProcess    g_OrigNtDebugActiveProcess = NULL;
static FnNtWaitForDebugEvent     g_OrigNtWaitForDebugEvent = NULL;
static FnNtDebugContinue         g_OrigNtDebugContinue = NULL;
static FnNtRemoveProcessDebug    g_OrigNtRemoveProcessDebug = NULL;
static FnDbgkForwardException    g_OrigDbgkForwardException = NULL;
static FnDbgkCreateThread        g_OrigDbgkCreateThread = NULL;
static FnDbgkExitThread          g_OrigDbgkExitThread = NULL;
static FnDbgkExitProcess         g_OrigDbgkExitProcess = NULL;
static FnDbgkMapViewOfSection    g_OrigDbgkMapViewOfSection = NULL;
static FnDbgkUnMapViewOfSection  g_OrigDbgkUnMapViewOfSection = NULL;
static FnDbgkpQueueMessage       g_OrigDbgkpQueueMessage = NULL;

/* Debug print-once macro for DebugApi Fake functions */
static volatile LONG g_DbgFakePrintFlags[HOOK_MAX_COUNT] = { 0 };
#if DEBUG
#define DBG_FAKE_PRINT_ONCE(hookIdx, name) \
    if (InterlockedCompareExchange(&g_DbgFakePrintFlags[hookIdx], 1, 0) == 0) \
        SvmDebugPrint("[DebugApi] " name " called\n")
#else
#define DBG_FAKE_PRINT_ONCE(hookIdx, name)
#endif



/* ========================================================================
 *  Section 1: 初始化 / 卸载
 * ======================================================================== */

 /**
  * @brief 按名称查找已注册的对象类型 (用于类型名冲突时复用)
  */
  /* Pool-based Debug Object + Handle Table */
PDEBUG_OBJECT DbgAllocateDebugObject() {
    PDEBUG_OBJECT obj = (PDEBUG_OBJECT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(DEBUG_OBJECT), 'DbgO');
    if (!obj) return NULL;
    RtlZeroMemory(obj, sizeof(DEBUG_OBJECT));
    ExInitializeFastMutex(&obj->Mutex);
    InitializeListHead(&obj->EventList);
    KeInitializeEvent(&obj->EventsPresent, NotificationEvent, FALSE);
    return obj;
}
VOID DbgFreeDebugObject(PDEBUG_OBJECT Obj) { if (Obj) ExFreePoolWithTag(Obj, 'DbgO'); }
HANDLE DbgInsertHandle(PDEBUG_OBJECT Obj) {
    if (!Obj) return NULL;
    ExAcquireFastMutex(&g_DbgHandleTableMutex);
    for (ULONG i = 0; i < DBG_MAX_HANDLES; i++) {
        if (!g_DbgHandleTable[i]) { g_DbgHandleTable[i] = Obj; ExReleaseFastMutex(&g_DbgHandleTableMutex); return DBG_INDEX_TO_HANDLE(i); }
    }
    ExReleaseFastMutex(&g_DbgHandleTableMutex); return NULL;
}
PDEBUG_OBJECT DbgLookupHandle(HANDLE h) {
    if (!DBG_IS_VALID_HANDLE(h)) return NULL;
    ULONG i = DBG_HANDLE_TO_INDEX(h); return (i < DBG_MAX_HANDLES) ? g_DbgHandleTable[i] : NULL;
}
VOID DbgRemoveHandle(HANDLE h) {
    if (!DBG_IS_VALID_HANDLE(h)) return;
    ULONG i = DBG_HANDLE_TO_INDEX(h); if (i >= DBG_MAX_HANDLES) return;
    ExAcquireFastMutex(&g_DbgHandleTableMutex); g_DbgHandleTable[i] = NULL; ExReleaseFastMutex(&g_DbgHandleTableMutex);
}

/**
 * @brief 初始化调试子系统
 */
NTSTATUS DbgInitialize()
{
    NTSTATUS Status = STATUS_SUCCESS;

    /* 初始化互斥锁和链表 */
    /* Resolve undocumented NT internals via MmGetSystemRoutineAddress */
    {
        UNICODE_STRING name;

        RtlInitUnicodeString(&name, L"PsGetNextProcess");
        g_pfnPsGetNextProcess = (FnPsGetNextProcess)MmGetSystemRoutineAddress(&name);

        /* PsGetNextProcess only needed for CloseObject process scan */
        if (!g_pfnPsGetNextProcess) {
            SvmDebugPrint("[DebugApi] INFO: PsGetNextProcess not found (non-fatal)\n");
        }
    }

    ExInitializeFastMutex(&g_DbgkpProcessDebugPortMutex);
    ExInitializeFastMutex(&g_DebugProcessListMutex);
    ExInitializeFastMutex(&g_DebuggerListMutex);
    InitializeListHead(&g_DebugProcessListHead);
    InitializeListHead(&g_DebuggerListHead);

    /* 创建自定义调试对象类型 "Hvm_DebugObject" */
    ExInitializeFastMutex(&g_DbgHandleTableMutex);
    RtlZeroMemory(g_DbgHandleTable, sizeof(g_DbgHandleTable));
    SvmDebugPrint("[DebugApi] Initialized (pool-based, no ObCreateObjectType)\n");

    /* 初始化VMM侧调试共享上下文 */
    HvInitDebugContext();

    return Status;
}

/**
 * @brief 卸载调试子系统
 */
VOID DbgUninitialize()
{
    /* 清理调试进程链表 */
    ExAcquireFastMutex(&g_DebugProcessListMutex);
    while (!IsListEmpty(&g_DebugProcessListHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_DebugProcessListHead);
        PDEBUG_PROCESS dbgProc = CONTAINING_RECORD(entry, DEBUG_PROCESS, ListEntry);
        ExFreePoolWithTag(dbgProc, 'DbgP');
    }
    ExReleaseFastMutex(&g_DebugProcessListMutex);

    /* 清理调试器链表 */
    ExAcquireFastMutex(&g_DebuggerListMutex);
    while (!IsListEmpty(&g_DebuggerListHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_DebuggerListHead);
        PDEBUGGER_TABLE_ENTRY dbgEntry = CONTAINING_RECORD(entry, DEBUGGER_TABLE_ENTRY, ListEntry);
        ExFreePoolWithTag(dbgEntry, 'DbgD');
    }
    ExReleaseFastMutex(&g_DebuggerListMutex);

    /* 释放调试页面MDL锁定 (Section 8定义) */
    extern VOID UnlockAllDebugPages();
    UnlockAllDebugPages();

    HvFreeDebugContext();

    SvmDebugPrint("[DebugApi] Uninitialized\n");
}

/**
 * @brief 初始化VMM侧调试共享上下文页
 */
NTSTATUS HvInitDebugContext()
{
    ExInitializeFastMutex(&g_HvDebugMutex);
    PHYSICAL_ADDRESS highAddr;
    highAddr.QuadPart = ~0ULL;

    g_HvDebugContext = (PHV_DEBUG_CONTEXT)MmAllocateContiguousMemory(
        PAGE_SIZE, highAddr);
    if (!g_HvDebugContext) {
        SvmDebugPrint("[DebugApi] Failed to allocate debug context\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_HvDebugContext, PAGE_SIZE);
    g_HvDebugContextPa = MmGetPhysicalAddress(g_HvDebugContext).QuadPart;

    SvmDebugPrint("[DebugApi] Debug context VA=%p PA=0x%llX\n",
        g_HvDebugContext, g_HvDebugContextPa);

    return STATUS_SUCCESS;
}

/**
 * @brief 释放VMM侧调试共享上下文页
 */
VOID HvFreeDebugContext()
{
    if (g_HvDebugContext) {
        MmFreeContiguousMemory(g_HvDebugContext);
        g_HvDebugContext = nullptr;
        g_HvDebugContextPa = 0;
    }
}


/* ========================================================================
 *  Section 2: 调试器 / 被调试进程管理
 * ======================================================================== */

BOOLEAN RegisterDebugger(PEPROCESS DebuggerProcess, HANDLE DebuggerPid)
{
    /* 检查是否已注册 */
    if (IsDebugger(DebuggerProcess)) return TRUE;

    PDEBUGGER_TABLE_ENTRY entry = (PDEBUGGER_TABLE_ENTRY)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(DEBUGGER_TABLE_ENTRY), 'DbgD');
    if (!entry) return FALSE;

    entry->DebuggerProcess = DebuggerProcess;
    entry->DebuggerPid = DebuggerPid;

    ExAcquireFastMutex(&g_DebuggerListMutex);
    InsertTailList(&g_DebuggerListHead, &entry->ListEntry);
    ExReleaseFastMutex(&g_DebuggerListMutex);

    SvmDebugPrint("[DebugApi] Registered debugger PID=%lld\n", (ULONG64)DebuggerPid);
    return TRUE;
}

BOOLEAN IsDebugger(PEPROCESS Process)
{
    BOOLEAN result = FALSE;
    HANDLE currentPid = PsGetProcessId(Process);

    ExAcquireFastMutex(&g_DebuggerListMutex);
    for (PLIST_ENTRY entry = g_DebuggerListHead.Flink;
        entry != &g_DebuggerListHead;
        entry = entry->Flink)
    {
        PDEBUGGER_TABLE_ENTRY dbgEntry = CONTAINING_RECORD(entry, DEBUGGER_TABLE_ENTRY, ListEntry);
        if (dbgEntry->DebuggerProcess == Process ||
            dbgEntry->DebuggerPid == currentPid) {
            result = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_DebuggerListMutex);
    return result;
}

BOOLEAN SetDebugTargetProcess(PEPROCESS Process, PDEBUG_OBJECT DebugObject)
{
    if (!Process || !DebugObject) return FALSE;

    PDEBUG_PROCESS entry = (PDEBUG_PROCESS)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(DEBUG_PROCESS), 'DbgP');
    if (!entry) return FALSE;

    entry->Process = Process;
    entry->DebugObject = DebugObject;
    ExInitializeFastMutex(&entry->Mutex);

    ExAcquireFastMutex(&g_DebugProcessListMutex);
    InsertTailList(&g_DebugProcessListHead, &entry->ListEntry);
    ExReleaseFastMutex(&g_DebugProcessListMutex);

    SvmDebugPrint("[DebugApi] SetDebugTarget Process=%p DebugObject=%p\n", Process, DebugObject);
    return TRUE;
}

BOOLEAN IsDebugTargetProcess(PEPROCESS Process, PDEBUG_PROCESS* DebugProcess)
{
    BOOLEAN result = FALSE;
    *DebugProcess = NULL;

    ExAcquireFastMutex(&g_DebugProcessListMutex);
    for (PLIST_ENTRY entry = g_DebugProcessListHead.Flink;
        entry != &g_DebugProcessListHead;
        entry = entry->Flink)
    {
        PDEBUG_PROCESS dbgProc = CONTAINING_RECORD(entry, DEBUG_PROCESS, ListEntry);
        if (dbgProc->Process == Process) {
            *DebugProcess = dbgProc;
            result = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_DebugProcessListMutex);
    return result;
}

VOID DeleteDebugProcess(PDEBUG_OBJECT DebugObject)
{
    ExAcquireFastMutex(&g_DebugProcessListMutex);
    for (PLIST_ENTRY entry = g_DebugProcessListHead.Flink;
        entry != &g_DebugProcessListHead;
        entry = entry->Flink)
    {
        PDEBUG_PROCESS dbgProc = CONTAINING_RECORD(entry, DEBUG_PROCESS, ListEntry);
        if (dbgProc->DebugObject == DebugObject) {
            RemoveEntryList(entry);
            ExFreePoolWithTag(dbgProc, 'DbgP');
            break;
        }
    }
    ExReleaseFastMutex(&g_DebugProcessListMutex);
}

NTSTATUS DbgkClearProcessDebugObject(PEPROCESS Process, PDEBUG_OBJECT SourceDebugObject)
{
    NTSTATUS Status;
    PDEBUG_OBJECT DebugObject = NULL;
    PDEBUG_PROCESS DebugProcess;
    PDEBUG_EVENT DebugEvent;
    LIST_ENTRY TempList;

    ExAcquireFastMutex(&g_DbgkpProcessDebugPortMutex);

    if (IsDebugTargetProcess(Process, &DebugProcess)) {
        DebugObject = DebugProcess->DebugObject;
    }

    if (!DebugObject || (SourceDebugObject && DebugObject != SourceDebugObject)) {
        ExReleaseFastMutex(&g_DbgkpProcessDebugPortMutex);
        return STATUS_PORT_NOT_SET;
    }

    Status = STATUS_SUCCESS;
    ExReleaseFastMutex(&g_DbgkpProcessDebugPortMutex);

    if (NT_SUCCESS(Status)) {
        DbgkpMarkProcessPeb(Process);
    }

    /* 清理该进程的事件 */
    InitializeListHead(&TempList);
    ExAcquireFastMutex(&DebugObject->Mutex);
    for (PLIST_ENTRY entry = DebugObject->EventList.Flink;
        entry != &DebugObject->EventList; )
    {
        DebugEvent = CONTAINING_RECORD(entry, DEBUG_EVENT, EventList);
        entry = entry->Flink;
        if (DebugEvent->Process == Process) {
            RemoveEntryList(&DebugEvent->EventList);
            InsertTailList(&TempList, &DebugEvent->EventList);
        }
    }
    ExReleaseFastMutex(&DebugObject->Mutex);


    /* 唤醒所有被移除的线程 */
    while (!IsListEmpty(&TempList)) {
        PLIST_ENTRY entry = RemoveHeadList(&TempList);
        DebugEvent = CONTAINING_RECORD(entry, DEBUG_EVENT, EventList);
        DebugEvent->Status = STATUS_DEBUGGER_INACTIVE;
        DbgkpWakeTarget(DebugEvent);
    }

    return Status;
}


/* ========================================================================
 *  Section 3: 调试事件辅助函数
 * ======================================================================== */

VOID DbgkpWakeTarget(IN PDEBUG_EVENT DebugEvent)
{
    if (!DebugEvent) return;

    if (DebugEvent->Flags & DEBUG_EVENT_NOWAIT) {
        /* 异步事件: 释放引用并释放内存 */
        ObDereferenceObject(DebugEvent->Thread);
        ObDereferenceObject(DebugEvent->Process);
        ExFreePoolWithTag(DebugEvent, 'EgbD');
    }
    else {
        /* 同步事件: 信号化ContinueEvent唤醒等待的线程 */
        KeSetEvent(&DebugEvent->ContinueEvent, IO_NO_INCREMENT, FALSE);
    }
}

VOID DbgkpFreeDebugEvent(IN PDEBUG_EVENT DebugEvent)
{
    if (!DebugEvent) return;
    if (DebugEvent->Flags & DEBUG_EVENT_NOWAIT) {
        ObDereferenceObject(DebugEvent->Thread);
        ObDereferenceObject(DebugEvent->Process);
    }
    ExFreePoolWithTag(DebugEvent, 'EgbD');
}

VOID DbgkpMarkProcessPeb(IN PEPROCESS Process)
{
    /*
     * 关键: 保持PEB.BeingDebugged = 0
     * 系统原始实现会在这里设置BeingDebugged,
     * 我们故意不设置, 使IsDebuggerPresent()返回FALSE。
     */
    PPEB_LITE pPeb = (PPEB_LITE)PsGetProcessPeb(Process);
    if (pPeb) {
        __try {
            pPeb->BeingDebugged = 0;  /* 始终保持为0, 隐藏调试状态 */
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            /* PEB不可访问, 忽略 */
        }
    }
}

VOID DbgkpConvertKernelToUserStateChange(
    OUT PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
    IN PDEBUG_EVENT DebugEvent)
{
    WaitStateChange->AppClientId = DebugEvent->ClientId;

    switch (DebugEvent->ApiMsg.ApiNumber)
    {
    case DbgKmCreateProcessApi:
        WaitStateChange->NewState = DbgCreateProcessStateChange;
        WaitStateChange->StateInfo.CreateProcessInfo.NewProcess =
            DebugEvent->ApiMsg.u.CreateProcess;
        DebugEvent->ApiMsg.u.CreateProcess.FileHandle = NULL;
        break;

    case DbgKmCreateThreadApi:
        WaitStateChange->NewState = DbgCreateThreadStateChange;
        WaitStateChange->StateInfo.CreateThread.NewThread.StartAddress =
            DebugEvent->ApiMsg.u.CreateThread.StartAddress;
        WaitStateChange->StateInfo.CreateThread.NewThread.SubSystemKey =
            DebugEvent->ApiMsg.u.CreateThread.SubSystemKey;
        break;

    case DbgKmExceptionApi:
        if ((NTSTATUS)DebugEvent->ApiMsg.u.Exception.ExceptionRecord.ExceptionCode ==
            STATUS_BREAKPOINT) {
            WaitStateChange->NewState = DbgBreakpointStateChange;
        }
        else if ((NTSTATUS)DebugEvent->ApiMsg.u.Exception.ExceptionRecord.ExceptionCode ==
            STATUS_SINGLE_STEP) {
            WaitStateChange->NewState = DbgSingleStepStateChange;
        }
        else {
            WaitStateChange->NewState = DbgExceptionStateChange;
        }
        WaitStateChange->StateInfo.Exception.ExceptionRecord =
            DebugEvent->ApiMsg.u.Exception.ExceptionRecord;
        WaitStateChange->StateInfo.Exception.FirstChance =
            DebugEvent->ApiMsg.u.Exception.FirstChance;
        break;

    case DbgKmExitProcessApi:
        WaitStateChange->NewState = DbgExitProcessStateChange;
        WaitStateChange->StateInfo.ExitProcess.ExitStatus =
            DebugEvent->ApiMsg.u.ExitProcess.ExitStatus;
        break;

    case DbgKmExitThreadApi:
        WaitStateChange->NewState = DbgExitThreadStateChange;
        WaitStateChange->StateInfo.ExitThread.ExitStatus =
            DebugEvent->ApiMsg.u.ExitThread.ExitStatus;
        break;

    case DbgKmLoadDllApi:
        WaitStateChange->NewState = DbgLoadDllStateChange;
        WaitStateChange->StateInfo.LoadDll = DebugEvent->ApiMsg.u.LoadDll;
        DebugEvent->ApiMsg.u.LoadDll.FileHandle = NULL;
        break;

    case DbgKmUnloadDllApi:
        WaitStateChange->NewState = DbgUnloadDllStateChange;
        WaitStateChange->StateInfo.UnloadDll.BaseAddress =
            DebugEvent->ApiMsg.u.UnloadDll.BaseAddress;
        break;

    default:
        break;
    }
}

VOID DbgkpOpenHandles(
    IN OUT PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
    IN PEPROCESS Process,
    IN PETHREAD Thread)
{
    NTSTATUS Status;
    HANDLE Handle;

    switch (WaitStateChange->NewState)
    {
    case DbgCreateThreadStateChange:
        Status = ObOpenObjectByPointer(Thread, 0, NULL, THREAD_ALL_ACCESS,
            *PsThreadType, KernelMode, &Handle);
        if (NT_SUCCESS(Status)) {
            WaitStateChange->StateInfo.CreateThread.HandleToThread = Handle;
        }
        return;

    case DbgCreateProcessStateChange:
        Status = ObOpenObjectByPointer(Thread, 0, NULL, THREAD_ALL_ACCESS,
            *PsThreadType, KernelMode, &Handle);
        if (NT_SUCCESS(Status)) {
            WaitStateChange->StateInfo.CreateProcessInfo.HandleToThread = Handle;
        }
        Status = ObOpenObjectByPointer(Process, 0, NULL, PROCESS_ALL_ACCESS,
            *PsProcessType, KernelMode, &Handle);
        if (NT_SUCCESS(Status)) {
            WaitStateChange->StateInfo.CreateProcessInfo.HandleToProcess = Handle;
        }
        /* 复制文件句柄 */
        {
            PHANDLE DupHandle = &WaitStateChange->StateInfo.CreateProcessInfo.NewProcess.FileHandle;
            Handle = *DupHandle;
            if (Handle) {
                Status = ObDuplicateObject(PsGetCurrentProcess(), Handle,
                    PsGetCurrentProcess(), DupHandle, 0, 0,
                    DUPLICATE_SAME_ACCESS, KernelMode);
                if (!NT_SUCCESS(Status)) *DupHandle = NULL;
                ObCloseHandle(Handle, KernelMode);
            }
        }
        return;

    case DbgLoadDllStateChange:
    {
        PHANDLE DupHandle = &WaitStateChange->StateInfo.LoadDll.FileHandle;
        Handle = *DupHandle;
        if (Handle) {
            Status = ObDuplicateObject(PsGetCurrentProcess(), Handle,
                PsGetCurrentProcess(), DupHandle, 0, 0,
                DUPLICATE_SAME_ACCESS, KernelMode);
            if (!NT_SUCCESS(Status)) *DupHandle = NULL;
            ObCloseHandle(Handle, KernelMode);
        }
    }
    return;

    default:
        return;
    }
}

/**
 * @brief 内部发送调试API消息 — 查询影子DebugPort后投递事件
 */
NTSTATUS DbgkpSendApiMessage(
    IN PEPROCESS Process,
    IN BOOLEAN SuspendProcess,
    IN OUT PDBGKM_APIMSG ApiMsg)
{
    UNREFERENCED_PARAMETER(SuspendProcess);

    PDEBUG_OBJECT DebugObject = NULL;
    PDEBUG_PROCESS DebugProcess;

    if (IsDebugTargetProcess(Process, &DebugProcess)) {
        DebugObject = DebugProcess->DebugObject;
    }

    if (!DebugObject) return STATUS_PORT_NOT_SET;

    return Fake_DbgkpQueueMessage(Process, PsGetCurrentThread(), ApiMsg, 0, NULL);
}


/* ========================================================================
 *  Section 4: NPT Fake函数 — 替换系统调试API
 * ======================================================================== */

 /**
  * @brief [Fake] NtCreateDebugObject — 使用自定义对象类型创建调试对象
  */
NTSTATUS NTAPI Fake_NtCreateDebugObject(
    OUT PHANDLE DebugHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG Flags)
{
    DBG_FAKE_PRINT_ONCE(HOOK_NtCreateDebugObject_Dbg, "Fake_NtCreateDebugObject");
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
    PDEBUG_OBJECT DebugObject;
    HANDLE hDebug = NULL;
    NTSTATUS Status;

    /* 只有已注册的调试器才能创建调试对象 */
    BOOLEAN bIsDbg = IsDebugger(PsGetCurrentProcess());
    if (!bIsDbg) {
        SvmDebugPrint("[DebugApi] NtCreateDebugObject: caller PID=%lld NOT debugger, passthrough\n",
            (ULONG64)PsGetCurrentProcessId());
        /* 非我们的调试器, 透传给原函数 */
        if (g_OrigNtCreateDebugObject)
            return g_OrigNtCreateDebugObject(DebugHandle, DesiredAccess, ObjectAttributes, Flags);
        return STATUS_ACCESS_DENIED;
    }

    /* 探测用户态指针 */
    if (PreviousMode != KernelMode) {
        __try {
            ProbeForWriteHandle(DebugHandle);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    if (Flags & ~DBGK_ALL_FLAGS) return STATUS_INVALID_PARAMETER;

    /* 创建自定义调试对象 */
    DebugObject = DbgAllocateDebugObject();
    if (!DebugObject) { Status = STATUS_INSUFFICIENT_RESOURCES; }
    else {
        DebugObject->Flags = (Flags & DBGK_KILL_PROCESS_ON_EXIT) ? DEBUG_OBJECT_KILL_ON_CLOSE : 0;
        hDebug = DbgInsertHandle(DebugObject);
        if (!hDebug) { DbgFreeDebugObject(DebugObject); Status = STATUS_INSUFFICIENT_RESOURCES; }
        else { __try { *DebugHandle = hDebug; Status = STATUS_SUCCESS; } __except (EXCEPTION_EXECUTE_HANDLER) { Status = GetExceptionCode(); } }
    }

    SvmDebugPrint("[DebugApi] NtCreateDebugObject Handle=%p Status=0x%X\n", hDebug, Status);
    return Status;
}

/**
 * @brief [Fake] NtSetInformationDebugObject
 */
NTSTATUS NTAPI Fake_NtSetInformationDebugObject(
    IN HANDLE DebugObjectHandle,
    IN DEBUGOBJECTINFOCLASS DebugObjectInformationClass,
    IN PVOID DebugInformation,
    IN ULONG DebugInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    DBG_FAKE_PRINT_ONCE(HOOK_NtSetInfoDebugObject_Dbg, "Fake_NtSetInformationDebugObject");
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
    NTSTATUS Status;
    PDEBUG_OBJECT DebugObject;
    ULONG Flags;

    if (!IsDebugger(PsGetCurrentProcess()) && !DBG_IS_VALID_HANDLE(DebugObjectHandle)) {
        /* 非我们的调试器, 透传 */
        return STATUS_PORT_NOT_SET;
    }

    __try {
        if (PreviousMode != KernelMode) {
            ProbeForRead(DebugInformation, DebugInformationLength, sizeof(ULONG));
            if (ReturnLength) ProbeForWriteUlong(ReturnLength);
        }
        if (ReturnLength) *ReturnLength = 0;

        if (DebugObjectInformationClass != DebugObjectFlags)
            return STATUS_INVALID_PARAMETER;

        if (DebugInformationLength != sizeof(ULONG)) {
            if (ReturnLength) *ReturnLength = sizeof(ULONG);
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        Flags = *(PULONG)DebugInformation;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (Flags & ~DBGK_KILL_PROCESS_ON_EXIT)
        return STATUS_INVALID_PARAMETER;

    Status = STATUS_SUCCESS; DebugObject = DbgLookupHandle(DebugObjectHandle);
    if (!DebugObject) return STATUS_INVALID_HANDLE;

    ExAcquireFastMutex(&DebugObject->Mutex);
    if (Flags & DBGK_KILL_PROCESS_ON_EXIT)
        DebugObject->Flags |= DEBUG_OBJECT_KILL_ON_CLOSE;
    else
        DebugObject->Flags &= ~DEBUG_OBJECT_KILL_ON_CLOSE;
    ExReleaseFastMutex(&DebugObject->Mutex);

    return STATUS_SUCCESS;
}


/**
 * @brief Post fake CREATE_PROCESS event after attach so CE's WaitForDebugEvent returns
 */
static VOID DbgkpPostFakeProcessCreateMessages(
    PEPROCESS TargetProcess,
    PDEBUG_OBJECT DebugObject)
{
    if (!TargetProcess || !DebugObject) return;


    PVOID imageBase = NULL;
    PPEB_LITE pPeb = (PPEB_LITE)PsGetProcessPeb(TargetProcess);
    if (pPeb) {
        KAPC_STATE apcState;
        KeStackAttachProcess(TargetProcess, &apcState);
        __try {
            /* PEB_LITE: Reserved1[2], BeingDebugged, Reserved2[1], Reserved3[2]
             * Reserved3[0] = Mutant (offset 0x08)
             * Reserved3[1] = ImageBaseAddress (offset 0x10) */
            imageBase = pPeb->Reserved3[1];
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            imageBase = NULL;
        }
        KeUnstackDetachProcess(&apcState);
    }


    PETHREAD initialThread = NULL;
    HANDLE targetPid = PsGetProcessId(TargetProcess);

    /* 方法: 扫描线程ID, 找到第一个属于目标进程的线程 */
    for (ULONG_PTR tid = 4; tid < 0x10000; tid += 4) {
        PETHREAD tempThread = NULL;
        NTSTATUS st = PsLookupThreadByThreadId((HANDLE)tid, &tempThread);
        if (NT_SUCCESS(st) && tempThread) {
            if (IoThreadToProcess(tempThread) == TargetProcess) {
                initialThread = tempThread;
                /* 保留引用, 后续 ObReferenceObject 时使用 */
                break;
            }
            ObDereferenceObject(tempThread);
        }
    }

    if (!initialThread) {
        /* 回退: 仍用当前线程, 但打印警告 */
        SvmDebugPrint("[DebugApi] WARNING: no thread found for target PID=%lld, using current thread\n",
            (ULONG64)targetPid);
        initialThread = PsGetCurrentThread();
        ObReferenceObject(initialThread);
    }

    PDEBUG_EVENT createProcEvent = (PDEBUG_EVENT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(DEBUG_EVENT), 'EgbD');
    if (!createProcEvent) {
        ObDereferenceObject(initialThread);
        return;
    }

    RtlZeroMemory(createProcEvent, sizeof(DEBUG_EVENT));
    createProcEvent->Flags = DEBUG_EVENT_NOWAIT;
    createProcEvent->Process = TargetProcess;
    ObReferenceObject(TargetProcess);

    createProcEvent->Thread = initialThread;
    /* initialThread 已经有一个引用 (来自 PsLookupThreadByThreadId 或手动 ObRef),
     * NOWAIT 事件在 WakeTarget 中会 ObDereferenceObject, 所以这里再加一个引用 */
    ObReferenceObject(initialThread);

    createProcEvent->ClientId.UniqueProcess = targetPid;
    createProcEvent->ClientId.UniqueThread = PsGetThreadId(initialThread);
    KeInitializeEvent(&createProcEvent->ContinueEvent, SynchronizationEvent, FALSE);

    createProcEvent->ApiMsg.ApiNumber = DbgKmCreateProcessApi;
    createProcEvent->ApiMsg.h.u1.Length = 0x500028;
    createProcEvent->ApiMsg.h.u2.ZeroInit = LPC_DEBUG_EVENT;
    createProcEvent->ApiMsg.u.CreateProcess.SubSystemKey = 0;
    createProcEvent->ApiMsg.u.CreateProcess.FileHandle = NULL;
    createProcEvent->ApiMsg.u.CreateProcess.BaseOfImage = imageBase;
    createProcEvent->ApiMsg.u.CreateProcess.DebugInfoFileOffset = 0;
    createProcEvent->ApiMsg.u.CreateProcess.DebugInfoSize = 0;
    createProcEvent->ApiMsg.u.CreateProcess.InitialThread.SubSystemKey = 0;
    createProcEvent->ApiMsg.u.CreateProcess.InitialThread.StartAddress = NULL;

    ExAcquireFastMutex(&DebugObject->Mutex);
    InsertTailList(&DebugObject->EventList, &createProcEvent->EventList);


    {
        PDEBUG_EVENT bpEvent = (PDEBUG_EVENT)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(DEBUG_EVENT), 'EgbD');
        if (bpEvent) {
            RtlZeroMemory(bpEvent, sizeof(DEBUG_EVENT));
            bpEvent->Flags = DEBUG_EVENT_NOWAIT;
            bpEvent->Process = TargetProcess;
            ObReferenceObject(TargetProcess);
            bpEvent->Thread = initialThread;
            ObReferenceObject(initialThread);
            bpEvent->ClientId.UniqueProcess = targetPid;
            bpEvent->ClientId.UniqueThread = PsGetThreadId(initialThread);
            KeInitializeEvent(&bpEvent->ContinueEvent, SynchronizationEvent, FALSE);

            bpEvent->ApiMsg.ApiNumber = DbgKmExceptionApi;
            bpEvent->ApiMsg.h.u1.Length = 0xD000A8;
            bpEvent->ApiMsg.h.u2.ZeroInit = LPC_DEBUG_EVENT;
            bpEvent->ApiMsg.u.Exception.ExceptionRecord.ExceptionCode = STATUS_BREAKPOINT;
            bpEvent->ApiMsg.u.Exception.ExceptionRecord.NumberParameters = 1;
            bpEvent->ApiMsg.u.Exception.ExceptionRecord.ExceptionInformation[0] = 0;
            bpEvent->ApiMsg.u.Exception.FirstChance = TRUE;

            InsertTailList(&DebugObject->EventList, &bpEvent->EventList);
        }
    }

    KeSetEvent(&DebugObject->EventsPresent, IO_NO_INCREMENT, FALSE);
    ExReleaseFastMutex(&DebugObject->Mutex);

    /* 释放我们自己持有的引用 (事件持有独立引用) */
    ObDereferenceObject(initialThread);

    SvmDebugPrint("[DebugApi] Posted fake CREATE_PROCESS: PID=%lld, TID=%lld, ImageBase=%p\n",
        (ULONG64)targetPid, (ULONG64)PsGetThreadId(createProcEvent->Thread), imageBase);
}

/**
 * @brief [Fake] NtDebugActiveProcess - attach debug, write shadow debug port
 *
 */
NTSTATUS NTAPI Fake_NtDebugActiveProcess(
    IN HANDLE ProcessHandle,
    IN HANDLE DebugHandle)
{
    NTSTATUS Status;
    PEPROCESS TargetProcess;
    PDEBUG_OBJECT DebugObject;
    BOOLEAN bIsDbg = IsDebugger(PsGetCurrentProcess());
    BOOLEAN bIsCustomHandle = DBG_IS_VALID_HANDLE(DebugHandle);

    SvmDebugPrint("[DebugApi] Fake_NtDebugActiveProcess: PH=%p DH=%p isDbg=%d isCustom=%d PID=%lld\n",
        ProcessHandle, DebugHandle, bIsDbg, bIsCustomHandle, (ULONG64)PsGetCurrentProcessId());

    if (!bIsDbg && !bIsCustomHandle) {
        /* 既不是注册的调试器, DebugHandle 也不是自定义句柄 → 正常透传 */
        if (g_OrigNtDebugActiveProcess)
            return g_OrigNtDebugActiveProcess(ProcessHandle, DebugHandle);
        return STATUS_ACCESS_DENIED;
    }

    if (bIsCustomHandle && !bIsDbg) {
        /* 自定义句柄但调用者不是注册的调试器 → 拒绝访问
         * 防止非授权进程利用伪造句柄 */
        SvmDebugPrint("[DebugApi] NtDebugActiveProcess: custom handle from non-debugger PID=%lld, denied\n",
            (ULONG64)PsGetCurrentProcessId());
        return STATUS_ACCESS_DENIED;
    }

    Status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_SET_PORT,
        *PsProcessType, KeGetPreviousMode(), (PVOID*)&TargetProcess, NULL);
    if (!NT_SUCCESS(Status)) {
        SvmDebugPrint("[DebugApi] NtDebugActiveProcess: ObRefByHandle failed 0x%X\n", Status);
        return Status;
    }

    /* 不能调试自己和System进程 */
    if (TargetProcess == PsGetCurrentProcess() ||
        TargetProcess == PsInitialSystemProcess) {
        ObDereferenceObject(TargetProcess);
        return STATUS_ACCESS_DENIED;
    }

    Status = STATUS_SUCCESS; DebugObject = DbgLookupHandle(DebugHandle);
    Status = DebugObject ? STATUS_SUCCESS : STATUS_INVALID_HANDLE;
    if (NT_SUCCESS(Status)) {
        /* 写入影子调试端口 (不写EPROCESS.DebugPort) */
        ExAcquireFastMutex(&g_DbgkpProcessDebugPortMutex);

        PDEBUG_PROCESS existingDebug;
        if (IsDebugTargetProcess(TargetProcess, &existingDebug)) {
            Status = STATUS_PORT_ALREADY_SET;
        }
        else {
            if (SetDebugTargetProcess(TargetProcess, DebugObject)) {
                Status = STATUS_SUCCESS;
            }
            else {
                Status = STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        ExReleaseFastMutex(&g_DbgkpProcessDebugPortMutex);

        if (NT_SUCCESS(Status)) {
            DbgkpMarkProcessPeb(TargetProcess);
            /* 投递初始CREATE_PROCESS事件, 否则CE的WaitForDebugEvent永远收不到事件 */
            DbgkpPostFakeProcessCreateMessages(TargetProcess, DebugObject);
        }

        /* NOTE: DebugObject is pool-based (DbgAllocateDebugObject), NOT an OB object.
         * Do NOT call ObDereferenceObject — it would access a non-existent OBJECT_HEADER → BSOD.
         * The DebugObject lifetime is managed by DbgRemoveHandle + DbgFreeDebugObject. */
    }

    ObDereferenceObject(TargetProcess);

    SvmDebugPrint("[DebugApi] NtDebugActiveProcess Status=0x%X\n", Status);
    return Status;
}

/**
 * @brief [Fake] NtWaitForDebugEvent — 从自定义事件队列取出事件
 */
NTSTATUS NTAPI Fake_NtWaitForDebugEvent(
    IN HANDLE DebugHandle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL,
    OUT PDBGUI_WAIT_STATE_CHANGE StateChange)
{
    DBG_FAKE_PRINT_ONCE(HOOK_NtWaitForDebugEvent_Dbg, "Fake_NtWaitForDebugEvent");
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
    LARGE_INTEGER LocalTimeOut = { 0 };
    PEPROCESS Process;
    PETHREAD Thread;
    BOOLEAN GotEvent;
    PDEBUG_OBJECT DebugObject;
    DBGUI_WAIT_STATE_CHANGE WaitStateChange = { 0 };
    NTSTATUS Status;
    PDEBUG_EVENT DebugEvent = NULL, DebugEvent2;
    PLIST_ENTRY ListHead, NextEntry, NextEntry2;
    LARGE_INTEGER StartTime = { 0 };

    BOOLEAN bIsCustomHandle = DBG_IS_VALID_HANDLE(DebugHandle);
    if (!IsDebugger(PsGetCurrentProcess()) && !bIsCustomHandle) {
        if (g_OrigNtWaitForDebugEvent)
            return g_OrigNtWaitForDebugEvent(DebugHandle, Alertable, Timeout, StateChange);
        return STATUS_ACCESS_DENIED;
    }

    /* 探测用户态指针 */
    if (PreviousMode != KernelMode) {
        __try {
            if (Timeout) {
                ProbeForReadLargeInteger(Timeout);
                LocalTimeOut = *Timeout;
                Timeout = &LocalTimeOut;
            }
            ProbeForWrite(StateChange, sizeof(*StateChange), sizeof(ULONG));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }
    else {
        if (Timeout) LocalTimeOut = *Timeout;
    }

    if (Timeout) KeQuerySystemTime(&StartTime);

    /* 获取调试对象 */
    Status = STATUS_SUCCESS; DebugObject = DbgLookupHandle(DebugHandle);
    if (!DebugObject) return STATUS_INVALID_HANDLE;

    Process = NULL;
    Thread = NULL;

    while (TRUE) {
        Status = KeWaitForSingleObject(&DebugObject->EventsPresent,
            Executive, PreviousMode, Alertable, Timeout);

        if (!NT_SUCCESS(Status) || Status == STATUS_TIMEOUT ||
            Status == STATUS_ALERTED || Status == STATUS_USER_APC)
            break;

        GotEvent = FALSE;
        ExAcquireFastMutex(&DebugObject->Mutex);

        if (DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING) {
            Status = STATUS_DEBUGGER_INACTIVE;
        }
        else {
            ListHead = &DebugObject->EventList;
            NextEntry = ListHead->Flink;
            while (ListHead != NextEntry) {
                DebugEvent = CONTAINING_RECORD(NextEntry, DEBUG_EVENT, EventList);

                if (!(DebugEvent->Flags & (DEBUG_EVENT_INACTIVE | DEBUG_EVENT_READ))) {
                    GotEvent = TRUE;

                    /* 检查同一进程是否有先前未完成的事件 */
                    NextEntry2 = DebugObject->EventList.Flink;
                    while (NextEntry2 != NextEntry) {
                        DebugEvent2 = CONTAINING_RECORD(NextEntry2, DEBUG_EVENT, EventList);
                        if (DebugEvent2->ClientId.UniqueProcess ==
                            DebugEvent->ClientId.UniqueProcess) {
                            DebugEvent->Flags |= DEBUG_EVENT_INACTIVE;
                            DebugEvent->BackoutThread = NULL;
                            GotEvent = FALSE;
                            break;
                        }
                        NextEntry2 = NextEntry2->Flink;
                    }
                    if (GotEvent) break;
                }
                NextEntry = NextEntry->Flink;
            }

            if (GotEvent) {
                Process = DebugEvent->Process;
                Thread = DebugEvent->Thread;
                ObReferenceObject(Process);
                ObReferenceObject(Thread);
                DbgkpConvertKernelToUserStateChange(&WaitStateChange, DebugEvent);
                DebugEvent->Flags |= DEBUG_EVENT_READ;
            }
            else {
                KeResetEvent(&DebugObject->EventsPresent);
            }
            Status = STATUS_SUCCESS;
        }

        ExReleaseFastMutex(&DebugObject->Mutex);
        if (!NT_SUCCESS(Status)) break;

        if (!GotEvent) {
            if (LocalTimeOut.QuadPart < 0) {
                LARGE_INTEGER NewTime;
                KeQuerySystemTime(&NewTime);
                LocalTimeOut.QuadPart += (NewTime.QuadPart - StartTime.QuadPart);
                StartTime = NewTime;
                if (LocalTimeOut.QuadPart >= 0) {
                    Status = STATUS_TIMEOUT;
                    break;
                }
            }
        }
        else {
            DbgkpOpenHandles(&WaitStateChange, Process, Thread);
            ObDereferenceObject(Process);
            ObDereferenceObject(Thread);
            break;
        }
    }


    __try {
        *StateChange = WaitStateChange;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    return Status;
}

/**
 * @brief [Fake] NtDebugContinue — 唤醒被挂起的线程
 */
NTSTATUS NTAPI Fake_NtDebugContinue(
    IN HANDLE DebugObjectHandle,
    IN PCLIENT_ID ClientId,
    IN NTSTATUS ContinueStatus)
{
    DBG_FAKE_PRINT_ONCE(HOOK_NtDebugContinue_Dbg, "Fake_NtDebugContinue");
    NTSTATUS Status;
    PDEBUG_OBJECT DebugObject;
    PDEBUG_EVENT DebugEvent, FoundDebugEvent;
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
    CLIENT_ID Clid;
    BOOLEAN GotEvent;

    BOOLEAN bIsCustomHandle = DBG_IS_VALID_HANDLE(DebugObjectHandle);
    if (!IsDebugger(PsGetCurrentProcess()) && !bIsCustomHandle) {
        if (g_OrigNtDebugContinue)
            return g_OrigNtDebugContinue(DebugObjectHandle, ClientId, ContinueStatus);
        return STATUS_ACCESS_DENIED;
    }

    __try {
        if (PreviousMode != KernelMode)
            ProbeForReadSmallStructure(ClientId, sizeof(*ClientId), sizeof(UCHAR));
        Clid = *ClientId;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    switch (ContinueStatus) {
    case DBG_EXCEPTION_HANDLED:
    case DBG_EXCEPTION_NOT_HANDLED:
    case DBG_TERMINATE_THREAD:
    case DBG_TERMINATE_PROCESS:
    case DBG_CONTINUE:
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    Status = STATUS_SUCCESS; DebugObject = DbgLookupHandle(DebugObjectHandle);
    if (!DebugObject) return STATUS_INVALID_HANDLE;

    GotEvent = FALSE;
    FoundDebugEvent = NULL;

    ExAcquireFastMutex(&DebugObject->Mutex);
    for (PLIST_ENTRY entry = DebugObject->EventList.Flink;
        entry != &DebugObject->EventList;
        entry = entry->Flink)
    {
        DebugEvent = CONTAINING_RECORD(entry, DEBUG_EVENT, EventList);
        if (DebugEvent->ClientId.UniqueProcess == Clid.UniqueProcess) {
            if (!GotEvent) {
                if (DebugEvent->ClientId.UniqueThread == Clid.UniqueThread &&
                    (DebugEvent->Flags & DEBUG_EVENT_READ))
                {
                    RemoveEntryList(entry);
                    FoundDebugEvent = DebugEvent;
                    GotEvent = TRUE;
                }
            }
            else {
                DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
                KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
                break;
            }
        }
    }
    ExReleaseFastMutex(&DebugObject->Mutex);

    if (GotEvent) {
        FoundDebugEvent->ApiMsg.ReturnedStatus = ContinueStatus;
        FoundDebugEvent->Status = STATUS_SUCCESS;
        DbgkpWakeTarget(FoundDebugEvent);
    }
    else {
        Status = STATUS_INVALID_PARAMETER;
    }

    return Status;
}

/**
 * @brief [Fake] NtRemoveProcessDebug
 */
NTSTATUS NTAPI Fake_NtRemoveProcessDebug(
    IN HANDLE ProcessHandle,
    IN HANDLE DebugObjectHandle)
{
    DBG_FAKE_PRINT_ONCE(HOOK_NtRemoveProcessDebug_Dbg, "Fake_NtRemoveProcessDebug");
    NTSTATUS Status;
    PDEBUG_OBJECT DebugObject;
    PEPROCESS Process;


    BOOLEAN bIsCustomHandle = DBG_IS_VALID_HANDLE(DebugObjectHandle);
    if (!IsDebugger(PsGetCurrentProcess()) && !bIsCustomHandle) {
        if (g_OrigNtRemoveProcessDebug)
            return g_OrigNtRemoveProcessDebug(ProcessHandle, DebugObjectHandle);
        return STATUS_ACCESS_DENIED;
    }


    Status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_SET_PORT,
        *PsProcessType, KeGetPreviousMode(), (PVOID*)&Process, NULL);
    if (!NT_SUCCESS(Status)) return Status;

    Status = STATUS_SUCCESS; DebugObject = DbgLookupHandle(DebugObjectHandle);
    Status = DebugObject ? STATUS_SUCCESS : STATUS_INVALID_HANDLE;
    if (NT_SUCCESS(Status)) {
        Status = DbgkClearProcessDebugObject(Process, DebugObject);
        DeleteDebugProcess(DebugObject);
        DbgRemoveHandle(DebugObjectHandle);

        /* Drain any remaining events and free the DebugObject.
         * Pool-based object — no ObDereferenceObject, manual cleanup. */
        ExAcquireFastMutex(&DebugObject->Mutex);
        DebugObject->Flags |= DEBUG_OBJECT_DELETE_PENDING;
        LIST_ENTRY tempList;
        InitializeListHead(&tempList);
        while (!IsListEmpty(&DebugObject->EventList)) {
            PLIST_ENTRY e = RemoveHeadList(&DebugObject->EventList);
            InsertTailList(&tempList, e);
        }
        ExReleaseFastMutex(&DebugObject->Mutex);

        while (!IsListEmpty(&tempList)) {
            PLIST_ENTRY e = RemoveHeadList(&tempList);
            PDEBUG_EVENT evt = CONTAINING_RECORD(e, DEBUG_EVENT, EventList);
            evt->Status = STATUS_DEBUGGER_INACTIVE;
            DbgkpWakeTarget(evt);
        }

        DbgFreeDebugObject(DebugObject);
    }

    ObDereferenceObject(Process);
    return Status;
}

/**
 * @brief [Fake] DbgkForwardException — 转发异常到影子调试端口
 */
BOOLEAN NTAPI Fake_DbgkForwardException(
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN BOOLEAN IsUseDebugPort,
    IN BOOLEAN SecondChance)
{
    DBG_FAKE_PRINT_ONCE(HOOK_DbgkForwardException_Dbg, "Fake_DbgkForwardException");
    PEPROCESS Process = PsGetCurrentProcess();
    PDEBUG_PROCESS DebugProcess;

    /* 检查是否为我们的被调试进程 */
    if (!IsDebugTargetProcess(Process, &DebugProcess)) {
        /* 不是我们的目标, 透传给原函数 */
        if (g_OrigDbgkForwardException)
            return g_OrigDbgkForwardException(ExceptionRecord, IsUseDebugPort, SecondChance);
        return FALSE;
    }

    if (!IsUseDebugPort) {
        /* 使用异常端口, 透传 */
        if (g_OrigDbgkForwardException)
            return g_OrigDbgkForwardException(ExceptionRecord, IsUseDebugPort, SecondChance);
        return FALSE;
    }

    PDEBUG_OBJECT DebugObject = DebugProcess->DebugObject;
    if (!DebugObject) return FALSE;

    /*
     * 过滤异常: 对于受保护的被调试进程,
     * 我们需要判断哪些异常应该转发给调试器,
     * 哪些应该由目标进程自己处理。
     *
     * 硬件断点(#DB)的特殊处理:
     * 我们的硬件断点通过VMM设置DR寄存器, 不会设置DR0-DR3,
     * 所以如果DR6.B0-B3被置位, 说明是我们的断点,
     * 应该转发给调试器。
     */

     /* 构造调试消息 */
    DBGKM_APIMSG ApiMessage = { 0 };
    PDBGKM_EXCEPTION DbgKmException = &ApiMessage.u.Exception;

    ApiMessage.h.u1.Length = 0xD000A8;
    ApiMessage.h.u2.ZeroInit = LPC_DEBUG_EVENT;
    ApiMessage.ApiNumber = DbgKmExceptionApi;

    DbgKmException->ExceptionRecord = *ExceptionRecord;
    DbgKmException->FirstChance = !SecondChance;

    /* 通过我们的路径发送消息 */
    NTSTATUS Status = DbgkpSendApiMessage(Process, IsUseDebugPort != 0, &ApiMessage);

    if (!NT_SUCCESS(Status)) return FALSE;
    if (ApiMessage.ReturnedStatus == DBG_EXCEPTION_NOT_HANDLED) {
        /* 对于单步异常, 即使调试器未处理也返回TRUE */
        if (ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP ||
            ExceptionRecord->ExceptionCode == STATUS_WX86_SINGLE_STEP) {
            return TRUE;
        }
        return FALSE;
    }

    return NT_SUCCESS(ApiMessage.ReturnedStatus);
}

/**
 * @brief [Fake] DbgkCreateThread — 拦截线程创建, 投递事件到影子端口
 */
VOID NTAPI Fake_DbgkCreateThread(IN PETHREAD Thread)
{
    PEPROCESS Process = PsGetCurrentProcess();
    PDEBUG_PROCESS DebugProcess;

    if (!IsDebugTargetProcess(Process, &DebugProcess)) {
        DBG_FAKE_PRINT_ONCE(HOOK_DbgkCreateThread_Dbg, "Fake_DbgkCreateThread");
        /* 不是我们的目标, 透传 */
        if (g_OrigDbgkCreateThread)
            g_OrigDbgkCreateThread(Thread);
        return;
    }

    /* 是我们的被调试进程, 走自定义路径 */
    PDEBUG_OBJECT DebugObject = DebugProcess->DebugObject;
    if (!DebugObject) {
        if (g_OrigDbgkCreateThread) g_OrigDbgkCreateThread(Thread);
        return;
    }

    DBGKM_APIMSG ApiMessage = { 0 };
    ApiMessage.u.CreateThread.SubSystemKey = 0;
    ApiMessage.u.CreateThread.StartAddress = NULL; /* TODO: 从ETHREAD读取Win32StartAddress */
    ApiMessage.h.u1.Length = 0x400018;
    ApiMessage.h.u2.ZeroInit = LPC_DEBUG_EVENT;
    ApiMessage.ApiNumber = DbgKmCreateThreadApi;

    DbgkpSendApiMessage(Process, TRUE, &ApiMessage);
}

/**
 * @brief [Fake] DbgkExitThread
 */
VOID NTAPI Fake_DbgkExitThread(NTSTATUS ExitStatus)
{
    PEPROCESS Process = PsGetCurrentProcess();
    PDEBUG_PROCESS DebugProcess;

    if (!IsDebugTargetProcess(Process, &DebugProcess)) {
        DBG_FAKE_PRINT_ONCE(HOOK_DbgkExitThread_Dbg, "Fake_DbgkExitThread");
        if (g_OrigDbgkExitThread)
            g_OrigDbgkExitThread(ExitStatus);
        return;
    }

    if (!DebugProcess->DebugObject) {
        if (g_OrigDbgkExitThread) g_OrigDbgkExitThread(ExitStatus);
        return;
    }

    DBGKM_APIMSG ApiMessage = { 0 };
    ApiMessage.u.ExitThread.ExitStatus = ExitStatus;
    ApiMessage.h.u1.Length = 0x34000C;
    ApiMessage.h.u2.ZeroInit = LPC_DEBUG_EVENT;
    ApiMessage.ApiNumber = DbgKmExitThreadApi;

    DbgkpSendApiMessage(Process, TRUE, &ApiMessage);
}

/**
 * @brief [Fake] DbgkExitProcess
 */
VOID NTAPI Fake_DbgkExitProcess(NTSTATUS ExitStatus)
{
    PEPROCESS Process = PsGetCurrentProcess();
    PDEBUG_PROCESS DebugProcess;

    if (!IsDebugTargetProcess(Process, &DebugProcess)) {
        DBG_FAKE_PRINT_ONCE(HOOK_DbgkExitProcess_Dbg, "Fake_DbgkExitProcess");
        if (g_OrigDbgkExitProcess)
            g_OrigDbgkExitProcess(ExitStatus);
        return;
    }

    if (!DebugProcess->DebugObject) {
        if (g_OrigDbgkExitProcess) g_OrigDbgkExitProcess(ExitStatus);
        return;
    }

    DBGKM_APIMSG ApiMessage = { 0 };
    ApiMessage.u.ExitProcess.ExitStatus = ExitStatus;
    ApiMessage.h.u1.Length = 0x34000C;
    ApiMessage.h.u2.ZeroInit = LPC_DEBUG_EVENT;
    ApiMessage.ApiNumber = DbgKmExitProcessApi;

    DbgkpSendApiMessage(Process, FALSE, &ApiMessage);
}

/**
 * @brief [Fake] DbgkMapViewOfSection — DLL加载事件
 */
VOID NTAPI Fake_DbgkMapViewOfSection(
    IN PEPROCESS Process,
    IN PVOID SectionObject,
    IN PVOID BaseAddress,
    IN ULONG SectionOffset,
    IN ULONG_PTR ViewSize)
{
    DBG_FAKE_PRINT_ONCE(HOOK_DbgkMapViewOfSection_Dbg, "Fake_DbgkMapViewOfSection");
    PDEBUG_PROCESS DebugProcess;

    if (!IsDebugTargetProcess(Process, &DebugProcess)) {
        if (g_OrigDbgkMapViewOfSection)
            g_OrigDbgkMapViewOfSection(Process, SectionObject, BaseAddress, SectionOffset, ViewSize);
        return;
    }

    if (!DebugProcess->DebugObject) {
        if (g_OrigDbgkMapViewOfSection)
            g_OrigDbgkMapViewOfSection(Process, SectionObject, BaseAddress, SectionOffset, ViewSize);
        return;
    }

    DBGKM_APIMSG ApiMsg = { 0 };
    PDBGKM_LOAD_DLL LoadDll = &ApiMsg.u.LoadDll;

    LoadDll->FileHandle = NULL;  /* TODO: DbgkpSectionToFileHandle */
    LoadDll->BaseOfDll = BaseAddress;
    LoadDll->DebugInfoFileOffset = 0;
    LoadDll->DebugInfoSize = 0;
    LoadDll->NamePointer = NULL;

    __try {
        PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)RtlImageNtHeader(BaseAddress);
        if (NtHeaders) {
            LoadDll->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
            LoadDll->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LoadDll->DebugInfoFileOffset = 0;
        LoadDll->DebugInfoSize = 0;
    }

    ApiMsg.h.u1.Length = 0x500028;
    ApiMsg.h.u2.ZeroInit = LPC_DEBUG_EVENT;
    ApiMsg.ApiNumber = DbgKmLoadDllApi;

    DbgkpSendApiMessage(Process, TRUE, &ApiMsg);

    if (LoadDll->FileHandle)
        ObCloseHandle(LoadDll->FileHandle, KernelMode);
}

/**
 * @brief [Fake] DbgkUnMapViewOfSection — DLL卸载事件
 */
VOID NTAPI Fake_DbgkUnMapViewOfSection(
    IN PEPROCESS Process,
    IN PVOID BaseAddress)
{
    DBG_FAKE_PRINT_ONCE(HOOK_DbgkUnMapViewOfSection_Dbg, "Fake_DbgkUnMapViewOfSection");
    PDEBUG_PROCESS DebugProcess;

    if (!IsDebugTargetProcess(Process, &DebugProcess)) {
        if (g_OrigDbgkUnMapViewOfSection)
            g_OrigDbgkUnMapViewOfSection(Process, BaseAddress);
        return;
    }

    if (!DebugProcess->DebugObject) {
        if (g_OrigDbgkUnMapViewOfSection)
            g_OrigDbgkUnMapViewOfSection(Process, BaseAddress);
        return;
    }

    DBGKM_APIMSG ApiMsg = { 0 };
    ApiMsg.u.UnloadDll.BaseAddress = BaseAddress;
    ApiMsg.h.u1.Length = 0x380010;
    ApiMsg.h.u2.ZeroInit = LPC_DEBUG_EVENT;
    ApiMsg.ApiNumber = DbgKmUnloadDllApi;

    DbgkpSendApiMessage(Process, TRUE, &ApiMsg);
}

/**
 * @brief [Fake] DbgkpQueueMessage — 将调试事件插入事件队列
 */
NTSTATUS NTAPI Fake_DbgkpQueueMessage(
    IN PEPROCESS Process,
    IN PETHREAD Thread,
    IN PDBGKM_APIMSG Message,
    IN ULONG Flags,
    IN PDEBUG_OBJECT TargetObject OPTIONAL)
{
    DBG_FAKE_PRINT_ONCE(HOOK_DbgkpQueueMessage_Dbg, "Fake_DbgkpQueueMessage");
    PDEBUG_EVENT DebugEvent;
    DEBUG_EVENT LocalDebugEvent;
    PDEBUG_OBJECT DebugObject;
    NTSTATUS Status;
    BOOLEAN NewEvent;
    PDEBUG_PROCESS DebugProcess;

    NewEvent = (Flags & DEBUG_EVENT_NOWAIT) ? TRUE : FALSE;
    if (NewEvent) {
        DebugEvent = (PDEBUG_EVENT)ExAllocatePoolWithTag(
            NonPagedPool, sizeof(DEBUG_EVENT), 'EgbD');
        if (!DebugEvent) return STATUS_INSUFFICIENT_RESOURCES;

        DebugEvent->Flags = Flags | DEBUG_EVENT_INACTIVE;
        ObReferenceObject(Thread);
        ObReferenceObject(Process);
        DebugEvent->BackoutThread = PsGetCurrentThread();
        DebugObject = TargetObject;
    }
    else {
        DebugEvent = &LocalDebugEvent;
        DebugEvent->Flags = Flags;

        ExAcquireFastMutex(&g_DbgkpProcessDebugPortMutex);

        if (IsDebugTargetProcess(Process, &DebugProcess)) {
            DebugObject = DebugProcess->DebugObject;
        }
        else {
            DebugObject = NULL;
        }
    }

    /* 填充事件 */
    KeInitializeEvent(&DebugEvent->ContinueEvent, SynchronizationEvent, FALSE);
    DebugEvent->Process = Process;
    DebugEvent->Thread = Thread;
    DebugEvent->ApiMsg = *Message;
    DebugEvent->ClientId.UniqueProcess = PsGetProcessId(Process);
    DebugEvent->ClientId.UniqueThread = PsGetThreadId(Thread);

    if (!DebugObject) {
        Status = STATUS_PORT_NOT_SET;
    }
    else {
        ExAcquireFastMutex(&DebugObject->Mutex);
        if (!(DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING)) {
            InsertTailList(&DebugObject->EventList, &DebugEvent->EventList);
            if (!NewEvent) {
                KeSetEvent(&DebugObject->EventsPresent, IO_NO_INCREMENT, FALSE);
            }
            Status = STATUS_SUCCESS;
        }
        else {
            Status = STATUS_DEBUGGER_INACTIVE;
        }
        ExReleaseFastMutex(&DebugObject->Mutex);
    }

    if (!NewEvent) {
        ExReleaseFastMutex(&g_DbgkpProcessDebugPortMutex);
        if (NT_SUCCESS(Status)) {
            KeWaitForSingleObject(&DebugEvent->ContinueEvent,
                Executive, KernelMode, FALSE, NULL);
            *Message = DebugEvent->ApiMsg;
            Status = DebugEvent->Status;
        }
    }
    else {
        if (!NT_SUCCESS(Status)) {
            ObDereferenceObject(Thread);
            ObDereferenceObject(Process);
            ExFreePoolWithTag(DebugEvent, 'EgbD');
        }
    }

    return Status;
}

/**
 * @brief [Fake] DbgkpCloseObject — 调试对象句柄关闭回调
 */
VOID NTAPI Fake_DbgkpCloseObject(
    IN PEPROCESS Process,
    IN PVOID Object,
    IN ACCESS_MASK GrantedAccess,
    IN ULONG_PTR SystemHandleCount)
{
    UNREFERENCED_PARAMETER(GrantedAccess);
    UNREFERENCED_PARAMETER(Process);

    PDEBUG_OBJECT DebugObject = (PDEBUG_OBJECT)Object;
    PDEBUG_EVENT DebugEvent;
    PLIST_ENTRY ListPtr;
    BOOLEAN Deref;
    PDEBUG_OBJECT Port;
    PDEBUG_PROCESS DebugProcess;

    if (SystemHandleCount > 1) return;

    ExAcquireFastMutex(&DebugObject->Mutex);
    DebugObject->Flags |= DEBUG_OBJECT_DELETE_PENDING;
    ListPtr = DebugObject->EventList.Flink;
    InitializeListHead(&DebugObject->EventList);
    ExReleaseFastMutex(&DebugObject->Mutex);

    KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);

    /* 遍历所有进程, 清除引用此调试对象的端口 */
    if (!g_pfnPsGetNextProcess) goto skip_process_scan;
    for (PEPROCESS Proc = PsGetNextProcess(NULL);
        Proc != NULL;
        Proc = PsGetNextProcess(Proc))
    {
        if (IsDebugTargetProcess(Proc, &DebugProcess)) {
            Port = DebugProcess->DebugObject;
        }
        else {
            Port = NULL;
        }

        if (Port == DebugObject) {
            Deref = FALSE;
            ExAcquireFastMutex(&g_DbgkpProcessDebugPortMutex);
            if (IsDebugTargetProcess(Proc, &DebugProcess) &&
                DebugProcess->DebugObject == DebugObject)
            {
                Deref = TRUE;
            }
            ExReleaseFastMutex(&g_DbgkpProcessDebugPortMutex);

            if (Deref) {
                DbgkpMarkProcessPeb(Proc);
                if (DebugObject->Flags & DEBUG_OBJECT_KILL_ON_CLOSE) {
                    /* PsTerminateProcess removed: no reliable resolve on all builds */
                }
            }
        }
    }

    /* 唤醒所有被移除的事件线程 */
skip_process_scan:
    while (ListPtr != &DebugObject->EventList) {
        DebugEvent = CONTAINING_RECORD(ListPtr, DEBUG_EVENT, EventList);
        ListPtr = ListPtr->Flink;
        DebugEvent->Status = STATUS_DEBUGGER_INACTIVE;
        DbgkpWakeTarget(DebugEvent);
    }

    DeleteDebugProcess(DebugObject);
}


/* ========================================================================
 *  Section 5: 断点管理 — Guest侧通过CPUID超级调用下发到VMM
 * ======================================================================== */

 /**
  * @brief 获取目标进程的CR3
  */
static ULONG64 DbgGetProcessCr3(ULONG64 TargetPid)
{
    PEPROCESS targetProc = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)TargetPid, &targetProc);
    if (!NT_SUCCESS(status) || !targetProc) return 0;

    /* EPROCESS->DirectoryTableBase at offset 0x28 (Win10 x64) */
    ULONG64 cr3 = *(PULONG64)((PUCHAR)targetProc + 0x28);
    ObDereferenceObject(targetProc);
    return cr3;
}

/**
 * @brief 通过CPUID超级调用发送调试命令到VMM
 */
static NTSTATUS DbgFireHypercall(ULONG Command, PHV_DEBUG_CONTEXT ctx)
{
    if (!g_HvDebugContext) return STATUS_NOT_INITIALIZED;

    ExAcquireFastMutex(&g_HvDebugMutex);

    g_HvDebugContext->Command = Command;
    g_HvDebugContext->TargetCr3 = ctx->TargetCr3;
    g_HvDebugContext->Address = ctx->Address;
    g_HvDebugContext->DrIndex = ctx->DrIndex;
    g_HvDebugContext->Type = ctx->Type;
    g_HvDebugContext->Length = ctx->Length;
    g_HvDebugContext->OriginalByte = ctx->OriginalByte;
    g_HvDebugContext->Status = 1;  /* Pending */

    int regs[4] = { 0 };
    __cpuidex(regs, CPUID_HV_DEBUG_OP, Command);

    NTSTATUS status = (g_HvDebugContext->Status == 0) ?
        STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    ctx->OriginalByte = g_HvDebugContext->OriginalByte;
    ctx->Status = g_HvDebugContext->Status;

    ExReleaseFastMutex(&g_HvDebugMutex);
    return status;
}

NTSTATUS DbgSetHardwareBreakpoint(PHW_BREAKPOINT_REQUEST Request)
{
    if (!Request || Request->DrIndex > 3) return STATUS_INVALID_PARAMETER;

    Request->TargetCr3 = DbgGetProcessCr3(Request->TargetPid);
    if (Request->TargetCr3 == 0) return STATUS_NOT_FOUND;

    HV_DEBUG_CONTEXT ctx = { 0 };
    ctx.Command = HV_DBG_SET_HW_BP;
    ctx.TargetCr3 = Request->TargetCr3;
    ctx.Address = Request->Address;
    ctx.DrIndex = Request->DrIndex;
    ctx.Type = Request->Type;
    ctx.Length = Request->Length;

    return DbgFireHypercall(HV_DBG_SET_HW_BP, &ctx);
}

NTSTATUS DbgRemoveHardwareBreakpoint(PHW_BREAKPOINT_REQUEST Request)
{
    if (!Request || Request->DrIndex > 3) return STATUS_INVALID_PARAMETER;

    Request->TargetCr3 = DbgGetProcessCr3(Request->TargetPid);
    if (Request->TargetCr3 == 0) return STATUS_NOT_FOUND;

    HV_DEBUG_CONTEXT ctx = { 0 };
    ctx.Command = HV_DBG_REMOVE_HW_BP;
    ctx.TargetCr3 = Request->TargetCr3;
    ctx.Address = Request->Address;
    ctx.DrIndex = Request->DrIndex;

    return DbgFireHypercall(HV_DBG_REMOVE_HW_BP, &ctx);
}

NTSTATUS DbgSetSoftwareBreakpoint(PSW_BREAKPOINT_REQUEST Request)
{
    if (!Request) return STATUS_INVALID_PARAMETER;

    Request->TargetCr3 = DbgGetProcessCr3(Request->TargetPid);
    if (Request->TargetCr3 == 0) return STATUS_NOT_FOUND;

    HV_DEBUG_CONTEXT ctx = { 0 };
    ctx.Command = HV_DBG_SET_SW_BP;
    ctx.TargetCr3 = Request->TargetCr3;
    ctx.Address = Request->Address;

    NTSTATUS status = DbgFireHypercall(HV_DBG_SET_SW_BP, &ctx);
    Request->OriginalByte = ctx.OriginalByte;
    return status;
}

NTSTATUS DbgRemoveSoftwareBreakpoint(PSW_BREAKPOINT_REQUEST Request)
{
    if (!Request) return STATUS_INVALID_PARAMETER;

    Request->TargetCr3 = DbgGetProcessCr3(Request->TargetPid);
    if (Request->TargetCr3 == 0) return STATUS_NOT_FOUND;

    HV_DEBUG_CONTEXT ctx = { 0 };
    ctx.Command = HV_DBG_REMOVE_SW_BP;
    ctx.TargetCr3 = Request->TargetCr3;
    ctx.Address = Request->Address;
    ctx.OriginalByte = Request->OriginalByte;

    return DbgFireHypercall(HV_DBG_REMOVE_SW_BP, &ctx);
}

NTSTATUS DbgReadSoftwareBreakpoint(PSW_BREAKPOINT_REQUEST Request)
{
    if (!Request) return STATUS_INVALID_PARAMETER;

    Request->TargetCr3 = DbgGetProcessCr3(Request->TargetPid);
    if (Request->TargetCr3 == 0) return STATUS_NOT_FOUND;

    HV_DEBUG_CONTEXT ctx = { 0 };
    ctx.Command = HV_DBG_READ_SW_BP;
    ctx.TargetCr3 = Request->TargetCr3;
    ctx.Address = Request->Address;

    NTSTATUS status = DbgFireHypercall(HV_DBG_READ_SW_BP, &ctx);
    Request->OriginalByte = ctx.OriginalByte;
    return status;
}


/* ========================================================================
 *  Section 6: VMM侧处理器 — VMEXIT中响应CPUID_HV_DEBUG_OP
 *
 *  此函数在SVM.cpp的SvHandleVmExit中被调用:
 *    case VMEXIT_CPUID:
 *      if (leaf == CPUID_HV_DEBUG_OP) {
 *          HvHandleDebugOp(vpData);
 *      }
 * ======================================================================== */

VOID HvHandleDebugOp(PVCPU_CONTEXT vpData)
{
    if (!vpData || !g_HvDebugContext) {
        if (vpData) vpData->Guest_gpr.Rax = (UINT64)-1;
        return;
    }

    PHV_DEBUG_CONTEXT ctx = g_HvDebugContext;
    PVMCB vmcb = &vpData->Guestvmcb;

    switch (ctx->Command)
    {
    case HV_DBG_SET_HW_BP:
    {
        /*
         * 设置硬件断点:
         * 修改Guest VMCB中保存的DR0-DR3和DR7
         * VMRUN恢复Guest时会自动加载这些值
         */
        ULONG64 addr = ctx->Address;
        ULONG drIdx = ctx->DrIndex;
        ULONG type = ctx->Type;
        ULONG len = ctx->Length;

        if (drIdx > 3) { ctx->Status = -1; break; }

        /* 设置DR0-DR3 */
        /* DR0-DR3 not in VMCB StateSaveArea,
           write via __writedr in VMEXIT context,
           VMRUN will auto-load them to Guest */
        switch (drIdx) {
        case 0: __writedr(0, (ULONG_PTR)addr); break;
        case 1: __writedr(1, (ULONG_PTR)addr); break;
        case 2: __writedr(2, (ULONG_PTR)addr); break;
        case 3: __writedr(3, (ULONG_PTR)addr); break;
        }

        /* Clear DR6 hit bit for this breakpoint */
        vmcb->StateSaveArea.Dr6 &= ~(1ULL << drIdx);

        /* 设置DR7: 启用对应DR寄存器的断点 */
        ULONG64 dr7 = vmcb->StateSaveArea.Dr7;

        /* 清除旧的设置 */
        dr7 &= ~(3ULL << (drIdx * 2));          /* 清除L/G位 */
        dr7 &= ~(0xFULL << (16 + drIdx * 4));   /* 清除Condition和Length */

        /* 设置新值 */
        dr7 |= (1ULL << (drIdx * 2));            /* 局部启用 */
        dr7 |= ((ULONG64)type << (16 + drIdx * 4));     /* 条件 */
        dr7 |= ((ULONG64)len << (18 + drIdx * 4));      /* 长度 */

        vmcb->StateSaveArea.Dr7 = dr7;

        ctx->Status = 0;  /* 成功 */
        SvmDebugPrint("[VMM] HW BP SET: DR%d=0x%llX type=%d len=%d DR7=0x%llX\n",
            drIdx, addr, type, len, dr7);
        break;
    }

    case HV_DBG_REMOVE_HW_BP:
    {
        ULONG drIdx = ctx->DrIndex;
        if (drIdx > 3) { ctx->Status = -1; break; }

        /* 清除DR7中的启用位 */
        ULONG64 dr7 = vmcb->StateSaveArea.Dr7;
        dr7 &= ~(3ULL << (drIdx * 2));
        dr7 &= ~(0xFULL << (16 + drIdx * 4));
        vmcb->StateSaveArea.Dr7 = dr7;

        ctx->Status = 0;
        SvmDebugPrint("[VMM] HW BP REMOVE: DR%d DR7=0x%llX\n", drIdx, dr7);
        break;
    }

    case HV_DBG_SET_SW_BP:
    case HV_DBG_REMOVE_SW_BP:
    case HV_DBG_READ_SW_BP:
    {
        /*
         * 软件断点通过NPT Execute/Read分离实现:
         * 执行视图: 目标地址为CC (INT3)
         * 读取视图: 目标地址为原始指令
         *
         * 这需要对目标地址所在页做NPT页表操作:
         *   1. 拆分大页为4KB页
         *   2. 创建Execute页(含INT3)和Read页(原始)
         *   3. 根据缺页类型(执行/读写)切换NPT映射
         *
         * 由于这与现有的NPT Hook基础设施深度耦合,
         * 具体实现需要在NPT.cpp中扩展。
         * 这里先标记为成功, 实际的NPT操作通过Guest侧
         * HvMemory的物理内存读写完成。
         */
        ULONG64 targetCr3 = ctx->TargetCr3;
        ULONG64 targetVa = ctx->Address;

        if (targetCr3 == 0 || targetVa == 0) {
            ctx->Status = -3;
            break;
        }

        /* Translate target VA to PA using page table walk */
        /* (Reuse TranslateGuestVaToPa from HvMemory.cpp) */
        extern ULONG64 TranslateGuestVaToPa_Ext(ULONG64, ULONG64);

        if (ctx->Command == HV_DBG_SET_SW_BP) {
            /* Read original byte first */
            PHYSICAL_ADDRESS pa;
            pa.QuadPart = TranslateGuestVaToPa_Ext(targetCr3, targetVa);
            if (pa.QuadPart == 0) { ctx->Status = -4; break; }

            PVOID mapped = MmGetVirtualForPhysical(pa);
            if (!mapped) { ctx->Status = -5; break; }

            ULONG offset = (ULONG)(targetVa & 0xFFF);
            ctx->OriginalByte = *((PUCHAR)mapped + offset);
            *((PUCHAR)mapped + offset) = 0xCC;  /* INT3 */
            ctx->Status = 0;
            SvmDebugPrint("[VMM] SW BP SET: addr=0x%llX orig=0x%02X\n",
                targetVa, ctx->OriginalByte);
        }
        else if (ctx->Command == HV_DBG_REMOVE_SW_BP) {
            PHYSICAL_ADDRESS pa;
            pa.QuadPart = TranslateGuestVaToPa_Ext(targetCr3, targetVa);
            if (pa.QuadPart == 0) { ctx->Status = -4; break; }

            PVOID mapped = MmGetVirtualForPhysical(pa);
            if (!mapped) { ctx->Status = -5; break; }

            ULONG offset = (ULONG)(targetVa & 0xFFF);
            *((PUCHAR)mapped + offset) = ctx->OriginalByte;
            ctx->Status = 0;
            SvmDebugPrint("[VMM] SW BP REMOVE: addr=0x%llX restored=0x%02X\n",
                targetVa, ctx->OriginalByte);
        }
        else { /* HV_DBG_READ_SW_BP */
            PHYSICAL_ADDRESS pa;
            pa.QuadPart = TranslateGuestVaToPa_Ext(targetCr3, targetVa);
            if (pa.QuadPart == 0) { ctx->Status = -4; break; }

            PVOID mapped = MmGetVirtualForPhysical(pa);
            if (!mapped) { ctx->Status = -5; break; }

            ULONG offset = (ULONG)(targetVa & 0xFFF);
            ctx->OriginalByte = *((PUCHAR)mapped + offset);
            ctx->Status = 0;
            SvmDebugPrint("[VMM] SW BP READ: addr=0x%llX byte=0x%02X\n",
                targetVa, ctx->OriginalByte);
        }
        break;
    }

    default:
        ctx->Status = -2;  /* 未知命令 */
        break;
    }

    vpData->Guest_gpr.Rax = (UINT64)ctx->Status;
}


/* ========================================================================
 *  Section 7: IOCTL 派发
 * ======================================================================== */

NTSTATUS DbgDispatchIoctl(
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputLength,
    PVOID OutputBuffer,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;
    *BytesReturned = 0;

    switch (IoControlCode)
    {
    case IOCTL_DBG_REGISTER_DEBUGGER:
    {
        if (InputLength < sizeof(DBG_REGISTER_REQUEST))
            return STATUS_BUFFER_TOO_SMALL;

        PDBG_REGISTER_REQUEST req = (PDBG_REGISTER_REQUEST)InputBuffer;
        PEPROCESS Process;
        Status = PsLookupProcessByProcessId((HANDLE)req->DebuggerPid, &Process);
        if (NT_SUCCESS(Status)) {
            if (RegisterDebugger(Process, (HANDLE)req->DebuggerPid)) {
                /* 同时将调试器加入保护列表 */
                AddProtectedPid((HANDLE)req->DebuggerPid);
                Status = STATUS_SUCCESS;
            }
            else {
                Status = STATUS_INSUFFICIENT_RESOURCES;
            }
            ObDereferenceObject(Process);
        }
        break;
    }

    case IOCTL_DBG_ATTACH_PROCESS:
    {
        if (InputLength < sizeof(DBG_ATTACH_REQUEST))
            return STATUS_BUFFER_TOO_SMALL;

        /* 附加操作由R3通过NtDebugActiveProcess完成,
           这里可以做额外的预处理(如将目标加入保护列表) */
        PDBG_ATTACH_REQUEST req = (PDBG_ATTACH_REQUEST)InputBuffer;
        AddProtectedPid((HANDLE)req->TargetPid);
        Status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_DBG_DETACH_PROCESS:
    {
        if (InputLength < sizeof(DBG_ATTACH_REQUEST))
            return STATUS_BUFFER_TOO_SMALL;

        PDBG_ATTACH_REQUEST req = (PDBG_ATTACH_REQUEST)InputBuffer;
        RemoveProtectedPid((HANDLE)req->TargetPid);
        Status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_DBG_SET_HW_BREAKPOINT:
    {
        if (InputLength < sizeof(HW_BREAKPOINT_REQUEST))
            return STATUS_BUFFER_TOO_SMALL;

        Status = DbgSetHardwareBreakpoint((PHW_BREAKPOINT_REQUEST)InputBuffer);
        break;
    }

    case IOCTL_DBG_REMOVE_HW_BREAKPOINT:
    {
        if (InputLength < sizeof(HW_BREAKPOINT_REQUEST))
            return STATUS_BUFFER_TOO_SMALL;

        Status = DbgRemoveHardwareBreakpoint((PHW_BREAKPOINT_REQUEST)InputBuffer);
        break;
    }

    case IOCTL_DBG_SET_SW_BREAKPOINT:
    {
        if (InputLength < sizeof(SW_BREAKPOINT_REQUEST) ||
            OutputLength < sizeof(SW_BREAKPOINT_REQUEST))
            return STATUS_BUFFER_TOO_SMALL;

        PSW_BREAKPOINT_REQUEST req = (PSW_BREAKPOINT_REQUEST)InputBuffer;
        Status = DbgSetSoftwareBreakpoint(req);
        if (NT_SUCCESS(Status) && OutputBuffer) {
            RtlCopyMemory(OutputBuffer, req, sizeof(SW_BREAKPOINT_REQUEST));
            *BytesReturned = sizeof(SW_BREAKPOINT_REQUEST);
        }
        break;
    }

    case IOCTL_DBG_REMOVE_SW_BREAKPOINT:
    {
        if (InputLength < sizeof(SW_BREAKPOINT_REQUEST))
            return STATUS_BUFFER_TOO_SMALL;

        Status = DbgRemoveSoftwareBreakpoint((PSW_BREAKPOINT_REQUEST)InputBuffer);
        break;
    }

    case IOCTL_DBG_READ_SW_BREAKPOINT:
    {
        if (InputLength < sizeof(SW_BREAKPOINT_REQUEST) ||
            OutputLength < sizeof(SW_BREAKPOINT_REQUEST))
            return STATUS_BUFFER_TOO_SMALL;

        PSW_BREAKPOINT_REQUEST req = (PSW_BREAKPOINT_REQUEST)InputBuffer;
        Status = DbgReadSoftwareBreakpoint(req);
        if (NT_SUCCESS(Status) && OutputBuffer) {
            RtlCopyMemory(OutputBuffer, req, sizeof(SW_BREAKPOINT_REQUEST));
            *BytesReturned = sizeof(SW_BREAKPOINT_REQUEST);
        }
        break;
    }

    case IOCTL_DBG_CONTINUE:
    {
        /* NtDebugContinue is handled by Fake_NtDebugContinue via NPT Hook.
           This IOCTL is reserved for future direct-IOCTL continue path. */
        Status = STATUS_SUCCESS;
        break;
    }

    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return Status;
}



/* ========================================================================
 *  Section 8: NPT Hook注册 — 调试相关函数
 *
 *  解决三个关键问题:
 *    1. Nt*调试函数位于ntoskrnl的PAGE段(可分页), MmGetPhysicalAddress
 *       在页面换出时返回0 → 使用MDL锁定页面强制驻留
 *    2. Dbgk*函数在Win10 19041上不是标准导出 → PE导出表扫描
 *    3. Dbgk*函数不在导出表中 → 从已知Nt*调试函数出发,
 *       沿CALL指令链逐级深入, 通过函数特征签名识别目标
 * ======================================================================== */

 /* ZwQuerySystemInformation未在WDK标准头文件中声明 */
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

/* ---- MDL页面锁定: 防止PAGE段代码被换出 ---- */
#define DBG_MAX_MDLS 256
static PMDL  g_DebugPageMdls[DBG_MAX_MDLS] = { 0 };
static ULONG g_DebugMdlCount = 0;

/**
 * @brief 锁定页面到物理内存 (通用版本)
 *
 * 安全条件: 地址必须在 ntoskrnl 映像范围内 (由调用者保证或此函数验证)。
 * ntoskrnl 映像内的所有段 (含 PAGE 段) 都有有效 PTE, 可安全锁定。
 *
 * @param Address 要锁定的地址
 * @return TRUE=成功, FALSE=失败
 */
static BOOLEAN LockPageForHook(PVOID Address)
{
    PVOID pageBase = (PVOID)((ULONG_PTR)Address & ~(PAGE_SIZE - 1));

    /* [PATCH] 先检查是否已锁定(去重), 再检查限额
     * 否则MDL槽位用完后, 已锁定的页面也会返回FALSE → 导致后续逻辑skip */
    for (ULONG i = 0; i < g_DebugMdlCount; i++) {
        if (g_DebugPageMdls[i] && MmGetMdlVirtualAddress(g_DebugPageMdls[i]) == pageBase)
            return TRUE;
    }

    if (g_DebugMdlCount >= DBG_MAX_MDLS) return FALSE;

    /* [FIX-BSOD-0x50] 地址必须在ntoskrnl映像范围内。
     * ntoskrnl映像内的所有段(含pageable的PAGE段)都有有效PTE,
     * MmProbeAndLockPages可以安全地将换出页面换入。
     * 但映像范围外或者DISCARDABLE段释放后的地址没有PTE, 锁定会BSOD。 */
    if (!IsWithinNtoskrnl(pageBase)) {
        SvmDebugPrint("[DebugApi] LockPageForHook: %p outside ntoskrnl, SKIP\n", Address);
        return FALSE;
    }

    /* [FIX-BSOD-0x50-v2] 即使在ntoskrnl范围内, INIT段和DISCARDABLE段
     * 在驱动初始化完成后可能被系统释放, PTE变为无效。
     * MmProbeAndLockPages 对无效PTE会触发 Bugcheck 0x50,
     * __try/__except 无法捕获此类内核bugcheck。
     * 额外检查: 如果页面不在代码段且未驻留 → 拒绝 */
    if (!IsWithinCodeRange(pageBase) && !MmIsAddressValid(pageBase)) {
        SvmDebugPrint("[DebugApi] LockPageForHook: %p in ntoskrnl but not resident (INIT/DISCARD?), SKIP\n", Address);
        return FALSE;
    }

    PMDL mdl = IoAllocateMdl(pageBase, PAGE_SIZE, FALSE, FALSE, NULL);
    if (!mdl) return FALSE;

    /* [FIX-BSOD-0x50-v3] MmProbeAndLockPages 对无效PTE触发Bugcheck 0x50,
     * __try/__except 无法捕获 bugcheck。
     * 安全策略: 先尝试读取页面触发软缺页, 如果软缺页也失败则跳过 */
    __try {
        volatile UCHAR probe = *(volatile UCHAR*)pageBase;
        UNREFERENCED_PARAMETER(probe);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        SvmDebugPrint("[DebugApi] LockPageForHook: %p probe read failed (no valid PTE), SKIP\n", Address);
        return FALSE;
    }

    /* 页面已驻留 (软缺页成功或本已驻留), MmProbeAndLockPages 安全 */
    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        SvmDebugPrint("[DebugApi] LockPageForHook: %p MmProbeAndLockPages FAILED (exception)\n", Address);
        return FALSE;
    }

    g_DebugPageMdls[g_DebugMdlCount++] = mdl;
    //SvmDebugPrint("[DebugApi] Locked page for %p (MDL#%lu)\n", Address, g_DebugMdlCount);
    return TRUE;
}

/**
 * @brief 锁定页面 (严格版本, 用于CALL-chain扫描器发现的间接目标)
 *
 * 与 LockPageForHook 相比增加了额外安全检查:
 *   - 地址必须在代码段VirtualSize范围内, 或者当前已驻留
 *   - 防止CALL-chain扫描跟随到.reloc/.rsrc等非代码段的虚假目标
 *
 * 注意: 直接从SSDT/导出表解析的已知函数地址应该用 LockPageForHook,
 *       因为PAGE段函数地址是有效的, 只是可能暂时换出。
 */
static BOOLEAN LockPageForHookStrict(PVOID Address)
{
    PVOID pageBase = (PVOID)((ULONG_PTR)Address & ~(PAGE_SIZE - 1));

    if (!IsWithinCodeRange(pageBase)) {
        if (!MmIsAddressValid(pageBase)) {
            /* 不在代码段且未驻留 → 可能是.reloc/.rsrc等无代码段, 拒绝 */
            return FALSE;
        }
        /* 不在代码段但已驻留 → 允许 (数据段已被触及) */
    }

    return LockPageForHook(Address);
}

VOID UnlockAllDebugPages()
{
    for (ULONG i = 0; i < g_DebugMdlCount; i++) {
        if (g_DebugPageMdls[i]) {
            MmUnlockPages(g_DebugPageMdls[i]);
            IoFreeMdl(g_DebugPageMdls[i]);
            g_DebugPageMdls[i] = NULL;
        }
    }
    g_DebugMdlCount = 0;
}


/* ---- ntoskrnl基址与导出表扫描 ---- */

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section; PVOID MappedBase; PVOID ImageBase;
    ULONG ImageSize; ULONG Flags; USHORT LoadOrderIndex;
    USHORT InitOrderIndex; USHORT LoadCount; USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

static PVOID g_NtoskrnlBase = NULL;
static ULONG g_NtoskrnlSize = 0;

static PVOID GetNtoskrnlBase(PULONG OutSize)
{
    if (g_NtoskrnlBase) {
        if (OutSize) *OutSize = g_NtoskrnlSize;
        return g_NtoskrnlBase;
    }
    ULONG bufSize = 0;
    ZwQuerySystemInformation(11, NULL, 0, &bufSize);
    if (bufSize == 0) return NULL;

    PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, 'NtBs');
    if (!mods) return NULL;

    NTSTATUS st = ZwQuerySystemInformation(11, mods, bufSize, &bufSize);
    if (NT_SUCCESS(st) && mods->NumberOfModules > 0) {
        g_NtoskrnlBase = mods->Modules[0].ImageBase;
        g_NtoskrnlSize = mods->Modules[0].ImageSize;
    }
    ExFreePoolWithTag(mods, 'NtBs');

    if (OutSize) *OutSize = g_NtoskrnlSize;
    return g_NtoskrnlBase;
}

static PVOID ScanNtoskrnlExport(PCSTR FuncName)
{
    ULONG ntSize = 0;
    PVOID ntBase = GetNtoskrnlBase(&ntSize);
    if (!ntBase || ntSize == 0) return NULL;

    __try {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ntBase;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
        PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)((PUCHAR)ntBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return NULL;

        ULONG expRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG expSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (expRva == 0) return NULL;

        PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ntBase + expRva);
        PULONG pNames = (PULONG)((PUCHAR)ntBase + pExp->AddressOfNames);
        PULONG pFunctions = (PULONG)((PUCHAR)ntBase + pExp->AddressOfFunctions);
        PUSHORT pOrdinals = (PUSHORT)((PUCHAR)ntBase + pExp->AddressOfNameOrdinals);

        for (ULONG i = 0; i < pExp->NumberOfNames; i++) {
            PCSTR name = (PCSTR)((PUCHAR)ntBase + pNames[i]);
            if (strcmp(name, FuncName) == 0) {
                ULONG funcRva = pFunctions[pOrdinals[i]];
                if (funcRva >= expRva && funcRva < expRva + expSize) return NULL;
                return (PVOID)((PUCHAR)ntBase + funcRva);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return NULL;
}


/* ========================================================================
 *  ApiNumber位掩码检测 — 扫描函数体中所有DBGKM_APIMSG.ApiNumber赋值
 *
 *  返回位掩码: bit N = 函数体中存在 mov [xxx], N (N=1~6)
 *  用于区分:
 *    DbgkCreateThread:      包含 bit1|bit2|bit5 (CreateThread+CreateProcess+LoadDll)
 *    DbgkMapViewOfSection:  只有 bit5 (LoadDll)
 *    DbgkExitThread:        只有 bit3
 *    DbgkExitProcess:       只有 bit4
 *    DbgkUnMapViewOfSection:只有 bit6
 * ======================================================================== */

#define API_BIT(n) (1U << (n))

static ULONG DetectDbgkApiNumbers(PUCHAR Func, ULONG FuncSize)
{
    ULONG mask = 0;
    if (FuncSize < 8) return 0;

    __try {
        for (ULONG b = 3; b < FuncSize - 3; b++) {
            if (Func[b] >= 1 && Func[b] <= 6 &&
                Func[b + 1] == 0 && Func[b + 2] == 0 && Func[b + 3] == 0) {
                /* 验证前方2-7字节内有C7操作码 */
                for (ULONG k = 2; k <= 7 && k <= b; k++) {
                    if (Func[b - k] == 0xC7) {
                        mask |= API_BIT(Func[b]);
                        break;
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return mask;
}


/* ========================================================================
 *  CALL-chain scanner — 从已知函数沿CALL指令链定位未导出Dbgk*函数
 *
 *  核心思路:
 *    NtDebugActiveProcess (已知)
 *      → E8 CALL → DbgkpSetProcessDebugObject (未知, 通过排除法识别)
 *        → E8 CALL → DbgkpPostFakeProcessCreateMessages
 *          → E8 CALL → DbgkpPostFakeThreadMessages
 *            → E8 CALL → DbgkpQueueMessage (通过函数签名识别)
 *
 *  找到DbgkpQueueMessage后, 反向扫描ntoskrnl中所有引用它的函数,
 *  通过函数特征区分DbgkForwardException/DbgkCreateThread等。
 * ======================================================================== */

 /* ---- 代码段有效范围表 —— 防止EnsurePageLocked在无PTE区域触发BSOD ----
  *
  * PE section的VirtualSize范围内的页面保证有PTE(可能换出但MmProbeAndLockPages可换入)。
  * 超出VirtualSize的尾部填充区和节间间隙可能无PTE, MmProbeAndLockPages会导致不可恢复的0x50。
  * 此表在扫描前从PE节头解析, 用于FindCallersOf中过滤安全可锁定的地址范围。
  */
typedef struct _CODE_VA_RANGE {
    ULONG_PTR Start;
    ULONG_PTR End;   /* Start + VirtualSize (不含尾部对齐填充) */
} CODE_VA_RANGE;

#define MAX_CODE_RANGES 16
static CODE_VA_RANGE g_CodeRanges[MAX_CODE_RANGES] = { 0 };
static ULONG         g_CodeRangeCount = 0;

static VOID InitCodeRanges()
{
    g_CodeRangeCount = 0;
    PVOID ntBase = GetNtoskrnlBase(NULL);
    if (!ntBase || g_NtoskrnlSize == 0) return;

    __try {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ntBase;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return;
        PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)((PUCHAR)ntBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return;

        USHORT numSections = pNt->FileHeader.NumberOfSections;
        PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

        for (USHORT i = 0; i < numSections && g_CodeRangeCount < MAX_CODE_RANGES; i++) {
            if (!(pSec[i].Characteristics & IMAGE_SCN_CNT_CODE) &&
                !(pSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;
            if (pSec[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
                continue;

            ULONG secSize = pSec[i].Misc.VirtualSize;
            if (secSize == 0) secSize = pSec[i].SizeOfRawData;
            if (secSize == 0) continue;

            ULONG_PTR start = (ULONG_PTR)ntBase + pSec[i].VirtualAddress;
            g_CodeRanges[g_CodeRangeCount].Start = start;
            g_CodeRanges[g_CodeRangeCount].End = start + secSize;
            g_CodeRangeCount++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    SvmDebugPrint("[DebugApi] InitCodeRanges: %lu code sections mapped\n", g_CodeRangeCount);
}

/**
 * @brief 检查地址是否在某个代码段的VirtualSize范围内 (有PTE保证, 可安全锁定)
 */
static BOOLEAN IsWithinCodeRange(PVOID Addr)
{
    ULONG_PTR a = (ULONG_PTR)Addr;
    for (ULONG i = 0; i < g_CodeRangeCount; i++) {
        if (a >= g_CodeRanges[i].Start && a < g_CodeRanges[i].End)
            return TRUE;
    }
    return FALSE;
}

#define MAX_CALL_TARGETS 48
#define MAX_SCAN_DEPTH   5

/**
 * @brief 检查地址是否在ntoskrnl映像范围内
 * 防止CALL-chain扫描跟随到无效/换出地址导致BSOD 0x50
 */
static BOOLEAN IsWithinNtoskrnl(PVOID Addr)
{
    if (!g_NtoskrnlBase || g_NtoskrnlSize == 0) return FALSE;
    ULONG_PTR a = (ULONG_PTR)Addr;
    ULONG_PTR base = (ULONG_PTR)g_NtoskrnlBase;
    return (a >= base && a < base + g_NtoskrnlSize);
}

/**
 * @brief 尝试锁定地址所在页面, 失败返回FALSE (用于扫描前的安全检查)
 */
static BOOLEAN EnsurePageLocked(PVOID Addr)
{
    /* EnsurePageLocked 被 CALL-chain 扫描器调用, 使用严格版本 */
    if (!IsWithinNtoskrnl(Addr)) return FALSE;
    return LockPageForHookStrict(Addr);
}

/**
 * @brief 从函数体中收集所有E8相对CALL指令的目标地址
 * 只收集落在ntoskrnl映像范围内的目标, 防止跟随到无效地址
 */
static ULONG CollectCallTargets(PVOID Start, ULONG MaxBytes, PVOID* Out, ULONG MaxOut)
{
    ULONG count = 0;
    PUCHAR p = (PUCHAR)Start;

    /* Start自身必须在ntoskrnl范围内 */
    if (!IsWithinNtoskrnl(Start)) return 0;

    __try {
        for (ULONG i = 0; i < MaxBytes - 5 && count < MaxOut; i++) {
            /* [PATCH] 跨页边界时检查下一页是否可访问 */
            if (i > 0 && (((ULONG_PTR)&p[i]) & 0xFFF) == 0) {
                if (!MmIsAddressValid(&p[i])) {
                    break;
                }
            }

            /* E8 xx xx xx xx = near relative CALL */
            if (p[i] == 0xE8) {
                LONG rel = *(PLONG)(&p[i + 1]);
                PVOID target = (PVOID)(&p[i + 5] + rel);

                /* 目标必须在ntoskrnl映像范围内 — 防止跟随到无效地址导致BSOD */
                if (!IsWithinNtoskrnl(target)) { i += 4; continue; }

                if (!IsWithinCodeRange(target) && !MmIsAddressValid(target)) { i += 4; continue; }

                /* 去重 */
                BOOLEAN dup = FALSE;
                for (ULONG j = 0; j < count; j++) {
                    if (Out[j] == target) { dup = TRUE; break; }
                }
                if (!dup) Out[count++] = target;
                i += 4;
            }
            /* C3 CC = RET followed by int3 padding = 真正的函数结尾
             * 单独的C3可能是错误路径的提前返回, 不应停止扫描 */
            else if (p[i] == 0xC3 && i > 16 && (i + 1 < MaxBytes) && p[i + 1] == 0xCC) {
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return count;
}

/**
 * @brief 解析常见内核导出函数地址, 用于从CALL目标中排除已知函数
 */
static PVOID g_KnownAddrs[32] = { 0 };
static ULONG g_KnownCount = 0;

static VOID InitKnownAddresses()
{
    if (g_KnownCount > 0) return;
    PCWSTR names[] = {
        L"ObReferenceObjectByHandle", L"ObDereferenceObject",
        L"ObfDereferenceObject", L"ObDereferenceObjectDeferDelete",
        L"ExAcquireFastMutex", L"ExReleaseFastMutex",
        L"ExAcquireFastMutexUnsafe", L"ExReleaseFastMutexUnsafe",
        L"KeSetEvent", L"KeWaitForSingleObject", L"KeResetEvent",
        L"PsGetCurrentProcess", L"PsGetProcessId", L"PsGetThreadId",
        L"ObReferenceObject", L"ExAllocatePoolWithTag",
        L"ExFreePoolWithTag", L"KeInitializeEvent",
        L"PsGetCurrentThread", L"ObOpenObjectByPointer",
        L"MmGetPhysicalAddress",
    };
    for (ULONG i = 0; i < ARRAYSIZE(names) && g_KnownCount < 32; i++) {
        UNICODE_STRING us;
        RtlInitUnicodeString(&us, names[i]);
        PVOID addr = MmGetSystemRoutineAddress(&us);
        if (addr) g_KnownAddrs[g_KnownCount++] = addr;
    }
}

static BOOLEAN IsKnownAddress(PVOID Addr)
{
    for (ULONG i = 0; i < g_KnownCount; i++) {
        if (g_KnownAddrs[i] == Addr) return TRUE;
    }
    return FALSE;
}

/**
 * @brief 检查函数是否具有DbgkpQueueMessage的特征签名
 *
 * DbgkpQueueMessage的关键特征:
 *   1. 调用ExAcquireFastMutex (操作DebugObject->Mutex)
 *   2. 调用KeSetEvent (通知EventsPresent)
 *   3. 调用KeWaitForSingleObject (同步事件等待ContinueEvent)
 *   4. 调用ExReleaseFastMutex
 *   5. 函数体较大 (>200字节)
 */
static BOOLEAN IsDbgkpQueueMessageCandidate(PVOID FuncAddr)
{
    /* 锁定目标页面, 防止扫描时触发不可恢复的页错误 */
    if (!EnsurePageLocked(FuncAddr)) return FALSE;

    PVOID calls[MAX_CALL_TARGETS];
    ULONG n = CollectCallTargets(FuncAddr, 0x600, calls, MAX_CALL_TARGETS);
    if (n < 3) return FALSE;

    /* DbgkpQueueMessage特征: 操作DebugObject互斥锁+事件
     * 编译器可能使用Safe或Unsafe版本的FastMutex */
    PCWSTR checkNames[] = {
        L"ExAcquireFastMutex", L"ExAcquireFastMutexUnsafe",
        L"KeSetEvent",
        L"KeWaitForSingleObject",
        L"ExReleaseFastMutex", L"ExReleaseFastMutexUnsafe",
    };
    PVOID checkAddrs[8] = { 0 };
    ULONG checkCount = 0;
    for (ULONG i = 0; i < ARRAYSIZE(checkNames); i++) {
        UNICODE_STRING us;
        RtlInitUnicodeString(&us, checkNames[i]);
        PVOID addr = MmGetSystemRoutineAddress(&us);
        if (addr) checkAddrs[checkCount++] = addr;
    }

    /* 统计匹配的关键API调用数 */
    ULONG matchCount = 0;
    BOOLEAN hasAcquire = FALSE, hasSetEvt = FALSE, hasWait = FALSE, hasRelease = FALSE;
    for (ULONG i = 0; i < n; i++) {
        for (ULONG j = 0; j < checkCount; j++) {
            if (calls[i] == checkAddrs[j]) {
                /* 按类别去重计数 */
                if (j <= 1 && !hasAcquire) { hasAcquire = TRUE; matchCount++; }
                if (j == 2 && !hasSetEvt) { hasSetEvt = TRUE; matchCount++; }
                if (j == 3 && !hasWait) { hasWait = TRUE; matchCount++; }
                if (j >= 4 && !hasRelease) { hasRelease = TRUE; matchCount++; }
            }
        }
    }

    /* 至少匹配3个特征API (Acquire+SetEvent+Wait 或 Acquire+SetEvent+Release 等) */
    return (matchCount >= 3);
}

/**
 * @brief 递归搜索CALL链, 查找匹配DbgkpQueueMessage签名的函数
 *
 * @param [in] Start - 起始函数地址
 * @param [in] Depth - 当前递归深度
 * @param [in] MaxDepth - 最大递归深度
 * @return 找到的DbgkpQueueMessage地址, 未找到返回NULL
 */
static PVOID SearchQueueMessageRecursive(PVOID Start, ULONG Depth, ULONG MaxDepth)
{
    if (Depth >= MaxDepth || !Start) return NULL;

    /* 锁定起始地址页面 */
    if (!EnsurePageLocked(Start)) return NULL;

    PVOID calls[MAX_CALL_TARGETS];
    ULONG n = CollectCallTargets(Start, 0x500, calls, MAX_CALL_TARGETS);

    /* 诊断: 显示前几层的扫描结果 */
    if (Depth <= 1) {
        SvmDebugPrint("[DebugApi] Depth=%lu Func=%p: %lu CALL targets (excl known)\n",
            Depth, Start, n);
        for (ULONG i = 0; i < n && i < 10; i++) {
            SvmDebugPrint("[DebugApi]   target[%lu] = %p %s\n",
                i, calls[i], IsKnownAddress(calls[i]) ? "(known)" : "");
        }
    }

    for (ULONG i = 0; i < n; i++) {
        if (IsKnownAddress(calls[i])) continue;

        /* 锁定CALL目标页面再检查 */
        if (!EnsurePageLocked(calls[i])) continue;

        /* 先检查当前目标是否是QueueMessage */
        if (IsDbgkpQueueMessageCandidate(calls[i])) {
            SvmDebugPrint("[DebugApi] QueueMessage candidate at %p (depth=%lu)\n",
                calls[i], Depth);
            return calls[i];
        }

        /* 递归向下搜索 */
        PVOID result = SearchQueueMessageRecursive(calls[i], Depth + 1, MaxDepth);
        if (result) return result;
    }
    return NULL;
}

/* ---- 扫描结果缓存 ---- */
static PVOID g_Scanned_DbgkpQueueMessage = NULL;
static PVOID g_Scanned_DbgkForwardException = NULL;
static PVOID g_Scanned_DbgkCreateThread = NULL;
static PVOID g_Scanned_DbgkExitThread = NULL;
static PVOID g_Scanned_DbgkExitProcess = NULL;
static PVOID g_Scanned_DbgkMapViewOfSection = NULL;
static PVOID g_Scanned_DbgkUnMapViewOfSection = NULL;

/**
 * @brief 在ntoskrnl中反向扫描所有引用targetAddr的E8 CALL指令
 *
 * 找到DbgkpQueueMessage后, 扫描ntoskrnl中所有调用它的函数入口。
 * 这些调用者包括: DbgkForwardException, DbgkCreateThread,
 * DbgkExitThread, DbgkExitProcess, DbgkpSendApiMessage等。
 */
#define MAX_CALLERS 32

static ULONG FindCallersOf(PVOID TargetFunc, PVOID* OutCallers, ULONG MaxCallers)
{
    ULONG count = 0;
    PVOID ntBase = GetNtoskrnlBase(NULL);
    if (!ntBase) return 0;

    PUCHAR base = (PUCHAR)ntBase;
    ULONG  size = g_NtoskrnlSize;

    __try {
        for (ULONG i = 0; i < size - 5 && count < MaxCallers; ) {
            /* [PATCH] 每到页边界: 先检查是否驻留, 如果不驻留则尝试MDL锁定(强制换入)
             * 安全性保证: 只对代码段VirtualSize范围内的地址尝试锁定
             *   - VirtualSize内的页面保证有PTE(可能换出) → MmProbeAndLockPages安全换入
             *   - VirtualSize外的填充区/间隙可能无PTE → MmProbeAndLockPages会BSOD
             *   - IsWithinCodeRange预先过滤, 杜绝无PTE风险 */
            if ((i & 0xFFF) == 0) {
                if (!MmIsAddressValid(&base[i])) {
                    if (IsWithinCodeRange(&base[i]) && EnsurePageLocked(&base[i])) {
                        /* 锁定成功: 页面已从pagefile换入, 可以安全读取 */
                    }
                    else {
                        /* 非代码区/锁定失败/MDL已满 → 跳过此页 */
                        i = (i | 0xFFF) + 1;
                        continue;
                    }
                }
            }

            if (base[i] == 0xE8) {
                /* [PATCH] E8指令横跨页边界时检查下一页 */
                ULONG endByte = i + 4;
                if (((i & ~0xFFFUL) != (endByte & ~0xFFFUL)) &&
                    !MmIsAddressValid(&base[endByte])) {
                    if (!(IsWithinCodeRange(&base[endByte]) && EnsurePageLocked(&base[endByte]))) {
                        i = (endByte | 0xFFF) + 1;
                        continue;
                    }
                }

                LONG rel = *(PLONG)(&base[i + 1]);
                PVOID target = (PVOID)(&base[i + 5] + rel);
                if (target == TargetFunc) {
                    PVOID funcStart = NULL;
                    for (LONG j = (LONG)i; j > (LONG)i - 0x200 && j > 0; j--) {
                        /* [PATCH] 回溯进入新页面时检查 */
                        if (((ULONG_PTR)&base[j] & 0xFFF) == 0xFFF) {
                            if (!MmIsAddressValid(&base[j])) break;
                        }
                        if (j > 0 && base[j - 1] == 0xCC &&
                            (base[j] == 0x48 || base[j] == 0x4C || base[j] == 0x40)) {
                            funcStart = &base[j];
                            break;
                        }
                        if ((((ULONG_PTR)&base[j]) & 0xF) == 0 &&
                            (base[j] == 0x48 || base[j] == 0x4C || base[j] == 0x40)) {
                            if (j > 0 && (base[j - 1] == 0xCC || base[j - 1] == 0xC3)) {
                                funcStart = &base[j];
                                break;
                            }
                        }
                    }

                    if (funcStart) {
                        if (!IsWithinCodeRange(funcStart)) {
                            i += 5;
                            continue;
                        }
                        BOOLEAN dup = FALSE;
                        for (ULONG k = 0; k < count; k++) {
                            if (OutCallers[k] == funcStart) { dup = TRUE; break; }
                        }
                        if (!dup) OutCallers[count++] = funcStart;
                    }
                }
                i += 5;
            }
            else {
                i++;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SvmDebugPrint("[DebugApi] Exception in FindCallersOf scan (count=%lu)\n", count);
    }

    return count;
}

/**
 * @brief 通过函数特征区分DbgkForwardException和其他Dbgk*函数
 *
 * 特征判断:
 *   - DbgkForwardException: 函数较大(>300B), 内部调用QueueMessage(间接通过SendApiMessage),
 *     且第一个参数是PEXCEPTION_RECORD (函数体中引用ExceptionCode偏移)
 *   - DbgkCreateThread: 函数较小(<300B), 参数是PETHREAD
 *   - DbgkExitThread/Process: 很小(<200B), 参数是NTSTATUS
 *   - DbgkMapViewOfSection: 中等大小, 5个参数, 内部调用RtlImageNtHeader
 *   - DbgkUnMapViewOfSection: 很小(<150B), 2个参数
 *   - DbgkpSendApiMessage: 内部函数, 直接调用QueueMessage
 *
 * 最可靠的区分方法: 检查函数是否直接调用DbgkpQueueMessage
 * (DbgkForwardException/Create/Exit等通过DbgkpSendApiMessage间接调用)
 */
static VOID IdentifyDbgkCallers(PVOID QueueMsgAddr)
{
    PVOID callers[MAX_CALLERS];
    ULONG nCallers = FindCallersOf(QueueMsgAddr, callers, MAX_CALLERS);

    SvmDebugPrint("[DebugApi] Found %lu callers of DbgkpQueueMessage\n", nCallers);

    /* 第一步: 从QueueMessage的调用者中找到DbgkpSendApiMessage
     * 它是一个小函数(~100B), 直接调用QueueMessage,
     * 且自身也被多个Dbgk*函数调用 */
    PVOID sendApiMsg = NULL;
    for (ULONG i = 0; i < nCallers; i++) {
        /* 锁定调用者页面再扫描 */
        if (!EnsurePageLocked(callers[i])) continue;
        PVOID calls[16];
        ULONG n = CollectCallTargets(callers[i], 0x100, calls, 16);
        /* SendApiMessage特征: 较小函数, 直接调用QueueMessage */
        for (ULONG j = 0; j < n; j++) {
            if (calls[j] == QueueMsgAddr && n <= 6) {
                sendApiMsg = callers[i];
                SvmDebugPrint("[DebugApi] DbgkpSendApiMessage candidate: %p\n", sendApiMsg);
                break;
            }
        }
        if (sendApiMsg) break;
    }

    if (!sendApiMsg) {
        SvmDebugPrint("[DebugApi] DbgkpSendApiMessage not found, trying direct callers\n");
        return;
    }

    /* 第二步: 找到调用DbgkpSendApiMessage的所有函数 = Dbgk*函数们 */
    PVOID dbgkCallers[MAX_CALLERS];
    ULONG nDbgk = FindCallersOf(sendApiMsg, dbgkCallers, MAX_CALLERS);

    SvmDebugPrint("[DebugApi] Found %lu callers of DbgkpSendApiMessage\n", nDbgk);

    UNICODE_STRING usRtlImgHdr;
    RtlInitUnicodeString(&usRtlImgHdr, L"RtlImageNtHeader");
    PVOID pRtlImgHdr = MmGetSystemRoutineAddress(&usRtlImgHdr);

    /* 第三步: 通过ApiNumber位掩码/CALL模式/函数大小区分各个Dbgk*函数
     *
     * 位掩码判定规则:
     *   DbgkCreateThread:      mask包含bit1或bit2 (最大函数, 多个ApiNumber)
     *   DbgkMapViewOfSection:  只有bit5, 且调用RtlImageNtHeader
     *   DbgkExitThread:        只有bit3
     *   DbgkExitProcess:       只有bit4
     *   DbgkUnMapViewOfSection:只有bit6, 或apiNum=-1且最小函数
     */
    for (ULONG i = 0; i < nDbgk; i++) {
        PVOID func = dbgkCallers[i];
        if (!EnsurePageLocked(func)) continue;
        PVOID calls[24];
        ULONG nCalls = CollectCallTargets(func, 0x400, calls, 24);

        /* 估算函数大小 */
        ULONG funcSize = 0;
        __try {
            for (ULONG b = 0; b < 0x500; b++) {
                if (b > 0 && ((((ULONG_PTR)func + b) & 0xFFF) == 0)) {
                    if (!MmIsAddressValid((PVOID)((ULONG_PTR)func + b))) break;
                }
                if (((PUCHAR)func)[b] == 0xC3 && b > 16 &&
                    (b + 1 < 0x500) && ((PUCHAR)func)[b + 1] == 0xCC) {
                    funcSize = b;
                    break;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }

        ULONG apiMask = (funcSize > 0) ? DetectDbgkApiNumbers((PUCHAR)func, funcSize) : 0;

        SvmDebugPrint("[DebugApi]   Candidate %p: size~%lu, calls=%lu, apiMask=0x%X\n",
            func, funcSize, nCalls, apiMask);

        /* ---- 第一优先级: DbgkCreateThread (最大函数, 包含bit1或bit2) ---- */
        if (!g_Scanned_DbgkCreateThread &&
            (apiMask & (API_BIT(1) | API_BIT(2))) &&
            funcSize > 200) {
            g_Scanned_DbgkCreateThread = func;
            SvmDebugPrint("[DebugApi] => DbgkCreateThread: %p (apiMask=0x%X, has CreateThread/Process)\n",
                func, apiMask);
            continue;
        }
        /* DbgkCreateThread兜底: 最大函数(>300B, calls>=6), 无论apiMask */
        if (!g_Scanned_DbgkCreateThread && funcSize > 300 && nCalls >= 6) {
            g_Scanned_DbgkCreateThread = func;
            SvmDebugPrint("[DebugApi] => DbgkCreateThread: %p (size=%lu fallback)\n", func, funcSize);
            continue;
        }

        /* ---- 第二优先级: DbgkForwardException (引用STATUS_BREAKPOINT) ---- */
        if (!g_Scanned_DbgkForwardException && funcSize > 200 && nCalls >= 4) {
            BOOLEAN hasExceptionPattern = FALSE;
            __try {
                PUCHAR p = (PUCHAR)func;
                for (ULONG b = 0; b + 4 <= funcSize; b++) {
                    ULONG val = *(PULONG)(&p[b]);
                    if (val == 0x80000003 || val == 0x80000004) {
                        hasExceptionPattern = TRUE;
                        break;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            if (hasExceptionPattern) {
                g_Scanned_DbgkForwardException = func;
                SvmDebugPrint("[DebugApi] => DbgkForwardException: %p\n", func);
                continue;
            }
        }

        /* ---- 第三优先级: DbgkMapViewOfSection (调用RtlImageNtHeader, 或仅bit5) ---- */
        if (!g_Scanned_DbgkMapViewOfSection && pRtlImgHdr) {
            BOOLEAN callsRtlImg = FALSE;
            for (ULONG j = 0; j < nCalls; j++) {
                if (calls[j] == pRtlImgHdr) { callsRtlImg = TRUE; break; }
            }
            if (callsRtlImg) {
                g_Scanned_DbgkMapViewOfSection = func;
                SvmDebugPrint("[DebugApi] => DbgkMapViewOfSection: %p (RtlImageNtHeader)\n", func);
                continue;
            }
        }
        /* MapViewOfSection: 只有bit5, 没有bit1/bit2(排除CreateThread) */
        if (!g_Scanned_DbgkMapViewOfSection &&
            (apiMask & API_BIT(5)) && !(apiMask & (API_BIT(1) | API_BIT(2))) &&
            funcSize > 100) {
            g_Scanned_DbgkMapViewOfSection = func;
            SvmDebugPrint("[DebugApi] => DbgkMapViewOfSection: %p (apiMask=0x%X, only bit5)\n",
                func, apiMask);
            continue;
        }

        /* ---- 第四优先级: 精确ApiNumber匹配 ---- */
        if (!g_Scanned_DbgkExitProcess &&
            (apiMask & API_BIT(4)) && funcSize > 30 && funcSize < 300) {
            g_Scanned_DbgkExitProcess = func;
            SvmDebugPrint("[DebugApi] => DbgkExitProcess: %p (apiMask=0x%X)\n", func, apiMask);
            continue;
        }
        if (!g_Scanned_DbgkExitThread &&
            (apiMask & API_BIT(3)) && funcSize > 30 && funcSize < 300) {
            g_Scanned_DbgkExitThread = func;
            SvmDebugPrint("[DebugApi] => DbgkExitThread: %p (apiMask=0x%X)\n", func, apiMask);
            continue;
        }
        if (!g_Scanned_DbgkUnMapViewOfSection &&
            (apiMask & API_BIT(6)) && funcSize > 30 && funcSize < 300) {
            g_Scanned_DbgkUnMapViewOfSection = func;
            SvmDebugPrint("[DebugApi] => DbgkUnMapViewOfSection: %p (apiMask=0x%X)\n", func, apiMask);
            continue;
        }

        /* ---- 兜底 ---- */
        if (!g_Scanned_DbgkUnMapViewOfSection && funcSize > 30 && funcSize < 200 && nCalls <= 4) {
            g_Scanned_DbgkUnMapViewOfSection = func;
            SvmDebugPrint("[DebugApi] => DbgkUnMapViewOfSection: %p (size fallback)\n", func);
            continue;
        }
    }
}

/**
 * @brief 主扫描入口 — 从已知Nt*调试函数出发定位所有Dbgk*函数
 */
static VOID ScanForDbgkFunctions()
{
    /* 关键: 先初始化ntoskrnl基址, 否则IsWithinNtoskrnl()始终返回FALSE */
    GetNtoskrnlBase(NULL);
    if (!g_NtoskrnlBase || g_NtoskrnlSize == 0) {
        SvmDebugPrint("[DebugApi] GetNtoskrnlBase failed, cannot scan\n");
        return;
    }
    SvmDebugPrint("[DebugApi] ntoskrnl base=%p size=0x%X\n", g_NtoskrnlBase, g_NtoskrnlSize);

    /* InitCodeRanges 已在 PrepareDebugNptHookResources 开头调用, 无需重复 */
    if (g_CodeRangeCount == 0)
        InitCodeRanges();  /* 仅当独立调用时补初始化 */

    InitKnownAddresses();

    /* 从NtDebugActiveProcess出发搜索DbgkpQueueMessage */
    PVOID ntDbgActive = NULL;
    if (g_HookList[HOOK_NtDebugActiveProcess_Dbg].IsUsed)
        ntDbgActive = g_HookList[HOOK_NtDebugActiveProcess_Dbg].TargetAddress;

    if (!ntDbgActive) {
        SvmDebugPrint("[DebugApi] NtDebugActiveProcess not available, cannot scan\n");
        return;
    }

    SvmDebugPrint("[DebugApi] Starting CALL-chain scan from NtDebugActiveProcess=%p\n", ntDbgActive);

    /* 锁定NtDebugActiveProcess附近页面(搜索目标可能在邻近PAGE段页面) */
    LockPageForHook(ntDbgActive);

    /* 递归搜索DbgkpQueueMessage (最多5层深度) */
    g_Scanned_DbgkpQueueMessage = SearchQueueMessageRecursive(ntDbgActive, 0, MAX_SCAN_DEPTH);

    if (!g_Scanned_DbgkpQueueMessage) {
        /* 备选: 从NtCreateDebugObject出发搜索 */
        PVOID ntCreateDbg = NULL;
        if (g_HookList[HOOK_NtCreateDebugObject_Dbg].IsUsed)
            ntCreateDbg = g_HookList[HOOK_NtCreateDebugObject_Dbg].TargetAddress;
        if (ntCreateDbg) {
            SvmDebugPrint("[DebugApi] Trying alternate scan from NtCreateDebugObject=%p\n", ntCreateDbg);
            g_Scanned_DbgkpQueueMessage = SearchQueueMessageRecursive(ntCreateDbg, 0, MAX_SCAN_DEPTH);
        }
    }

    if (g_Scanned_DbgkpQueueMessage) {
        SvmDebugPrint("[DebugApi] DbgkpQueueMessage found: %p\n", g_Scanned_DbgkpQueueMessage);

        /* 锁定QueueMessage所在页面 */
        LockPageForHook(g_Scanned_DbgkpQueueMessage);

        /* 从QueueMessage反向扫描, 定位所有Dbgk*调用者 */
        IdentifyDbgkCallers(g_Scanned_DbgkpQueueMessage);
    }
    else {
        SvmDebugPrint("[DebugApi] DbgkpQueueMessage NOT found via CALL-chain scan\n");
    }
}


/* ---- PrepareDebugNptHookResources: 注册调试API的NPT Hook ---- */

NTSTATUS PrepareDebugNptHookResources()
{
    NTSTATUS status;
    PVOID pTarget = NULL;
    ULONG ok = 0;

    GetNtoskrnlBase(NULL);
    if (!g_NtoskrnlBase || g_NtoskrnlSize == 0) {
        SvmDebugPrint("[DebugApi] GetNtoskrnlBase failed in PrepareDebugNptHookResources\n");
        /* 不return, 继续尝试 — 某些路径可能不需要ntoskrnl基址 */
    }

    InitCodeRanges();

    enum DbgResolve { DBG_RESOLVE_NTDLL, DBG_RESOLVE_EXPORT, DBG_RESOLVE_CALLSCAN };

    struct DbgHookDef {
        PCWSTR     ExportName;
        PCSTR      NtdllName;
        PCSTR      ScanName;
        PVOID      Proxy;
        HOOK_INDEX Index;
        BOOLEAN    Required;
        DbgResolve Method;
        PVOID* ScanResult;   /* 指向g_Scanned_Xxx缓存变量 */
    };

    /* 第一阶段: 先注册Nt*系统调用 (它们的地址需要先确定, 才能用于CALL-chain扫描) */
    DbgHookDef ntHooks[] = {
        { NULL, "NtCreateDebugObject", NULL,
          (PVOID)Fake_NtCreateDebugObject,
          HOOK_NtCreateDebugObject_Dbg, TRUE, DBG_RESOLVE_NTDLL, NULL },

        { NULL, "NtSetInformationDebugObject", NULL,
          (PVOID)Fake_NtSetInformationDebugObject,
          HOOK_NtSetInfoDebugObject_Dbg, FALSE, DBG_RESOLVE_NTDLL, NULL },

        { NULL, "NtDebugActiveProcess", NULL,
          (PVOID)Fake_NtDebugActiveProcess,
          HOOK_NtDebugActiveProcess_Dbg, TRUE, DBG_RESOLVE_NTDLL, NULL },

        { NULL, "NtWaitForDebugEvent", NULL,
          (PVOID)Fake_NtWaitForDebugEvent,
          HOOK_NtWaitForDebugEvent_Dbg, TRUE, DBG_RESOLVE_NTDLL, NULL },

        { NULL, "NtRemoveProcessDebug", NULL,
          (PVOID)Fake_NtRemoveProcessDebug,
          HOOK_NtRemoveProcessDebug_Dbg, TRUE, DBG_RESOLVE_NTDLL, NULL },

        { NULL, "NtDebugContinue", NULL,
          (PVOID)Fake_NtDebugContinue,
          HOOK_NtDebugContinue_Dbg, TRUE, DBG_RESOLVE_NTDLL, NULL },
    };

    for (ULONG i = 0; i < ARRAYSIZE(ntHooks); i++) {
        pTarget = GetSsdtAddressByNtdllName(ntHooks[i].NtdllName);
        if (!pTarget) {
            SvmDebugPrint("[DebugApi] %s: not found%s\n",
                ntHooks[i].NtdllName, ntHooks[i].Required ? " (REQUIRED)" : " (skipped)");
            continue;
        }
        SvmDebugPrint("[DebugApi] %s -> %p\n", ntHooks[i].NtdllName, pTarget);

        if (!LockPageForHook(pTarget)) continue;

        g_HookList[ntHooks[i].Index].IsUsed = TRUE;
        g_HookList[ntHooks[i].Index].TargetAddress = pTarget;
        g_HookList[ntHooks[i].Index].ProxyFunction = ntHooks[i].Proxy;

        status = PrepareNptHookResources(pTarget, ntHooks[i].Proxy, &g_HookList[ntHooks[i].Index]);
        if (!NT_SUCCESS(status)) {
            SvmDebugPrint("[DebugApi] PrepareNptHookResources failed for %s: 0x%X\n",
                ntHooks[i].NtdllName, status);
            g_HookList[ntHooks[i].Index].IsUsed = FALSE;
            continue;
        }
        ok++;
    }

    /* 第二阶段: 运行CALL-chain扫描器定位Dbgk*函数 */
    SvmDebugPrint("[DebugApi] Phase 1 complete: %lu Nt* hooks ready. Starting Dbgk* scan...\n", ok);
    ScanForDbgkFunctions();

    /* 第三阶段: 注册扫描到的Dbgk*函数Hook */
    DbgHookDef dbgkHooks[] = {
        { L"DbgkForwardException", NULL, "DbgkForwardException",
          (PVOID)Fake_DbgkForwardException,
          HOOK_DbgkForwardException_Dbg, FALSE, DBG_RESOLVE_CALLSCAN,
          &g_Scanned_DbgkForwardException },

        { L"DbgkCreateThread", NULL, "DbgkCreateThread",
          (PVOID)Fake_DbgkCreateThread,
          HOOK_DbgkCreateThread_Dbg, FALSE, DBG_RESOLVE_CALLSCAN,
          &g_Scanned_DbgkCreateThread },

        { L"DbgkExitThread", NULL, "DbgkExitThread",
          (PVOID)Fake_DbgkExitThread,
          HOOK_DbgkExitThread_Dbg, FALSE, DBG_RESOLVE_CALLSCAN,
          &g_Scanned_DbgkExitThread },

        { L"DbgkExitProcess", NULL, "DbgkExitProcess",
          (PVOID)Fake_DbgkExitProcess,
          HOOK_DbgkExitProcess_Dbg, FALSE, DBG_RESOLVE_CALLSCAN,
          &g_Scanned_DbgkExitProcess },

        { L"DbgkMapViewOfSection", NULL, "DbgkMapViewOfSection",
          (PVOID)Fake_DbgkMapViewOfSection,
          HOOK_DbgkMapViewOfSection_Dbg, FALSE, DBG_RESOLVE_CALLSCAN,
          &g_Scanned_DbgkMapViewOfSection },

        { L"DbgkUnMapViewOfSection", NULL, "DbgkUnMapViewOfSection",
          (PVOID)Fake_DbgkUnMapViewOfSection,
          HOOK_DbgkUnMapViewOfSection_Dbg, FALSE, DBG_RESOLVE_CALLSCAN,
          &g_Scanned_DbgkUnMapViewOfSection },

        { L"DbgkpQueueMessage", NULL, "DbgkpQueueMessage",
          (PVOID)Fake_DbgkpQueueMessage,
          HOOK_DbgkpQueueMessage_Dbg, FALSE, DBG_RESOLVE_CALLSCAN,
          &g_Scanned_DbgkpQueueMessage },
    };

    for (ULONG i = 0; i < ARRAYSIZE(dbgkHooks); i++) {
        pTarget = NULL;

        /* 优先使用CALL-chain扫描结果 */
        if (dbgkHooks[i].ScanResult && *dbgkHooks[i].ScanResult) {
            pTarget = *dbgkHooks[i].ScanResult;
            SvmDebugPrint("[DebugApi] %s -> %p (via call-chain scan)\n",
                dbgkHooks[i].ScanName, pTarget);
        }

        /* 降级: MmGetSystemRoutineAddress */
        if (!pTarget && dbgkHooks[i].ExportName) {
            UNICODE_STRING rn;
            RtlInitUnicodeString(&rn, dbgkHooks[i].ExportName);
            pTarget = MmGetSystemRoutineAddress(&rn);
            if (pTarget)
                SvmDebugPrint("[DebugApi] %ws -> %p (via MmGetSystemRoutineAddress)\n",
                    dbgkHooks[i].ExportName, pTarget);
        }

        /* 降级: PE导出表扫描 */
        if (!pTarget && dbgkHooks[i].ScanName) {
            pTarget = ScanNtoskrnlExport(dbgkHooks[i].ScanName);
            if (pTarget)
                SvmDebugPrint("[DebugApi] %s -> %p (via PE export scan)\n",
                    dbgkHooks[i].ScanName, pTarget);
        }

        if (!pTarget) {
            SvmDebugPrint("[DebugApi] %s: not found (skipped)\n", dbgkHooks[i].ScanName);
            continue;
        }

        if (!LockPageForHook(pTarget)) continue;

        g_HookList[dbgkHooks[i].Index].IsUsed = TRUE;
        g_HookList[dbgkHooks[i].Index].TargetAddress = pTarget;
        g_HookList[dbgkHooks[i].Index].ProxyFunction = dbgkHooks[i].Proxy;

        status = PrepareNptHookResources(pTarget, dbgkHooks[i].Proxy, &g_HookList[dbgkHooks[i].Index]);
        if (!NT_SUCCESS(status)) {
            SvmDebugPrint("[DebugApi] PrepareNptHookResources failed for %s: 0x%X\n",
                dbgkHooks[i].ScanName, status);
            g_HookList[dbgkHooks[i].Index].IsUsed = FALSE;
            continue;
        }
        ok++;
    }

    SvmDebugPrint("[DebugApi] PrepareDebugNptHookResources: %lu hooks total ready\n", ok);
    return (ok > 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

VOID LinkDebugTrampolineAddresses()
{
#define LH(i, p, t) \
    if (g_HookList[i].IsUsed && g_HookList[i].TrampolinePage) \
        p = (t)g_HookList[i].TrampolinePage;

    LH(HOOK_NtCreateDebugObject_Dbg, g_OrigNtCreateDebugObject, FnNtCreateDebugObject);
    LH(HOOK_NtDebugActiveProcess_Dbg, g_OrigNtDebugActiveProcess, FnNtDebugActiveProcess);
    LH(HOOK_NtWaitForDebugEvent_Dbg, g_OrigNtWaitForDebugEvent, FnNtWaitForDebugEvent);
    LH(HOOK_NtDebugContinue_Dbg, g_OrigNtDebugContinue, FnNtDebugContinue);
    LH(HOOK_NtRemoveProcessDebug_Dbg, g_OrigNtRemoveProcessDebug, FnNtRemoveProcessDebug);
    LH(HOOK_DbgkForwardException_Dbg, g_OrigDbgkForwardException, FnDbgkForwardException);
    LH(HOOK_DbgkCreateThread_Dbg, g_OrigDbgkCreateThread, FnDbgkCreateThread);
    LH(HOOK_DbgkExitThread_Dbg, g_OrigDbgkExitThread, FnDbgkExitThread);
    LH(HOOK_DbgkExitProcess_Dbg, g_OrigDbgkExitProcess, FnDbgkExitProcess);
    LH(HOOK_DbgkMapViewOfSection_Dbg, g_OrigDbgkMapViewOfSection, FnDbgkMapViewOfSection);
    LH(HOOK_DbgkUnMapViewOfSection_Dbg, g_OrigDbgkUnMapViewOfSection, FnDbgkUnMapViewOfSection);
    LH(HOOK_DbgkpQueueMessage_Dbg, g_OrigDbgkpQueueMessage, FnDbgkpQueueMessage);

#undef LH

    ULONG linked =
        (g_OrigNtCreateDebugObject ? 1 : 0) + (g_OrigNtDebugActiveProcess ? 1 : 0) +
        (g_OrigNtWaitForDebugEvent ? 1 : 0) + (g_OrigNtDebugContinue ? 1 : 0) +
        (g_OrigNtRemoveProcessDebug ? 1 : 0) + (g_OrigDbgkForwardException ? 1 : 0) +
        (g_OrigDbgkCreateThread ? 1 : 0) + (g_OrigDbgkExitThread ? 1 : 0) +
        (g_OrigDbgkExitProcess ? 1 : 0) + (g_OrigDbgkMapViewOfSection ? 1 : 0) +
        (g_OrigDbgkUnMapViewOfSection ? 1 : 0) + (g_OrigDbgkpQueueMessage ? 1 : 0);

    SvmDebugPrint("[DebugApi] LinkDebugTrampolineAddresses: linked %lu trampolines\n", linked);
}