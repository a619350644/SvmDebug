/**
 * @file DebugApi.h
 * @brief SVM受保护调试器头文件 - 调试对象管理、事件队列、断点控制、NPT Hook声明
 * @author yewilliam
 * @date 2026/03/17
 *
 * 设计思路 (参考Intel VT-x DbgkApi项目, 适配到AMD SVM + NPT Hook架构):
 *
 *   1. 自定义调试对象类型 (Hvm_DebugObject):
 *      不使用系统的 DbgkDebugObjectType, 而是创建自定义对象类型,
 *      ACE等反作弊无法通过枚举标准DebugObject发现调试关系。
 *
 *   2. 影子调试端口 (Shadow Debug Port):
 *      不写入 EPROCESS.DebugPort, 而是维护独立的 g_DebugProcessList,
 *      所有调试API通过 IsDebugTargetProcess() 查询此链表获取DebugObject。
 *      ACE读取 DebugPort 永远为NULL。
 *
 *   3. NPT Hook 替换调试相关函数:
 *      通过NPT(嵌套页表)Hook替换NtCreateDebugObject、NtDebugActiveProcess、
 *      NtWaitForDebugEvent、NtDebugContinue、DbgkForwardException等函数,
 *      使调试事件流经我们的自定义路径。
 *
 *   4. 硬件/软件断点管理:
 *      硬件断点通过CPUID超级调用下发到VMM, VMM在VMEXIT中设置DR0-DR3;
 *      软件断点(INT3)通过NPT Hook的Execute/Read分离实现隐形替换。
 *
 * 文件架构:
 *   DebugApi.h  - 结构体定义、常量、函数声明 (本文件)
 *   DebugApi.cpp - 调试子系统初始化、调试对象CRUD、调试事件处理、
 *                  NPT Fake函数、断点管理等完整实现
 */

#pragma once

#include <ntifs.h>
#include "Common.h"
#include "Hook.h"
#include "Hide.h"

 /* ========================================================================
  *  编译兼容性
  * ======================================================================== */
#pragma warning(disable: 4201)  /* nameless struct/union */

/* ========================================================================
 *  Undocumented NT Internal Declarations
 *  Required for debug object creation and management
 * ======================================================================== */

#include <ntimage.h>

/* --- Missing status codes --- */
#ifndef STATUS_NOT_INITIALIZED
#define STATUS_NOT_INITIALIZED   ((NTSTATUS)0xC0000191L)
#endif

#ifndef PROCESS_SET_PORT
#define PROCESS_SET_PORT         0x0800
#endif

/* --- Dynamic-resolved NT internals (not in ntoskrnl.lib) --- */
typedef PEPROCESS (NTAPI *FnPsGetNextProcess)(IN PEPROCESS Process);

extern FnPsGetNextProcess     g_pfnPsGetNextProcess;

#define PsGetNextProcess(p)         g_pfnPsGetNextProcess(p)

/* KeGetPreviousMode -> use ExGetPreviousMode (documented & exported) */
#define KeGetPreviousMode()         ExGetPreviousMode()

/* RtlImageNtHeader is in ntoskrnl exports, just needs correct declaration */
EXTERN_C NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(IN PVOID ModuleAddress);

/* Forward declarations (full typedef) */
typedef struct _DEBUG_OBJECT DEBUG_OBJECT, *PDEBUG_OBJECT;

/* Pool-based handle table for DEBUG_OBJECT (replaces ObCreateObjectType) */
#define DBG_MAX_HANDLES         16
#define DBG_HANDLE_BASE         0xDB000000ULL
#define DBG_HANDLE_TO_INDEX(h)  ((ULONG)((ULONG64)(h) - DBG_HANDLE_BASE))
#define DBG_INDEX_TO_HANDLE(i)  ((HANDLE)(DBG_HANDLE_BASE + (ULONG64)(i)))
#define DBG_IS_VALID_HANDLE(h)  ((ULONG64)(h) >= DBG_HANDLE_BASE && (ULONG64)(h) < DBG_HANDLE_BASE + DBG_MAX_HANDLES)

extern PDEBUG_OBJECT g_DbgHandleTable[DBG_MAX_HANDLES];
extern FAST_MUTEX    g_DbgHandleTableMutex;

PDEBUG_OBJECT DbgAllocateDebugObject();
VOID          DbgFreeDebugObject(PDEBUG_OBJECT Obj);
HANDLE        DbgInsertHandle(PDEBUG_OBJECT Obj);
PDEBUG_OBJECT DbgLookupHandle(HANDLE Handle);
VOID          DbgRemoveHandle(HANDLE Handle);

/* ObDuplicateObject (for file handle duplication in OpenHandles) */
EXTERN_C NTKERNELAPI NTSTATUS ObDuplicateObject(
    IN PEPROCESS SourceProcess, IN HANDLE SourceHandle,
    IN PEPROCESS TargetProcess OPTIONAL, OUT PHANDLE TargetHandle OPTIONAL,
    IN ACCESS_MASK DesiredAccess, IN ULONG HandleAttributes,
    IN ULONG Options, IN KPROCESSOR_MODE PreviousMode);


/* --- Probe macros (normally in ntoskrnl internal headers) --- */
#ifndef ProbeForWriteHandle
#define ProbeForWriteHandle(addr) \
    ProbeForWrite((PVOID)(addr), sizeof(HANDLE), sizeof(HANDLE))
#endif

#ifndef ProbeForWriteUlong
#define ProbeForWriteUlong(addr) \
    ProbeForWrite((PVOID)(addr), sizeof(ULONG), sizeof(ULONG))
#endif

#ifndef ProbeForReadLargeInteger
#define ProbeForReadLargeInteger(addr) \
    ProbeForRead((PVOID)(addr), sizeof(LARGE_INTEGER), sizeof(ULONG))
#endif

#ifndef ProbeForReadSmallStructure
#define ProbeForReadSmallStructure(addr, size, align) \
    ProbeForRead((PVOID)(addr), (ULONG)(size), (ULONG)(align))
#endif

#ifndef ExSystemExceptionFilter
#define ExSystemExceptionFilter() EXCEPTION_EXECUTE_HANDLER
#endif


  /* ========================================================================
   *  Section 1: 调试对象访问权限与标志
   * ======================================================================== */

#define DEBUG_READ_EVENT            0x0001
#define DEBUG_PROCESS_ASSIGN        0x0002
#define DEBUG_SET_INFORMATION       0x0004
#define DEBUG_QUERY_INFORMATION     0x0008

#define DEBUG_ALL_ACCESS            (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                     DEBUG_READ_EVENT | DEBUG_PROCESS_ASSIGN | \
                                     DEBUG_SET_INFORMATION | DEBUG_QUERY_INFORMATION)

#define DBGK_KILL_PROCESS_ON_EXIT   0x1
#define DBGK_ALL_FLAGS              (DBGK_KILL_PROCESS_ON_EXIT)

   /* 调试对象内部标志 */
#define DEBUG_OBJECT_DELETE_PENDING  0x1
#define DEBUG_OBJECT_KILL_ON_CLOSE   0x2

/* 调试事件标志 */
#define DEBUG_EVENT_READ             0x01
#define DEBUG_EVENT_INACTIVE         0x02
#define DEBUG_EVENT_NOWAIT           0x04
#define DEBUG_EVENT_RELEASE          0x08
#define DEBUG_EVENT_PROTECT_FAILED   0x10


/* ========================================================================
 *  Section 2: DBGKM API编号
 * ======================================================================== */

typedef enum _DBGKM_APINUMBER {
    DbgKmExceptionApi = 0,
    DbgKmCreateThreadApi = 1,
    DbgKmCreateProcessApi = 2,
    DbgKmExitThreadApi = 3,
    DbgKmExitProcessApi = 4,
    DbgKmLoadDllApi = 5,
    DbgKmUnloadDllApi = 6,
    DbgKmMaxApiNumber = 7
} DBGKM_APINUMBER;


/* ========================================================================
 *  Section 3: DBGKM 消息子结构体
 * ======================================================================== */

typedef struct _DBGKM_EXCEPTION {
    EXCEPTION_RECORD ExceptionRecord;
    ULONG FirstChance;
} DBGKM_EXCEPTION, * PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD {
    ULONG SubSystemKey;
    PVOID StartAddress;
} DBGKM_CREATE_THREAD, * PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS {
    ULONG SubSystemKey;
    HANDLE FileHandle;
    PVOID BaseOfImage;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, * PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD {
    NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, * PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS {
    NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, * PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL {
    HANDLE FileHandle;
    PVOID BaseOfDll;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    PVOID NamePointer;
} DBGKM_LOAD_DLL, * PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL {
    PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, * PDBGKM_UNLOAD_DLL;


/* ========================================================================
 *  Section 4: LPC消息头 + DBGKM_APIMSG
 * ======================================================================== */

typedef struct _PORT_MESSAGE_LITE {
    union {
        struct { CSHORT DataLength; CSHORT TotalLength; } s1;
        ULONG Length;
    } u1;
    union {
        struct { CSHORT Type; CSHORT DataInfoOffset; } s2;
        ULONG ZeroInit;
    } u2;
    union {
        CLIENT_ID ClientId;
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union {
        SIZE_T ClientViewSize;
        ULONG CallbackId;
    };
} PORT_MESSAGE_LITE;

#define LPC_DEBUG_EVENT   8
#define LPC_EXCEPTION     10

/**
 * @brief DBGKM_APIMSG - 调试API消息 (核心通信结构体)
 */
typedef struct _DBGKM_APIMSG {
    PORT_MESSAGE_LITE h;
    DBGKM_APINUMBER ApiNumber;
    NTSTATUS ReturnedStatus;
    union {
        DBGKM_EXCEPTION Exception;
        DBGKM_CREATE_THREAD CreateThread;
        DBGKM_CREATE_PROCESS CreateProcess;
        DBGKM_EXIT_THREAD ExitThread;
        DBGKM_EXIT_PROCESS ExitProcess;
        DBGKM_LOAD_DLL LoadDll;
        DBGKM_UNLOAD_DLL UnloadDll;
    } u;
} DBGKM_APIMSG, * PDBGKM_APIMSG;


/* ========================================================================
 *  Section 5: DEBUG_OBJECT / DEBUG_EVENT
 * ======================================================================== */

 /**
  * @brief DEBUG_OBJECT - 自定义调试对象
  *
  * 使用自定义对象类型"Hvm_DebugObject", ACE无法通过标准枚举发现。
  */
struct _DEBUG_OBJECT {
    KEVENT EventsPresent;
    FAST_MUTEX Mutex;
    LIST_ENTRY EventList;
    union {
        ULONG Flags;
        struct {
            ULONG DebuggerInactive : 1;
            ULONG KillProcessOnExit : 1;
        };
    };
};

/**
 * @brief DEBUG_EVENT - 调试事件节点
 *
 * 生命周期: QueueMessage分配 -> WaitForDebugEvent标记READ -> DebugContinue唤醒释放
 */
typedef struct _DEBUG_EVENT {
    LIST_ENTRY EventList;
    KEVENT ContinueEvent;
    CLIENT_ID ClientId;
    PEPROCESS Process;
    PETHREAD Thread;
    NTSTATUS Status;
    ULONG Flags;
    PETHREAD BackoutThread;
    DBGKM_APIMSG ApiMsg;
} DEBUG_EVENT, * PDEBUG_EVENT;


/* ========================================================================
 *  Section 6: DBGUI_WAIT_STATE_CHANGE (用户态输出)
 * ======================================================================== */

typedef enum _DBG_STATE {
    DbgIdle = 0,
    DbgReplyPending,
    DbgCreateThreadStateChange,
    DbgCreateProcessStateChange,
    DbgExitThreadStateChange,
    DbgExitProcessStateChange,
    DbgExceptionStateChange,
    DbgBreakpointStateChange,
    DbgSingleStepStateChange,
    DbgLoadDllStateChange,
    DbgUnloadDllStateChange
} DBG_STATE, * PDBG_STATE;

typedef struct _DBGUI_CREATE_THREAD {
    HANDLE HandleToThread;
    DBGKM_CREATE_THREAD NewThread;
} DBGUI_CREATE_THREAD, * PDBGUI_CREATE_THREAD;

typedef struct _DBGUI_CREATE_PROCESS {
    HANDLE HandleToProcess;
    HANDLE HandleToThread;
    DBGKM_CREATE_PROCESS NewProcess;
} DBGUI_CREATE_PROCESS, * PDBGUI_CREATE_PROCESS;

typedef struct _DBGUI_WAIT_STATE_CHANGE {
    DBG_STATE NewState;
    CLIENT_ID AppClientId;
    union {
        DBGKM_EXCEPTION Exception;
        DBGUI_CREATE_THREAD CreateThread;
        DBGUI_CREATE_PROCESS CreateProcessInfo;
        DBGKM_EXIT_THREAD ExitThread;
        DBGKM_EXIT_PROCESS ExitProcess;
        DBGKM_LOAD_DLL LoadDll;
        DBGKM_UNLOAD_DLL UnloadDll;
    } StateInfo;
} DBGUI_WAIT_STATE_CHANGE, * PDBGUI_WAIT_STATE_CHANGE;

typedef enum _DEBUGOBJECTINFOCLASS {
    DebugObjectFlags = 1
} DEBUGOBJECTINFOCLASS;


/* ========================================================================
 *  Section 7: 影子调试端口管理结构体
 * ======================================================================== */

 /**
  * @brief DEBUG_PROCESS - 影子调试端口节点 (替代EPROCESS.DebugPort)
  */
typedef struct _DEBUG_PROCESS {
    LIST_ENTRY ListEntry;
    PEPROCESS Process;
    PDEBUG_OBJECT DebugObject;
    FAST_MUTEX Mutex;
} DEBUG_PROCESS, * PDEBUG_PROCESS;

/**
 * @brief DEBUGGER_TABLE_ENTRY - 调试器进程登记项
 */
typedef struct _DEBUGGER_TABLE_ENTRY {
    LIST_ENTRY ListEntry;
    PEPROCESS DebuggerProcess;
    HANDLE DebuggerPid;
} DEBUGGER_TABLE_ENTRY, * PDEBUGGER_TABLE_ENTRY;


/* ========================================================================
 *  Section 8: IOCTL 定义 (0x830起)
 * ======================================================================== */

#define IOCTL_DBG_REGISTER_DEBUGGER      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DBG_ATTACH_PROCESS         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DBG_DETACH_PROCESS         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DBG_SET_HW_BREAKPOINT      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x833, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DBG_REMOVE_HW_BREAKPOINT   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x834, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DBG_SET_SW_BREAKPOINT      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x835, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DBG_REMOVE_SW_BREAKPOINT   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x836, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DBG_READ_SW_BREAKPOINT     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x837, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DBG_CONTINUE               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x838, METHOD_BUFFERED, FILE_ANY_ACCESS)


 /* ========================================================================
  *  Section 9: R3<->R0 通信结构体
  * ======================================================================== */

typedef struct _DBG_REGISTER_REQUEST {
    ULONG64 DebuggerPid;
} DBG_REGISTER_REQUEST, * PDBG_REGISTER_REQUEST;

typedef struct _DBG_ATTACH_REQUEST {
    ULONG64 TargetPid;
} DBG_ATTACH_REQUEST, * PDBG_ATTACH_REQUEST;

/* CPUID超级调用: 调试操作 */
#define CPUID_HV_DEBUG_OP              0x41414160

/* 子命令 */
#define HV_DBG_SET_HW_BP              0x01
#define HV_DBG_REMOVE_HW_BP           0x02
#define HV_DBG_SET_SW_BP              0x03
#define HV_DBG_REMOVE_SW_BP           0x04
#define HV_DBG_READ_SW_BP             0x05

/**
 * @brief 硬件断点请求 (R3->R0->VMM)
 */
typedef struct _HW_BREAKPOINT_REQUEST {
    ULONG64 TargetPid;
    ULONG64 Address;
    ULONG   DrIndex;       /* 0-3 -> DR0-DR3 */
    ULONG   Type;          /* 0=执行, 1=写入, 2=IO, 3=读写 */
    ULONG   Length;         /* 0=1B, 1=2B, 2=8B, 3=4B */
    ULONG64 TargetCr3;     /* 由驱动填充 */
} HW_BREAKPOINT_REQUEST, * PHW_BREAKPOINT_REQUEST;

/**
 * @brief 软件断点请求 (R3->R0->VMM, NPT隐形INT3)
 */
typedef struct _SW_BREAKPOINT_REQUEST {
    ULONG64 TargetPid;
    ULONG64 Address;
    UCHAR   OriginalByte;  /* 输出: 被替换的原始字节 */
    ULONG64 TargetCr3;
} SW_BREAKPOINT_REQUEST, * PSW_BREAKPOINT_REQUEST;

/**
 * @brief VMM侧调试上下文 (共享内存, VMEXIT中读取)
 */
typedef struct _HV_DEBUG_CONTEXT {
    ULONG   Command;
    ULONG64 TargetCr3;
    ULONG64 Address;
    ULONG   DrIndex;
    ULONG   Type;
    ULONG   Length;
    UCHAR   OriginalByte;
    volatile LONG Status;
} HV_DEBUG_CONTEXT, * PHV_DEBUG_CONTEXT;


/* ========================================================================
 *  Section 10: 全局变量
 * ======================================================================== */

extern FAST_MUTEX g_DbgkpProcessDebugPortMutex;
extern LIST_ENTRY g_DebugProcessListHead;
extern FAST_MUTEX g_DebugProcessListMutex;
extern LIST_ENTRY g_DebuggerListHead;
extern FAST_MUTEX g_DebuggerListMutex;
extern PHV_DEBUG_CONTEXT g_HvDebugContext;
extern ULONG64 g_HvDebugContextPa;


/* ========================================================================
 *  Section 11: 函数声明 - 初始化/卸载
 * ======================================================================== */

NTSTATUS DbgInitialize();
VOID DbgUninitialize();
NTSTATUS HvInitDebugContext();
VOID HvFreeDebugContext();


/* ========================================================================
 *  Section 12: 调试器/被调试进程管理
 * ======================================================================== */

BOOLEAN RegisterDebugger(PEPROCESS DebuggerProcess, HANDLE DebuggerPid);
BOOLEAN IsDebugger(PEPROCESS Process);
BOOLEAN SetDebugTargetProcess(PEPROCESS Process, PDEBUG_OBJECT DebugObject);
BOOLEAN IsDebugTargetProcess(PEPROCESS Process, PDEBUG_PROCESS* DebugProcess);
VOID DeleteDebugProcess(PDEBUG_OBJECT DebugObject);
NTSTATUS DbgkClearProcessDebugObject(PEPROCESS Process, PDEBUG_OBJECT SourceDebugObject);


/* ========================================================================
 *  Section 13: NPT Fake函数 (替换系统调试API)
 * ======================================================================== */

NTSTATUS NTAPI Fake_NtCreateDebugObject(
    OUT PHANDLE DebugHandle, IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes, IN ULONG Flags);

NTSTATUS NTAPI Fake_NtSetInformationDebugObject(
    IN HANDLE DebugObjectHandle, IN DEBUGOBJECTINFOCLASS DebugObjectInformationClass,
    IN PVOID DebugInformation, IN ULONG DebugInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

NTSTATUS NTAPI Fake_NtDebugActiveProcess(
    IN HANDLE ProcessHandle, IN HANDLE DebugHandle);

NTSTATUS NTAPI Fake_NtWaitForDebugEvent(
    IN HANDLE DebugHandle, IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL, OUT PDBGUI_WAIT_STATE_CHANGE StateChange);

NTSTATUS NTAPI Fake_NtRemoveProcessDebug(
    IN HANDLE ProcessHandle, IN HANDLE DebugObjectHandle);

NTSTATUS NTAPI Fake_NtDebugContinue(
    IN HANDLE DebugObjectHandle, IN PCLIENT_ID ClientId, IN NTSTATUS ContinueStatus);

BOOLEAN NTAPI Fake_DbgkForwardException(
    IN PEXCEPTION_RECORD ExceptionRecord, IN BOOLEAN DebugPort, IN BOOLEAN SecondChance);

VOID NTAPI Fake_DbgkCreateThread(IN PETHREAD Thread);
VOID NTAPI Fake_DbgkExitThread(NTSTATUS ExitStatus);
VOID NTAPI Fake_DbgkExitProcess(NTSTATUS ExitStatus);

VOID NTAPI Fake_DbgkMapViewOfSection(
    IN PEPROCESS Process, IN PVOID SectionObject,
    IN PVOID BaseAddress, IN ULONG SectionOffset, IN ULONG_PTR ViewSize);

VOID NTAPI Fake_DbgkUnMapViewOfSection(
    IN PEPROCESS Process, IN PVOID BaseAddress);

NTSTATUS NTAPI Fake_DbgkpQueueMessage(
    IN PEPROCESS Process, IN PETHREAD Thread,
    IN PDBGKM_APIMSG Message, IN ULONG Flags,
    IN PDEBUG_OBJECT TargetObject OPTIONAL);

VOID NTAPI Fake_DbgkpCloseObject(
    IN PEPROCESS Process, IN PVOID Object,
    IN ACCESS_MASK GrantedAccess, IN ULONG_PTR SystemHandleCount);


/* ========================================================================
 *  Section 14: 调试事件辅助函数
 * ======================================================================== */

VOID DbgkpConvertKernelToUserStateChange(
    OUT PDBGUI_WAIT_STATE_CHANGE WaitStateChange, IN PDEBUG_EVENT DebugEvent);

VOID DbgkpOpenHandles(
    IN OUT PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
    IN PEPROCESS Process, IN PETHREAD Thread);

VOID DbgkpWakeTarget(IN PDEBUG_EVENT DebugEvent);
VOID DbgkpFreeDebugEvent(IN PDEBUG_EVENT DebugEvent);
VOID DbgkpMarkProcessPeb(IN PEPROCESS Process);

NTSTATUS DbgkpSendApiMessage(
    IN PEPROCESS Process, IN BOOLEAN SuspendProcess, IN OUT PDBGKM_APIMSG ApiMsg);


/* ========================================================================
 *  Section 15: 断点管理 (Guest侧)
 * ======================================================================== */

NTSTATUS DbgSetHardwareBreakpoint(PHW_BREAKPOINT_REQUEST Request);
NTSTATUS DbgRemoveHardwareBreakpoint(PHW_BREAKPOINT_REQUEST Request);
NTSTATUS DbgSetSoftwareBreakpoint(PSW_BREAKPOINT_REQUEST Request);
NTSTATUS DbgRemoveSoftwareBreakpoint(PSW_BREAKPOINT_REQUEST Request);
NTSTATUS DbgReadSoftwareBreakpoint(PSW_BREAKPOINT_REQUEST Request);


/* ========================================================================
 *  Section 16: VMM侧处理器
 * ======================================================================== */

VOID HvHandleDebugOp(PVCPU_CONTEXT vpData);


/* ========================================================================
 *  Section 17: IOCTL派发 / Hook注册
 * ======================================================================== */

NTSTATUS DbgDispatchIoctl(
    ULONG IoControlCode, PVOID InputBuffer, ULONG InputLength,
    PVOID OutputBuffer, ULONG OutputLength, PULONG BytesReturned);

static BOOLEAN IsWithinCodeRange(PVOID Addr);

static BOOLEAN IsWithinNtoskrnl(PVOID Addr);

NTSTATUS PrepareDebugNptHookResources();
VOID LinkDebugTrampolineAddresses();

