/**
 * @file DebugApi.h
 * @brief SVM�ܱ���������ͷ�ļ� - ���Զ���������¼����С��ϵ���ơ�NPT Hook����
 * @author yewilliam
 * @date 2026/03/17
 *
 * ���˼· (�ο�Intel VT-x DbgkApi��Ŀ, ���䵽AMD SVM + NPT Hook�ܹ�):
 *
 *   1. �Զ�����Զ������� (Hvm_DebugObject):
 *      ��ʹ��ϵͳ�� DbgkDebugObjectType, ���Ǵ����Զ����������,
 *      ACE�ȷ������޷�ͨ��ö�ٱ�׼DebugObject���ֵ��Թ�ϵ��
 *
 *   2. Ӱ�ӵ��Զ˿� (Shadow Debug Port):
 *      ��д�� EPROCESS.DebugPort, ����ά�������� g_DebugProcessList,
 *      ���е���APIͨ�� IsDebugTargetProcess() ��ѯ��������ȡDebugObject��
 *      ACE��ȡ DebugPort ��ԶΪNULL��
 *
 *   3. NPT Hook �滻������غ���:
 *      ͨ��NPT(Ƕ��ҳ��)Hook�滻NtCreateDebugObject��NtDebugActiveProcess��
 *      NtWaitForDebugEvent��NtDebugContinue��DbgkForwardException�Ⱥ���,
 *      ʹ�����¼��������ǵ��Զ���·����
 *
 *   4. Ӳ��/�����ϵ����:
 *      Ӳ���ϵ�ͨ��CPUID���������·���VMM, VMM��VMEXIT������DR0-DR3;
 *      �����ϵ�(INT3)ͨ��NPT Hook��Execute/Read����ʵ�������滻��
 *
 * �ļ��ܹ�:
 *   DebugApi.h  - �ṹ�嶨�塢�������������� (���ļ�)
 *   DebugApi.cpp - ������ϵͳ��ʼ�������Զ���CRUD�������¼�������
 *                  NPT Fake�������ϵ����������ʵ��
 */

#pragma once

#include <ntifs.h>
#include "Common.h"
#include "Hook.h"
#include "Hide.h"

 /* ========================================================================
  *  ���������
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
typedef PEPROCESS(NTAPI* FnPsGetNextProcess)(IN PEPROCESS Process);

extern FnPsGetNextProcess     g_pfnPsGetNextProcess;

#define PsGetNextProcess(p)         g_pfnPsGetNextProcess(p)

/* KeGetPreviousMode -> use ExGetPreviousMode (documented & exported) */
#define KeGetPreviousMode()         ExGetPreviousMode()

/* RtlImageNtHeader is in ntoskrnl exports, just needs correct declaration */
EXTERN_C NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(IN PVOID ModuleAddress);

/* Forward declarations (full typedef) */
typedef struct _DEBUG_OBJECT DEBUG_OBJECT, * PDEBUG_OBJECT;

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
   *  Section 1: ���Զ������Ȩ�����־
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

   /* ���Զ����ڲ���־ */
#define DEBUG_OBJECT_DELETE_PENDING  0x1
#define DEBUG_OBJECT_KILL_ON_CLOSE   0x2

/* �����¼���־ */
#define DEBUG_EVENT_READ             0x01
#define DEBUG_EVENT_INACTIVE         0x02
#define DEBUG_EVENT_NOWAIT           0x04
#define DEBUG_EVENT_RELEASE          0x08
#define DEBUG_EVENT_PROTECT_FAILED   0x10


/* ========================================================================
 *  Section 2: DBGKM API���
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
 *  Section 3: DBGKM ��Ϣ�ӽṹ��
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
 *  Section 4: LPC��Ϣͷ + DBGKM_APIMSG
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
 * @brief DBGKM_APIMSG - ����API��Ϣ (����ͨ�Žṹ��)
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
  * @brief DEBUG_OBJECT - �Զ�����Զ���
  *
  * ʹ���Զ����������"Hvm_DebugObject", ACE�޷�ͨ����׼ö�ٷ��֡�
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
 * @brief DEBUG_EVENT - �����¼��ڵ�
 *
 * ��������: QueueMessage���� -> WaitForDebugEvent���READ -> DebugContinue�����ͷ�
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
 *  Section 6: DBGUI_WAIT_STATE_CHANGE (�û�̬���)
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
 *  Section 7: Ӱ�ӵ��Զ˿ڹ����ṹ��
 * ======================================================================== */

 /**
  * @brief DEBUG_PROCESS - Ӱ�ӵ��Զ˿ڽڵ� (���EPROCESS.DebugPort)
  */
typedef struct _DEBUG_PROCESS {
    LIST_ENTRY ListEntry;
    PEPROCESS Process;
    PDEBUG_OBJECT DebugObject;
    FAST_MUTEX Mutex;
} DEBUG_PROCESS, * PDEBUG_PROCESS;

/**
 * @brief DEBUGGER_TABLE_ENTRY - ���������̵Ǽ���
 */
typedef struct _DEBUGGER_TABLE_ENTRY {
    LIST_ENTRY ListEntry;
    PEPROCESS DebuggerProcess;
    HANDLE DebuggerPid;
} DEBUGGER_TABLE_ENTRY, * PDEBUGGER_TABLE_ENTRY;


/* ========================================================================
 *  Section 8: IOCTL ���� (0x830��)
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
  *  Section 9: R3<->R0 ͨ�Žṹ��
  * ======================================================================== */

typedef struct _DBG_REGISTER_REQUEST {
    ULONG64 DebuggerPid;
} DBG_REGISTER_REQUEST, * PDBG_REGISTER_REQUEST;

typedef struct _DBG_ATTACH_REQUEST {
    ULONG64 TargetPid;
} DBG_ATTACH_REQUEST, * PDBG_ATTACH_REQUEST;

/* CPUID��������: ���Բ��� */
#define CPUID_HV_DEBUG_OP              0x41414160

/* ������ */
#define HV_DBG_SET_HW_BP              0x01
#define HV_DBG_REMOVE_HW_BP           0x02
#define HV_DBG_SET_SW_BP              0x03
#define HV_DBG_REMOVE_SW_BP           0x04
#define HV_DBG_READ_SW_BP             0x05

/**
 * @brief Ӳ���ϵ����� (R3->R0->VMM)
 */
typedef struct _HW_BREAKPOINT_REQUEST {
    ULONG64 TargetPid;
    ULONG64 Address;
    ULONG   DrIndex;       /* 0-3 -> DR0-DR3 */
    ULONG   Type;          /* 0=ִ��, 1=д��, 2=IO, 3=��д */
    ULONG   Length;         /* 0=1B, 1=2B, 2=8B, 3=4B */
    ULONG64 TargetCr3;     /* ��������� */
} HW_BREAKPOINT_REQUEST, * PHW_BREAKPOINT_REQUEST;

/**
 * @brief �����ϵ����� (R3->R0->VMM, NPT����INT3)
 */
typedef struct _SW_BREAKPOINT_REQUEST {
    ULONG64 TargetPid;
    ULONG64 Address;
    UCHAR   OriginalByte;  /* ���: ���滻��ԭʼ�ֽ� */
    ULONG64 TargetCr3;
} SW_BREAKPOINT_REQUEST, * PSW_BREAKPOINT_REQUEST;

/**
 * @brief VMM����������� (�����ڴ�, VMEXIT�ж�ȡ)
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
 *  Section 10: ȫ�ֱ���
 * ======================================================================== */

extern FAST_MUTEX g_DbgkpProcessDebugPortMutex;
extern LIST_ENTRY g_DebugProcessListHead;
extern FAST_MUTEX g_DebugProcessListMutex;
extern LIST_ENTRY g_DebuggerListHead;
extern FAST_MUTEX g_DebuggerListMutex;
extern PHV_DEBUG_CONTEXT g_HvDebugContext;
extern ULONG64 g_HvDebugContextPa;


/* ========================================================================
 *  NPT 隐形断点管理 — Execute/Read 分离实现对反作弊透明的软件断点
 *
 *  原理: 断点所在物理页拆分为两个视图:
 *    Original Page (R/W) — 反作弊扫描时看到原始指令
 *    Fake Page (X)       — CPU 执行时命中 0xCC (INT3)
 *
 *  #BP 异常在 VMCB 层拦截 (不进 Guest IDT), 反作弊的 VEH/SEH 无感知
 * ======================================================================== */

#define MAX_NPT_BREAKPOINTS  64

typedef struct _NPT_BREAKPOINT {
    BOOLEAN  IsActive;           // 断点是否激活
    ULONG64  TargetPid;          // 目标进程 PID
    ULONG64  TargetCr3;          // 目标进程 CR3
    ULONG64  VirtualAddress;     // 断点虚拟地址
    ULONG64  PhysicalAddress;    // 断点所在物理页基址 (4KB 对齐)
    ULONG    PageOffset;         // 页内偏移 (VA & 0xFFF)
    UCHAR    OriginalByte;       // 原始字节
    LONG     HookSlotIndex;      // 对应的 g_HookList 槽位索引 (-1 = 未分配)
    BOOLEAN  IsSingleStepping;   // 是否在单步恢复中
    HANDLE   OwnerThread;        // 触发断点的线程
} NPT_BREAKPOINT, * PNPT_BREAKPOINT;

extern NPT_BREAKPOINT g_NptBreakpoints[MAX_NPT_BREAKPOINTS];
extern volatile LONG   g_NptBreakpointCount;


/* ========================================================================
 *  Section 11: �������� - ��ʼ��/ж��
 * ======================================================================== */

NTSTATUS DbgInitialize();
VOID DbgUninitialize();
NTSTATUS HvInitDebugContext();
VOID HvFreeDebugContext();


/* ========================================================================
 *  Section 12: ������/�����Խ��̹���
 * ======================================================================== */

BOOLEAN RegisterDebugger(PEPROCESS DebuggerProcess, HANDLE DebuggerPid);
BOOLEAN IsDebugger(PEPROCESS Process);
BOOLEAN SetDebugTargetProcess(PEPROCESS Process, PDEBUG_OBJECT DebugObject);
BOOLEAN IsDebugTargetProcess(PEPROCESS Process, PDEBUG_PROCESS* DebugProcess);
VOID DeleteDebugProcess(PDEBUG_OBJECT DebugObject);
NTSTATUS DbgkClearProcessDebugObject(PEPROCESS Process, PDEBUG_OBJECT SourceDebugObject);


/* ========================================================================
 *  Section 13: NPT Fake���� (�滻ϵͳ����API)
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
 *  Section 14: �����¼���������
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
 *  Section 15: �ϵ���� (Guest��)
 * ======================================================================== */

NTSTATUS DbgSetHardwareBreakpoint(PHW_BREAKPOINT_REQUEST Request);
NTSTATUS DbgRemoveHardwareBreakpoint(PHW_BREAKPOINT_REQUEST Request);
NTSTATUS DbgSetSoftwareBreakpoint(PSW_BREAKPOINT_REQUEST Request);
NTSTATUS DbgRemoveSoftwareBreakpoint(PSW_BREAKPOINT_REQUEST Request);
NTSTATUS DbgReadSoftwareBreakpoint(PSW_BREAKPOINT_REQUEST Request);


/* ========================================================================
 *  Section 16: VMM�ദ����
 * ======================================================================== */

VOID HvHandleDebugOp(PVCPU_CONTEXT vpData);


/* ========================================================================
 *  Section 17: IOCTL�ɷ� / Hookע��
 * ======================================================================== */

NTSTATUS DbgDispatchIoctl(
    ULONG IoControlCode, PVOID InputBuffer, ULONG InputLength,
    PVOID OutputBuffer, ULONG OutputLength, PULONG BytesReturned);

static BOOLEAN IsWithinCodeRange(PVOID Addr);

static BOOLEAN IsWithinNtoskrnl(PVOID Addr);

NTSTATUS PrepareDebugNptHookResources();
VOID LinkDebugTrampolineAddresses();