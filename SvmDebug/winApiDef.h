/**
 * @file winApiDef.h
 * @brief Windows API定义 - 函数指针typedef、系统信息结构体、Win32k窗口结构体
 * @author yewilliam
 * @date 2026/03/16
 *
 * 包含所有Hook目标函数的函数指针类型定义，
 * SystemProcessInformation/HandleInformation等系统信息结构体，
 * 以及Win32k tagWND/THREADINFO等最小窗口结构体定义。
 */

#pragma once
#include <ntifs.h>

 /** @brief 读取GDT(全局描述符表)寄存器内容到指定内存 */
EXTERN_C
VOID
_sgdt(
    _Out_ PVOID Descriptor
);


/* ========================================================================
 *  SVM_HWND 类型定义 — 全局唯一定义, 窗口句柄的内核表示
 *
 *  在用户态 HWND 是指针大小的句柄, 内核中用 HANDLE 表示。
 *  定义为独立类型以区分普通HANDLE, 提高代码可读性。
 * ======================================================================== */
#ifndef SVM_HWND_DEFINED
#define SVM_HWND_DEFINED
 /** @brief 窗口句柄类型 — 等同于HANDLE, 用于Win32k Hook中标识窗口 */
typedef HANDLE SVM_HWND;
#endif


/* ========================================================================
 *  系统信息枚举 — NtQuerySystemInformation的信息类别
 *
 *  Fake_NtQuerySystemInformation根据此枚举值决定过滤策略:
 *    - SystemProcessInformation(5):  进程链表 → 摘除保护进程节点
 *    - SystemHandleInformation(16):  句柄数组 → 移除保护进程的句柄条目
 *    - SystemExtendedHandleInformation(64): 扩展句柄数组 → 同上
 * ======================================================================== */
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0, // 基本系统信息 (处理器数量/页大小等)
    SystemProcessInformation = 5, // 进程信息链表 — 每个节点是SYSTEM_PROCESS_INFORMATION
    SystemHandleInformation = 16, // 句柄信息数组 — 16位PID, 旧版API
    SystemExtendedHandleInformation = 64, // 扩展句柄信息 — 64位PID, 新版API (Win Vista+)
} SYSTEM_INFORMATION_CLASS;


/* ========================================================================
 *  系统进程信息结构体 — SystemProcessInformation(Class 5) 的返回格式
 *
 *  NtQuerySystemInformation返回的进程列表是链表结构:
 *    - NextEntryOffset非零: 下一个节点在(当前地址 + NextEntryOffset)处
 *    - NextEntryOffset为零: 这是最后一个节点
 *
 *  Fake_NtQuerySystemInformation通过调整NextEntryOffset跳过保护进程,
 *  或将首节点内容前移来摘除链表头部的保护进程。
 * ======================================================================== */
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset; // 到下一个进程节点的字节偏移, 0=末尾 (过滤时修改此值跳过节点)
    ULONG NumberOfThreads; // 该进程的线程数量
    LARGE_INTEGER WorkingSetPrivateSize; // 私有工作集大小 (字节)
    ULONG HardFaultCount; // 硬页错误次数
    ULONG NumberOfThreadsHighWatermark; // 历史最大线程数
    ULONGLONG CycleTime; // 进程累计CPU周期数
    LARGE_INTEGER CreateTime; // 进程创建时间 (UTC, 100ns精度)
    LARGE_INTEGER UserTime; // 用户态累计CPU时间
    LARGE_INTEGER KernelTime; // 内核态累计CPU时间
    UNICODE_STRING ImageName; // 进程映像名称 (如 L"game.exe")
    KPRIORITY BasePriority; // 基础优先级
    HANDLE UniqueProcessId; // 进程PID — 过滤时用IsProtectedPid()检查此字段
    HANDLE InheritedFromUniqueProcessId; // 父进程PID
    ULONG HandleCount; // 当前打开的句柄数
    ULONG SessionId; // 会话ID (0=System, 1+=用户会话)
    ULONG_PTR UniqueProcessKey; // ETW唯一进程键
    SIZE_T PeakVirtualSize; // 峰值虚拟内存大小
    SIZE_T VirtualSize; // 当前虚拟内存大小
    ULONG PageFaultCount; // 页错误总次数
    SIZE_T PeakWorkingSetSize; // 峰值工作集大小
    SIZE_T WorkingSetSize; // 当前工作集大小
    SIZE_T QuotaPeakPagedPoolUsage; // 峰值分页池配额使用量
    SIZE_T QuotaPagedPoolUsage; // 当前分页池配额使用量
    SIZE_T QuotaPeakNonPagedPoolUsage; // 峰值非分页池配额使用量
    SIZE_T QuotaNonPagedPoolUsage; // 当前非分页池配额使用量
    SIZE_T PagefileUsage; // 页面文件使用量
    SIZE_T PeakPagefileUsage; // 峰值页面文件使用量
    SIZE_T PrivatePageCount; // 私有页面数
    LARGE_INTEGER ReadOperationCount; // 读I/O操作次数
    LARGE_INTEGER WriteOperationCount; // 写I/O操作次数
    LARGE_INTEGER OtherOperationCount; // 其他I/O操作次数
    LARGE_INTEGER ReadTransferCount; // 读I/O传输字节数
    LARGE_INTEGER WriteTransferCount; // 写I/O传输字节数
    LARGE_INTEGER OtherTransferCount; // 其他I/O传输字节数
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


/* ========================================================================
 *  句柄信息结构体 — SystemHandleInformation(Class 16) 的返回格式
 *
 *  旧版句柄枚举API, PID字段只有USHORT(16位), 最大支持PID=65535。
 *  Fake_NtQuerySystemInformation通过原地压缩数组移除保护PID的条目。
 * ======================================================================== */

 /**
  * @brief SVM_HANDLE_ENTRY — 单个句柄条目 (旧版, 16位PID)
  *
  * 对应 SYSTEM_HANDLE_TABLE_ENTRY_INFO (未公开结构体)。
  * ACE可通过枚举所有句柄发现哪些进程持有目标进程的句柄。
  */
typedef struct _SVM_HANDLE_ENTRY {
    USHORT OwnerPid; // 拥有此句柄的进程PID (16位, 过滤时检查此字段)
    USHORT BackTraceIndex; // 回溯索引 (调试用)
    UCHAR  ObjTypeIdx; // 对象类型索引 (7=Process, 8=Thread, 37=File等)
    UCHAR  Attribs; // 句柄属性 (OBJ_INHERIT/OBJ_PROTECT_CLOSE等)
    USHORT Value; // 句柄值 (如 0x1A4)
    PVOID  ObjectPtr; // 内核对象指针 (EPROCESS*/ETHREAD*等)
    ULONG  GrantedAcc; // 已授予的访问权限掩码
} SVM_HANDLE_ENTRY, * PSVM_HANDLE_ENTRY;

/**
 * @brief SVM_HANDLE_INFO — 句柄信息数组容器 (旧版)
 *
 * NtQuerySystemInformation(SystemHandleInformation)返回此结构体。
 * Handles[]是变长数组, 实际长度由NumberOfHandles决定。
 * 过滤后将NumberOfHandles更新为压缩后的数量。
 */
typedef struct _SVM_HANDLE_INFO {
    ULONG NumberOfHandles; // 句柄条目总数 (过滤后更新)
    SVM_HANDLE_ENTRY Handles[1]; // 变长句柄条目数组 (实际大小 = NumberOfHandles)
} SVM_HANDLE_INFO, * PSVM_HANDLE_INFO;


/* ========================================================================
 *  扩展句柄信息结构体 — SystemExtendedHandleInformation(Class 64)
 *
 *  新版句柄枚举API (Vista+), PID字段为ULONG_PTR(64位),
 *  支持超过65535的PID, 且包含更多信息。
 * ======================================================================== */

 /**
  * @brief SVM_HANDLE_ENTRY_EX — 单个句柄条目 (新版, 64位PID)
  *
  * 对应 SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX (未公开结构体)。
  * 与旧版的主要区别: OwnerPid从USHORT升级为ULONG_PTR。
  */
typedef struct _SVM_HANDLE_ENTRY_EX {
    PVOID      ObjectPtr; // 内核对象指针
    ULONG_PTR  OwnerPid; // 拥有此句柄的进程PID (64位, 过滤时检查此字段)
    ULONG_PTR  Value; // 句柄值
    ULONG      GrantedAcc; // 已授予的访问权限掩码
    USHORT     BackTraceIndex; // 回溯索引
    USHORT     ObjTypeIdx; // 对象类型索引
    ULONG      Attribs; // 句柄属性
    ULONG      Reserved; // 保留字段
} SVM_HANDLE_ENTRY_EX, * PSVM_HANDLE_ENTRY_EX;

/**
 * @brief SVM_HANDLE_INFO_EX — 扩展句柄信息数组容器 (新版)
 *
 * NtQuerySystemInformation(SystemExtendedHandleInformation)返回此结构体。
 * 结构与旧版类似, 但NumberOfHandles为ULONG_PTR以支持大量句柄。
 */
typedef struct _SVM_HANDLE_INFO_EX {
    ULONG_PTR NumberOfHandles; // 句柄条目总数 (过滤后更新)
    ULONG_PTR Reserved; // 保留字段
    SVM_HANDLE_ENTRY_EX Handles[1]; // 变长句柄条目数组
} SVM_HANDLE_INFO_EX, * PSVM_HANDLE_INFO_EX;


/* ========================================================================
 *  SSDT 函数指针类型定义 — 12个Nt系统调用的函数签名
 *
 *  这些typedef用于:
 *    1. 声明g_Orig*原函数指针 (由Trampoline填充)
 *    2. 在Fake_Xxx中通过g_Orig*调用原函数
 *    3. LinkTrampolineAddresses()中的类型转换
 * ======================================================================== */

 /**
  * @brief NtQuerySystemInformation — 查询各类系统信息
  * @param SystemInformationClass [in]  信息类别 (进程/句柄/模块等)
  * @param SystemInformation     [out] 输出缓冲区
  * @param SystemInformationLength [in] 缓冲区大小
  * @param ReturnLength          [out] 实际/所需数据大小
  */
typedef NTSTATUS(NTAPI* FnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

/**
 * @brief NtOpenProcess — 打开进程获取句柄
 * @param ProcessHandle   [out] 输出进程句柄
 * @param DesiredAccess   [in]  请求的访问权限
 * @param ObjectAttributes [in] 对象属性
 * @param ClientId        [in]  目标进程/线程ID
 */
typedef NTSTATUS(NTAPI* FnNtOpenProcess)(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

/**
 * @brief NtQueryInformationProcess — 查询进程详细信息
 * @param ProcessHandle         [in]  进程句柄
 * @param ProcessInformationClass [in] 信息类别
 * @param ProcessInformation    [out] 输出缓冲区
 * @param ProcessInformationLength [in] 缓冲区大小
 * @param ReturnLength          [out] 实际数据大小
 */
typedef NTSTATUS(NTAPI* FnNtQueryInformationProcess)(
    HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

/**
 * @brief NtQueryVirtualMemory — 查询进程虚拟内存区域信息
 * @param ProcessHandle        [in]  进程句柄
 * @param BaseAddress          [in]  查询的起始地址
 * @param MemoryInformationClass [in] 信息类别 (Basic/Region/Image等)
 * @param MemoryInformation    [out] 输出缓冲区
 * @param MemoryInformationLength [in] 缓冲区大小
 * @param ReturnLength         [out] 实际数据大小
 */
typedef NTSTATUS(NTAPI* FnNtQueryVirtualMemory)(
    HANDLE ProcessHandle, PVOID BaseAddress, ULONG MemoryInformationClass,
    PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

/**
 * @brief NtDuplicateObject — 跨进程复制句柄
 * @param SourceProcessHandle [in]  源进程句柄
 * @param SourceHandle        [in]  要复制的句柄
 * @param TargetProcessHandle [in]  目标进程句柄
 * @param TargetHandle        [out] 复制后的新句柄
 * @param DesiredAccess       [in]  新句柄权限
 * @param HandleAttributes    [in]  新句柄属性
 * @param Options             [in]  操作选项
 */
typedef NTSTATUS(NTAPI* FnNtDuplicateObject)(
    HANDLE SourceProcessHandle, HANDLE SourceHandle,
    HANDLE TargetProcessHandle, PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);

/**
 * @brief NtGetNextProcess — 遍历系统进程链表获取下一个进程
 * @param ProcessHandle   [in]  当前进程句柄 (NULL=从头开始)
 * @param DesiredAccess   [in]  请求的访问权限
 * @param HandleAttributes [in] 句柄属性
 * @param Flags           [in]  遍历标志
 * @param NewProcessHandle [out] 下一个进程句柄
 */
typedef NTSTATUS(NTAPI* FnNtGetNextProcess)(
    HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle);

/**
 * @brief NtGetNextThread — 遍历进程的线程链表获取下一个线程
 * @param ProcessHandle   [in]  进程句柄
 * @param ThreadHandle    [in]  当前线程句柄 (NULL=从头开始)
 * @param DesiredAccess   [in]  请求的访问权限
 * @param HandleAttributes [in] 句柄属性
 * @param Flags           [in]  遍历标志
 * @param NewThreadHandle [out] 下一个线程句柄
 */
typedef NTSTATUS(NTAPI* FnNtGetNextThread)(
    HANDLE ProcessHandle, HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes,
    ULONG Flags, PHANDLE NewThreadHandle);

/**
 * @brief NtReadVirtualMemory — 读取目标进程的虚拟内存
 * @param ProcessHandle    [in]  进程句柄
 * @param BaseAddress      [in]  读取起始地址
 * @param Buffer           [out] 数据输出缓冲区
 * @param Size             [in]  读取字节数
 * @param NumberOfBytesRead [out] 实际读取字节数
 */
typedef NTSTATUS(NTAPI* FnNtReadVirtualMemory)(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T Size, PSIZE_T NumberOfBytesRead);

/**
 * @brief NtWriteVirtualMemory — 向目标进程写入虚拟内存
 * @param ProcessHandle       [in]  进程句柄
 * @param BaseAddress         [in]  写入起始地址
 * @param Buffer              [in]  待写入数据
 * @param Size                [in]  写入字节数
 * @param NumberOfBytesWritten [out] 实际写入字节数
 */
typedef NTSTATUS(NTAPI* FnNtWriteVirtualMemory)(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T Size, PSIZE_T NumberOfBytesWritten);

/**
 * @brief NtProtectVirtualMemory — 修改进程虚拟内存的保护属性
 * @param ProcessHandle [in]     进程句柄
 * @param BaseAddress   [in,out] 目标区域基地址 (输出实际修改的基地址)
 * @param RegionSize    [in,out] 区域大小 (输出实际修改的大小)
 * @param NewProtect    [in]     新保护属性 (PAGE_EXECUTE_READWRITE等)
 * @param OldProtect    [out]    修改前的保护属性
 */
typedef NTSTATUS(NTAPI* FnNtProtectVirtualMemory)(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

/**
 * @brief NtTerminateProcess — 终止目标进程
 * @param ProcessHandle [in] 进程句柄 (NtCurrentProcess()=自身)
 * @param ExitStatus    [in] 退出状态码
 */
typedef NTSTATUS(NTAPI* FnNtTerminateProcess)(
    HANDLE ProcessHandle, NTSTATUS ExitStatus);

/**
 * @brief NtCreateThreadEx — 在目标进程中创建线程 (远程线程注入的核心API)
 * @param ThreadHandle     [out] 新线程句柄
 * @param DesiredAccess    [in]  线程访问权限
 * @param ObjectAttributes [in]  对象属性
 * @param ProcessHandle    [in]  目标进程句柄
 * @param StartRoutine     [in]  线程入口函数地址
 * @param Argument         [in]  线程参数
 * @param CreateFlags      [in]  创建标志 (CREATE_SUSPENDED等)
 * @param ZeroBits         [in]  地址空间零位数
 * @param StackSize        [in]  初始栈大小
 * @param MaximumStackSize [in]  最大栈大小
 * @param AttributeList    [in]  线程属性列表 (PS_ATTRIBUTE_LIST)
 */
typedef NTSTATUS(NTAPI* FnNtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
    PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits,
    SIZE_T StackSize, SIZE_T MaximumStackSize,
    PVOID AttributeList);


/* ========================================================================
 *  线程保护函数指针 — 5个线程操作Nt系统调用
 *
 *  ACE典型攻击路径: SuspendThread → GetContextThread(读DR) → ReadMemory → ResumeThread
 *  通过Hook这5个函数完整封堵此攻击链。
 * ======================================================================== */

 /**
  * @brief NtSuspendThread — 挂起目标线程
  * @param ThreadHandle        [in]  线程句柄
  * @param PreviousSuspendCount [out] 挂起前的暂停计数 (用于嵌套挂起管理)
  */
typedef NTSTATUS(NTAPI* FnNtSuspendThread)(
    HANDLE ThreadHandle, PULONG PreviousSuspendCount);

/**
 * @brief NtResumeThread — 恢复被挂起的线程
 * @param ThreadHandle        [in]  线程句柄
 * @param PreviousSuspendCount [out] 恢复前的暂停计数
 */
typedef NTSTATUS(NTAPI* FnNtResumeThread)(
    HANDLE ThreadHandle, PULONG PreviousSuspendCount);

/**
 * @brief NtGetContextThread — 获取线程的CPU上下文 (含通用寄存器/调试寄存器)
 * @param ThreadHandle  [in]     线程句柄
 * @param ThreadContext [in,out] CONTEXT结构体 (ContextFlags指定要获取的寄存器组)
 * @note ACE通过此函数读取DR0-DR7发现硬件断点, Fake版本会清零DR寄存器
 */
typedef NTSTATUS(NTAPI* FnNtGetContextThread)(
    HANDLE ThreadHandle, PCONTEXT ThreadContext);

/**
 * @brief NtSetContextThread — 设置线程的CPU上下文
 * @param ThreadHandle  [in] 线程句柄
 * @param ThreadContext [in] 包含要设置的寄存器值的CONTEXT
 * @note ACE可能通过此函数清除硬件断点或篡改RIP劫持执行流
 */
typedef NTSTATUS(NTAPI* FnNtSetContextThread)(
    HANDLE ThreadHandle, PCONTEXT ThreadContext);

/**
 * @brief NtQueryInformationThread — 查询线程详细信息
 * @param ThreadHandle           [in]  线程句柄
 * @param ThreadInformationClass [in]  信息类别 (0=BasicInfo含OwnerPID, 9=入口地址)
 * @param ThreadInformation      [out] 输出缓冲区
 * @param ThreadInformationLength [in] 缓冲区大小
 * @param ReturnLength           [out] 实际数据大小
 */
typedef NTSTATUS(NTAPI* FnNtQueryInformationThread)(
    HANDLE ThreadHandle, ULONG ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength,
    PULONG ReturnLength);


/* ========================================================================
 *  内核导出函数指针 — 6个Ring0级别的进程/对象操作函数
 *
 *  这些函数不经过SSDT, 是内核内部直接调用的API。
 *  ACE的驱动可能绕过Nt*系统调用直接使用这些函数, 因此也需要Hook。
 * ======================================================================== */

 /**
  * @brief PsLookupProcessByProcessId — 通过PID查找EPROCESS对象
  * @param ProcessId [in]  进程PID
  * @param Process   [out] EPROCESS指针 (成功时带+1引用计数, 需ObDereferenceObject)
  * @note 内核中最常用的PID→进程转换API, ACE驱动必经之路
  */
typedef NTSTATUS(NTAPI* FnPsLookupProcessByProcessId)(
    HANDLE ProcessId, PEPROCESS* Process);

/**
 * @brief PsLookupThreadByThreadId — 通过TID查找ETHREAD对象
 * @param ThreadId [in]  线程ID
 * @param Thread   [out] ETHREAD指针 (成功时带+1引用计数)
 */
typedef NTSTATUS(NTAPI* FnPsLookupThreadByThreadId)(
    HANDLE ThreadId, PETHREAD* Thread);

/**
 * @brief ObReferenceObjectByHandle — 通过句柄获取内核对象指针 (带引用计数)
 * @param Handle            [in]  对象句柄
 * @param DesiredAccess     [in]  请求的访问权限
 * @param ObjectType        [in]  期望的对象类型 (PsProcessType/PsThreadType等)
 * @param AccessMode        [in]  访问模式 (UserMode/KernelMode)
 * @param Object            [out] 对象指针 (EPROCESS* /ETHREAD* / FILE_OBJECT * 等)
 * @param HandleInformation[out] 句柄信息(含GrantedAccess, 被裁剪的关键字段)
 * @note 实际Hook的是内部函数ObpReferenceObjectByHandleWithTag
*/
    typedef NTSTATUS(NTAPI* FnObReferenceObjectByHandle)(
        HANDLE Handle, ACCESS_MASK DesiredAccess,
        POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode,
        PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation);

 /**
  * @brief MmCopyVirtualMemory — 内核级跨进程内存拷贝
  * @param FromProcess        [in]  源进程EPROCESS
  * @param FromAddress        [in]  源地址
  * @param ToProcess          [in]  目标进程EPROCESS
  * @param ToAddress          [in]  目标地址
  * @param BufferSize         [in]  拷贝字节数
  * @param PreviousMode       [in]  调用者模式
  * @param NumberOfBytesCopied [out] 实际拷贝字节数
  * @note NtReadVirtualMemory/NtWriteVirtualMemory的底层实现, ACE可能直接调用绕过
  */
 typedef NTSTATUS(NTAPI* FnMmCopyVirtualMemory)(
     PEPROCESS FromProcess, PVOID FromAddress,
     PEPROCESS ToProcess, PVOID ToAddress,
     SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
     PSIZE_T NumberOfBytesCopied);

 /**
  * @brief PsGetNextProcessThread — 遍历进程的线程链表
  * @param Process [in] 进程EPROCESS
  * @param Thread  [in] 当前线程PETHREAD (NULL=第一个)
  * @return 下一个PETHREAD, NULL=遍历结束
  * @note 当前版本预留, 未实际Hook
  */
 typedef PETHREAD(NTAPI* FnPsGetNextProcessThread)(
     PEPROCESS Process, PETHREAD Thread);

 /**
  * @brief KeStackAttachProcess — 将当前线程的地址空间切换到目标进程
  * @param Process  [in]  目标进程EPROCESS
  * @param ApcState [out] 保存的APC状态 (需配对KeUnstackDetachProcess恢复)
  * @note 切换后当前线程可直接访问目标进程的用户态地址空间
  */
 typedef VOID(NTAPI* FnKeStackAttachProcess)(
     PEPROCESS Process, PKAPC_STATE ApcState);

 /* ZwQuerySystemInformation未在WDK标准头文件中声明 */
 extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
     ULONG SystemInformationClass,
     PVOID SystemInformation,
     ULONG SystemInformationLength,
     PULONG ReturnLength);

 /* ========================================================================
  *  SSSDT (Win32k) 函数指针 — 4个窗口子系统调用
  *
  *  Win32k的系统调用通过Shadow SSDT (SSSDT/W32pServiceTable)分发。
  *  这些函数运行在GUI进程的Session地址空间中,
  *  解析时需要在csrss/explorer等GUI进程上下文中操作。
  * ======================================================================== */

  /**
   * @brief NtUserFindWindowEx — 按类名/标题查找窗口 (FindWindowEx的内核实现)
   * @param hwndParent     [in] 父窗口 (NULL=桌面)
   * @param hwndChildAfter [in] 搜索起点子窗口 (NULL=第一个)
   * @param lpszClass      [in] 窗口类名 (可选)
   * @param lpszWindow     [in] 窗口标题 (可选)
   * @param dwType         [in] 查找类型标志
   * @return 找到的窗口句柄, 未找到返回NULL
   */
 typedef SVM_HWND(NTAPI* FnNtUserFindWindowEx)(
     SVM_HWND hwndParent, SVM_HWND hwndChildAfter,
     PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, ULONG dwType);

 /**
  * @brief NtUserWindowFromPoint — 获取屏幕坐标处的窗口 (WindowFromPoint的内核实现)
  * @param x [in] 屏幕X坐标 (像素)
  * @param y [in] 屏幕Y坐标 (像素)
  * @return 该坐标处最顶层窗口句柄
  */
 typedef SVM_HWND(NTAPI* FnNtUserWindowFromPoint)(
     LONG x, LONG y);

 /**
  * @brief ValidateHwnd — 验证窗口句柄并返回内核窗口对象 (win32kbase内部导出)
  * @param hwnd [in] 窗口句柄
  * @return 内核tagWND对象指针 (实际类型为WND*), 无效句柄返回NULL
  * @note 窗口隐藏的核心Hook点 — 返回NULL使外部进程"看不到"保护窗口
  */
 typedef PVOID(NTAPI* FnValidateHwnd)(
     SVM_HWND hwnd);

 /**
  * @brief NtUserBuildHwndList — 构建窗口句柄枚举列表 (EnumWindows的内核实现)
  * @param hdesk            [in]     桌面句柄
  * @param hwndNext         [in]     枚举起始窗口
  * @param fEnumChildren    [in]     是否枚举子窗口 (1=是)
  * @param bRemoveImmersive [in]     是否排除UWP沉浸式窗口
  * @param idThread         [in]     按线程ID过滤 (0=不过滤)
  * @param cHwndMax         [in]     phwndFirst数组最大容量
  * @param phwndFirst       [in,out] 窗口句柄输出数组
  * @param pcHwndNeeded     [in,out] 输入: 数组大小; 输出: 实际窗口数
  * @note Win10 8参数版本, 过滤后原地压缩数组并更新pcHwndNeeded
  */
 typedef NTSTATUS(NTAPI* FnNtUserBuildHwndList)(
     HANDLE hdesk, SVM_HWND hwndNext, ULONG fEnumChildren,
     ULONG bRemoveImmersive, ULONG idThread,
     ULONG cHwndMax, SVM_HWND* phwndFirst, ULONG* pcHwndNeeded);


 /* ========================================================================
  *  内部未导出函数指针 — 通过模式扫描定位
  * ======================================================================== */

  /**
   * @brief PspReferenceCidTableEntry — CID(客户端ID)表项引用函数
   * @param Id       [in] 进程PID或线程TID
   * @param IsThread [in] TRUE=查找线程, FALSE=查找进程
   * @return CID表项指针 (内部HANDLE_TABLE_ENTRY)
   * @note PsLookupProcessByProcessId的底层实现, 通过模式扫描PsLookupProcessByProcessId中的CALL指令定位
   */
 typedef PVOID(NTAPI* FnPspReferenceCidTableEntry)(
     HANDLE Id, BOOLEAN IsThread);


 /* ========================================================================
  *  Win32k 最小窗口结构体 — 用于ValidateHwnd Hook中解析窗口所属进程
  *
  *  内核中窗口对象(tagWND)非常庞大(几百字节), 这里只定义了
  *  Hook逻辑所需的最小字段子集。
  *
  *  窗口→进程的解析链:
  *    tagWND+0x10 → pti (THREADINFO*)
  *    THREADINFO+0x00 → pEThread (ETHREAD*)
  *    PsGetThreadProcess(pEThread) → EPROCESS*
  *    PsGetProcessId(EPROCESS*) → PID
  * ======================================================================== */
#pragma pack(push, 8)

  /**
   * @brief SVM_W32THREAD — Win32k线程信息结构体精简版 (THREADINFO)
   *
   * 完整的THREADINFO包含消息队列/输入状态/会话信息等大量字段,
   * 这里只保留第一个字段pEThread用于获取线程所属进程。
   *
   * @note THREADINFO是Session空间的结构体, 必须在GUI进程上下文中访问
   */
 typedef struct _SVM_W32THREAD {
     PETHREAD pEThread; // +0x00: 此Win32线程对应的ETHREAD内核对象指针
 } SVM_W32THREAD, * PSVM_W32THREAD;

 /**
  * @brief SVM_WND — Win32k窗口对象结构体精简版 (tagWND)
  *
  * 完整的tagWND包含窗口矩形/样式/消息处理/父子关系等几十个字段,
  * 这里只定义了ValidateHwnd Hook所需的最小路径:
  *   pwnd->pti->pEThread → 可获取窗口所属进程
  *
  * 内存布局 (x64):
  *   +0x00  hHandle   — HEAD.h (窗口句柄, 内核态版本)
  *   +0x08  cLockObj  — HEAD.cLockObj (对象锁计数)
  *   +0x0C  _pad      — 4字节对齐填充
  *   +0x10  pti       — THROBJHEAD.pti (指向THREADINFO)
  */
 typedef struct _SVM_WND {
     PVOID           hHandle; // +0x00: 窗口句柄 (HEAD.h, 内核态表示)
     ULONG           cLockObj; // +0x08: 对象锁引用计数 (HEAD.cLockObj)
     ULONG           _pad; // +0x0C: 4字节对齐填充
     PSVM_W32THREAD  pti; // +0x10: 线程信息指针 (THROBJHEAD.pti → THREADINFO)
 } SVM_WND, * PSVM_WND;

#pragma pack(pop)


 /* ========================================================================
  *  外部NT API声明 — 编译器需要的前向声明
  * ======================================================================== */

  /** @brief NtQuerySystemInformation — 查询系统信息 (内核导出, 供驱动直接调用) */
 EXTERN_C NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

 /** @brief NtReadVirtualMemory — 读取进程内存 (内核导出) */
 EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

 /** @brief PsGetProcessWow64Process — 获取进程的WOW64 PEB指针 (32位兼容层)
  *  @return 32位PEB指针, 非WOW64进程返回NULL
  *  @note 用于进程伪装时同时处理PEB32的参数和模块列表
  */
 EXTERN_C NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(PEPROCESS Process);