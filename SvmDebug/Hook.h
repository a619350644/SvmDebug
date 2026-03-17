/**
 * @file Hook.h
 * @brief NPT Hook框架头文件 - Hook上下文结构体、索引枚举与函数声明
 * @author yewilliam
 * @date 2026/03/16
 */

#pragma once
#include <ntifs.h>

 /** @brief Hook槽位数组最大容量, 支持同时挂钩的最大函数数量 */
#define HOOK_MAX_COUNT 64
#pragma warning(disable: 4201)

/* ========================================================================
 *  未导出的内核API声明
 * ======================================================================== */

 /** @brief 获取进程的PEB(进程环境块)指针 (未导出, 需NTKERNELAPI声明) */
EXTERN_C NTKERNELAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);

/** @brief 获取进程的ImageFileName (15字节短名, 如"explorer.exe") */
EXTERN_C NTKERNELAPI PUCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);


/* ========================================================================
 *  PEB 相关精简结构体 — 用于读取进程参数(路径/命令行)
 * ======================================================================== */

 /**
  * @brief RTL_USER_PROCESS_PARAMETERS 精简版
  *
  * PEB->ProcessParameters 指向此结构体。
  * 只保留了进程伪装(FakeProcessByPid)需要的两个关键字段:
  *   - ImagePathName: 进程可执行文件的完整NT路径 (如 \Device\HarddiskVolume3\Windows\explorer.exe)
  *   - CommandLine:   进程启动命令行参数
  *
  * Reserved字段跳过了CurrentDirectory、DllPath、WindowTitle等不需要的成员。
  */
typedef struct _RTL_USER_PROCESS_PARAMETERS_LITE {
    UCHAR Reserved1[16]; // 跳过 MaximumLength + Length + Flags + DebugFlags
    PVOID Reserved2[10]; // 跳过 ConsoleHandle ~ DllPath (10个指针/UNICODE_STRING)
    UNICODE_STRING ImagePathName; // 进程映像完整路径 (NT格式, 可被伪装覆写)
    UNICODE_STRING CommandLine; // 进程命令行字符串 (可被伪装覆写)
} RTL_USER_PROCESS_PARAMETERS_LITE, * PRTL_USER_PROCESS_PARAMETERS_LITE;

/**
 * @brief PEB (进程环境块) 精简版
 *
 * 每个用户态进程都有一个PEB, 位于用户空间。
 * 只保留了Hook和进程伪装需要的关键字段:
 *   - BeingDebugged: 调试标志 (IsDebuggerPresent检查此字段)
 *   - Ldr:           PEB_LDR_DATA指针, 包含已加载模块链表 (DLL列表)
 *   - ProcessParameters: 进程参数 (路径/命令行/环境变量)
 */
typedef struct _PEB_LITE {
    UCHAR Reserved1[2]; // 跳过 InheritedAddressSpace + ReadImageFileExecOptions
    UCHAR BeingDebugged; // 调试标志: 0=未调试, 1=被调试
    UCHAR Reserved2[1]; // 跳过 BitField (UCHAR)
    PVOID Reserved3[2]; // 跳过 Mutant + ImageBaseAddress
    PVOID Ldr; // PEB_LDR_DATA指针, 包含InLoadOrderModuleList等模块链表
    PRTL_USER_PROCESS_PARAMETERS_LITE ProcessParameters; // 进程参数: 映像路径/命令行/环境变量
} PEB_LITE, * PPEB_LITE;


/* ========================================================================
 *  vCPU 上下文前向声明
 * ======================================================================== */

 /** @brief vCPU上下文结构体前向声明, 包含VMCB/主机栈/NPT页表等虚拟化核心数据 */
typedef struct _VCPU_CONTEXT VCPU_CONTEXT, * PVCPU_CONTEXT;


/* ========================================================================
 *  内核模块链表结构体 — 用于驱动隐藏(DKOM)
 * ======================================================================== */

 /**
  * @brief KLDR_DATA_TABLE_ENTRY — 内核加载器数据表项
  *
  * 每个已加载的内核模块(驱动/DLL)在PsLoadedModuleList链表中
  * 都有一个此结构体。驱动隐藏(HideDriver)通过DKOM摘除
  * InLoadOrderLinks节点来使驱动从模块枚举中消失。
  */
typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks; // 加载顺序双向链表节点 (DKOM摘除此节点实现隐藏)
    PVOID ExceptionTable; // 异常处理表指针
    ULONG ExceptionTableSize; // 异常表大小
    PVOID GpValue; // Global Pointer值 (IA64)
    PVOID NonPagedDebugInfo; // 非分页调试信息
    PVOID DllBase; // 模块加载基地址 (ImageBase)
    PVOID EntryPoint; // 模块入口点 (DriverEntry地址)
    ULONG SizeOfImage; // 模块映像大小 (字节)
    UNICODE_STRING FullDllName; // 完整路径 (如 \SystemRoot\System32\drivers\xxx.sys)
    UNICODE_STRING BaseDllName; // 短文件名 (如 xxx.sys)
    ULONG Flags; // 模块标志
    USHORT LoadCount; // 引用计数
    USHORT TlsIndex; // TLS索引
    union {
        LIST_ENTRY HashLinks; // 哈希桶链表节点
        struct {
            PVOID SectionPointer; // SECTION_OBJECT指针 (删除驱动文件时需清除)
            ULONG CheckSum; // PE校验和
        };
    };
    union {
        ULONG TimeDateStamp; // PE时间戳
        PVOID LoadedImports; // 已加载导入表
    };
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;


/* ========================================================================
 *  NPT Hook 上下文结构体 — 每个Hook点的完整状态
 * ======================================================================== */

 /**
  * @brief NPT_HOOK_CONTEXT — NPT(嵌套页表) Hook上下文
  *
  * AMD SVM的NPT Hook原理:
  *   1. 将目标函数所在物理页的NPT映射指向FakePage(含JMP到ProxyFunction)
  *   2. 执行流命中FakePage时跳转到Fake_Xxx拦截函数
  *   3. 拦截函数通过TrampolinePage调用原函数(跳回OriginalPage)
  *
  * 每个被Hook的函数对应一个此结构体实例, 存储在g_HookList[]数组中。
  */
typedef struct _NPT_HOOK_CONTEXT {
    BOOLEAN IsUsed; // 此槽位是否已被占用
    BOOLEAN ResourcesReady; // 所有页表资源(FakePage/Trampoline)是否已创建完成
    PVOID TargetAddress; // 目标函数的虚拟地址 (如 nt!NtOpenProcess)
    ULONG64 TargetPa; // 目标函数的物理地址 (MmGetPhysicalAddress转换)
    PVOID ProxyFunction; // 替代函数(Fake_Xxx)的虚拟地址
    PVOID OriginalPageBase; // 目标函数所在原始物理页的虚拟映射基地址 (页对齐)
    ULONG64 OriginalPagePa; // 原始物理页的物理地址 (4KB对齐)
    PVOID FakePage; // 伪造页的虚拟地址 — 复制原页内容后在目标偏移处写入JMP
    ULONG64 FakePagePa; // 伪造页的物理地址 — NPT将此页映射替换原页
    PVOID TrampolinePage; // 跳床页虚拟地址 — 包含被覆盖的原始指令 + JMP回原函数
    SIZE_T HookedBytes; // Hook修改的字节数 (通常为14, 即FF25 JMP [rip] + 8字节地址)
    ULONG TrampolineLength; // 跳板总长度 = 被偷指令 + 14字节跳转
    ULONG StolenBytesLength; // 被覆盖(偷取)的原始指令总长度 (需>=14字节, 按指令边界对齐)
} NPT_HOOK_CONTEXT, * PNPT_HOOK_CONTEXT;

/** @brief 全局Hook槽位数组, 下标为HOOK_INDEX枚举值 */
extern NPT_HOOK_CONTEXT g_HookList[HOOK_MAX_COUNT];


/* ========================================================================
 *  寄存器上下文结构体 — VMEXIT时保存的通用寄存器
 * ======================================================================== */

 /**
  * @brief REGISTER_CONTEXT — VMEXIT时保存的x64通用寄存器+RFLAGS
  *
  * 汇编VMEXIT handler在进入C代码前将所有通用寄存器压栈,
  * 形成此结构体。Fake函数(如Cpp_Fake_NtUserBuildHwndList)
  * 可通过此结构体读取/修改Guest的寄存器值。
  *
  * @note 使用#pragma pack(1)确保无填充, 与汇编push顺序严格匹配
  */
#pragma pack(push, 1)
typedef struct _REGISTER_CONTEXT {
    ULONG64 Rax; // 通用寄存器RAX (常用于返回值)
    ULONG64 Rcx; // 通用寄存器RCX (第1个参数, Windows x64调用约定)
    ULONG64 Rdx; // 通用寄存器RDX (第2个参数)
    ULONG64 Rbx; // 通用寄存器RBX (被调用者保存)
    ULONG64 Rsp; // 栈指针RSP
    ULONG64 Rbp; // 帧指针RBP
    ULONG64 Rsi; // 源变址寄存器RSI
    ULONG64 Rdi; // 目标变址寄存器RDI
    ULONG64 R8; // 通用寄存器R8  (第3个参数)
    ULONG64 R9; // 通用寄存器R9  (第4个参数)
    ULONG64 R10; // 通用寄存器R10 (调用者保存, syscall时保存RCX)
    ULONG64 R11; // 通用寄存器R11 (调用者保存, syscall时保存RFLAGS)
    ULONG64 R12; // 通用寄存器R12 (被调用者保存)
    ULONG64 R13; // 通用寄存器R13 (被调用者保存)
    ULONG64 R14; // 通用寄存器R14 (被调用者保存)
    ULONG64 R15; // 通用寄存器R15 (被调用者保存)
    ULONG64 Rflags; // RFLAGS寄存器 (包含CF/ZF/SF/OF等标志位)
} REGISTER_CONTEXT, * PREGISTER_CONTEXT;
#pragma pack(pop)


/* ========================================================================
 *  全局跳床地址 — 供汇编VMEXIT handler使用
 * ======================================================================== */

 /**
  * @brief NtUserBuildHwndList的Trampoline地址
  *
  * 汇编入口(Asm_Fake_NtUserBuildHwndList)需要此地址
  * 来调用原始NtUserBuildHwndList。由LinkTrampolineAddresses()填充。
  */
#ifdef __cplusplus
extern "C" ULONG64 g_Trampoline_NtUserBuildHwndList;
#else
extern ULONG64 g_Trampoline_NtUserBuildHwndList;
#endif


/* ========================================================================
 *  HOOK_INDEX — Hook索引枚举, 全局唯一定义点
 *
 *  每个枚举值对应g_HookList[]数组的下标。
 *  所有文件通过 #include "Hook.h" 引用此枚举。
 * ======================================================================== */

 /**
  * @brief HOOK_INDEX — 所有NPT Hook点的索引枚举
  *
  * 按功能分为5大类:
  *   - SSDT系统调用 (0~11):  进程发现/访问/操控拦截
  *   - 线程保护 (12~16):      SuspendThread/GetContext等ACE攻击路径拦截
  *   - 内核导出函数 (17~22): PsLookup/ObRef/MmCopy等内核级拦截
  *   - SSSDT Win32k (23~26): 窗口查找/枚举/验证过滤
  *   - 内部函数 (27):         模式扫描定位的未导出函数
  */
typedef enum _HOOK_INDEX {
    /* ---- SSDT 系统调用 (用户态可直接调用的Nt*函数) ---- */
    HOOK_NtQuerySystemInformation = 0, // 系统信息查询 — 过滤进程列表/句柄列表
    HOOK_NtOpenProcess, // 进程打开 — 阻止获取保护进程句柄
    HOOK_NtQueryInformationProcess, // 进程信息查询 — 阻止查询保护进程详情
    HOOK_NtQueryVirtualMemory, // 虚拟内存查询 — 阻止探测保护进程内存布局
    HOOK_NtDuplicateObject, // 句柄复制 — 阻止间接获取保护进程句柄
    HOOK_NtGetNextProcess, // 进程遍历 — 跳过保护进程
    HOOK_NtGetNextThread, // 线程遍历 — 阻止枚举保护进程的线程
    HOOK_NtReadVirtualMemory, // 内存读取 — 返回全零欺骗(不拒绝, 更隐蔽)
    HOOK_NtWriteVirtualMemory, // 内存写入 — 阻止向保护进程写入
    HOOK_NtProtectVirtualMemory, // 内存保护修改 — 阻止修改保护进程内存属性
    HOOK_NtTerminateProcess, // 进程终止 — 阻止杀死保护进程
    HOOK_NtCreateThreadEx, // 远程线程创建 — 阻止DLL注入/代码注入

    /* ---- 线程保护 (ACE攻击路径: Suspend→GetContext→ReadMem→Resume) ---- */
    HOOK_NtSuspendThread, // 线程挂起 — 阻止冻结保护线程
    HOOK_NtResumeThread, // 线程恢复 — 阻止外部恢复保护线程
    HOOK_NtGetContextThread, // 获取线程上下文 — 擦除DR0-DR7硬件断点
    HOOK_NtSetContextThread, // 设置线程上下文 — 阻止篡改RIP/DR寄存器
    HOOK_NtQueryInformationThread, // 线程信息查询 — 阻止泄露OwnerPID/入口地址

    /* ---- 内核导出函数 (Ring0级别的进程/对象操作) ---- */
    HOOK_PsLookupProcessByProcessId, // PID→EPROCESS查找 — 阻止获取保护进程对象
    HOOK_PsLookupThreadByThreadId, // TID→ETHREAD查找 — 阻止获取保护线程对象
    HOOK_ObReferenceObjectByHandle, // 句柄→对象引用 — 裁剪保护对象的GrantedAccess
    HOOK_MmCopyVirtualMemory, // 内核内存拷贝 — 阻止跨进程内存复制
    HOOK_PsGetNextProcessThread, // 进程线程遍历 — (预留, 当前未使用)
    HOOK_KeStackAttachProcess, // 进程上下文附加 — 当前直接透传

    /* ---- SSSDT Win32k影子系统调用 (窗口子系统) ---- */
    HOOK_NtUserFindWindowEx, // 窗口查找 — 跳过保护进程的窗口
    HOOK_NtUserWindowFromPoint, // 坐标点查窗口 — 保护窗口返回NULL
    HOOK_NtUserBuildHwndList, // 窗口列表枚举 — 从列表中移除保护窗口
    HOOK_ValidateHwnd, // 窗口句柄验证 — win32kbase内部导出, 窗口隐藏核心

    /* ---- 内部函数 (通过模式扫描定位的未导出函数) ---- */
    HOOK_PspReferenceCidTableEntry, // CID表项引用 — PID/TID查找的底层函数

    HOOK_MAX_ENUM_COUNT // 枚举计数哨兵, 用于数组边界检查
} HOOK_INDEX;


/* ========================================================================
 *  NPT Hook 操作函数
 * ======================================================================== */

 /**
  * @brief 注册一个NPT Hook (填充g_HookList槽位)
  * @param [in] TargetAddress  - 要Hook的目标函数虚拟地址
  * @param [in] ProxyFunction  - 替代函数(Fake_Xxx)地址
  * @return STATUS_SUCCESS
  */
NTSTATUS RegisterNptHook(PVOID TargetAddress, PVOID ProxyFunction);

/**
 * @brief 准备所有NPT Hook — 分配FakePage/Trampoline等资源
 * @return STATUS_SUCCESS
 */
NTSTATUS PrepareAllNptHooks(void);

/**
 * @brief 在NPT页表中激活所有已准备的Hook
 * @param [in] vpData - 当前vCPU上下文 (包含NPT页表根)
 * @return STATUS_SUCCESS
 */
NTSTATUS ActivateAllNptHooks(PVCPU_CONTEXT vpData);

/**
 * @brief 清理所有NPT Hook — 释放FakePage/TrampolinePage, 重置g_HookList
 */
VOID CleanupAllNptHooks(void);

/**
 * @brief 通过缺页物理地址查找对应的Hook上下文
 * @param [in] FaultPa - #NPF(嵌套页错误)的物理地址
 * @return 匹配的NPT_HOOK_CONTEXT指针, 未找到返回NULL
 */
PNPT_HOOK_CONTEXT FindHookByFaultPa(ULONG64 FaultPa);


/* ========================================================================
 *  NPT Hook 内部构建函数
 * ======================================================================== */

 /**
  * @brief 构建FakePage — 复制原页内容, 在目标偏移处写入JMP到ProxyFunction
  * @param [in,out] HookContext - Hook上下文 (FakePage/FakePagePa将被填充)
  * @return STATUS_SUCCESS
  */
NTSTATUS BuildPage(PNPT_HOOK_CONTEXT HookContext);

/**
 * @brief 构建TrampolinePage — 保存被覆盖指令 + 追加JMP回原函数
 * @param [in,out] HookContext - Hook上下文 (TrampolinePage将被填充)
 * @return STATUS_SUCCESS
 */
NTSTATUS BuildTrampoline(PNPT_HOOK_CONTEXT HookContext);

/**
 * @brief 在FakePage上执行Hook — 写入跳转指令
 * @param [in,out] HookContext - Hook上下文
 * @return STATUS_SUCCESS
 */
NTSTATUS HookPage(PNPT_HOOK_CONTEXT HookContext);

/**
 * @brief 一站式准备单个NPT Hook的所有资源
 * @param [in]     TargetAddress  - 目标函数虚拟地址
 * @param [in]     ProxyFunction  - 替代函数地址
 * @param [in,out] HookContext    - 待填充的Hook上下文
 * @return STATUS_SUCCESS
 */
NTSTATUS PrepareNptHookResources(PVOID TargetAddress, PVOID ProxyFunction, PNPT_HOOK_CONTEXT HookContext);

/**
 * @brief 在NPT中激活单个Hook — 修改NPT PTE指向FakePage
 * @param [in] vpData      - vCPU上下文
 * @param [in] HookContext - 已准备好的Hook上下文
 * @return STATUS_SUCCESS
 */
NTSTATUS ActivateNptHookInNpt(PVCPU_CONTEXT vpData, PNPT_HOOK_CONTEXT HookContext);

/**
 * @brief 释放单个NPT Hook的资源 — ExFreePool释放FakePage/TrampolinePage
 * @param [in,out] HookContext - 要释放的Hook上下文
 */
VOID FreeNptHook(PNPT_HOOK_CONTEXT HookContext);

/**
 * @brief 从内核模块链表中隐藏驱动 — DKOM摘除
 * @param [in] DriverObject - 驱动对象指针
 * @return STATUS_SUCCESS
 */
NTSTATUS HideDriver(PDRIVER_OBJECT DriverObject);

/**
 * @brief 获取Nt函数的真实内核地址 (通过Zw导出+SSDT索引计算)
 * @param [in] ZwName - Zw函数名
 * @return Nt函数虚拟地址
 */
PVOID GetRealNtAddress(PCWSTR ZwName);


/* ========================================================================
 *  跳转指令模板 — 用于FakePage和TrampolinePage的代码注入
 * ======================================================================== */

 /**
  * @brief RedirectInstruction — 14字节绝对跳转指令 (用于FakePage)
  *
  * 机器码布局:
  *   FF 25 00 00 00 00       ; JMP [RIP+0] — 跳转到紧随其后的8字节地址
  *   XX XX XX XX XX XX XX XX ; 64位目标地址 (ProxyFunction的地址)
  *
  * 写入FakePage中目标函数偏移处, 执行时跳转到Fake_Xxx。
  */
typedef union {
    struct {
        unsigned char jmp_opcode[6]; // FF 25 00 00 00 00 — JMP [RIP+0] 操作码
        unsigned char imm64[8]; // 8字节绝对地址 — ProxyFunction的虚拟地址
    } parts;
    unsigned char bytes[14]; // 完整14字节, 可直接memcpy到FakePage
} RedirectInstruction;

/**
 * @brief TrampolineStackZero — 18字节栈式跳转指令 (备用跳转方案)
 *
 * 机器码布局:
 *   6A 00                         ; PUSH 0          — 先压入占位符(低4字节=0)
 *   C7 44 24 04 XX XX XX XX       ; MOV [RSP+4], lo — 写入目标地址低32位
 *   C7 44 24 08 XX XX XX XX       ; MOV [RSP+8], hi — 写入目标地址高32位 (注意: 这里disp=08是错位覆盖)
 *   C3                            ; RET             — 从栈顶弹出地址并跳转
 *
 * 优点: 不占用任何寄存器 (FF25方案会用到[RIP]寻址)
 * 缺点: 18字节, 比RedirectInstruction多4字节
 *
 * @note 实际使用中优先选择14字节的RedirectInstruction, 此模板作为备选
 */
typedef union {
    struct {
        unsigned char push_opcode; // 0x6A — PUSH imm8 操作码
        unsigned char push_imm; // 0x00 — 压入0作为占位符
        unsigned char mov1_opcode; // 0xC7 — MOV r/m32, imm32 操作码
        unsigned char mov1_modrm; // 0x44 — ModRM: [RSP+disp8]
        unsigned char mov1_sib; // 0x24 — SIB: base=RSP
        unsigned char mov1_imm[4]; // 目标地址低32位 (little-endian)
        unsigned char mov2_opcode; // 0xC7 — MOV r/m32, imm32 操作码
        unsigned char mov2_modrm; // 0x44 — ModRM: [RSP+disp8]
        unsigned char mov2_sib; // 0x24 — SIB: base=RSP
        unsigned char mov2_disp; // 偏移量 (覆写高4字节位置)
        unsigned char mov2_imm[4]; // 目标地址高32位 (little-endian)
        unsigned char ret_opcode; // 0xC3 — RET指令, 弹出完整64位地址并跳转
    } parts;
    unsigned char bytes[18]; // 完整18字节, 可直接memcpy
} TrampolineStackZero;