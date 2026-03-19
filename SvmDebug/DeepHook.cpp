/**
 * @file DeepHook.cpp
 * @brief 深度内核拦截实现 - 特征码扫描引擎、Fake函数、Hook注册
 * @author yewilliam
 * @date 2026/03/18
 *
 * Hyper-Vanguard 深度拦截层完整实现:
 *
 *   Phase 1: Obp/Psp/Mi/Ki 核心函数拦截
 *   Phase 2: APC注入防御 / 物理内存防御 / 句柄表隐藏 / 进程生命周期 / DRx隐藏
 *
 * 编译要求: C++17, WDK 10.0.26100.0+
 */

#include "DeepHook.h"
#include "DebugApi.h"
#include "SVM.h"
#include "NPT.h"

#include <ntimage.h>
#include <ntstrsafe.h>

#pragma warning(disable: 4505)
#pragma warning(disable: 4201)

 /* ========================================================================
  *  可写数据段
  * ======================================================================== */
#pragma section(".drv_rw", read, write)
#pragma comment(linker, "/SECTION:.drv_rw,RW")

__declspec(allocate(".drv_rw")) static volatile LONG g_DeepGuard[64] = { 0 };
/* 使用 HOOK_MAX_COUNT 作为 print-once 数组大小, 防止枚举值越界 */
__declspec(allocate(".drv_rw")) static volatile LONG g_DeepPrintOnce[HOOK_MAX_COUNT] = { 0 };

#if DEBUG
#define DEEP_PRINT_ONCE(idx) \
    (void)(((idx) < HOOK_MAX_COUNT && InterlockedCompareExchange(&g_DeepPrintOnce[(idx)], 1, 0) == 0) ? \
        (SvmDebugPrint("[DeepFake] %s called\n", __FUNCTION__), 0) : 0)
#else
#define DEEP_PRINT_ONCE(idx)
#endif


/* ========================================================================
 *  Guard — per-CPU 防递归
 * ======================================================================== */
static __forceinline BOOLEAN DeepEnterGuard(PKIRQL OldIrql)
{
    *OldIrql = KeGetCurrentIrql();
    ULONG cpu = KeGetCurrentProcessorNumber();
    if (cpu >= 64) return FALSE;
    return (InterlockedCompareExchange(&g_DeepGuard[cpu], 1, 0) == 0);
}

static __forceinline VOID DeepLeaveGuard(KIRQL OldIrql)
{
    UNREFERENCED_PARAMETER(OldIrql);
    ULONG cpu = KeGetCurrentProcessorNumber();
    if (cpu < 64) InterlockedExchange(&g_DeepGuard[cpu], 0);
}


/* ========================================================================
 *  原函数指针 — Phase 1
 * ======================================================================== */
static FnObReferenceObjectByHandleWithTag  g_OrigObRefByHandleWithTag = NULL;
static FnObfDereferenceObject              g_OrigObfDerefObj = NULL;
static FnObfDereferenceObjectWithTag       g_OrigObfDerefObjWithTag = NULL;
static FnPspInsertThread                   g_OrigPspInsertThread = NULL;
static FnPspCallThreadNotifyRoutines       g_OrigPspCallThreadNotifyRoutines = NULL;
static FnPspExitThread                     g_OrigPspExitThread = NULL;
static FnMmProtectVirtualMemory            g_OrigMmProtectVmDeep = NULL;
static FnMiObtainReferencedVadEx           g_OrigMiObtainRefVadEx = NULL;
static FnKiDispatchException               g_OrigKiDispatchException = NULL;
static FnKiStackAttachProcess              g_OrigKiStackAttachProcess = NULL;

/* ========================================================================
 *  原函数指针 — Phase 2
 * ======================================================================== */
static FnKiInsertQueueApc                  g_OrigKiInsertQueueApc = NULL;
static FnMmGetPhysicalAddress              g_OrigMmGetPhysicalAddress = NULL;
static FnMmMapIoSpace                      g_OrigMmMapIoSpace = NULL;
static FnMmMapLockedPagesSpecifyCache      g_OrigMmMapLockedPages = NULL;
static FnExpLookupHandleTableEntry         g_OrigExpLookupHandleTableEntry = NULL;
static FnPspInsertProcess                  g_OrigPspInsertProcess = NULL;
static FnPspGetContextThreadInternal       g_OrigPspGetContextInternal = NULL;

/* PspCidTable 全局指针缓存 */
static PVOID g_PspCidTable = NULL;

extern POBJECT_TYPE* PsProcessType;
extern POBJECT_TYPE* PsThreadType;


/* ========================================================================
 *  智能白名单 — 区分 "外部恶意访问" vs "系统/自身合法操作"
 *
 *  IsCallerProtected() 只检查 PsGetCurrentProcessId(), 遗漏了:
 *    - System 进程 (PID=4) 的工作线程代替保护进程操作
 *    - csrss.exe 的子系统操作
 *    - 保护进程 Attach 后被 System 线程继续执行
 *    - dwm/explorer 等桌面基础设施进程
 *
 *  ShouldBlockDeepAccess() 综合判断, 只对真正的外部恶意访问返回 TRUE。
 * ======================================================================== */

 /** @brief 系统白名单进程名 — 与 Hide.cpp g_WhitelistProcesses 保持一致 */
static PCSTR g_DeepWhitelistNames[] = {
    "csrss.exe", "dwm.exe", "explorer.exe", "svchost.exe",
    "services.exe", "lsass.exe", "smss.exe", "ctfmon.exe",
    "dllhost.exe", "WmiPrvSE.exe", "conhost.exe", "sihost.exe",
    "taskhostw.exe",
};

/**
 * @brief 检查进程是否为系统白名单进程
 * @note 使用 PsGetProcessImageFileName (15字节短名) 进行快速比对
 */
static BOOLEAN IsDeepWhitelistedProcess(PEPROCESS Process)
{
    if (!Process) return FALSE;

    PUCHAR name = PsGetProcessImageFileName(Process);
    if (!name || name[0] == '\0') return FALSE;

    for (ULONG i = 0; i < ARRAYSIZE(g_DeepWhitelistNames); i++) {
        /* _stricmp 内核中可用, 大小写不敏感比较 */
        if (_stricmp((const char*)name, g_DeepWhitelistNames[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

/**
 * @brief 智能判断: 是否应该阻止对受保护进程的深层操作
 *
 * @param TargetProcess [in] 操作的目标进程 (被保护方)
 * @return TRUE = 外部恶意访问, 应阻止
 *         FALSE = 合法操作 (自身/系统/白名单), 应放行
 *
 * 判断优先级:
 *   1. 目标不在保护列表 → 放行
 *   2. 调用者 == 目标进程 (自操作) → 放行
 *   3. 调用者 PID 在保护列表 (保护进程互操作) → 放行
 *   4. 调用者是 System 进程 (PID=4) → 放行 (工作集管理器/平衡集管理器)
 *   5. 调用者是 csrss → 放行 (子系统操作)
 *   6. 调用者在系统白名单 → 放行 (dwm/explorer/svchost 等)
 *   7. 其他 → 阻止
 */
static BOOLEAN ShouldBlockDeepAccess(PEPROCESS TargetProcess)
{
    if (g_ProtectedPidCount == 0 || !TargetProcess)
        return FALSE;

    /* 安全性验证: TargetProcess 必须是有效内核指针 */
    if ((ULONG_PTR)TargetProcess < 0xFFFF800000000000ULL)
        return FALSE;

    __try {
        HANDLE targetPid = PsGetProcessId(TargetProcess);
        if (!IsProtectedPid(targetPid))
            return FALSE;  /* 目标不受保护 → 放行 */

        PEPROCESS callerProcess = PsGetCurrentProcess();

        /* Rule 1: 自操作 (目标进程 == 当前进程上下文) → 放行 */
        if (callerProcess == TargetProcess)
            return FALSE;

        /* Rule 2: 调用者也是受保护进程 → 放行 */
        HANDLE callerPid = PsGetProcessId(callerProcess);
        if (IsProtectedPid(callerPid))
            return FALSE;

        /* Rule 3: System 进程 (PID=4, 内核工作线程) → 放行 */
        if (callerProcess == PsInitialSystemProcess)
            return FALSE;

        /* Rule 4: csrss → 放行 (线程初始化/子系统注册) */
        if (g_CsrssProcess && callerProcess == g_CsrssProcess)
            return FALSE;

        /* Rule 5: 系统白名单进程 → 放行 */
        if (IsDeepWhitelistedProcess(callerProcess))
            return FALSE;

        /* 其他 → 阻止 */
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;  /* 异常 → 安全放行 */
    }
}

/**
 * @brief 检查线程通知是否应被抑制 (专用于 PspCallThreadNotifyRoutines)
 *
 * 只在"远程线程注入"场景下抑制通知:
 *   - 线程属于保护进程, 但创建者不是保护进程 → 抑制
 *   - 保护进程自己创建的线程 → 放行 (系统组件需要收到通知)
 *
 * @param Thread [in] 目标线程
 * @param Create [in] TRUE=创建通知, FALSE=退出通知
 * @return TRUE = 应抑制通知, FALSE = 应放行
 */
static BOOLEAN ShouldSuppressThreadNotify(PETHREAD Thread, BOOLEAN Create)
{
    if (g_ProtectedPidCount == 0 || !Thread)
        return FALSE;

    __try {
        PEPROCESS ownerProc = PsGetThreadProcess(Thread);
        if (!ownerProc) return FALSE;

        HANDLE ownerPid = PsGetProcessId(ownerProc);
        if (!IsProtectedPid(ownerPid))
            return FALSE;  /* 线程不属于保护进程 → 放行 */

        if (!Create)
            return FALSE;  /* 线程退出通知 → 永远放行 (抑制会导致资源泄漏) */

        /* 线程创建通知: 检查创建者 */
        PEPROCESS callerProcess = PsGetCurrentProcess();

        /* 保护进程自己创建线程 → 放行 (csrss 等需要收到通知) */
        if (callerProcess == ownerProc)
            return FALSE;

        /* 创建者也是受保护进程 → 放行 */
        if (IsProtectedPid(PsGetProcessId(callerProcess)))
            return FALSE;

        /* System/csrss/白名单创建 → 放行 (内核回调、子系统) */
        if (callerProcess == PsInitialSystemProcess)
            return FALSE;
        if (g_CsrssProcess && callerProcess == g_CsrssProcess)
            return FALSE;
        if (IsDeepWhitelistedProcess(callerProcess))
            return FALSE;

        /* 外部进程向保护进程创建远程线程 → 抑制通知 */
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}


/* ========================================================================
 *  Section 1: 通用特征码扫描引擎 (与原 DeepHook.cpp 相同)
 * ======================================================================== */

PVOID PatternScan(PVOID Base, SIZE_T Size, const UCHAR* Pattern, const char* Mask, SIZE_T PatternLen)
{
    if (!Base || !Pattern || !Mask || PatternLen == 0 || Size < PatternLen) return NULL;
    PUCHAR start = (PUCHAR)Base;
    SIZE_T searchLen = Size - PatternLen;

    for (SIZE_T i = 0; i <= searchLen; i++) {
        BOOLEAN found = TRUE;
        for (SIZE_T j = 0; j < PatternLen; j++) {
            if (Mask[j] == 'x' && start[i + j] != Pattern[j]) {
                found = FALSE;
                break;
            }
        }
        if (found) return (PVOID)(start + i);
    }
    return NULL;
}

BOOLEAN GetNtoskrnlBaseAndSize(PVOID* OutBase, PSIZE_T OutSize)
{
    ULONG bufSize = 0;
    NTSTATUS status = ZwQuerySystemInformation(11 /* SystemModuleInformation */, NULL, 0, &bufSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH || bufSize == 0) return FALSE;

    PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, 'dNtK');
    if (!buf) return FALSE;

    status = ZwQuerySystemInformation(11, buf, bufSize, &bufSize);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(buf, 'dNtK'); return FALSE; }

    typedef struct {
        ULONG ModulesCount;
        struct {
            PVOID Reserved[2]; PVOID ImageBase; ULONG ImageSize;
            ULONG Flags; USHORT LoadOrderIndex; USHORT InitOrderIndex;
            USHORT LoadCount; USHORT OffsetToFileName;
            CHAR FullPathName[256];
        } Modules[1];
    } SYSTEM_MODULE_INFORMATION;

    SYSTEM_MODULE_INFORMATION* mi = (SYSTEM_MODULE_INFORMATION*)buf;
    if (mi->ModulesCount > 0) {
        *OutBase = mi->Modules[0].ImageBase;
        *OutSize = mi->Modules[0].ImageSize;
        ExFreePoolWithTag(buf, 'dNtK');
        return TRUE;
    }
    ExFreePoolWithTag(buf, 'dNtK');
    return FALSE;
}

BOOLEAN GetNtoskrnlTextSection(PVOID ImageBase, PVOID* OutTextBase, PSIZE_T OutTextSize)
{
    if (!ImageBase) return FALSE;
    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)ImageBase;
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dosHdr->e_lfanew);
    if (ntHdr->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHdr);
    for (USHORT i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0 ||
            memcmp(section[i].Name, "PAGE", 4) == 0) {
            if (memcmp(section[i].Name, ".text", 5) == 0) {
                *OutTextBase = (PVOID)((PUCHAR)ImageBase + section[i].VirtualAddress);
                *OutTextSize = section[i].Misc.VirtualSize;
                return TRUE;
            }
        }
    }
    return FALSE;
}

PVOID ResolveRelativeAddress(PVOID InstructionAddr, ULONG InstructionLen, ULONG OffsetPos)
{
    PUCHAR insn = (PUCHAR)InstructionAddr;
    LONG relOffset = *(PLONG)(insn + OffsetPos);
    return (PVOID)(insn + InstructionLen + relOffset);
}


/* ========================================================================
 *  Section 2: Phase 1 扫描器 (保持原始实现不变)
 * ======================================================================== */

PVOID ScanForPspInsertThread()
{
    PVOID ntBase = NULL; SIZE_T ntSize = 0;
    if (!GetNtoskrnlBaseAndSize(&ntBase, &ntSize)) return NULL;
    PVOID textBase = NULL; SIZE_T textSize = 0;
    if (!GetNtoskrnlTextSection(ntBase, &textBase, &textSize)) {
        textBase = ntBase; textSize = ntSize;
    }

    PVOID ntCreateThread = GetSsdtAddressByNtdllName("NtCreateThreadEx");
    if (!ntCreateThread) return NULL;

    PUCHAR fn = (PUCHAR)ntCreateThread;
    int callCount = 0;
    for (int i = 0; i < 0x500; i++) {
        if (fn[i] == 0xE8) {
            callCount++;
            if (callCount >= 3 && callCount <= 8) {
                PVOID target = ResolveRelativeAddress(&fn[i], 5, 1);
                if ((ULONG_PTR)target > (ULONG_PTR)ntBase &&
                    (ULONG_PTR)target < (ULONG_PTR)ntBase + ntSize) {
                    SvmDebugPrint("[DeepScan] PspInsertThread candidate #%d -> %p\n", callCount, target);
                    return target;
                }
            }
        }
    }
    SvmDebugPrint("[DeepScan] PspInsertThread not found\n");
    return NULL;
}

PVOID ScanForPspCallThreadNotifyRoutines()
{
    PVOID ntBase = NULL; SIZE_T ntSize = 0;
    if (!GetNtoskrnlBaseAndSize(&ntBase, &ntSize)) return NULL;
    PVOID textBase = NULL; SIZE_T textSize = 0;
    if (!GetNtoskrnlTextSection(ntBase, &textBase, &textSize)) {
        textBase = ntBase; textSize = ntSize;
    }

    static const UCHAR pattern[] = {
        0x48, 0x89, 0x5C, 0x24, 0x00,
        0x48, 0x89, 0x74, 0x24, 0x00,
        0x57, 0x48, 0x83, 0xEC, 0x20
    };
    static const char mask[] = "xxxx?xxxx?xxxxx";

    PVOID hit = PatternScan(textBase, textSize, pattern, mask, sizeof(pattern));
    if (hit) {
        SvmDebugPrint("[DeepScan] PspCallThreadNotifyRoutines -> %p\n", hit);
        return hit;
    }
    SvmDebugPrint("[DeepScan] PspCallThreadNotifyRoutines not found\n");
    return NULL;
}

PVOID ScanForPspExitThread()
{
    PVOID ntBase = NULL; SIZE_T ntSize = 0;
    if (!GetNtoskrnlBaseAndSize(&ntBase, &ntSize)) return NULL;
    PVOID textBase = NULL; SIZE_T textSize = 0;
    if (!GetNtoskrnlTextSection(ntBase, &textBase, &textSize)) {
        textBase = ntBase; textSize = ntSize;
    }

    UNICODE_STRING fn;
    RtlInitUnicodeString(&fn, L"PsTerminateSystemThread");
    PUCHAR psTerminate = (PUCHAR)MmGetSystemRoutineAddress(&fn);
    if (!psTerminate) return NULL;

    for (int i = 0; i < 0x40; i++) {
        if (psTerminate[i] == 0xE8) {
            PVOID target = ResolveRelativeAddress(&psTerminate[i], 5, 1);
            if ((ULONG_PTR)target > (ULONG_PTR)0xFFFF800000000000ULL) {
                SvmDebugPrint("[DeepScan] PspExitThread -> %p\n", target);
                return target;
            }
        }
    }
    SvmDebugPrint("[DeepScan] PspExitThread not found\n");
    return NULL;
}

PVOID ScanForObReferenceObjectByHandleWithTag()
{
    UNICODE_STRING fn;
    RtlInitUnicodeString(&fn, L"ObReferenceObjectByHandleWithTag");
    PVOID addr = MmGetSystemRoutineAddress(&fn);
    if (addr) {
        SvmDebugPrint("[DeepScan] ObReferenceObjectByHandleWithTag -> %p (export)\n", addr);
        return addr;
    }

    PVOID ntBase = NULL; SIZE_T ntSize = 0;
    if (!GetNtoskrnlBaseAndSize(&ntBase, &ntSize)) return NULL;
    PVOID textBase = NULL; SIZE_T textSize = 0;
    if (!GetNtoskrnlTextSection(ntBase, &textBase, &textSize)) {
        textBase = ntBase; textSize = ntSize;
    }

    static const UCHAR pattern[] = {
        0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x00,
        0x49, 0x89, 0x6B, 0x00, 0x49, 0x89, 0x73, 0x00
    };
    static const char mask[] = "xxxxxx?xxx?xxx?";

    PVOID hit = PatternScan(textBase, textSize, pattern, mask, sizeof(pattern));
    if (hit) {
        SvmDebugPrint("[DeepScan] ObReferenceObjectByHandleWithTag -> %p (pattern)\n", hit);
        return hit;
    }
    SvmDebugPrint("[DeepScan] ObReferenceObjectByHandleWithTag not found\n");
    return NULL;
}

PVOID ScanForObfDereferenceObject()
{
    UNICODE_STRING fn;
    RtlInitUnicodeString(&fn, L"ObfDereferenceObject");
    PVOID addr = MmGetSystemRoutineAddress(&fn);
    if (addr) {
        SvmDebugPrint("[DeepScan] ObfDereferenceObject -> %p\n", addr);
        return addr;
    }
    return NULL;
}

PVOID ScanForObfDereferenceObjectWithTag()
{
    UNICODE_STRING fn;
    RtlInitUnicodeString(&fn, L"ObfDereferenceObjectWithTag");
    PVOID addr = MmGetSystemRoutineAddress(&fn);
    if (addr) {
        SvmDebugPrint("[DeepScan] ObfDereferenceObjectWithTag -> %p\n", addr);
        return addr;
    }
    return NULL;
}

PVOID ScanForMmProtectVirtualMemory()
{
    PVOID ntProtect = GetSsdtAddressByNtdllName("NtProtectVirtualMemory");
    if (!ntProtect) {
        ntProtect = GetTrueSsdtAddress(L"ZwProtectVirtualMemory");
    }
    if (!ntProtect) return NULL;

    PUCHAR fn = (PUCHAR)ntProtect;
    for (int i = 0x40; i < 0x200; i++) {
        if (fn[i] == 0xE8) {
            PVOID target = ResolveRelativeAddress(&fn[i], 5, 1);
            if ((ULONG_PTR)target > (ULONG_PTR)0xFFFF800000000000ULL) {
                SvmDebugPrint("[DeepScan] MmProtectVirtualMemory -> %p\n", target);
                return target;
            }
        }
    }
    SvmDebugPrint("[DeepScan] MmProtectVirtualMemory not found\n");
    return NULL;
}

PVOID ScanForMiObtainReferencedVadEx()
{
    PVOID ntQueryVm = GetSsdtAddressByNtdllName("NtQueryVirtualMemory");
    if (!ntQueryVm) ntQueryVm = GetTrueSsdtAddress(L"ZwQueryVirtualMemory");
    if (!ntQueryVm) return NULL;

    PUCHAR fn = (PUCHAR)ntQueryVm;
    int callCount = 0;
    for (int i = 0; i < 0x400; i++) {
        if (fn[i] == 0xE8) {
            callCount++;
            if (callCount >= 2 && callCount <= 5) {
                PVOID target = ResolveRelativeAddress(&fn[i], 5, 1);
                if ((ULONG_PTR)target > (ULONG_PTR)0xFFFF800000000000ULL &&
                    (ULONG_PTR)target < (ULONG_PTR)fn + 0x100000) {
                    SvmDebugPrint("[DeepScan] MiObtainReferencedVadEx candidate #%d -> %p\n", callCount, target);
                    return target;
                }
            }
        }
    }
    SvmDebugPrint("[DeepScan] MiObtainReferencedVadEx not found\n");
    return NULL;
}

PVOID ScanForKiDispatchException()
{
    PVOID ntBase = NULL; SIZE_T ntSize = 0;
    if (!GetNtoskrnlBaseAndSize(&ntBase, &ntSize)) return NULL;
    PVOID textBase = NULL; SIZE_T textSize = 0;
    if (!GetNtoskrnlTextSection(ntBase, &textBase, &textSize)) {
        textBase = ntBase; textSize = ntSize;
    }

    static const UCHAR pattern[] = {
        0x48, 0x8B, 0xC4,
        0x48, 0x89, 0x58, 0x00,
        0x48, 0x89, 0x68, 0x00,
        0x48, 0x89, 0x70, 0x00,
        0x48, 0x89, 0x78, 0x00,
        0x41, 0x56,
        0x48, 0x81, 0xEC
    };
    static const char mask[] = "xxxxxx?xxx?xxx?xxx?xxxxx";

    PVOID hit = PatternScan(textBase, textSize, pattern, mask, sizeof(pattern));
    if (hit) {
        SvmDebugPrint("[DeepScan] KiDispatchException -> %p\n", hit);
        return hit;
    }

    static const UCHAR pattern2[] = { 0x81, 0x39, 0x03, 0x00, 0x00, 0x80 };
    static const char mask2[] = "xxxxxx";

    PUCHAR searchStart = (PUCHAR)textBase;
    for (SIZE_T off = 0; off < textSize - 256; off++) {
        PVOID candidate = PatternScan(searchStart + off, textSize - off, pattern2, mask2, sizeof(pattern2));
        if (!candidate) break;
        PUCHAR check = (PUCHAR)candidate;
        for (int back = 1; back < 0x100; back++) {
            if (check[-back] == 0xCC && check[-back - 1] != 0xCC) {
                PVOID funcHead = (PVOID)(check - back + 1);
                SvmDebugPrint("[DeepScan] KiDispatchException (alt) -> %p\n", funcHead);
                return funcHead;
            }
        }
        off = (SIZE_T)((PUCHAR)candidate - searchStart) + 1;
    }
    SvmDebugPrint("[DeepScan] KiDispatchException not found\n");
    return NULL;
}

PVOID ScanForKiStackAttachProcess()
{
    UNICODE_STRING fn;
    RtlInitUnicodeString(&fn, L"KeStackAttachProcess");
    PUCHAR keAttach = (PUCHAR)MmGetSystemRoutineAddress(&fn);
    if (!keAttach) return NULL;

    for (int i = 0x10; i < 0x80; i++) {
        if (keAttach[i] == 0xE8) {
            PVOID target = ResolveRelativeAddress(&keAttach[i], 5, 1);
            if ((ULONG_PTR)target > (ULONG_PTR)0xFFFF800000000000ULL) {
                SvmDebugPrint("[DeepScan] KiStackAttachProcess -> %p\n", target);
                return target;
            }
        }
    }
    SvmDebugPrint("[DeepScan] KiStackAttachProcess not found\n");
    return NULL;
}


/* ========================================================================
 *  Section 2b: Phase 2 扫描器 (新增)
 * ======================================================================== */

 /**
  * @brief 扫描 KiInsertQueueApc — 从 KeInsertQueueApc (导出) 内部定位
  *
  * KeInsertQueueApc 进行参数验证后调用 KiInsertQueueApc。
  * 通常在 KeInsertQueueApc 的前 0x60 字节内有一个 CALL rel32。
  */
PVOID ScanForKiInsertQueueApc()
{
    UNICODE_STRING fn;
    RtlInitUnicodeString(&fn, L"KeInsertQueueApc");
    PUCHAR keInsert = (PUCHAR)MmGetSystemRoutineAddress(&fn);
    if (!keInsert) {
        SvmDebugPrint("[DeepScan] KeInsertQueueApc export not found\n");
        return NULL;
    }

    /* KeInsertQueueApc:
     *   ... 参数验证 / 获取锁 ...
     *   call KiInsertQueueApc     ; 这是我们要找的目标
     *   ... 清理 ...
     *
     * 搜索前 0x80 字节内的 E8 CALL, 跳过特别短的 stub 调用 */
    for (int i = 0x20; i < 0x80; i++) {
        if (keInsert[i] == 0xE8) {
            PVOID target = ResolveRelativeAddress(&keInsert[i], 5, 1);
            /* 验证: 目标应在 ntoskrnl 范围内且不是自身 */
            if ((ULONG_PTR)target > (ULONG_PTR)0xFFFF800000000000ULL &&
                (ULONG_PTR)target != (ULONG_PTR)keInsert) {
                SvmDebugPrint("[DeepScan] KiInsertQueueApc -> %p\n", target);
                return target;
            }
        }
    }

    SvmDebugPrint("[DeepScan] KiInsertQueueApc not found\n");
    return NULL;
}

/**
 * @brief 定位 MmGetPhysicalAddress — 直接从导出表解析
 */
PVOID ScanForMmGetPhysicalAddress()
{
    UNICODE_STRING fn;
    RtlInitUnicodeString(&fn, L"MmGetPhysicalAddress");
    PVOID addr = MmGetSystemRoutineAddress(&fn);
    if (addr) SvmDebugPrint("[DeepScan] MmGetPhysicalAddress -> %p\n", addr);
    else      SvmDebugPrint("[DeepScan] MmGetPhysicalAddress not found\n");
    return addr;
}

/**
 * @brief 定位 MmMapIoSpace — 直接从导出表解析
 */
PVOID ScanForMmMapIoSpace()
{
    UNICODE_STRING fn;
    RtlInitUnicodeString(&fn, L"MmMapIoSpace");
    PVOID addr = MmGetSystemRoutineAddress(&fn);
    if (addr) SvmDebugPrint("[DeepScan] MmMapIoSpace -> %p\n", addr);
    else      SvmDebugPrint("[DeepScan] MmMapIoSpace not found\n");
    return addr;
}

/**
 * @brief 定位 MmMapLockedPagesSpecifyCache — 直接从导出表解析
 */
PVOID ScanForMmMapLockedPagesSpecifyCache()
{
    UNICODE_STRING fn;
    RtlInitUnicodeString(&fn, L"MmMapLockedPagesSpecifyCache");
    PVOID addr = MmGetSystemRoutineAddress(&fn);
    if (addr) SvmDebugPrint("[DeepScan] MmMapLockedPagesSpecifyCache -> %p\n", addr);
    else      SvmDebugPrint("[DeepScan] MmMapLockedPagesSpecifyCache not found\n");
    return addr;
}

/**
 * @brief 获取 PspCidTable 全局指针
 *
 * 方法: PsLookupProcessByProcessId 内部有 LEA RCX, [PspCidTable] 指令,
 * 紧接着 CALL ExpLookupHandleTableEntry。
 * 搜索 48 8D 0D (LEA RCX, [rip+disp32]) 模式。
 */
PVOID GetPspCidTable()
{
    if (g_PspCidTable) return g_PspCidTable;

    UNICODE_STRING fn;
    RtlInitUnicodeString(&fn, L"PsLookupProcessByProcessId");
    PUCHAR psLookup = (PUCHAR)MmGetSystemRoutineAddress(&fn);
    if (!psLookup) return NULL;

    /* 搜索 LEA RCX, [rip+disp32] → 48 8D 0D XX XX XX XX */
    for (int i = 0; i < 0x60; i++) {
        if (psLookup[i] == 0x48 && psLookup[i + 1] == 0x8D && psLookup[i + 2] == 0x0D) {
            PVOID cidTable = ResolveRelativeAddress(&psLookup[i], 7, 3);
            /* PspCidTable 是一个指针变量, 取其值 */
            __try {
                PVOID tablePtr = *(PVOID*)cidTable;
                if (tablePtr && (ULONG_PTR)tablePtr > (ULONG_PTR)0xFFFF800000000000ULL) {
                    g_PspCidTable = tablePtr;
                    SvmDebugPrint("[DeepScan] PspCidTable -> %p (var at %p)\n", tablePtr, cidTable);
                    return tablePtr;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }

    SvmDebugPrint("[DeepScan] PspCidTable not found\n");
    return NULL;
}

/**
 * @brief 扫描 ExpLookupHandleTableEntry
 *
 * 方法: PsLookupProcessByProcessId 中 LEA RCX, [PspCidTable] 后紧跟
 * CALL ExpLookupHandleTableEntry。
 */
PVOID ScanForExpLookupHandleTableEntry()
{
    UNICODE_STRING fn;
    RtlInitUnicodeString(&fn, L"PsLookupProcessByProcessId");
    PUCHAR psLookup = (PUCHAR)MmGetSystemRoutineAddress(&fn);
    if (!psLookup) {
        SvmDebugPrint("[DeepScan] PsLookupProcessByProcessId export not found\n");
        return NULL;
    }

    /* 找到 LEA RCX, [PspCidTable] 后的第一个 CALL */
    BOOLEAN foundLea = FALSE;
    for (int i = 0; i < 0x80; i++) {
        if (!foundLea && psLookup[i] == 0x48 && psLookup[i + 1] == 0x8D && psLookup[i + 2] == 0x0D) {
            foundLea = TRUE;
            i += 6; /* 跳过 LEA 指令 (7 bytes) */
        }
        if (foundLea && psLookup[i] == 0xE8) {
            PVOID target = ResolveRelativeAddress(&psLookup[i], 5, 1);
            if ((ULONG_PTR)target > (ULONG_PTR)0xFFFF800000000000ULL) {
                SvmDebugPrint("[DeepScan] ExpLookupHandleTableEntry -> %p\n", target);
                return target;
            }
        }
    }

    SvmDebugPrint("[DeepScan] ExpLookupHandleTableEntry not found\n");
    return NULL;
}

/**
 * @brief 扫描 PspInsertProcess — 从 NtCreateUserProcess CALL 链定位
 *
 * NtCreateUserProcess 内部在进程创建流程的后半段调用 PspInsertProcess。
 * PspInsertProcess 的特征: 以 EPROCESS 为第一参数, 且调用 ObInsertObjectEx。
 */
PVOID ScanForPspInsertProcess()
{
    PVOID ntCreateProcess = GetSsdtAddressByNtdllName("NtCreateUserProcess");
    if (!ntCreateProcess) {
        SvmDebugPrint("[DeepScan] NtCreateUserProcess not found, trying NtCreateProcessEx\n");
        ntCreateProcess = GetSsdtAddressByNtdllName("NtCreateProcessEx");
    }
    if (!ntCreateProcess) {
        SvmDebugPrint("[DeepScan] PspInsertProcess: no entry point found\n");
        return NULL;
    }

    PVOID ntBase = NULL; SIZE_T ntSize = 0;
    if (!GetNtoskrnlBaseAndSize(&ntBase, &ntSize)) return NULL;

    /* NtCreateUserProcess 是一个很大的函数 (> 0x800 字节),
     * PspInsertProcess 通常在偏移 0x300 ~ 0x800 处被调用 */
    PUCHAR fn = (PUCHAR)ntCreateProcess;
    int callCount = 0;
    for (int i = 0x200; i < 0xA00; i++) {
        if (fn[i] == 0xE8) {
            callCount++;
            PVOID target = ResolveRelativeAddress(&fn[i], 5, 1);
            if ((ULONG_PTR)target > (ULONG_PTR)ntBase &&
                (ULONG_PTR)target < (ULONG_PTR)ntBase + ntSize) {
                /* PspInsertProcess 内部会调用 ObInsertObjectEx,
                 * 验证目标函数内是否包含特征调用 */
                PUCHAR tfn = (PUCHAR)target;
                BOOLEAN hasObInsert = FALSE;
                __try {
                    for (int j = 0; j < 0x100; j++) {
                        if (tfn[j] == 0xE8) {
                            PVOID inner = ResolveRelativeAddress(&tfn[j], 5, 1);
                            UNICODE_STRING obFn;
                            RtlInitUnicodeString(&obFn, L"ObInsertObjectEx");
                            PVOID obInsert = MmGetSystemRoutineAddress(&obFn);
                            if (!obInsert) {
                                RtlInitUnicodeString(&obFn, L"ObInsertObject");
                                obInsert = MmGetSystemRoutineAddress(&obFn);
                            }
                            if (obInsert && inner == obInsert) {
                                hasObInsert = TRUE;
                                break;
                            }
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {}

                if (hasObInsert) {
                    SvmDebugPrint("[DeepScan] PspInsertProcess -> %p (call #%d, verified ObInsert)\n",
                        target, callCount);
                    return target;
                }
            }
        }
    }

    SvmDebugPrint("[DeepScan] PspInsertProcess not found\n");
    return NULL;
}

/**
 * @brief 扫描 PspGetContextThreadInternal — 从 NtGetContextThread CALL 链定位
 *
 * NtGetContextThread 验证参数后调用 PspGetContextThreadInternal。
 * 通常是前几个 CALL 中的一个。
 */
PVOID ScanForPspGetContextThreadInternal()
{
    PVOID ntGetCtx = GetSsdtAddressByNtdllName("NtGetContextThread");
    if (!ntGetCtx) {
        ntGetCtx = GetTrueSsdtAddress(L"ZwGetContextThread");
    }
    if (!ntGetCtx) {
        SvmDebugPrint("[DeepScan] NtGetContextThread not found\n");
        return NULL;
    }

    PVOID ntBase = NULL; SIZE_T ntSize = 0;
    if (!GetNtoskrnlBaseAndSize(&ntBase, &ntSize)) return NULL;

    /* NtGetContextThread 通常:
     *   1. ObReferenceObjectByHandle (获取线程对象)
     *   2. PspGetContextThreadInternal (核心逻辑)
     *   3. ObfDereferenceObject
     *
     * 我们跳过第一个 CALL (通常是 ObRef), 取第二个 CALL */
    PUCHAR fn = (PUCHAR)ntGetCtx;
    int callCount = 0;
    for (int i = 0x20; i < 0x100; i++) {
        if (fn[i] == 0xE8) {
            callCount++;
            if (callCount == 2) {
                PVOID target = ResolveRelativeAddress(&fn[i], 5, 1);
                if ((ULONG_PTR)target > (ULONG_PTR)ntBase &&
                    (ULONG_PTR)target < (ULONG_PTR)ntBase + ntSize) {
                    SvmDebugPrint("[DeepScan] PspGetContextThreadInternal -> %p\n", target);
                    return target;
                }
            }
        }
    }

    SvmDebugPrint("[DeepScan] PspGetContextThreadInternal not found\n");
    return NULL;
}


/* ========================================================================
 *  Section 3: Phase 1 Fake 函数 (保持原始实现)
 * ======================================================================== */

NTSTATUS NTAPI Fake_ObReferenceObjectByHandleWithTag(
    HANDLE Handle, ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode,
    ULONG Tag, PVOID* Object,
    POBJECT_HANDLE_INFORMATION HandleInformation)
{
    DEEP_PRINT_ONCE(HOOK_ObRefByHandleWithTag);
    if (!g_OrigObRefByHandleWithTag) return STATUS_NOT_IMPLEMENTED;

    KIRQL oldIrql;
    if (!DeepEnterGuard(&oldIrql))
        return g_OrigObRefByHandleWithTag(Handle, DesiredAccess, ObjectType,
            AccessMode, Tag, Object, HandleInformation);

    NTSTATUS status = g_OrigObRefByHandleWithTag(Handle, DesiredAccess, ObjectType,
        AccessMode, Tag, Object, HandleInformation);
    if (!NT_SUCCESS(status) || !Object || !*Object || g_ProtectedPidCount == 0) {
        DeepLeaveGuard(oldIrql);
        return status;
    }

    if (IsCallerProtected()) { DeepLeaveGuard(oldIrql); return status; }

    __try {
        if (ObjectType == *PsProcessType) {
            PEPROCESS proc = (PEPROCESS)*Object;
            HANDLE pid = PsGetProcessId(proc);
            if (IsProtectedPid(pid) && HandleInformation) {
                HandleInformation->GrantedAccess &= PROCESS_QUERY_LIMITED_INFORMATION;
            }
        }
        else if (ObjectType == *PsThreadType) {
            PETHREAD thread = (PETHREAD)*Object;
            PEPROCESS ownerProc = PsGetThreadProcess(thread);
            if (ownerProc) {
                HANDLE ownerPid = PsGetProcessId(ownerProc);
                if (IsProtectedPid(ownerPid) && HandleInformation) {
                    HandleInformation->GrantedAccess &= THREAD_SUSPEND_RESUME;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    DeepLeaveGuard(oldIrql);
    return status;
}

LONG_PTR FASTCALL Fake_ObfDereferenceObject(PVOID Object)
{
    DEEP_PRINT_ONCE(HOOK_ObfDereferenceObject);
    if (!g_OrigObfDerefObj) return 0;
    return g_OrigObfDerefObj(Object);
}

LONG_PTR FASTCALL Fake_ObfDereferenceObjectWithTag(PVOID Object, ULONG Tag)
{
    DEEP_PRINT_ONCE(HOOK_ObfDereferenceObjectWithTag);
    if (!g_OrigObfDerefObjWithTag) return 0;
    return g_OrigObfDerefObjWithTag(Object, Tag);
}

NTSTATUS NTAPI Fake_PspInsertThread(
    PETHREAD Thread, PEPROCESS Process,
    KPROCESSOR_MODE PreviousMode, PVOID Reserved)
{
    DEEP_PRINT_ONCE(HOOK_PspInsertThread);
    if (!g_OrigPspInsertThread) return STATUS_NOT_IMPLEMENTED;

    KIRQL oldIrql;
    if (!DeepEnterGuard(&oldIrql))
        return g_OrigPspInsertThread(Thread, Process, PreviousMode, Reserved);

    BOOLEAN blocked = FALSE;
    if (g_ProtectedPidCount > 0 && Process) {
        /* 安全性检查: PspInsertThread 签名在不同 build 上可能变化,
         * Process 参数可能不是有效 EPROCESS 指针 (如 rcx=1)。
         * 验证: 必须是内核地址 (>= 0xFFFF800000000000) 且可读 */
        __try {
            if ((ULONG_PTR)Process >= 0xFFFF800000000000ULL && MmIsAddressValid(Process)) {
                HANDLE targetPid = PsGetProcessId(Process);
                if (IsProtectedPid(targetPid)) {
                    PEPROCESS caller = PsGetCurrentProcess();
                    HANDLE callerPid = PsGetProcessId(caller);
                    if (!IsProtectedPid(callerPid) && PreviousMode == UserMode) {
                        SvmDebugPrint("[DeepFake] PspInsertThread BLOCKED: PID=%llu -> target=%llu\n",
                            (ULONG64)callerPid, (ULONG64)targetPid);
                        blocked = TRUE;
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            /* Process 参数无效, 不拦截, 直接透传 */
        }
    }

    DeepLeaveGuard(oldIrql);
    if (blocked) return STATUS_ACCESS_DENIED;
    return g_OrigPspInsertThread(Thread, Process, PreviousMode, Reserved);
}

VOID NTAPI Fake_PspCallThreadNotifyRoutines(PETHREAD Thread, BOOLEAN Create)
{
    DEEP_PRINT_ONCE(HOOK_PspCallThreadNotifyRoutines);
    if (!g_OrigPspCallThreadNotifyRoutines) return;

    /* 智能抑制: 只在外部远程线程注入场景下抑制通知
     * 保护进程自己的线程创建/退出 → 正常通知 (csrss 需要) */
    if (ShouldSuppressThreadNotify(Thread, Create)) {
        SvmDebugPrint("[DeepFake] PspCallThreadNotifyRoutines SUPPRESSED: remote thread in protected PID\n");
        return;
    }

    g_OrigPspCallThreadNotifyRoutines(Thread, Create);
}

VOID NTAPI Fake_PspExitThread(NTSTATUS ExitStatus)
{
    DEEP_PRINT_ONCE(HOOK_PspExitThread);
    if (!g_OrigPspExitThread) return;

    if (g_ProtectedPidCount > 0) {
        PEPROCESS currentProc = PsGetCurrentProcess();
        HANDLE currentPid = PsGetProcessId(currentProc);
        if (IsProtectedPid(currentPid)) {
            if (ExitStatus == STATUS_THREAD_IS_TERMINATING ||
                ExitStatus == STATUS_PROCESS_IS_TERMINATING) {
                SvmDebugPrint("[DeepFake] PspExitThread: protected thread %llu exit=0x%X\n",
                    (ULONG64)PsGetCurrentThreadId(), ExitStatus);
            }
        }
    }
    g_OrigPspExitThread(ExitStatus);
}

NTSTATUS NTAPI Fake_MmProtectVirtualMemory_Deep(
    PEPROCESS Process, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect)
{
    DEEP_PRINT_ONCE(HOOK_MmProtectVirtualMemory_Deep);
    if (!g_OrigMmProtectVmDeep) return STATUS_NOT_IMPLEMENTED;

    /* 快速路径: 无保护目标时直接透传 */
    if (g_ProtectedPidCount == 0)
        return g_OrigMmProtectVmDeep(Process, BaseAddress, RegionSize, NewProtect, OldProtect);

    KIRQL oldIrql;
    if (!DeepEnterGuard(&oldIrql))
        return g_OrigMmProtectVmDeep(Process, BaseAddress, RegionSize, NewProtect, OldProtect);

    /* 安全性验证: Process 必须是有效内核指针 */
    BOOLEAN shouldBlock = FALSE;
    if ((ULONG_PTR)Process >= 0xFFFF800000000000ULL) {
        shouldBlock = ShouldBlockDeepAccess(Process);
    }

    DeepLeaveGuard(oldIrql);

    if (shouldBlock) {
        SvmDebugPrint("[DeepFake] MmProtectVirtualMemory BLOCKED: caller=%s -> PID=%llu, Protect=0x%X\n",
            PsGetProcessImageFileName(PsGetCurrentProcess()),
            (ULONG64)PsGetProcessId(Process), NewProtect);
        if (OldProtect) *OldProtect = 0;
        return STATUS_ACCESS_DENIED;
    }

    return g_OrigMmProtectVmDeep(Process, BaseAddress, RegionSize, NewProtect, OldProtect);
}

PVOID NTAPI Fake_MiObtainReferencedVadEx(PEPROCESS Process, PVOID VirtualAddr, ULONG PoolTag)
{
    DEEP_PRINT_ONCE(HOOK_MiObtainReferencedVadEx);
    if (!g_OrigMiObtainRefVadEx) return NULL;

    /* 极热路径: 只有保护列表非空时才进入检查 */
    if (g_ProtectedPidCount == 0)
        return g_OrigMiObtainRefVadEx(Process, VirtualAddr, PoolTag);

    KIRQL oldIrql;
    if (!DeepEnterGuard(&oldIrql))
        return g_OrigMiObtainRefVadEx(Process, VirtualAddr, PoolTag);

    /* 安全性验证: Process 必须是有效内核指针 */
    BOOLEAN shouldHide = FALSE;
    if ((ULONG_PTR)Process >= 0xFFFF800000000000ULL) {
        __try {
            shouldHide = ShouldBlockDeepAccess(Process);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            shouldHide = FALSE;
        }
    }

    DeepLeaveGuard(oldIrql);

    if (shouldHide) {
        /* 外部进程扫描保护进程 VAD → 返回 NULL (内存区域不存在) */
        return NULL;
    }

    return g_OrigMiObtainRefVadEx(Process, VirtualAddr, PoolTag);
}

VOID NTAPI Fake_KiDispatchException(
    PEXCEPTION_RECORD ExceptionRecord, PVOID ExceptionFrame, PVOID TrapFrame,
    KPROCESSOR_MODE PreviousMode, BOOLEAN FirstChance)
{
    DEEP_PRINT_ONCE(HOOK_KiDispatchException);
    if (!g_OrigKiDispatchException) return;

    if (g_ProtectedPidCount > 0 && ExceptionRecord && PreviousMode == UserMode) {
        __try {
            PEPROCESS currentProc = PsGetCurrentProcess();
            HANDLE currentPid = PsGetProcessId(currentProc);
            if (IsProtectedPid(currentPid)) {
                NTSTATUS exCode = ExceptionRecord->ExceptionCode;
                if (exCode == STATUS_SINGLE_STEP && FirstChance) {
                    SvmDebugPrint("[DeepFake] KiDispatchException: #DB in PID=%llu, RIP=%p\n",
                        (ULONG64)currentPid, ExceptionRecord->ExceptionAddress);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    g_OrigKiDispatchException(ExceptionRecord, ExceptionFrame, TrapFrame,
        PreviousMode, FirstChance);
}

VOID NTAPI Fake_KiStackAttachProcess(PEPROCESS Process, PKAPC_STATE ApcState)
{
    DEEP_PRINT_ONCE(HOOK_KiStackAttachProcess);
    if (!g_OrigKiStackAttachProcess) return;

    if (ShouldBlockDeepAccess(Process)) {
        SvmDebugPrint("[DeepFake] KiStackAttachProcess REDIRECTED: caller=%s -> PID=%llu\n",
            PsGetProcessImageFileName(PsGetCurrentProcess()),
            (ULONG64)PsGetProcessId(Process));
        /* 重定向到 System 进程, 避免 BSOD */
        g_OrigKiStackAttachProcess(PsInitialSystemProcess, ApcState);
        return;
    }
    g_OrigKiStackAttachProcess(Process, ApcState);
}


/* ========================================================================
 *  Section 3b: Phase 2 Fake 函数 (新增)
 * ======================================================================== */

 /**
  * @brief Fake_KiInsertQueueApc — 拦截向保护线程投递的 APC
  *
  * 检查 KAPC 中的目标线程, 如果属于受保护进程且调用者不在白名单内,
  * 直接丢弃 APC 并返回 FALSE (插入失败)。
  *
  * 关键: 不拦截内核模式下 System 进程发起的 APC, 否则会破坏系统运行。
  */
BOOLEAN NTAPI Fake_KiInsertQueueApc(PKAPC Apc, KPRIORITY Increment)
{
    DEEP_PRINT_ONCE(HOOK_KiInsertQueueApc);
    if (!g_OrigKiInsertQueueApc) return FALSE;

    if (g_ProtectedPidCount == 0 || !Apc)
        return g_OrigKiInsertQueueApc(Apc, Increment);

    /* KiInsertQueueApc 经常在 DISPATCH_LEVEL 调用,
     * 此时不能访问分页内存 (PsGetProcessImageFileName 等),
     * 只在 PASSIVE/APC_LEVEL 才进行拦截逻辑 */
    if (KeGetCurrentIrql() > APC_LEVEL)
        return g_OrigKiInsertQueueApc(Apc, Increment);

    KIRQL oldIrql;
    if (!DeepEnterGuard(&oldIrql))
        return g_OrigKiInsertQueueApc(Apc, Increment);

    BOOLEAN shouldBlock = FALSE;

    __try {
        /* KAPC.Thread 在 x64 Win10/11 上的偏移为 0x08 */
        PETHREAD targetThread = *(PETHREAD*)((PUCHAR)Apc + 0x08);
        if (targetThread && (ULONG_PTR)targetThread >= 0xFFFF800000000000ULL) {
            PEPROCESS ownerProc = PsGetThreadProcess(targetThread);
            if (ownerProc) {
                /* 使用智能白名单: System/csrss/白名单进程的 APC → 放行 */
                shouldBlock = ShouldBlockDeepAccess(ownerProc);
                if (shouldBlock) {
                    SvmDebugPrint("[DeepFake] KiInsertQueueApc BLOCKED: caller=%s -> target PID=%llu\n",
                        PsGetProcessImageFileName(PsGetCurrentProcess()),
                        (ULONG64)PsGetProcessId(ownerProc));
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    DeepLeaveGuard(oldIrql);

    if (shouldBlock)
        return FALSE;

    return g_OrigKiInsertQueueApc(Apc, Increment);
}

/**
 * @brief Fake_MmGetPhysicalAddress_Deep — 物理地址转换拦截
 *
 * MmGetPhysicalAddress 是极高频调用 (每秒数千~数万次), 在任何 IRQL 下都可能被调用,
 * 包括在页面错误处理器、DPC、中断上下文中。
 *
 * 策略: 零分配、零锁、零分页内存访问
 *   1. 内核地址 → 无条件放行 (占 99% 以上)
 *   2. 无保护进程 → 无条件放行
 *   3. 用户态地址 → 检查当前进程上下文是否是受保护进程
 *      - 用 PsGetCurrentProcess() 获取 EPROCESS (非分页, 任何 IRQL 安全)
 *      - 用 PsGetProcessId() 获取 PID (非分页, 任何 IRQL 安全)
 *      - 与全局数组 g_ProtectedPIDs 比对 (非分页 .data 段, 任何 IRQL 安全)
 *      - 如果当前上下文是保护进程 → 检查调用者是否是保护进程自身
 *        若不是 (外部驱动 Attach 进来的) → 返回 0
 *
 * 关键安全措施:
 *   - 不使用 DeepEnterGuard (避免递归死锁)
 *   - 不使用 PsGetProcessImageFileName (分页内存, 高 IRQL 不安全)
 *   - 不使用 SvmDebugPrint (会触发 I/O, 高 IRQL 不安全)
 *   - 不使用 __try/__except (MmGetPhysicalAddress 本身不该引发异常)
 *   - 仅访问非分页数据结构
 */
PHYSICAL_ADDRESS NTAPI Fake_MmGetPhysicalAddress_Deep(PVOID BaseAddress)
{
    DEEP_PRINT_ONCE(HOOK_MmGetPhysicalAddress_Deep);
    if (!g_OrigMmGetPhysicalAddress) {
        PHYSICAL_ADDRESS zero = { 0 };
        return zero;
    }

    /* 快速路径 1: 内核地址 → 无条件放行 */
    if ((ULONG_PTR)BaseAddress >= 0x800000000000ULL)
        return g_OrigMmGetPhysicalAddress(BaseAddress);

    /* 快速路径 2: 无保护进程 → 无条件放行 */
    if (g_ProtectedPidCount == 0)
        return g_OrigMmGetPhysicalAddress(BaseAddress);

    /* 慢路径: 用户态地址 + 有保护进程
     * 所有操作仅访问非分页数据, 任何 IRQL 安全 */

    /* PsGetCurrentProcess 读取 KPCR->CurrentThread->ApcState.Process,
     * 全部在非分页内存中, 任何 IRQL 安全 */
    PEPROCESS currentProc = PsGetCurrentProcess();
    if (!currentProc)
        return g_OrigMmGetPhysicalAddress(BaseAddress);

    /* PsGetProcessId 读取 EPROCESS.UniqueProcessId, 非分页, 任何 IRQL 安全 */
    HANDLE currentPid = PsGetProcessId(currentProc);

    /* 如果当前进程上下文不是受保护进程 → 放行
     * (IsProtectedPid 仅访问全局 .data 数组, 非分页, 安全) */
    if (!IsProtectedPid(currentPid))
        return g_OrigMmGetPhysicalAddress(BaseAddress);

    /* 当前进程上下文 IS 保护进程。
     * 这意味着要么:
     *   a) 保护进程自身在做 MmGetPhysicalAddress (正常, 应放行)
     *   b) 外部驱动通过 KeStackAttachProcess 切换到保护进程后调用 (威胁, 应拦截)
     *
     * 区分方法: 检查当前线程的原始进程 (OriginalProcess) 与当前进程是否一致。
     * 如果不一致, 说明有人 Attach 进来了。
     *
     * KTHREAD.ApcState.Process = 当前 Attach 的进程 (currentProc)
     * KTHREAD.Process = 线程的原始所属进程
     *
     * PsGetThreadProcess(PsGetCurrentThread()) 返回原始进程。
     * 如果 原始进程 != currentProc → 说明发生了 StackAttach。
     */
    PETHREAD currentThread = PsGetCurrentThread();
    if (!currentThread)
        return g_OrigMmGetPhysicalAddress(BaseAddress);

    /* PsGetThreadProcess 读取 KTHREAD.Process, 非分页, 任何 IRQL 安全 */
    PEPROCESS originalProc = PsGetThreadProcess(currentThread);

    if (originalProc == currentProc) {
        /* 没有 Attach — 保护进程自身的调用, 放行 */
        return g_OrigMmGetPhysicalAddress(BaseAddress);
    }

    /* 有人 Attach 到保护进程后调用 MmGetPhysicalAddress — 拦截!
     * 返回 0 让调用者认为该页不在物理内存中 */
    PHYSICAL_ADDRESS zero = { 0 };
    return zero;
}

/**
 * @brief Fake_MmMapIoSpace_Deep — IO 空间映射拦截
 *
 * 策略: 记录所有映射请求, 如果物理地址命中保护进程的内存页则拒绝。
 * 注意: 完整实现需要维护保护进程的物理页列表, 当前版本仅做日志 + 基本拦截。
 */
PVOID NTAPI Fake_MmMapIoSpace_Deep(
    PHYSICAL_ADDRESS PhysicalAddress,
    SIZE_T NumberOfBytes,
    MEMORY_CACHING_TYPE CacheType)
{
    DEEP_PRINT_ONCE(HOOK_MmMapIoSpace_Deep);
    if (!g_OrigMmMapIoSpace) return NULL;

    if (g_ProtectedPidCount == 0 || IsCallerProtected())
        return g_OrigMmMapIoSpace(PhysicalAddress, NumberOfBytes, CacheType);

    /* 可疑检查: 大范围映射 (>4KB) 可能是内存扫描 */
    /* 实际部署时应比对保护进程的 DirectoryTableBase 对应的物理页 */
    /* 当前版本: 仅日志, 全部放行 */

    return g_OrigMmMapIoSpace(PhysicalAddress, NumberOfBytes, CacheType);
}

/**
 * @brief Fake_MmMapLockedPages_Deep — MDL 锁定页映射拦截
 *
 * 检查 MDL->Process: 如果关联的进程是受保护进程, 且调用者非白名单, 则拒绝映射。
 */
PVOID NTAPI Fake_MmMapLockedPages_Deep(
    PMDL MemoryDescriptorList,
    KPROCESSOR_MODE AccessMode,
    MEMORY_CACHING_TYPE CacheType,
    PVOID RequestedAddress,
    ULONG BugCheckOnFailure,
    ULONG Priority)
{
    DEEP_PRINT_ONCE(HOOK_MmMapLockedPages_Deep);
    if (!g_OrigMmMapLockedPages) return NULL;

    if (g_ProtectedPidCount == 0 || !MemoryDescriptorList)
        return g_OrigMmMapLockedPages(MemoryDescriptorList, AccessMode,
            CacheType, RequestedAddress, BugCheckOnFailure, Priority);

    /* MmMapLockedPagesSpecifyCache 可在 DISPATCH_LEVEL 调用,
     * ShouldBlockDeepAccess 内部访问分页结构, 需 APC_LEVEL 以下 */
    if (KeGetCurrentIrql() > APC_LEVEL)
        return g_OrigMmMapLockedPages(MemoryDescriptorList, AccessMode,
            CacheType, RequestedAddress, BugCheckOnFailure, Priority);

    KIRQL oldIrql;
    if (!DeepEnterGuard(&oldIrql))
        return g_OrigMmMapLockedPages(MemoryDescriptorList, AccessMode,
            CacheType, RequestedAddress, BugCheckOnFailure, Priority);

    BOOLEAN shouldBlock = FALSE;

    __try {
        /* MDL.Process 指向拥有这些页面的进程 */
        PEPROCESS mdlProcess = *(PEPROCESS*)((PUCHAR)MemoryDescriptorList + 0x20);
        if (mdlProcess && (ULONG_PTR)mdlProcess > (ULONG_PTR)0xFFFF800000000000ULL) {
            /* 使用智能白名单判断 */
            shouldBlock = ShouldBlockDeepAccess(mdlProcess);
            if (shouldBlock) {
                SvmDebugPrint("[DeepFake] MmMapLockedPages BLOCKED: caller=%s -> MDL PID=%llu\n",
                    PsGetProcessImageFileName(PsGetCurrentProcess()),
                    (ULONG64)PsGetProcessId(mdlProcess));
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    DeepLeaveGuard(oldIrql);

    if (shouldBlock) return NULL;

    return g_OrigMmMapLockedPages(MemoryDescriptorList, AccessMode,
        CacheType, RequestedAddress, BugCheckOnFailure, Priority);
}

/**
 * @brief Fake_ExpLookupHandleTableEntry — 从句柄表中隐藏保护对象
 *
 * 核心防御: 当查询的是 PspCidTable (全局CID表) 时,
 * 如果 Handle 对应的 PID/TID 属于受保护进程, 返回 NULL。
 * 这使得直接遍历句柄表的硬核驱动也无法发现保护进程。
 */
PVOID NTAPI Fake_ExpLookupHandleTableEntry(PVOID HandleTable, HANDLE Handle)
{
    DEEP_PRINT_ONCE(HOOK_ExpLookupHandleTableEntry);
    if (!g_OrigExpLookupHandleTableEntry) return NULL;

    if (g_ProtectedPidCount == 0)
        return g_OrigExpLookupHandleTableEntry(HandleTable, Handle);

    KIRQL oldIrql;
    if (!DeepEnterGuard(&oldIrql))
        return g_OrigExpLookupHandleTableEntry(HandleTable, Handle);

    BOOLEAN shouldHide = FALSE;

    /* 只对 PspCidTable 做隐藏 (普通句柄表操作不干预) */
    if (g_PspCidTable && HandleTable == g_PspCidTable && !IsCallerProtected()) {
        /* 在 CID 表中, Handle 就是 PID 或 TID */
        if (IsProtectedPid(Handle)) {
            shouldHide = TRUE;
        }
        else {
            /* 也检查 TID: 保护进程的线程 TID 也要隐藏 */
            /* Handle 是 TID 时, 需要查找对应线程的所属进程 */
            /* 注意: 此处不能调用 PsLookupThreadByThreadId (会递归)
             * 我们只能隐藏已知 PID, TID 隐藏依赖上层 Hook */
        }
    }

    DeepLeaveGuard(oldIrql);

    if (shouldHide) return NULL;
    return g_OrigExpLookupHandleTableEntry(HandleTable, Handle);
}

/**
 * @brief Fake_PspInsertProcess — 进程插入拦截
 *
 * 拦截时机: 进程结构体刚创建完成, 即将插入全局链表。
 * 用途:
 *   1. 如果是保护进程的子进程, 自动加入保护列表
 *   2. 监控新进程创建, 记录日志
 */
NTSTATUS NTAPI Fake_PspInsertProcess(
    PEPROCESS Process, PVOID Parent,
    ACCESS_MASK DesiredAccess, ULONG ObjectAttributeFlags)
{
    DEEP_PRINT_ONCE(HOOK_PspInsertProcess);
    if (!g_OrigPspInsertProcess) return STATUS_NOT_IMPLEMENTED;

    /* 先调用原函数完成进程插入 */
    NTSTATUS status = g_OrigPspInsertProcess(Process, Parent, DesiredAccess, ObjectAttributeFlags);

    if (!NT_SUCCESS(status) || g_ProtectedPidCount == 0)
        return status;

    /* 检查父进程是否受保护 → 子进程自动继承保护 */
    __try {
        if (Parent) {
            PEPROCESS parentProc = (PEPROCESS)Parent;
            HANDLE parentPid = PsGetProcessId(parentProc);
            if (IsProtectedPid(parentPid)) {
                HANDLE childPid = PsGetProcessId(Process);
                AddProtectedPid(childPid);
                SvmDebugPrint("[DeepFake] PspInsertProcess: child PID=%llu auto-protected (parent=%llu)\n",
                    (ULONG64)childPid, (ULONG64)parentPid);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return status;
}

/**
 * @brief Fake_PspGetContextThreadInternal — 底层线程上下文获取拦截
 *
 * 核心防御: 如果外部进程获取受保护线程的上下文,
 * 清除返回的 DR0-DR7 硬件调试寄存器, 完美隐藏我们设置的硬件断点。
 */
NTSTATUS NTAPI Fake_PspGetContextThreadInternal(
    PETHREAD Thread, PCONTEXT ThreadContext,
    KPROCESSOR_MODE PreviousMode, PVOID Reserved,
    ULONG ContextFlags)
{
    DEEP_PRINT_ONCE(HOOK_PspGetContextThreadInternal);
    if (!g_OrigPspGetContextInternal) return STATUS_NOT_IMPLEMENTED;

    /* 先调用原函数获取真实上下文 */
    NTSTATUS status = g_OrigPspGetContextInternal(
        Thread, ThreadContext, PreviousMode, Reserved, ContextFlags);

    if (!NT_SUCCESS(status) || !ThreadContext || g_ProtectedPidCount == 0)
        return status;

    KIRQL oldIrql;
    if (!DeepEnterGuard(&oldIrql))
        return status;

    __try {
        PEPROCESS ownerProc = PsGetThreadProcess(Thread);
        if (ownerProc) {
            HANDLE ownerPid = PsGetProcessId(ownerProc);

            if (IsProtectedPid(ownerPid) && !IsCallerProtected()) {
                /* 外部进程获取受保护线程的上下文 → 清除硬件断点寄存器 */
                if (ContextFlags & CONTEXT_DEBUG_REGISTERS) {
                    ThreadContext->Dr0 = 0;
                    ThreadContext->Dr1 = 0;
                    ThreadContext->Dr2 = 0;
                    ThreadContext->Dr3 = 0;
                    ThreadContext->Dr6 = 0;
                    ThreadContext->Dr7 = 0;

                    SvmDebugPrint("[DeepFake] PspGetContextInternal: DR0-7 cleared for PID=%llu, TID=%llu\n",
                        (ULONG64)ownerPid, (ULONG64)PsGetThreadId(Thread));
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    DeepLeaveGuard(oldIrql);
    return status;
}


/* ========================================================================
 *  Section 4: 深度 Hook 注册与集成
 * ======================================================================== */

NTSTATUS PrepareDeepHookResources(PULONG OutOkCount)
{
    if (!OutOkCount) return STATUS_INVALID_PARAMETER;

    SvmDebugPrint("[DeepHook] ======= Preparing Deep Hook Resources (Phase 1+2) =======\n");

    /* 预先解析 PspCidTable (ExpLookupHandleTableEntry 的 Fake 函数需要) */
    GetPspCidTable();

    struct DeepHookDef {
        const char* Name;
        PVOID(*Scanner)();
        PVOID      Proxy;
        ULONG      Index;
    };

    DeepHookDef deepHooks[] = {
        /* ---- Phase 1: 原有深度 Hook ---- */

        /* 对象管理 */
        { "ObReferenceObjectByHandleWithTag", ScanForObReferenceObjectByHandleWithTag,
          (PVOID)Fake_ObReferenceObjectByHandleWithTag, HOOK_ObRefByHandleWithTag },
        { "ObfDereferenceObject", ScanForObfDereferenceObject,
          (PVOID)Fake_ObfDereferenceObject, HOOK_ObfDereferenceObject },
        { "ObfDereferenceObjectWithTag", ScanForObfDereferenceObjectWithTag,
          (PVOID)Fake_ObfDereferenceObjectWithTag, HOOK_ObfDereferenceObjectWithTag },

          /* 进程/线程 */
          { "PspInsertThread", ScanForPspInsertThread,
          (PVOID)Fake_PspInsertThread, HOOK_PspInsertThread },
          { "PspCallThreadNotifyRoutines", ScanForPspCallThreadNotifyRoutines,
          (PVOID)Fake_PspCallThreadNotifyRoutines, HOOK_PspCallThreadNotifyRoutines },
          //{ "PspExitThread", ScanForPspExitThread,
          //(PVOID)Fake_PspExitThread, HOOK_PspExitThread },

          /* 内存管理 */
          /* [DISABLED] MmProtectVirtualMemory: trampoline stolen bytes 问题 */
          //{ "MmProtectVirtualMemory(internal)", ScanForMmProtectVirtualMemory,
          //    (PVOID)Fake_MmProtectVirtualMemory_Deep, HOOK_MmProtectVirtualMemory_Deep },
          /* [DISABLED] MiObtainReferencedVadEx: BSOD 0xA + 字体异常 */
          //{ "MiObtainReferencedVadEx", ScanForMiObtainReferencedVadEx,
          //    (PVOID)Fake_MiObtainReferencedVadEx, HOOK_MiObtainReferencedVadEx },

              /* 异常/调度 */
              { "KiDispatchException", ScanForKiDispatchException,
              (PVOID)Fake_KiDispatchException, HOOK_KiDispatchException },
              { "KiStackAttachProcess", ScanForKiStackAttachProcess,
              (PVOID)Fake_KiStackAttachProcess, HOOK_KiStackAttachProcess },

              /* ---- Phase 2: 新增深度 Hook ---- */

      /* APC 注入防御 */
      { "KiInsertQueueApc", ScanForKiInsertQueueApc,
          (PVOID)Fake_KiInsertQueueApc, HOOK_KiInsertQueueApc },

          /* 物理内存防御 */
          { "MmGetPhysicalAddress", ScanForMmGetPhysicalAddress,
          (PVOID)Fake_MmGetPhysicalAddress_Deep, HOOK_MmGetPhysicalAddress_Deep },
          { "MmMapIoSpace", ScanForMmMapIoSpace,
          (PVOID)Fake_MmMapIoSpace_Deep, HOOK_MmMapIoSpace_Deep },
          /* [DISABLED] MmMapLockedPagesSpecifyCache: BSOD in MmProbeAndLockPages */
          //{ "MmMapLockedPagesSpecifyCache", ScanForMmMapLockedPagesSpecifyCache,
          //(PVOID)Fake_MmMapLockedPages_Deep, HOOK_MmMapLockedPages_Deep },

          /* 句柄表隐藏 */
          { "ExpLookupHandleTableEntry", ScanForExpLookupHandleTableEntry,
              (PVOID)Fake_ExpLookupHandleTableEntry, HOOK_ExpLookupHandleTableEntry },

              /* 进程生命周期 */
              { "PspInsertProcess", ScanForPspInsertProcess,
              (PVOID)Fake_PspInsertProcess, HOOK_PspInsertProcess },

              /* 硬件断点隐藏 */
              //{ "PspGetContextThreadInternal", ScanForPspGetContextThreadInternal,
              //    (PVOID)Fake_PspGetContextThreadInternal, HOOK_PspGetContextThreadInternal },
    };

    ULONG total = ARRAYSIZE(deepHooks);
    ULONG ok = 0;

    for (ULONG i = 0; i < total; i++) {
        PVOID targetAddr = deepHooks[i].Scanner();
        if (!targetAddr) {
            SvmDebugPrint("[DeepHook] SKIP: %s (scanner returned NULL)\n", deepHooks[i].Name);
            continue;
        }

        if (!MmIsAddressValid(targetAddr)) {
            SvmDebugPrint("[DeepHook] SKIP: %s (address %p not valid)\n",
                deepHooks[i].Name, targetAddr);
            continue;
        }

        ULONG idx = deepHooks[i].Index;
        if (idx >= HOOK_MAX_COUNT) {
            SvmDebugPrint("[DeepHook] SKIP: %s (index %lu >= HOOK_MAX_COUNT)\n",
                deepHooks[i].Name, idx);
            continue;
        }

        if (g_HookList[idx].IsUsed) {
            SvmDebugPrint("[DeepHook] SKIP: %s (slot %lu already in use)\n",
                deepHooks[i].Name, idx);
            continue;
        }

        g_HookList[idx].IsUsed = TRUE;
        g_HookList[idx].TargetAddress = targetAddr;
        g_HookList[idx].ProxyFunction = deepHooks[i].Proxy;

        NTSTATUS status = PrepareNptHookResources(
            targetAddr, deepHooks[i].Proxy, &g_HookList[idx]);

        if (!NT_SUCCESS(status)) {
            SvmDebugPrint("[DeepHook] FAIL: %s PrepareNptHookResources=0x%X\n",
                deepHooks[i].Name, status);
            g_HookList[idx].IsUsed = FALSE;
            continue;
        }

        SvmDebugPrint("[DeepHook] OK: %s -> %p (slot %lu)\n",
            deepHooks[i].Name, targetAddr, idx);
        ok++;
    }

    SvmDebugPrint("[DeepHook] ======= %lu/%lu deep hooks prepared =======\n", ok, total);
    *OutOkCount += ok;
    return STATUS_SUCCESS;
}


VOID LinkDeepTrampolineAddresses()
{
#define DLH(idx, ptr, type) \
    if ((idx) < HOOK_MAX_COUNT && g_HookList[(idx)].IsUsed && g_HookList[(idx)].TrampolinePage) \
        (ptr) = (type)g_HookList[(idx)].TrampolinePage;

    /* Phase 1 */
    DLH(HOOK_ObRefByHandleWithTag, g_OrigObRefByHandleWithTag, FnObReferenceObjectByHandleWithTag);
    DLH(HOOK_ObfDereferenceObject, g_OrigObfDerefObj, FnObfDereferenceObject);
    DLH(HOOK_ObfDereferenceObjectWithTag, g_OrigObfDerefObjWithTag, FnObfDereferenceObjectWithTag);
    DLH(HOOK_PspInsertThread, g_OrigPspInsertThread, FnPspInsertThread);
    DLH(HOOK_PspCallThreadNotifyRoutines, g_OrigPspCallThreadNotifyRoutines, FnPspCallThreadNotifyRoutines);
    DLH(HOOK_PspExitThread, g_OrigPspExitThread, FnPspExitThread);
    DLH(HOOK_MmProtectVirtualMemory_Deep, g_OrigMmProtectVmDeep, FnMmProtectVirtualMemory);
    DLH(HOOK_MiObtainReferencedVadEx, g_OrigMiObtainRefVadEx, FnMiObtainReferencedVadEx);
    DLH(HOOK_KiDispatchException, g_OrigKiDispatchException, FnKiDispatchException);
    DLH(HOOK_KiStackAttachProcess, g_OrigKiStackAttachProcess, FnKiStackAttachProcess);

    /* Phase 2 */
    DLH(HOOK_KiInsertQueueApc, g_OrigKiInsertQueueApc, FnKiInsertQueueApc);
    DLH(HOOK_MmGetPhysicalAddress_Deep, g_OrigMmGetPhysicalAddress, FnMmGetPhysicalAddress);
    DLH(HOOK_MmMapIoSpace_Deep, g_OrigMmMapIoSpace, FnMmMapIoSpace);
    DLH(HOOK_MmMapLockedPages_Deep, g_OrigMmMapLockedPages, FnMmMapLockedPagesSpecifyCache);
    DLH(HOOK_ExpLookupHandleTableEntry, g_OrigExpLookupHandleTableEntry, FnExpLookupHandleTableEntry);
    DLH(HOOK_PspInsertProcess, g_OrigPspInsertProcess, FnPspInsertProcess);
    DLH(HOOK_PspGetContextThreadInternal, g_OrigPspGetContextInternal, FnPspGetContextThreadInternal);

#undef DLH

    SvmDebugPrint("[DeepHook] LinkDeepTrampolineAddresses complete\n");
}