#include "Hide.h"
#include <ntstrsafe.h>
#pragma warning(disable: 4505)
#define SEC_IMAGE   0x01000000  // 将区段映射为可执行映像

// ================================================================
// DEBUG 开关 - 设置为 1 启用 Fake 函数入口打印，0 则关闭
// ================================================================
#define DEBUG 0  // 1: 启用调试打印 (每个 Fake 函数最多打印三次); 0: 禁用

// ================================================================
// Multi-target protection arrays
// ================================================================
HANDLE  g_ProtectedPIDs[MAX_PROTECTED_PIDS] = { 0 };
volatile LONG g_ProtectedPidCount = 0;

SVM_HWND g_ProtectedHwnds[MAX_PROTECTED_HWNDS] = { 0 };
volatile LONG g_ProtectedHwndCount = 0;

SVM_HWND g_ProtectedChildHwnds[MAX_PROTECTED_CHILD_HWNDS] = { 0 };
volatile LONG g_ProtectedChildHwndCount = 0;

// Legacy single-PID (backward compat, points to first array entry)
HANDLE g_ProtectedPID = (HANDLE)0;
WCHAR g_ProtectedProcessName[260] = { 0 };

// CSRSS process - cached for session-space access (Win32k pages)
PEPROCESS g_CsrssProcess = nullptr;
PVOID g_SavedCallbacks[MAX_CALLBACKS] = { 0 };
PEX_FAST_REF g_PspCreateProcessNotifyRoutine = NULL;
// ================================================================
// 补充微软未在头文件中声明的内部函数和对象类型
// ================================================================
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
// ================================================================

// ================================================================
// Multi-target management
// ================================================================
BOOLEAN AddProtectedPid(HANDLE Pid)
{
    if (Pid == (HANDLE)0) return FALSE;
    // Check duplicates
    for (LONG i = 0; i < g_ProtectedPidCount; i++) {
        if (g_ProtectedPIDs[i] == Pid) return TRUE; // Already there
    }
    LONG idx = InterlockedIncrement(&g_ProtectedPidCount) - 1;
    if (idx >= MAX_PROTECTED_PIDS) {
        InterlockedDecrement(&g_ProtectedPidCount);
        return FALSE;
    }
    g_ProtectedPIDs[idx] = Pid;
    // Keep legacy pointer at first entry
    if (idx == 0) g_ProtectedPID = Pid;
    return TRUE;
}

BOOLEAN RemoveProtectedPid(HANDLE Pid)
{
    for (LONG i = 0; i < g_ProtectedPidCount; i++) {
        if (g_ProtectedPIDs[i] == Pid) {
            // Shift remaining
            for (LONG j = i; j < g_ProtectedPidCount - 1; j++) {
                g_ProtectedPIDs[j] = g_ProtectedPIDs[j + 1];
            }
            LONG newCount = InterlockedDecrement(&g_ProtectedPidCount);
            g_ProtectedPIDs[newCount] = (HANDLE)0;
            g_ProtectedPID = (newCount > 0) ? g_ProtectedPIDs[0] : (HANDLE)0;
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN AddProtectedHwnd(SVM_HWND Hwnd)
{
    if (Hwnd == NULL) return FALSE;
    for (LONG i = 0; i < g_ProtectedHwndCount; i++) {
        if (g_ProtectedHwnds[i] == Hwnd) return TRUE;
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
    if (Hwnd == NULL) return FALSE;
    for (LONG i = 0; i < g_ProtectedChildHwndCount; i++) {
        if (g_ProtectedChildHwnds[i] == Hwnd) return TRUE;
    }
    LONG idx = InterlockedIncrement(&g_ProtectedChildHwndCount) - 1;
    if (idx >= MAX_PROTECTED_CHILD_HWNDS) {
        InterlockedDecrement(&g_ProtectedChildHwndCount);
        return FALSE;
    }
    g_ProtectedChildHwnds[idx] = Hwnd;
    return TRUE;
}

VOID ClearAllProtectedTargets()
{
    RtlZeroMemory(g_ProtectedPIDs, sizeof(g_ProtectedPIDs));
    InterlockedExchange(&g_ProtectedPidCount, 0);
    RtlZeroMemory(g_ProtectedHwnds, sizeof(g_ProtectedHwnds));
    InterlockedExchange(&g_ProtectedHwndCount, 0);
    RtlZeroMemory(g_ProtectedChildHwnds, sizeof(g_ProtectedChildHwnds));
    InterlockedExchange(&g_ProtectedChildHwndCount, 0);
    g_ProtectedPID = (HANDLE)0;
}

// ================================================================
// Trampoline function pointers
// ================================================================
static FnNtQuerySystemInformation    g_OrigNtQuerySystemInformation = nullptr;
static FnNtOpenProcess               g_OrigNtOpenProcess = nullptr;
static FnNtQueryInformationProcess   g_OrigNtQueryInformationProcess = nullptr;
static FnNtQueryVirtualMemory        g_OrigNtQueryVirtualMemory = nullptr;
static FnNtDuplicateObject           g_OrigNtDuplicateObject = nullptr;
static FnNtGetNextProcess            g_OrigNtGetNextProcess = nullptr;
static FnNtGetNextThread             g_OrigNtGetNextThread = nullptr;
static FnPsLookupProcessByProcessId  g_OrigPsLookupProcessByProcessId = nullptr;
static FnPsLookupThreadByThreadId    g_OrigPsLookupThreadByThreadId = nullptr;
static FnObReferenceObjectByHandle   g_OrigObReferenceObjectByHandle = nullptr;
static FnMmCopyVirtualMemory         g_OrigMmCopyVirtualMemory = nullptr;
static FnPsGetNextProcessThread      g_OrigPsGetNextProcessThread = nullptr;
static FnNtUserFindWindowEx          g_OrigNtUserFindWindowEx = nullptr;
static FnNtUserWindowFromPoint       g_OrigNtUserWindowFromPoint = nullptr;
static FnPspReferenceCidTableEntry   g_OrigPspReferenceCidTableEntry = nullptr;

// ================================================================
// Helper functions
// ================================================================
BOOLEAN IsProtectedPid(HANDLE Pid) {
    if (Pid == (HANDLE)0) return FALSE;
    for (LONG i = 0; i < g_ProtectedPidCount; i++) {
        if (g_ProtectedPIDs[i] == Pid) return TRUE;
    }
    return FALSE;
}

BOOLEAN IsProtectedHwnd(SVM_HWND Hwnd) {
    if (Hwnd == NULL) return FALSE;
    for (LONG i = 0; i < g_ProtectedHwndCount; i++) {
        if (g_ProtectedHwnds[i] == Hwnd) return TRUE;
    }
    for (LONG i = 0; i < g_ProtectedChildHwndCount; i++) {
        if (g_ProtectedChildHwnds[i] == Hwnd) return TRUE;
    }
    return FALSE;
}

BOOLEAN IsCallerProtected() {
    return IsProtectedPid(PsGetCurrentProcessId());
}

BOOLEAN IsProtectedProcessHandle(HANDLE ProcessHandle) {
    if (g_ProtectedPidCount == 0) return FALSE;
    if (ProcessHandle == NULL || ProcessHandle == (HANDLE)-1) return FALSE;
    if (ProcessHandle == NtCurrentProcess()) return FALSE;
    if (!g_OrigObReferenceObjectByHandle) return FALSE;

    PEPROCESS TargetProcess = nullptr;
    NTSTATUS status = g_OrigObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, KernelMode, (PVOID*)&TargetProcess, nullptr);
    if (!NT_SUCCESS(status) || TargetProcess == nullptr) return FALSE;

    HANDLE targetPid = PsGetProcessId(TargetProcess);
    ObDereferenceObject(TargetProcess);
    return IsProtectedPid(targetPid);
}

PVOID GetTrueSsdtAddress(PCWSTR ZwName) {
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, ZwName);
    PVOID ZwFunc = MmGetSystemRoutineAddress(&routineName);
    if (!ZwFunc) return nullptr;
    PUCHAR p = (PUCHAR)ZwFunc;
    ULONG index = 0;
    for (int i = 0; i < 50; i++) {
        // 匹配 0xB8 (mov eax)，并且判断提取出的调用号是否在合理范围内（小于 0x1000）
        if (p[i] == 0xB8) {
            ULONG tempIndex = *(PULONG)(&p[i + 1]);
            if (tempIndex > 0 && tempIndex < 0x1000) {
                index = tempIndex;
                break;
            }
        }
    }
    if (index == 0) return nullptr;
    PUCHAR kiSysCall = (PUCHAR)__readmsr(0xC0000082);
    PVOID keSDT = nullptr;
    for (int i = 0; i < 1000; i++) {
        if (kiSysCall[i] == 0x4C && kiSysCall[i + 1] == 0x8D) {
            if (kiSysCall[i + 2] == 0x15 || kiSysCall[i + 2] == 0x1D) {
                LONG offset = *(PLONG)(&kiSysCall[i + 3]);
                keSDT = (PVOID)(kiSysCall + i + 7 + offset);
                break;
            }
        }
    }
    if (!keSDT) return nullptr;
    PLONG ssdtTable = *(PLONG*)keSDT;
    LONG ssdtOffset = ssdtTable[index];
    return (PVOID)((UINT64)ssdtTable + (ssdtOffset >> 4));
}

// ================================================================
// SSSDT (Shadow SSDT) Resolver
//
// The Shadow SSDT (KeServiceDescriptorTableShadow) contains Win32k
// syscall addresses. It is only accessible from GUI threads.
// We find it by:
// 1. Locating CSRSS (always has GUI threads)
// 2. Attaching to one of its threads
// 3. Reading KTHREAD->ServiceTable which points to KeServiceDescriptorTableShadow
// 4. The second entry in that table is the Win32k SSDT base
//
// Shadow SSDT layout (array of 2 KSERVICE_TABLE_DESCRIPTOR):
//   [0] = ntoskrnl SSDT (same as KeServiceDescriptorTable)
//   [1] = win32k SSDT (W32pServiceTable)
// Each descriptor: { Base, Count, Limit, Number }
// Win32k base is at offset +0x20 from KeServiceDescriptorTableShadow
// ================================================================

// KTHREAD.ServiceTable offset (Windows 10/11 x64)
// This is at different offsets per build. Common: 0x118 (RS5+), 0x100 (older)
// We scan to find it dynamically.
static PVOID g_SssdtBase = nullptr;     // W32pServiceTable base
static ULONG g_SssdtLimit = 0;          // Number of entries

static PEPROCESS FindGuiProcess()
{
    PEPROCESS proc = nullptr;
    for (ULONG pid = 4; pid < 65536; pid += 4) {
        NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
        if (NT_SUCCESS(st) && proc) {
            PUCHAR name = PsGetProcessImageFileName(proc);
            // 找 explorer.exe 最安全，它绝对有 Win32k 会话内存
            if (name && _stricmp((const char*)name, "explorer.exe") == 0) {
                return proc;
            }
            ObDereferenceObject(proc);
        }
    }
    return nullptr;
}

NTSTATUS InitSssdtResolver()
{
    // Find KeServiceDescriptorTableShadow via KiSystemCall64

    PUCHAR kiSysCall = (PUCHAR)__readmsr(0xC0000082);
    PVOID keSDT = nullptr;       // KeServiceDescriptorTable
    PVOID keSDTShadow = nullptr; // KeServiceDescriptorTableShadow

    // KiSystemCall64 has two LEA instructions referencing the two tables:
    //   lea r10, KeServiceDescriptorTable      (4C 8D 15 xx xx xx xx)
    //   lea r11, KeServiceDescriptorTableShadow (4C 8D 1D xx xx xx xx)
    for (int i = 0; i < 1000; i++) {
        if (kiSysCall[i] == 0x4C && kiSysCall[i + 1] == 0x8D) {
            if (kiSysCall[i + 2] == 0x15) {
                // lea r10, [rip+disp32] = KeServiceDescriptorTable
                LONG offset = *(PLONG)(&kiSysCall[i + 3]);
                keSDT = (PVOID)(kiSysCall + i + 7 + offset);
            }
            else if (kiSysCall[i + 2] == 0x1D) {
                // lea r11, [rip+disp32] = KeServiceDescriptorTableShadow
                LONG offset = *(PLONG)(&kiSysCall[i + 3]);
                keSDTShadow = (PVOID)(kiSysCall + i + 7 + offset);
            }
        }
        if (keSDT && keSDTShadow) break;
    }

    if (!keSDTShadow) {
        SvmDebugPrint("[SSSDT] Failed to locate KeServiceDescriptorTableShadow\n");
        return STATUS_NOT_FOUND;
    }

    // KeServiceDescriptorTableShadow layout:
    // Offset +0x00: SSDT (ntoskrnl) Base, Count, Limit, Number  (32 bytes)
    // Offset +0x20: Shadow SSDT (win32k) Base, Count, Limit, Number
    //
    // Each entry:
    //   PLONG Base;        // +0x00 - array of encoded offsets
    //   PVOID Count;       // +0x08
    //   ULONG Limit;       // +0x10 - number of entries
    //   PUCHAR Number;     // +0x18

    PUCHAR pShadow = (PUCHAR)keSDTShadow;
    g_SssdtBase = *(PVOID*)(pShadow + 0x20);       // W32pServiceTable
    g_SssdtLimit = *(PULONG)(pShadow + 0x20 + 0x10); // Entry count

    // Always find and cache CSRSS - we need it for ALL session-page access
    PEPROCESS guiProc = FindGuiProcess();
    if (g_SssdtBase == nullptr || g_SssdtLimit == 0) {
        if (!guiProc) return STATUS_NOT_FOUND;

        KAPC_STATE apcState;
        KeStackAttachProcess(guiProc, &apcState);
        g_SssdtBase = *(PVOID*)(pShadow + 0x20);
        g_SssdtLimit = *(PULONG)(pShadow + 0x20 + 0x10);
        KeUnstackDetachProcess(&apcState);
    }

    if (guiProc) {
        g_CsrssProcess = guiProc; // 变量名没改没关系，只要存的是 explorer 的 EPROCESS 就行
    }

    if (g_SssdtBase == nullptr || g_SssdtLimit == 0) {
        SvmDebugPrint("[SSSDT] Shadow SSDT base is still NULL after CSRSS attach\n");
        return STATUS_NOT_FOUND;
    }

    SvmDebugPrint("[SSSDT] W32pServiceTable=%p, Limit=%lu\n", g_SssdtBase, g_SssdtLimit);
    return STATUS_SUCCESS;
}

PVOID GetSssdtFunctionAddress(ULONG SssdtIndex)
{

    if (g_SssdtBase == nullptr || SssdtIndex >= g_SssdtLimit) return nullptr;
    PLONG table = (PLONG)g_SssdtBase;

    // 【核弹引爆点】：在这里直接读取了 table[SssdtIndex]！
    LONG entry = table[SssdtIndex];
    PVOID addr = (PVOID)((UINT64)table + (entry >> 4));
    return addr;
}

// ================================================================
// PspReferenceCidTableEntry scanner
//
// This is an unexported ntoskrnl function called by
// PsLookupProcessByProcessId and PsLookupThreadByThreadId.
// We pattern-scan PsLookupProcessByProcessId to find the CALL to it.
// ================================================================
PVOID ScanForPspReferenceCidTableEntry()
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsLookupProcessByProcessId");
    PUCHAR pFunc = (PUCHAR)MmGetSystemRoutineAddress(&name);
    if (!pFunc) return nullptr;

    // PsLookupProcessByProcessId calls PspReferenceCidTableEntry early.
    // Look for E8 xx xx xx xx (CALL rel32) within the first 80 bytes.
    for (int i = 0; i < 80; i++) {
        if (pFunc[i] == 0xE8) {
            LONG rel32 = *(PLONG)(pFunc + i + 1);
            PVOID target = (PVOID)(pFunc + i + 5 + rel32);

            // Basic validation: target should be in kernel range
            if ((UINT64)target > 0xFFFFF80000000000ULL &&
                (UINT64)target < 0xFFFFFFFFFFFFFFFFULL) {
                SvmDebugPrint("[Scan] PspReferenceCidTableEntry candidate at %p\n", target);
                return target;
            }
        }
    }

    SvmDebugPrint("[Scan] Failed to find PspReferenceCidTableEntry\n");
    return nullptr;
}

// ================================================================
// Proxy functions
// ================================================================

// 1. NtQuerySystemInformation - hide processes and handles
static NTSTATUS NTAPI Fake_NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
#if DEBUG
    static LONG printCount = 0;
    if (InterlockedIncrement(&printCount) <= 3) {
        SvmDebugPrint("[Fake] NtQuerySystemInformation called\n");
    }
#endif

    if (!g_OrigNtQuerySystemInformation) return STATUS_UNSUCCESSFUL;

    NTSTATUS status = g_OrigNtQuerySystemInformation(
        SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    if (!NT_SUCCESS(status) || g_ProtectedPidCount == 0) {
        return status;
    }

    if (IsCallerProtected()) {
        return status;
    }

    __try {
        // SystemProcessInformation (Class 5)
        // SystemProcessInformation (Class 5)
        if (SystemInformationClass == SystemProcessInformation && SystemInformation != nullptr)
        {
            PSYSTEM_PROCESS_INFORMATION pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
            PSYSTEM_PROCESS_INFORMATION pPrev = nullptr;
            ULONG_PTR bufferEnd = (ULONG_PTR)SystemInformation + SystemInformationLength;

            while (TRUE)
            {
                // 安全边界检查，防止蓝屏
                if ((ULONG_PTR)pCur < (ULONG_PTR)SystemInformation ||
                    (ULONG_PTR)pCur + sizeof(SYSTEM_PROCESS_INFORMATION) > bufferEnd)
                {
                    break;
                }

                if (IsProtectedPid(pCur->UniqueProcessId))
                {
                    if (pPrev == nullptr) // 如果它是链表里的第一个进程
                    {
                        if (pCur->NextEntryOffset == 0) // 唯一进程
                        {
                            RtlZeroMemory(SystemInformation, SystemInformationLength);
                            break;
                        }
                        else
                        {
                            // 启发一：内存覆盖，直接把后面的数据拉到最前面！
                            PUCHAR next = (PUCHAR)pCur + pCur->NextEntryOffset;
                            ULONG moveSize = (ULONG)(bufferEnd - (ULONG_PTR)next);

                            if ((ULONG_PTR)next + moveSize <= bufferEnd)
                            {
                                RtlMoveMemory(pCur, next, moveSize);
                                continue; // 注意：指针不移，重新检查当前位置
                            }
                        }
                    }
                    else // 如果它在链表中间
                    {
                        if (pCur->NextEntryOffset == 0) {
                            pPrev->NextEntryOffset = 0; // 它是最后一个，直接切断尾巴
                        }
                        else {
                            pPrev->NextEntryOffset += pCur->NextEntryOffset; // 跨过当前节点
                        }
                        if (pCur->NextEntryOffset == 0) break;
                        pCur = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pPrev + pPrev->NextEntryOffset);
                        continue;
                    }
                }

                if (pCur->NextEntryOffset == 0) break;
                pPrev = pCur;
                pCur = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pCur + pCur->NextEntryOffset);
            }
        }
        // SystemHandleInformation (Class 16)
        else if (SystemInformationClass == SystemHandleInformation && SystemInformation != nullptr)
        {
            PSVM_HANDLE_INFO pInfo = (PSVM_HANDLE_INFO)SystemInformation;
            ULONG dst = 0;

            for (ULONG i = 0; i < pInfo->NumberOfHandles; i++)
            {
                if (!IsProtectedPid((HANDLE)(ULONG_PTR)pInfo->Handles[i].OwnerPid))
                {
                    if (dst != i) {
                        pInfo->Handles[dst] = pInfo->Handles[i];
                    }
                    dst++;
                }
            }
            pInfo->NumberOfHandles = dst;
        }
        // SystemExtendedHandleInformation (Class 64)
        else if (SystemInformationClass == SystemExtendedHandleInformation && SystemInformation != nullptr)
        {
            PSVM_HANDLE_INFO_EX pInfo = (PSVM_HANDLE_INFO_EX)SystemInformation;
            ULONG_PTR dst = 0;

            for (ULONG_PTR i = 0; i < pInfo->NumberOfHandles; i++)
            {
                if (!IsProtectedPid((HANDLE)pInfo->Handles[i].OwnerPid))
                {
                    if (dst != i) {
                        pInfo->Handles[dst] = pInfo->Handles[i];
                    }
                    dst++;
                }
            }
            pInfo->NumberOfHandles = dst;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    return status;
}

// 2. NtOpenProcess
static NTSTATUS NTAPI Fake_NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId)
{
#if DEBUG
    static LONG printCount = 0;
    if (InterlockedIncrement(&printCount) <= 3) {
        SvmDebugPrint("[Fake] NtOpenProcess called\n");
    }
#endif

    if (!g_OrigNtOpenProcess) return STATUS_UNSUCCESSFUL;

    //if (DesiredAccess == 0x19999999 && ClientId != nullptr && ClientId->UniqueProcess != nullptr) {
    //    extern HANDLE g_PendingProtectPID;
    //    // 收到暗号，将目标 PID 传递给我们的巡逻线程
    //    g_PendingProtectPID = ClientId->UniqueProcess;

    //    return (NTSTATUS)0x66668888;
    //}

    // Block external open of any protected PID
    if (ClientId != nullptr && ClientId->UniqueProcess != nullptr &&
        IsProtectedPid(ClientId->UniqueProcess))
    {
        static LONG hitOnce = 0;
        if (InterlockedCompareExchange(&hitOnce, 1, 0) == 0) {
            SvmDebugPrint("[HOOK TEST] xxx is intercepted!\n");
        }
        if (!IsCallerProtected()) {
            if (ProcessHandle) {
                __try { *ProcessHandle = NULL; }
                __except (1) {}
            }
            return STATUS_ACCESS_DENIED;
        }
    }

    // Protected process opening game target: downgrade access
    if (g_ProtectedPidCount > 0 && IsCallerProtected() && ClientId != nullptr) {
        if (!IsProtectedPid(ClientId->UniqueProcess)) {
            ;
            ACCESS_MASK fakeAccess = PROCESS_QUERY_LIMITED_INFORMATION;
            return g_OrigNtOpenProcess(ProcessHandle, fakeAccess, ObjectAttributes, ClientId);
        }
    }
    return g_OrigNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

// 3. NtQueryInformationProcess
static NTSTATUS NTAPI Fake_NtQueryInformationProcess(
    HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
#if DEBUG
    static LONG printCount = 0;
    if (InterlockedIncrement(&printCount) <= 3) {
        SvmDebugPrint("[Fake] NtQueryInformationProcess called\n");
    }
#endif

    if (!g_OrigNtQueryInformationProcess) return STATUS_UNSUCCESSFUL;
    if (IsProtectedProcessHandle(ProcessHandle) && !IsCallerProtected()) {

        if (ReturnLength) __try { *ReturnLength = 0; }
        __except (1) {}
        return STATUS_ACCESS_DENIED;
    }
    return g_OrigNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

// 4. NtQueryVirtualMemory
static NTSTATUS NTAPI Fake_NtQueryVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, ULONG MemoryInformationClass,
    PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
{
#if DEBUG
    static LONG printCount = 0;
    if (InterlockedIncrement(&printCount) <= 3) {
        SvmDebugPrint("[Fake] NtQueryVirtualMemory called\n");
    }
#endif

    if (!g_OrigNtQueryVirtualMemory) return STATUS_UNSUCCESSFUL;
    if (IsProtectedProcessHandle(ProcessHandle) && !IsCallerProtected()) {

        if (ReturnLength) __try { *ReturnLength = 0; }
        __except (1) {}
        return STATUS_ACCESS_DENIED;
    }
    return g_OrigNtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}

// 5. NtDuplicateObject
static NTSTATUS NTAPI Fake_NtDuplicateObject(
    HANDLE SourceProcessHandle, HANDLE SourceHandle,
    HANDLE TargetProcessHandle, PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
{
#if DEBUG
    static LONG printCount = 0;
    if (InterlockedIncrement(&printCount) <= 3) {
        SvmDebugPrint("[Fake] NtDuplicateObject called\n");
    }
#endif

    if (!g_OrigNtDuplicateObject) return STATUS_UNSUCCESSFUL;
    if (g_ProtectedPidCount > 0 && !IsCallerProtected()) {
        if (IsProtectedProcessHandle(SourceProcessHandle)) {

            return STATUS_ACCESS_DENIED;
        }
    }
    return g_OrigNtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
}

// 6. NtGetNextProcess
static NTSTATUS NTAPI Fake_NtGetNextProcess(
    HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle)
{
#if DEBUG
    static LONG printCount = 0;
    if (InterlockedIncrement(&printCount) <= 3) {
        SvmDebugPrint("[Fake] NtGetNextProcess called\n");
    }
#endif

    if (!g_OrigNtGetNextProcess) return STATUS_UNSUCCESSFUL;

    NTSTATUS status = g_OrigNtGetNextProcess(ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);

    if (g_ProtectedPidCount == 0 || IsCallerProtected()) return status;

    while (NT_SUCCESS(status) && NewProcessHandle != nullptr) {
        HANDLE hNext = NULL;
        __try { hNext = *NewProcessHandle; }
        __except (1) { break; }
        if (hNext == NULL) break;

        if (IsProtectedProcessHandle(hNext)) {
            HANDLE hSkip = hNext;

            __try { *NewProcessHandle = NULL; }
            __except (1) {}
            status = g_OrigNtGetNextProcess(hSkip, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
            ZwClose(hSkip);
            if (!NT_SUCCESS(status)) break;
            continue;
        }
        break;
    }
    return status;
}

// 7. NtGetNextThread
static NTSTATUS NTAPI Fake_NtGetNextThread(
    HANDLE ProcessHandle, HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes,
    ULONG Flags, PHANDLE NewThreadHandle)
{
#if DEBUG
    static LONG printCount = 0;
    if (InterlockedIncrement(&printCount) <= 3) {
        SvmDebugPrint("[Fake] NtGetNextThread called\n");
    }
#endif

    if (!g_OrigNtGetNextThread) return STATUS_UNSUCCESSFUL;
    if (g_ProtectedPidCount > 0 && !IsCallerProtected()) {
        if (IsProtectedProcessHandle(ProcessHandle)) {

            return STATUS_ACCESS_DENIED;
        }
    }
    return g_OrigNtGetNextThread(ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags, NewThreadHandle);
}

// 8. PsLookupProcessByProcessId
static NTSTATUS NTAPI Fake_PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process) {
#if DEBUG
    static LONG printCount = 0;
    if (InterlockedIncrement(&printCount) <= 3) {
        SvmDebugPrint("[Fake] PsLookupProcessByProcessId called\n");
    }
#endif

    if (!g_OrigPsLookupProcessByProcessId) return STATUS_UNSUCCESSFUL;
    if (IsProtectedPid(ProcessId) && !IsCallerProtected()) {

        if (Process) *Process = nullptr;
        return STATUS_INVALID_PARAMETER;
    }
    return g_OrigPsLookupProcessByProcessId(ProcessId, Process);
}

// 9. PsLookupThreadByThreadId
static NTSTATUS NTAPI Fake_PsLookupThreadByThreadId(HANDLE ThreadId, PETHREAD* Thread) {
#if DEBUG
    static LONG printCount = 0;
    if (InterlockedIncrement(&printCount) <= 3) {
        SvmDebugPrint("[Fake] PsLookupThreadByThreadId called\n");
    }
#endif

    if (!g_OrigPsLookupThreadByThreadId) return STATUS_UNSUCCESSFUL;
    NTSTATUS status = g_OrigPsLookupThreadByThreadId(ThreadId, Thread);
    if (NT_SUCCESS(status) && Thread && *Thread && g_ProtectedPidCount > 0) {
        if (IsProtectedPid(PsGetThreadProcessId(*Thread)) && !IsCallerProtected()) {
            ObDereferenceObject(*Thread);

            *Thread = nullptr;
            return STATUS_INVALID_PARAMETER;
        }
    }
    return status;
}

// 10. PsGetNextProcessThread
static PETHREAD NTAPI Fake_PsGetNextProcessThread(PEPROCESS Process, PETHREAD Thread) {
#if DEBUG
    static LONG printCount = 0;
    if (InterlockedIncrement(&printCount) <= 3) {
        SvmDebugPrint("[Fake] PsGetNextProcessThread called\n");
    }
#endif

    if (!g_OrigPsGetNextProcessThread) return NULL;
    if (g_ProtectedPidCount > 0 && Process != nullptr) {
        if (IsProtectedPid(PsGetProcessId(Process)) && !IsCallerProtected()) {
            if (Thread != nullptr) ObDereferenceObject(Thread);
            return NULL;
        }
    }
    return g_OrigPsGetNextProcessThread(Process, Thread);
}

// 11. ObReferenceObjectByHandle - privilege escalation + defense
static NTSTATUS NTAPI Fake_ObReferenceObjectByHandle(
    HANDLE Handle, ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode,
    PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation)
{
#if DEBUG
    static LONG printCount = 0;
    if (InterlockedIncrement(&printCount) <= 3) {
        SvmDebugPrint("[Fake] ObReferenceObjectByHandle called\n");
    }
#endif

    if (!g_OrigObReferenceObjectByHandle) return STATUS_UNSUCCESSFUL;

    NTSTATUS status = g_OrigObReferenceObjectByHandle(
        Handle, DesiredAccess, ObjectType, AccessMode, Object, HandleInformation);

    if (NT_SUCCESS(status) && Object && *Object && g_ProtectedPidCount > 0) {
        if (!IsCallerProtected()) { // 外部程序（包括 ACE）试图操作受保护的进程
            if (ObjectType == *PsProcessType && IsProtectedPid(PsGetProcessId((PEPROCESS)(*Object)))) {
                if (HandleInformation) {
                    // 【神来之笔】：保留句柄，只擦除读内存和写内存的权限！
                    HandleInformation->GrantedAccess &= ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
                }
            }
            else if (ObjectType == *PsThreadType && IsProtectedPid(PsGetThreadProcessId((PETHREAD)(*Object)))) {
                if (HandleInformation) {
                    // 剥夺对该进程内线程的挂起、结束、获取上下文的权限
                    HandleInformation->GrantedAccess &= ~(THREAD_SUSPEND_RESUME | THREAD_TERMINATE | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT);
                }
            }
        }
    }
    return status;
}

// 12. MmCopyVirtualMemory
static NTSTATUS NTAPI Fake_MmCopyVirtualMemory(
    PEPROCESS FromProcess, PVOID FromAddress,
    PEPROCESS ToProcess, PVOID ToAddress,
    SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T NumberOfBytesCopied)
{
#if DEBUG
    static LONG printCount = 0;
    if (InterlockedIncrement(&printCount) <= 3) {
        SvmDebugPrint("[Fake] MmCopyVirtualMemory called\n");
    }
#endif

    if (!g_OrigMmCopyVirtualMemory) return STATUS_UNSUCCESSFUL;

    if (g_ProtectedPidCount > 0) {
        if (IsCallerProtected()) {
            return g_OrigMmCopyVirtualMemory(FromProcess, FromAddress, ToProcess, ToAddress, BufferSize, PreviousMode, NumberOfBytesCopied);
        }

        BOOLEAN isTouchingProtected = FALSE;
        if (FromProcess && IsProtectedPid(PsGetProcessId(FromProcess))) {
            ;
            isTouchingProtected = TRUE;
        }
        if (ToProcess && IsProtectedPid(PsGetProcessId(ToProcess))) isTouchingProtected = TRUE;

        if (isTouchingProtected) {
            if (NumberOfBytesCopied) *NumberOfBytesCopied = 0;
            return STATUS_ACCESS_DENIED;
        }
    }
    return g_OrigMmCopyVirtualMemory(FromProcess, FromAddress, ToProcess, ToAddress, BufferSize, PreviousMode, NumberOfBytesCopied);
}

// ================================================================
// 13. NtUserFindWindowEx - window enumeration hiding
//
// If an external (non-protected) process tries to enumerate windows,
// hide any HWND that belongs to the protected process.
// ================================================================
static SVM_HWND NTAPI Fake_NtUserFindWindowEx(
    SVM_HWND hwndParent, SVM_HWND hwndChildAfter,
    PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow,
    ULONG dwType)
{
#if DEBUG
    static LONG printCount = 0;
    if (InterlockedIncrement(&printCount) <= 3) {
        SvmDebugPrint("[Fake] NtUserFindWindowEx called\n");
    }
#endif

    if (!g_OrigNtUserFindWindowEx) return NULL;

    SVM_HWND result = g_OrigNtUserFindWindowEx(hwndParent, hwndChildAfter, lpszClass, lpszWindow, dwType);

    if (result == NULL || g_ProtectedHwndCount == 0 || IsCallerProtected()) {
        return result;
    }

    // If the found window is protected, skip it by calling again with it as hwndChildAfter
    while (result != NULL && IsProtectedHwnd(result)) {
        ;
        result = g_OrigNtUserFindWindowEx(hwndParent, result, lpszClass, lpszWindow, dwType);
    }

    return result;
}

// ================================================================
// 14. NtUserWindowFromPoint - point-to-window hiding
//
// If a non-protected process hits the screen location of a protected window,
// return NULL so the protected window is invisible to mouse-based detection.
// ================================================================
static SVM_HWND NTAPI Fake_NtUserWindowFromPoint(LONG x, LONG y)
{
#if DEBUG
    static LONG printCount = 0;
    if (InterlockedIncrement(&printCount) <= 3) {
        SvmDebugPrint("[Fake] NtUserWindowFromPoint called\n");
    }
#endif

    if (!g_OrigNtUserWindowFromPoint) return NULL;

    SVM_HWND result = g_OrigNtUserWindowFromPoint(x, y);

    if (result == NULL || g_ProtectedHwndCount == 0 || IsCallerProtected()) {
        return result;
    }

    if (IsProtectedHwnd(result)) {

        return NULL;
    }

    return result;
}

// ================================================================
// 15. NtUserBuildHwndList (C++ helper called from assembly)
// ================================================================
extern "C" BOOLEAN Cpp_Fake_NtUserBuildHwndList(PREGISTER_CONTEXT Ctx)
{
#if DEBUG
    static LONG printCount = 0;
    if (InterlockedIncrement(&printCount) <= 3) {
        SvmDebugPrint("[Fake] Cpp_Fake_NtUserBuildHwndList called\n");
    }
#endif

    // 1. 前 4 个参数直接从寄存器里拿
    HANDLE hdesk;
    SVM_HWND hwndNext;
    ULONG fEnumChildren;
    ULONG idThread;
    ULONG cHwndMax;
    SVM_HWND* phwndFirst;
    ULONG* pcHwndNeeded;

    hdesk = (HANDLE)Ctx->Rcx;
    hwndNext = (SVM_HWND)Ctx->Rdx;
    fEnumChildren = (ULONG)Ctx->R8;
    idThread = (ULONG)Ctx->R9;

    // 2. 第 5、6、7 个参数，通过原始 RSP 去堆栈里拿！
    // 为什么是 0x28？因为 [Rsp]是返回地址, [Rsp+8,10,18,20]是前四个参数的影子空间
    // [Rsp+0x28] 刚好就是万恶的第 5 个参数！
    cHwndMax = *(ULONG*)(Ctx->Rsp + 0x28);
    phwndFirst = *(SVM_HWND**)(Ctx->Rsp + 0x30);
    pcHwndNeeded = *(ULONG**)(Ctx->Rsp + 0x38);

    // 3. 执行你的判断逻辑
    if (g_ProtectedHwndCount > 0 && !IsCallerProtected()) {
        // 如果想拦截：
        // 直接在快照里篡改 RAX 作为函数的返回值
        Ctx->Rax = (ULONG64)STATUS_ACCESS_DENIED;

        // 返回 FALSE 告诉汇编：直接 return，别去跳床了！
        return FALSE;
    }

    // 4. 如果你想修改参数骗过原函数（比如把 idThread 改成 0）
    // Ctx->R9 = 0; 
    // 汇编在 pop r9 时，就会把 0 塞进寄存器传给跳床！

    // 返回 TRUE 告诉汇编：恢复寄存器，跳向 Trampoline！
    return TRUE;
}

// 完美拦截 NtUserBuildHwndList (Win10 专属 8 参数版)
static NTSTATUS NTAPI Fake_NtUserBuildHwndList(
    HANDLE hdesk,
    SVM_HWND hwndNext,
    ULONG fEnumChildren,
    ULONG bRemoveImmersive,
    ULONG idThread,
    ULONG cHwndMax,
    SVM_HWND* phwndFirst,
    ULONG* pcHwndNeeded)
{
#if DEBUG
    static LONG printCount = 0;
    if (InterlockedIncrement(&printCount) <= 3) {
        SvmDebugPrint("[Fake] NtUserBuildHwndList called\n");
    }
#endif

    if (!g_OrigNtUserBuildHwndList) return STATUS_UNSUCCESSFUL;

    NTSTATUS status = g_OrigNtUserBuildHwndList(
        hdesk, hwndNext, fEnumChildren, bRemoveImmersive,
        idThread, cHwndMax, phwndFirst, pcHwndNeeded);

    // 只在以下条件全部满足时才过滤：
    // 1. 原函数调用成功
    // 2. 输出缓冲区有效
    // 3. 有需要保护的窗口
    // 4. 调用者不是受保护的进程自己
    if (NT_SUCCESS(status) &&
        phwndFirst != nullptr &&
        pcHwndNeeded != nullptr &&
        (g_ProtectedHwndCount > 0 || g_ProtectedChildHwndCount > 0) &&
        !IsCallerProtected())
    {
        __try {
            ULONG count = *pcHwndNeeded;

            // 安全边界：不超过缓冲区容量
            if (count > cHwndMax) {
                count = cHwndMax;
            }

            ULONG validCount = 0;
            for (ULONG i = 0; i < count; i++) {
                if (!IsProtectedHwnd(phwndFirst[i])) {
                    if (validCount != i) {
                        phwndFirst[validCount] = phwndFirst[i];
                    }
                    validCount++;
                }
            }

            // 清零数组尾部的残余数据，防止信息泄露
            for (ULONG i = validCount; i < count; i++) {
                phwndFirst[i] = NULL;
            }

            // 更新实际数量
            *pcHwndNeeded = validCount;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // 访问异常时静默忽略，返回原始结果
        }
    }

    return status;
}

// ================================================================
// 16. PspReferenceCidTableEntry - CID table entry hiding
//
// This is the lowest-level PID/TID lookup. By returning NULL for
// protected PIDs, we block ALL higher-level lookups that internally
// call this function (PsLookupProcessByProcessId, etc.)
// ================================================================
static PVOID NTAPI Fake_PspReferenceCidTableEntry(HANDLE Id, BOOLEAN IsThread)
{
#if DEBUG
    static LONG printCount = 0;
    if (InterlockedIncrement(&printCount) <= 3) {
        SvmDebugPrint("[Fake] PspReferenceCidTableEntry called\n");
    }
#endif

    if (!g_OrigPspReferenceCidTableEntry) return nullptr;

    // If this is a process ID lookup (not thread) and the PID is protected
    if (!IsThread && IsProtectedPid(Id) && !IsCallerProtected()) {
        ;
        return nullptr; // Pretend PID doesn't exist
    }

    PVOID result = g_OrigPspReferenceCidTableEntry(Id, IsThread);

    // For thread lookups, check if the thread belongs to a protected process
    if (result != nullptr && IsThread && g_ProtectedPidCount > 0 && !IsCallerProtected()) {
        // We can't easily check thread ownership from the CID entry alone
        // without risking instability, so we let PsLookupThreadByThreadId
        // handle the filtering at a higher level.
    }

    return result;
}



// 定义给汇编用的全局变量，保存跳床地址
extern "C" ULONG64 g_Trampoline_NtUserBuildHwndList = 0;

// ================================================================
// Init & Link
// ================================================================
NTSTATUS InitializeProcessHideHooks() {
    SvmDebugPrint("[Hide] InitializeProcessHideHooks called\n");


    InitNotifyRoutineResolver();

    // Initialize SSSDT resolver (find Win32k shadow syscall table)
    NTSTATUS st = InitSssdtResolver();
    if (!NT_SUCCESS(st)) {
        SvmDebugPrint("[Hide] SSSDT resolver failed (0x%X), window hooks will be skipped\n", st);
    }

    return STATUS_SUCCESS;
}

VOID LinkTrampolineAddresses() {
    // SSDT hooks
    if (g_HookList[HOOK_NtQuerySystemInformation].IsUsed && g_HookList[HOOK_NtQuerySystemInformation].TrampolinePage)
        g_OrigNtQuerySystemInformation = (FnNtQuerySystemInformation)g_HookList[HOOK_NtQuerySystemInformation].TrampolinePage;
    if (g_HookList[HOOK_NtOpenProcess].IsUsed && g_HookList[HOOK_NtOpenProcess].TrampolinePage)
        g_OrigNtOpenProcess = (FnNtOpenProcess)g_HookList[HOOK_NtOpenProcess].TrampolinePage;
    if (g_HookList[HOOK_NtQueryInformationProcess].IsUsed && g_HookList[HOOK_NtQueryInformationProcess].TrampolinePage)
        g_OrigNtQueryInformationProcess = (FnNtQueryInformationProcess)g_HookList[HOOK_NtQueryInformationProcess].TrampolinePage;
    if (g_HookList[HOOK_NtQueryVirtualMemory].IsUsed && g_HookList[HOOK_NtQueryVirtualMemory].TrampolinePage)
        g_OrigNtQueryVirtualMemory = (FnNtQueryVirtualMemory)g_HookList[HOOK_NtQueryVirtualMemory].TrampolinePage;
    if (g_HookList[HOOK_NtDuplicateObject].IsUsed && g_HookList[HOOK_NtDuplicateObject].TrampolinePage)
        g_OrigNtDuplicateObject = (FnNtDuplicateObject)g_HookList[HOOK_NtDuplicateObject].TrampolinePage;
    if (g_HookList[HOOK_NtGetNextProcess].IsUsed && g_HookList[HOOK_NtGetNextProcess].TrampolinePage)
        g_OrigNtGetNextProcess = (FnNtGetNextProcess)g_HookList[HOOK_NtGetNextProcess].TrampolinePage;
    if (g_HookList[HOOK_NtGetNextThread].IsUsed && g_HookList[HOOK_NtGetNextThread].TrampolinePage)
        g_OrigNtGetNextThread = (FnNtGetNextThread)g_HookList[HOOK_NtGetNextThread].TrampolinePage;

    // Kernel export hooks
    if (g_HookList[HOOK_PsLookupProcessByProcessId].IsUsed && g_HookList[HOOK_PsLookupProcessByProcessId].TrampolinePage)
        g_OrigPsLookupProcessByProcessId = (FnPsLookupProcessByProcessId)g_HookList[HOOK_PsLookupProcessByProcessId].TrampolinePage;
    if (g_HookList[HOOK_PsLookupThreadByThreadId].IsUsed && g_HookList[HOOK_PsLookupThreadByThreadId].TrampolinePage)
        g_OrigPsLookupThreadByThreadId = (FnPsLookupThreadByThreadId)g_HookList[HOOK_PsLookupThreadByThreadId].TrampolinePage;
    if (g_HookList[HOOK_ObReferenceObjectByHandle].IsUsed && g_HookList[HOOK_ObReferenceObjectByHandle].TrampolinePage)
        g_OrigObReferenceObjectByHandle = (FnObReferenceObjectByHandle)g_HookList[HOOK_ObReferenceObjectByHandle].TrampolinePage;
    if (g_HookList[HOOK_MmCopyVirtualMemory].IsUsed && g_HookList[HOOK_MmCopyVirtualMemory].TrampolinePage)
        g_OrigMmCopyVirtualMemory = (FnMmCopyVirtualMemory)g_HookList[HOOK_MmCopyVirtualMemory].TrampolinePage;
    if (g_HookList[HOOK_PsGetNextProcessThread].IsUsed && g_HookList[HOOK_PsGetNextProcessThread].TrampolinePage)
        g_OrigPsGetNextProcessThread = (FnPsGetNextProcessThread)g_HookList[HOOK_PsGetNextProcessThread].TrampolinePage;

    // SSSDT hooks
    if (g_HookList[HOOK_NtUserFindWindowEx].IsUsed && g_HookList[HOOK_NtUserFindWindowEx].TrampolinePage)
        g_OrigNtUserFindWindowEx = (FnNtUserFindWindowEx)g_HookList[HOOK_NtUserFindWindowEx].TrampolinePage;
    if (g_HookList[HOOK_NtUserWindowFromPoint].IsUsed && g_HookList[HOOK_NtUserWindowFromPoint].TrampolinePage)
        g_OrigNtUserWindowFromPoint = (FnNtUserWindowFromPoint)g_HookList[HOOK_NtUserWindowFromPoint].TrampolinePage;
    if (g_HookList[HOOK_NtUserBuildHwndList].IsUsed && g_HookList[HOOK_NtUserBuildHwndList].TrampolinePage)
        g_OrigNtUserBuildHwndList = (FnNtUserBuildHwndList)g_HookList[HOOK_NtUserBuildHwndList].TrampolinePage;

    // Pattern-scanned hooks
    if (g_HookList[HOOK_PspReferenceCidTableEntry].IsUsed && g_HookList[HOOK_PspReferenceCidTableEntry].TrampolinePage)
        g_OrigPspReferenceCidTableEntry = (FnPspReferenceCidTableEntry)g_HookList[HOOK_PspReferenceCidTableEntry].TrampolinePage;
}

#include <ntimage.h>  // WDK 内部自带的 PE 结构头文件

// 简单的字符串匹配，避免依赖外部库
static BOOLEAN IsStringMatch(PCSTR s1, PCSTR s2) {
    while (*s1 && *s2) {
        if (*s1 != *s2) return FALSE;
        s1++; s2++;
    }
    return (*s1 == *s2);
}

// 终极武器：从系统磁盘直读 win32u.dll，动态解析最新 SSSDT 索引
ULONG GetSssdtIndexDynamic(PCSTR FunctionName)
{
    UNICODE_STRING uniName;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE hFile = NULL;
    HANDLE hSection = NULL;
    PVOID BaseAddress = NULL;
    SIZE_T ViewSize = 0;
    ULONG SyscallIndex = 0;

    // win32u.dll 包含了所有 win32k 的 syscall 存根
    RtlInitUnicodeString(&uniName, L"\\SystemRoot\\System32\\win32u.dll");
    InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    NTSTATUS status = ZwOpenFile(&hFile, FILE_EXECUTE | SYNCHRONIZE, &objAttr, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) return 0;

    // 以 SEC_IMAGE 标志映射，系统会自动帮我们处理好 PE 节区的对齐
    status = ZwCreateSection(&hSection, SECTION_MAP_READ, NULL, NULL, PAGE_EXECUTE_READ, SEC_IMAGE, hFile);
    if (NT_SUCCESS(status)) {
        status = ZwMapViewOfSection(hSection, (HANDLE)-1, &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_READ);
        if (NT_SUCCESS(status)) {
            PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)BaseAddress;
            if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PUCHAR)BaseAddress + pDos->e_lfanew);
                if (pNt->Signature == IMAGE_NT_SIGNATURE) {
                    ULONG exportDirRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                    if (exportDirRva) {
                        PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)BaseAddress + exportDirRva);
                        PULONG pNames = (PULONG)((PUCHAR)BaseAddress + pExportDir->AddressOfNames);
                        PULONG pFuncs = (PULONG)((PUCHAR)BaseAddress + pExportDir->AddressOfFunctions);
                        PUSHORT pOrds = (PUSHORT)((PUCHAR)BaseAddress + pExportDir->AddressOfNameOrdinals);

                        for (ULONG i = 0; i < pExportDir->NumberOfNames; i++) {
                            PCSTR name = (PCSTR)((PUCHAR)BaseAddress + pNames[i]);
                            if (IsStringMatch(name, FunctionName)) {
                                USHORT ord = pOrds[i];
                                PUCHAR func = (PUCHAR)BaseAddress + pFuncs[ord];

                                // Win10/Win11 win32u.dll Syscall 机器码特征:
                                // 4C 8B D1       mov r10, rcx
                                // B8 XX XX 00 00 mov eax, <SyscallIndex>
                                if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1 && func[3] == 0xB8) {
                                    SyscallIndex = *(PULONG)(&func[4]);
                                }
                                break;
                            }
                        }
                    }
                }
            }
            ZwUnmapViewOfSection((HANDLE)-1, BaseAddress);
        }
        ZwClose(hSection);
    }
    ZwClose(hFile);

    if (SyscallIndex != 0) {
        SvmDebugPrint("[SSSDT] %s dynamic index: 0x%X\n", FunctionName, SyscallIndex & 0xFFF);
        return SyscallIndex & 0xFFF; // 去掉 0x1000 的基址，返回纯数组索引
    }

    SvmDebugPrint("[SSSDT] Failed to find dynamic index for %s\n", FunctionName);
    return 0;
}

// ================================================================
// PrepareAllNptHookResources
// ================================================================
NTSTATUS PrepareAllNptHookResources()
{
    NTSTATUS status;
    PVOID pTarget = nullptr;

    // Resolution method: how to find the target address
    enum ResolveMethod { RESOLVE_SSDT, RESOLVE_EXPORT, RESOLVE_SSSDT, RESOLVE_SCAN };

    struct HookDef {
        PCWSTR Name;
        PVOID ProxyFunc;
        HOOK_INDEX Index;
        BOOLEAN IsRequired;
        ResolveMethod Method;
        ULONG SssdtIndex;  // Only for RESOLVE_SSSDT
    };

    // NtUserFindWindowEx SSSDT index: 0x106C & 0xFFF = varies by build
    // NtUserWindowFromPoint: also varies
    // These are approximate for Win10 22H2. The exact index depends on your
    // target Windows build. You may need to adjust.
    // Common values:
    //   NtUserFindWindowEx  = 0x6C (SSSDT index, i.e. real_index - 0x1000)
    //   NtUserWindowFromPoint = 0xC1
    //const ULONG SSSDT_NtUserFindWindowEx = 0x6C;
    //const ULONG SSSDT_NtUserWindowFromPoint = 0xC1;
    //const ULONG SSSDT_NtUserBuildHwndList = 0x0B;
    // 动态获取准确的 SSSDT 索引，从此无视任何 Windows 系统更新！
    const ULONG SSSDT_NtUserFindWindowEx = GetSssdtIndexDynamic("NtUserFindWindowEx");
    const ULONG SSSDT_NtUserWindowFromPoint = GetSssdtIndexDynamic("NtUserWindowFromPoint");
    const ULONG SSSDT_NtUserBuildHwndList = GetSssdtIndexDynamic("NtUserBuildHwndList");
    HookDef hooks[] = {
        // ========================================================================

        { L"ZwQuerySystemInformation",     (PVOID)Fake_NtQuerySystemInformation,    HOOK_NtQuerySystemInformation,  TRUE,  RESOLVE_SSDT, 0 },
        { L"ZwOpenProcess",                (PVOID)Fake_NtOpenProcess,               HOOK_NtOpenProcess,             TRUE,  RESOLVE_SSDT, 0 },
        { L"ZwQueryInformationProcess",    (PVOID)Fake_NtQueryInformationProcess,   HOOK_NtQueryInformationProcess, TRUE,  RESOLVE_SSDT, 0 },
        { L"ZwQueryVirtualMemory",         (PVOID)Fake_NtQueryVirtualMemory,        HOOK_NtQueryVirtualMemory,      FALSE, RESOLVE_SSDT, 0 },
        { L"ZwDuplicateObject",            (PVOID)Fake_NtDuplicateObject,           HOOK_NtDuplicateObject,         TRUE,  RESOLVE_SSDT, 0 },
        { L"ZwGetNextProcess",             (PVOID)Fake_NtGetNextProcess,            HOOK_NtGetNextProcess,          FALSE, RESOLVE_SSDT, 0 },
        { L"ZwGetNextThread",              (PVOID)Fake_NtGetNextThread,        HOOK_NtGetNextThread,           FALSE, RESOLVE_SSDT, 0 },

        // Kernel export hooks (保持不变，因为它们本来就是内核专属的导出函数)
        { L"PsLookupProcessByProcessId",   (PVOID)Fake_PsLookupProcessByProcessId,  HOOK_PsLookupProcessByProcessId, TRUE,  RESOLVE_EXPORT, 0 },
        { L"PsLookupThreadByThreadId",     (PVOID)Fake_PsLookupThreadByThreadId,    HOOK_PsLookupThreadByThreadId,   TRUE,  RESOLVE_EXPORT, 0 },
        { L"ObReferenceObjectByHandle",    (PVOID)Fake_ObReferenceObjectByHandle,   HOOK_ObReferenceObjectByHandle,  TRUE,  RESOLVE_EXPORT, 0 },
        { L"MmCopyVirtualMemory",          (PVOID)Fake_MmCopyVirtualMemory,         HOOK_MmCopyVirtualMemory,        TRUE,  RESOLVE_EXPORT, 0 },
        { L"PsGetNextProcessThread",       (PVOID)Fake_PsGetNextProcessThread,      HOOK_PsGetNextProcessThread,     FALSE, RESOLVE_EXPORT, 0 },

        // SSSDT hooks (Win32k shadow syscalls - 保持不变，已是 Nt 级)
        { L"NtUserFindWindowEx",           (PVOID)Fake_NtUserFindWindowEx,          HOOK_NtUserFindWindowEx,         FALSE, RESOLVE_SSSDT, SSSDT_NtUserFindWindowEx },
        { L"NtUserWindowFromPoint",        (PVOID)Fake_NtUserWindowFromPoint,       HOOK_NtUserWindowFromPoint,      FALSE, RESOLVE_SSSDT, SSSDT_NtUserWindowFromPoint },
        { L"NtUserBuildHwndList",          (PVOID)Fake_NtUserBuildHwndList,         HOOK_NtUserBuildHwndList,        FALSE, RESOLVE_SSSDT, SSSDT_NtUserBuildHwndList },

        // Pattern-scanned hooks (保持不变)
        { L"PspReferenceCidTableEntry",    (PVOID)Fake_PspReferenceCidTableEntry,   HOOK_PspReferenceCidTableEntry,  FALSE, RESOLVE_SCAN, 0 },
    
    };

    ULONG totalCount = ARRAYSIZE(hooks);
    ULONG successCount = 0;

    // ================================================================
    // TWO-PASS APPROACH:
    //
    // Pass 1: Process all non-SSSDT hooks (SSDT, EXPORT, SCAN)
    //         These target ntoskrnl addresses in global kernel space,
    //         accessible from any process context.
    //
    // Pass 2: Attach to CSRSS, then process all SSSDT hooks.
    //         Win32k functions live in SESSION-PAGED memory.
    //         GetSssdtFunctionAddress reads g_SssdtBase (session page),
    //         BuildPage does memcpy from target page (session page),
    //         MmGetPhysicalAddress needs the page mapped (session page).
    //         ALL of these will BSOD if not attached to a session process.
    // ================================================================

    // --- Pass 1: non-SSSDT hooks ---
    for (ULONG i = 0; i < totalCount; i++)
    {
        if (hooks[i].Method == RESOLVE_SSSDT) continue; // Defer to pass 2

        pTarget = nullptr;

        switch (hooks[i].Method) {
        case RESOLVE_SSDT:
            pTarget = GetTrueSsdtAddress(hooks[i].Name);
            break;
        case RESOLVE_EXPORT: {
            UNICODE_STRING routineName;
            RtlInitUnicodeString(&routineName, hooks[i].Name);
            pTarget = MmGetSystemRoutineAddress(&routineName);
            break;
        }
        case RESOLVE_SCAN:
            pTarget = ScanForPspReferenceCidTableEntry();
            break;
        default:
            break;
        }

        if (pTarget == nullptr) {
            if (hooks[i].IsRequired) {
                SvmDebugPrint("[ERROR] Required target not found: %ws, aborting all hooks\n", hooks[i].Name);
                CleanupAllNptHooks();
                return STATUS_NOT_FOUND;
            }
            else {
                SvmDebugPrint("[WARN] Optional target not found: %ws, skipping\n", hooks[i].Name);
                continue;
            }
        }

        SvmDebugPrint("[INFO] Resolved %ws -> %p\n", hooks[i].Name, pTarget);

        g_HookList[hooks[i].Index].IsUsed = TRUE;
        g_HookList[hooks[i].Index].TargetAddress = pTarget;
        g_HookList[hooks[i].Index].ProxyFunction = hooks[i].ProxyFunc;

        status = PrepareNptHookResources(
            pTarget,
            hooks[i].ProxyFunc,
            &g_HookList[hooks[i].Index]
        );

        if (!NT_SUCCESS(status)) {
            if (hooks[i].IsRequired) {
                SvmDebugPrint("[ERROR] Prepare hook failed: %ws (0x%X), aborting\n", hooks[i].Name, status);
                CleanupAllNptHooks();
                return status;
            }
            else {
                SvmDebugPrint("[WARN] Optional hook prepare failed: %ws (0x%X), skipping\n", hooks[i].Name, status);
                g_HookList[hooks[i].Index].IsUsed = FALSE;
                continue;
            }
        }

        successCount++;
    }

    // --- Pass 2: SSSDT hooks (must be attached to CSRSS for session-page access) ---
    if (g_CsrssProcess != nullptr)
    {
        KAPC_STATE sssdtApcState;
        KeStackAttachProcess(g_CsrssProcess, &sssdtApcState);

        for (ULONG i = 0; i < totalCount; i++)
        {
            if (hooks[i].Method != RESOLVE_SSSDT) continue; // Already done in pass 1

            pTarget = GetSssdtFunctionAddress(hooks[i].SssdtIndex);

            if (pTarget == nullptr) {
                SvmDebugPrint("[WARN] SSSDT target not found: %ws (index 0x%X), skipping\n",
                    hooks[i].Name, hooks[i].SssdtIndex);
                continue;
            }

            SvmDebugPrint("[INFO] Resolved %ws -> %p (SSSDT, attached to CSRSS)\n", hooks[i].Name, pTarget);

            g_HookList[hooks[i].Index].IsUsed = TRUE;
            g_HookList[hooks[i].Index].TargetAddress = pTarget;
            g_HookList[hooks[i].Index].ProxyFunction = hooks[i].ProxyFunc;

            status = PrepareNptHookResources(
                pTarget,
                hooks[i].ProxyFunc,
                &g_HookList[hooks[i].Index]
            );

            if (!NT_SUCCESS(status)) {
                SvmDebugPrint("[WARN] SSSDT hook prepare failed: %ws (0x%X), skipping\n", hooks[i].Name, status);
                g_HookList[hooks[i].Index].IsUsed = FALSE;
                continue;
            }

            successCount++;
        }

        KeUnstackDetachProcess(&sssdtApcState);
    }
    else {
        SvmDebugPrint("[WARN] g_CsrssProcess is NULL, all SSSDT hooks skipped\n");
    }

    SvmDebugPrint("[Phase1] Hook resources ready: %lu/%lu succeeded\n", successCount, totalCount);

    if (successCount == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

// ================================================================
// DKOM
// ================================================================
static LIST_ENTRY* g_SavedFlink = nullptr;
static LIST_ENTRY* g_SavedBlink = nullptr;
static LIST_ENTRY* g_UnlinkedEntry = nullptr;
static ULONG g_ActiveProcessLinksOffset = 0;

static ULONG FindActiveProcessLinksOffset()
{
    PEPROCESS currentProcess = PsGetCurrentProcess();
    HANDLE currentPid = PsGetCurrentProcessId();
    PUCHAR base = (PUCHAR)currentProcess;

    for (ULONG offset = 0x200; offset < 0x600; offset += 8) {
        if (*(PHANDLE)(base + offset) == currentPid) {
            ULONG linksOffset = offset + 8;
            PLIST_ENTRY links = (PLIST_ENTRY)(base + linksOffset);
            if (links->Flink != nullptr && links->Blink != nullptr &&
                links->Flink != links) {
                SvmDebugPrint("[DKOM] ActiveProcessLinks offset = 0x%X\n", linksOffset);
                return linksOffset;
            }
        }
    }

    SvmDebugPrint("[DKOM] Failed to find ActiveProcessLinks offset\n");
    return 0;
}

NTSTATUS HideProcessByDkom(HANDLE Pid)
{
    if (Pid == (HANDLE)0) return STATUS_INVALID_PARAMETER;

    if (g_ActiveProcessLinksOffset == 0) {
        g_ActiveProcessLinksOffset = FindActiveProcessLinksOffset();
        if (g_ActiveProcessLinksOffset == 0) {
            return STATUS_NOT_FOUND;
        }
    }

    PEPROCESS targetProcess = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(Pid, &targetProcess);
    if (!NT_SUCCESS(status) || !targetProcess) {
        return STATUS_NOT_FOUND;
    }

    PLIST_ENTRY targetLinks = (PLIST_ENTRY)((PUCHAR)targetProcess + g_ActiveProcessLinksOffset);

    g_SavedFlink = targetLinks->Flink;
    g_SavedBlink = targetLinks->Blink;
    g_UnlinkedEntry = targetLinks;

    targetLinks->Blink->Flink = targetLinks->Flink;
    targetLinks->Flink->Blink = targetLinks->Blink;

    targetLinks->Flink = targetLinks;
    targetLinks->Blink = targetLinks;

    ObDereferenceObject(targetProcess);
    SvmDebugPrint("[DKOM] Process PID=%I64d unlinked from ActiveProcessLinks\n", (ULONG64)Pid);
    return STATUS_SUCCESS;
}

VOID RestoreProcessByDkom()
{
    if (g_UnlinkedEntry == nullptr || g_SavedFlink == nullptr || g_SavedBlink == nullptr) {
        return;
    }

    g_UnlinkedEntry->Flink = g_SavedFlink;
    g_UnlinkedEntry->Blink = g_SavedBlink;
    g_SavedBlink->Flink = g_UnlinkedEntry;
    g_SavedFlink->Blink = g_UnlinkedEntry;

    g_UnlinkedEntry = nullptr;
    g_SavedFlink = nullptr;
    g_SavedBlink = nullptr;

    SvmDebugPrint("[DKOM] Process re-linked to ActiveProcessLinks\n");
}
extern "C" BOOLEAN FakeProcessByPid(PEPROCESS fakeProcess, HANDLE SrcPid);
// ================================================================
// Process disguise
// ================================================================
static HANDLE GetExplorerPid()
{
    HANDLE foundPid = (HANDLE)0;
    PEPROCESS proc = nullptr;
    for (ULONG pid = 4; pid < 65536; pid += 4) {
        NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
        if (NT_SUCCESS(st) && proc) {
            PUCHAR name = PsGetProcessImageFileName(proc);
            if (name && _stricmp((const char*)name, "explorer.exe") == 0) {
                foundPid = (HANDLE)(ULONG_PTR)pid;
                ObDereferenceObject(proc);
                break;
            }
            ObDereferenceObject(proc);
        }
    }
    return foundPid;
}

// ================================================================
// Process disguise (使用启发二：全方位 PEB/LDR 伪装)
// ================================================================
NTSTATUS DisguiseProcess(HANDLE Pid)
{
    PEPROCESS targetProcess = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(Pid, &targetProcess);
    if (!NT_SUCCESS(status) || !targetProcess) return status;

    // 寻找合法的 explorer.exe 作为模板
    HANDLE hExplorer = GetExplorerPid();
    if (hExplorer) {
        // 调用 Disguise.c 里的神级伪装函数
        if (FakeProcessByPid(targetProcess, hExplorer)) {
            SvmDebugPrint("[INFO] Process %I64d deep-disguised as explorer.exe (Template PID: %I64d)\n",
                (ULONG64)Pid, (ULONG64)hExplorer);
        }
        else {
            SvmDebugPrint("[WARN] FakeProcessByPid failed.\n");
        }
    }

    // 【关键】：彻底弃用 DKOM 物理断链，避免 ACE 查出“幽灵线程”
    // HideProcessByDkom(Pid); 

    ObDereferenceObject(targetProcess);
    return STATUS_SUCCESS;
}
// ================================================================
// Driver file self-delete
//
// Deletes the driver file from disk after loading.
// Works by getting the driver's image file path from DriverObject,
// then clearing the section object pointer to release the file lock,
// and finally calling ZwDeleteFile.
// ================================================================
NTSTATUS DeleteDriverFile(PDRIVER_OBJECT DriverObject)
{
    if (!DriverObject || !DriverObject->DriverSection) {
        return STATUS_INVALID_PARAMETER;
    }

    PKLDR_DATA_TABLE_ENTRY pLdrEntry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

    if (pLdrEntry->FullDllName.Buffer == nullptr || pLdrEntry->FullDllName.Length == 0) {
        SvmDebugPrint("[SelfDel] No FullDllName available\n");
        return STATUS_NOT_FOUND;
    }

    // Build the NT path from the loader entry
    UNICODE_STRING filePath = pLdrEntry->FullDllName;

    SvmDebugPrint("[SelfDel] Attempting to delete: %wZ\n", &filePath);

    // Open the file to manipulate its section object
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status = ZwOpenFile(&hFile, DELETE | SYNCHRONIZE, &objAttr, &iosb,
        FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(status)) {
        SvmDebugPrint("[SelfDel] ZwOpenFile failed: 0x%X\n", status);
        // Try alternative: get file object and clear section pointers
        PFILE_OBJECT fileObj = nullptr;
        status = ObReferenceObjectByName(&filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL, 0, *IoFileObjectType, KernelMode, NULL, (PVOID*)&fileObj);
        if (NT_SUCCESS(status) && fileObj) {
            // Clear the section object pointer to release the file mapping lock
            PSECTION_OBJECT_POINTERS pSectionObj = fileObj->SectionObjectPointer;
            if (pSectionObj) {
                pSectionObj->ImageSectionObject = NULL;
                pSectionObj->DataSectionObject = NULL;
            }
            ObDereferenceObject(fileObj);

            // Now try to delete
            status = ZwDeleteFile(&objAttr);
            if (NT_SUCCESS(status)) {
                SvmDebugPrint("[SelfDel] Driver file deleted via section clear\n");
            }
            else {
                SvmDebugPrint("[SelfDel] ZwDeleteFile failed after section clear: 0x%X\n", status);
            }
        }
        return status;
    }

    // Set file disposition to delete-on-close
    FILE_DISPOSITION_INFORMATION dispInfo;
    dispInfo.DeleteFile = TRUE;
    status = ZwSetInformationFile(hFile, &iosb, &dispInfo,
        sizeof(FILE_DISPOSITION_INFORMATION), FileDispositionInformation);

    ZwClose(hFile);

    if (NT_SUCCESS(status)) {
        SvmDebugPrint("[SelfDel] Driver file marked for deletion\n");
    }
    else {
        SvmDebugPrint("[SelfDel] SetDisposition failed: 0x%X\n", status);
    }

    return status;
}

// 1. 动态寻找 PspCreateProcessNotifyRoutine 数组的地址
PEX_FAST_REF FindPspCreateProcessNotifyRoutine() {
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"PsSetCreateProcessNotifyRoutine");
    PUCHAR funcAddr = (PUCHAR)MmGetSystemRoutineAddress(&routineName);
    if (!funcAddr) return NULL;

    for (int i = 0; i < 0x100; i++) {
        if (funcAddr[i] == 0x48 && funcAddr[i + 1] == 0x8D && funcAddr[i + 2] == 0x0D) {
            LONG offset = *(PLONG)(funcAddr + i + 3);
            return (PEX_FAST_REF)(funcAddr + i + 7 + offset);
        }
    }
    return NULL;
}


NTSTATUS InitNotifyRoutineResolver() {
    g_PspCreateProcessNotifyRoutine = FindPspCreateProcessNotifyRoutine();
    if (g_PspCreateProcessNotifyRoutine) {
        SvmDebugPrint("[INFO] PspCreateProcessNotifyRoutine found at %p\n", g_PspCreateProcessNotifyRoutine);
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

// 2. 拔掉所有的眼线 (仅执行纯粹的物理内存赋值，绝对不掉用 API，不打印 Log)
void DisableAllProcessCallbacks() {
    if (!g_PspCreateProcessNotifyRoutine) return;

    for (int i = 0; i < MAX_CALLBACKS; i++) {
        PEX_FAST_REF callbackSlot = &g_PspCreateProcessNotifyRoutine[i];
        PVOID currentVal = (PVOID)callbackSlot->Object;
        if (currentVal != NULL) {
            g_SavedCallbacks[i] = currentVal;
            // 原子操作覆盖内存，在 VMExit 中极其安全
            InterlockedExchangePointer((PVOID*)callbackSlot, NULL);
        }
        else {
            g_SavedCallbacks[i] = NULL;
        }
    }
}

// 3. 恢复所有的眼线 (同样无 API，纯内存操作)
void RestoreAllProcessCallbacks() {
    if (!g_PspCreateProcessNotifyRoutine) return;

    for (int i = 0; i < MAX_CALLBACKS; i++) {
        if (g_SavedCallbacks[i] != NULL) {
            PEX_FAST_REF callbackSlot = &g_PspCreateProcessNotifyRoutine[i];
            InterlockedExchangePointer((PVOID*)callbackSlot, g_SavedCallbacks[i]);
            g_SavedCallbacks[i] = NULL;
        }
    }
}