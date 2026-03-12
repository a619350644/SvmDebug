#include <ntifs.h>
#include <ntimage.h>
#include "SVM.h"
#include "Hook.h"
#include "Hide.h"
#include "HvMemory.h"
#include "Common.h"

VCPU_CONTEXT g_nVMCB[64] = { 0 };

// ========================================================
// Global variables
// ========================================================
HANDLE g_PendingProtectPID = (HANDLE)0;
HANDLE g_WorkerThreadHandle = NULL;
volatile BOOLEAN g_DriverUnloading = FALSE;

static LONG volatile g_SuccessfulSvmCores = 0;

ULONG_PTR IpiActivateHookBroadcastCallback(ULONG_PTR Argument);
ULONG_PTR IpiInstallBroadcastCallback(ULONG_PTR Argument);
ULONG_PTR IpiUnloadBroadcastCallback(ULONG_PTR Argument);

static VOID ReleaseDriverResources()
{
    ULONG n_cout = KeQueryActiveProcessorCount(0);
    if (n_cout > 64) n_cout = 64;

    for (ULONG i = 0; i < n_cout; i++)
    {
        if (g_nVMCB[i].HostStackBase) {
            ExFreePoolWithTag(g_nVMCB[i].HostStackBase, 'HSTK');
            g_nVMCB[i].HostStackBase = nullptr;
        }
        g_nVMCB[i].HostStackTop = 0;
        FreePvCPUNPT(&g_nVMCB[i]);
    }
    CleanupAllNptHooks();
}

// ========================================================
// Communication thread (runs at PASSIVE_LEVEL)
// ========================================================
VOID CommunicationThread(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    LARGE_INTEGER timeout;
    timeout.QuadPart = -10000000; // 1 second

    while (!g_DriverUnloading)
    {
        if (g_PendingProtectPID != (HANDLE)0 && g_PendingProtectPID != g_ProtectedPID)
        {
            SvmDebugPrint("[INFO] New protection request, target PID: %I64d\n", (ULONG64)g_PendingProtectPID);

            // 1. Disguise process as explorer.exe
            DisguiseProcess(g_PendingProtectPID);

            // 2. Activate intercept
            g_ProtectedPID = g_PendingProtectPID;

            SvmDebugPrint("[INFO] Process disguise and SVM protection fully activated!\n");
        }
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
    }

    // ---- 【新增】卸载清理流程 ----
    SvmDebugPrint("[INFO] CommunicationThread: Unload signal received, starting cleanup...\n");

    // 1. 恢复进程回调
    RestoreAllProcessCallbacks();

    // 2. 恢复 DKOM 链接
    RestoreProcessByDkom();

    // 3. 广播 IPI 让所有核心退出 SVM
    KeIpiGenericCall(IpiUnloadBroadcastCallback, 0);
    SvmDebugPrint("[INFO] All cores exited SVM mode.\n");

    // 4. 释放资源
    HvFreeSharedContext();
    // 注意：ReleaseDriverResources 应该在所有核心退出后才能安全调用
    // 但由于我们是手动映射的，内存释放需要格外小心

    SvmDebugPrint("[INFO] Cleanup complete. System is back to normal.\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ========================================================
// Delayed hook activation thread
// ========================================================
VOID DelayedHookWorkItemRoutine(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    SvmDebugPrint("[INFO] Hook Install Thread Started...\n");

    NTSTATUS status = InitializeProcessHideHooks();
    if (!NT_SUCCESS(status)) return;

    status = PrepareAllNptHookResources();
    if (!NT_SUCCESS(status)) return;

    // Link trampoline function pointers before activation
    LinkTrampolineAddresses();

    {
        KAPC_STATE paApcState;
        BOOLEAN attached = FALSE;

        // Attach to CSRSS to resolve ALL physical addresses (including session pages)
        if (g_CsrssProcess != nullptr) {
            KeStackAttachProcess(g_CsrssProcess, &paApcState);
            attached = TRUE;
        }

        for (int h = 0; h < HOOK_MAX_COUNT; h++) {
            if (g_HookList[h].IsUsed && g_HookList[h].TargetAddress && g_HookList[h].TargetPa == 0) {
                g_HookList[h].TargetPa = MmGetPhysicalAddress(g_HookList[h].TargetAddress).QuadPart;
                if (g_HookList[h].TargetPa == 0) {
                    SvmDebugPrint("[WARN] TargetPa still 0 for hook %d (VA=%p), disabling\n",
                        h, g_HookList[h].TargetAddress);
                    g_HookList[h].IsUsed = FALSE;
                }
            }
        }

        if (attached) {
            KeUnstackDetachProcess(&paApcState);
        }
    }

    SvmDebugPrint("[INFO] SUCCESS! TargetPa All safely resolved.\n");

    ULONG n_cout = KeQueryActiveProcessorCount(0);
    if (n_cout > 64) n_cout = 64;

    for (ULONG cpu = 0; cpu < n_cout; cpu++) {
        for (int h = 0; h < HOOK_MAX_COUNT; h++) {
            if (g_HookList[h].IsUsed && g_HookList[h].ResourcesReady && g_HookList[h].TargetPa != 0) {
                PreSplitLargePageByPa(&g_nVMCB[cpu], g_HookList[h].TargetPa);
            }
        }
    }

    // Broadcast IPI to activate NPT hooks on all cores via CPUID hypercall
    KeIpiGenericCall(IpiActivateHookBroadcastCallback, 0);
    SvmDebugPrint("[INFO] SUCCESS! All NPT hooks safely activated.\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

ULONG_PTR IpiActivateHookBroadcastCallback(ULONG_PTR Argument)
{
    UNREFERENCED_PARAMETER(Argument);
    int regs[4] = { 0 };
    __cpuid(regs, CPUID_UNLOAD_SVM_INSTALL_HOOK);
    return 0;
}

ULONG_PTR IpiInstallBroadcastCallback(ULONG_PTR Argument)
{
    UNREFERENCED_PARAMETER(Argument);
    ULONG processorNumber = KeGetCurrentProcessorNumber();
    if (processorNumber >= 64) return 0;

    PVCPU_CONTEXT vpData = &g_nVMCB[processorNumber];
    BOOLEAN svmState = CommCheckAMDsupport();
    if (svmState == false) {
        return 0;
    }

    NTSTATUS status = InitSVMCORE(vpData);
    if (NT_SUCCESS(status)) {
        InterlockedIncrement(&g_SuccessfulSvmCores);
        return 1;
    }
    return 0;
}

ULONG_PTR IpiUnloadBroadcastCallback(ULONG_PTR Argument)
{
    UNREFERENCED_PARAMETER(Argument);
    int regs[4] = { 0 };
    __cpuid(regs, CPUID_UNLOAD_SVM_DEBUG);
    return 0;
}

void UnloadDriver(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    g_DriverUnloading = TRUE;
    if (g_WorkerThreadHandle) {
        ZwWaitForSingleObject(g_WorkerThreadHandle, FALSE, NULL);
        ZwClose(g_WorkerThreadHandle);
    }

    RestoreProcessByDkom();

    KeIpiGenericCall(IpiUnloadBroadcastCallback, 0);
    SvmDebugPrint("[DrvMain] SVM unloaded\n");

    HvFreeSharedContext();
    ReleaseDriverResources();
}

static ULONG_PTR BroadcastHookActivation(ULONG_PTR Argument) {
    UNREFERENCED_PARAMETER(Argument);
    int cpuInfo[4] = { 0 };
    __cpuidex(cpuInfo, CPUID_UNLOAD_SVM_INSTALL_HOOK, 0);
    return 0;
}

VOID TriggerGlobalHookActivation() {
    SvmDebugPrint("[INFO] 正在通过 IPI 广播向所有核心下发 NPT Hook 指令...\n");
    KeIpiGenericCall(BroadcastHookActivation, 0);
    SvmDebugPrint("[INFO] 全核心 NPT Hook 激活完毕！\n");
}

ULONG64 g_SystemCr3 = 0;
// ========================================================
// 【新增】安全初始化系统线程：脱离 KDMapper 的 CR3 上下文
// ========================================================
VOID SvmInitSystemThread(PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);
    // 此时我们身处 System 进程中，这里的 CR3 是永恒不变的！
    SvmDebugPrint("[SVM] SvmInitSystemThread started in System process.\n");
    g_SystemCr3 = __readcr3() & ~0xFFF;
    if (!CommCheckAMDsupport()) {
        SvmDebugPrint("[ERROR] AMD SVM is not supported or locked by BIOS / Hyper-V.\n");
        PsTerminateSystemThread(STATUS_NOT_SUPPORTED);
        return; // 必须 return
    }

    LONG n_cout = KeQueryActiveProcessorCount(0);
    if (n_cout > 64) n_cout = 64;

    for (LONG i = 0; i < n_cout; i++)
    {
        g_nVMCB[i].HostStackBase = ExAllocatePool2(POOL_FLAG_NON_PAGED, KERNEL_STACK_SIZE, 'HSTK');
        g_nVMCB[i].ProcessorIndex = i;
        g_nVMCB[i].NptCr3 = PrepareNPT(&g_nVMCB[i]);
        g_nVMCB[i].HostStackTop = (UINT64)g_nVMCB[i].HostStackBase + KERNEL_STACK_SIZE;
    }

    HvInitSharedContext();

    g_SuccessfulSvmCores = 0;
    KeIpiGenericCall(IpiInstallBroadcastCallback, 0);

    if (g_SuccessfulSvmCores != n_cout) {
        SvmDebugPrint("[ERROR] SVM initialization failed! Expected: %lu, Success: %ld\n", n_cout, g_SuccessfulSvmCores);

        KeIpiGenericCall(IpiUnloadBroadcastCallback, 0);
        HvFreeSharedContext();
        ReleaseDriverResources();

        PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
        return;
    }

    SvmDebugPrint("[DrvMain] System is now running in SVM Guest mode on ALL %ld cores.\n", g_SuccessfulSvmCores);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    PsCreateSystemThread(&g_WorkerThreadHandle, THREAD_ALL_ACCESS, &oa, NULL, NULL, CommunicationThread, NULL);

    // 【重要修改】因为我们是手动映射，根本没有 DriverObject，绝对不要调用 HideDriver！
    // 否则一调就会抛出 0xC0000005 蓝屏
    // HideDriver(DriverObject);

    HANDLE hThreadHook;
    PsCreateSystemThread(&hThreadHook, THREAD_ALL_ACCESS, &oa, NULL, NULL, (PKSTART_ROUTINE)DelayedHookWorkItemRoutine, NULL);
    if (hThreadHook) ZwClose(hThreadHook);

    // 系统线程的使命完成，功成身退
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ========================================================
// 【修改】KDMapper 专用入口点
// ========================================================
EXTERN_C NTSTATUS DriverEntry(PVOID pAllocationBase, PVOID pSize)
{
    UNREFERENCED_PARAMETER(pAllocationBase);
    UNREFERENCED_PARAMETER(pSize);

    // 参数不再是 DriverObject 和 RegistryPath！不要碰它们！

    HANDLE hThread;

    // 参数3传NULL，代表这个线程挂靠在 System 进程身上
    NTSTATUS status = PsCreateSystemThread(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        SvmInitSystemThread,
        NULL
    );

    if (NT_SUCCESS(status)) {
        ZwClose(hThread);
    }
    else {
        SvmDebugPrint("[ERROR] Failed to create SVM init thread! Status: 0x%X\n", status);
        return status;
    }

    // 【神之一手】主函数立即返回成功！
    // 这样 KDMapper 就可以安全退出，销毁它的内存和临时 CR3。
    // 而我们的 SvmInitSystemThread 已经挂在 System 进程下，开始接管 CPU 硬件了！
    return STATUS_SUCCESS;
}