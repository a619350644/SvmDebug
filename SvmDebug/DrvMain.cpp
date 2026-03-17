/**
 * @file DrvMain.cpp
 * @brief 驱动主入口 - DriverEntry、IRP派发、SVM初始化线程、卸载清理
 * @author yewilliam
 * @date 2026/03/16
 *
 * 标准WDM驱动入口点, 提供:
 *   - 设备对象/符号链接创建(R3通过\\.\SvmDebug通信)
 *   - IOCTL派发: 进程保护/窗口保护/内存读写
 *   - SVM初始化系统线程(多核VCPU分配+NPT构建+IPI广播)
 *   - 延迟Hook安装线程(SSDT/SSSDT解析+NPT Hook激活)
 *   - 安全卸载流程(drain等待+IPI恢复+资源释放)
 */

#include <ntifs.h>
#include <ntimage.h>
#include "SVM.h"
#include "Hook.h"
#include "Hide.h"
#include "HvMemory.h"
#include "Common.h"

/* ========================================================================
 *  设备名 / 符号链接 / IOCTL 定义
 *  正常加载方式: sc create / ZwLoadDriver / inf 安装
 * ======================================================================== */
#define SVM_DEVICE_NAME     L"\\Device\\SvmDebug"
#define SVM_SYMLINK_NAME    L"\\DosDevices\\SvmDebug"

/* 保护命令 IOCTL (0x820 起, 避开 HvMemory.h 中 0x810-0x812) */
#define IOCTL_SVM_PROTECT_PID           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SVM_PROTECT_HWND          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SVM_PROTECT_CHILD_HWND    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SVM_CLEAR_ALL             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x823, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SVM_DISABLE_CALLBACKS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x824, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SVM_RESTORE_CALLBACKS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x825, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SVM_PROTECT_EX            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x826, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ========================================================================
 *  全局变量
 * ======================================================================== */
PVCPU_CONTEXT g_nVMCB[64] = { 0 };

PDEVICE_OBJECT g_DeviceObject = NULL;

HANDLE g_PendingProtectPID = (HANDLE)0;
HANDLE g_WorkerThreadHandle = NULL;
volatile BOOLEAN g_DriverUnloading = FALSE;

volatile LONG g_PendingCallbackOp = 0;

static LONG volatile g_SuccessfulSvmCores = 0;

ULONG64 g_SystemCr3 = 0;

/* ========================================================================
 *  前向声明
 * ======================================================================== */
ULONG_PTR IpiActivateHookBroadcastCallback(ULONG_PTR Argument);
ULONG_PTR IpiInstallBroadcastCallback(ULONG_PTR Argument);
ULONG_PTR IpiUnloadBroadcastCallback(ULONG_PTR Argument);
ULONG_PTR IpiUninstallHookBroadcastCallback(ULONG_PTR Argument);

VOID SvmInitSystemThread(PVOID StartContext);
VOID CommunicationThread(PVOID Context);
VOID DelayedHookWorkItemRoutine(PVOID Context);

/* ========================================================================
 *  资源释放
 * ======================================================================== */
/**
 * @brief 释放所有驱动资源 - VCPU上下文、Host栈、NPT页表、TrampolinePage
 * @author yewilliam
 * @date 2026/03/16
 * @note TrampolinePage在此统一释放(CleanupAllNptHooks故意保留以防执行中崩溃)
 */
static VOID ReleaseDriverResources()
{
    ULONG n_cout = KeQueryActiveProcessorCount(0);
    if (n_cout > 64) n_cout = 64;

    for (ULONG i = 0; i < n_cout; i++)
    {
        if (!g_nVMCB[i]) continue;
        if (g_nVMCB[i]->HostStackBase) {
            ExFreePoolWithTag(g_nVMCB[i]->HostStackBase, 'HSTK');
            g_nVMCB[i]->HostStackBase = nullptr;
        }
        g_nVMCB[i]->HostStackTop = 0;
        FreePvCPUNPT(g_nVMCB[i]);
        ExFreePoolWithTag(g_nVMCB[i], 'VMCB');
        g_nVMCB[i] = nullptr;
    }
    CleanupAllNptHooks();

    for (int i = 0; i < HOOK_MAX_COUNT; i++) {
        if (g_HookList[i].TrampolinePage) {
            MmFreeContiguousMemory(g_HookList[i].TrampolinePage);
            g_HookList[i].TrampolinePage = nullptr;
        }
    }
}

/* ========================================================================
 *  IRP 派发 — Create / Close
 * ======================================================================== */
static NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ========================================================================
 *  IRP 派发 — DeviceIoControl
 *  R3 通过 CreateFile("\\\\.\\SvmDebug") + DeviceIoControl 下发命令
 * ======================================================================== */
static NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    switch (ioctl)
    {
    /* ---- 保护 PID ---- */
    case IOCTL_SVM_PROTECT_PID:
    {
        if (inLen < sizeof(PROTECT_INFO) || !buffer) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        PPROTECT_INFO pi = (PPROTECT_INFO)buffer;
        HANDLE pid = (HANDLE)pi->Pid;

        AddProtectedPid(pid);
        g_PendingProtectPID = pid;

        SvmDebugPrint("[IOCTL] PROTECT_PID: %llu\n", pi->Pid);
        break;
    }

    /* ---- 扩展保护 (PID + HWND + 子窗口) ---- */
    case IOCTL_SVM_PROTECT_EX:
    {
        if (inLen < sizeof(PROTECT_INFO_EX) || !buffer) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        PPROTECT_INFO_EX px = (PPROTECT_INFO_EX)buffer;

        AddProtectedPid((HANDLE)px->Pid);
        g_PendingProtectPID = (HANDLE)px->Pid;

        if (px->Hwnd)
            AddProtectedHwnd((SVM_HWND)px->Hwnd);

        for (ULONG c = 0; c < px->ChildHwndCount && c < 8; c++) {
            if (px->ChildHwnds[c])
                AddProtectedChildHwnd((SVM_HWND)px->ChildHwnds[c]);
        }

        SvmDebugPrint("[IOCTL] PROTECT_EX: PID=%llu, HWND=0x%llX, children=%lu\n",
            px->Pid, px->Hwnd, px->ChildHwndCount);
        break;
    }

    /* ---- 保护窗口句柄 ---- */
    case IOCTL_SVM_PROTECT_HWND:
    {
        if (inLen < sizeof(ULONG64) || !buffer) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        SVM_HWND hwnd = (SVM_HWND)(*(PULONG64)buffer);
        AddProtectedHwnd(hwnd);
        SvmDebugPrint("[IOCTL] PROTECT_HWND: 0x%llX\n", (ULONG64)hwnd);
        break;
    }

    /* ---- 保护子窗口 ---- */
    case IOCTL_SVM_PROTECT_CHILD_HWND:
    {
        if (inLen < sizeof(ULONG64) || !buffer) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        SVM_HWND hwnd = (SVM_HWND)(*(PULONG64)buffer);
        AddProtectedChildHwnd(hwnd);
        break;
    }

    /* ---- 清除所有保护 ---- */
    case IOCTL_SVM_CLEAR_ALL:
    {
        ClearAllProtectedTargets();
        SvmDebugPrint("[IOCTL] CLEAR_ALL\n");
        break;
    }

    /* ---- 禁用 / 恢复回调 (IOCTL 已在 PASSIVE_LEVEL, 可直接调用) ---- */
    case IOCTL_SVM_DISABLE_CALLBACKS:
    {
        DisableAllProcessCallbacks();
        SvmDebugPrint("[IOCTL] DISABLE_CALLBACKS\n");
        break;
    }

    case IOCTL_SVM_RESTORE_CALLBACKS:
    {
        RestoreAllProcessCallbacks();
        SvmDebugPrint("[IOCTL] RESTORE_CALLBACKS\n");
        break;
    }

    /* ---- 内存读写 (复用 HvMemory.h 定义) ---- */
    case IOCTL_HV_READ_MEMORY:
    {
        if (inLen < sizeof(HV_MEMORY_REQUEST) || !buffer) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        PHV_MEMORY_REQUEST req = (PHV_MEMORY_REQUEST)buffer;
        status = HvReadProcessMemory(
            req->TargetPid,
            (PVOID)req->Address,
            (PVOID)req->BufferAddress,
            (SIZE_T)req->Size);
        break;
    }

    case IOCTL_HV_WRITE_MEMORY:
    {
        if (inLen < sizeof(HV_MEMORY_REQUEST) || !buffer) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        PHV_MEMORY_REQUEST req = (PHV_MEMORY_REQUEST)buffer;
        status = HvWriteProcessMemory(
            req->TargetPid,
            (PVOID)req->Address,
            (PVOID)req->BufferAddress,
            (SIZE_T)req->Size);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ========================================================================
 *  Communication thread (runs at PASSIVE_LEVEL)
 * ======================================================================== */

/**
 * @brief 通信工作线程 - 轮询保护请求、执行PEB伪装、卸载时统一清理
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] Context - 未使用
 * @note 运行在PASSIVE_LEVEL, 1秒轮询间隔
 *       卸载流程: 清除保护→drain等待→IPI卸载Hook→IPI退出SVM→释放资源
 */
VOID CommunicationThread(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    LARGE_INTEGER timeout;
    timeout.QuadPart = -10000000; // 1 second

    while (!g_DriverUnloading)
    {

        if (g_PendingProtectPID != (HANDLE)0 && g_PendingProtectPID != g_ProtectedPID)
        {
            HANDLE targetPid = g_PendingProtectPID;
            SvmDebugPrint("[INFO] New protection request, target PID: %I64d\n", (ULONG64)targetPid);

            {
                LARGE_INTEGER initDelay;
                initDelay.QuadPart = -5000000LL; // 500ms
                KeDelayExecutionThread(KernelMode, FALSE, &initDelay);
            }

            __try {
                DisguiseProcess(targetPid);
                SvmDebugPrint("[INFO] Process PEB disguise complete.\n");
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                SvmDebugPrint("[WARN] DisguiseProcess exception 0x%X for PID %I64d (non-fatal)\n",
                    GetExceptionCode(), (ULONG64)targetPid);
            }

            AddProtectedPid(targetPid);
            SvmDebugPrint("[INFO] PID %I64d added to protected list (count=%ld).\n",
                (ULONG64)targetPid, g_ProtectedPidCount);

            g_ProtectedPID = targetPid;
            SvmDebugPrint("[INFO] Process disguise and SVM protection fully activated!\n");
        }
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
    }

    // ================================================================
    // 统一卸载清理流程
    // ================================================================
    SvmDebugPrint("[INFO] CommunicationThread: Unload signal received, starting cleanup...\n");

    ClearAllProtectedTargets();
    MemoryBarrier();

    {
        LARGE_INTEGER drainDelay;
        drainDelay.QuadPart = -20000000LL; // 2s
        KeDelayExecutionThread(KernelMode, FALSE, &drainDelay);
    }
    SvmDebugPrint("[INFO] Hook drain complete.\n");


    KeIpiGenericCall(IpiUninstallHookBroadcastCallback, 0);
    SvmDebugPrint("[INFO] All NPT hooks deactivated (original pages restored).\n");

    {
        LARGE_INTEGER hookDrainDelay;
        hookDrainDelay.QuadPart = -30000000LL; // 3s — 增加等待，确保 win32k 永久线程完成
        KeDelayExecutionThread(KernelMode, FALSE, &hookDrainDelay);
    }

    KeIpiGenericCall(IpiUnloadBroadcastCallback, 0);
    SvmDebugPrint("[INFO] All cores exited SVM mode.\n");

    {
        LARGE_INTEGER drainDelay2;
        drainDelay2.QuadPart = -30000000LL; // 3s
        KeDelayExecutionThread(KernelMode, FALSE, &drainDelay2);
    }

    HvFreeSharedContext();
    CleanupAllNptHooks();
    ReleaseDriverResources();
    if (g_CsrssProcess) {
        ObDereferenceObject(g_CsrssProcess);
        g_CsrssProcess = NULL;
    }

    SvmDebugPrint("[INFO] Cleanup complete. System is back to normal.\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}


/* ========================================================================
 *  Delayed hook activation thread
 * ======================================================================== */

/**
 * @brief 延迟Hook安装线程 - 初始化Hook→准备资源→拆分大页→激活NPT Hook
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] Context - 未使用
 * @note 完整流程: InitializeProcessHideHooks → PrepareAllNptHookResources
 *       → LinkTrampolineAddresses → 解析TargetPa → PreSplitLargePageByPa
 *       → PrewarmPtVaCache → ActivateAllNptHooks → IPI广播激活
 */
VOID DelayedHookWorkItemRoutine(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    SvmDebugPrint("[INFO] Hook Install Thread Started...\n");

    NTSTATUS status = InitializeProcessHideHooks();
    if (!NT_SUCCESS(status)) {
        SvmDebugPrint("[ERROR] InitializeProcessHideHooks failed: 0x%X\n", status);
        PsTerminateSystemThread(status);
        return;
    }

    status = PrepareAllNptHookResources();
    if (!NT_SUCCESS(status)) {
        SvmDebugPrint("[ERROR] PrepareAllNptHookResources failed: 0x%X\n", status);
        PsTerminateSystemThread(status);
        return;
    }

    LinkTrampolineAddresses();

    ULONG n_cout = KeQueryActiveProcessorCount(0);
    if (n_cout > 64) n_cout = 64;

    {
        KAPC_STATE paApcState;
        BOOLEAN attached = FALSE;

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

    for (int h = 0; h < HOOK_MAX_COUNT; h++) {
        if (g_HookList[h].IsUsed && g_HookList[h].ResourcesReady) {
            if (g_HookList[h].OriginalPagePa == 0 || g_HookList[h].TargetPa == 0) {
                SvmDebugPrint("[WARN] Disabling hook %d: OrigPa=0x%llX, TargetPa=0x%llX\n",
                    h, g_HookList[h].OriginalPagePa, g_HookList[h].TargetPa);
                g_HookList[h].ResourcesReady = FALSE;
            }
        }
    }

    for (ULONG cpu = 0; cpu < n_cout; cpu++) {
        for (int h = 0; h < HOOK_MAX_COUNT; h++) {
            if (g_HookList[h].IsUsed && g_HookList[h].ResourcesReady && g_HookList[h].TargetPa != 0) {
                NTSTATUS splitStatus = PreSplitLargePageByPa(g_nVMCB[cpu], g_HookList[h].TargetPa);
                if (!NT_SUCCESS(splitStatus)) {
                    SvmDebugPrint("[WARN] PreSplitLargePageByPa failed for hook %d on CPU %lu: 0x%X\n",
                        h, cpu, splitStatus);
                }
            }
        }
    }
    SvmDebugPrint("[INFO] All large pages pre-split for %lu cores.\n", n_cout);

    for (ULONG cpu = 0; cpu < n_cout; cpu++) {
        PrewarmPtVaCache(g_nVMCB[cpu]);
    }
    SvmDebugPrint("[INFO] PT VA cache prewarmed for all %lu cores.\n", n_cout);

    for (ULONG cpu = 0; cpu < n_cout; cpu++) {
        status = ActivateAllNptHooks(g_nVMCB[cpu]);
        if (!NT_SUCCESS(status)) {
            SvmDebugPrint("[ERROR] ActivateAllNptHooks failed for CPU %lu: 0x%X\n", cpu, status);
        }
    }
    SvmDebugPrint("[INFO] NPT entries prepared at PASSIVE_LEVEL for all %lu cores.\n", n_cout);

    KeIpiGenericCall(IpiActivateHookBroadcastCallback, 0);
    SvmDebugPrint("[INFO] SUCCESS! All NPT hooks safely activated.\n");

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* ========================================================================
 *  IPI 回调
 * ======================================================================== */

/**
 * @brief IPI回调: 在所有CPU上通过CPUID超级调用刷新NPT TLB激活Hook
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] Argument - 未使用
 * @return 0
 */
ULONG_PTR IpiActivateHookBroadcastCallback(ULONG_PTR Argument)
{
    UNREFERENCED_PARAMETER(Argument);
    int regs[4] = { 0 };
    __cpuid(regs, CPUID_UNLOAD_SVM_INSTALL_HOOK);
    return 0;
}

/**
 * @brief IPI回调: 在当前CPU上初始化SVM核心(VMCB配置+VMRUN)
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] Argument - 未使用
 * @return 1表示成功进入SVM模式, 0表示失败
 */
ULONG_PTR IpiInstallBroadcastCallback(ULONG_PTR Argument)
{
    UNREFERENCED_PARAMETER(Argument);
    ULONG processorNumber = KeGetCurrentProcessorNumber();
    if (processorNumber >= 64) return 0;

    PVCPU_CONTEXT vpData = g_nVMCB[processorNumber];
    if (!vpData) return 0;
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

/**
 * @brief IPI回调: 在所有CPU上通过CPUID超级调用退出SVM模式
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] Argument - 未使用
 * @return 0
 */
ULONG_PTR IpiUnloadBroadcastCallback(ULONG_PTR Argument)
{
    UNREFERENCED_PARAMETER(Argument);
    int regs[4] = { 0 };
    __cpuid(regs, CPUID_UNLOAD_SVM_DEBUG);
    return 0;
}

/**
 * @brief IPI回调: 在所有CPU上通过CPUID超级调用恢复NPT原始映射(卸载Hook)
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] Argument - 未使用
 * @return 0
 */
ULONG_PTR IpiUninstallHookBroadcastCallback(ULONG_PTR Argument)
{
    UNREFERENCED_PARAMETER(Argument);
    int regs[4] = { 0 };
    __cpuid(regs, CPUID_UNLOAD_SVM_UNINSTALL_HOOK);
    return 0;
}

/* ========================================================================
 *  DriverUnload — 删除设备/符号链接, 通知 CommunicationThread 退出
 * ======================================================================== */
/**
 * @brief 驱动卸载入口 - 通知CommunicationThread退出并等待, 删除设备/符号链接
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] DriverObject - 驱动对象
 */
void UnloadDriver(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    SvmDebugPrint("[DrvMain] UnloadDriver called.\n");

    g_DriverUnloading = TRUE;
    MemoryBarrier();

    if (g_WorkerThreadHandle) {
        ZwWaitForSingleObject(g_WorkerThreadHandle, FALSE, NULL);
        ZwClose(g_WorkerThreadHandle);
        g_WorkerThreadHandle = NULL;
    }

    /* 删除符号链接和设备对象 */
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, SVM_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);

    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    SvmDebugPrint("[DrvMain] Unload complete.\n");
}
/**
 * @brief IPI回调: 通过CPUID超级调用触发NPT Hook激活
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] Argument - 未使用
 * @return 0
 */

static ULONG_PTR BroadcastHookActivation(ULONG_PTR Argument) {
    UNREFERENCED_PARAMETER(Argument);
    int cpuInfo[4] = { 0 };
    __cpuidex(cpuInfo, CPUID_UNLOAD_SVM_INSTALL_HOOK, 0);
    return 0;
}
/**
 * @brief 通过IPI广播在所有CPU上同步激活NPT Hook
 * @author yewilliam
 * @date 2026/03/16
 */

VOID TriggerGlobalHookActivation() {
    SvmDebugPrint("[INFO] IPI broadcast NPT Hook activation...\n");
    KeIpiGenericCall(BroadcastHookActivation, 0);
    SvmDebugPrint("[INFO] All cores NPT Hook activated.\n");
}

/* ========================================================================
 *  SVM 初始化系统线程
 * ======================================================================== */

/**
 * @brief SVM初始化系统线程 - 分配VCPU资源、构建NPT、IPI广播启动SVM
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] StartContext - 未使用
 * @note 在System进程上下文运行, 独立线程避免阻塞DriverEntry返回
 *       流程: AMD支持检查 → 分配VCPU_CONTEXT × N核 → PrepareNPT
 *       → HvInitSharedContext → IPI InitSVMCORE → 启动通信线程和Hook线程
 */
VOID SvmInitSystemThread(PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);

    SvmDebugPrint("[SVM] SvmInitSystemThread started in System process.\n");
    g_SystemCr3 = __readcr3() & ~0xFFF;

    if (!CommCheckAMDsupport()) {
        SvmDebugPrint("[ERROR] AMD SVM is not supported or locked by BIOS / Hyper-V.\n");
        PsTerminateSystemThread(STATUS_NOT_SUPPORTED);
        return;
    }

    LONG n_cout = KeQueryActiveProcessorCount(0);
    if (n_cout > 64) n_cout = 64;

    for (LONG i = 0; i < n_cout; i++)
    {
        g_nVMCB[i] = (PVCPU_CONTEXT)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(VCPU_CONTEXT), 'VMCB');
        if (!g_nVMCB[i]) {
            SvmDebugPrint("[ERROR] Failed to allocate VCPU_CONTEXT for CPU %ld\n", i);
            goto cleanup_alloc;
        }
        RtlZeroMemory(g_nVMCB[i], sizeof(VCPU_CONTEXT));

        g_nVMCB[i]->HostStackBase = ExAllocatePool2(POOL_FLAG_NON_PAGED, KERNEL_STACK_SIZE, 'HSTK');
        if (!g_nVMCB[i]->HostStackBase) {
            SvmDebugPrint("[ERROR] Failed to allocate host stack for CPU %ld\n", i);
            goto cleanup_alloc;
        }
        g_nVMCB[i]->ProcessorIndex = i;
        g_nVMCB[i]->NptCr3 = PrepareNPT(g_nVMCB[i]);
        if (g_nVMCB[i]->NptCr3 == 0) {
            SvmDebugPrint("[ERROR] PrepareNPT failed for CPU %ld\n", i);
            goto cleanup_alloc;
        }
        g_nVMCB[i]->HostStackTop = (UINT64)g_nVMCB[i]->HostStackBase + KERNEL_STACK_SIZE;

        g_nVMCB[i]->ActiveHook = nullptr;
        g_nVMCB[i]->SuspendedHook = nullptr;
        g_nVMCB[i]->SplitPtCount = 0;
        RtlZeroMemory(g_nVMCB[i]->SplitPtPas, sizeof(g_nVMCB[i]->SplitPtPas));
        continue;

    cleanup_alloc:
        for (LONG j = 0; j <= i; j++) {
            if (g_nVMCB[j]) {
                if (g_nVMCB[j]->HostStackBase)
                    ExFreePoolWithTag(g_nVMCB[j]->HostStackBase, 'HSTK');
                ExFreePoolWithTag(g_nVMCB[j], 'VMCB');
                g_nVMCB[j] = nullptr;
            }
        }
        PsTerminateSystemThread(STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    SvmDebugPrint("[SVM] All CPU resources allocated. Initializing shared context...\n");
    HvInitSharedContext();

    g_SuccessfulSvmCores = 0;
    KeIpiGenericCall(IpiInstallBroadcastCallback, 0);

    if (g_SuccessfulSvmCores != n_cout) {
        SvmDebugPrint("[ERROR] SVM initialization failed! Expected: %ld, Success: %ld\n",
            n_cout, g_SuccessfulSvmCores);

        KeIpiGenericCall(IpiUnloadBroadcastCallback, 0);
        HvFreeSharedContext();
        ReleaseDriverResources();

        PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
        return;
    }

    SvmDebugPrint("[DrvMain] System is now running in SVM Guest mode on ALL %ld cores.\n",
        g_SuccessfulSvmCores);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS status = PsCreateSystemThread(
        &g_WorkerThreadHandle, THREAD_ALL_ACCESS,
        &oa, NULL, NULL, CommunicationThread, NULL);
    if (!NT_SUCCESS(status)) {
        SvmDebugPrint("[ERROR] Failed to create CommunicationThread: 0x%X\n", status);
    }

    HANDLE hThreadHook;
    status = PsCreateSystemThread(
        &hThreadHook, THREAD_ALL_ACCESS,
        &oa, NULL, NULL, (PKSTART_ROUTINE)DelayedHookWorkItemRoutine, NULL);
    if (NT_SUCCESS(status) && hThreadHook) {
        ZwClose(hThreadHook);
    }
    else {
        SvmDebugPrint("[ERROR] Failed to create hook installation thread: 0x%X\n", status);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* ========================================================================
 *  DriverEntry — 标准 WDM 入口点
 *
 *  加载方式:
 *    sc create SvmDebug type= kernel binPath= C:\path\SvmDebug.sys
 *    sc start  SvmDebug
 *    sc stop   SvmDebug
 *    sc delete SvmDebug
 * ======================================================================== */
/**
 * @brief 驱动主入口 - 创建设备对象/符号链接, 启动SVM初始化线程
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] DriverObject - WDM驱动对象
 * @param [in] RegistryPath - 注册表路径(未使用)
 * @return STATUS_SUCCESS或设备创建/线程创建错误码
 */
EXTERN_C NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    SvmDebugPrint("[DrvMain] DriverEntry (standard loading).\n");

    /* ---- 创建设备对象 ---- */
    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, SVM_DEVICE_NAME);

    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject);

    if (!NT_SUCCESS(status)) {
        SvmDebugPrint("[ERROR] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    /* ---- 创建符号链接 (R3 通过 \\\\.\\SvmDebug 打开) ---- */
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, SVM_SYMLINK_NAME);

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        SvmDebugPrint("[ERROR] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    /* ---- IRP 派发表 ---- */
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload                         = UnloadDriver;

    /* ---- 启动 SVM 初始化线程 (不阻塞 DriverEntry 返回) ---- */
    HANDLE hThread;
    status = PsCreateSystemThread(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL, NULL, NULL,
        SvmInitSystemThread,
        NULL);

    if (NT_SUCCESS(status)) {
        ZwClose(hThread);
    }
    else {
        SvmDebugPrint("[ERROR] Failed to create SVM init thread: 0x%X\n", status);
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    SvmDebugPrint("[DrvMain] DriverEntry completed, SVM init in progress.\n");
    return STATUS_SUCCESS;
}

/* ========================================================================
 *  [原始代码备份] KDMapper 专用入口点
 *
 *  KDMapper 以 (PVOID, PVOID) 签名调用 DriverEntry,
 *  不创建设备对象, 不注册 DriverUnload, 也没有 IRP 通信。
 *  R3 只能通过 CPUID hypercall 下发命令。
 *
 *  如需恢复 KDMapper 加载方式:
 *    1. 注释掉上方的 DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)
 *    2. 取消注释以下代码
 *    3. 可删除 DispatchCreateClose / DispatchDeviceControl / g_DeviceObject
 * ========================================================================
 *
 * EXTERN_C NTSTATUS DriverEntry(PVOID pAllocationBase, PVOID pSize)
 * {
 *     UNREFERENCED_PARAMETER(pAllocationBase);
 *     UNREFERENCED_PARAMETER(pSize);
 *
 *     HANDLE hThread;
 *
 *     NTSTATUS status = PsCreateSystemThread(
 *         &hThread,
 *         THREAD_ALL_ACCESS,
 *         NULL,
 *         NULL,
 *         NULL,
 *         SvmInitSystemThread,
 *         NULL
 *     );
 *
 *     if (NT_SUCCESS(status)) {
 *         ZwClose(hThread);
 *     }
 *     else {
 *         SvmDebugPrint("[ERROR] Failed to create SVM init thread! Status: 0x%X\n", status);
 *         return status;
 *     }
 *
 *     return STATUS_SUCCESS;
 * }
 *
 * ======================================================================== */
