#include "Hide.h"
#include "NPT.h"


PNT_QUERY_SYSTEM_INFORMATION g_OriginalNtQuerySystemInformation = nullptr;

// 供 SVM.cpp 在 #VMEXIT NPF 中调用的全局变量
ULONG64 g_NtQuery_Gpa = 0;
ULONG64 g_NtQuery_RealPa = 0;
ULONG64 g_NtQuery_HookPa = 0;


NTSTATUS InstallNptHook()
{

    return STATUS_SUCCESS;
}

// 导出给 DrvMain.cpp 调用
VOID UninstallNptHook()
{

    return;
}

NTSTATUS HookedNtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    NTSTATUS status = g_OriginalNtQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );

    // 如果原始调用失败或未找到受保护的 PID，直接返回
    if (!NT_SUCCESS(status) || g_ProtectedPID == NULL) {
        return status;
    }

    // 新增：防御性编程，防止在 IRQL >= DISPATCH_LEVEL 时修改分页/用户态内存导致 d1 蓝屏
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
        return status;
    }

    // 注意：SystemInformation 缓冲区可能在用户态，必须用 __try/__except 保护
    __try {
        if (SystemInformationClass == 16 && SystemInformation) {
            PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)SystemInformation;
            ULONG validCount = 0;
            for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
                if ((HANDLE)(ULONG_PTR)handleInfo->Handles[i].UniqueProcessId != g_ProtectedPID) {
                    handleInfo->Handles[validCount] = handleInfo->Handles[i];
                    validCount++;
                }
            }
            handleInfo->NumberOfHandles = validCount;
        }
        else if (SystemInformationClass == 64 && SystemInformation) {
            PSYSTEM_HANDLE_INFORMATION_EX handleInfoEx = (PSYSTEM_HANDLE_INFORMATION_EX)SystemInformation;
            ULONG_PTR validCount = 0;
            for (ULONG_PTR i = 0; i < handleInfoEx->NumberOfHandles; i++) {
                if ((HANDLE)handleInfoEx->Handles[i].UniqueProcessId != g_ProtectedPID) {
                    handleInfoEx->Handles[validCount] = handleInfoEx->Handles[i];
                    validCount++;
                }
            }
            handleInfoEx->NumberOfHandles = validCount;
        }
        // 隐藏进程
        else if (SystemInformationClass == 5 && SystemInformation) {
            PSYSTEM_PROCESS_INFORMATION curr = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
            PSYSTEM_PROCESS_INFORMATION prev = nullptr;

            while (curr) {
                if (curr->UniqueProcessId == g_ProtectedPID) {
                    if (prev != nullptr) {
                        if (curr->NextEntryOffset != 0) {
                            prev->NextEntryOffset += curr->NextEntryOffset;
                        }
                        else {
                            prev->NextEntryOffset = 0;
                        }
                    }
                }
                else {
                    prev = curr;
                }
                if (curr->NextEntryOffset == 0) break;
                curr = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)curr + curr->NextEntryOffset);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 静默忽略
    }

    return status;
}