#include "Hook.h"
#include "SVM.h" 
#include "NPT.h"
#include "hde/hde64.h"

// 定义全局数组
NPT_HOOK_CONTEXT g_HookList[HOOK_MAX_COUNT] = { 0 };

static volatile LONG g_HookCleanupDone = 0;
static KSPIN_LOCK g_HookCleanupLock;
static BOOLEAN g_HookCleanupLockInitialized = FALSE;

static VOID EnsureHookCleanupLockInitialized()
{
    if (!g_HookCleanupLockInitialized) {
        KeInitializeSpinLock(&g_HookCleanupLock);
        g_HookCleanupLockInitialized = TRUE;
    }
}

// 驱动自隐藏核心函数
NTSTATUS HideDriver(PDRIVER_OBJECT DriverObject)
{
    if (!DriverObject || !DriverObject->DriverSection) return STATUS_INVALID_PARAMETER;

    PKLDR_DATA_TABLE_ENTRY pLdrEntry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

    // 1. 从 InLoadOrderLinks 链表中摘除
    if (pLdrEntry->InLoadOrderLinks.Flink && pLdrEntry->InLoadOrderLinks.Blink) {
        PLIST_ENTRY Prev = pLdrEntry->InLoadOrderLinks.Blink;
        PLIST_ENTRY Next = pLdrEntry->InLoadOrderLinks.Flink;
        Prev->Flink = Next;
        Next->Blink = Prev;
        // 自循环，防止蓝屏
        pLdrEntry->InLoadOrderLinks.Flink = &pLdrEntry->InLoadOrderLinks;
        pLdrEntry->InLoadOrderLinks.Blink = &pLdrEntry->InLoadOrderLinks;
    }

    // 2. 抹除 DriverObject 里的敏感特征 (幽灵化)
    DriverObject->DriverInit = NULL;
    DriverObject->DriverStartIo = NULL;
    DriverObject->DriverUnload = NULL;
    DriverObject->DriverSize = 0;

    // 清空驱动名
    if (DriverObject->DriverName.Buffer) {
        RtlZeroMemory(DriverObject->DriverName.Buffer, DriverObject->DriverName.MaximumLength);
        DriverObject->DriverName.Length = 0;
    }

    SvmDebugPrint("[INFO] Driver successfully unlinked and hidden.\n");
    return STATUS_SUCCESS;
}

PVOID GetRealNtAddress(PCWSTR ZwName) {
    UNICODE_STRING uniName;
    RtlInitUnicodeString(&uniName, ZwName);

    PVOID ZwAddr = MmGetSystemRoutineAddress(&uniName);
    if (!ZwAddr) return nullptr;

    ULONG SsdtIndex = 0;
    PUCHAR ptr = (PUCHAR)ZwAddr;
    for (int i = 0; i < 32; i++) {
        if (ptr[i] == 0xB8) {
            SsdtIndex = *(PULONG)(ptr + i + 1);
            break;
        }
    }
    if (SsdtIndex == 0) return nullptr;

    static ULONG_PTR SsdtBase = 0;
    if (!SsdtBase) {
        PUCHAR KiSystemCall64 = (PUCHAR)__readmsr(0xC0000082);
        for (int i = 0; i < 512; i++) {
            if (KiSystemCall64[i] == 0x4C && KiSystemCall64[i + 1] == 0x8D && KiSystemCall64[i + 2] == 0x15) {
                LONG offset = *(PLONG)(&KiSystemCall64[i + 3]);
                SsdtBase = (ULONG_PTR)&KiSystemCall64[i + 7] + offset;
                break;
            }
        }
    }

    if (!SsdtBase) return nullptr;

    PLONG SsdtTable = (PLONG)SsdtBase;
    LONG offset = SsdtTable[SsdtIndex];

    return (PVOID)(SsdtBase + (offset >> 4));
}

static VOID ResetSingleHookState(PNPT_HOOK_CONTEXT HookContext)
{
    if (!HookContext) return;

    HookContext->ResourcesReady = FALSE;
    HookContext->HookedBytes = 0;

    if (HookContext->FakePage != nullptr) {
        BOOLEAN isSharedByOthers = FALSE;
        for (int i = 0; i < HOOK_MAX_COUNT; i++) {
            if (&g_HookList[i] != HookContext && g_HookList[i].IsUsed &&
                g_HookList[i].FakePage == HookContext->FakePage) {
                isSharedByOthers = TRUE;
                break;
            }
        }

        if (!isSharedByOthers) {
            MmFreeContiguousMemory(HookContext->FakePage);
        }
        HookContext->FakePage = nullptr;
    }
    HookContext->FakePagePa = 0;

    if (HookContext->TrampolinePage != nullptr) {
        MmFreeContiguousMemory(HookContext->TrampolinePage);
        HookContext->TrampolinePage = nullptr;
    }
}

NTSTATUS RegisterNptHook(PVOID TargetAddress, PVOID ProxyFunction)
{
    if (!TargetAddress || !ProxyFunction) return STATUS_INVALID_PARAMETER;

    EnsureHookCleanupLockInitialized();
    InterlockedExchange(&g_HookCleanupDone, 0);

    for (int i = 0; i < HOOK_MAX_COUNT; i++) {
        if (!g_HookList[i].IsUsed) {
            RtlZeroMemory(&g_HookList[i], sizeof(NPT_HOOK_CONTEXT));
            g_HookList[i].IsUsed = TRUE;
            g_HookList[i].TargetAddress = TargetAddress;
            g_HookList[i].ProxyFunction = ProxyFunction;
            SvmDebugPrint("[INFO] Hook registered: Target=%p, Proxy=%p (Slot %d)\n",
                TargetAddress, ProxyFunction, i);
            return STATUS_SUCCESS;
        }
    }

    SvmDebugPrint("[ERROR] Hook table full!\n");
    return STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS PrepareAllNptHooks()
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG successCount = 0;

    for (int i = 0; i < HOOK_MAX_COUNT; ++i)
    {
        if (g_HookList[i].IsUsed && !g_HookList[i].ResourcesReady)
        {
            status = PrepareNptHookResources(
                g_HookList[i].TargetAddress,
                g_HookList[i].ProxyFunction,
                &g_HookList[i]);

            if (!NT_SUCCESS(status)) {
                SvmDebugPrint("[ERROR] Prepare hook failed: Target=%p, status=0x%X\n",
                    g_HookList[i].TargetAddress, status);
                return status;
            }
            successCount++;
        }
    }

    SvmDebugPrint("[INFO] Phase1 prepared %lu hook resource(s).\n", successCount);
    return STATUS_SUCCESS;
}

NTSTATUS ActivateAllNptHooks(PVCPU_CONTEXT vpData)
{
    if (vpData == nullptr) return STATUS_INVALID_PARAMETER;

    NTSTATUS status = STATUS_SUCCESS;
    for (int i = 0; i < HOOK_MAX_COUNT; ++i)
    {
        if (g_HookList[i].IsUsed && g_HookList[i].ResourcesReady)
        {
            status = ActivateNptHookInNpt(vpData, &g_HookList[i]);
            if (!NT_SUCCESS(status)) return status;
        }
    }
    return STATUS_SUCCESS;
}

VOID CleanupAllNptHooks()
{
    EnsureHookCleanupLockInitialized();

    if (InterlockedCompareExchange(&g_HookCleanupDone, 1, 0) == 1) return;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_HookCleanupLock, &oldIrql);

    for (int i = 0; i < HOOK_MAX_COUNT; ++i)
    {
        if (g_HookList[i].IsUsed || g_HookList[i].ResourcesReady)
            FreeNptHook(&g_HookList[i]);
    }

    KeReleaseSpinLock(&g_HookCleanupLock, oldIrql);
    SvmDebugPrint("[INFO] All NPT hook resources cleaned up safely.\n");
}

PNPT_HOOK_CONTEXT FindHookByFaultPa(ULONG64 FaultPa)
{
    ULONG64 faultPagePa = FaultPa & ~0xFFFULL;

    for (int i = 0; i < HOOK_MAX_COUNT; ++i)
    {
        if (!g_HookList[i].IsUsed) continue;

        if (g_HookList[i].OriginalPagePa != 0 &&
            g_HookList[i].OriginalPagePa == faultPagePa)
            return &g_HookList[i];

        if (g_HookList[i].TargetPa != 0 &&
            (g_HookList[i].TargetPa & ~0xFFFULL) == faultPagePa)
            return &g_HookList[i];
    }

    return nullptr;
}

// 构建 NPT 假页 (影子页)
NTSTATUS BuildPage(PNPT_HOOK_CONTEXT HookContext)
{
    PHYSICAL_ADDRESS HighestAcceptableAddress;
    HighestAcceptableAddress.QuadPart = ~0ULL;

    if (HookContext->OriginalPageBase == nullptr) {
        SvmDebugPrint("[ERROR][BuildPage] OriginalPageBase is NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    HookContext->FakePage = MmAllocateContiguousMemory(PAGE_SIZE, HighestAcceptableAddress);
    if (HookContext->FakePage == nullptr) {
        SvmDebugPrint("[ERROR][BuildPage] FakePage alloc failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(HookContext->FakePage, PAGE_SIZE);
    RtlCopyMemory(HookContext->FakePage, HookContext->OriginalPageBase, PAGE_SIZE);

    return STATUS_SUCCESS;
}


// ================================================================
// BuildTrampoline
//
// 【CHANGE vs ORIGINAL】新增 case 5: MOV CRn, GPR (0F 22) 检测
// 将 VMware 嵌套不安全的 "mov cr0, rax" 等指令替换为 VMMCALL
// ================================================================
NTSTATUS BuildTrampoline(PNPT_HOOK_CONTEXT HookContext)
{
    if (!HookContext || !HookContext->TargetAddress || !HookContext->TrampolinePage) {
        return STATUS_INVALID_PARAMETER;
    }

    PUCHAR src = (PUCHAR)HookContext->TargetAddress;
    PUCHAR dst = (PUCHAR)HookContext->TrampolinePage;
    ULONG copiedBytes = 0;
    ULONG dstOffset = 0;
    hde64s hs;

    // 最少拷贝 14 字节，以便在原函数处写入 14 字节的绝对 JMP
    while (copiedBytes < 14)
    {
        ULONG len = hde64_disasm(src + copiedBytes, &hs);
        if (hs.flags & F_ERROR) {
            SvmDebugPrint("[ERR][BuildTrampoline] Disassembly error at %p\n", src + copiedBytes);
            return STATUS_UNSUCCESSFUL;
        }

        // 1. CALL rel32 (机器码 E8)
        if (hs.opcode == 0xE8)
        {
            LONG rel32 = (LONG)hs.imm.imm32;
            ULONG64 targetAddr = (ULONG64)src + copiedBytes + hs.len + rel32;

            UCHAR callStub[] = { 0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08 };
            RtlCopyMemory(dst + dstOffset, callStub, sizeof(callStub));
            dstOffset += sizeof(callStub);
            *(PULONG64)(dst + dstOffset) = targetAddr;
            dstOffset += 8;
        }
        // 2. JMP rel32 (E9) / JMP rel8 (EB)
        else if (hs.opcode == 0xE9 || hs.opcode == 0xEB)
        {
            LONG relOffset = (hs.opcode == 0xE9) ? (LONG)hs.imm.imm32 : (CHAR)hs.imm.imm8;
            ULONG64 targetAddr = (ULONG64)src + copiedBytes + hs.len + relOffset;

            UCHAR jmpStub[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            *(PULONG64)(&jmpStub[6]) = targetAddr;
            RtlCopyMemory(dst + dstOffset, jmpStub, 14);
            dstOffset += 14;
        }
        // 3. Jcc rel32 / Jcc rel8 (条件跳转)
        else if ((hs.opcode == 0x0F && hs.opcode2 >= 0x80 && hs.opcode2 <= 0x8F) ||
            (hs.opcode >= 0x70 && hs.opcode <= 0x7F))
        {
            LONG relOffset = (hs.opcode == 0x0F) ? (LONG)hs.imm.imm32 : (CHAR)hs.imm.imm8;
            ULONG64 targetAddr = (ULONG64)src + copiedBytes + hs.len + relOffset;
            UCHAR jcc8 = (hs.opcode == 0x0F) ? (0x70 + (hs.opcode2 & 0x0F)) : hs.opcode;

            UCHAR jccStub[] = {
                jcc8, 0x02,                         // Jcc +2
                0xEB, 0x0E,                         // JMP +14
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00  // JMP [RIP]
            };
            RtlCopyMemory(dst + dstOffset, jccStub, sizeof(jccStub));
            dstOffset += sizeof(jccStub);
            *(PULONG64)(dst + dstOffset) = targetAddr;
            dstOffset += 8;
        }
        // 4. RIP 相对数据寻址 (如获取全局变量)
        else if (hs.modrm_mod == 0 && hs.modrm_rm == 5)
        {
            LONG rel32 = (LONG)hs.disp.disp32;
            ULONG64 targetAddr = (ULONG64)src + copiedBytes + hs.len + rel32;

            UCHAR reg = (hs.modrm >> 3) & 7;
            UCHAR rex_r = (hs.rex_r) ? 1 : 0;
            UCHAR rex_w = (hs.rex_w) ? 1 : 0;

            if (hs.opcode == 0x8D) // LEA reg, [RIP+disp]
            {
                *(dst + dstOffset++) = 0x48 | rex_r;
                *(dst + dstOffset++) = 0xB8 | reg;
                *(PULONG64)(dst + dstOffset) = targetAddr;
                dstOffset += 8;
            }
            else if (hs.opcode == 0x8B) // MOV reg, [RIP+disp]
            {
                *(dst + dstOffset++) = 0x48 | rex_r;
                *(dst + dstOffset++) = 0xB8 | reg;
                *(PULONG64)(dst + dstOffset) = targetAddr;
                dstOffset += 8;

                UCHAR rex_byte2 = 0x40 | (rex_w << 3) | (rex_r << 2) | rex_r;
                if (rex_byte2 != 0x40) {
                    *(dst + dstOffset++) = rex_byte2;
                }
                *(dst + dstOffset++) = 0x8B;

                if (reg == 4) {
                    *(dst + dstOffset++) = 0x00 | (reg << 3) | 4;
                    *(dst + dstOffset++) = 0x24;
                }
                else if (reg == 5) {
                    *(dst + dstOffset++) = 0x40 | (reg << 3) | 5;
                    *(dst + dstOffset++) = 0x00;
                }
                else {
                    *(dst + dstOffset++) = 0x00 | (reg << 3) | reg;
                }
            }
            else {
                SvmDebugPrint("[ERR][BuildTrampoline] Unsupported RIP opcode: 0x%X at %p\n", hs.opcode, src + copiedBytes);
                return STATUS_UNSUCCESSFUL;
            }
        }
        // ================================================================
        // 5. 【NEW】MOV CRn, GPR  (opcode 0F 22 /r)
        //    VMware 嵌套 SVM 下直接执行 mov cr0, rax 会 #GP！
        //    替换为 VMMCALL 超级调用：
        //      push rax / push rcx / mov rcx, <srcGPR> /
        //      mov eax, 0x4141FExx / vmmcall / pop rcx / pop rax
        // ================================================================
        else if (hs.opcode == 0x0F && hs.opcode2 == 0x22)
        {
            UCHAR crNum = (hs.modrm >> 3) & 7;
            UCHAR srcGpr = hs.modrm & 7;
            if (hs.rex_b) srcGpr += 8;
            if (hs.rex_r) crNum += 8;

            SvmDebugPrint("[BuildTrampoline] Replacing MOV CR%d, GPR%d with VMMCALL at %p\n",
                crNum, srcGpr, src + copiedBytes);

            // push rax
            *(dst + dstOffset++) = 0x50;
            // push rcx
            *(dst + dstOffset++) = 0x51;

            // mov rcx, <srcGpr>
            if (srcGpr != 1) {
                UCHAR rexByte = 0x48;
                if (srcGpr >= 8) rexByte |= 0x04;
                *(dst + dstOffset++) = rexByte;
                *(dst + dstOffset++) = 0x89;
                *(dst + dstOffset++) = (UCHAR)(0xC0 | ((srcGpr & 7) << 3) | 1);
            }

            // mov eax, VMMCALL_CR_WRITE_BASE | crNum
            *(dst + dstOffset++) = 0xB8;
            *(PULONG)(dst + dstOffset) = VMMCALL_CR_WRITE_BASE | crNum;
            dstOffset += 4;

            // vmmcall (0F 01 D9)
            *(dst + dstOffset++) = 0x0F;
            *(dst + dstOffset++) = 0x01;
            *(dst + dstOffset++) = 0xD9;

            // pop rcx
            *(dst + dstOffset++) = 0x59;
            // pop rax
            *(dst + dstOffset++) = 0x58;
        }
        // 6. 普通指令，直接原样拷贝
        else
        {
            RtlCopyMemory(dst + dstOffset, src + copiedBytes, len);
            dstOffset += len;
        }
        copiedBytes += len;
    }

    // 跳床尾部：14 字节 JMP 跳回原函数剩余部分
    ULONG64 returnAddr = (ULONG64)src + copiedBytes;
    UCHAR jmpBackStub[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    *(PULONG64)(&jmpBackStub[6]) = returnAddr;

    RtlCopyMemory(dst + dstOffset, jmpBackStub, 14);
    dstOffset += 14;

    HookContext->TrampolineLength = dstOffset;
    HookContext->StolenBytesLength = copiedBytes;

    return STATUS_SUCCESS;
}


NTSTATUS HookPage(PNPT_HOOK_CONTEXT HookContext)
{
    const SIZE_T hookLen = 14;
    UINT64 originalFunc = (UINT64)HookContext->TargetAddress;
    UINT64 pageOffset = originalFunc & (PAGE_SIZE - 1);

    if (!HookContext->FakePage || !HookContext->TargetAddress || !HookContext->ProxyFunction) {
        SvmDebugPrint("[ERROR][HookPage] NULL parameter\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (pageOffset + hookLen > PAGE_SIZE) {
        SvmDebugPrint("[ERROR][HookPage] Cross-page not supported: %p\n", HookContext->TargetAddress);
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS status = BuildTrampoline(HookContext);
    if (!NT_SUCCESS(status)) {
        SvmDebugPrint("[ERROR][HookPage] BuildTrampoline failed\n");
        return status;
    }

    UCHAR AbsoluteJmpCode[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    *(PULONG64)(&AbsoluteJmpCode[6]) = (ULONG64)HookContext->ProxyFunction;

    PVOID hookTargetInFakePage = (PVOID)((UINT64)HookContext->FakePage + pageOffset);

    RtlCopyMemory(hookTargetInFakePage, AbsoluteJmpCode, hookLen);

    if (HookContext->StolenBytesLength > hookLen) {
        RtlFillMemory((PVOID)((UINT64)hookTargetInFakePage + hookLen),
            HookContext->StolenBytesLength - hookLen, 0x90);
    }

    // 【DEBUG】验证 FakePage 内容
    PUCHAR verify = (PUCHAR)hookTargetInFakePage;
    SvmDebugPrint("[HookPage] FakePage[0..5] at offset 0x%llX: %02X %02X %02X %02X %02X %02X -> Proxy=%p\n",
        pageOffset, verify[0], verify[1], verify[2], verify[3], verify[4], verify[5],
        HookContext->ProxyFunction);

    return STATUS_SUCCESS;
}


NTSTATUS PrepareNptHookResources(PVOID TargetAddress, PVOID ProxyFunction, PNPT_HOOK_CONTEXT HookContext)
{
    if (!TargetAddress || !ProxyFunction || !HookContext) return STATUS_INVALID_PARAMETER;

    EnsureHookCleanupLockInitialized();
    InterlockedExchange(&g_HookCleanupDone, 0);

    RtlZeroMemory(HookContext, sizeof(NPT_HOOK_CONTEXT));
    HookContext->IsUsed = TRUE;
    HookContext->TargetAddress = TargetAddress;
    HookContext->ProxyFunction = ProxyFunction;
    HookContext->OriginalPageBase = (PVOID)((UINT64)TargetAddress & ~(PAGE_SIZE - 1));
    HookContext->OriginalPagePa = MmGetPhysicalAddress(HookContext->OriginalPageBase).QuadPart;

    // 检查同物理页共享复用
    PNPT_HOOK_CONTEXT SharedHook = nullptr;
    for (int i = 0; i < HOOK_MAX_COUNT; i++) {
        if (&g_HookList[i] != HookContext && g_HookList[i].IsUsed && g_HookList[i].FakePage != nullptr &&
            g_HookList[i].OriginalPagePa == HookContext->OriginalPagePa) {
            SharedHook = &g_HookList[i];
            break;
        }
    }

    if (SharedHook) {
        HookContext->FakePage = SharedHook->FakePage;
        HookContext->FakePagePa = SharedHook->FakePagePa;
        SvmDebugPrint("[Phase1] Page reuse: %p (shared with %p)\n", TargetAddress, SharedHook->TargetAddress);
    }
    else {
        NTSTATUS status = BuildPage(HookContext);
        if (!NT_SUCCESS(status)) {
            ResetSingleHookState(HookContext);
            HookContext->IsUsed = FALSE;
            return status;
        }
        HookContext->FakePagePa = MmGetPhysicalAddress(HookContext->FakePage).QuadPart;
    }

    // 跳板页独立分配
    PHYSICAL_ADDRESS HighAddr;
    HighAddr.QuadPart = ~0ULL;
    HookContext->TrampolinePage = MmAllocateContiguousMemory(PAGE_SIZE, HighAddr);
    if (!HookContext->TrampolinePage) {
        ResetSingleHookState(HookContext);
        HookContext->IsUsed = FALSE;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(HookContext->TrampolinePage, PAGE_SIZE);

    NTSTATUS status = HookPage(HookContext);
    if (!NT_SUCCESS(status)) {
        ResetSingleHookState(HookContext);
        HookContext->IsUsed = FALSE;
        return status;
    }

    HookContext->ResourcesReady = TRUE;
    SvmDebugPrint("[Phase1] Hook ready: %p (FakePa=0x%llX, OrigPa=0x%llX)\n",
        TargetAddress, HookContext->FakePagePa, HookContext->OriginalPagePa);
    return STATUS_SUCCESS;
}


VOID FreeNptHook(PNPT_HOOK_CONTEXT HookContext)
{
    if (HookContext == nullptr) return;

    ResetSingleHookState(HookContext);
    RtlZeroMemory(HookContext, sizeof(NPT_HOOK_CONTEXT));
    SvmDebugPrint("[INFO] NPT Hook resources freed.\n");
}