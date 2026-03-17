// Disable C4819 (codepage 936 encoding warning) BEFORE any other content
#pragma warning(disable: 4819)

/**
 * @file Hook.cpp
 * @brief NPT Hook框架 - 影子页构建、Trampoline生成、Hook激活与清理
 * @author yewilliam
 * @date 2026/03/16
 *
 * 基于NPT的透明函数Hook实现:
 *   Phase1: 分配FakePage(影子页) + TrampolinePage(跳板页)
 *   Phase2: 修改NPT PTE(PFN替换 + NX权限设置)
 *   Phase3: IPI广播TLB刷新, 所有核心同步激活
 *
 * Trampoline支持7种指令重定位:
 *   1. CALL rel32 → 间接调用
 *   2. JMP rel32/rel8 → 绝对跳转
 *   3. Jcc条件跳转 → 短跳+绝对跳转
 *   4a. RIP相对LEA → MOV reg, imm64
 *   4b. RIP相对MOV load → MOV reg, imm64 + MOV reg, [reg]
 *   4c. RIP相对通用指令 → 使用R11/R10作为暂存寄存器
 *   5. MOV CRn, GPR → VMMCALL(写CR)
 *   6. MOV GPR, CRn → VMMCALL(读CR)
 *   7. 普通指令 → 原始拷贝
 */
#include "Hook.h"
#include "SVM.h"
#include "NPT.h"
#include "hde/hde64.h"

NPT_HOOK_CONTEXT g_HookList[HOOK_MAX_COUNT] = { 0 };

static volatile LONG g_HookCleanupDone = 0;
static KSPIN_LOCK g_HookCleanupLock;
static BOOLEAN g_HookCleanupLockInitialized = FALSE;
/**
 * @brief 确保Hook清理自旋锁已初始化 - 延迟初始化模式
 * @author yewilliam
 * @date 2026/03/16
 */

static VOID EnsureHookCleanupLockInitialized()
{
    if (!g_HookCleanupLockInitialized) {
        KeInitializeSpinLock(&g_HookCleanupLock);
        g_HookCleanupLockInitialized = TRUE;
    }
}
/**
 * @brief 从内核模块链表中摘除驱动 - DKOM隐藏驱动
 * @author yewilliam
 * @date 2026/03/16
 * @param [in,out] DriverObject - 要隐藏的驱动对象
 * @return STATUS_SUCCESS, STATUS_INVALID_PARAMETER
 * @note 断开InLoadOrderLinks双向链表, 清零DriverInit/DriverName等字段
 */

NTSTATUS HideDriver(PDRIVER_OBJECT DriverObject)
{
    if (!DriverObject || !DriverObject->DriverSection) return STATUS_INVALID_PARAMETER;

    PKLDR_DATA_TABLE_ENTRY pLdrEntry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

    if (pLdrEntry->InLoadOrderLinks.Flink && pLdrEntry->InLoadOrderLinks.Blink) {
        PLIST_ENTRY Prev = pLdrEntry->InLoadOrderLinks.Blink;
        PLIST_ENTRY Next = pLdrEntry->InLoadOrderLinks.Flink;
        Prev->Flink = Next;
        Next->Blink = Prev;
        pLdrEntry->InLoadOrderLinks.Flink = &pLdrEntry->InLoadOrderLinks;
        pLdrEntry->InLoadOrderLinks.Blink = &pLdrEntry->InLoadOrderLinks;
    }

    DriverObject->DriverInit = NULL;
    DriverObject->DriverStartIo = NULL;
    DriverObject->DriverUnload = NULL;
    DriverObject->DriverSize = 0;

    if (DriverObject->DriverName.Buffer) {
        RtlZeroMemory(DriverObject->DriverName.Buffer, DriverObject->DriverName.MaximumLength);
        DriverObject->DriverName.Length = 0;
    }

    SvmDebugPrint("[INFO] Driver successfully unlinked and hidden.\n");
    return STATUS_SUCCESS;
}
/**
 * @brief 获取SSDT中Nt函数的真实内核地址 - 通过Zw桩函数提取索引再查SSDT
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] ZwName - Zw函数名称(如L"ZwQuerySystemInformation")
 * @return Nt函数的内核虚拟地址, 失败返回nullptr
 * @note 从KiSystemCall64定位SSDT基址, 通过MOV EAX,imm32提取系统调用号
 */

PVOID GetRealNtAddress(PCWSTR ZwName)
{
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
        PUCHAR KiSystemCall64 = (PUCHAR)__readmsr(MSR_LSTAR);
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
/**
 * @brief 重置单个Hook的状态并释放资源 - FakePage(检查共享)/TrampolinePage
 * @author yewilliam
 * @date 2026/03/16
 * @param [in,out] HookContext - Hook上下文
 * @note FakePage可能被同物理页的多个Hook共享, 仅最后一个引用者释放
 */

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
/**
 * @brief 注册NPT Hook - 在全局Hook表中分配槽位并记录目标/代理地址
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] TargetAddress - Hook目标函数地址
 * @param [in] ProxyFunction - 替代函数(Fake函数)地址
 * @return STATUS_SUCCESS, STATUS_INVALID_PARAMETER, STATUS_INSUFFICIENT_RESOURCES(表满)
 */

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
/**
 * @brief 批量准备所有已注册Hook的资源 - 分配FakePage/TrampolinePage并构建跳板
 * @author yewilliam
 * @date 2026/03/16
 * @return STATUS_SUCCESS或第一个失败的状态码
 */

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
/**
 * @brief 在指定VCPU上激活所有已就绪的Hook - 修改NPT PTE实现页面替换
 * @author yewilliam
 * @date 2026/03/16
 * @param [in,out] vpData - VCPU上下文
 * @return STATUS_SUCCESS(即使部分Hook失败也继续激活其余Hook)
 * @note 跳过OriginalPagePa=0或TargetPa=0的无效Hook, 避免中断后续激活
 */

NTSTATUS ActivateAllNptHooks(PVCPU_CONTEXT vpData)
{
    if (vpData == nullptr) return STATUS_INVALID_PARAMETER;

    ULONG okCount = 0, failCount = 0;
    for (int i = 0; i < HOOK_MAX_COUNT; ++i)
    {
        if (!g_HookList[i].IsUsed || !g_HookList[i].ResourcesReady)
            continue;

        if (g_HookList[i].OriginalPagePa == 0 || g_HookList[i].TargetPa == 0) {
            SvmDebugPrint("[WARN] Skipping hook slot %d: OrigPa=0x%llX, TargetPa=0x%llX\n",
                i, g_HookList[i].OriginalPagePa, g_HookList[i].TargetPa);
            failCount++;
            continue;
        }

        NTSTATUS status = ActivateNptHookInNpt(vpData, &g_HookList[i]);
        if (!NT_SUCCESS(status)) {
            SvmDebugPrint("[WARN] ActivateNptHookInNpt failed for slot %d: 0x%X (continue)\n",
                i, status);
            failCount++;
        }
        else {
            okCount++;
        }
    }

    if (failCount > 0) {
        SvmDebugPrint("[WARN] ActivateAllNptHooks: %lu ok, %lu failed\n", okCount, failCount);
    }
    return STATUS_SUCCESS;
}
/**
 * @brief 清理所有NPT Hook资源 - 释放FakePage, 保留TrampolinePage防止执行中崩溃
 * @author yewilliam
 * @date 2026/03/16
 * @note TrampolinePage故意不释放: SVM退出后仍有线程可能在执行trampoline代码,
 *       由ReleaseDriverResources在drain等待后统一释放
 */

VOID CleanupAllNptHooks()
{
    EnsureHookCleanupLockInitialized();

    if (InterlockedCompareExchange(&g_HookCleanupDone, 1, 0) == 1) return;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_HookCleanupLock, &oldIrql);

    for (int i = 0; i < HOOK_MAX_COUNT; ++i)
    {
        if (!g_HookList[i].IsUsed && !g_HookList[i].ResourcesReady) continue;

        /* FakePage 可以安全释放 — SVM 退出后 NPT 不再引用它 */
        if (g_HookList[i].FakePage != nullptr) {
            BOOLEAN shared = FALSE;
            for (int j = 0; j < HOOK_MAX_COUNT; j++) {
                if (j != i && g_HookList[j].IsUsed &&
                    g_HookList[j].FakePage == g_HookList[i].FakePage) {
                    shared = TRUE;
                    break;
                }
            }
            if (!shared) MmFreeContiguousMemory(g_HookList[i].FakePage);
            g_HookList[i].FakePage = nullptr;
        }

         /* g_HookList[i].TrampolinePage 故意不释放 */

        g_HookList[i].IsUsed = FALSE;
        g_HookList[i].ResourcesReady = FALSE;
    }

    KeReleaseSpinLock(&g_HookCleanupLock, oldIrql);
    SvmDebugPrint("[INFO] All NPT hook resources cleaned up (trampolines kept alive).\n");
}
/**
 * @brief 根据NPF故障物理地址查找对应的Hook上下文
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] FaultPa - NPF故障的物理地址(ExitInfo2)
 * @return 匹配的Hook上下文指针, 未找到返回nullptr
 * @note 匹配OriginalPagePa或TargetPa的页对齐地址
 */

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
/**
 * @brief 构建影子页(FakePage) - 分配物理连续页并拷贝原始页内容
 * @author yewilliam
 * @date 2026/03/16
 * @param [in,out] HookContext - Hook上下文(OriginalPageBase必须已设置)
 * @return STATUS_SUCCESS, STATUS_INVALID_PARAMETER, STATUS_INSUFFICIENT_RESOURCES
 */

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

/**
 * @brief 构建跳板代码 - 重定位被覆盖的指令并在末尾跳回原函数
 * @author yewilliam
 * @date 2026/03/16
 * @param [in,out] HookContext - Hook上下文(TrampolinePage必须已分配)
 * @return STATUS_SUCCESS, STATUS_INVALID_PARAMETER, STATUS_UNSUCCESSFUL
 *
 * 支持7种指令重定位类型:
 *   1. CALL rel32 → FF 15间接调用
 *   2. JMP rel32/rel8 → FF 25绝对跳转
 *   3. Jcc条件跳转 → 短Jcc + 绝对跳转
 *   4a. RIP相对LEA → MOV reg, imm64(直接加载目标地址)
 *   4b. RIP相对MOV load → MOV reg, imm64 + MOV reg, [reg]
 *   4c. RIP相对通用指令 → push scratch + movabs scratch + 重编码指令 + pop scratch
 *   5. MOV CRn, GPR → VMMCALL(写CR, 由VMM模拟)
 *   6. MOV GPR, CRn → VMMCALL(读CR, 由VMM模拟)
 *   7. 普通指令 → 原始字节拷贝
 *
 * 末尾追加14字节绝对JMP回到原函数未被覆盖的部分
 */
NTSTATUS BuildTrampoline(PNPT_HOOK_CONTEXT HookContext)
{
    // 参数检查
    if (!HookContext || !HookContext->TargetAddress || !HookContext->TrampolinePage) {
        return STATUS_INVALID_PARAMETER;
    }

    PUCHAR src = (PUCHAR)HookContext->TargetAddress;   // 源地址：被Hook的目标函数起始处
    PUCHAR dst = (PUCHAR)HookContext->TrampolinePage;  // 目标地址：跳板页（存放重定位后的指令）
    ULONG copiedBytes = 0;       // 已从源地址复制的字节数（累计的指令长度）
    ULONG dstOffset = 0;         // 跳板内的当前写入偏移
    hde64s hs;                   // HDE64反汇编引擎输出的指令信息结构

    // 最少需要复制14个字节，因为后面要附加一个14字节的绝对跳转指令
    while (copiedBytes < 14)
    {
        // 反汇编当前指令，获取指令长度和详细信息
        ULONG len = hde64_disasm(src + copiedBytes, &hs);
        if (hs.flags & F_ERROR) {
            SvmDebugPrint("[ERR][BuildTrampoline] Disassembly error at %p (offset %u)\n",
                src + copiedBytes, copiedBytes);
            return STATUS_UNSUCCESSFUL;
        }

        /* 安全检查：确保跳板页不会溢出（每条指令最多预留40字节空间） */
        if (dstOffset + 40 > PAGE_SIZE) {
            SvmDebugPrint("[ERR][BuildTrampoline] Trampoline overflow at %p\n", src + copiedBytes);
            return STATUS_UNSUCCESSFUL;
        }

        // 1. 处理 CALL rel32 指令（操作码0xE8）
        if (hs.opcode == 0xE8)
        {
            LONG rel32 = (LONG)hs.imm.imm32;                     // 获取相对偏移
            ULONG64 targetAddr = (ULONG64)src + copiedBytes + hs.len + rel32; // 计算实际目标地址

            // 构建间接调用 stub：FF 15 [RIP+2] （即 call qword ptr [rip+2]）
            UCHAR callStub[] = { 0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08 };
            RtlCopyMemory(dst + dstOffset, callStub, sizeof(callStub));
            dstOffset += sizeof(callStub);
            // 在 stub 后放置目标地址（64位），供间接调用使用
            *(PULONG64)(dst + dstOffset) = targetAddr;
            dstOffset += 8;
        }
        // 2. 处理 JMP rel32 (0xE9) 和 JMP rel8 (0xEB)
        else if (hs.opcode == 0xE9 || hs.opcode == 0xEB)
        {
            LONG relOffset = (hs.opcode == 0xE9) ? (LONG)hs.imm.imm32 : (CHAR)hs.imm.imm8; // 相对偏移
            ULONG64 targetAddr = (ULONG64)src + copiedBytes + hs.len + relOffset;

            // 构建绝对跳转 stub：FF 25 [RIP+0] 后跟8字节目标地址
            UCHAR jmpStub[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            *(PULONG64)(&jmpStub[6]) = targetAddr;  // 从偏移6开始存放目标地址
            RtlCopyMemory(dst + dstOffset, jmpStub, 14);
            dstOffset += 14;
        }
        // 3. 处理条件跳转 Jcc（包括两字节0F 80-8F和单字节70-7F）
        else if ((hs.opcode == 0x0F && hs.opcode2 >= 0x80 && hs.opcode2 <= 0x8F) ||
            (hs.opcode >= 0x70 && hs.opcode <= 0x7F))
        {
            LONG relOffset = (hs.opcode == 0x0F) ? (LONG)hs.imm.imm32 : (CHAR)hs.imm.imm8; // 相对偏移
            ULONG64 targetAddr = (ULONG64)src + copiedBytes + hs.len + relOffset;

            // 获取条件跳转的条件码（对于两字节Jcc，条件码在opcode2的低4位）
            UCHAR jcc8 = (hs.opcode == 0x0F) ? (0x70 + (hs.opcode2 & 0x0F)) : hs.opcode;

            // 构建条件跳转 stub：
            // 先执行条件跳转，如果条件满足则跳过后续的绝对跳转直接跳转；否则顺序执行到绝对跳转
            UCHAR jccStub[] = {
                jcc8, 0x02,                 // 条件跳转，向前跳2字节（跳过EB 0E）
                0xEB, 0x0E,                  // 无条件跳转，向后跳14字节（跳到绝对跳转之后）
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00  // 绝对跳转占位
            };
            RtlCopyMemory(dst + dstOffset, jccStub, sizeof(jccStub));
            dstOffset += sizeof(jccStub);
            // 在 stub 后放置绝对跳转的目标地址
            *(PULONG64)(dst + dstOffset) = targetAddr;
            dstOffset += 8;
        }
        // 4. 处理 RIP-相对寻址的指令（ModRM.mod = 0, ModRM.rm = 5 表示 [rip+disp32]）
        else if (hs.modrm_mod == 0 && hs.modrm_rm == 5)
        {
            LONG rel32 = (LONG)hs.disp.disp32;                  // 获取相对偏移
            ULONG64 targetAddr = (ULONG64)src + copiedBytes + hs.len + rel32; // 实际有效地址

            UCHAR reg = (hs.modrm >> 3) & 7;   // ModRM.reg 字段（寄存器编号）
            UCHAR rex_r = (hs.rex_r) ? 1 : 0;  // REX.R 位
            UCHAR rex_w = (hs.rex_w) ? 1 : 0;  // REX.W 位（64位操作数）

            // 4a. 如果是 LEA reg, [RIP+disp] (操作码0x8D)
            if (hs.opcode == 0x8D) // LEA reg, [RIP+disp]
            {
                // 转换为 MOV reg, imm64 (直接加载有效地址)
                *(dst + dstOffset++) = 0x48 | rex_r;        // REX.W + REX.R（如果有）
                *(dst + dstOffset++) = 0xB8 | reg;          // MOV reg, imm64
                *(PULONG64)(dst + dstOffset) = targetAddr;  // 存放64位立即数
                dstOffset += 8;
            }
            // 4b. 如果是 MOV reg, [RIP+disp] (操作码0x8B)
            else if (hs.opcode == 0x8B) // MOV reg, [RIP+disp] (load)
            {
                // 先加载有效地址到同一寄存器：MOV reg, imm64
                *(dst + dstOffset++) = 0x48 | rex_r;
                *(dst + dstOffset++) = 0xB8 | reg;
                *(PULONG64)(dst + dstOffset) = targetAddr;
                dstOffset += 8;

                // 然后从该寄存器间接取数：MOV reg, [reg]
                // 构造 REX 前缀（如果需要）
                UCHAR rex_byte2 = 0x40 | (rex_w << 3) | (rex_r << 2) | rex_r;
                if (rex_byte2 != 0x40) {  // 不是默认值时才写入
                    *(dst + dstOffset++) = rex_byte2;
                }
                *(dst + dstOffset++) = 0x8B;  // MOV 操作码

                // 根据目标寄存器构造 ModRM 字节，实现 [reg] 寻址
                if (reg == 4) { // 如果 reg 是 RSP/ R12，需要 SIB 字节
                    *(dst + dstOffset++) = 0x00 | (reg << 3) | 4; // ModRM: mod=00, reg=reg, rm=4 (表示后面有SIB)
                    *(dst + dstOffset++) = 0x24;                   // SIB: scale=0, index=4 (无index), base=4 (RSP)
                }
                else if (reg == 5) { // 如果 reg 是 RBP/ R13，需要 disp8=0 (虽然 ModRM.mod=00, rm=5 理论上表示 [RIP+disp32]，但我们这里用 [RBP] 需要 disp8=0)
                    *(dst + dstOffset++) = 0x40 | (reg << 3) | 5; // ModRM: mod=01, reg=reg, rm=5 (表示 [RBP+disp8])
                    *(dst + dstOffset++) = 0x00;                   // disp8 = 0
                }
                else {
                    // 一般情况：ModRM: mod=00, reg=reg, rm=reg (即 [reg])
                    *(dst + dstOffset++) = 0x00 | (reg << 3) | reg;
                }
            }
            /*
             * 4c. 其他任意 RIP-相对指令的通用处理方法：
             *     使用 scratch 寄存器（优先选择 R10 或 R11）来暂存有效地址，
             *     然后修改原指令的 ModRM 将 [RIP+disp] 改为 [scratch]，
             *     最后恢复 scratch。
             */
            else
            {
                // 选择 scratch 寄存器：如果原目标寄存器是 R11 且 REX.R=1，则使用 R10，否则用 R11
                BOOLEAN useR10 = (reg == 3 && rex_r == 1);
                UCHAR scratchRegBits = useR10 ? 2 : 3; // R10=2, R11=3 (对应ModRM.rm字段的值)

                SvmDebugPrint("[BuildTrampoline] Generic RIP-rel: opcode=0x%02X at %p, scratch=R%d\n",
                    hs.opcode, src + copiedBytes, useR10 ? 10 : 11);

                /* push scratch (R10: 41 52, R11: 41 53) */
                *(dst + dstOffset++) = 0x41;               // REX.B 前缀
                *(dst + dstOffset++) = 0x50 | scratchRegBits; // PUSH r10/r11

                /* mov scratch, imm64 (movabs): 49 BA/BB <8 bytes> */
                *(dst + dstOffset++) = 0x49;               // REX.W + REX.B
                *(dst + dstOffset++) = 0xB8 | scratchRegBits; // MOV r64, imm64
                *(PULONG64)(dst + dstOffset) = targetAddr; // 存放有效地址
                dstOffset += 8;

                /*
                 * 重新生成原指令，但将其中的 [RIP+disp] 替换为 [scratch]
                 */
                PUCHAR origInstr = src + copiedBytes;
                ULONG newPos = 0;

                /* 复制原有前缀（忽略原有的 REX，我们后面会添加新的REX） */
                for (int p = 0; p < 5 && newPos < len; p++) {
                    UCHAR b = origInstr[newPos];
                    // 判断是否为常见前缀（如锁定、重复、段前缀、操作数大小等）
                    if (b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x66 ||
                        b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
                        b == 0x64 || b == 0x65 || b == 0x67) {
                        *(dst + dstOffset++) = b;
                        newPos++;
                    }
                    else break;
                }

                /* 新 REX：保留原 W 和 R 位，X=0, B=1 (因为使用 scratch，B 置1表示扩展寄存器) */
                UCHAR newRex = 0x41 | (rex_w << 3) | (rex_r << 2);
                *(dst + dstOffset++) = newRex;

                /* 跳过原指令中的 REX 前缀（如果存在） */
                if (newPos < len && (origInstr[newPos] & 0xF0) == 0x40)
                    newPos++;

                /* 复制操作码（可能是单字节或两字节，如0F开头的） */
                if (origInstr[newPos] == 0x0F) {
                    *(dst + dstOffset++) = origInstr[newPos++];
                    if (newPos < len)
                        *(dst + dstOffset++) = origInstr[newPos++];
                }
                else {
                    *(dst + dstOffset++) = origInstr[newPos++];
                }

                /* 新 ModRM：mod=00（寄存器间接寻址），reg 字段不变，rm 字段改为 scratch 的编号 */
                UCHAR newModrm = (0x00) | (hs.modrm & 0x38) | scratchRegBits;
                *(dst + dstOffset++) = newModrm;
                newPos++; /* 跳过原 ModRM */
                newPos += 4; /* 跳过原 disp32 */

                /* 复制剩余的字节（如立即数等） */
                while (newPos < len) {
                    *(dst + dstOffset++) = origInstr[newPos++];
                }

                /* pop scratch (R10: 41 5A, R11: 41 5B) */
                *(dst + dstOffset++) = 0x41;
                *(dst + dstOffset++) = 0x58 | scratchRegBits;
            }
        }
        // 5. 处理 MOV CRn, GPR（写控制寄存器），操作码 0F 22，使用 VMMCALL 让虚拟机监控器模拟
        else if (hs.opcode == 0x0F && hs.opcode2 == 0x22)
        {
            UCHAR crNum = (hs.modrm >> 3) & 7;   // 控制寄存器编号 (低3位)
            UCHAR srcGpr = hs.modrm & 7;          // 源通用寄存器编号
            if (hs.rex_b) srcGpr += 8;             // REX.B 扩展寄存器
            if (hs.rex_r) crNum += 8;               // REX.R 扩展控制寄存器编号（如 CR8 等）

            SvmDebugPrint("[BuildTrampoline] Replacing MOV CR%d, GPR%d with VMMCALL at %p\n",
                crNum, srcGpr, src + copiedBytes);

            // 保存现场：push rax; push rcx
            *(dst + dstOffset++) = 0x50;   // push rax
            *(dst + dstOffset++) = 0x51;   // push rcx

            // 如果源寄存器不是 rcx，则 mov rcx, srcGpr
            if (srcGpr != 1) {
                UCHAR rexByte = 0x48;       // REX.W
                if (srcGpr >= 8) rexByte |= 0x04; // REX.B 置1
                *(dst + dstOffset++) = rexByte;
                *(dst + dstOffset++) = 0x89; // MOV r/m64, r64
                // ModRM: mod=11, reg=srcGpr低3位, rm=1 (rcx)
                *(dst + dstOffset++) = (UCHAR)(0xC0 | ((srcGpr & 7) << 3) | 1);
            }

            // 将 VMCALL 参数（写CR操作码）放入 eax
            *(dst + dstOffset++) = 0xB8;   // mov eax, imm32
            *(PULONG)(dst + dstOffset) = VMMCALL_CR_WRITE_BASE | crNum;
            dstOffset += 4;

            // 执行 VMMCALL 指令 (0F 01 D9)
            *(dst + dstOffset++) = 0x0F;
            *(dst + dstOffset++) = 0x01;
            *(dst + dstOffset++) = 0xD9;

            // 恢复现场：pop rcx; pop rax
            *(dst + dstOffset++) = 0x59;   // pop rcx
            *(dst + dstOffset++) = 0x58;   // pop rax
        }
        // 6. 处理 MOV GPR, CRn（读控制寄存器），操作码 0F 20，同样用 VMMCALL
        else if (hs.opcode == 0x0F && hs.opcode2 == 0x20)
        {
            UCHAR crNum = (hs.modrm >> 3) & 7;   // 控制寄存器编号
            UCHAR dstGpr = hs.modrm & 7;          // 目标通用寄存器
            if (hs.rex_b) dstGpr += 8;
            if (hs.rex_r) crNum += 8;

            // 保存现场：push rax; push rcx
            *(dst + dstOffset++) = 0x50;
            *(dst + dstOffset++) = 0x51;

            // 将 VMCALL 参数（读CR操作码）放入 eax
            *(dst + dstOffset++) = 0xB8;
            *(PULONG)(dst + dstOffset) = VMMCALL_CR_READ_BASE | crNum;
            dstOffset += 4;

            // 执行 VMMCALL
            *(dst + dstOffset++) = 0x0F;
            *(dst + dstOffset++) = 0x01;
            *(dst + dstOffset++) = 0xD9;

            // 将结果（rax）移动到目标寄存器（如果目标不是 rcx 的话）
            if (dstGpr != 1) {
                UCHAR rexByte = 0x48;
                if (dstGpr >= 8) rexByte |= 0x01; // REX.B 置1
                *(dst + dstOffset++) = rexByte;
                *(dst + dstOffset++) = 0x89;       // MOV r/m64, r64
                // ModRM: mod=11, reg=1 (rcx), rm=dstGpr低3位
                *(dst + dstOffset++) = (UCHAR)(0xC0 | (1 << 3) | (dstGpr & 7));
            }

            // 恢复现场：pop rcx; pop rax
            *(dst + dstOffset++) = 0x59;
            *(dst + dstOffset++) = 0x58;
        }
        // 7. 其他普通指令：直接复制原始字节
        else
        {
            RtlCopyMemory(dst + dstOffset, src + copiedBytes, len);
            dstOffset += len;
        }
        copiedBytes += len;  // 累计已处理的指令长度
    }

    /* 在跳板末尾添加一个14字节的绝对跳转指令，跳回原函数剩余部分（即被复制指令之后的位置） */
    {
        ULONG64 retAddr = (ULONG64)src + copiedBytes;  // 原函数中紧接被复制指令之后的地址
        UCHAR jmpBackStub[14] = {
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,         // jmp qword ptr [rip+0]
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // 存放64位目标地址
        };
        *(PULONG64)(&jmpBackStub[6]) = retAddr;  // 从偏移6开始存放地址
        RtlCopyMemory(dst + dstOffset, jmpBackStub, 14);
        dstOffset += 14;
    }

    // 记录跳板的总长度和被覆盖的指令总长度
    HookContext->TrampolineLength = dstOffset;
    HookContext->StolenBytesLength = copiedBytes;

    return STATUS_SUCCESS;
}
/**
 * @brief 在FakePage中写入Hook跳转指令 - 14字节FF25绝对JMP到ProxyFunction
 * @author yewilliam
 * @date 2026/03/16
 * @param [in,out] HookContext - Hook上下文
 * @return STATUS_SUCCESS, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED(跨页)
 * @note 先调用BuildTrampoline构建跳板, 再在FakePage的目标偏移处写入JMP
 */

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
        SvmDebugPrint("[ERROR][HookPage] BuildTrampoline failed for %p\n", HookContext->TargetAddress);
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

    PUCHAR verify = (PUCHAR)hookTargetInFakePage;
    SvmDebugPrint("[HookPage] FakePage[0..5] at offset 0x%llX: %02X %02X %02X %02X %02X %02X -> Proxy=%p\n",
        pageOffset, verify[0], verify[1], verify[2], verify[3], verify[4], verify[5],
        HookContext->ProxyFunction);

    return STATUS_SUCCESS;
}
/**
 * @brief 为单个Hook准备全部资源 - FakePage+TrampolinePage+跳转代码
 * @author yewilliam
 * @date 2026/03/16
 * @param [in]     TargetAddress  - Hook目标函数地址
 * @param [in]     ProxyFunction  - 替代函数地址
 * @param [in,out] HookContext    - Hook上下文(输出完整的Hook信息)
 * @return STATUS_SUCCESS或错误码
 * @note 同物理页的多个Hook共享FakePage, 各自拥有独立TrampolinePage，中断等级低
 */

NTSTATUS PrepareNptHookResources(PVOID TargetAddress, PVOID ProxyFunction, PNPT_HOOK_CONTEXT HookContext)
{
    if (!TargetAddress || !ProxyFunction || !HookContext) return STATUS_INVALID_PARAMETER;
    //初始化自旋锁
    EnsureHookCleanupLockInitialized();
    //原子操作，将0写入到g_HookCleanupDone
    InterlockedExchange(&g_HookCleanupDone, 0);
    //清空HookContext结构
    RtlZeroMemory(HookContext, sizeof(NPT_HOOK_CONTEXT));
    //给HookContext赋值
    HookContext->IsUsed = TRUE;
    HookContext->TargetAddress = TargetAddress;
    HookContext->ProxyFunction = ProxyFunction;
    HookContext->OriginalPageBase = (PVOID)((UINT64)TargetAddress & ~(PAGE_SIZE - 1));
    HookContext->OriginalPagePa = MmGetPhysicalAddress(HookContext->OriginalPageBase).QuadPart;

    if (HookContext->OriginalPagePa == 0) {
        SvmDebugPrint("[WARN] OriginalPagePa=0 for %p, skipping\n", TargetAddress);
        RtlZeroMemory(HookContext, sizeof(NPT_HOOK_CONTEXT));
        return STATUS_UNSUCCESSFUL;
    }

    // 检查有没有重复的hook页上下文
    PNPT_HOOK_CONTEXT pSharedHook = nullptr;
    for (int i = 0; i < HOOK_MAX_COUNT; i++) {
        if (&g_HookList[i] != HookContext && g_HookList[i].IsUsed && g_HookList[i].FakePage != nullptr &&
            g_HookList[i].OriginalPagePa == HookContext->OriginalPagePa) {
            pSharedHook = &g_HookList[i];
            break;
        }
    }

    //如果重复的那么就拿已经创建过的hook页表来用
    //如果没有那就创建新的页表
    if (pSharedHook) {
        HookContext->FakePage = pSharedHook->FakePage;
        HookContext->FakePagePa = pSharedHook->FakePagePa;
        SvmDebugPrint("[Phase1] Page reuse: %p (shared with %p)\n", TargetAddress, pSharedHook->TargetAddress);
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

    // 创建蹦床页表
    PHYSICAL_ADDRESS highAddr;
    highAddr.QuadPart = ~0ULL;
    HookContext->TrampolinePage = MmAllocateContiguousMemory(PAGE_SIZE, highAddr);
    if (!HookContext->TrampolinePage) {
        ResetSingleHookState(HookContext);
        HookContext->IsUsed = FALSE;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(HookContext->TrampolinePage, PAGE_SIZE);

    //在fake页上写上跳转逻辑
    NTSTATUS status = HookPage(HookContext);
    if (!NT_SUCCESS(status)) {
        ResetSingleHookState(HookContext);
        HookContext->IsUsed = FALSE;
        return status;
    }

    HookContext->ResourcesReady = TRUE;
    SvmDebugPrint("[Phase1] Hook ready: %p (FakePa=0x%llX, OrigPa=0x%llX, Stolen=%u)\n",
        TargetAddress, HookContext->FakePagePa, HookContext->OriginalPagePa,
        HookContext->StolenBytesLength);
    return STATUS_SUCCESS;
}
/**
 * @brief 释放单个NPT Hook的所有资源
 * @author yewilliam
 * @date 2026/03/16
 * @param [in,out] HookContext - Hook上下文
 */

VOID FreeNptHook(PNPT_HOOK_CONTEXT HookContext)
{
    if (HookContext == nullptr) return;

    ResetSingleHookState(HookContext);
    RtlZeroMemory(HookContext, sizeof(NPT_HOOK_CONTEXT));
    SvmDebugPrint("[INFO] NPT Hook resources freed.\n");
}