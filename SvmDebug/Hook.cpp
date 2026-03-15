// Disable C4819 (codepage 936 encoding warning) BEFORE any other content
#pragma warning(disable: 4819)

/**
 * @file Hook.cpp
 * @brief NPT Hook Framework - Shadow page, Trampoline, Hook activation & cleanup
 * @author yewilliam
 * @date 2026/02/06
 *
 * NPT-based transparent function hook:
 * Phase1: Allocate FakePage + TrampolinePage
 * Phase2: Modify NPT PTE (PFN swap + NX permission)
 * Phase3: IPI broadcast TLB flush
 *
 * [BUGFIX 2026/03/15] BuildTrampoline: Added generic RIP-relative handler.
 *   Old code only handled LEA(0x8D) and MOV-load(0x8B) for RIP-relative,
 *   returning STATUS_UNSUCCESSFUL for any other opcode. On physical machines
 *   with different kernel binary layouts, this caused critical hooks to fail
 *   or worse: if HDE didn't flag RIP-relative properly, the instruction was
 *   copied verbatim to the trampoline at a different VA, causing wrong
 *   RIP displacement -> garbage read -> illegal instruction BSOD.
 */

#include "Hook.h"
#include "SVM.h"
#include "NPT.h"
#include "hde/hde64.h"

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
 * @brief Build trampoline code - relocate overwritten instructions and jump back
 *
 * [BUGFIX 2026/03/15] Added generic RIP-relative instruction handler (case 4c).
 *
 * Handles 7 instruction types:
 *   1. CALL rel32
 *   2. JMP rel32/rel8
 *   3. Jcc (conditional jumps)
 *   4a. RIP-relative: LEA (0x8D) -> MOV reg, imm64
 *   4b. RIP-relative: MOV load (0x8B) -> MOV reg, imm64 + MOV reg, [reg]
 *   4c. [NEW] RIP-relative: generic handler using R11/R10 as scratch
 *   5. MOV CRn, GPR -> VMMCALL (write CR)
 *   6. MOV GPR, CRn -> VMMCALL (read CR)
 *   7. Normal instructions -> raw copy
 */
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

    /* Copy at least 14 bytes for the 14-byte absolute JMP at original site */
    while (copiedBytes < 14)
    {
        ULONG len = hde64_disasm(src + copiedBytes, &hs);
        if (hs.flags & F_ERROR) {
            SvmDebugPrint("[ERR][BuildTrampoline] Disassembly error at %p (offset %u)\n",
                src + copiedBytes, copiedBytes);
            return STATUS_UNSUCCESSFUL;
        }

        /* Safety check: trampoline page overflow */
        if (dstOffset + 40 > PAGE_SIZE) {
            SvmDebugPrint("[ERR][BuildTrampoline] Trampoline overflow at %p\n", src + copiedBytes);
            return STATUS_UNSUCCESSFUL;
        }

        // 1. CALL rel32 (opcode E8)
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
        // 3. Jcc rel32 / Jcc rel8
        else if ((hs.opcode == 0x0F && hs.opcode2 >= 0x80 && hs.opcode2 <= 0x8F) ||
            (hs.opcode >= 0x70 && hs.opcode <= 0x7F))
        {
            LONG relOffset = (hs.opcode == 0x0F) ? (LONG)hs.imm.imm32 : (CHAR)hs.imm.imm8;
            ULONG64 targetAddr = (ULONG64)src + copiedBytes + hs.len + relOffset;
            UCHAR jcc8 = (hs.opcode == 0x0F) ? (0x70 + (hs.opcode2 & 0x0F)) : hs.opcode;

            UCHAR jccStub[] = {
                jcc8, 0x02,
                0xEB, 0x0E,
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00
            };
            RtlCopyMemory(dst + dstOffset, jccStub, sizeof(jccStub));
            dstOffset += sizeof(jccStub);
            *(PULONG64)(dst + dstOffset) = targetAddr;
            dstOffset += 8;
        }
        // 4. RIP-relative data addressing (mod=00, rm=5)
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
            else if (hs.opcode == 0x8B) // MOV reg, [RIP+disp] (load)
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
            /*
             * [BUGFIX 2026/03/15] Generic RIP-relative instruction handler.
             * Uses R11 (or R10 if reg==R11) as scratch register.
             */
            else
            {
                BOOLEAN useR10 = (reg == 3 && rex_r == 1);
                UCHAR scratchRegBits = useR10 ? 2 : 3;

                SvmDebugPrint("[BuildTrampoline] Generic RIP-rel: opcode=0x%02X at %p, scratch=R%d\n",
                    hs.opcode, src + copiedBytes, useR10 ? 10 : 11);

                /* push scratch (R10: 41 52, R11: 41 53) */
                *(dst + dstOffset++) = 0x41;
                *(dst + dstOffset++) = 0x50 | scratchRegBits;

                /* mov scratch, imm64 (movabs): 49 BA/BB <8 bytes> */
                *(dst + dstOffset++) = 0x49;
                *(dst + dstOffset++) = 0xB8 | scratchRegBits;
                *(PULONG64)(dst + dstOffset) = targetAddr;
                dstOffset += 8;

                /*
                 * Re-emit instruction with ModRM changed:
                 * [RIP+disp32] -> [scratch]
                 */
                PUCHAR origInstr = src + copiedBytes;
                ULONG newPos = 0;

                /* Copy legacy prefixes, skip original REX */
                for (int p = 0; p < 5 && newPos < len; p++) {
                    UCHAR b = origInstr[newPos];
                    if (b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x66 ||
                        b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
                        b == 0x64 || b == 0x65 || b == 0x67) {
                        *(dst + dstOffset++) = b;
                        newPos++;
                    }
                    else break;
                }

                /* New REX: W=orig, R=orig, X=0, B=1 */
                UCHAR newRex = 0x41 | (rex_w << 3) | (rex_r << 2);
                *(dst + dstOffset++) = newRex;

                /* Skip original REX if present */
                if (newPos < len && (origInstr[newPos] & 0xF0) == 0x40)
                    newPos++;

                /* Copy opcode (1 or 2 bytes) */
                if (origInstr[newPos] == 0x0F) {
                    *(dst + dstOffset++) = origInstr[newPos++];
                    if (newPos < len)
                        *(dst + dstOffset++) = origInstr[newPos++];
                }
                else {
                    *(dst + dstOffset++) = origInstr[newPos++];
                }

                /* New ModRM: mod=00, reg=original, rm=scratchRegBits */
                UCHAR newModrm = (0x00) | (hs.modrm & 0x38) | scratchRegBits;
                *(dst + dstOffset++) = newModrm;
                newPos++; /* skip original ModRM */
                newPos += 4; /* skip original disp32 */

                /* Copy remaining bytes (immediates etc.) */
                while (newPos < len) {
                    *(dst + dstOffset++) = origInstr[newPos++];
                }

                /* pop scratch (R10: 41 5A, R11: 41 5B) */
                *(dst + dstOffset++) = 0x41;
                *(dst + dstOffset++) = 0x58 | scratchRegBits;
            }
        }
        // 5. MOV CRn, GPR (opcode 0F 22 /r) - write CR via VMMCALL
        else if (hs.opcode == 0x0F && hs.opcode2 == 0x22)
        {
            UCHAR crNum = (hs.modrm >> 3) & 7;
            UCHAR srcGpr = hs.modrm & 7;
            if (hs.rex_b) srcGpr += 8;
            if (hs.rex_r) crNum += 8;

            SvmDebugPrint("[BuildTrampoline] Replacing MOV CR%d, GPR%d with VMMCALL at %p\n",
                crNum, srcGpr, src + copiedBytes);

            *(dst + dstOffset++) = 0x50;
            *(dst + dstOffset++) = 0x51;

            if (srcGpr != 1) {
                UCHAR rexByte = 0x48;
                if (srcGpr >= 8) rexByte |= 0x04;
                *(dst + dstOffset++) = rexByte;
                *(dst + dstOffset++) = 0x89;
                *(dst + dstOffset++) = (UCHAR)(0xC0 | ((srcGpr & 7) << 3) | 1);
            }

            *(dst + dstOffset++) = 0xB8;
            *(PULONG)(dst + dstOffset) = VMMCALL_CR_WRITE_BASE | crNum;
            dstOffset += 4;

            *(dst + dstOffset++) = 0x0F;
            *(dst + dstOffset++) = 0x01;
            *(dst + dstOffset++) = 0xD9;

            *(dst + dstOffset++) = 0x59;
            *(dst + dstOffset++) = 0x58;
        }
        // 6. MOV GPR, CRn (opcode 0F 20 /r) - read CR via VMMCALL
        else if (hs.opcode == 0x0F && hs.opcode2 == 0x20)
        {
            UCHAR crNum = (hs.modrm >> 3) & 7;
            UCHAR dstGpr = hs.modrm & 7;
            if (hs.rex_b) dstGpr += 8;
            if (hs.rex_r) crNum += 8;

            *(dst + dstOffset++) = 0x50;
            *(dst + dstOffset++) = 0x51;

            *(dst + dstOffset++) = 0xB8;
            *(PULONG)(dst + dstOffset) = VMMCALL_CR_READ_BASE | crNum;
            dstOffset += 4;

            *(dst + dstOffset++) = 0x0F;
            *(dst + dstOffset++) = 0x01;
            *(dst + dstOffset++) = 0xD9;

            if (dstGpr != 1) {
                UCHAR rexByte = 0x48;
                if (dstGpr >= 8) rexByte |= 0x01;
                *(dst + dstOffset++) = rexByte;
                *(dst + dstOffset++) = 0x89;
                *(dst + dstOffset++) = (UCHAR)(0xC0 | (1 << 3) | (dstGpr & 7));
            }

            *(dst + dstOffset++) = 0x59;
            *(dst + dstOffset++) = 0x58;
        }
        // 7. Normal instruction - raw copy
        else
        {
            RtlCopyMemory(dst + dstOffset, src + copiedBytes, len);
            dstOffset += len;
        }
        copiedBytes += len;
    }

    /* Trampoline tail: 14-byte absolute JMP back to original function remainder */
    {
        ULONG64 retAddr = (ULONG64)src + copiedBytes;
        UCHAR jmpBackStub[14] = {
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        *(PULONG64)(&jmpBackStub[6]) = retAddr;
        RtlCopyMemory(dst + dstOffset, jmpBackStub, 14);
        dstOffset += 14;
    }

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

    // Check for same-physical-page sharing
    PNPT_HOOK_CONTEXT pSharedHook = nullptr;
    for (int i = 0; i < HOOK_MAX_COUNT; i++) {
        if (&g_HookList[i] != HookContext && g_HookList[i].IsUsed && g_HookList[i].FakePage != nullptr &&
            g_HookList[i].OriginalPagePa == HookContext->OriginalPagePa) {
            pSharedHook = &g_HookList[i];
            break;
        }
    }

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

    // Allocate independent trampoline page
    PHYSICAL_ADDRESS highAddr;
    highAddr.QuadPart = ~0ULL;
    HookContext->TrampolinePage = MmAllocateContiguousMemory(PAGE_SIZE, highAddr);
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
    SvmDebugPrint("[Phase1] Hook ready: %p (FakePa=0x%llX, OrigPa=0x%llX, Stolen=%u)\n",
        TargetAddress, HookContext->FakePagePa, HookContext->OriginalPagePa,
        HookContext->StolenBytesLength);
    return STATUS_SUCCESS;
}

VOID FreeNptHook(PNPT_HOOK_CONTEXT HookContext)
{
    if (HookContext == nullptr) return;

    ResetSingleHookState(HookContext);
    RtlZeroMemory(HookContext, sizeof(NPT_HOOK_CONTEXT));
    SvmDebugPrint("[INFO] NPT Hook resources freed.\n");
}