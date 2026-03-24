// Disable C4819 (codepage 936 encoding warning) BEFORE any other content
#pragma warning(disable: 4819)

/**
 * @file SVM.cpp
 * @brief SVM虚拟化引擎 - VMCB配置、VMEXIT分派、超级调用处理
 * @author yewilliam
 * @date 2026/03/16
 *
 * 实现AMD SVM核心功能:
 *   - VMCB控制区/状态保存区初始化
 *   - VMEXIT退出事件分派(CPUID/NPF/GP/VMMCALL等)
 *   - NPT Hook执行/读写分离处理
 *   - 自定义超级调用命令(进程保护/内存操作)
 *   - CR寄存器读写模拟(#GP处理 + VMMCALL中转)
 */
#include "SVM.h"
#include "HvMemory.h"
#include "DebugApi.h"

extern ULONG64 g_SystemCr3;
/**
 * @brief 强制刷新NPT TLB - 清除VMCB缓存并重新加载NPT CR3
 * @author yewilliam
 * @date 2026/03/16
 * @param [in,out] vpData - VCPU上下文
 * @note 设置VmcbClean=0强制处理器重新读取所有VMCB字段, TlbControl=1触发TLB全刷新
 */

static inline VOID ForceNptFlush(PVCPU_CONTEXT vpData)
{
    vpData->Guestvmcb.ControlArea.VmcbClean = 0;
    vpData->Guestvmcb.ControlArea.NCr3 = vpData->NptCr3;
    vpData->Guestvmcb.ControlArea.TlbControl = 1;
}
/**
 * @brief 快速判断地址是否在内核空间范围内 - 检查高16位canonical形式
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] Address - 待检查的64位虚拟地址
 * @return TRUE表示地址在内核空间(0xFFFF8000_00000000以上), FALSE表示不在
 */

static __forceinline BOOLEAN IsKernelAddressLikely(UINT64 Address)
{
    return (Address >= 0xFFFF800000000000ULL && Address <= 0xFFFFFFFFFFFFFFFFULL);
}
/**
 * @brief 从Guest RIP解码MOV CRn指令 - 解析REX前缀、操作码和ModRM字段
 * @author yewilliam
 * @date 2026/03/16
 * @param [in]  GuestRip - Guest当前指令指针
 * @param [out] crNum    - 解码出的CR寄存器编号(0/2/3/4)
 * @param [out] gprNum   - 解码出的通用寄存器编号(0-15)
 * @param [out] instrLen - 指令总长度(含前缀)
 * @param [out] isWrite  - TRUE表示MOV CRn,GPR(写CR), FALSE表示MOV GPR,CRn(读CR)
 * @return TRUE表示成功解码为CR指令, FALSE表示非CR指令或解码失败
 * @note 用于#GP异常处理, 模拟被拦截的CR寄存器访问
 */

static BOOLEAN DecodeCrInstructionFromRip(
    UINT64 GuestRip,
    PULONG crNum,
    PULONG gprNum,
    PULONG instrLen,
    PBOOLEAN isWrite)
{
    if (!IsKernelAddressLikely(GuestRip)) return FALSE;

    __try {
        PUCHAR instr = (PUCHAR)GuestRip;
        ULONG pos = 0;
        BOOLEAN rexB = FALSE, rexR = FALSE;

        for (int i = 0; i < 5; i++) {
            UCHAR b = instr[pos];
            if (b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x66 ||
                b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
                b == 0x64 || b == 0x65 || b == 0x67) {
                pos++;
            }
            else break;
        }

        if ((instr[pos] & 0xF0) == 0x40) {
            rexB = (instr[pos] & 0x01) != 0;
            rexR = (instr[pos] & 0x04) != 0;
            pos++;
        }

        if (instr[pos] == 0x0F && (instr[pos + 1] == 0x22 || instr[pos + 1] == 0x20)) {
            UCHAR modrm = instr[pos + 2];
            *crNum = (modrm >> 3) & 7;
            *gprNum = modrm & 7;
            if (rexR) *crNum += 8;
            if (rexB) *gprNum += 8;
            *instrLen = pos + 3;
            *isWrite = (instr[pos + 1] == 0x22);
            return TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return FALSE;
}
/**
 * @brief 读取Guest通用寄存器值 - 根据寄存器索引从VMCB或GPR结构体读取
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] vpData   - VCPU上下文(GPR保存区)
 * @param [in] vmcb     - VMCB(RAX/RSP保存在StateSaveArea中)
 * @param [in] gprIndex - 寄存器索引(0=RAX, 1=RCX, ..., 15=R15)
 * @return 指定寄存器的64位值
 */

static UINT64 ReadGuestGpr(PVCPU_CONTEXT vpData, PVMCB vmcb, ULONG gprIndex)
{
    switch (gprIndex) {
    case 0:  return vmcb->StateSaveArea.Rax;
    case 1:  return vpData->Guest_gpr.Rcx;
    case 2:  return vpData->Guest_gpr.Rdx;
    case 3:  return vpData->Guest_gpr.Rbx;
    case 4:  return vmcb->StateSaveArea.Rsp;
    case 5:  return vpData->Guest_gpr.Rbp;
    case 6:  return vpData->Guest_gpr.Rsi;
    case 7:  return vpData->Guest_gpr.Rdi;
    case 8:  return vpData->Guest_gpr.R8;
    case 9:  return vpData->Guest_gpr.R9;
    case 10: return vpData->Guest_gpr.R10;
    case 11: return vpData->Guest_gpr.R11;
    case 12: return vpData->Guest_gpr.R12;
    case 13: return vpData->Guest_gpr.R13;
    case 14: return vpData->Guest_gpr.R14;
    case 15: return vpData->Guest_gpr.R15;
    default: return 0;
    }
}
/**
 * @brief 写入Guest通用寄存器值 - 根据寄存器索引写入VMCB或GPR结构体
 * @author yewilliam
 * @date 2026/03/16
 * @param [in,out] vpData   - VCPU上下文(GPR保存区)
 * @param [in,out] vmcb     - VMCB(RAX/RSP保存在StateSaveArea中)
 * @param [in]     gprIndex - 寄存器索引(0=RAX, 1=RCX, ..., 15=R15)
 * @param [in]     value    - 要写入的64位值
 */

static VOID WriteGuestGpr(PVCPU_CONTEXT vpData, PVMCB vmcb, ULONG gprIndex, UINT64 value)
{
    switch (gprIndex) {
    case 0:  vmcb->StateSaveArea.Rax = value; break;
    case 1:  vpData->Guest_gpr.Rcx = value; break;
    case 2:  vpData->Guest_gpr.Rdx = value; break;
    case 3:  vpData->Guest_gpr.Rbx = value; break;
    case 4:  vmcb->StateSaveArea.Rsp = value; break;
    case 5:  vpData->Guest_gpr.Rbp = value; break;
    case 6:  vpData->Guest_gpr.Rsi = value; break;
    case 7:  vpData->Guest_gpr.Rdi = value; break;
    case 8:  vpData->Guest_gpr.R8 = value; break;
    case 9:  vpData->Guest_gpr.R9 = value; break;
    case 10: vpData->Guest_gpr.R10 = value; break;
    case 11: vpData->Guest_gpr.R11 = value; break;
    case 12: vpData->Guest_gpr.R12 = value; break;
    case 13: vpData->Guest_gpr.R13 = value; break;
    case 14: vpData->Guest_gpr.R14 = value; break;
    case 15: vpData->Guest_gpr.R15 = value; break;
    }
}
/**
 * @brief 初始化当前CPU的SVM核心 - 捕获上下文、配置VMCB、进入VMM
 * @author yewilliam
 * @date 2026/03/16
 * @param [in,out] vpData - 当前CPU的VCPU上下文(已预分配)
 * @return STATUS_SUCCESS表示成功进入SVM Guest模式
 * @note 调用RtlCaptureContext获取当前寄存器状态作为Guest初始状态,
/**
 * @brief 检测自研Hypervisor是否已安装 - 通过CPUID 0x40000000读取Vendor ID
 * @author yewilliam
 * @date 2026/03/16
 * @return TRUE表示CPUID返回"VtDebugView "(自定义签名), FALSE表示未安装
 * @note 用于InitSVMCORE中避免重复虚拟化(VMRUN后CPUID被拦截返回自定义签名)
 */
 /*       IsSvmHypervisorInstalled()在VMRUN后返回TRUE实现"回溯"检测
 */

NTSTATUS InitSVMCORE(PVCPU_CONTEXT vpData)
{
    if (vpData == nullptr) return STATUS_INVALID_PARAMETER;
    CONTEXT contextRecord = { 0 };
    RtlCaptureContext(&contextRecord);
    if (IsSvmHypervisorInstalled()) return STATUS_SUCCESS;
    NTSTATUS status = PrepareVMCB(vpData, contextRecord);
    if (!NT_SUCCESS(status)) {
        SvmDebugPrint("[ERROR] CPU %d: PrepareVMCB failed\n", KeGetCurrentProcessorNumber());
        return status;
    }
    if (g_SystemCr3 != 0) __writecr3(g_SystemCr3);
    SvEnterVmmOnNewStack(vpData);
    return STATUS_SUCCESS;
}
/**
 * @brief 配置VMCB控制区和状态保存区 - 填充段寄存器、控制寄存器、拦截位
 * @author yewilliam
 * @date 2026/03/16
 * @param [in,out] vpData        - VCPU上下文(包含Guest/Host VMCB)
 * @param [in]     contextRecord - RtlCaptureContext捕获的CPU寄存器快照
 * @return STATUS_SUCCESS表示VMCB配置完成, STATUS_NOT_SUPPORTED表示NPT不可用
 * @note 配置拦截项: CPUID + VMRUN + VMMCALL + #DB + #GP
 *       启用EFER.SVME, 设置ASID=1, 初始化Host Save Area
 */

NTSTATUS PrepareVMCB(PVCPU_CONTEXT vpData, CONTEXT contextRecord)
{
    if (vpData == nullptr) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(&vpData->Guestvmcb, sizeof(VMCB));
    RtlZeroMemory(&vpData->Hostvmcb, sizeof(VMCB));

    NTSTATUS status = InitNPT(vpData);
    if (!NT_SUCCESS(status)) return STATUS_NOT_SUPPORTED;

    vpData->Guestvmcb.StateSaveArea.Cr0 = __readcr0();
    vpData->Guestvmcb.StateSaveArea.Cr2 = __readcr2();
    vpData->Guestvmcb.StateSaveArea.Cr3 = __readcr3();
    vpData->Guestvmcb.StateSaveArea.Cr4 = __readcr4();
    vpData->Guestvmcb.StateSaveArea.Dr6 = __readdr(6);
    vpData->Guestvmcb.StateSaveArea.Dr7 = __readdr(7);

    UINT8 gdtBuffer[10] = { 0 }, idtBuffer[10] = { 0 };
    __sidt(idtBuffer);
    _sgdt(gdtBuffer);
    UINT16 gdtLimit = *(UINT16*)(gdtBuffer);
    UINT64 gdtBase = *(UINT64*)(gdtBuffer + 2);
    UINT16 idtLimit = *(UINT16*)(idtBuffer);
    UINT64 idtBase = *(UINT64*)(idtBuffer + 2);

    vpData->Guestvmcb.StateSaveArea.GdtrLimit = gdtLimit;
    vpData->Guestvmcb.StateSaveArea.GdtrBase = gdtBase;
    vpData->Guestvmcb.StateSaveArea.IdtrLimit = idtLimit;
    vpData->Guestvmcb.StateSaveArea.IdtrBase = idtBase;
    vpData->Guestvmcb.StateSaveArea.Rax = contextRecord.Rax;

    vpData->Guestvmcb.StateSaveArea.CsSelector = contextRecord.SegCs;
    vpData->Guestvmcb.StateSaveArea.CsLimit = GetSegmentLimit(contextRecord.SegCs);
    vpData->Guestvmcb.StateSaveArea.CsAttrib = GetSegmentAttribute(contextRecord.SegCs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.CsBase = GetSegmentBase(contextRecord.SegCs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.DsSelector = contextRecord.SegDs;
    vpData->Guestvmcb.StateSaveArea.DsLimit = GetSegmentLimit(contextRecord.SegDs);
    vpData->Guestvmcb.StateSaveArea.DsAttrib = GetSegmentAttribute(contextRecord.SegDs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.DsBase = GetSegmentBase(contextRecord.SegDs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.EsSelector = contextRecord.SegEs;
    vpData->Guestvmcb.StateSaveArea.EsLimit = GetSegmentLimit(contextRecord.SegEs);
    vpData->Guestvmcb.StateSaveArea.EsAttrib = GetSegmentAttribute(contextRecord.SegEs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.EsBase = GetSegmentBase(contextRecord.SegEs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.SsSelector = contextRecord.SegSs;
    vpData->Guestvmcb.StateSaveArea.SsLimit = GetSegmentLimit(contextRecord.SegSs);
    vpData->Guestvmcb.StateSaveArea.SsAttrib = GetSegmentAttribute(contextRecord.SegSs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.SsBase = GetSegmentBase(contextRecord.SegSs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.FsSelector = contextRecord.SegFs;
    vpData->Guestvmcb.StateSaveArea.FsLimit = GetSegmentLimit(contextRecord.SegFs);
    vpData->Guestvmcb.StateSaveArea.FsAttrib = GetSegmentAttribute(contextRecord.SegFs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.FsBase = __readmsr(MSR_IA32_FS_BASE);
    vpData->Guestvmcb.StateSaveArea.GsSelector = contextRecord.SegGs;
    vpData->Guestvmcb.StateSaveArea.GsLimit = GetSegmentLimit(contextRecord.SegGs);
    vpData->Guestvmcb.StateSaveArea.GsAttrib = GetSegmentAttribute(contextRecord.SegGs, gdtBase);
    vpData->Guestvmcb.StateSaveArea.GsBase = __readmsr(MSR_IA32_GS_BASE);

    vpData->Guestvmcb.StateSaveArea.Rflags = __readeflags();
    vpData->Guestvmcb.StateSaveArea.Cpl = 0;
    vpData->Guestvmcb.StateSaveArea.GPat = __readmsr(IA32_MSR_PAT);
    vpData->Guestvmcb.StateSaveArea.Rsp = contextRecord.Rsp;
    vpData->Guestvmcb.StateSaveArea.Rip = contextRecord.Rip;
    vpData->Guestvmcb.ControlArea.VIntr = 0;
    vpData->Guestvmcb.ControlArea.InterruptShadow = 0;

    vpData->GuestVmcbPa = MmGetPhysicalAddress(&vpData->Guestvmcb).QuadPart;
    vpData->HostVmcbPa = MmGetPhysicalAddress(&vpData->Hostvmcb).QuadPart;

    vpData->Guest_gpr.Rax = contextRecord.Rax;
    vpData->Guest_gpr.Rbx = contextRecord.Rbx;
    vpData->Guest_gpr.Rcx = contextRecord.Rcx;
    vpData->Guest_gpr.Rdx = contextRecord.Rdx;
    vpData->Guest_gpr.Rsi = contextRecord.Rsi;
    vpData->Guest_gpr.Rdi = contextRecord.Rdi;
    vpData->Guest_gpr.Rbp = contextRecord.Rbp;
    vpData->Guest_gpr.R8 = contextRecord.R8;
    vpData->Guest_gpr.R9 = contextRecord.R9;
    vpData->Guest_gpr.R10 = contextRecord.R10;
    vpData->Guest_gpr.R11 = contextRecord.R11;
    vpData->Guest_gpr.R12 = contextRecord.R12;
    vpData->Guest_gpr.R13 = contextRecord.R13;
    vpData->Guest_gpr.R14 = contextRecord.R14;
    vpData->Guest_gpr.R15 = contextRecord.R15;

    vpData->Guestvmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_CPUID;
    vpData->Guestvmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMRUN | SVM_INTERCEPT_MISC2_VMCALL;

    vpData->Guestvmcb.ControlArea.InterceptException |= (1UL << 1);   /* #DB */
    vpData->Guestvmcb.ControlArea.InterceptException |= (1UL << 3);   /* #BP — 隐形断点基础 */
    vpData->Guestvmcb.ControlArea.InterceptException |= (1UL << 13);  /* #GP */

    if (vpData->ProcessorIndex == 0) {
        SvmDebugPrint("[SVM] InterceptException=0x%X (#DB=%d #BP=%d #GP=%d)\n",
            vpData->Guestvmcb.ControlArea.InterceptException,
            (vpData->Guestvmcb.ControlArea.InterceptException >> 1) & 1,
            (vpData->Guestvmcb.ControlArea.InterceptException >> 3) & 1,
            (vpData->Guestvmcb.ControlArea.InterceptException >> 13) & 1);
    }

    /* Do NOT intercept RDTSC/RDTSCP - causes physical machine freeze */

    __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) | EFER_SVME);
    vpData->Guestvmcb.StateSaveArea.Efer = __readmsr(IA32_MSR_EFER);
    vpData->Guestvmcb.ControlArea.GuestAsid = 1;

    PHYSICAL_ADDRESS hostSaveAreaPa = MmGetPhysicalAddress(vpData->HostSaveArea);
    __writemsr(SVM_MSR_VM_HSAVE_PA, hostSaveAreaPa.QuadPart);
    if ((vpData->GuestVmcbPa & 0xFFF) != 0 || (hostSaveAreaPa.QuadPart & 0xFFF) != 0) {
        return STATUS_UNSUCCESSFUL;
    }
    __svm_vmsave(vpData->GuestVmcbPa);
    __svm_vmsave(vpData->HostVmcbPa);
    return STATUS_SUCCESS;
}
/**
 * @brief 从GDT获取段描述符属性 - 解析Type/DPL/Present/LongMode等字段
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] SegmentSelector - 段选择子(CS/DS/SS等)
 * @param [in] GdtBase         - GDT基地址
 * @return VMCB格式的16位段属性值
 */

UINT16 GetSegmentAttribute(UINT16 SegmentSelector, UINT64 GdtBase)
{
    SEGMENT_ATTRIBUTE attribute = { 0 };
    if ((SegmentSelector & ~RPL_MASK) == 0) return attribute.AsUInt16;
    PSEGMENT_DESCRIPTOR descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(GdtBase + (SegmentSelector & ~RPL_MASK));
    attribute.Fields.Type = descriptor->Fields.Type;
    attribute.Fields.System = descriptor->Fields.System;
    attribute.Fields.Dpl = descriptor->Fields.Dpl;
    attribute.Fields.Present = descriptor->Fields.Present;
    attribute.Fields.Avl = descriptor->Fields.Avl;
    attribute.Fields.LongMode = descriptor->Fields.LongMode;
    attribute.Fields.DefaultBit = descriptor->Fields.DefaultBit;
    attribute.Fields.Granularity = descriptor->Fields.Granularity;
    attribute.Fields.Reserved1 = 0;
    return attribute.AsUInt16;
}
/**
 * @brief 从GDT获取段基地址 - 拼接BaseLow/BaseMiddle/BaseHigh
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] SegmentSelector - 段选择子
 * @param [in] GdtBase         - GDT基地址
 * @return 段基地址(x64长模式下通常为0, FS/GS例外)
 */

UINT64 GetSegmentBase(UINT16 SegmentSelector, UINT64 GdtBase)
{
    UINT16 index = SegmentSelector >> 3;
    if (index == 0) return 0;
    PSEGMENT_DESCRIPTOR descriptor = (PSEGMENT_DESCRIPTOR)(GdtBase + index * sizeof(SEGMENT_DESCRIPTOR));
    ULONG_PTR base = ((ULONG_PTR)descriptor->Fields.BaseHigh << 24) |
        ((ULONG_PTR)descriptor->Fields.BaseMiddle << 16) | descriptor->Fields.BaseLow;
    return base;
}

BOOLEAN IsSvmHypervisorInstalled()
{
    int regs[4] = { 0 };
    char vendorId[13] = { 0 };
    __cpuid(regs, CPUID_HV_VENDOR_AND_MAX_FUNCTIONS);
    RtlCopyMemory(vendorId, &regs[1], 4);
    RtlCopyMemory(vendorId + 4, &regs[2], 4);
    RtlCopyMemory(vendorId + 8, &regs[3], 4);
    vendorId[12] = ANSI_NULL;
    return (strcmp(vendorId, "VtDebugView ") == 0);
}
/**
 * @brief 处理自定义超级调用命令 - 在VMEXIT(CPUID/VMMCALL)中执行保护操作
 * @author yewilliam
 * @date 2026/03/16
 * @param [in,out] vpData - VCPU上下文
 * @param [in,out] vmcb   - Guest VMCB
 * @param [in]     cmd    - 命令码(0x12345678=保护PID, 0x12345679=保护HWND等)
 * @return TRUE表示命令已处理, FALSE表示未识别的命令
 */

static BOOLEAN HandleHypercallCommand(PVCPU_CONTEXT vpData, PVMCB vmcb, UINT32 cmd)
{
    if (cmd == 0x12345678) {
        HANDLE pid = (HANDLE)vpData->Guest_gpr.Rcx;
        AddProtectedPid(pid);
        extern HANDLE g_PendingProtectPID;
        g_PendingProtectPID = pid;
        vmcb->StateSaveArea.Rax = 1;
        vpData->Guest_gpr.Rax = 1;
        SvmDebugPrint("[HyperCall] HIDE_PID: %llu, added to protection list\n", (ULONG64)pid);
        return TRUE;
    }
    else if (cmd == 0x12345679) {
        AddProtectedHwnd((SVM_HWND)vpData->Guest_gpr.Rcx);
        vmcb->StateSaveArea.Rax = 1;
        vpData->Guest_gpr.Rax = 1;
        SvmDebugPrint("[HyperCall] HIDE_HWND: 0x%llX\n", vpData->Guest_gpr.Rcx);
        return TRUE;
    }
    else if (cmd == 0x1234567A) {
        AddProtectedChildHwnd((SVM_HWND)vpData->Guest_gpr.Rcx);
        vmcb->StateSaveArea.Rax = 1;
        vpData->Guest_gpr.Rax = 1;
        return TRUE;
    }
    else if (cmd == 0x1234567F) {
        ClearAllProtectedTargets();
        vmcb->StateSaveArea.Rax = 1;
        vpData->Guest_gpr.Rax = 1;
        return TRUE;
    }
    else if (cmd == 0x12345680) {
        vmcb->StateSaveArea.Rax = 1;
        vpData->Guest_gpr.Rax = 1;
        return TRUE;
    }
    else if (cmd == 0x12345681) {
        vmcb->StateSaveArea.Rax = 1;
        vpData->Guest_gpr.Rax = 1;
        return TRUE;
    }
    return FALSE;
}

/**
 * @brief VMEXIT分派中心 - 根据退出码分发到对应处理器
 * @author yewilliam
 * @date 2026/03/16
 * @param [in,out] vpData - VCPU上下文
 *
 * 处理的VMEXIT类型:
 *   - CPUID: Hypervisor签名/卸载/Hook激活/内存操作/透传
 *   - VMRUN: 跳过(推进RIP)
 *   - NPF: 执行故障→切换FakePage, 读写故障→恢复OriginalPage
 *   - #DB: 重注入调试异常
 *   - #GP: 解码CR指令模拟/重注入
 *   - VMMCALL: CR读写模拟/超级调用命令
 *
 * SuspendedHook恢复逻辑: 当RIP离开Hook页面时, 恢复NPT为ReadOnly触发态
 */
void SvHandleVmExit(PVCPU_CONTEXT vpData)
{
    if (vpData == nullptr) return;
    PVMCB vmcb = &vpData->Guestvmcb;

    /* SuspendedHook restoration: when RIP leaves the hook page, restore normal state */
    if (vpData->SuspendedHook != nullptr) {
        PNPT_HOOK_CONTEXT suspCtx = (PNPT_HOOK_CONTEXT)vpData->SuspendedHook;
        ULONG64 ripPage = vmcb->StateSaveArea.Rip & ~0xFFFULL;
        ULONG64 hookVaPage = ((ULONG64)suspCtx->TargetAddress) & ~0xFFFULL;

        if (ripPage != hookVaPage) {
            BOOLEAN switchedToOtherHook = FALSE;
            ULONG64 suspPagePa = suspCtx->TargetPa & ~0xFFFULL;

            for (int hh = 0; hh < HOOK_MAX_COUNT; hh++) {
                if (!g_HookList[hh].IsUsed || &g_HookList[hh] == suspCtx) continue;
                ULONG64 otherVaPage = ((ULONG64)g_HookList[hh].TargetAddress) & ~0xFFFULL;
                if (ripPage == otherVaPage &&
                    (g_HookList[hh].TargetPa & ~0xFFFULL) == suspPagePa)
                {
                    vpData->SuspendedHook = &g_HookList[hh];
                    switchedToOtherHook = TRUE;
                    break;
                }
            }

            if (!switchedToOtherHook) {
                ApplyNptHookByPa(vpData, suspCtx->TargetPa, suspCtx->OriginalPagePa);
                SetNptPagePermissions(vpData, suspCtx->TargetPa, NPT_PERM_READ_ONLY);
                ForceNptFlush(vpData);
                vpData->SuspendedHook = nullptr;
            }
        }
    }

    UINT64 exitCode = vmcb->ControlArea.ExitCode;
    UINT32 leaf = (UINT32)vmcb->StateSaveArea.Rax;

    switch (exitCode)
    {
    case VMEXIT_CPUID:
    {
        if (leaf == CPUID_HV_VENDOR_AND_MAX_FUNCTIONS) {
            vmcb->StateSaveArea.Rax = CPUID_HV_INTERFACE;
            vpData->Guest_gpr.Rbx = 0x65447456;
            vpData->Guest_gpr.Rcx = 0x56677562;
            vpData->Guest_gpr.Rdx = 0x20776569;
        }
        else if (leaf == CPUID_UNLOAD_SVM_DEBUG) {
            extern volatile BOOLEAN g_DriverUnloading;
            g_DriverUnloading = TRUE;
            MemoryBarrier();
            vpData->isExit = 1;
        }
        else if (leaf == CPUID_UNLOAD_SVM_INSTALL_HOOK) {
            ForceNptFlush(vpData);
        }
        else if (leaf == CPUID_UNLOAD_SVM_UNINSTALL_HOOK) {
            for (int i = 0; i < HOOK_MAX_COUNT; i++) {
                if (g_HookList[i].IsUsed && g_HookList[i].TargetPa != 0
                    && g_HookList[i].OriginalPagePa != 0) {
                    ApplyNptHookByPa(vpData, g_HookList[i].TargetPa, g_HookList[i].OriginalPagePa);
                    SetNptPagePermissions(vpData, g_HookList[i].TargetPa, NPT_PERM_EXECUTE);
                }
            }
            vpData->SuspendedHook = nullptr;
            vpData->ActiveHook = nullptr;
            ForceNptFlush(vpData);
            vpData->Guest_gpr.Rax = 0;
        }
        else if (leaf == CPUID_HV_MEMORY_OP) {
            vpData->Guest_gpr.Rbx = g_HvSharedContextPa;
            HvHandleMemoryOp(vpData);
        }
        else if (leaf == CPUID_HV_BATCH_READ) {
            HvHandleBatchRead(vpData);
        }
        else if (leaf == CPUID_HV_DEBUG_OP) {
            HvHandleDebugOp(vpData);
        }
        else if (HandleHypercallCommand(vpData, vmcb, leaf)) {
            /* handled */
        }
        else {
            int cpuInfo[4] = { 0 };
            __cpuidex(cpuInfo, leaf, (int)vpData->Guest_gpr.Rcx);


            if (leaf == 1) {
                cpuInfo[2] &= ~(1 << 31);  /* 清除 ECX.HypervisorPresent */
            }

            vmcb->StateSaveArea.Rax = (UINT64)cpuInfo[0];
            vpData->Guest_gpr.Rbx = (UINT64)cpuInfo[1];
            vpData->Guest_gpr.Rcx = (UINT64)cpuInfo[2];
            vpData->Guest_gpr.Rdx = (UINT64)cpuInfo[3];
        }
        vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
        break;
    }

    case VMEXIT_VMRUN:
        vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
        break;

        /*
         * NPF handler - No TF model (Execution/Read split)
         *
         */
    case VMEXIT_NPF:
    {
        UINT64 faultHpa = vmcb->ControlArea.ExitInfo2;
        UINT64 errorCode = vmcb->ControlArea.ExitInfo1;
        BOOLEAN isExecFault = (errorCode & 0x10) != 0;
        PNPT_HOOK_CONTEXT hookCtx = FindHookByFaultPa(faultHpa);

        if (hookCtx != nullptr) {
            if (isExecFault) {
                NTSTATUS s1, s2;
                ULONG64 guestRip = vmcb->StateSaveArea.Rip;


                PNPT_HOOK_CONTEXT matchedHook = nullptr;
                ULONG64 faultPagePa = hookCtx->OriginalPagePa;
                for (int hi = 0; hi < HOOK_MAX_COUNT; hi++) {
                    if (g_HookList[hi].IsUsed &&
                        g_HookList[hi].OriginalPagePa == faultPagePa &&
                        guestRip == (ULONG64)g_HookList[hi].TargetAddress) {
                        matchedHook = &g_HookList[hi];
                        break;
                    }
                }

                if (matchedHook != nullptr) {
                    /* RIP精确命中某个Hook的入口 → 显示FakePage(含JMP到Proxy) */
                    s1 = ApplyNptHookByPa(vpData, hookCtx->TargetPa, hookCtx->FakePagePa);
                }
                else {
                    /* RIP在Hook页上但不是任何Hook入口 → 显示原始页继续执行 */
                    s1 = ApplyNptHookByPa(vpData, hookCtx->TargetPa, hookCtx->OriginalPagePa);
                }
                s2 = SetNptPagePermissions(vpData, hookCtx->TargetPa, NPT_PERM_EXECUTE);
                ForceNptFlush(vpData);

                /* Only set SuspendedHook if both operations succeeded */
                if (NT_SUCCESS(s1) && NT_SUCCESS(s2)) {
                    vpData->SuspendedHook = hookCtx;
                }
            }
            else {
                /* Read/write fault - show original page */
                ApplyNptHookByPa(vpData, hookCtx->TargetPa, hookCtx->OriginalPagePa);
                SetNptPagePermissions(vpData, hookCtx->TargetPa, NPT_PERM_READ_ONLY);
                ForceNptFlush(vpData);
            }
        }
        else {
            /* Non-hook NPF - possibly MMIO or NPT coverage gap */
            SvmDebugPrint("[WARN] Unhandled NPF: HPA=0x%llX RIP=0x%llX err=0x%llX\n",
                faultHpa, vmcb->StateSaveArea.Rip, errorCode);
        }
        break;
    }

    case VMEXIT_EXCEPTION_DB:
    {
        /* === 验证计数器 === */
        static volatile LONG s_DbVmexitCount = 0;
        LONG dbCount = InterlockedIncrement(&s_DbVmexitCount);

        /* 场景 1: NPT 断点单步恢复 */
        BOOLEAN handled = FALSE;

        if (g_NptBreakpointCount > 0) {
            for (LONG i = 0; i < MAX_NPT_BREAKPOINTS; i++) {
                if (g_NptBreakpoints[i].IsActive &&
                    g_NptBreakpoints[i].IsSingleStepping)
                {
                    SvmDebugPrint("[VMM] #DB single-step recovery: BP[%d] addr=0x%llX\n",
                        i, g_NptBreakpoints[i].VirtualAddress);

                    /* 重新激活 NPT 断点: 切回 FakePage (含 0xCC) */
                    LONG hookSlot = g_NptBreakpoints[i].HookSlotIndex;
                    if (hookSlot >= 0 && hookSlot < HOOK_MAX_COUNT &&
                        g_HookList[hookSlot].IsUsed) {
                        ApplyNptHookByPa(vpData,
                            g_HookList[hookSlot].TargetPa,
                            g_HookList[hookSlot].FakePagePa);
                        SetNptPagePermissions(vpData,
                            g_HookList[hookSlot].TargetPa, NPT_PERM_READ_ONLY);
                        ForceNptFlush(vpData);
                    }

                    /* 清除 TF 和 DR6.BS */
                    vmcb->StateSaveArea.Rflags &= ~(1ULL << 8);
                    vmcb->StateSaveArea.Dr6 &= ~(1ULL << 14);
                    g_NptBreakpoints[i].IsSingleStepping = FALSE;
                    handled = TRUE;
                    break;
                }
            }
        }

        if (!handled) {
            if (dbCount <= 3) {
                SvmDebugPrint("[VMM] #DB VMEXIT (reinject): RIP=0x%llX DR6=0x%llX\n",
                    vmcb->StateSaveArea.Rip, vmcb->StateSaveArea.Dr6);
            }
            /* 回注到 Guest */
            EVENTINJ reinject = { 0 };
            reinject.Fields.Vector = 1;
            reinject.Fields.Type = 3;
            reinject.Fields.Valid = 1;
            vmcb->ControlArea.EventInj = reinject.AsUInt64;
        }
        break;
    }

    case VMEXIT_EXCEPTION_BP:
    {
        /* ============================================================
         * #BP (Vector 3) — INT3 断点异常
         *
         * 两种场景:
         *   1. 我们的 NPT 隐形断点: 通知调试器, 单步恢复
         *   2. 其他 INT3 (游戏/OS 自己的): 回注到 Guest OS
         * ============================================================ */
        ULONG64 bpRip = vmcb->StateSaveArea.Rip;
        ULONG64 bpCr3 = vmcb->StateSaveArea.Cr3;
        ULONG64 bpAddr = bpRip;  /* INT3 执行后 RIP 已指向下一条指令 */

        /* AMD SVM: INT3 的 #BP 异常是 fault 类型, RIP 已指向 INT3 之后
         * 所以断点地址 = RIP - 1 */
        bpAddr = bpRip - 1;

        /* === 验证计数器: 前 5 次打印详情, 之后每 1000 次打印一次汇总 === */
        static volatile LONG s_BpVmexitCount = 0;
        LONG bpCount = InterlockedIncrement(&s_BpVmexitCount);
        if (bpCount <= 5) {
            SvmDebugPrint("[VMM] #BP VMEXIT #%d: RIP=0x%llX CR3=0x%llX CPU=%d\n",
                bpCount, bpRip, bpCr3, vpData->ProcessorIndex);
        }
        else if ((bpCount % 1000) == 0) {
            SvmDebugPrint("[VMM] #BP VMEXIT total: %d\n", bpCount);
        }

        BOOLEAN isOurBp = FALSE;
        LONG bpIdx = -1;

        if (g_NptBreakpointCount > 0) {
            for (LONG i = 0; i < MAX_NPT_BREAKPOINTS; i++) {
                if (g_NptBreakpoints[i].IsActive &&
                    g_NptBreakpoints[i].VirtualAddress == bpAddr &&
                    g_NptBreakpoints[i].TargetCr3 == bpCr3)
                {
                    isOurBp = TRUE;
                    bpIdx = i;
                    break;
                }
            }
        }

        if (isOurBp && bpIdx >= 0) {
            SvmDebugPrint("[VMM] >>> NPT BP HIT! addr=0x%llX pid=%llu slot=%d\n",
                bpAddr, g_NptBreakpoints[bpIdx].TargetPid, bpIdx);

            vmcb->StateSaveArea.Rip = bpAddr;

            /* 临时切回原始页 */
            LONG hookSlot = g_NptBreakpoints[bpIdx].HookSlotIndex;
            if (hookSlot >= 0 && hookSlot < HOOK_MAX_COUNT) {
                ApplyNptHookByPa(vpData,
                    g_HookList[hookSlot].TargetPa,
                    g_HookList[hookSlot].OriginalPagePa);
                SetNptPagePermissions(vpData,
                    g_HookList[hookSlot].TargetPa, NPT_PERM_EXECUTE);
                ForceNptFlush(vpData);
            }

            /* 设置 TF → 执行 1 条原始指令后 #DB VMEXIT → 重新激活断点 */
            vmcb->StateSaveArea.Rflags |= (1ULL << 8);
            g_NptBreakpoints[bpIdx].IsSingleStepping = TRUE;

            /* TODO: 投递 STATUS_BREAKPOINT 事件到 DebugApi 事件队列 */
        }
        else {
            /* 不是我们的断点 — 回注到 Guest OS */
            EVENTINJ reinject = { 0 };
            reinject.Fields.Vector = 3;
            reinject.Fields.Type = 3;   /* Software exception */
            reinject.Fields.Valid = 1;
            vmcb->ControlArea.EventInj = reinject.AsUInt64;
        }
        break;
    }

    case VMEXIT_EXCEPTION_GP:
    {
        ULONG crNum = 0, gprNum = 0, instrLen = 0;
        BOOLEAN isCrWrite = FALSE;

        if (DecodeCrInstructionFromRip(vmcb->StateSaveArea.Rip, &crNum, &gprNum, &instrLen, &isCrWrite))
        {
            if (isCrWrite) {
                UINT64 value = ReadGuestGpr(vpData, vmcb, gprNum);
                switch (crNum) {
                case 0: vmcb->StateSaveArea.Cr0 = value; break;
                case 2: vmcb->StateSaveArea.Cr2 = value; break;
                case 3: vmcb->StateSaveArea.Cr3 = value; break;
                case 4: vmcb->StateSaveArea.Cr4 = value; break;
                default: break;
                }
            }
            else {
                UINT64 value = 0;
                switch (crNum) {
                case 0: value = vmcb->StateSaveArea.Cr0; break;
                case 2: value = vmcb->StateSaveArea.Cr2; break;
                case 3: value = vmcb->StateSaveArea.Cr3; break;
                case 4: value = vmcb->StateSaveArea.Cr4; break;
                default: break;
                }
                WriteGuestGpr(vpData, vmcb, gprNum, value);
            }
            vmcb->StateSaveArea.Rip += instrLen;
        }
        else {
            EVENTINJ reinject = { 0 };
            reinject.Fields.Vector = 13;
            reinject.Fields.Type = 3;
            reinject.Fields.ErrorCodeValid = 1;
            reinject.Fields.Valid = 1;
            reinject.Fields.ErrorCode = (UINT32)vmcb->ControlArea.ExitInfo1;
            vmcb->ControlArea.EventInj = reinject.AsUInt64;
        }
        break;
    }

    case VMEXIT_VMMCALL:
    {
        leaf = (UINT32)vmcb->StateSaveArea.Rax;

        if ((leaf & 0xFFFFFF00) == VMMCALL_CR_WRITE_BASE) {
            ULONG crNum = leaf & 0xFF;
            UINT64 value = vpData->Guest_gpr.Rcx;
            switch (crNum) {
            case 0: vmcb->StateSaveArea.Cr0 = value; break;
            case 2: vmcb->StateSaveArea.Cr2 = value; break;
            case 3: vmcb->StateSaveArea.Cr3 = value; break;
            case 4: vmcb->StateSaveArea.Cr4 = value; break;
            default: break;
            }
            vmcb->StateSaveArea.Rax = 0;
        }
        else if ((leaf & 0xFFFFFF00) == VMMCALL_CR_READ_BASE) {
            ULONG crNum = leaf & 0xFF;
            UINT64 value = 0;
            switch (crNum) {
            case 0: value = vmcb->StateSaveArea.Cr0; break;
            case 2: value = vmcb->StateSaveArea.Cr2; break;
            case 3: value = vmcb->StateSaveArea.Cr3; break;
            case 4: value = vmcb->StateSaveArea.Cr4; break;
            default: break;
            }
            vpData->Guest_gpr.Rcx = value;
            vmcb->StateSaveArea.Rax = 0;
        }
        else if (HandleHypercallCommand(vpData, vmcb, leaf)) {
            /* handled */
        }
        else {
            vpData->Guest_gpr.Rax = 0xFFFFFFFFFFFFFFFFull;
        }
        vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
        break;
    }

    default:
        vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
        break;
    }
}
/**
 * @brief 执行单次VMRUN - 包装SvLaunchVm汇编调用
 * @author yewilliam
 * @date 2026/03/16
 * @param [in,out] vpData - VCPU上下文
 */

void SVMLauchRun(PVCPU_CONTEXT vpData)
{
    if (vpData == nullptr) return;
    SvLaunchVm(vpData);
}
/**
 * @brief VMM主循环 - 反复执行VMRUN并处理VMEXIT直到收到退出信号
 * @author yewilliam
 * @date 2026/03/16
 * @param [in,out] vpData - VCPU上下文
 * @note 循环: VMRUN → 保存RAX → SvHandleVmExit → 检查isExit
 *       退出后调用SvSwitchStack切回Guest栈
 */

EXTERN_C void HostLoop(PVCPU_CONTEXT vpData)
{
    while (!vpData->isExit) {
        SVMLauchRun(vpData);
        vpData->Guest_gpr.Rax = vpData->Guestvmcb.StateSaveArea.Rax;
        SvHandleVmExit(vpData);
    }
    SvSwitchStack(vpData);
}
/**
 * @brief 调试打印Guest GPR寄存器值
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] Gpr - Guest通用寄存器结构体指针
 */

VOID PrintGuestGpr(PGUEST_GPR Gpr)
{
    if (Gpr == NULL) { SvmDebugPrint("GUEST_GPR is NULL\n"); return; }
    SvmDebugPrint("RAX=%016I64X RBX=%016I64X RCX=%016I64X RDX=%016I64X\n",
        Gpr->Rax, Gpr->Rbx, Gpr->Rcx, Gpr->Rdx);
}