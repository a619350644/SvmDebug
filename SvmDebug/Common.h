/**
 * @file Common.h
 * @brief 公共头文件 - 全局数据结构定义、VMCB布局、常量宏、CPU检测函数声明
 * @author yewilliam
 * @date 2026/03/16
 *
 * 本文件为整个SVM Hypervisor项目的基础头文件，包含：
 *   - MSR/CPUID 常量定义
 *   - VMCB 控制区和状态保存区结构体
 *   - Guest GPR、段描述符、事件注入等辅助结构体
 *   - VMEXIT 退出码枚举
 *   - CPU 硬件支持检测函数声明
 */

#pragma once
#include <ntifs.h>
#include <basetsd.h>
#include <intrin.h>
#include <stdarg.h>
#define DEBUG 0
/* ============================================================================
 *  Section 1: MSR 地址常量
 * ============================================================================ */

#define MSR_IA32_INTEL_FEATURE_CONTROL   0x3a
#define IA32_MSR_PAT                     0x00000277
#define IA32_MSR_EFER                    0xc0000080
#define MSR_STAR                         0xC0000081
#define MSR_LSTAR                        0xC0000082
#define MSR_CSTAR                        0xC0000083
#define MSR_SFMASK                       0xC0000084
#define MSR_IA32_FS_BASE                 0xC0000100
#define MSR_IA32_GS_BASE                 0xC0000101
#define MSR_IA32_KERNEL_GS_BASE          0xC0000102
#define MSR_KERNEL_GS_BASE               0xC0000102
#define MSR_IA32_SYSENTER_CS             0x174
#define MSR_IA32_SYSENTER_ESP            0x175
#define MSR_IA32_SYSENTER_EIP            0x176

/* ============================================================================
 *  Section 2: SVM 相关常量
 * ============================================================================ */

#define SVM_MSR_VM_CR                    0xc0010114
#define SVM_MSR_VM_HSAVE_PA              0xc0010117
#define SVM_VM_CR_SVMDIS                 (1UL << 4)
#define SVM_MSR_PERMISSIONS_MAP_SIZE     (PAGE_SIZE * 2)
#define EFER_SVME                        (1UL << 12)

/** RDTSC拦截: Misc1 bit14 = RDTSC, Misc2 bit7 = RDTSCP */
#define SVM_INTERCEPT_MISC1_RDTSC        (1UL << 14)
#define SVM_INTERCEPT_MISC2_RDTSCP       (1UL << 7)
#define SVM_INTERCEPT_MISC1_CPUID        (1UL << 18)
#define SVM_INTERCEPT_MISC1_MSR_PROT     (1UL << 28)
#define SVM_INTERCEPT_MISC2_VMRUN        (1UL << 0)
#define SVM_INTERCEPT_MISC2_VMCALL       (1UL << 1)
#define SVM_NP_ENABLE_NP_ENABLE          (1UL << 0)

/* ============================================================================
 *  Section 3: CPUID 功能号常量
 * ============================================================================ */

#define CPUID_MAX_STANDARD_FN_NUMBER_AND_VENDOR_STRING       0x00000000
#define CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS    0x00000001
#define CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS_EX 0x80000001
#define CPUID_SVM_FEATURES                                   0x8000000a

#define CPUID_FN8000_0001_ECX_SVM                    (1UL << 2)
#define CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT     (1UL << 31)
#define CPUID_FN8000_000A_EDX_NP                     (1UL << 0)

/** Hypervisor自定义CPUID叶 */
#define CPUID_HV_VENDOR_AND_MAX_FUNCTIONS  0x40000000
#define CPUID_HV_INTERFACE                 0x40000001
#define CPUID_HV_MAX                       CPUID_HV_INTERFACE

/** 内部控制命令CPUID叶 */
#define CPUID_UNLOAD_SVM_DEBUG             0x41414141
#define CPUID_UNLOAD_SVM_INSTALL_HOOK      0x41414142
#define CPUID_UNLOAD_SVM_UNINSTALL_HOOK    0x41414143

/* ============================================================================
 *  Section 4: 段描述符与权限常量
 * ============================================================================ */

#define RPL_MASK       3
#define DPL_SYSTEM     0

#ifndef KERNEL_STACK_SIZE
#define KERNEL_STACK_SIZE 0x6000
#endif

/** VMMCALL超级调用magic (用于Trampoline中MOV CRn模拟) */
#define VMMCALL_CR_WRITE_BASE   0x4141FE00
#define VMMCALL_CR_READ_BASE    0x4141FD00

/* ============================================================================
 *  Section 5: VMCB 控制区结构体 (偏移 0x000 - 0x3FF)
 * ============================================================================ */

#pragma pack(push, 1)
typedef struct _VMCB_CONTROL_AREA
{
    UINT16 InterceptCrRead;             /* +0x000 */
    UINT16 InterceptCrWrite;            /* +0x002 */
    UINT16 InterceptDrRead;             /* +0x004 */
    UINT16 InterceptDrWrite;            /* +0x006 */
    UINT32 InterceptException;          /* +0x008 */
    UINT32 InterceptMisc1;              /* +0x00C */
    UINT32 InterceptMisc2;              /* +0x010 */
    UINT32 InterceptMisc3;              /* +0x014 */
    UINT8  Reserved1[0x03C - 0x018];    /* +0x018 */
    UINT16 PauseFilterThreshold;        /* +0x03C */
    UINT16 PauseFilterCount;            /* +0x03E */
    UINT64 IopmBasePa;                  /* +0x040 */
    UINT64 MsrpmBasePa;                 /* +0x048 */
    UINT64 TscOffset;                   /* +0x050 */
    UINT32 GuestAsid;                   /* +0x058 */
    UINT32 TlbControl;                  /* +0x05C */
    UINT64 VIntr;                       /* +0x060 */
    UINT64 InterruptShadow;             /* +0x068 */
    UINT64 ExitCode;                    /* +0x070 */
    UINT64 ExitInfo1;                   /* +0x078 */
    UINT64 ExitInfo2;                   /* +0x080 */
    UINT64 ExitIntInfo;                 /* +0x088 */
    UINT64 NpEnable;                    /* +0x090 */
    UINT64 AvicApicBar;                 /* +0x098 */
    UINT64 GuestPaOfGhcb;              /* +0x0A0 */
    UINT64 EventInj;                    /* +0x0A8 */
    UINT64 NCr3;                        /* +0x0B0 */
    UINT64 LbrVirtualizationEnable;     /* +0x0B8 */
    UINT64 VmcbClean;                   /* +0x0C0 */
    UINT64 NRip;                        /* +0x0C8 */
    UINT8  NumOfBytesFetched;           /* +0x0D0 */
    UINT8  GuestInstructionBytes[15];   /* +0x0D1 */
    UINT64 AvicApicBackingPagePointer;  /* +0x0E0 */
    UINT64 Reserved2;                   /* +0x0E8 */
    UINT64 AvicLogicalTablePointer;     /* +0x0F0 */
    UINT64 AvicPhysicalTablePointer;    /* +0x0F8 */
    UINT64 Reserved3;                   /* +0x100 */
    UINT64 VmcbSaveStatePointer;        /* +0x108 */
    UINT64 VmgExitRax;                  /* +0x110 */
    UINT8  VmgExitCpl;                  /* +0x118 */
    UINT8  VmgExitCplReserved[7];       /* +0x119 */
    UINT16 BusLockThresholdCounter;     /* +0x120 */
    UINT8  BusLockReserved[6];          /* +0x122 */
    UINT8  Reserved128_133[12];         /* +0x128 */
    UINT32 UpdateIrr;                   /* +0x134 */
    UINT64 AllowedSevFeatures;          /* +0x138 */
    UINT64 GuestSevFeatures;            /* +0x140 */
    UINT8  Reserved148_14F[8];          /* +0x148 */
    UINT8  RequestedIrr[32];            /* +0x150 */
    UINT8  Reserved170_3DF[0x3E0 - 0x170];
    UINT8  ReservedForHost[0x400 - 0x3E0];
} VMCB_CONTROL_AREA, *PVMCB_CONTROL_AREA;
#pragma pack(pop)
static_assert(sizeof(VMCB_CONTROL_AREA) == 0x400, "VMCB_CONTROL_AREA Size Mismatch");

/* ============================================================================
 *  Section 6: VMCB 状态保存区结构体 (偏移 0x400 - 0xFFF)
 * ============================================================================ */

#pragma pack(push, 1)
typedef struct _VMCB_STATE_SAVE_AREA
{
    UINT16 EsSelector;  UINT16 EsAttrib;  UINT32 EsLimit;  UINT64 EsBase;
    UINT16 CsSelector;  UINT16 CsAttrib;  UINT32 CsLimit;  UINT64 CsBase;
    UINT16 SsSelector;  UINT16 SsAttrib;  UINT32 SsLimit;  UINT64 SsBase;
    UINT16 DsSelector;  UINT16 DsAttrib;  UINT32 DsLimit;  UINT64 DsBase;
    UINT16 FsSelector;  UINT16 FsAttrib;  UINT32 FsLimit;  UINT64 FsBase;
    UINT16 GsSelector;  UINT16 GsAttrib;  UINT32 GsLimit;  UINT64 GsBase;
    UINT16 GdtrSelector; UINT16 GdtrAttrib; UINT32 GdtrLimit; UINT64 GdtrBase;
    UINT16 LdtrSelector; UINT16 LdtrAttrib; UINT32 LdtrLimit; UINT64 LdtrBase;
    UINT16 IdtrSelector; UINT16 IdtrAttrib; UINT32 IdtrLimit; UINT64 IdtrBase;
    UINT16 TrSelector;  UINT16 TrAttrib;  UINT32 TrLimit;  UINT64 TrBase;
    UINT8  Reserved0[0x0CB - 0x0A0]; UINT8 Cpl; UINT32 Reserved1;
    UINT64 Efer; UINT64 Reserved2;
    UINT64 PerfCtl0; UINT64 PerfCtr0; UINT64 PerfCtl1; UINT64 PerfCtr1;
    UINT64 PerfCtl2; UINT64 PerfCtr2; UINT64 PerfCtl3; UINT64 PerfCtr3;
    UINT64 PerfCtl4; UINT64 PerfCtr4; UINT64 PerfCtl5; UINT64 PerfCtr5;
    UINT64 Reserved3; UINT64 Cr4; UINT64 Cr3; UINT64 Cr0;
    UINT64 Dr7; UINT64 Dr6; UINT64 Rflags; UINT64 Rip;
    UINT8  Reserved4[0x1C0 - 0x180];
    UINT64 InstrRetiredCtr; UINT64 PerfCtrGlobalSts; UINT64 PerfCtrGlobalCtl;
    UINT64 Rsp; UINT64 SCet; UINT64 Ssp; UINT64 IsstAddr; UINT64 Rax;
    UINT64 Star; UINT64 LStar; UINT64 CStar; UINT64 SfMask; UINT64 KernelGsBase;
    UINT64 SysenterCs; UINT64 SysenterEsp; UINT64 SysenterEip; UINT64 Cr2;
    UINT8  Reserved5[0x268 - 0x248];
    UINT64 GPat; UINT64 DbgCtl; UINT64 BrFrom; UINT64 BrTo;
    UINT64 LastExcepFrom; UINT64 LastExcepTo; UINT64 DbgExtnCtl;
    UINT8  Reserved6[0x2E0 - 0x2A0]; UINT64 SpecCtrl;
    UINT8  Reserved7[0x670 - 0x2E8]; UINT8 LbrStack[0x770 - 0x670];
    UINT64 LbrSelect; UINT64 IbsFetchCtl; UINT64 IbsFetchLinaddr;
    UINT64 IbsOpCtl; UINT64 IbsOpRip; UINT64 IbsOpData; UINT64 IbsOpData2;
    UINT64 IbsOpData3; UINT64 IbsDcLinaddr; UINT64 BpIbstgtRip; UINT64 IcIbsExtdCtl;
    UINT8  Reserved8[0xC00 - 0x7C8];
} VMCB_STATE_SAVE_AREA, *PVMCB_STATE_SAVE_AREA;
#pragma pack(pop)
static_assert(sizeof(VMCB_STATE_SAVE_AREA) == 0xC00, "VMCB_STATE_SAVE_AREA Size Mismatch");

/* ============================================================================
 *  Section 7: VMSA / VMCB 复合结构体
 * ============================================================================ */

#pragma pack(push, 1)
typedef struct _VMSA_SAVE_AREA
{
    UINT8 Es[16]; UINT8 Cs[16]; UINT8 Ss[16]; UINT8 Ds[16];
    UINT8 Fs[16]; UINT8 Gs[16]; UINT8 Gdtr[16]; UINT8 Ldtr[16];
    UINT8 Idtr[16]; UINT8 Tr[16];
    UINT64 Pl0Ssp; UINT64 Pl1Ssp; UINT64 Pl2Ssp; UINT64 Pl3Ssp; UINT64 UCet;
    UINT8  Reserved0C8[0x0F0 - 0x0C8]; UINT64 Reserved0F0; UINT8 Reserved0F8[8];
    UINT8  Psr[48][16];
    UINT64 Rsp; UINT8 RspReserved[8]; UINT64 Rdi; UINT8 RdiReserved[8];
    UINT64 Rbp; UINT8 RbpReserved[8]; UINT64 Rsi; UINT8 RsiReserved[8];
    UINT64 Rdx; UINT8 RdxReserved[8]; UINT64 Rcx; UINT8 RcxReserved[8];
    UINT64 Rbx; UINT8 RbxReserved[8];
    UINT64 R8; UINT8 R8Reserved[8]; UINT64 R9; UINT8 R9Reserved[8];
    UINT64 R10; UINT8 R10Reserved[8]; UINT64 R11; UINT8 R11Reserved[8];
    UINT64 R12; UINT8 R12Reserved[8]; UINT64 R13; UINT8 R13Reserved[8];
    UINT64 R14; UINT8 R14Reserved[8]; UINT64 R15; UINT8 R15Reserved[8];
    UINT8  ReservedGpr[16];
    UINT64 GuestExitInfo1; UINT8 Gei1Reserved[8];
    UINT64 GuestExitInfo2; UINT8 Gei2Reserved[8];
    UINT64 GuestExitInfo3; UINT8 Gei3Reserved[8];
    UINT64 GuestExitInfo4; UINT8 Gei4Reserved[8];
    UINT8  Reserved540_BFF[0xC00 - 0x540];
} VMSA_SAVE_AREA, *PVMSA_SAVE_AREA;
#pragma pack(pop)
static_assert(sizeof(VMSA_SAVE_AREA) == 0xC00, "VMSA_SAVE_AREA Size Mismatch");

typedef struct _VMCB { VMCB_CONTROL_AREA ControlArea; VMCB_STATE_SAVE_AREA StateSaveArea; } VMCB, *PVMCB;
static_assert(sizeof(VMCB) == 0x1000, "VMCB Size Mismatch");

/* ============================================================================
 *  Section 8: Guest GPR / 段描述符 / 事件注入 辅助结构体
 * ============================================================================ */

typedef struct _GUEST_GPR
{
    UINT64 Rax; UINT64 Rbx; UINT64 Rcx; UINT64 Rdx;
    UINT64 Rsi; UINT64 Rdi; UINT64 Rbp;
    UINT64 R8; UINT64 R9; UINT64 R10; UINT64 R11;
    UINT64 R12; UINT64 R13; UINT64 R14; UINT64 R15;
} GUEST_GPR, *PGUEST_GPR;

typedef struct _SEGMENT_DESCRIPTOR
{
    union {
        UINT64 AsUInt64; struct {
            UINT16 LimitLow : 16; UINT16 BaseLow : 16; UINT32 BaseMiddle : 8; UINT32 Type : 4;
            UINT32 System : 1; UINT32 Dpl : 2; UINT32 Present : 1; UINT32 LimitHigh : 4;
            UINT32 Avl : 1; UINT32 LongMode : 1; UINT32 DefaultBit : 1; UINT32 Granularity : 1;
            UINT32 BaseHigh : 8;
        } Fields;
    };
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;

typedef struct _SEGMENT_ATTRIBUTE
{
    union {
        UINT16 AsUInt16; struct {
            UINT16 Type : 4; UINT16 System : 1; UINT16 Dpl : 2; UINT16 Present : 1;
            UINT16 Avl : 1; UINT16 LongMode : 1; UINT16 DefaultBit : 1; UINT16 Granularity : 1;
            UINT16 Reserved1 : 4;
        } Fields;
    };
} SEGMENT_ATTRIBUTE, *PSEGMENT_ATTRIBUTE;

typedef struct _EVENTINJ
{
    union {
        UINT64 AsUInt64; struct {
            UINT64 Vector : 8; UINT64 Type : 3; UINT64 ErrorCodeValid : 1;
            UINT64 Reserved1 : 19; UINT64 Valid : 1; UINT64 ErrorCode : 32;
        } Fields;
    };
} EVENTINJ, *PEVENTINJ;
static_assert(sizeof(EVENTINJ) == 8, "EVENTINJ Size Mismatch");

/* ============================================================================
 *  Section 9: VMEXIT 退出码定义
 * ============================================================================ */

#define VMEXIT_CR0_READ         0x0000
#define VMEXIT_CR0_WRITE        0x0010
#define VMEXIT_EXCEPTION_DE     0x0040
#define VMEXIT_EXCEPTION_DB     0x0041
#define VMEXIT_EXCEPTION_NMI    0x0042
#define VMEXIT_EXCEPTION_BP     0x0043
#define VMEXIT_EXCEPTION_GP     0x004d
#define VMEXIT_EXCEPTION_PF     0x004e
#define VMEXIT_INTR             0x0060
#define VMEXIT_NMI              0x0061
#define VMEXIT_SMI              0x0062
#define VMEXIT_INIT             0x0063
#define VMEXIT_VINTR            0x0064
#define VMEXIT_CR0_SEL_WRITE    0x0065
#define VMEXIT_IDTR_WRITE       0x006a
#define VMEXIT_GDTR_WRITE       0x006b
#define VMEXIT_RDTSC            0x006e
#define VMEXIT_CPUID            0x0072
#define VMEXIT_INVD             0x0076
#define VMEXIT_HLT              0x0078
#define VMEXIT_IOIO             0x007b
#define VMEXIT_MSR              0x007c
#define VMEXIT_SHUTDOWN         0x007f
#define VMEXIT_VMRUN            0x0080
#define VMEXIT_VMMCALL          0x0081
#define VMEXIT_VMLOAD           0x0082
#define VMEXIT_VMSAVE           0x0083
#define VMEXIT_STGI             0x0084
#define VMEXIT_CLGI             0x0085
#define VMEXIT_RDTSCP           0x0087
#define VMEXIT_WBINVD           0x0089
#define VMEXIT_XSETBV           0x008d
#define VMEXIT_NPF              0x0400
#define VMEXIT_INVALID          -1

/* ============================================================================
 *  Section 10: SVM 状态枚举与函数声明
 * ============================================================================ */

typedef enum _SVM_STATUS { SVM_ALLOWED = 0, SVM_NOT_AVAIL, SVM_DISABLED_BY_BIOS, SVM_DISABLED_WITH_KEY } SVM_STATUS;

void CommGetCPUName(char* vendor, SIZE_T size);
BOOLEAN CommCheckIntelBios();
BOOLEAN CommCheckAMDBios();
BOOLEAN CommCheckIntelCpuid();
BOOLEAN CommCheckAMDCpuid();
BOOLEAN CommCheckCr4();
BOOLEAN CommCheckAMDLock();
BOOLEAN CommCheckIntelsupport();
BOOLEAN CommCheckAMDsupport();
BOOLEAN CommCheckAMDSvmlFeature();

/**
 * @brief SVM调试输出函数 - 带[SvmDebug]前缀的格式化打印
 * @author yewilliam
 * @date 2026/03/16
 * @param [in] Format - printf格式字符串
 * @param [in] ...    - 可变参数
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
static inline VOID SvmDebugPrint(_In_z_ _Printf_format_string_ PCSTR Format, ...)
{
    va_list argList;
    va_start(argList, Format);
    vDbgPrintExWithPrefix("[SvmDebug] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, argList);
    va_end(argList);
}
