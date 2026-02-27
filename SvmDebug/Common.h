#pragma once
#pragma once
#include <basetsd.h>
#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>
#include <stdarg.h>

#define MSR_IA32_INTEL_FEATURE_CONTROL 0x3a
#define SVM_MSR_PERMISSIONS_MAP_SIZE    (PAGE_SIZE * 2)
#define IA32_MSR_PAT    0x00000277
#define IA32_MSR_EFER   0xc0000080

#define EFER_SVME       (1UL << 12)

#define RPL_MASK        3
#define DPL_SYSTEM      0

#define CPUID_FN8000_0001_ECX_SVM                   (1UL << 2)
#define CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT    (1UL << 31)
#define CPUID_FN8000_000A_EDX_NP                    (1UL << 0)
#define CPUID_MAX_STANDARD_FN_NUMBER_AND_VENDOR_STRING          0x00000000
#define CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS       0x00000001
#define CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS_EX    0x80000001
#define CPUID_SVM_FEATURES                                      0x8000000a
#define CPUID_HV_VENDOR_AND_MAX_FUNCTIONS   0x40000000
#define CPUID_HV_INTERFACE                  0x40000001
#define CPUID_UNLOAD_SIMPLE_SVM     0x41414141
#define CPUID_HV_MAX                CPUID_HV_INTERFACE

#define SVM_MSR_VM_CR                   0xc0010114

#define SVM_MSR_VM_HSAVE_PA             0xc0010117
#define SVM_VM_CR_SVMDIS                (1UL << 4)
#ifndef KERNEL_STACK_SIZE
#define KERNEL_STACK_SIZE 0x6000  // 24KB
#endif

#define SVM_INTERCEPT_MISC1_CPUID       (1UL << 18)
#define SVM_INTERCEPT_MISC1_MSR_PROT    (1UL << 28)
#define SVM_INTERCEPT_MISC2_VMRUN       (1UL << 0)
#define SVM_NP_ENABLE_NP_ENABLE         (1UL << 0)
#define CPUID_HV_VENDOR_AND_MAX_FUNCTIONS 0x40000000
#define MSR_STAR               0xC0000081
#define MSR_LSTAR              0xC0000082
#define MSR_CSTAR              0xC0000083
#define MSR_SFMASK             0xC0000084
#define MSR_KERNEL_GS_BASE     0xC0000102
#define MSR_IA32_SYSENTER_CS    0x174
#define MSR_IA32_SYSENTER_ESP   0x175
#define MSR_IA32_SYSENTER_EIP   0x176
#define MSR_IA32_FS_BASE       0xC0000100
#define MSR_IA32_GS_BASE       0xC0000101
#define MSR_IA32_KERNEL_GS_BASE 0xC0000102


#pragma pack(push, 1)
typedef struct _VMCB_CONTROL_AREA
{
    UINT16 InterceptCrRead;             // +0x000
    UINT16 InterceptCrWrite;            // +0x002
    UINT16 InterceptDrRead;             // +0x004
    UINT16 InterceptDrWrite;            // +0x006
    UINT32 InterceptException;          // +0x008
    UINT32 InterceptMisc1;              // +0x00c
    UINT32 InterceptMisc2;              // +0x010
    UINT32 InterceptMisc3;              // +0x014
    UINT8  Reserved1[0x03c - 0x018];    // +0x018
    UINT16 PauseFilterThreshold;        // +0x03c
    UINT16 PauseFilterCount;            // +0x03e
    UINT64 IopmBasePa;                  // +0x040
    UINT64 MsrpmBasePa;                 // +0x048
    UINT64 TscOffset;                   // +0x050
    UINT32 GuestAsid;                   // +0x058
    UINT32 TlbControl;                  // +0x05c
    UINT64 VIntr;                       // +0x060
    UINT64 InterruptShadow;             // +0x068
    UINT64 ExitCode;                    // +0x070
    UINT64 ExitInfo1;                   // +0x078
    UINT64 ExitInfo2;                   // +0x080
    UINT64 ExitIntInfo;                 // +0x088
    UINT64 NpEnable;                    // +0x090
    UINT64 AvicApicBar;                 // +0x098
    UINT64 GuestPaOfGhcb;               // +0x0a0
    UINT64 EventInj;                    // +0x0a8
    UINT64 NCr3;                        // +0x0b0
    UINT64 LbrVirtualizationEnable;     // +0x0b8
    UINT64 VmcbClean;                   // +0x0c0
    UINT64 NRip;                        // +0x0c8
    UINT8  NumOfBytesFetched;           // +0x0d0
    UINT8  GuestInstructionBytes[15];   // +0x0d1
    UINT64 AvicApicBackingPagePointer;  // +0x0e0
    UINT64 Reserved2;                   // +0x0e8
    UINT64 AvicLogicalTablePointer;     // +0x0f0
    UINT64 AvicPhysicalTablePointer;    // +0x0f8
    UINT64 Reserved3;                   // +0x100
    UINT64 VmcbSaveStatePointer;        // +0x108
    UINT64 VmgExitRax;                  // +0x110
    UINT8  VmgExitCpl;                  // +0x118
    UINT8  VmgExitCplReserved[7];       // +0x119
    UINT16 BusLockThresholdCounter;     // +0x120
    UINT8  BusLockReserved[6];          // +0x122
    UINT8  Reserved128_133[12];         // +0x128
    UINT32 UpdateIrr;                   // +0x134
    UINT64 AllowedSevFeatures;          // +0x138
    UINT64 GuestSevFeatures;            // +0x140
    UINT8  Reserved148_14F[8];          // +0x148
    UINT8  RequestedIrr[32];            // +0x150
    UINT8  Reserved170_3DF[0x3E0 - 0x170];
    UINT8  ReservedForHost[0x400 - 0x3E0];
} VMCB_CONTROL_AREA, * PVMCB_CONTROL_AREA;
#pragma pack(pop)
static_assert(sizeof(VMCB_CONTROL_AREA) == 0x400, "VMCB_CONTROL_AREA Size Mismatch");


#pragma pack(push, 1)
typedef struct _VMCB_STATE_SAVE_AREA
{
    UINT16 EsSelector;                  // +0x000
    UINT16 EsAttrib;                    // +0x002
    UINT32 EsLimit;                     // +0x004
    UINT64 EsBase;                      // +0x008
    UINT16 CsSelector;                  // +0x010
    UINT16 CsAttrib;                    // +0x012
    UINT32 CsLimit;                     // +0x014
    UINT64 CsBase;                      // +0x018
    UINT16 SsSelector;                  // +0x020
    UINT16 SsAttrib;                    // +0x022
    UINT32 SsLimit;                     // +0x024
    UINT64 SsBase;                      // +0x028
    UINT16 DsSelector;                  // +0x030
    UINT16 DsAttrib;                    // +0x032
    UINT32 DsLimit;                     // +0x034
    UINT64 DsBase;                      // +0x038
    UINT16 FsSelector;                  // +0x040
    UINT16 FsAttrib;                    // +0x042
    UINT32 FsLimit;                     // +0x044
    UINT64 FsBase;                      // +0x048
    UINT16 GsSelector;                  // +0x050
    UINT16 GsAttrib;                    // +0x052
    UINT32 GsLimit;                     // +0x054
    UINT64 GsBase;                      // +0x058
    UINT16 GdtrSelector;                // +0x060
    UINT16 GdtrAttrib;                  // +0x062
    UINT32 GdtrLimit;                   // +0x064
    UINT64 GdtrBase;                    // +0x068
    UINT16 LdtrSelector;                // +0x070
    UINT16 LdtrAttrib;                  // +0x072
    UINT32 LdtrLimit;                   // +0x074
    UINT64 LdtrBase;                    // +0x078
    UINT16 IdtrSelector;                // +0x080
    UINT16 IdtrAttrib;                  // +0x082
    UINT32 IdtrLimit;                   // +0x084
    UINT64 IdtrBase;                    // +0x088
    UINT16 TrSelector;                  // +0x090
    UINT16 TrAttrib;                    // +0x092
    UINT32 TrLimit;                     // +0x094
    UINT64 TrBase;                      // +0x098
    UINT8  Reserved0[0x0CB - 0x0A0];    // +0x0A0
    UINT8  Cpl;                         // +0x0CB
    UINT32 Reserved1;                   // +0x0CC
    UINT64 Efer;                        // +0x0D0
    UINT64 Reserved2;                   // +0x0D8
    UINT64 PerfCtl0;                    // +0x0E0
    UINT64 PerfCtr0;                    // +0x0E8
    UINT64 PerfCtl1;                    // +0x0F0
    UINT64 PerfCtr1;                    // +0x0F8
    UINT64 PerfCtl2;                    // +0x100
    UINT64 PerfCtr2;                    // +0x108
    UINT64 PerfCtl3;                    // +0x110
    UINT64 PerfCtr3;                    // +0x118
    UINT64 PerfCtl4;                    // +0x120
    UINT64 PerfCtr4;                    // +0x128
    UINT64 PerfCtl5;                    // +0x130
    UINT64 PerfCtr5;                    // +0x138
    UINT64 Reserved3;                   // +0x140
    UINT64 Cr4;                         // +0x148
    UINT64 Cr3;                         // +0x150
    UINT64 Cr0;                         // +0x158
    UINT64 Dr7;                         // +0x160
    UINT64 Dr6;                         // +0x168
    UINT64 Rflags;                      // +0x170
    UINT64 Rip;                         // +0x178
    UINT8  Reserved4[0x1C0 - 0x180];    // +0x180
    UINT64 InstrRetiredCtr;             // +0x1C0
    UINT64 PerfCtrGlobalSts;            // +0x1C8
    UINT64 PerfCtrGlobalCtl;            // +0x1D0
    UINT64 Rsp;                         // +0x1D8
    UINT64 SCet;                        // +0x1E0
    UINT64 Ssp;                         // +0x1E8
    UINT64 IsstAddr;                    // +0x1F0
    UINT64 Rax;                         // +0x1F8
    UINT64 Star;                        // +0x200
    UINT64 LStar;                       // +0x208
    UINT64 CStar;                       // +0x210
    UINT64 SfMask;                      // +0x218
    UINT64 KernelGsBase;                // +0x220
    UINT64 SysenterCs;                  // +0x228
    UINT64 SysenterEsp;                 // +0x230
    UINT64 SysenterEip;                 // +0x238
    UINT64 Cr2;                         // +0x240
    UINT8  Reserved5[0x268 - 0x248];    // +0x248
    UINT64 GPat;                        // +0x268
    UINT64 DbgCtl;                      // +0x270
    UINT64 BrFrom;                      // +0x278
    UINT64 BrTo;                        // +0x280
    UINT64 LastExcepFrom;               // +0x288
    UINT64 LastExcepTo;                 // +0x290
    UINT64 DbgExtnCtl;                  // +0x298
    UINT8  Reserved6[0x2E0 - 0x2A0];    // +0x2A0
    UINT64 SpecCtrl;                    // +0x2E0
    UINT8  Reserved7[0x670 - 0x2E8];    // +0x2E8
    UINT8  LbrStack[0x770 - 0x670];     // +0x670
    UINT64 LbrSelect;                   // +0x770
    UINT64 IbsFetchCtl;                 // +0x778
    UINT64 IbsFetchLinaddr;             // +0x780
    UINT64 IbsOpCtl;                    // +0x788
    UINT64 IbsOpRip;                    // +0x790
    UINT64 IbsOpData;                   // +0x798
    UINT64 IbsOpData2;                  // +0x7A0
    UINT64 IbsOpData3;                  // +0x7A8
    UINT64 IbsDcLinaddr;                // +0x7B0
    UINT64 BpIbstgtRip;                 // +0x7B8
    UINT64 IcIbsExtdCtl;                // +0x7C0
    UINT8  Reserved8[0xC00 - 0x7C8];    // +0x7C8
} VMCB_STATE_SAVE_AREA, * PVMCB_STATE_SAVE_AREA;
#pragma pack(pop)
static_assert(sizeof(VMCB_STATE_SAVE_AREA) == 0xC00,
    "VMCB_STATE_SAVE_AREA Size Mismatch");

//
//
//
#pragma pack(push, 1)
typedef struct _VMSA_SAVE_AREA
{
    UINT8  Es[16];                      // +0x000
    UINT8  Cs[16];                      // +0x010
    UINT8  Ss[16];                      // +0x020
    UINT8  Ds[16];                      // +0x030
    UINT8  Fs[16];                      // +0x040
    UINT8  Gs[16];                      // +0x050
    UINT8  Gdtr[16];                    // +0x060
    UINT8  Ldtr[16];                    // +0x070
    UINT8  Idtr[16];                    // +0x080
    UINT8  Tr[16];                      // +0x090

    UINT64 Pl0Ssp;                       // +0x0A0
    UINT64 Pl1Ssp;                       // +0x0A8
    UINT64 Pl2Ssp;                       // +0x0B0
    UINT64 Pl3Ssp;                       // +0x0B8
    UINT64 UCet;                         // +0x0C0

    UINT8  Reserved0C8[0x0F0 - 0x0C8];   // +0x0C8

    UINT64 Reserved0F0;                   // +0x0F0
    UINT8  Reserved0F8[8];                // +0x0F8

    UINT8  Psr[48][16];                   // +0x100

    UINT64 Rsp;                           // +0x400
    UINT8  RspReserved[8];                 // +0x408
    UINT64 Rdi;                           // +0x410
    UINT8  RdiReserved[8];                 // +0x418
    UINT64 Rbp;                           // +0x420
    UINT8  RbpReserved[8];                 // +0x428
    UINT64 Rsi;                           // +0x430
    UINT8  RsiReserved[8];                 // +0x438
    UINT64 Rdx;                           // +0x440
    UINT8  RdxReserved[8];                 // +0x448
    UINT64 Rcx;                           // +0x450
    UINT8  RcxReserved[8];                 // +0x458
    UINT64 Rbx;                           // +0x460
    UINT8  RbxReserved[8];                 // +0x468
    UINT64 R8;                            // +0x470
    UINT8  R8Reserved[8];                  // +0x478
    UINT64 R9;                            // +0x480
    UINT8  R9Reserved[8];                  // +0x488
    UINT64 R10;                           // +0x490
    UINT8  R10Reserved[8];                 // +0x498
    UINT64 R11;                           // +0x4A0
    UINT8  R11Reserved[8];                 // +0x4A8
    UINT64 R12;                           // +0x4B0
    UINT8  R12Reserved[8];                 // +0x4B8
    UINT64 R13;                           // +0x4C0
    UINT8  R13Reserved[8];                 // +0x4C8
    UINT64 R14;                           // +0x4D0
    UINT8  R14Reserved[8];                 // +0x4D8
    UINT64 R15;                           // +0x4E0
    UINT8  R15Reserved[8];                 // +0x4E8
    UINT8  ReservedGpr[16];                // +0x4F0
    UINT64 GuestExitInfo1;                 // +0x500
    UINT8  Gei1Reserved[8];                // +0x508
    UINT64 GuestExitInfo2;                 // +0x510
    UINT8  Gei2Reserved[8];                // +0x518
    UINT64 GuestExitInfo3;                 // +0x520
    UINT8  Gei3Reserved[8];                // +0x528
    UINT64 GuestExitInfo4;                 // +0x530
    UINT8  Gei4Reserved[8];                // +0x538

    UINT8  Reserved540_BFF[0xC00 - 0x540]; // +0x540
} VMSA_SAVE_AREA, * PVMSA_SAVE_AREA;
#pragma pack(pop)

static_assert(sizeof(VMSA_SAVE_AREA) == 0xC00, "VMSA_SAVE_AREA Size Mismatch");
typedef struct _VMCB
{
    VMCB_CONTROL_AREA    ControlArea;      // 0x000 - 0x3FF
    VMCB_STATE_SAVE_AREA StateSaveArea;    // 0x400 - 0xFFF
} VMCB, * PVMCB;
static_assert(sizeof(VMCB) == 0x1000, "VMCB Size Mismatch");

typedef struct _GUEST_GPR
{
    UINT64 Rax;   // 0x00
    UINT64 Rbx;   // 0x08
    UINT64 Rcx;   // 0x10
    UINT64 Rdx;   // 0x18
    UINT64 Rsi;   // 0x20
    UINT64 Rdi;   // 0x28
    UINT64 Rbp;   // 0x30
    UINT64 R8;    // 0x38
    UINT64 R9;    // 0x40
    UINT64 R10;   // 0x48
    UINT64 R11;   // 0x50
    UINT64 R12;   // 0x58
    UINT64 R13;   // 0x60
    UINT64 R14;   // 0x68
    UINT64 R15;   // 0x70
} GUEST_GPR, * PGUEST_GPR;

typedef struct _SEGMENT_DESCRIPTOR
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT16 LimitLow : 16;
            UINT16 BaseLow : 16;
            UINT32 BaseMiddle : 8;
            UINT32 Type : 4;
            UINT32 System : 1;
            UINT32 Dpl : 2;
            UINT32 Present : 1;
            UINT32 LimitHigh : 4;
            UINT32 Avl : 1;
            UINT32 LongMode : 1;
            UINT32 DefaultBit : 1;
            UINT32 Granularity : 1;
            UINT32 BaseHigh : 8;
        } Fields;
    };
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

typedef struct _SEGMENT_ATTRIBUTE
{
    union
    {
        UINT16 AsUInt16;
        struct
        {
            UINT16 Type : 4;
            UINT16 System : 1;
            UINT16 Dpl : 2;
            UINT16 Present : 1;
            UINT16 Avl : 1;
            UINT16 LongMode : 1;
            UINT16 DefaultBit : 1;
            UINT16 Granularity : 1;
            UINT16 Reserved1 : 4;
        } Fields;
    };
} SEGMENT_ATTRIBUTE, * PSEGMENT_ATTRIBUTE;

typedef struct _EVENTINJ
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT64 Vector : 8;          // [0:7]
            UINT64 Type : 3;            // [8:10]
            UINT64 ErrorCodeValid : 1;  // [11]
            UINT64 Reserved1 : 19;      // [12:30]
            UINT64 Valid : 1;           // [31]
            UINT64 ErrorCode : 32;      // [32:63]
        } Fields;
    };
} EVENTINJ, * PEVENTINJ;
static_assert(sizeof(EVENTINJ) == 8,
    "EVENTINJ Size Mismatch");

#define VMEXIT_CR0_READ             0x0000
#define VMEXIT_CR1_READ             0x0001
#define VMEXIT_CR2_READ             0x0002
#define VMEXIT_CR3_READ             0x0003
#define VMEXIT_CR4_READ             0x0004
#define VMEXIT_CR5_READ             0x0005
#define VMEXIT_CR6_READ             0x0006
#define VMEXIT_CR7_READ             0x0007
#define VMEXIT_CR8_READ             0x0008
#define VMEXIT_CR9_READ             0x0009
#define VMEXIT_CR10_READ            0x000a
#define VMEXIT_CR11_READ            0x000b
#define VMEXIT_CR12_READ            0x000c
#define VMEXIT_CR13_READ            0x000d
#define VMEXIT_CR14_READ            0x000e
#define VMEXIT_CR15_READ            0x000f
#define VMEXIT_CR0_WRITE            0x0010
#define VMEXIT_CR1_WRITE            0x0011
#define VMEXIT_CR2_WRITE            0x0012
#define VMEXIT_CR3_WRITE            0x0013
#define VMEXIT_CR4_WRITE            0x0014
#define VMEXIT_CR5_WRITE            0x0015
#define VMEXIT_CR6_WRITE            0x0016
#define VMEXIT_CR7_WRITE            0x0017
#define VMEXIT_CR8_WRITE            0x0018
#define VMEXIT_CR9_WRITE            0x0019
#define VMEXIT_CR10_WRITE           0x001a
#define VMEXIT_CR11_WRITE           0x001b
#define VMEXIT_CR12_WRITE           0x001c
#define VMEXIT_CR13_WRITE           0x001d
#define VMEXIT_CR14_WRITE           0x001e
#define VMEXIT_CR15_WRITE           0x001f
#define VMEXIT_DR0_READ             0x0020
#define VMEXIT_DR1_READ             0x0021
#define VMEXIT_DR2_READ             0x0022
#define VMEXIT_DR3_READ             0x0023
#define VMEXIT_DR4_READ             0x0024
#define VMEXIT_DR5_READ             0x0025
#define VMEXIT_DR6_READ             0x0026
#define VMEXIT_DR7_READ             0x0027
#define VMEXIT_DR8_READ             0x0028
#define VMEXIT_DR9_READ             0x0029
#define VMEXIT_DR10_READ            0x002a
#define VMEXIT_DR11_READ            0x002b
#define VMEXIT_DR12_READ            0x002c
#define VMEXIT_DR13_READ            0x002d
#define VMEXIT_DR14_READ            0x002e
#define VMEXIT_DR15_READ            0x002f
#define VMEXIT_DR0_WRITE            0x0030
#define VMEXIT_DR1_WRITE            0x0031
#define VMEXIT_DR2_WRITE            0x0032
#define VMEXIT_DR3_WRITE            0x0033
#define VMEXIT_DR4_WRITE            0x0034
#define VMEXIT_DR5_WRITE            0x0035
#define VMEXIT_DR6_WRITE            0x0036
#define VMEXIT_DR7_WRITE            0x0037
#define VMEXIT_DR8_WRITE            0x0038
#define VMEXIT_DR9_WRITE            0x0039
#define VMEXIT_DR10_WRITE           0x003a
#define VMEXIT_DR11_WRITE           0x003b
#define VMEXIT_DR12_WRITE           0x003c
#define VMEXIT_DR13_WRITE           0x003d
#define VMEXIT_DR14_WRITE           0x003e
#define VMEXIT_DR15_WRITE           0x003f
#define VMEXIT_EXCEPTION_DE         0x0040
#define VMEXIT_EXCEPTION_DB         0x0041
#define VMEXIT_EXCEPTION_NMI        0x0042
#define VMEXIT_EXCEPTION_BP         0x0043
#define VMEXIT_EXCEPTION_OF         0x0044
#define VMEXIT_EXCEPTION_BR         0x0045
#define VMEXIT_EXCEPTION_UD         0x0046
#define VMEXIT_EXCEPTION_NM         0x0047
#define VMEXIT_EXCEPTION_DF         0x0048
#define VMEXIT_EXCEPTION_09         0x0049
#define VMEXIT_EXCEPTION_TS         0x004a
#define VMEXIT_EXCEPTION_NP         0x004b
#define VMEXIT_EXCEPTION_SS         0x004c
#define VMEXIT_EXCEPTION_GP         0x004d
#define VMEXIT_EXCEPTION_PF         0x004e
#define VMEXIT_EXCEPTION_15         0x004f
#define VMEXIT_EXCEPTION_MF         0x0050
#define VMEXIT_EXCEPTION_AC         0x0051
#define VMEXIT_EXCEPTION_MC         0x0052
#define VMEXIT_EXCEPTION_XF         0x0053
#define VMEXIT_EXCEPTION_20         0x0054
#define VMEXIT_EXCEPTION_21         0x0055
#define VMEXIT_EXCEPTION_22         0x0056
#define VMEXIT_EXCEPTION_23         0x0057
#define VMEXIT_EXCEPTION_24         0x0058
#define VMEXIT_EXCEPTION_25         0x0059
#define VMEXIT_EXCEPTION_26         0x005a
#define VMEXIT_EXCEPTION_27         0x005b
#define VMEXIT_EXCEPTION_28         0x005c
#define VMEXIT_EXCEPTION_VC         0x005d
#define VMEXIT_EXCEPTION_SX         0x005e
#define VMEXIT_EXCEPTION_31         0x005f
#define VMEXIT_INTR                 0x0060
#define VMEXIT_NMI                  0x0061
#define VMEXIT_SMI                  0x0062
#define VMEXIT_INIT                 0x0063
#define VMEXIT_VINTR                0x0064
#define VMEXIT_CR0_SEL_WRITE        0x0065
#define VMEXIT_IDTR_READ            0x0066
#define VMEXIT_GDTR_READ            0x0067
#define VMEXIT_LDTR_READ            0x0068
#define VMEXIT_TR_READ              0x0069
#define VMEXIT_IDTR_WRITE           0x006a
#define VMEXIT_GDTR_WRITE           0x006b
#define VMEXIT_LDTR_WRITE           0x006c
#define VMEXIT_TR_WRITE             0x006d
#define VMEXIT_RDTSC                0x006e
#define VMEXIT_RDPMC                0x006f
#define VMEXIT_PUSHF                0x0070
#define VMEXIT_POPF                 0x0071
#define VMEXIT_CPUID                0x0072
#define VMEXIT_RSM                  0x0073
#define VMEXIT_IRET                 0x0074
#define VMEXIT_SWINT                0x0075
#define VMEXIT_INVD                 0x0076
#define VMEXIT_PAUSE                0x0077
#define VMEXIT_HLT                  0x0078
#define VMEXIT_INVLPG               0x0079
#define VMEXIT_INVLPGA              0x007a
#define VMEXIT_IOIO                 0x007b
#define VMEXIT_MSR                  0x007c
#define VMEXIT_TASK_SWITCH          0x007d
#define VMEXIT_FERR_FREEZE          0x007e
#define VMEXIT_SHUTDOWN             0x007f
#define VMEXIT_VMRUN                0x0080
#define VMEXIT_VMMCALL              0x0081
#define VMEXIT_VMLOAD               0x0082
#define VMEXIT_VMSAVE               0x0083
#define VMEXIT_STGI                 0x0084
#define VMEXIT_CLGI                 0x0085
#define VMEXIT_SKINIT               0x0086
#define VMEXIT_RDTSCP               0x0087
#define VMEXIT_ICEBP                0x0088
#define VMEXIT_WBINVD               0x0089
#define VMEXIT_MONITOR              0x008a
#define VMEXIT_MWAIT                0x008b
#define VMEXIT_MWAIT_CONDITIONAL    0x008c
#define VMEXIT_XSETBV               0x008d
#define VMEXIT_EFER_WRITE_TRAP      0x008f
#define VMEXIT_CR0_WRITE_TRAP       0x0090
#define VMEXIT_CR1_WRITE_TRAP       0x0091
#define VMEXIT_CR2_WRITE_TRAP       0x0092
#define VMEXIT_CR3_WRITE_TRAP       0x0093
#define VMEXIT_CR4_WRITE_TRAP       0x0094
#define VMEXIT_CR5_WRITE_TRAP       0x0095
#define VMEXIT_CR6_WRITE_TRAP       0x0096
#define VMEXIT_CR7_WRITE_TRAP       0x0097
#define VMEXIT_CR8_WRITE_TRAP       0x0098
#define VMEXIT_CR9_WRITE_TRAP       0x0099
#define VMEXIT_CR10_WRITE_TRAP      0x009a
#define VMEXIT_CR11_WRITE_TRAP      0x009b
#define VMEXIT_CR12_WRITE_TRAP      0x009c
#define VMEXIT_CR13_WRITE_TRAP      0x009d
#define VMEXIT_CR14_WRITE_TRAP      0x009e
#define VMEXIT_CR15_WRITE_TRAP      0x009f
#define VMEXIT_NPF                  0x0400
#define AVIC_INCOMPLETE_IPI         0x0401
#define AVIC_NOACCEL                0x0402
#define VMEXIT_VMGEXIT              0x0403
#define VMEXIT_INVALID              -1


void CommGetCPUName(char* vendor, SIZE_T size);
BOOLEAN CommCheckIntelBios();
BOOLEAN CommCheckAMDBios();
BOOLEAN CommCheckIntelCpuid();
BOOLEAN CommCheckAMDCpuid();
BOOLEAN CommCheckCr4();
BOOLEAN CommCheckAMDLock();
BOOLEAN CommCheckIntelsupport();
BOOLEAN CommCheckAMDsupport();



_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
static inline VOID SvmDebugPrint(
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
)
{
    
    va_list argList;

    va_start(argList, Format);
    vDbgPrintExWithPrefix("[SvmDebug] ",
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        Format,
        argList);
    va_end(argList);
    return;
}
