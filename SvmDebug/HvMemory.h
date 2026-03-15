/**
 * @file HvMemory.h
 * @brief 超级调用内存操作头文件 - 通信结构体与接口声明
 * @author yewilliam
 * @date 2026/02/06
 */

#pragma once
#include <ntifs.h>
#include "Common.h"

/* ========================================================================
 *  Hypervisor Memory R/W Interface *   *  Architecture: *  CE (R3) -> IOCTL -> Driver (R0) -> CPUID hypercall -> VMM (Host) *  VMM walks target CR3 page tables, does physical memory copy *  ACE cannot see any of this - no syscall, no kernel API called
 * ======================================================================== */

// CPUID leaf for memory operations
#define CPUID_HV_MEMORY_OP          0x41414150

// Sub-commands (passed in ECX)
#define HV_MEM_OP_READ              0x01
#define HV_MEM_OP_WRITE             0x02
#define HV_MEM_OP_GET_MODULE_BASE   0x03
#define HV_MEM_OP_GET_PEB           0x04

// IOCTL codes for R3 communication
#define IOCTL_HV_READ_MEMORY   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_WRITE_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_GET_MODULE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)

// R3 <-> R0 communication structure for memory operations
typedef struct _HV_MEMORY_REQUEST {
    ULONG64 TargetPid;         // PID of target process
    ULONG64 Address;           // Virtual address in target process
    ULONG64 Size;              // Number of bytes to read/write
    ULONG64 BufferAddress;     // User-mode buffer address (in caller)
} HV_MEMORY_REQUEST, * PHV_MEMORY_REQUEST;

// Internal structure passed to VMM via shared memory
// (since CPUID only has 4 registers, we use a shared page)
typedef struct _HV_RW_CONTEXT {
    ULONG64 TargetCr3;        // CR3 of target process
    ULONG64 SourceVa;         // VA to read from (or write to) in target
    ULONG64 DestPa;           // Physical address of kernel buffer
    ULONG64 Size;             // Bytes to transfer
    ULONG64 IsWrite;          // 0 = read, 1 = write
    volatile LONG Status;     // Result: 0 = success, negative = error
} HV_RW_CONTEXT, * PHV_RW_CONTEXT;

// Forward declarations
typedef struct _VCPU_CONTEXT VCPU_CONTEXT, * PVCPU_CONTEXT;

// VMM-level functions (run in Host context during VMEXIT)
VOID HvHandleMemoryOp(PVCPU_CONTEXT vpData);

// Driver-level functions (run in Guest context at PASSIVE_LEVEL)
NTSTATUS HvReadProcessMemory(ULONG64 TargetPid, PVOID Address, PVOID Buffer, SIZE_T Size);
NTSTATUS HvWriteProcessMemory(ULONG64 TargetPid, PVOID Address, PVOID Buffer, SIZE_T Size);

// Shared context page (allocated once, used for VMM communication)
extern PHV_RW_CONTEXT g_HvSharedContext;
extern ULONG64 g_HvSharedContextPa;

NTSTATUS HvInitSharedContext();
VOID HvFreeSharedContext();
