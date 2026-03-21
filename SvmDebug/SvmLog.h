/**
 * @file SvmLog.h
 * @brief SVM 日志系统 - 内核环形缓冲区 + R3 IOCTL 通信
 * @author yewilliam
 * @date 2026/03/21
 *
 * DEBUG=1: SvmDebugPrint -> DbgPrint (本地内核调试输出)
 * DEBUG=0: SvmDebugPrint -> 环形缓冲区 -> R3 通过 IOCTL 轮询读取
 *
 * R0端: ntifs.h 已提供 CTL_CODE
 * R3端: windows.h 已提供 CTL_CODE
 * 因此本文件不需要额外 include 任何头文件来获取 CTL_CODE
 */

#pragma once

 /* ------------------------------------------------------------------
  * 共享常量 (R0 和 R3 均可见)
  * ------------------------------------------------------------------ */

  /** 读取日志的 IOCTL 码 (0x840, 避开已用的 0x810-0x838) */
#define IOCTL_SVM_READ_LOG  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS)

/** 单条日志最大长度 (含 '\0') */
#define SVM_LOG_ENTRY_SIZE      512

/** 环形缓冲区条目数 (2的幂, 方便取模) */
#define SVM_LOG_RING_COUNT      256

/** R3 单次 IOCTL 读取的最大缓冲区大小 */
#define SVM_LOG_READ_BUF_SIZE   (SVM_LOG_ENTRY_SIZE * 64)


/* ------------------------------------------------------------------
 * R0 专用 (内核驱动端)
 * 判断条件: _KERNEL_MODE 或 NTDDI_VERSION (WDK 一定会定义后者)
 * ------------------------------------------------------------------ */
#if defined(_KERNEL_MODE) || defined(NTDDI_VERSION)

#include <ntifs.h>
#include <ntstrsafe.h>
#include <stdarg.h>

 /**
  * @brief 日志环形缓冲区结构体
  *
  * 无锁单生产者设计:
  *   WriteIndex: InterlockedIncrement 原子递增
  *   ReadIndex:  IOCTL 处理中串行推进
  *   缓冲区满时旧日志被覆盖 (环形语义)
  */
typedef struct _SVM_LOG_RING_BUFFER {
    volatile LONG WriteIndex;
    volatile LONG ReadIndex;
    CHAR Buffer[SVM_LOG_RING_COUNT][SVM_LOG_ENTRY_SIZE];
} SVM_LOG_RING_BUFFER, * PSVM_LOG_RING_BUFFER;

/** 全局日志环形缓冲区指针 (在 SvmLog.cpp 中定义) */
extern PSVM_LOG_RING_BUFFER g_SvmLogRing;

/** 初始化日志系统 */
NTSTATUS SvmLogInit(VOID);

/** 释放日志系统资源 */
VOID SvmLogFree(VOID);

/** 向环形缓冲区写入一条格式化日志 (线程安全, <= DISPATCH_LEVEL) */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID SvmLogWrite(_In_z_ _Printf_format_string_ PCSTR Format, ...);

/** IOCTL 处理: 从环形缓冲区读取所有未读日志 */
NTSTATUS SvmLogRead(PVOID OutBuffer, ULONG OutBufSize, PULONG BytesWritten);

#endif /* _KERNEL_MODE || NTDDI_VERSION */