/**
 * @file SvmLog.cpp
 * @brief SVM 日志系统实现 - 内核环形缓冲区写入与 IOCTL 读取
 * @author yewilliam
 * @date 2026/03/21
 */

#include "SvmLog.h"

#if defined(_KERNEL_MODE) || defined(NTDDI_VERSION)

 /* ========================================================================
  *  全局变量
  * ======================================================================== */
PSVM_LOG_RING_BUFFER g_SvmLogRing = NULL;

/* ========================================================================
 *  初始化 / 释放
 * ======================================================================== */

NTSTATUS SvmLogInit(VOID)
{
    if (g_SvmLogRing)
        return STATUS_SUCCESS;

    g_SvmLogRing = (PSVM_LOG_RING_BUFFER)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(SVM_LOG_RING_BUFFER),
        'SLOG');

    if (!g_SvmLogRing)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(g_SvmLogRing, sizeof(SVM_LOG_RING_BUFFER));
    return STATUS_SUCCESS;
}

VOID SvmLogFree(VOID)
{
    if (g_SvmLogRing) {
        ExFreePoolWithTag(g_SvmLogRing, 'SLOG');
        g_SvmLogRing = NULL;
    }
}

/* ========================================================================
 *  写入日志 (可在 <= DISPATCH_LEVEL 调用)
 * ======================================================================== */

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID SvmLogWrite(_In_z_ _Printf_format_string_ PCSTR Format, ...)
{
    if (!g_SvmLogRing)
        return;

    /* 原子获取写入槽位 */
    LONG slot = InterlockedIncrement(&g_SvmLogRing->WriteIndex) - 1;
    LONG idx = slot & (SVM_LOG_RING_COUNT - 1);  /* 2的幂取模 */

    va_list argList;
    va_start(argList, Format);

    NTSTATUS fmtStatus = RtlStringCbVPrintfA(
        g_SvmLogRing->Buffer[idx],
        SVM_LOG_ENTRY_SIZE,
        Format,
        argList);

    va_end(argList);

    /* 格式化失败时写入错误提示 */
    if (!NT_SUCCESS(fmtStatus)) {
        RtlStringCbCopyA(g_SvmLogRing->Buffer[idx], SVM_LOG_ENTRY_SIZE,
            "[SvmLog] format error\n");
    }
}

/* ========================================================================
 *  IOCTL 读取 — 将所有未读日志拼接到输出缓冲区
 * ======================================================================== */

NTSTATUS SvmLogRead(PVOID OutBuffer, ULONG OutBufSize, PULONG BytesWritten)
{
    *BytesWritten = 0;

    if (!g_SvmLogRing || !OutBuffer || OutBufSize < 2)
        return STATUS_SUCCESS;

    PCHAR dst = (PCHAR)OutBuffer;
    ULONG remaining = OutBufSize - 1;  /* 留 1 字节给终止符 */
    ULONG written = 0;

    LONG writePos = g_SvmLogRing->WriteIndex;
    LONG readPos = g_SvmLogRing->ReadIndex;

    /* 计算未读条目数 */
    LONG pending = writePos - readPos;
    if (pending <= 0) {
        dst[0] = '\0';
        return STATUS_SUCCESS;
    }

    /* 落后太多 (缓冲区已被覆盖), 跳到最新可读位置 */
    if (pending > SVM_LOG_RING_COUNT) {
        readPos = writePos - SVM_LOG_RING_COUNT;
    }

    for (LONG i = readPos; i < writePos; i++)
    {
        LONG idx = i & (SVM_LOG_RING_COUNT - 1);

        SIZE_T entryLen = 0;
        RtlStringCbLengthA(g_SvmLogRing->Buffer[idx], SVM_LOG_ENTRY_SIZE, &entryLen);

        if (entryLen == 0)
            continue;

        if (entryLen > remaining)
            break;  /* 输出缓冲区不够, 下次再读 */

        RtlCopyMemory(dst + written, g_SvmLogRing->Buffer[idx], entryLen);
        written += (ULONG)entryLen;
        remaining -= (ULONG)entryLen;

        /* 更新已读位置 */
        g_SvmLogRing->ReadIndex = i + 1;
    }

    dst[written] = '\0';
    *BytesWritten = written;

    return STATUS_SUCCESS;
}

#endif /* _KERNEL_MODE || NTDDI_VERSION */