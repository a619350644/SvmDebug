/**
 * @file HvMapSlot.h
 * @brief 无锁 PTE 槽位池 — VMEXIT 期间安全映射物理页
 *
 * 解决的问题:
 *   VMEXIT 期间 IF=0(中断禁用), 不能调用 MmMapIoSpace(需要锁)
 *   也不能用 MmGetVirtualForPhysical(自引用 PTE 在 Host CR3 下不正确)
 *
 * 方案:
 *   初始化阶段预分配连续内核内存, 获取每页的 PTE 地址
 *   VMEXIT 期间直接写 PTE + INVLPG 来映射任意物理页, 零锁操作
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>

/* ========================================================================
 * 配置
 * ======================================================================== */

#define HV_SLOTS_PER_CPU    8       /* 每个 CPU 8 个映射槽位 */
#define HV_MAX_CPUS         64      /* 最大支持 CPU 数 */

/* 槽位用途分配 (约定, 非强制):
 *   0-3: TranslateGuestVaToPa (PML4/PDPT/PD/PT 各一个)
 *   4-5: PhysicalMemoryCopy (src + dst)
 *   6:   HvHandleBatchRead context 页
 *   7:   HvHandleBatchRead scatter entry 页
 */
#define SLOT_PML4   0
#define SLOT_PDPT   1
#define SLOT_PD     2
#define SLOT_PT     3
#define SLOT_SRC    4
#define SLOT_DST    5
#define SLOT_CTX    6
#define SLOT_ENTRY  7

/* ========================================================================
 * 数据结构
 * ======================================================================== */

typedef struct _HV_MAP_SLOT {
    PVOID       Va;         /* 固定虚拟地址 (内核空间) */
    PULONG64    Pte;        /* 指向该 VA 的 PTE 条目 */
    ULONG64     OrigPte;    /* 原始 PTE 值 (初始化时保存) */
} HV_MAP_SLOT;

typedef struct _HV_MAP_POOL {
    HV_MAP_SLOT Slots[HV_MAX_CPUS][HV_SLOTS_PER_CPU];
    PVOID       PoolVa;         /* 连续物理内存基址 */
    ULONG64     PoolPa;         /* 连续物理内存 PA */
    ULONG       CpuCount;       /* 实际 CPU 数 */
    ULONG       TotalPages;     /* 总页数 */
    ULONG64     PteBase;        /* Windows PTE_BASE (动态获取) */
    BOOLEAN     Initialized;    /* 初始化完成标志 */
} HV_MAP_POOL;

/* ========================================================================
 * API
 * ======================================================================== */

/**
 * @brief 初始化映射槽位池 (PASSIVE_LEVEL, 驱动加载时调用)
 * @param CpuCount 系统 CPU 数
 * @return STATUS_SUCCESS 或错误码
 */
NTSTATUS HvMapSlotInit(ULONG CpuCount);

/**
 * @brief 清理映射槽位池 (驱动卸载时调用)
 */
VOID HvMapSlotCleanup(void);

/**
 * @brief VMEXIT 期间映射物理页 (无锁, per-CPU 隔离)
 * @param CpuId  当前 CPU 编号 (KeGetCurrentProcessorNumber)
 * @param Slot   槽位索引 (0 ~ HV_SLOTS_PER_CPU-1)
 * @param PhysAddr 要映射的物理地址 (自动对齐到页, 返回含页内偏移)
 * @return 映射后的虚拟地址 (含页内偏移), 失败返回 NULL
 */
PVOID VmxMapPhys(ULONG CpuId, ULONG Slot, ULONG64 PhysAddr);

/**
 * @brief VMEXIT 期间取消映射 (恢复原始 PTE)
 * @param CpuId  当前 CPU 编号
 * @param Slot   槽位索引
 */
VOID VmxUnmapPhys(ULONG CpuId, ULONG Slot);

/**
 * @brief 获取全局映射池指针 (供外部查询状态)
 */
HV_MAP_POOL* HvGetMapPool(void);

#ifdef __cplusplus
}
#endif
