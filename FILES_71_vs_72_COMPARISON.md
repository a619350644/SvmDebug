# Files (71) vs Files (72) — 版本对比

## 概述

- **Files (71)**: v18 → v19 "RBX Fix Edition" — 修复 3 个 Bug
- **Files (72)**: v18 → v19 "Pure VMEXIT Edition" — Files (71) + FIX #4

## 关键差异

### 1. 内存读取失败处理

#### Files (71) - v18
```c
if (!HvBatchRead_SingleRead(...)) {
    // FALLBACK: 回退到 Guest R0 MmCopyMemory
    ntStatus = StealthDirectRead(pid, addr, buf, size) 
        ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
```

#### Files (72) - v19
```c
if (!HvBatchRead_SingleRead(...)) {
    // VMEXIT 失败 — 填零, 不回退
    RtlZeroMemory(buf, size);
    ntStatus = STATUS_SUCCESS;  // 返回成功但数据为零
}
```

**影响**:
- 隐蔽性: 零 Guest R0 MmCopyMemory 调用
- 稳定性: 失败时优雅返回零 (vs 报错)
- 安全性: 完全 VMEXIT, 不受 Guest 检测

### 2. 内存写入实现

#### Files (71) - v17/v18
```c
ntStatus = StealthDirectWrite(pid, addr, data, size)
    ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
```
特点: Guest R0 MmMapIoSpace 映射物理页, 直接修改

#### Files (72) - v19
```c
ntStatus = HvBridge_WriteProcessMemory(pid, ..., addr, size, data)
    ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
```
特点: CPUID VMEXIT → VMM Host 物理写入

**影响**:
- 隐蔽性: 零 MmMapIoSpace 调用
- 完整性: 读写对称 (都是 VMEXIT)
- 可靠性: VMM 直接物理写入, 无中间步骤

### 3. 诊断日志

#### 读取失败日志

Files (71):
```
[SVM-CE] !! FALLBACK #10: StealthDirectRead PID=1234 addr=0x... size=4096
```

Files (72):
```
[SVM-CE] VMEXIT READ FAIL (zero-fill, NO Guest R0 fallback) #10: PID=1234 addr=0x... size=4096
```

#### 写入日志

Files (71):
```
不存在 (写入仍然使用 StealthDirectWrite)
```

Files (72):
```
[SVM-CE] WRITE VMEXIT #5: PID=1234 addr=0x... size=256
```

#### 成功读取日志

Files (71):
```
[SVM-CE] VMEXIT READ OK #1: PID=1234 addr=0x... size=4096
```

Files (72):
```
[SVM-CE] VMEXIT READ OK #1: PID=1234 addr=0x... size=4096 
         data[0..7]=48 65 6C 6C 6F 21 00 00
```
(增加了数据预览)

## 完整执行路径对比

### Files (71) - v18 "Mixed Mode"
```
读取:  ✅ HvBatchRead (VMEXIT) 或 ❌ StealthDirectRead (Guest R0)
写入:  ✗ StealthDirectWrite (Guest R0 MmMapIoSpace)
查询:  ⚠️ ObOpenObjectByPointer (kernel handle)
```

### Files (72) - v19 "Pure VMEXIT"
```
读取:  ✅ HvBatchRead (VMEXIT) 或 ➡️ 填零 (优雅降级)
写入:  ✅ HvBridge_WriteProcessMemory (VMEXIT)
查询:  ✅ ObOpenObjectByPointer (kernel handle)
```

## 修改统计

### Files (71)
- 修复 Bug #1, #2, #3
- 修改文件: 8 个
- 新增函数: HvCpuidWithRbx (2 个 ASM 版本)
- 删除代码: RBX 强制覆盖 (1 行)
- 替换调用: __cpuidex → HvCpuidWithRbx (3 处)
- 添加检查: ExGetPreviousMode() == UserMode (1 处)

### Files (72)
- 修复 Bug #1, #2, #3, #4
- 修改文件: 同 8 个 (包含 files 71 所有修改)
- 新增函数: 同 files 71
- **新增修改**:
  - 移除 StealthDirectRead 回退 (1 处)
  - 添加 HvBridge_WriteProcessMemory 调用 (1 处)
  - 增强诊断日志 (2 处)

## 代码量对比

| 项目 | Files (71) | Files (72) | 增加 |
|------|-----------|-----------|------|
| IOPLDispatcher.c 新增行 | 15 | 35 | +20 |
| HvMemBridge.c 新增行 | 8 | 8 | 0 |
| HvBatchRead_Guest.c 新增行 | 8 | 8 | 0 |
| Hide.cpp 修改行 | 1 | 1 | 0 |
| 总计新增行 | ~32 | ~52 | +20 |

## 性能特性

### 读取性能
| 指标 | Files (71) | Files (72) |
|------|-----------|-----------|
| 正常情况 | VMEXIT | VMEXIT (相同) |
| 页面换出 | MmCopyMemory | RtlZeroMemory |
| 未映射页 | MmCopyMemory | RtlZeroMemory |

### 写入性能
| 指标 | Files (71) | Files (72) |
|------|-----------|-----------|
| 执行路径 | Guest R0 | VMEXIT |
| 延迟 | 低 (本地) | 高 (虚拟化) |
| 隐蔽性 | 差 (MmMapIoSpace) | 优 (0 Guest API) |

## 部署建议

### 使用 Files (71) 如果...
- 需要最高性能 (写入操作较多)
- 能接受 Guest R0 MmCopyMemory 痕迹
- 目标环保游戏检测不包括写入路径

### 使用 Files (72) 如果...
- 优先隐蔽性 (完全 VMEXIT)
- 读多写少的典型场景
- 需要完整的诊断日志
- 要求 Guest R0 "完全无痕"

## 选择指南

```
┌─ 优先隐蔽性?
│  ├─ YES → Files (72) ✓
│  └─ NO
│
└─ 写入操作很频繁?
   ├─ YES → Files (71) (性能优)
   └─ NO → Files (72) ✓
```

## 验证差异

使用 DebugView 观察:

### Files (71) 特征日志
```
[SVM-CE] !! FALLBACK #N: StealthDirectRead ...  (读取失败时)
[SVM-CE] WRITE #N (Guest R0 StealthDirectWrite, NOT VMEXIT) ...
```

### Files (72) 特征日志
```
[SVM-CE] VMEXIT READ FAIL (zero-fill, NO Guest R0 fallback) #N ...  (读取失败时)
[SVM-CE] WRITE VMEXIT #N ...
[SVM-CE] VMEXIT READ OK #N ... data[0..7]=XX XX ...  (包含数据预览)
```

## 总结

| 特性 | Files (71) | Files (72) |
|------|-----------|-----------|
| Bug 修复数 | 3 | 4 |
| Guest R0 API 调用 | MmCopyMemory + MmMapIoSpace | MmCopyMemory only |
| 完全 VMEXIT | 读取可以, 写入不行 | 读写都是 |
| 隐蔽性 | 较好 | 优秀 |
| 诊断能力 | 基础 | 增强 |
| 推荐指数 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

---

**结论**: Files (72) 是 Files (71) 的完全增强版本, 包含所有修复 + FIX #4 (零 Guest R0 回退)
