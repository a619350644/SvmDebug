# CE Memory Scan & Memory Viewer 修复总结

## 问题现象
1. **Memory Viewer 全部显示 `???`** - 无法读取内存数据
2. **First Scan 之后数据为空** - 没有任何搜索结果

## 根本原因 - 3 个严重 Bug

### BUG #1 (致命): CPUID_HV_BATCH_READ — RBX 未设置
**位置**: DBKKernel/HvBatchRead_Guest.c 第 229 → 237 行

**问题**: 
- `__cpuidex` 只设置 EAX (leaf) 和 ECX (sub-leaf)
- 不设置 RBX 寄存器
- VMM 读 `vpData->Guest_gpr.Rbx` 作为 BatchContext 物理地址时得到垃圾值

**后果**: VMM 映射错误物理地址 → batch read 全部失败 → CE 读取全部返回零

**修复**: 新增 `HvCpuidWithRbx()` ASM 函数，显式设置 RBX = g_BatchContextPa

---

### BUG #2 (致命): CPUID_HV_MEMORY_OP — VMM 强制覆盖 RBX  
**位置**: SvmDebug/SvmDebug/SVM.cpp 第 524 行

**问题**:
```cpp
else if (leaf == CPUID_HV_MEMORY_OP) {
    vpData->Guest_gpr.Rbx = g_HvSharedContextPa;  // ← 强制覆盖!
    HvHandleMemoryOp(vpData);
}
```
- VMM 无条件覆盖 RBX = g_HvSharedContextPa
- 当 DBKKernel 调用此 CPUID 时，用的是自己的 g_BridgeContext (PA = g_BridgeContextPa)
- 但 VMM 强制改成 SvmDebug 的上下文 → 读到错误数据

**后果**: HvBridge_ReadProcessMemory 永远失败 → Memory Viewer 无法读取

**修复**: 移除强制覆盖，改为 Guest 通过 RBX 主动传递上下文 PA

---

### BUG #3 (中等): NPT Hook 污染 NtQueryVirtualMemory 结果
**位置**: 
- DBKKernel/IOPLDispatcher.c 第 504-534 行 (StealthQueryVM)
- SvmDebug/SvmDebug/Hide.cpp 第 1486-1501 行 (Fake_NtQueryVirtualMemory)

**流程**:
1. CE IOCTL_CE_QUERY_VIRTUAL_MEMORY → StealthQueryVM
2. StealthQueryVM: `KeStackAttachProcess(target)` → `ZwQueryVirtualMemory(NtCurrentProcess())`
3. NPT Hook `Fake_NtQueryVirtualMemory` 拦截到 ProcessHandle == NtCurrentProcess() 的调用
4. Hook 误以为是进程自查，触发"自查伪装"代码
5. 把 PAGE_EXECUTE_READWRITE 改成 PAGE_READONLY

**后果**: CE 看到错误的保护属性 → Memory Viewer 显示 `???` + First Scan 跳过区域

**修复**: 
- DBKKernel 改用 `ObOpenObjectByPointer()` 创建 kernel handle (不再是 NtCurrentProcess())
- SvmDebug Hide.cpp 加 `ExGetPreviousMode() == UserMode` 检查 (内核模式调用不需要伪装)

---

## 修复清单

### ✅ SvmDebug 项目修改

| 文件 | 修改内容 | 行号 |
|------|---------|------|
| SvmDebug/SvmDebug/SVM.cpp | 移除 RBX 强制覆盖 + 添加注释 | 523-531 |
| SvmDebug/SvmDebug/Asm.asm | 新增 `HvCpuidWithRbx()` 函数 | 144-182 |
| SvmDebug/SvmDebug/HvMemory.cpp | 调用 HvCpuidWithRbx 传递 g_HvSharedContextPa | 473-477 |
| SvmDebug/SvmDebug/Hide.cpp | 添加 `ExGetPreviousMode() == UserMode` 检查 | 1499 |

### ✅ DBKKernel 项目修改

| 文件 | 修改内容 | 行号 |
|------|---------|------|
| DBKKernel/amd64/dbkfunca.asm | 新增 `HvCpuidWithRbx()` 函数 | 158-194 |
| DBKKernel/HvBatchRead_Guest.c | 调用 HvCpuidWithRbx 传递 g_BatchContextPa | 65, 237 |
| DBKKernel/HvMemBridge.c | 调用 HvCpuidWithRbx 传递 g_BridgeContextPa | 18, 151-157 |
| DBKKernel/IOPLDispatcher.c | 改用 ObOpenObjectByPointer kernel handle | 499-545 |

---

## 修复后预期结果

✅ **Memory Viewer 正常显示数据** - 不再显示 `???`

✅ **First Scan 有搜索结果** - 不再返回空结果

✅ **读取路径正确** - HvCpuidWithRbx 确保 VMM 得到正确的上下文 PA

✅ **保护属性准确** - StealthQueryVM 不再触发错误的伪装

---

## 构建说明

### SvmDebug
```bash
msbuild SvmDebug.sln /p:Configuration=Release /p:Platform=x64
```
输出: `SvmDebug/x64/Release/SvmDebug.sys`

### DBKKernel (Cheat Engine)
```bash
# 在 Visual Studio 中打开 DBKKernel.vcxproj 并编译
```
输出: `Release/DBKDrvr.sys`

---

## 验证检查清单

- [ ] SVM.cpp 第 523-531 行：RBX 覆盖已移除
- [ ] Asm.asm / dbkfunca.asm：HvCpuidWithRbx 函数已添加
- [ ] HvMemory.cpp 第 477 行：调用 HvCpuidWithRbx
- [ ] HvBatchRead_Guest.c 第 237 行：调用 HvCpuidWithRbx
- [ ] HvMemBridge.c 第 156 行：调用 HvCpuidWithRbx
- [ ] IOPLDispatcher.c 第 528 行：使用 ObOpenObjectByPointer
- [ ] Hide.cpp 第 1499 行：添加 UserMode 检查

全部修改已应用 ✅
