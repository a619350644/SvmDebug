# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build

Requires Visual Studio + Windows Driver Kit (WDK) installed.

```bash
# Release build
msbuild SvmDebug.sln /p:Configuration=Release /p:Platform=x64

# Debug build
msbuild SvmDebug.sln /p:Configuration=Debug /p:Platform=x64
```

Output: `SvmDebug/x64/Release/SvmDebug.sys` (kernel-mode driver)

## Install / Uninstall

```bash
# Install
sc create SvmDebug type= kernel binPath= C:\path\to\SvmDebug.sys
sc start SvmDebug

# Uninstall
sc stop SvmDebug
sc delete SvmDebug
```

## Project Overview

SvmDebug (also called Hyper-Vanguard) is an AMD SVM-based Type-1 hypervisor implemented as a Windows kernel driver (`SvmDebug.sys`). It uses Nested Page Tables (NPT) to hook kernel functions at the physical-memory level without modifying software visible to the guest OS.

## Architecture

### Privilege Layers

```
Ring -1 (VMM Host)    VMRUN/VMEXIT control, NPT page tables, physical memory ops
Ring 0  (Guest)       SvmDebug.sys, Windows kernel, third-party kernel drivers
Ring 3  (User)        Applications communicating via DeviceIoControl
```

### Key Modules

| File | Role |
|------|------|
| `DrvMain.cpp` | `DriverEntry`, IOCTL dispatch, SVM init (IPI broadcast to all cores) |
| `SVM.cpp` | VMCB setup, `SvHandleVmExit` dispatch loop |
| `SvmRun.asm` | VMRUN loop and low-level VMEXIT entry |
| `NPT.cpp` | Nested page table (PML4/PDPT/PD/PT) management, large-page splitting |
| `Hook.cpp` | NPT hook framework: FakePage + Trampoline construction, `RegisterNptHook` / `PrepareAllNptHooks` / `ActivateAllNptHooks` |
| `Hide.cpp` | Process/window hiding — hooks 30+ Nt/Ps/Ob syscalls and Win32k SSSDT |
| `DebugApi.cpp` | Shadow debug system — custom `DEBUG_OBJECT`, event queue, invisible debug port |
| `DeepHook.cpp` | Deep kernel intercepts (PspInsertThread, KiInsertQueueApc, ExpLookupHandleTableEntry, etc.) |
| `Disguise.cpp` | Process masquerading via DKOM (modifies PEB/LDR/ImageFileName) |
| `HvMemory.cpp` | Hypervisor-level memory R/W via CPUID supercalls (bypasses all kernel APIs) |
| `Common.h` | VMCB structures, MSR/CPUID constants, VMEXIT codes — central shared header |
| `winApiDef.h` | Undocumented Windows kernel API declarations |
| `hde/` | HDE64 instruction-length disassembler (used when constructing trampolines) |

### NPT Hook Mechanism

All hooks are registered in `HOOK_INDEX` (50+ entries in `Common.h`). Each entry in `g_HookList` stores:
- `TargetPA` — physical address of the original function
- `FakePage` — modified copy where hook logic is injected
- `TrampolinePage` — original stolen bytes + JMP back to rest of function

At VMEXIT (nested page fault), the VMM transparently redirects execution to the FakePage. The guest OS never sees patched memory.

### CPUID Supercall Protocol

User-mode or ring-0 code triggers hypervisor memory operations by executing `CPUID` with leaf `0x41414150`. The VMM intercepts this VMEXIT and performs physical-address–level memory R/W, bypassing all kernel memory APIs.

### IOCTL Interface

Device: `\\.\SvmDebug`

```c
IOCTL_SVM_PROTECT_PID        (0x820)  // Register PID for protection
IOCTL_SVM_PROTECT_HWND       (0x821)  // Protect main window handle
IOCTL_SVM_PROTECT_CHILD_HWND (0x822)  // Protect child windows
IOCTL_SVM_CLEAR_ALL          (0x823)  // Remove all protections
IOCTL_SVM_ELEVATE_PID        (0x828)  // Elevate process token
IOCTL_HV_READ_MEMORY         (0x810)  // Read target process memory
IOCTL_HV_WRITE_MEMORY        (0x811)  // Write target process memory
IOCTL_HV_GET_MODULE          (0x812)  // Get module base address
IOCTL_HV_QUERY_VM            (0x813)  // Query virtual memory info
```

## Documentation

- `SvmDebug_设计文档.md` — comprehensive Chinese design document with detailed architecture diagrams, data flow, module dependencies, and complete HOOK_INDEX enumeration.
