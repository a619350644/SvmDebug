# SvmDebug

AMD SVM hypervisor for Windows process protection and transparent debugging.

## Requirements

- AMD CPU with SVM + NPT support
- Windows 10 x64
- Visual Studio + WDK

## Build

```bash
msbuild SvmDebug.sln /p:Configuration=Release /p:Platform=x64
```

## Install

```bash
sc create SvmDebug type= kernel binPath= C:\path\to\SvmDebug.sys
sc start SvmDebug
```

## Uninstall

```bash
sc stop SvmDebug
sc delete SvmDebug
```

## Features

- Process/window hiding via NPT hooks
- Shadow debugging system
- Hypervisor memory access
- Handle protection

## Communication

Device: `\\.\SvmDebug`

Key IOCTLs:
- `IOCTL_SVM_PROTECT_PID` - Protect process
- `IOCTL_HV_READ_MEMORY` - Read memory
- `IOCTL_HV_WRITE_MEMORY` - Write memory

## Warning

Kernel-mode hypervisor. Research/education use only.
