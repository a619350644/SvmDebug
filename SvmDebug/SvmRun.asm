OPTION CASEMAP:NONE			; 使标签大小写敏感

;常量定义
GuestVmcbPaOffset EQU 30F0h
GuestGPR EQU 3000h
HostStackTopOffset EQU 5020h

HostVmcbPaOffset EQU 30F8h


PUBLIC SvLaunchVm
PUBLIC SvEnterVmmOnNewStack
EXTERN HostLoop:PROC

.CODE
;---------------------------------------------------------------------
; 定义一个宏，保存通用寄存器
;---------------------------------------------------------------------
PUSHAQ macro
        push    rax
        push    rcx
        push    rdx
        push    rbx
        push    -1      ; Dummy for rsp.
        push    rbp
        push    rsi
        push    rdi
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15
        endm

;---------------------------------------------------------------------
; 定义一个宏，保存通用寄存器
;---------------------------------------------------------------------
POPAQ macro
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx    ; Dummy for rsp (this value is destroyed by the next pop).
        pop     rbx
        pop     rdx
        pop     rcx
        pop     rax
        endm

;---------------------------------------------------------------------
; 定义一个宏，将通用寄存器保存到guest State
;typedef struct _GUEST_GPR
;{
;    UINT64 Rax;   // 0x00
;    UINT64 Rbx;   // 0x08
;    UINT64 Rcx;   // 0x10
;    UINT64 Rdx;   // 0x18
;    UINT64 Rsi;   // 0x20
;    UINT64 Rdi;   // 0x28
;    UINT64 Rbp;   // 0x30
;    UINT64 R8;    // 0x38
;    UINT64 R9;    // 0x40
;    UINT64 R10;   // 0x48
;    UINT64 R11;   // 0x50
;    UINT64 R12;   // 0x58
;    UINT64 R13;   // 0x60
;    UINT64 R14;   // 0x68
;    UINT64 R15;   // 0x70
;} GUEST_GPR, * PGUEST_GPR;
;---------------------------------------------------------------------

SAVEGPR macro
    ;PUSH RDX
    ;MOV [RSP+00H],RAX
    MOV RAX,[RSP+88H]
    MOV [RAX+08H],RBX
    MOV [RAX+10H],RCX
    MOV [RAX+18H],RDX
    MOV [RAX+20H],RSI
    MOV [RAX+28H],RDI
    MOV [RAX+30H],RBP
    MOV [RAX+38H],R8
    MOV [RAX+40H],R9
    MOV [RAX+48H],R10
    MOV [RAX+50H],R11
    MOV [RAX+58H],R12
    MOV [RAX+60H],R13
    MOV [RAX+68H],R14
    MOV [RAX+70H],R15
    ;POP RDX
    endm

    ;---------------------------------------------------------------------
; 定义一个宏，将guest State加载到通用寄存器
;---------------------------------------------------------------------
LOADGPR macro
         
    MOV RBX, [RAX+08H]          ; 加载 RBX
    MOV RCX, [RAX+10H]          ; 加载 RCX
    MOV RDX, [RAX+18H]          ; 加载 RDX
    MOV RSI, [RAX+20H]          ; 加载 RSI
    MOV RDI, [RAX+28H]          ; 加载 RDI
    MOV RBP, [RAX+30H]          ; 加载 RBP
    MOV R8,  [RAX+38H]          ; 加载 R8
    MOV R9,  [RAX+40H]          ; 加载 R9
    MOV R10, [RAX+48H]          ; 加载 R10
    MOV R11, [RAX+50H]          ; 加载 R11
    MOV R12, [RAX+58H]          ; 加载 R12
    MOV R13, [RAX+60H]          ; 加载 R13
    MOV R14, [RAX+68H]          ; 加载 R14
    MOV R15, [RAX+70H]          ; 加载 R15

    MOV RAX, [RAX+00H]          ; 最后加载 RAX
    endm
;---------------------------------------------------------------------
; VOID SvEnterVmmOnNewStack(PSVM_CORE VpData);
;
; 切换到 Host 独立栈，然后调用 SVMLoop(VpData)
; 此函数永远不会返回
;---------------------------------------------------------------------
SvEnterVmmOnNewStack PROC
    ; 切换到 Host 独立栈
    MOV RSP, [RCX+HostStackTopOffset]
    ; 按 x64 ABI 对齐 RSP 到 16 字节
    AND RSP, 0FFFFFFFFFFFFFFF0H
    SUB RSP, 28H 
    CALL HostLoop
    ; 永远不会到这里
    INT 3
SvEnterVmmOnNewStack ENDP


;---------------------------------------------------------------------
; VOID SvLaunchVm(SVM_CORE vpData);
;
; RCX = Guestvmcb
; 
;---------------------------------------------------------------------
SvLaunchVm PROC
    PUSHAQ
    SUB RSP,100H
    MOV RAX,[RCX+HostVmcbPaOffset]
    MOV [RSP+78H],RAX                   ;HostVmcbPa
    VMSAVE RAX
    MOV RAX,[RCX+GuestVmcbPaOffset]     ;GuestVmcbPa
    MOV [RSP+80H],RAX                   ;GuestVmcbPa
    VMLOAD RAX
    LEA RAX,[RCX+GuestGPR]              ;GuestGPR
    MOV [RSP+88H],RAX                   ;GuestGPR
    LOADGPR
    MOV RAX,[RSP+80H]                   ;GuestVmcbPa
    VMRUN RAX
    ;被拦截到这个地方
    SAVEGPR
    MOV RAX,[RSP+80H]
    VMSAVE RAX
    MOV RAX,[RSP+78H]
    VMLOAD RAX
    ADD RSP,100H
    POPAQ
    RET

SvLaunchVm ENDP

END