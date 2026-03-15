; =========================================================================
; @file SvmRun.asm
; @brief SVM VM Launch Assembly - VMRUN/VMSAVE/VMLOAD and stack switching
; @author yewilliam
; @date 2026/02/06
;
; Core routines:
;   SvLaunchVm        - Save Host -> Load Guest -> VMRUN -> Save Guest -> Restore Host
;   SvEnterVmmOnNewStack - Switch to Host independent stack then enter HostLoop
;   SvSwitchStack     - Exit SVM: switch from Host stack back to Guest stack via IRETQ
;
; Macros:
;   PUSHAQ / POPAQ    - Push/pop all 16 general purpose registers
;   SAVEGPR / LOADGPR - Save/load GPRs to/from GUEST_GPR structure
; =========================================================================
OPTION CASEMAP:NONE

; =========================================================================
; VCPU_CONTEXT field offsets (must match C++ struct layout)
; =========================================================================
GuestVmcbPaOffset   EQU 30F0h
HostVmcbPaOffset    EQU 30F8h
GuestGPR            EQU 3000h
GuestStateSaveRSP   EQU 5D8h
HostStackTopOffset  EQU 5020h

PUBLIC SvLaunchVm
PUBLIC SvEnterVmmOnNewStack
PUBLIC SvSwitchStack
EXTERN HostLoop:PROC

.CODE

; =========================================================================
; @brief PUSHAQ macro - push all 16 general purpose registers
; @note Pushes a dummy value for RSP (will be discarded on POPAQ)
; =========================================================================
PUSHAQ macro
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    -1          ; Dummy for RSP
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

; =========================================================================
; @brief POPAQ macro - pop all 16 general purpose registers
; @note The dummy RSP slot is consumed by a redundant RBX pop
; =========================================================================
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
    pop     rbx         ; Dummy RSP slot (value discarded)
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
endm

; =========================================================================
; @brief SAVEGPR macro - save Guest GPRs from CPU registers to GUEST_GPR struct
; @note RAX on stack at [RSP+88h] points to GUEST_GPR base
;
; GUEST_GPR layout:
;   +00h RAX, +08h RBX, +10h RCX, +18h RDX, +20h RSI, +28h RDI,
;   +30h RBP, +38h R8,  +40h R9,  +48h R10, +50h R11, +58h R12,
;   +60h R13, +68h R14, +70h R15
; =========================================================================
SAVEGPR macro
    MOV RAX,[RSP+88H]       ; RAX = pointer to GUEST_GPR struct
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
endm

; =========================================================================
; @brief LOADGPR macro - load GPRs from GUEST_GPR struct into CPU registers
; @note RAX must point to GUEST_GPR base on entry; RAX loaded last
; =========================================================================
LOADGPR macro
    MOV RBX, [RAX+08H]
    MOV RCX, [RAX+10H]
    MOV RDX, [RAX+18H]
    MOV RSI, [RAX+20H]
    MOV RDI, [RAX+28H]
    MOV RBP, [RAX+30H]
    MOV R8,  [RAX+38H]
    MOV R9,  [RAX+40H]
    MOV R10, [RAX+48H]
    MOV R11, [RAX+50H]
    MOV R12, [RAX+58H]
    MOV R13, [RAX+60H]
    MOV R14, [RAX+68H]
    MOV R15, [RAX+70H]
    MOV RAX, [RAX+00H]      ; Load RAX last
endm

; =========================================================================
; @brief Switch to Host independent stack then enter SVM Host loop
; @param RCX = PVCPU_CONTEXT VpData
; @note This function NEVER returns
; =========================================================================
SvEnterVmmOnNewStack PROC
    MOV RSP, [RCX+HostStackTopOffset]
    AND RSP, 0FFFFFFFFFFFFFFF0H   ; 16-byte align per x64 ABI
    SUB RSP, 28H                  ; Shadow space + alignment
    CALL HostLoop
    INT 3                         ; Should never reach here
SvEnterVmmOnNewStack ENDP

; =========================================================================
; @brief Exit SVM: switch from Host stack to Guest stack and IRETQ
; @param RCX = PVCPU_CONTEXT VpData
; @note Restores Guest segment state, disables EFER.SVME, then IRETQ
; =========================================================================
SvSwitchStack PROC
    MOV R15, RCX                 ; Save VpData in R15

    ; Step 1: Enable interrupts and restore Guest hidden state
    STGI
    MOV RAX, [R15 + GuestVmcbPaOffset]
    VMLOAD RAX

    ; Step 2: Disable SVM (clear EFER.SVME bit 12)
    MOV ECX, 0C0000080h
    RDMSR
    BTR EAX, 12
    WRMSR

    ; Step 3: Build IRETQ frame (SS, RSP, RFLAGS, CS, RIP)
    MOVZX RAX, word ptr [R15 + 1420h]    ; Push SS
    PUSH RAX
    MOV RAX, [R15 + 15D8h]               ; Push RSP
    PUSH RAX
    MOV RAX, [R15 + 1570h]               ; Push RFLAGS
    PUSH RAX
    MOVZX RAX, word ptr [R15 + 1410h]    ; Push CS
    PUSH RAX
    MOV RAX, [R15 + 1578h]               ; Push RIP
    PUSH RAX

    ; Step 4: Restore Guest GPRs (manual expansion to preserve IRETQ frame)
    LEA RAX, [R15 + GuestGPR]
    MOV RBX, [RAX+08H]
    MOV RCX, [RAX+10H]
    MOV RDX, [RAX+18H]
    MOV RSI, [RAX+20H]
    MOV RDI, [RAX+28H]
    MOV RBP, [RAX+30H]
    MOV R8,  [RAX+38H]
    MOV R9,  [RAX+40H]
    MOV R10, [RAX+48H]
    MOV R11, [RAX+50H]
    MOV R12, [RAX+58H]
    MOV R13, [RAX+60H]
    MOV R14, [RAX+68H]
    MOV R15, [RAX+70H]
    MOV RAX, [RAX+00H]

    ; Step 5: Return to Guest
    IRETQ
SvSwitchStack ENDP

; =========================================================================
; @brief Execute one VMRUN cycle: save Host, load+run Guest, save Guest, restore Host
; @param RCX = PVCPU_CONTEXT VpData
;
; Flow: PUSHAQ -> VMSAVE(Host) -> VMLOAD(Guest) -> LOADGPR -> VMRUN
;       -> SAVEGPR -> VMSAVE(Guest) -> VMLOAD(Host) -> POPAQ -> RET
; =========================================================================
SvLaunchVm PROC
    PUSHAQ
    SUB RSP, 100H

    ; Save Host VMCB state
    MOV RAX, [RCX+HostVmcbPaOffset]
    MOV [RSP+78H], RAX               ; Store HostVmcbPa on stack
    VMSAVE RAX

    ; Load Guest VMCB state
    MOV RAX, [RCX+GuestVmcbPaOffset]
    MOV [RSP+80H], RAX               ; Store GuestVmcbPa on stack
    VMLOAD RAX

    ; Load Guest GPRs from GUEST_GPR struct
    LEA RAX, [RCX+GuestGPR]
    MOV [RSP+88H], RAX               ; Store GuestGPR pointer on stack
    LOADGPR

    ; Execute Guest (VMRUN blocks until VMEXIT)
    MOV RAX, [RSP+80H]               ; GuestVmcbPa
    VMRUN RAX

    ; --- VMEXIT occurred, now back in Host ---

    ; Save Guest GPRs back to GUEST_GPR struct
    SAVEGPR

    ; Save Guest VMCB hidden state
    MOV RAX, [RSP+80H]
    VMSAVE RAX

    ; Restore Host VMCB hidden state
    MOV RAX, [RSP+78H]
    VMLOAD RAX

    ADD RSP, 100H
    POPAQ
    RET

SvLaunchVm ENDP

END
