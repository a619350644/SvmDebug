; =========================================================================
; @file Asm.asm
; @brief x64 ASM Hook Entry - NtUserBuildHwndList trampoline & multi-arg helpers
; @author yewilliam
; @date 2026/03/16
;
; Provides:
;   Asm_Fake_NtUserBuildHwndList - Save/restore GPRs, build REGISTER_CONTEXT,
;     call C++ handler, then execute original or block and return
;   Asm_CallOrig5/6/7Args - Relocate stack params and tail-jump to original
; =========================================================================
.code

; Import C++ callback and trampoline address global
EXTERN Cpp_Fake_NtUserBuildHwndList : PROC
EXTERN g_Trampoline_NtUserBuildHwndList : QWORD

; =========================================================================
; @brief ASM proxy entry for NtUserBuildHwndList NPT Hook
; @note Written into FakePage by HookPage; CPU jumps here on execution fault
;
; On entry RSP points to caller return address.
; We build REGISTER_CONTEXT on stack, call C++, then dispatch.
; =========================================================================
Asm_Fake_NtUserBuildHwndList PROC
    ; Step 1: Push all GPRs -> REGISTER_CONTEXT layout
    pushfq                  ; +80h Rflags
    push r15                ; +78h
    push r14                ; +70h
    push r13                ; +68h
    push r12                ; +60h
    push r11                ; +58h
    push r10                ; +50h
    push r9                 ; +48h
    push r8                 ; +40h
    push rdi                ; +38h
    push rsi                ; +30h
    push rbp                ; +28h
    push rsp                ; +20h (placeholder, fixed below)
    push rbx                ; +18h
    push rdx                ; +10h
    push rcx                ; +08h
    push rax                ; +00h (struct top)

    ; Step 2: Fix RSP field -> original stack = current + 17*8 (88h)
    lea rax, [rsp + 88h]
    mov [rsp + 20h], rax

    ; Step 3: RCX = PREGISTER_CONTEXT (first arg to C++)
    mov rcx, rsp

    ; Step 4: Shadow space (32 bytes) + 16-byte alignment
    sub rsp, 20h

    ; Step 5: Call C++ handler
    call Cpp_Fake_NtUserBuildHwndList

    ; Step 6: Free shadow space
    add rsp, 20h

    ; Step 7: AL=0 -> block, AL=1 -> allow
    cmp al, 0
    je Block_And_Return

Allow_And_Execute_Original:
    ; Restore all GPRs then jump to original via trampoline
    pop rax
    pop rcx
    pop rdx
    pop rbx
    add rsp, 8              ; skip RSP placeholder
    pop rbp
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    popfq
    jmp qword ptr [g_Trampoline_NtUserBuildHwndList]

Block_And_Return:
    ; Context->Rax holds faked return value from C++ handler
    pop rax
    pop rcx
    pop rdx
    pop rbx
    add rsp, 8
    pop rbp
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    popfq
    ret                     ; return to caller directly

Asm_Fake_NtUserBuildHwndList ENDP

; =========================================================================
; @brief Multi-argument call helpers
; @note For functions with >4 args: relocate stack params then tail-jump
; =========================================================================

; EXTERN_C ULONG64 Asm_CallOrig5Args(p1,p2,p3,p4, p5, Trampoline);
Asm_CallOrig5Args PROC
    mov r10, [rsp+38h]      ; arg6 = trampoline addr
    mov rax, [rsp+30h]      ; arg5 = p5
    mov [rsp+28h], rax      ; relocate p5
    jmp r10
Asm_CallOrig5Args ENDP

; EXTERN_C ULONG64 Asm_CallOrig6Args(p1,p2,p3,p4, p5,p6, Trampoline);
Asm_CallOrig6Args PROC
    mov r10, [rsp+40h]      ; arg7 = trampoline addr
    mov rax, [rsp+30h]
    mov [rsp+28h], rax      ; relocate p5
    mov rax, [rsp+38h]
    mov [rsp+30h], rax      ; relocate p6
    jmp r10
Asm_CallOrig6Args ENDP

; EXTERN_C ULONG64 Asm_CallOrig7Args(p1,p2,p3,p4, p5,p6,p7, Trampoline);
Asm_CallOrig7Args PROC
    mov r10, [rsp+48h]      ; arg8 = trampoline addr
    mov rax, [rsp+30h]
    mov [rsp+28h], rax      ; relocate p5
    mov rax, [rsp+38h]
    mov [rsp+30h], rax      ; relocate p6
    mov rax, [rsp+40h]
    mov [rsp+38h], rax      ; relocate p7
    jmp r10
Asm_CallOrig7Args ENDP

END
