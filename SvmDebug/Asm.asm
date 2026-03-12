; =========================================================================
; x64 完美上下文劫持引擎 (Asm.asm)
; =========================================================================
.code

; 导入 C++ 处理函数和全局跳床变量
EXTERN Cpp_Fake_NtUserBuildHwndList : PROC
EXTERN g_Trampoline_NtUserBuildHwndList : QWORD 

; 这是你在 HookPage 里填写的真正的跳转目标
Asm_Fake_NtUserBuildHwndList PROC
    ; 1. 此时 CPU 刚刚跳过来，RSP 完美指向返回地址
    ; 我们开始把所有寄存器压栈，严格按照 REGISTER_CONTEXT 结构体的倒序！
    
    pushfq                  ; +80h (Rflags)
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
    push rsp                ; +20h (注意：这里压入的 RSP 是错误的，下面会修复)
    push rbx                ; +18h
    push rdx                ; +10h
    push rcx                ; +08h
    push rax                ; +00h (结构体顶端)

    ; 2. 修复刚才压入的 RSP，让它指向真正的原函数栈顶！
    ; 当前 rsp 指向 rax。原本的栈顶在 rsp + 17个8字节(88h) 的地方。
    lea rax, [rsp + 88h]    ; 算出最原始的 RSP 地址
    mov [rsp + 20h], rax    ; 把它填进结构体的 Rsp 字段里

    ; 3. 现在的 RSP 就是 PREGISTER_CONTEXT 结构体的指针！
    mov rcx, rsp

    ; 4. 申请 32 字节影子空间，保证 call 之前的 RSP 是 16 字节对齐 (16n)
    sub rsp, 20h

    ; 5. 呼叫 C++ 大脑！
    call Cpp_Fake_NtUserBuildHwndList

    ; 6. 恢复影子空间
    add rsp, 20h

    ; 7. C++ 函数返回一个 BOOLEAN (在 AL 寄存器里)
    ; 如果 AL == 0，说明我们要在内核里拦截它，直接返回
    ; 如果 AL == 1，说明放行，跳到 Trampoline
    cmp al, 0
    je Block_And_Return

Allow_And_Execute_Original:
    ; 放行逻辑：恢复所有寄存器（包括可能被 C++ 篡改的参数），然后跳向原函数
    pop rax
    pop rcx
    pop rdx
    pop rbx
    add rsp, 8              ; 跳过 Rsp 字段
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

    ; 带着完好无损的堆栈，直接跳到跳床！
    jmp qword ptr [g_Trampoline_NtUserBuildHwndList]

Block_And_Return:
    ; 拦截逻辑：C++ 会把伪造的返回值写进 Context->Rax 里
    ; 我们弹栈恢复一切，拿到那个伪造的 RAX，然后直接 ret！
    pop rax                 ; 拿到 C++ 伪造的返回值！
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

    ; 不去跳床了，直接假装原函数执行完毕，返回给调用者！
    ret

Asm_Fake_NtUserBuildHwndList ENDP

; ----------------------------------------------------
; 解决 C++ 代理调用 >4 参数原函数的 8 字节堆栈错位问题
; ----------------------------------------------------

; EXTERN_C ULONG64 Asm_CallOrig5Args(PVOID p1, PVOID p2, PVOID p3, PVOID p4, PVOID p5, PVOID Trampoline);
Asm_CallOrig5Args PROC
    mov r10, [rsp+38h]      ; 取出第 6 个参数 (跳床地址)
    mov rax, [rsp+30h]      ; 取出原来的 p5
    mov [rsp+28h], rax      ; 移位到原函数期待的 [rsp+28h] 位置
    jmp r10                 ; 无痕跳转，不压栈！
Asm_CallOrig5Args ENDP

; EXTERN_C ULONG64 Asm_CallOrig6Args(PVOID p1, PVOID p2, PVOID p3, PVOID p4, PVOID p5, PVOID p6, PVOID Trampoline);
Asm_CallOrig6Args PROC
    mov r10, [rsp+40h]      ; 取出第 7 个参数 (跳床地址)
    
    mov rax, [rsp+30h]
    mov [rsp+28h], rax      ; 移位 p5
    
    mov rax, [rsp+38h]
    mov [rsp+30h], rax      ; 移位 p6
    
    jmp r10
Asm_CallOrig6Args ENDP

; EXTERN_C ULONG64 Asm_CallOrig7Args(PVOID p1, PVOID p2, PVOID p3, PVOID p4, PVOID p5, PVOID p6, PVOID p7, PVOID Trampoline);
Asm_CallOrig7Args PROC
    mov r10, [rsp+48h]      ; 取出第 8 个参数 (跳床地址)
    
    mov rax, [rsp+30h]
    mov [rsp+28h], rax      ; 移位 p5
    
    mov rax, [rsp+38h]
    mov [rsp+30h], rax      ; 移位 p6
    
    mov rax, [rsp+40h]
    mov [rsp+38h], rax      ; 移位 p7
    
    jmp r10
Asm_CallOrig7Args ENDP

END