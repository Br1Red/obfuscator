#if !defined(__linux__) || !defined(__x86_64__)
#error "Direct execution of libobfuscator.so requires Linux x86-64"
#endif

.section .interp,"a",@progbits
.string "/lib64/ld-linux-x86-64.so.2"

.text
.hidden libobfuscator_main
.globl libobfuscator_start
.hidden libobfuscator_start
.type libobfuscator_start, @function
libobfuscator_start:
    xorl %ebp, %ebp
    movq %rdx, %r9
    popq %rsi
    movq %rsp, %rdx
    andq $-16, %rsp
    pushq %rax
    pushq %rsp
    xorl %r8d, %r8d
    xorl %ecx, %ecx
    leaq libobfuscator_main(%rip), %rdi
    call *__libc_start_main@GOTPCREL(%rip)
    hlt
.size libobfuscator_start, .-libobfuscator_start

.section .note.GNU-stack,"",@progbits
