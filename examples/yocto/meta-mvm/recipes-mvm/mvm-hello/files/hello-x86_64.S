    .section .rodata
message:
    .ascii "mvm-yocto-health-ok\n"
    .equ message_len, . - message

    .section .text
    .global _start
    .type _start, @function
_start:
    mov $1, %edi
    lea message(%rip), %rsi
    mov $message_len, %edx
    mov $1, %eax
    syscall
    cmp %edx, %eax
    setne %dil
    movzbl %dil, %edi
    mov $60, %eax
    syscall
    .size _start, . - _start
