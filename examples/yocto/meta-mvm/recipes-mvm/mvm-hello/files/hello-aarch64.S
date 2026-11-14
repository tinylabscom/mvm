    .section .rodata
message:
    .ascii "mvm-yocto-health-ok\n"
    .equ message_len, . - message

    .section .text
    .global _start
    .type _start, %function
_start:
    mov x0, #1
    adr x1, message
    mov x2, #message_len
    mov x8, #64
    svc #0
    cmp x0, x2
    cset x0, ne
    mov x8, #93
    svc #0
    .size _start, . - _start
