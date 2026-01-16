; =============================================================================
; NanOS Boot - Multiboot2 Header + Entry Point
; A unikernel cell that reacts to stimuli from the swarm
; =============================================================================

bits 32
section .multiboot
align 8

; Multiboot2 magic numbers
MULTIBOOT2_MAGIC    equ 0xE85250D6
GRUB_MAGIC          equ 0x36D76289
ARCH_I386           equ 0

; Header length calculation
header_start:
    dd MULTIBOOT2_MAGIC             ; Magic number
    dd ARCH_I386                    ; Architecture (i386)
    dd header_end - header_start    ; Header length
    dd -(MULTIBOOT2_MAGIC + ARCH_I386 + (header_end - header_start)) ; Checksum

    ; End tag (required)
    align 8
    dw 0    ; type
    dw 0    ; flags
    dd 8    ; size
header_end:

; =============================================================================
; Stack - 16KB static, as promised. No heap growing, no stack overflow checks.
; If you overflow this, the cell dies. That's fine. There are thousands more.
; =============================================================================
section .bss
align 16
stack_bottom:
    resb 16384          ; 16KB stack
stack_top:

; =============================================================================
; Entry Point - Where the cell wakes up
; =============================================================================
section .text
global _start
extern kernel_main

_start:
    ; Disable interrupts during setup (we'll enable them when ready)
    cli

    ; Set up our static stack
    mov esp, stack_top

    ; Clear EFLAGS
    push 0
    popf

    ; Push multiboot info pointer and magic (for kernel_main)
    push ebx            ; Multiboot info structure pointer
    push eax            ; Should contain GRUB_MAGIC (0x36D76289)

    ; Jump to C - the cell begins to live
    call kernel_main

    ; If kernel_main returns (it shouldn't), enter infinite halt
.hang:
    cli
    hlt
    jmp .hang

; =============================================================================
; CPU Sleep - Called from C when there's nothing to do
; =============================================================================
global cpu_halt
cpu_halt:
    hlt
    ret

; =============================================================================
; GDT - Flat memory model, no protection (we're all in this together)
; =============================================================================
section .data
align 16
gdt_start:
    ; Null descriptor (required)
    dq 0

gdt_code:
    ; Code segment: base=0, limit=4GB, executable, readable
    dw 0xFFFF       ; Limit low
    dw 0x0000       ; Base low
    db 0x00         ; Base middle
    db 10011010b    ; Access: present, ring0, code, executable, readable
    db 11001111b    ; Flags: 4KB granularity, 32-bit + limit high
    db 0x00         ; Base high

gdt_data:
    ; Data segment: base=0, limit=4GB, writable
    dw 0xFFFF       ; Limit low
    dw 0x0000       ; Base low
    db 0x00         ; Base middle
    db 10010010b    ; Access: present, ring0, data, writable
    db 11001111b    ; Flags: 4KB granularity, 32-bit + limit high
    db 0x00         ; Base high

gdt_end:

gdt_descriptor:
    dw gdt_end - gdt_start - 1  ; Size
    dd gdt_start                 ; Address

; Segment selectors
CODE_SEG equ gdt_code - gdt_start
DATA_SEG equ gdt_data - gdt_start

; =============================================================================
; Load GDT - Called early in kernel_main
; =============================================================================
global gdt_load
gdt_load:
    lgdt [gdt_descriptor]

    ; Reload segment registers with new GDT
    mov ax, DATA_SEG
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; Far jump to reload CS
    jmp CODE_SEG:.reload_cs
.reload_cs:
    ret

; =============================================================================
; IDT Loading - For interrupt handling
; =============================================================================
global idt_load
idt_load:
    mov eax, [esp + 4]  ; Get IDT pointer from stack
    lidt [eax]
    ret

; =============================================================================
; Interrupt enable/disable
; =============================================================================
global interrupts_enable
interrupts_enable:
    sti
    ret

global interrupts_disable
interrupts_disable:
    cli
    ret
