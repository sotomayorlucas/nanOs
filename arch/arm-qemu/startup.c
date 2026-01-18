/*
 * NanOS ARM Cortex-M3 Startup Code
 * Target: QEMU lm3s6965evb
 */

#include <stdint.h>

/* Linker symbols */
extern uint32_t _etext;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern uint32_t _stack_top;

/* Main function */
extern int main(void);

/* Default handler */
void Default_Handler(void) {
    while (1);
}

/* Exception handlers (weak, can be overridden) */
void NMI_Handler(void)        __attribute__((weak, alias("Default_Handler")));
void HardFault_Handler(void)  __attribute__((weak, alias("Default_Handler")));
void MemManage_Handler(void)  __attribute__((weak, alias("Default_Handler")));
void BusFault_Handler(void)   __attribute__((weak, alias("Default_Handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SVC_Handler(void)        __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void)     __attribute__((weak, alias("Default_Handler")));
void SysTick_Handler(void)    __attribute__((weak, alias("Default_Handler")));

/* IRQ handlers for LM3S6965 */
void UART0_Handler(void)      __attribute__((weak, alias("Default_Handler")));
void UART1_Handler(void)      __attribute__((weak, alias("Default_Handler")));
void UART2_Handler(void)      __attribute__((weak, alias("Default_Handler")));
void Timer0_Handler(void)     __attribute__((weak, alias("Default_Handler")));
void Timer1_Handler(void)     __attribute__((weak, alias("Default_Handler")));
void Timer2_Handler(void)     __attribute__((weak, alias("Default_Handler")));
void Timer3_Handler(void)     __attribute__((weak, alias("Default_Handler")));
void Ethernet_Handler(void)   __attribute__((weak, alias("Default_Handler")));

/* Reset handler */
void Reset_Handler(void) {
    uint32_t *src, *dst;

    /* Copy .data from Flash to SRAM */
    src = &_etext;
    dst = &_sdata;
    while (dst < &_edata) {
        *dst++ = *src++;
    }

    /* Zero .bss */
    dst = &_sbss;
    while (dst < &_ebss) {
        *dst++ = 0;
    }

    /* Call main */
    main();

    /* Hang if main returns */
    while (1);
}

/* Vector table */
__attribute__((section(".vectors")))
void (* const vector_table[])(void) = {
    (void (*)(void))(&_stack_top),  /* Initial SP */
    Reset_Handler,                   /* Reset */
    NMI_Handler,                     /* NMI */
    HardFault_Handler,               /* Hard Fault */
    MemManage_Handler,               /* MPU Fault */
    BusFault_Handler,                /* Bus Fault */
    UsageFault_Handler,              /* Usage Fault */
    0, 0, 0, 0,                      /* Reserved */
    SVC_Handler,                     /* SVCall */
    0, 0,                            /* Reserved */
    PendSV_Handler,                  /* PendSV */
    SysTick_Handler,                 /* SysTick */

    /* LM3S6965 IRQs */
    0,                  /* 0: GPIO Port A */
    0,                  /* 1: GPIO Port B */
    0,                  /* 2: GPIO Port C */
    0,                  /* 3: GPIO Port D */
    0,                  /* 4: GPIO Port E */
    UART0_Handler,      /* 5: UART0 */
    UART1_Handler,      /* 6: UART1 */
    0,                  /* 7: SSI0 */
    0,                  /* 8: I2C0 */
    0,                  /* 9: PWM Fault */
    0,                  /* 10: PWM Gen 0 */
    0,                  /* 11: PWM Gen 1 */
    0,                  /* 12: PWM Gen 2 */
    0,                  /* 13: QEI0 */
    0,                  /* 14: ADC0 Seq 0 */
    0,                  /* 15: ADC0 Seq 1 */
    0,                  /* 16: ADC0 Seq 2 */
    0,                  /* 17: ADC0 Seq 3 */
    0,                  /* 18: Watchdog */
    Timer0_Handler,     /* 19: Timer0 A */
    0,                  /* 20: Timer0 B */
    Timer1_Handler,     /* 21: Timer1 A */
    0,                  /* 22: Timer1 B */
    Timer2_Handler,     /* 23: Timer2 A */
    0,                  /* 24: Timer2 B */
    0,                  /* 25: Comparator 0 */
    0,                  /* 26: Comparator 1 */
    0,                  /* 27: Comparator 2 */
    0,                  /* 28: System Control */
    0,                  /* 29: Flash Control */
    0,                  /* 30: GPIO Port F */
    0,                  /* 31: GPIO Port G */
    0,                  /* 32: GPIO Port H */
    UART2_Handler,      /* 33: UART2 */
    0,                  /* 34: SSI1 */
    Timer3_Handler,     /* 35: Timer3 A */
    0,                  /* 36: Timer3 B */
    0,                  /* 37: I2C1 */
    0,                  /* 38: QEI1 */
    0,                  /* 39: CAN0 */
    0,                  /* 40: CAN1 */
    0,                  /* 41: CAN2 */
    Ethernet_Handler,   /* 42: Ethernet */
    0,                  /* 43: Hibernate */
};
