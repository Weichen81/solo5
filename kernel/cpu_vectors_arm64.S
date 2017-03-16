/* Linkage for ARM */
#define __ALIGN .align 2
#define __ALIGN_STR ".align 2"

#define ALIGN __ALIGN
#define ALIGN_STR __ALIGN_STR

#define ENTRY(name)                             \
  .globl name;                                  \
  ALIGN;                                        \
  name:

#define GLOBAL(name)                            \
  .globl name;                                  \
  name:

#define END(name) \
  .size name, .-name

#define ENDPROC(name) \
  .type name, %function; \
  END(name)

/*
 * Exception trap types
 *-----------------
 */
#define ET_SYNC    0
#define ET_IRQ     1
#define ET_FIQ     2
#define ET_ERROR   3

/*
 * Invalid exception handlers
 */
    .macro	invalid_trap, el, type
    mov	x0, #\el
    mov x1, #\type
    b	trap_handler
    .endm

el0_sync_invalid:
	invalid_trap 0, ET_SYNC
ENDPROC(el0_sync_invalid)

el0_irq_invalid:
	invalid_trap 0, ET_IRQ
ENDPROC(el0_irq_invalid)

el0_fiq_invalid:
    invalid_trap 0, ET_FIQ
ENDPROC(el0_fiq_invalid)

el0_error_invalid:
	invalid_trap 0, ET_ERROR
ENDPROC(el0_error_invalid)

el1_sync_invalid:
	invalid_trap 1, ET_SYNC
ENDPROC(el1_sync_invalid)

el1_irq_invalid:
	invalid_trap 1, ET_IRQ
ENDPROC(el1_irq_invalid)

el1_fiq_invalid:
	invalid_trap 1, ET_FIQ
ENDPROC(el1_fiq_invalid)

el1_error_invalid:
	invalid_trap 1, ET_ERROR
ENDPROC(el1_error_invalid)

    .macro exception_entry label
    .align 7
    b \label
    .endm

/*
 * Exception vectors.
 *
 * AArch64 unikernel runs in EL1 mode using the SP1 stack. The vectors
 * don't have a fixed address, only alignment (2^11) requirements.
 */
	.pushsection ".exception.text", "ax"

    .align  11
ENTRY(exception_vectors)
    /*
     * EL1 Exceptions with SP_EL0. We had configure the SPSel to
     * select the SP_EL1. So all such excetpions will be treated
     * as invalid.
     */
    exception_entry el1_sync_invalid        // Synchronous EL1t
    exception_entry el1_irq_invalid         // IRQ EL1t
    exception_entry el1_fiq_invalid         // FIQ EL1t
    exception_entry el1_error_invalid       // Error EL1t

    /* EL1 Exceptions with SP_EL1 */
    exception_entry el1_sync_invalid        // Synchronous EL1h
    exception_entry el1_irq_invalid         // IRQ EL1h
    exception_entry el1_fiq_invalid         // FIQ EL1h
    exception_entry el1_error_invalid       // Error EL1h

    /* EL0 Exceptions, and EL0 execute state is AARCH64. */
    exception_entry el0_sync_invalid        // Synchronous 64-bit EL0
    exception_entry el0_irq_invalid         // IRQ 64-bit EL0
    exception_entry el0_fiq_invalid         // FIQ 64-bit EL0
    exception_entry el0_error_invalid       // Error 64-bit EL0

    /*
     * EL0 Exceptions, and EL0 execute state is AARCH32. We don't want to
     * make AARCH32 code to be compatible on AACH64, so all such exceptions
     * will be treated as invalid.
     */
    exception_entry el0_sync_invalid        // Synchronous 32-bit EL0
    exception_entry el0_irq_invalid         // IRQ 32-bit EL0
    exception_entry el0_fiq_invalid         // FIQ 32-bit EL0
    exception_entry el0_error_invalid       // Error 32-bit EL0

END(exception_vectors)
