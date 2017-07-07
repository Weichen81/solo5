/*
 * Copyright (c) 2015-2017 Contributors as noted in the AUTHORS file
 *
 * This file is part of Solo5, a unikernel base layer.
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _BITUL

#ifdef ASM_FILE
#define _AC(X,Y)                X
#define _AT(T,X)                X
#else
#define __AC(X,Y)               (X##Y)
#define _AC(X,Y)                __AC(X,Y)
#define _AT(T,X)                ((T)(X))
#endif

#define _BITUL(x)               (_AC(1,UL) << (x))
#define _BITULL(x)              (_AC(1,ULL) << (x))

#endif

/* memory defines */
#define PAGE_SIZE               4096
#define PAGE_SHIFT              12
#define PAGE_MASK               ~(0xfff)

#ifndef ASM_FILE

/* Must be 16-bytes alignment */
struct trap_regs {
    uint64_t regs[31];
    uint64_t pc;
    uint64_t sp;
    uint64_t pstate;
    uint64_t esr;
    uint64_t pad;
};

/*
 * The remainder of this file is used only from C.
 */
static inline uint64_t cpu_cntvct(void)
{
    uint64_t val;

    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r" (val)::);
    return val;
}

#endif /* !ASM_FILE */

