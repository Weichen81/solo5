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

#include "kernel.h"
#include "queue.h"

static void vector_table_init(void)
{
    __asm__ __volatile__("adr x8, exception_vectors\n"
                         "msr vbar_el1, x8\n");
    return;
}

static const char *exception_modes[]= {
        "Synchronous Abort",
        "IRQ",
        "FIQ",
        "Error"
};

void trap_handler(int el, int mode)
{
    printf("Exception caught in EL%d:%s\n", el, exception_modes[mode]);
    PANIC("Fatal trap");
}

void intr_init(void)
{
    vector_table_init();
    platform_intr_init();
}

struct irq_handler {
    int (*handler)(void *);
    void *arg;

    SLIST_ENTRY(irq_handler) entries;
};

SLIST_HEAD(irq_handler_head, irq_handler);
static struct irq_handler_head irq_handlers[16];

void intr_register_irq(unsigned irq, int (*handler)(void *), void *arg)
{
    assert (irq < 16);
    struct irq_handler *h = malloc(sizeof (struct irq_handler));
    assert(h != NULL);
    h->handler = handler;
    h->arg = arg;

    intr_disable();
    SLIST_INSERT_HEAD(&irq_handlers[irq], h, entries);
    intr_enable();
    platform_intr_clear_irq(irq);
}

void irq_handler(uint64_t irq)
{
    struct irq_handler *h;
    int handled = 0;

    SLIST_FOREACH(h, &irq_handlers[irq], entries) {
        if (h->handler(h->arg) == 1) {
            handled = 1;
            break;
        }
    }

    if (!handled)
        printf("Solo5: unhandled irq %d\n", irq);
    else
        /* Only ACK the IRQ if handled; we only need to know about an unhandled
         * IRQ the first time round. */
        platform_intr_ack_irq(irq);
}

/* keeps track of how many stacked "interrupts_disable"'s there are */
int intr_depth = 1;

void intr_disable(void)
{
    __asm__ __volatile__("msr daifset, #2");
    intr_depth++;
}

void intr_enable(void)
{
    assert(intr_depth > 0);

    if (--intr_depth == 0)
        __asm__ __volatile__("msr daifclr, #2");
}
