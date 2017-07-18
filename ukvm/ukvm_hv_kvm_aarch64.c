/*
 * Copyright (c) 2015-2017 Contributors as noted in the AUTHORS file
 *
 * This file is part of ukvm, a unikernel monitor.
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

/*
 * ukvm_hv_kvm_aarch64.c: aarch64 architecture-dependent part of KVM backend
 * implementation.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

#include <linux/kvm.h>

#include "ukvm.h"
#include "ukvm_hv_kvm.h"
#include "ukvm_cpu_aarch64.h"

void ukvm_hv_vcpu_init(struct ukvm_hv *hv, ukvm_gpa_t gpa_ep,
        ukvm_gpa_t gpa_kend, char **cmdline)
{
    struct ukvm_hvb *hvb = hv->b;

    /* Setup aarch64 guest pagetables */
    ukvm_aarch64_setup_pagetables(hv->mem, hv->mem_size);

    /* Setup aarch64 system registers */
    ukvm_aarch64_setup_system(hvb->vmfd, hvb->vcpufd);

    /* Setup aarch64 core registers */
    ukvm_aarch64_setup_core(hv, gpa_ep, gpa_kend);

    *cmdline = (char *)(hv->mem + AARCH64_CMDLINE_BASE);
}

static inline uint32_t mmio_read32(void *data)
{
    return *(uint32_t *)data;
}

void ukvm_hv_vcpu_loop(struct ukvm_hv *hv)
{
    struct ukvm_hvb *hvb = hv->b;
    int ret;

    while (1) {
        ret = ioctl(hvb->vcpufd, KVM_RUN, NULL);
        if (ret == -1 && errno == EINTR)
            continue;
        if (ret == -1) {
            if (errno == EFAULT) {
                uint64_t pc;
                ret = ukvm_aarch64_dump_pc(hvb->vcpufd, &pc);
                if (ret == -1)
                    err(1, "KVM: Dump PC failed after guest fault");
                errx(1, "KVM: host/guest translation fault: pc=0x%lx", pc);
            }
            else
                err(1, "KVM: ioctl (RUN) failed");
        }

        int handled = 0;
        for (ukvm_vmexit_fn_t *fn = ukvm_core_vmexits; *fn && !handled; fn++)
            handled = ((*fn)(hv) == 0);
        if (handled)
            continue;

        struct kvm_run *run = hvb->vcpurun;

        switch (run->exit_reason) {
        case KVM_EXIT_MMIO: {
            if (!run->mmio.is_write || run->mmio.len != 4)
                errx(1, "Invalid guest mmio access: mmio=0x%llx", run->mmio.phys_addr);

            if (run->mmio.phys_addr < UKVM_HYPERCALL_MMIO_BASE ||
                    run->mmio.phys_addr >=
                    (UKVM_HYPERCALL_MMIO_BASE + (UKVM_HYPERCALL_MAX << 2)))
                errx(1, "Invalid guest mmio access: mmio=0x%llx", run->mmio.phys_addr);

            int nr = (run->mmio.phys_addr - UKVM_HYPERCALL_MMIO_BASE) >> 2;

            /* Guest has halted the CPU, this is considered as a normal exit. */
            if (nr == UKVM_HYPERCALL_HALT)
                return;

            ukvm_hypercall_fn_t fn = ukvm_core_hypercalls[nr];
            if (fn == NULL)
                errx(1, "Invalid guest hypercall: num=%d", nr);

            ukvm_gpa_t gpa = mmio_read32(run->mmio.data);
            fn(hv, gpa);
            break;
        }

        case KVM_EXIT_FAIL_ENTRY:
            errx(1, "KVM: entry failure: hw_entry_failure_reason=0x%llx",
                 run->fail_entry.hardware_entry_failure_reason);

        case KVM_EXIT_INTERNAL_ERROR:
            errx(1, "KVM: internal error exit: suberror=0x%x",
                 run->internal.suberror);

        default: {
            uint64_t pc;
            ret = ukvm_aarch64_dump_pc(hvb->vcpufd, &pc);
            if (ret == -1)
                err(1, "KVM: Dump PC failed after unhandled exit");
            errx(1, "KVM: unhandled exit: exit_reason=0x%x, pc=0x%lx",
                    run->exit_reason, pc);
        }
        } /* switch(run->exit_reason) */
    }
}
