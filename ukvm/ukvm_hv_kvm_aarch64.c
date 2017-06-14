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

    /* Setup aarch64 guest memroy */
    ukvm_aarch64_setup_memory(hvb->vmfd, hv->mem, 0, hv->mem_size,
                              gpa_ep, gpa_kend);

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

