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

/* We used several existing projects as guides
 *   kvmtest.c: http://lwn.net/Articles/658512/
 *   lkvm: http://github.com/clearlinux/kvmtool
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/kvm.h>
#include <assert.h>

#include "ukvm-private.h"
#include "ukvm-cpu.h"
#include "ukvm.h"

/*
 * Memory map:
 *
 * 0x100000    loaded elf file (linker script dictates location)
 * ########    unused
 * 0x010000    unused
 * ########    command line arguments
 * 0x001000    ukvm_boot_info
 * 0x000000    MMIO space to emulate IO abort
 */

#define BOOT_MMIO       0x0
#define BOOT_MMIO_SZ    (BOOT_INFO - BOOT_MMIO)
#define BOOT_INFO       0x1000
#define BOOT_INFO_SZ    (BOOT_UNUSED - BOOT_INFO)
#define BOOT_UNUSED     0x10000
#define BOOT_UNUSED_SZ  (BOOT_ELF_ENTRY - BOOT_UNUSED)
#define BOOT_ELF_ENTRY  0x100000
