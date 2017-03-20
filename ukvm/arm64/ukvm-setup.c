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
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/kvm.h>
#include <assert.h>

#include "ukvm-private.h"
#include "ukvm-cpu.h"
#include "ukvm-api.h"
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

void setup_boot_info(uint8_t *mem,
                    uint64_t size,
                    uint64_t kernel_end,
                    int argc, char **argv)
{
    struct ukvm_boot_info *bi = (struct ukvm_boot_info *)(mem + BOOT_INFO);
    uint64_t cmdline = BOOT_INFO + sizeof(struct ukvm_boot_info);
    size_t cmdline_free = BOOT_UNUSED - cmdline - 1;
    char *cmdline_p = (char *)(mem + cmdline);

    bi->mem_size = size;
    bi->kernel_end = kernel_end;
    bi->cmdline = cmdline;
    cmdline_p[0] = 0;

    for (; *argv; argc--, argv++) {
        size_t alen = snprintf(cmdline_p, cmdline_free, "%s%s", *argv,
                (argc > 1) ? " " : "");
        if (alen >= cmdline_free) {
            warnx("command line too long, truncated");
            break;
        }
        cmdline_free -= alen;
        cmdline_p += alen;
    }
}

static void setup_system_preferred_target(int vmfd, int vcpufd)
{
    int ret;
    struct kvm_vcpu_init init;

    ret = ioctl(vmfd, KVM_ARM_PREFERRED_TARGET, &init);
    if (ret == -1)
        err(1, "KVM: ioctl (KVM_ARM_PREFERRED_TARGET) failed");

    ret = ioctl(vcpufd, KVM_ARM_VCPU_INIT, &init);
    if (ret == -1)
        err(1, "KVM: ioctl (KVM_ARM_VCPU_INIT) failed");
}

static void setup_system_enable_float(int vcpufd)
{
    int ret;
    uint64_t data;
    struct kvm_one_reg reg = {
        .addr = (uint64_t)&data,
    };

    /* Enable the floating-point and Advanced SIMD registers for Guest */
    reg.id	= CPACR_EL1;
    ret = ioctl(vcpufd, KVM_GET_ONE_REG, &reg);
    if (ret == -1)
         err(1, "KVM: Get CPACR_EL1 failed");

    data &= ~(_FPEN_MASK);
    data |= (_FPEN_NOTRAP << _FPEN_SHIFT);
    ret = ioctl(vcpufd, KVM_SET_ONE_REG, &reg);
    if (ret == -1)
         err(1, "KVM: Enable SIMD[:FPEN] failed");
}

/*
 * Initialize registers: instruction pointer for our code, addends,
 * and PSTATE flags required by ARM64 architecture.
 * Arguments to the kernel main are passed using the ARM64 calling
 * convention: x0 ~ x7
 */
void setup_vcpu_init_register(int vcpufd, uint64_t reset_entry)
{
    int ret;
    uint64_t data;
    struct kvm_one_reg reg = {
        .addr = (uint64_t)&data,
    };

    /* Setup PSTATE: Mask Debug, Abort, IRQ and FIQ. Switch to EL1h mode */
    data = PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL1h;
    reg.id = ARM64_CORE_REG(regs.pstate);
    ret = ioctl(vcpufd, KVM_SET_ONE_REG, &reg);
    if (ret == -1)
         err(1, "KVM_SET_ONE_REG failed (spsr[EL1])");

    /*
     * Set Stack Poniter for Guest. ARM64 require stack be 16-bytes
     * alignment by default.
     */
    data = GUEST_SIZE - 16;
    reg.id = ARM64_CORE_REG(sp_el1);
    ret = ioctl(vcpufd, KVM_SET_ONE_REG, &reg);
    if (ret == -1)
         err(1, "KVM_SET_ONE_REG failed (SP)");


    /* Passing ukvm_boot_info through x0 */
    data = BOOT_INFO;
    reg.id = ARM64_CORE_REG(regs.regs[0]);
    ret = ioctl(vcpufd, KVM_SET_ONE_REG, &reg);
    if (ret == -1)
         err(1, "KVM_SET_ONE_REG failed (x0])");

    /* Set guest reset PC entry here */
    data = reset_entry;
    reg.id = ARM64_CORE_REG(regs.pc);
    ret = ioctl(vcpufd, KVM_SET_ONE_REG, &reg);
    if (ret == -1)
         err(1, "KVM_SET_ONE_REG failed (PC)");
}

void setup_system(int vmfd, int vcpufd, uint8_t *mem)
{
    setup_system_preferred_target(vmfd, vcpufd);

    setup_system_enable_float(vcpufd);
}

/* Map a userspace memroy range as guest physical memroy. */
void setup_user_memory_for_guest(int vmfd,
                                 struct ukvm_mem_region_list *regions_list,
                                 uint8_t *va_addr, uint64_t guest_phys_addr,
                                 uint64_t size)
{
    int ret, idx;
    uint32_t used_slot = 0;
    uint64_t elf_va_end = 0, elf_pa_end = 0;
    struct kvm_userspace_memory_region *elf_region;
    struct kvm_userspace_memory_region region;

    /* Register boot_info and unused region before ELF regions */
    region.slot = 0;
    region.flags = 0;
    /* We will skip first 4K bytes for MMIO */
    region.guest_phys_addr = guest_phys_addr + BOOT_MMIO_SZ;
    region.memory_size = BOOT_ELF_ENTRY - BOOT_MMIO_SZ;
    /*
     * To keep the pa and va have the same offset in elf, we should skip
     * first 4K bytes in va too.
     */
    region.userspace_addr = (uint64_t) va_addr + BOOT_MMIO_SZ,

    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
    if (ret == -1)
        err(1, "KVM: ioctl (SET_USER_MEMORY_REGION) slot=%d failed", used_slot);

    used_slot++;
    /* Register elf regions */
    for (idx = 0; idx < regions_list->count; idx++) {
        uint64_t va_end, pa_end;
        elf_region = regions_list->regions + idx;

        /* Update slot number with used slot before elf regions */
        elf_region->slot = used_slot;
        ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, elf_region);
        if (ret == -1)
            err(1, "KVM: ioctl (SET_USER_MEMORY_REGION) failed");

        va_end = elf_region->userspace_addr + elf_region->memory_size;
        pa_end = elf_region->guest_phys_addr + elf_region->memory_size;
        if (pa_end > elf_pa_end) {
            elf_pa_end = pa_end;
            elf_va_end = va_end;
        }

        used_slot++;
    }

    /* Register left memorys (elf_end to guest_size) */
    region.slot = used_slot;
    region.flags = 0;
    region.guest_phys_addr = elf_pa_end;
    region.memory_size = size - elf_pa_end;
    region.userspace_addr = elf_va_end,
    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
    if (ret == -1)
        err(1, "KVM: ioctl (SET_USER_MEMORY_REGION) slot=%d failed", used_slot);
}
