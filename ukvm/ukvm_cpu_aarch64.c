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
 * ukvm_cpu_aarch64.c: Common architecture-dependent code supporting aarch64
 * backend implementations.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/ioctl.h>

#include <linux/kvm.h>

#include "ukvm.h"
#include "ukvm_hv_kvm.h"
#include "ukvm_cpu_aarch64.h"

static int s_page_used_for_pgt;
static uint64_t alloc_page_for_pgt(void)
{
    uint64_t phy_addr;

    phy_addr = AARCH64_PAGE_TABLE + PAGE_SIZE * s_page_used_for_pgt;
    if (phy_addr >= AARCH64_GUEST_MIN_BASE)
        err(1, "Run out of the memory for page table!");

    s_page_used_for_pgt++;

    return phy_addr;
}

static void init_pud_table(uint8_t *va_addr, struct pud *pud_tbl,
                           uint64_t start, uint64_t size)
{
    int idx, pud_entries;
    uint64_t out_address;
    uint64_t *pud_entry;

    /* How many pud we should use */
    pud_entries = DIV_ROUND_UP(size, PUD_SIZE);
    if (pud_entries == 0)
        err(1, "Zero size for guest memory is not permitted!");
    if (pud_entries > 512)
        err(1, "Currently, we only support 512GB address space!");

    for (idx = 0; idx < pud_entries; idx++) {
        pud_entry = pud_tbl->entry + idx;
        out_address = start + PUD_SIZE * idx;

        *pud_entry = out_address | PROT_SECT_NORMAL_EXEC;
    }
}

/* We put the page table at the unused memory */
void ukvm_aarch64_setup_pagetables(uint8_t *va_addr, uint64_t size)
{
    struct pgd *pgd;
    uint64_t pud_tbl;

    /* First page in AARCH64_PAGE_TABLE is used for pgd */
    pgd = (struct pgd *)(va_addr + alloc_page_for_pgt());

    /*
     * 1 pud table can provide 512GB address space, so set 1 pud in pgd
     * table is enough. We use the second page for pud table.
     */
    pud_tbl = alloc_page_for_pgt();

    init_pud_table(va_addr, (struct pud *)(va_addr + pud_tbl), 0, size);

    pgd->entry[0] = pud_tbl | PGD_TYPE_TABLE;
}

static int aarch64_set_one_register(int vcpufd, uint64_t id, uint64_t data)
{
    struct kvm_one_reg one_reg = {
        .id   = id,
        .addr = (uint64_t)&data,
    };

    return ioctl(vcpufd, KVM_SET_ONE_REG, &one_reg);
}

static int aarch64_get_one_register(int vcpufd, uint64_t id, uint64_t *pdata)
{
    struct kvm_one_reg one_reg = {
        .id   = id,
        .addr = (uint64_t)pdata,
    };

    return ioctl(vcpufd, KVM_GET_ONE_REG, &one_reg);
}

static uint64_t aarch64_get_counter_frequency(void)
{
    uint64_t frq;

    __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r" (frq):: "memory");

    return frq;
}

static void aarch64_setup_preferred_target(int vmfd, int vcpufd)
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

static void aarch64_enable_guest_float(int vcpufd)
{
    int ret;
    uint64_t data;

    /* Enable the floating-point and Advanced SIMD registers for Guest */
    ret = aarch64_get_one_register(vcpufd, CPACR_EL1, &data);
    if (ret == -1)
         err(1, "KVM: Get Architectural Feature Access Control Register failed");

    data &= ~(_FPEN_MASK);
    data |= (_FPEN_NOTRAP << _FPEN_SHIFT);
    ret = aarch64_set_one_register(vcpufd, CPACR_EL1, data);
    if (ret == -1)
         err(1, "KVM: Enable the floating-point and Advanced SIMD for Guest failed");
}

static void aarch64_enable_guest_mmu(int vcpufd)
{
    int ret;
    uint64_t data;

    /*
     * Setup Memory Attribute Indirection Register EL1, this register
     * must be set before setup page tables.
     */
    data = MAIR_EL1_INIT;
    ret = aarch64_set_one_register(vcpufd, MAIR_EL1, data);
    if (ret == -1)
         err(1, "KVM: Setup Memory Attribute Indirection Register failed");

    /* Setup Translation Control Register EL1 */
    data = TCR_EL1_INIT;
    ret = aarch64_set_one_register(vcpufd, TCR_EL1, data);
    if (ret == -1)
         err(1, "KVM: Setup Translation Control Register EL1 failed");

    /* Setup Translation Table Base Register 0 EL1 */
    data = AARCH64_PAGE_TABLE;
    ret = aarch64_set_one_register(vcpufd, TTBR0_EL1, data);
    if (ret == -1)
         err(1, "KVM: Translation Table Base Register 0 EL1 failed");

    /* Setup Translation Table Base Register 1 EL1 */
    data = AARCH64_PAGE_TABLE;
    ret = aarch64_set_one_register(vcpufd, TTBR1_EL1, data);
    if (ret == -1)
         err(1, "KVM: Setup Translation Table Base Register 1 EL1 failed");

    /* Setup System Control Register EL1 to enable MMU */
    ret = aarch64_get_one_register(vcpufd, SCTLR_EL1, &data);
    if (ret == -1)
         err(1, "KVM: Get System Control Register EL1 failed");

    /* Enable MMU and I/D Cache for EL1 */
    data |= (_SCTLR_M | _SCTLR_C | _SCTLR_I);
    ret = aarch64_set_one_register(vcpufd, SCTLR_EL1, data);
    if (ret == -1)
         err(1, "KVM: Setup System Control Register EL1 failed");
}

int ukvm_aarch64_dump_pc(int vcpufd, uint64_t *pdata)
{
    return aarch64_get_one_register(vcpufd, REG_PC, pdata);
}

/*
 * Configure aarch64 system registers for guest.
 */
void ukvm_aarch64_setup_system(int vmfd, int vcpufd)
{
    aarch64_setup_preferred_target(vmfd, vcpufd);

    aarch64_enable_guest_float(vcpufd);

    aarch64_enable_guest_mmu(vcpufd);
}

/*
 * Initialize registers: instruction pointer for our code, addends,
 * and PSTATE flags required by ARM64 architecture.
 * Arguments to the kernel main are passed using the ARM64 calling
 * convention: x0 ~ x7
 */
void ukvm_aarch64_setup_core(struct ukvm_hv *hv,
                             ukvm_gpa_t gpa_ep, ukvm_gpa_t gpa_kend)
{
    int ret;
    struct ukvm_hvb *hvb = hv->b;
    struct ukvm_boot_info *bi;

    /* Set default PSTATE flags to SPSR_EL1 */
    ret = aarch64_set_one_register(hvb->vcpufd, SPSR_EL1,
                                   AARCH64_PSTATE_INIT);
    if (ret == -1)
         err(1, "Initialize spsr[EL1] failed!\n");

    /*
     * Set Stack Poniter for Guest. ARM64 require stack be 16-bytes
     * alignment by default.
     */
    ret = aarch64_set_one_register(hvb->vcpufd, SP_EL1,
                                   hv->mem_size - 16);
    if (ret == -1)
         err(1, "Initialize sp[EL1] failed!\n");

    bi = (struct ukvm_boot_info *)(hv->mem + AARCH64_BOOT_INFO);
    bi->mem_size = hv->mem_size;
    bi->kernel_end = gpa_kend;
    bi->cmdline = AARCH64_CMDLINE_BASE;

    /*
     * KVM on aarch64 doesn't support KVM_CAP_GET_TSC_KHZ. But we can use
     * the cntvct_el0 as RDTSC of x86. So we can read counter frequency
     * from cntfrq_el0 directly.
     */
    bi->cpu.tsc_freq = aarch64_get_counter_frequency();

    /* Passing ukvm_boot_info through x0 */
    ret = aarch64_set_one_register(hvb->vcpufd, REG_X0, AARCH64_BOOT_INFO);
    if (ret == -1)
         err(1, "Set boot info to x0 failed!\n");

    /* Set guest reset PC entry here */
    ret = aarch64_set_one_register(hvb->vcpufd, REG_PC, gpa_ep);
    if (ret == -1)
         err(1, "Set guest reset entry to PC failed!\n");
}
