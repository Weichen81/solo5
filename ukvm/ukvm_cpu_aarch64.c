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

static void init_pte_table(struct pte *pte_tbl, uint64_t start, uint64_t size,
                          uint64_t code_area_entry, uint64_t code_area_end)
{
    int idx, pte_entries;

    pte_entries = DIV_ROUND_UP(size, PAGE_SIZE);
    if (!pte_entries)
        err(1, "Zero size is not permit!");

    for (idx = 0; idx < pte_entries; idx++)
    {
        uint64_t prot = PROT_NORMAL;
        uint64_t out_address = start + PAGE_SIZE * idx;
        uint64_t *pte_entry = pte_tbl->entry + idx;

        /*
         * If we are still in core area, we have to check the region list
         * to set correct attributes.
         */
        if (out_address >= code_area_entry &&
            out_address < ukvm_end_of_kernel_rodata) {
            /* Fill the pte for readonly aread */
            prot |= PTE_RDONLY;

            /* Fill the pte for text aread */
            if (out_address < ukvm_end_of_kernel_etext)
                prot &= ~PTE_PXN; /* we need the exec in EL1 */
        }

        *pte_entry = out_address | prot;
    }
}

static void init_pmd_table(uint8_t *va_addr, struct pmd *pmd_tbl,
                           uint64_t start, uint64_t size,
                           uint64_t code_area_entry,
                           uint64_t code_area_end)
{
    int idx, pmd_entries;
    uint64_t out_address, left_sz;
    uint64_t *pmd_entry;

    pmd_entries = DIV_ROUND_UP(size, PMD_SIZE);
    if (!pmd_entries)
        err(1, "Zero size is not permit!");

    for (idx = 0; idx < pmd_entries; idx++)
    {
        pmd_entry = pmd_tbl->entry + idx;
        out_address = start + PMD_SIZE * idx;

        /* Caculate the left memory size that this pmd will cover */
        left_sz = size - out_address;
        if (left_sz > PMD_SIZE)
            left_sz = PMD_SIZE;

        /*
         * 1. If this memory is in code area, we have to create a pte table.
         * 2. If the size is smaller than PMD_SIZE, the last pmd entry must
         *    be configured as table attribute.
         */
        if ((out_address < code_area_end) ||
            (idx == (pmd_entries - 1)  && (left_sz < PMD_SIZE))) {
            uint64_t pte_tbl = alloc_page_for_pgt();

            init_pte_table((struct pte *)(va_addr + pte_tbl), out_address,
                           left_sz, code_area_entry, code_area_end);
            *pmd_entry = pte_tbl | PMD_TYPE_TABLE;
        }
        /* Use 2MB block to map VA <--> PA for other memory area */
        else
            *pmd_entry = out_address | PROT_SECT_NORMAL;
    }
}

static void init_pud_table(uint8_t *va_addr, struct pud *pud_tbl,
                           uint64_t start, uint64_t size,
                           uint64_t code_area_entry,
                           uint64_t code_area_end)
{
    int idx, pud_entries;
    uint64_t left_sz, out_address;
    uint64_t *pud_entry;

    /* How many pud we should use */
    pud_entries = DIV_ROUND_UP(size, PUD_SIZE);
    if (pud_entries == 0)
        err(1, "Zero size for guest memory is not permitted!");
    if (pud_entries > 512)
        err(1, "Currently, we only support 512GB address space!");

    /*
     * Because the we placed the code at the beginning of guest memroy,
     * and this memory has been split to multiple sections. Different
     * sections may have different attributes, so we have to use page to
     * manage these sections' attribute. For other memory, we can use
     * block to do VA-PA mapping.
     */
    for (idx = 0; idx < pud_entries; idx++) {
        pud_entry = pud_tbl->entry + idx;
        out_address = start + PUD_SIZE * idx;

        /* Caculate the left memory size that this pud will cover */
        left_sz = size - out_address;
        if (left_sz > PUD_SIZE)
            left_sz = PUD_SIZE;

        /*
         * 1. If this memory is in code area, we have to create a pud table.
         * 2. If the size is smaller than PUD_SIZE, the last pud entry must
         *    be configured as table attribute.
         */
        if ((out_address < code_area_end) ||
            (idx == (pud_entries - 1) && (left_sz < PUD_SIZE))) {
            /* Create next level for code area */
            uint64_t pmd_tbl = alloc_page_for_pgt();

            init_pmd_table(va_addr, (struct pmd *)(va_addr + pmd_tbl),
                           out_address, left_sz,
                           code_area_entry, code_area_end);

            /* Update pmd table address to pud entry */
            *pud_entry = pmd_tbl | PUD_TYPE_TABLE;
        }
        /* Other memory can use 1GB mapping */
        else
            *pud_entry = out_address | PROT_SECT_NORMAL;
    }
}

/* We put the page table at the unused memory */
static void aarch64_setup_pagetables(uint8_t *va_addr, uint64_t size,
                                     uint64_t guest_phys_addr,
                                     uint64_t code_area_entry,
                                     uint64_t code_area_end)
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

    init_pud_table(va_addr, (struct pud *)(va_addr + pud_tbl),
                   0, size, code_area_entry, code_area_end);

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

/* Map a userspace memroy range as guest physical memroy. */
void ukvm_aarch64_setup_memory(int vmfd, void* vaddr,
                               uint64_t guest_phys_addr, uint64_t size,
                               ukvm_gpa_t gpa_ep, ukvm_gpa_t gpa_kend)
{
    int ret;
    struct kvm_userspace_memory_region region;

    /* Register boot_info and unused region before ELF regions */
    region.slot = 0;
    region.flags = 0;

    /* We will skip first 4K bytes for MMIO */
    region.guest_phys_addr = guest_phys_addr + AARCH64_MMIO_SZ;

    /* The elf entry can't be smaller than AARCH64_GUEST_MIN_BASE */
    if (gpa_ep < AARCH64_GUEST_MIN_BASE)
         err(1, "Guest elf entry [%lx] is smaller than AARCH64_GUEST_MIN_BASE [%x]\n",
             gpa_ep, AARCH64_GUEST_MIN_BASE);

    /*
     * Regardless of the gap between elf entry and AARCH64_GUEST_MIN_BASE,
     * We configure all memroy before elf entry as the first region.
     */
    region.memory_size = gpa_ep - AARCH64_MMIO_SZ;

    /*
     * To keep the pa and va have the same offset in elf, we should skip
     * first 4K bytes in va too.
     */
    region.userspace_addr = (uint64_t)(vaddr + AARCH64_MMIO_SZ);
    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
    if (ret == -1)
        goto out_error;


    /*
     * Register the memory from elf entry to _erodata as the second region.
     * This region contains .text and .rodata. It should be configured as
     * READONLY.
     */
    region.slot++;
    region.flags = KVM_MEM_READONLY;
    region.guest_phys_addr = guest_phys_addr + gpa_ep;
    region.memory_size = ukvm_end_of_kernel_rodata - gpa_ep;
    region.userspace_addr = (uint64_t)(vaddr + gpa_ep);
    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
    if (ret == -1)
        goto out_error;

    /*
     * Register the memory from _erodata to guest_size as the third region.
     * This region contains .data, .bss, stack and heap. it should be
     * configured as WRITEABLE.
     */
    region.slot++;
    region.flags = 0;
    region.guest_phys_addr = guest_phys_addr + ukvm_end_of_kernel_rodata;
    region.memory_size = size - ukvm_end_of_kernel_rodata;
    region.userspace_addr = (uint64_t)(vaddr + ukvm_end_of_kernel_rodata);
    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
    if (ret == -1)
        goto out_error;

    /* Build guest side page tables */
    aarch64_setup_pagetables(vaddr, size, guest_phys_addr, gpa_ep, gpa_kend);

    return;

out_error:
    err(1, "KVM: ioctl (SET_USER_MEMORY_REGION) slot=%d failed", region.slot);
}

