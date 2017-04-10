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
#include "ukvm-mm.h"
#include "ukvm-api.h"
#include "ukvm.h"

/*
 * Memory map:
 *
 * 0x100000    loaded elf file (linker script dictates location)
 * ########    unused
 * 0x010000    memory for page table
 * ########    command line arguments
 * 0x002000    ukvm_boot_info
 * 0x001000    non-cacheable page
 * 0x000000    MMIO space to emulate IO abort
 */

#define BOOT_MMIO       0x0
#define BOOT_MMIO_SZ    (BOOT_INFO - BOOT_MMIO)
#define BOOT_PAGE_TABLE 0x10000
#define BOOT_INFO       0x1000
#define BOOT_INFO_SZ    (BOOT_PAGE_TABLE - BOOT_INFO)
#define BOOT_ELF_ENTRY  0x100000

void setup_boot_info(uint8_t *mem,
                    uint64_t size,
                    uint64_t kernel_end,
                    int argc, char **argv)
{
    struct ukvm_boot_info *bi = (struct ukvm_boot_info *)(mem + BOOT_INFO);
    uint64_t cmdline = BOOT_INFO + sizeof(struct ukvm_boot_info);
    size_t cmdline_free = BOOT_PAGE_TABLE - cmdline - 1;
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

static int s_page_used_for_pgt;
static uint64_t alloc_page_for_pgt(void)
{
    uint64_t phy_addr;

    phy_addr = BOOT_PAGE_TABLE + PAGE_SIZE * s_page_used_for_pgt;
    if (phy_addr >= BOOT_ELF_ENTRY)
        err(1, "Run out of the memory for page table!");

    s_page_used_for_pgt++;

    return phy_addr;
}

static uint64_t get_prot_from_region(uint64_t address,
                                struct ukvm_mem_region_list *region_list)
{
    int idx;
    uint64_t prot = PROT_NORMAL;
    struct kvm_userspace_memory_region *r;

    /* Fill the pte for regions */
    for (idx = 0; idx < region_list->count; idx++) {
        r = region_list->regions + idx;

        if (address >= r->guest_phys_addr &&
            address < (r->guest_phys_addr + r->memory_size) ) {
            printf("[%s] slot: %d <%llx, %llx> user : %llx, flag: %d\n",
                __func__, r->slot, r->guest_phys_addr,
                r->memory_size, r->userspace_addr, r->flags);

            if (r->flags & KVM_MEM_READONLY) {
               prot |= PTE_RDONLY;
               prot &= ~PTE_PXN; /* we need the exec in EL1 */
            }
            break;
        }
    }

    if (idx == region_list->count)
        printf("Could not find a prot from regions, address=0x%lx\n", address);

    return prot;
}

static uint64_t get_code_area_end_from_region(struct ukvm_mem_region_list *region_list)
{
    struct kvm_userspace_memory_region *last_region;

    /*
     * The left memory that is not used by elf image is saved in the last
     * region. So the last region is a continuous memory area. We can use
     * 1GB or 2MB block in page tables to map it.
     */
    if (region_list->count <= 0)
        err(1, "Memory regions is empty!");

    /* Get last region from region list */
    last_region = region_list->regions + (region_list->count - 1);
    if (!last_region->guest_phys_addr)
        err(1, "Elf image hasn't been loaded to memory!");

    return last_region->guest_phys_addr - 1;
}

static void init_pte_table(struct pte *pte_tbl, uint64_t start,
                          uint64_t size, uint64_t code_area_end,
                          struct ukvm_mem_region_list *region_list)
{
    int idx, pte_entries;
    uint64_t out_address, prot, *pte_entry;

    pte_entries = DIV_ROUND_UP(size, PAGE_SIZE);
    if (!pte_entries)
        err(1, "Zero size is not permit!");

    for (idx = 0; idx < pte_entries; idx++)
    {
        pte_entry = pte_tbl->entry + idx;
        out_address = start + PAGE_SIZE * idx;

        /*
         * If we are still in core area, we have to check the region list
         * to set correct attributes.
         */
        if (out_address < code_area_end) {
            /* Fill the pte for 0 ~ BOOT_ELF_ENTRY */
            if (out_address < BOOT_ELF_ENTRY)
                prot = PROT_NORMAL;
            /* Fill the pte for code area regions */
            else
                prot = get_prot_from_region(out_address, region_list);
        }
        else
            prot = PROT_NORMAL;

        *pte_entry = out_address | prot;
    }
}

static void init_pmd_table(uint8_t *va_addr, struct pmd *pmd_tbl,
                           uint64_t start, uint64_t size,
                           uint64_t code_area_end,
                           struct ukvm_mem_region_list *region_list)
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
                           left_sz, code_area_end, region_list);
            *pmd_entry = pte_tbl | PMD_TYPE_TABLE;
        }
        /* Use 2MB block to map VA <--> PA for other memory area */
        else
            *pmd_entry = out_address | PROT_SECT_NORMAL;
    }
}

static void init_pud_table(uint8_t *va_addr, struct pud *pud_tbl,
                           uint64_t start, uint64_t size,
                           struct ukvm_mem_region_list *region_list)
{
    int idx, pud_entries;
    uint64_t code_area_end, left_sz, out_address;
    uint64_t *pud_entry;

    /* How many pud we should use */
    pud_entries = DIV_ROUND_UP(size, PUD_SIZE);
    if (pud_entries == 0)
        err(1, "Zero size for guest memory is not permitted!");
    if (pud_entries > 512)
        err(1, "Currently, we only support 512GB address space!");

    /*
     * Because the we placed the code at the beginning of guest memroy,
     * and this memory has been split to multiple regions. Different
     * regions may have different attribute, so we have to use page to
     * manage these regions' attribute. For other memory, we can use
     * block to do VA-PA mapping.
     */
    code_area_end = get_code_area_end_from_region(region_list);

    for (idx = 0; idx < pud_entries; idx++) {
        pud_entry = pud_tbl->entry + idx;
        out_address = start + PUD_SIZE * idx;

        /* Caculate the left memory size that this pud will cover */
        left_sz = size - out_address;
        if (left_sz > PUD_SIZE)
            left_sz = PUD_SIZE;

        printf("** left memory size = 0x%lx\n", left_sz);

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
                           out_address, left_sz, code_area_end, region_list);

            /* Update pmd table address to pud entry */
            *pud_entry = pmd_tbl | PUD_TYPE_TABLE;
        }
        /* Other memory can use 1GB mapping */
        else
            *pud_entry = out_address | PROT_SECT_NORMAL;
    }
}

/* We put the page table at the unused memory */
static void setup_page_table_for_guest(uint8_t *va_addr,
                            uint64_t guest_phys_addr, uint64_t size,
                            struct ukvm_mem_region_list *region_list)
{
    struct pgd *pgd;
    uint64_t pud_tbl;

    /* First page in BOOT_PAGE_TABLE is used for pgd */
    pgd = (struct pgd *)(va_addr + alloc_page_for_pgt());

    /*
     * 1 pud table can provide 512GB address space, so set 1 pud in pgd
     * table is enough. We use the second page for pud table.
     */
    pud_tbl = alloc_page_for_pgt();

    init_pud_table(va_addr, (struct pud *)(va_addr + pud_tbl), 0, size, region_list);

    pgd->entry[0] = pud_tbl | PGD_TYPE_TABLE;
}

static void enable_mmu(int vcpufd)
{
    int ret;
    uint64_t data = 0;
    struct kvm_one_reg reg = {
        .addr = (uint64_t)&data,
    };

    /* set TCR_EL1 */
    data = TCR_TxSZ(48) | TCR_CACHE_FLAGS | TCR_SHARED | \
			TCR_TG_FLAGS | TCR_ASID16 | TCR_TBI0;
    reg.id = ARM64_SYS_REG(3, 0, 2, 0, 2);
    ret = ioctl(vcpufd, KVM_SET_ONE_REG, &reg);
    if (ret == -1)
         err(1, "KVM: Enable SCTLR_EL1[:CM] failed");

    /* set TTBR0_EL1 */
    data = BOOT_PAGE_TABLE;
    reg.id = ARM64_SYS_REG(3, 0, 2, 0, 0);
    ret = ioctl(vcpufd, KVM_SET_ONE_REG, &reg);
    if (ret == -1)
         err(1, "KVM: Enable SCTLR_EL1[:CM] failed");

    /* set TTBR1_EL1 */
    data = BOOT_PAGE_TABLE;
    reg.id = ARM64_SYS_REG(3, 0, 2, 0, 1);
    ret = ioctl(vcpufd, KVM_SET_ONE_REG, &reg);
    if (ret == -1)
         err(1, "KVM: Enable SCTLR_EL1[:CM] failed");

    /* enable MMU, set SCTLR_EL1 */
    reg.id = ARM64_SYS_REG(3, 0, 1, 0, 0);
    ret = ioctl(vcpufd, KVM_GET_ONE_REG, &reg);
    if (ret == -1)
         err(1, "KVM: Get SCTLR_EL1 failed");

    data |= 0x5; /* enable C/M bits for SCTLR_EL1 */
    ret = ioctl(vcpufd, KVM_SET_ONE_REG, &reg);
    if (ret == -1)
         err(1, "KVM: Enable SCTLR_EL1[:CM] failed");
}

static void set_mair(int vcpufd)
{
    int ret;
    uint64_t data;
    struct kvm_one_reg reg = {
        .addr = (uint64_t)&data,
    };

    /* Set the MAIR register */
    data = MAIR(0x00, MT_DEVICE_nGnRnE) | \
           MAIR(0x04, MT_DEVICE_nGnRE) | \
           MAIR(0x0c, MT_DEVICE_GRE) | \
           MAIR(0x44, MT_NORMAL_NC) | \
           MAIR(0xffUL, MT_NORMAL) | \
           MAIR(0xbbUL, MT_NORMAL_WT);

    reg.id = ARM64_SYS_REG(3, 0, 0xa, 2, 0);
    ret = ioctl(vcpufd, KVM_SET_ONE_REG, &reg);
    if (ret == -1)
         err(1, "KVM: Set MAIR_EL1 failed");
}

static void setup_system_mmu(int vcpufd)
{
    /* Set the MAIR before we set the page table. */
    set_mair(vcpufd);

    /* Enable the MMU */
    enable_mmu(vcpufd);
}

void setup_system(int vmfd, int vcpufd, uint8_t *mem)
{
    setup_system_preferred_target(vmfd, vcpufd);

    setup_system_enable_float(vcpufd);

    setup_system_mmu(vcpufd);
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

    /* Build guest side page table */
    setup_page_table_for_guest(va_addr, guest_phys_addr, size, regions_list);
}

void err_exit_and_dump_pc(struct kvm_regs *regs, int exit_code)
{
    errx(exit_code, "KVM: host/guest translation fault: pc=0x%llx",
         regs->regs.pc);
}

/* Check whether the guest memory size is valid. */
void check_guest_memory_size(uint32_t size)
{
    if (size & (PAGE_SIZE - 1))
        err(1, "Guest memory size must be %d alignment!", PAGE_SIZE);
}

void setup_cpuid(int kvm, int vcpufd)
{

}
