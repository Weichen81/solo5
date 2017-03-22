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
#include <asm/msr-index.h>
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
 * 0x013000
 * 0x012000    bootstrap pde
 * 0x011000    bootstrap pdpte
 * 0x010000    bootstrap pml4
 * ########    command line arguments
 * 0x002000    ukvm_boot_info
 * 0x001000    bootstrap gdt (contains correct code/data/ but tss points to 0)
 */

#define BOOT_GDT     0x1000
#define BOOT_INFO    0x2000
#define BOOT_PML4    0x10000
#define BOOT_PDPTE   0x11000
#define BOOT_PDE     0x12000

#define BOOT_GDT_NULL    0
#define BOOT_GDT_CODE    1
#define BOOT_GDT_DATA    2
#define BOOT_GDT_MAX     3

#define KVM_32BIT_MAX_MEM_SIZE  (1ULL << 32)
#define KVM_32BIT_GAP_SIZE    (768 << 20)
#define KVM_32BIT_GAP_START    (KVM_32BIT_MAX_MEM_SIZE - KVM_32BIT_GAP_SIZE)

void setup_boot_info(uint8_t *mem,
                    uint64_t size,
                    uint64_t kernel_end,
                    int argc, char **argv)
{
    struct ukvm_boot_info *bi = (struct ukvm_boot_info *)(mem + BOOT_INFO);
    uint64_t cmdline = BOOT_INFO + sizeof(struct ukvm_boot_info);
    size_t cmdline_free = BOOT_PML4 - cmdline - 1;
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

static void setup_system_64bit(struct kvm_sregs *sregs)
{
    sregs->cr0 |= X86_CR0_PE;
    sregs->efer |= EFER_LME;
}

static void setup_system_sse(struct kvm_sregs *sregs)
{
    sregs->cr0 &= ~X86_CR0_EM;
    sregs->cr0 |= X86_CR0_MP;
    sregs->cr4 |= X86_CR4_OSFXSR;
    sregs->cr4 |= X86_CR4_OSXMMEXCPT;
}

static void setup_system_page_tables(struct kvm_sregs *sregs, uint8_t *mem)
{
    uint64_t *pml4 = (uint64_t *) (mem + BOOT_PML4);
    uint64_t *pdpte = (uint64_t *) (mem + BOOT_PDPTE);
    uint64_t *pde = (uint64_t *) (mem + BOOT_PDE);
    uint64_t paddr;

    /*
     * For simplicity we currently use 2MB pages and only a single
     * PML4/PDPTE/PDE.  Sanity check that the guest size is a multiple of the
     * page size and will fit in a single PDE (512 entries).
     */
    assert((GUEST_SIZE & (GUEST_PAGE_SIZE - 1)) == 0);
    assert(GUEST_SIZE <= (GUEST_PAGE_SIZE * 512));

    memset(pml4, 0, 4096);
    memset(pdpte, 0, 4096);
    memset(pde, 0, 4096);

    *pml4 = BOOT_PDPTE | (X86_PDPT_P | X86_PDPT_RW);
    *pdpte = BOOT_PDE | (X86_PDPT_P | X86_PDPT_RW);
    for (paddr = 0; paddr < GUEST_SIZE; paddr += GUEST_PAGE_SIZE, pde++)
        *pde = paddr | (X86_PDPT_P | X86_PDPT_RW | X86_PDPT_PS);

    sregs->cr3 = BOOT_PML4;
    sregs->cr4 |= X86_CR4_PAE;
    sregs->cr0 |= X86_CR0_PG;
}

static void setup_system_gdt(struct kvm_sregs *sregs,
                             uint8_t *mem,
                             uint64_t off)
{
    uint64_t *gdt = (uint64_t *) (mem + off);
    struct kvm_segment data_seg, code_seg;

    /* flags, base, limit */
    gdt[BOOT_GDT_NULL] = GDT_ENTRY(0, 0, 0);
    gdt[BOOT_GDT_CODE] = GDT_ENTRY(0xA09B, 0, 0xFFFFF);
    gdt[BOOT_GDT_DATA] = GDT_ENTRY(0xC093, 0, 0xFFFFF);

    sregs->gdt.base = off;
    sregs->gdt.limit = (sizeof(uint64_t) * BOOT_GDT_MAX) - 1;

    GDT_TO_KVM_SEGMENT(code_seg, gdt, BOOT_GDT_CODE);
    GDT_TO_KVM_SEGMENT(data_seg, gdt, BOOT_GDT_DATA);

    sregs->cs = code_seg;
    sregs->ds = data_seg;
    sregs->es = data_seg;
    sregs->fs = data_seg;
    sregs->gs = data_seg;
    sregs->ss = data_seg;
}

void setup_system(int vmfd, int vcpufd, uint8_t *mem)
{
    struct kvm_sregs sregs;
    int ret;

    /* Set all cpu/mem system structures */
    ret = ioctl(vcpufd, KVM_GET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM: ioctl (GET_SREGS) failed");

    setup_system_gdt(&sregs, mem, BOOT_GDT);
    setup_system_page_tables(&sregs, mem);
    setup_system_64bit(&sregs);
    setup_system_sse(&sregs);

    ret = ioctl(vcpufd, KVM_SET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM: ioctl (SET_SREGS) failed");
}

void setup_cpuid(int kvm, int vcpufd)
{
    struct kvm_cpuid2 *kvm_cpuid;
    int max_entries = 100;

    kvm_cpuid = calloc(1, sizeof(*kvm_cpuid) +
                          max_entries * sizeof(*kvm_cpuid->entries));
    kvm_cpuid->nent = max_entries;

    if (ioctl(kvm, KVM_GET_SUPPORTED_CPUID, kvm_cpuid) < 0)
        err(1, "KVM: ioctl (GET_SUPPORTED_CPUID) failed");

    if (ioctl(vcpufd, KVM_SET_CPUID2, kvm_cpuid) < 0)
        err(1, "KVM: ioctl (SET_CPUID2) failed");
}


/*
 * Initialize registers: instruction pointer for our code, addends,
 * and initial flags required by x86 architecture.
 * Arguments to the kernel main are passed using the x86_64 calling
 * convention: RDI, RSI, RDX, RCX, R8, and R9
 */
void setup_vcpu_init_register(int vcpufd, uint64_t reset_entry)
{
    int ret;
    struct kvm_regs regs = {
        .rip = reset_entry,
        .rax = 2,
        .rbx = 2,
        .rflags = 0x2,
        .rsp = GUEST_SIZE - 8,  /* x86_64 ABI requires ((rsp + 8) % 16) == 0 */
        .rdi = BOOT_INFO,       /* size arg in kernel main */
    };

    ret = ioctl(vcpufd, KVM_SET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM: ioctl (SET_REGS) failed");
}

/* Map a userspace memroy range as guest physical memroy. */
void setup_user_memory_for_guest(int vmfd,
                                 struct ukvm_mem_region_list *regions_list,
                                 uint8_t *va_addr, uint64_t guest_phys_addr,
                                 uint64_t size)
{
    int ret;
    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .flags = 0,
        .guest_phys_addr = guest_phys_addr,
        .memory_size = size,
        .userspace_addr = (uint64_t) va_addr,
    };

    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
    if (ret == -1)
        err(1, "KVM: ioctl (SET_USER_MEMORY_REGION) failed");
}

/* Check whether the guest memory size is valid. */
void check_guest_memory_size(uint32_t size)
{
    /*
     * TODO If the guest size is larger than ~4GB, we need two region
     * slots: one before the pci gap, and one after it.
     * Reference: kvmtool x86/kvm.c:kvm__init_ram()
     */
    assert(size < KVM_32BIT_GAP_START);
}

void err_exit_and_dump_pc(struct kvm_regs *regs, int exit_code)
{
    errx(exit_code, "KVM: host/guest translation fault: rip=0x%llx",
         regs->rip);
}
