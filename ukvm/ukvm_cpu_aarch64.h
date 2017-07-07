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
 * ukvm_cpu_aarch64.h: CPU constants and initialisation data common to aarch64
 * backend implementations.
 */

#ifndef UKVM_CPU_AARCH64_H
#define UKVM_CPU_AARCH64_H

#ifndef _BITUL

#ifdef __ASSEMBLY__
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

#define BITS_32     32
#define BITS_64     64

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << (PAGE_SHIFT))

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
#define AARCH64_GUEST_MIN_BASE  0x100000
#define AARCH64_PAGE_TABLE      0x10000
#define AARCH64_CMDLINE_BASE    0xC000
#define AARCH64_CMDLINE_SZ      (AARCH64_PAGE_TABLE - AARCH64_CMDLINE_BASE)
#define AARCH64_BOOT_INFO       0x1000
#define AARCH64_BOOT_INFO_SZ    (AARCH64_CMDLINE_BASE - AARCH64_BOOT_INFO)
#define AARCH64_MMIO_BASE       0x0
#define AARCH64_MMIO_SZ         (AARCH64_BOOT_INFO - AARCH64_MMIO_BASE)

#define GENMASK32(h, l) \
    (((~0U) << (l)) & (~0U >> (BITS_32 - 1 - (h))))
#define GENMASK64(h, l) \
    (((~0UL) << (l)) & (~0UL >> (BITS_64 - 1 - (h))))

/*
 * KVM/ARM64 provides an interface to userspace to modify the
 * VM registers. This interface describe the register by index.
 * We have to define the index here for those registers that we
 * will modify.
 */

/* Normal registers are mapped as coprocessor 16. */
#define KVM_REG_ARM_CORE    (0x0010 << KVM_REG_ARM_COPROC_SHIFT)

#define ARM64_CORE_REG(x)   \
            (KVM_REG_ARM64 | KVM_REG_SIZE_U64 | \
            KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(x))

/* Saved Program Status Register EL1 */
#define SPSR_EL1            ARM64_CORE_REG(regs.pstate)

/*
 * Default PSTATE flags:
 * Mask Debug, Abort, IRQ and FIQ. Switch to EL1h mode
 */
#define AARCH64_PSTATE_INIT \
                            (PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | \
                             PSR_F_BIT | PSR_MODE_EL1h)

/* PC Register */
#define REG_PC              ARM64_CORE_REG(regs.pc)

/* Stack Pointer EL1 */
#define SP_EL1              ARM64_CORE_REG(sp_el1)

/* Generic Purpose register x0 */
#define REG_X0              ARM64_CORE_REG(regs.regs[0])

/* Architectural Feature Access Control Register EL1 */
#define CPACR_EL1           ARM64_SYS_REG(3, 0, 1, 0, 2)
#define _FPEN_NOTRAP        0x3
#define _FPEN_SHIFT         20
#define _FPEN_MASK          GENMASK32(21, 20)

/* Memory Attribute Indirection Register EL1 */
#define MAIR_EL1            ARM64_SYS_REG(3, 0, 10, 2, 0)

/* Memory types available. */
#define MT_DEVICE_nGnRnE    0
#define MT_DEVICE_nGnRE     1
#define MT_DEVICE_GRE       2
#define MT_NORMAL_NC        3
#define MT_NORMAL           4
#define MT_NORMAL_WT        5

#define MAIR(attr, mt)      (_AC(attr, UL) << ((mt) * 8))

#define MAIR_EL1_INIT       \
        MAIR(0x00, MT_DEVICE_nGnRnE) | MAIR(0x04, MT_DEVICE_nGnRE) | \
        MAIR(0x0C, MT_DEVICE_GRE) | MAIR(0x44, MT_NORMAL_NC) | \
        MAIR(0xFF, MT_NORMAL) | MAIR(0xBB, MT_NORMAL_WT)

/* Translation Control Register EL1 */
#define TCR_EL1             ARM64_SYS_REG(3, 0, 2, 0, 2)

/*
 * TCR flags.
 */
#define TCR_T0SZ_OFFSET     0
#define TCR_T1SZ_OFFSET     16
#define TCR_T0SZ(x)         ((_AC(64, UL) - (x)) << TCR_T0SZ_OFFSET)
#define TCR_T1SZ(x)         ((_AC(64, UL) - (x)) << TCR_T1SZ_OFFSET)
#define TCR_TxSZ(x)         (TCR_T0SZ(x) | TCR_T1SZ(x))

#define TCR_IRGN0_SHIFT     8
#define TCR_IRGN0_WBWA      (_AC(1, UL) << TCR_IRGN0_SHIFT)
#define TCR_IRGN1_SHIFT     24
#define TCR_IRGN1_WBWA      (_AC(1, UL) << TCR_IRGN1_SHIFT)
#define TCR_IRGN_WBWA       (TCR_IRGN0_WBWA | TCR_IRGN1_WBWA)

#define TCR_ORGN0_SHIFT     10
#define TCR_ORGN0_WBWA      (_AC(1, UL) << TCR_ORGN0_SHIFT)
#define TCR_ORGN1_SHIFT     26
#define TCR_ORGN1_WBWA      (_AC(1, UL) << TCR_ORGN1_SHIFT)
#define TCR_ORGN_WBWA       (TCR_ORGN0_WBWA | TCR_ORGN1_WBWA)

#define TCR_SH0_SHIFT       12
#define TCR_SH0_INNER       (_AC(3, UL) << TCR_SH0_SHIFT)
#define TCR_SH1_SHIFT       28
#define TCR_SH1_INNER       (_AC(3, UL) << TCR_SH1_SHIFT)
#define TCR_SHARED          (TCR_SH0_INNER | TCR_SH1_INNER)

#define TCR_TG0_SHIFT       14
#define TCR_TG0_4K          (_AC(0, UL) << TCR_TG0_SHIFT)
#define TCR_TG1_SHIFT       30
#define TCR_TG1_4K          (_AC(2, UL) << TCR_TG1_SHIFT)

#define TCR_ASID16          (_AC(1, UL) << 36)
#define TCR_TBI0            (_AC(1, UL) << 37)

#define TCR_TG_FLAGS        TCR_TG0_4K | TCR_TG1_4K
#define TCR_CACHE_FLAGS     TCR_IRGN_WBWA | TCR_ORGN_WBWA

#define TCR_EL1_INIT        \
            TCR_TxSZ(48) | TCR_CACHE_FLAGS | TCR_SHARED | \
			TCR_TG_FLAGS | TCR_ASID16 | TCR_TBI0;

/* Translation Table Base Register 0 EL1 */
#define TTBR0_EL1           ARM64_SYS_REG(3, 0, 2, 0, 0)

/* Translation Table Base Register 1 EL1 */
#define TTBR1_EL1           ARM64_SYS_REG(3, 0, 2, 0, 1)

/* System Control Register EL1 */
#define SCTLR_EL1           ARM64_SYS_REG(3, 0, 1, 0, 0)
#define _SCTLR_M            _BITUL(0)
#define _SCTLR_C            _BITUL(2)
#define _SCTLR_I            _BITUL(12)

/* Definitions of Page tables */
#define PUD_SIZE    0x40000000
#define PUD_MASK	(~(PUD_SIZE-1))
#define PMD_SIZE    0x00200000
#define PMD_MASK	(~(PMD_SIZE-1))

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

struct pte {
    uint64_t entry[1];
};

struct pmd {
    uint64_t entry[1];
};

struct pud {
    uint64_t entry[1];
};

struct pgd {
    uint64_t entry[1];
};

struct pgprot {
    uint64_t value;
} pgprot_t;

/*
 * Hardware page table definitions.
 *
 * Level 0 descriptor (PGD).
 */
#define PGD_TYPE_TABLE      (_AC(3, UL) << 0)
#define PGD_TABLE_BIT		(_AC(1, UL) << 1)
#define PGD_TYPE_MASK		(_AC(3, UL) << 0)
#define PGD_TYPE_SECT		(_AC(1, UL) << 0)

/*
 *
 * Level 1 descriptor (PUD).
 */
#define PUD_TYPE_TABLE      (_AC(3, UL) << 0)
#define PUD_TABLE_BIT       (_AC(1, UL) << 1)
#define PUD_TYPE_MASK       (_AC(3, UL) << 0)
#define PUD_TYPE_SECT       (_AC(1, UL) << 0)

/*
 * Level 2 descriptor (PMD).
 */
#define PMD_TYPE_MASK       (_AC(3, UL) << 0)
#define PMD_TYPE_FAULT      (_AC(0, UL) << 0)
#define PMD_TYPE_TABLE      (_AC(3, UL) << 0)
#define PMD_TYPE_SECT       (_AC(1, UL) << 0)
#define PMD_TABLE_BIT       (_AC(1, UL) << 1)

/*
 * Section
 */
#define PMD_SECT_VALID      (_AC(1, UL) << 0)
#define PMD_SECT_USER       (_AC(1, UL) << 6)     /* AP[1] */
#define PMD_SECT_RDONLY     (_AC(1, UL) << 7)     /* AP[2] */
#define PMD_SECT_S          (_AC(3, UL) << 8)
#define PMD_SECT_AF         (_AC(1, UL) << 10)
#define PMD_SECT_NG         (_AC(1, UL) << 11)
#define PMD_SECT_CONT       (_AC(1, UL) << 52)
#define PMD_SECT_PXN        (_AC(1, UL) << 53)
#define PMD_SECT_UXN        (_AC(1, UL) << 54)

/*
 * AttrIndx[2:0] encoding (mapping attributes defined in the MAIR* registers).
 */
#define PMD_ATTRINDX(t)     (_AC(t, UL) << 2)
#define PMD_ATTRINDX_MASK   (_AC(7) << 2)

/*
 * Level 3 descriptor (PTE).
 */
#define PTE_TYPE_MASK       (_AC(3, UL) << 0)
#define PTE_TYPE_FAULT      (_AC(0, UL) << 0)
#define PTE_TYPE_PAGE       (_AC(3, UL) << 0)
#define PTE_TABLE_BIT       (_AC(1, UL) << 1)
#define PTE_USER            (_AC(1, UL) << 6)     /* AP[1] */
#define PTE_RDONLY          (_AC(1, UL) << 7)     /* AP[2] */
#define PTE_SHARED          (_AC(3, UL) << 8)     /* SH[1:0], inner shareable */
#define PTE_AF              (_AC(1, UL) << 10)    /* Access Flag */
#define PTE_NG              (_AC(1, UL) << 11)    /* nG */
#define PTE_DBM             (_AC(1, UL) << 51)    /* Dirty Bit Management */
#define PTE_CONT            (_AC(1, UL) << 52)    /* Contiguous range */
#define PTE_PXN             (_AC(1, UL) << 53)    /* Privileged XN */
#define PTE_UXN             (_AC(1, UL) << 54)    /* User XN */
#define PTE_HYP_XN          (_AC(1, UL) << 54)    /* HYP XN */

#define PTE_WRITE           (PTE_DBM)        /* same as DBM (51) */
#define PTE_DIRTY           (_AC(1, UL) << 55)

/*
 * AttrIndx[2:0] encoding (mapping attributes defined in the MAIR* registers).
 */
#define PTE_ATTRINDX(t)     (_AC(t, UL) << 2)
#define PTE_ATTRINDX_MASK   (_AC(7, UL) << 2)

#define PROT_DEFAULT        (PTE_TYPE_PAGE | PTE_AF | PTE_SHARED)
#define PROT_SECT_DEFAULT   (PMD_TYPE_SECT | PMD_SECT_AF | PMD_SECT_S)

#define PROT_DEVICE_nGnRnE  (PROT_DEFAULT | PTE_PXN | PTE_UXN | PTE_DIRTY | PTE_WRITE | PTE_ATTRINDX(MT_DEVICE_nGnRnE))
#define PROT_DEVICE_nGnRE   (PROT_DEFAULT | PTE_PXN | PTE_UXN | PTE_DIRTY | PTE_WRITE | PTE_ATTRINDX(MT_DEVICE_nGnRE))
#define PROT_NORMAL_NC      (PROT_DEFAULT | PTE_PXN | PTE_UXN | PTE_DIRTY | PTE_WRITE | PTE_ATTRINDX(MT_NORMAL_NC))
#define PROT_NORMAL_WT      (PROT_DEFAULT | PTE_PXN | PTE_UXN | PTE_DIRTY | PTE_WRITE | PTE_ATTRINDX(MT_NORMAL_WT))
#define PROT_NORMAL         (PROT_DEFAULT | PTE_PXN | PTE_UXN | PTE_DIRTY | PTE_WRITE | PTE_ATTRINDX(MT_NORMAL))

#define PROT_SECT_DEVICE_nGnRE  (PROT_SECT_DEFAULT | PMD_SECT_PXN | PMD_SECT_UXN | PMD_ATTRINDX(MT_DEVICE_nGnRE))
#define PROT_SECT_NORMAL        (PROT_SECT_DEFAULT | PMD_SECT_PXN | PMD_SECT_UXN | PMD_ATTRINDX(MT_NORMAL))
#define PROT_SECT_NORMAL_EXEC   (PROT_SECT_DEFAULT | PMD_SECT_UXN | PMD_ATTRINDX(MT_NORMAL))

uint64_t ukvm_end_of_kernel_rodata;
uint64_t ukvm_end_of_kernel_etext;

int ukvm_aarch64_dump_pc(int vcpufd, uint64_t *pdata);

void ukvm_aarch64_setup_memory(int vmfd, void* vaddr,
                               uint64_t guest_phys_addr, uint64_t size,
                               ukvm_gpa_t gpa_ep, ukvm_gpa_t gpa_kend);

void ukvm_aarch64_setup_system(int vmfd, int vcpufd);

void ukvm_aarch64_setup_core(struct ukvm_hv *hv,
                             ukvm_gpa_t gpa_ep, ukvm_gpa_t gpa_kend);

#endif /* UKVM_CPU_AARCH64_H */
