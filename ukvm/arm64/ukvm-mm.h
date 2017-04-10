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

#ifndef __UKVM_MM_H__
#define __UKVM_MM_H__

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << (PAGE_SHIFT))

#define SZ_1				0x00000001
#define SZ_2				0x00000002
#define SZ_4				0x00000004
#define SZ_8				0x00000008
#define SZ_16				0x00000010
#define SZ_32				0x00000020
#define SZ_64				0x00000040
#define SZ_128				0x00000080
#define SZ_256				0x00000100
#define SZ_512				0x00000200

#define SZ_1K				0x00000400
#define SZ_2K				0x00000800
#define SZ_4K				0x00001000
#define SZ_8K				0x00002000
#define SZ_16K				0x00004000
#define SZ_32K				0x00008000
#define SZ_64K				0x00010000
#define SZ_128K				0x00020000
#define SZ_256K				0x00040000
#define SZ_512K				0x00080000

#define SZ_1M				0x00100000
#define SZ_2M				0x00200000
#define SZ_4M				0x00400000
#define SZ_8M				0x00800000
#define SZ_16M				0x01000000
#define SZ_32M				0x02000000
#define SZ_64M				0x04000000
#define SZ_128M				0x08000000
#define SZ_256M				0x10000000
#define SZ_512M				0x20000000

#define SZ_1G				0x40000000
#define SZ_2G				0x80000000

#define PUD_SIZE    SZ_1G
#define PUD_MASK	(~(PUD_SIZE-1))
#define PMD_SIZE    SZ_2M
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
#define PGD_TYPE_TABLE      (_AT(uint64_t, 3) << 0)
#define PGD_TABLE_BIT		(_AT(uint64_t, 1) << 1)
#define PGD_TYPE_MASK		(_AT(uint64_t, 3) << 0)
#define PGD_TYPE_SECT		(_AT(uint64_t, 1) << 0)

/*
 *
 * Level 1 descriptor (PUD).
 */
#define PUD_TYPE_TABLE      (_AT(uint64_t, 3) << 0)
#define PUD_TABLE_BIT       (_AT(uint64_t, 1) << 1)
#define PUD_TYPE_MASK       (_AT(uint64_t, 3) << 0)
#define PUD_TYPE_SECT       (_AT(uint64_t, 1) << 0)

/*
 * Level 2 descriptor (PMD).
 */
#define PMD_TYPE_MASK       (_AT(uint64_t, 3) << 0)
#define PMD_TYPE_FAULT      (_AT(uint64_t, 0) << 0)
#define PMD_TYPE_TABLE      (_AT(uint64_t, 3) << 0)
#define PMD_TYPE_SECT       (_AT(uint64_t, 1) << 0)
#define PMD_TABLE_BIT       (_AT(uint64_t, 1) << 1)

/*
 * Section
 */
#define PMD_SECT_VALID      (_AT(uint64_t, 1) << 0)
#define PMD_SECT_USER       (_AT(uint64_t, 1) << 6)     /* AP[1] */
#define PMD_SECT_RDONLY     (_AT(uint64_t, 1) << 7)     /* AP[2] */
#define PMD_SECT_S          (_AT(uint64_t, 3) << 8)
#define PMD_SECT_AF         (_AT(uint64_t, 1) << 10)
#define PMD_SECT_NG         (_AT(uint64_t, 1) << 11)
#define PMD_SECT_CONT       (_AT(uint64_t, 1) << 52)
#define PMD_SECT_PXN        (_AT(uint64_t, 1) << 53)
#define PMD_SECT_UXN        (_AT(uint64_t, 1) << 54)

/*
 * AttrIndx[2:0] encoding (mapping attributes defined in the MAIR* registers).
 */
#define PMD_ATTRINDX(t)     (_AT(uint64_t, (t)) << 2)
#define PMD_ATTRINDX_MASK   (_AT(uint64_t, 7) << 2)

/*
 * Level 3 descriptor (PTE).
 */
#define PTE_TYPE_MASK       (_AT(uint64_t, 3) << 0)
#define PTE_TYPE_FAULT      (_AT(uint64_t, 0) << 0)
#define PTE_TYPE_PAGE       (_AT(uint64_t, 3) << 0)
#define PTE_TABLE_BIT       (_AT(uint64_t, 1) << 1)
#define PTE_USER            (_AT(uint64_t, 1) << 6)     /* AP[1] */
#define PTE_RDONLY          (_AT(uint64_t, 1) << 7)     /* AP[2] */
#define PTE_SHARED          (_AT(uint64_t, 3) << 8)     /* SH[1:0], inner shareable */
#define PTE_AF              (_AT(uint64_t, 1) << 10)    /* Access Flag */
#define PTE_NG              (_AT(uint64_t, 1) << 11)    /* nG */
#define PTE_DBM             (_AT(uint64_t, 1) << 51)    /* Dirty Bit Management */
#define PTE_CONT            (_AT(uint64_t, 1) << 52)    /* Contiguous range */
#define PTE_PXN             (_AT(uint64_t, 1) << 53)    /* Privileged XN */
#define PTE_UXN             (_AT(uint64_t, 1) << 54)    /* User XN */
#define PTE_HYP_XN          (_AT(uint64_t, 1) << 54)    /* HYP XN */

#define PTE_WRITE           (PTE_DBM)        /* same as DBM (51) */
#define PTE_DIRTY           (_AT(uint64_t, 1) << 55)

/*
 * AttrIndx[2:0] encoding (mapping attributes defined in the MAIR* registers).
 */
#define PTE_ATTRINDX(t)     (_AT(uint64_t, (t)) << 2)
#define PTE_ATTRINDX_MASK   (_AT(uint64_t, 7) << 2)

/*
 * Memory types available.
 */
#define MT_DEVICE_nGnRnE    0
#define MT_DEVICE_nGnRE     1
#define MT_DEVICE_GRE       2
#define MT_NORMAL_NC        3
#define MT_NORMAL           4
#define MT_NORMAL_WT        5

#define MAIR(attr, mt)      ((attr) << ((mt) * 8))

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

/*
 * TCR flags.
 */
#define TCR_T0SZ_OFFSET     0
#define TCR_T1SZ_OFFSET     16
#define TCR_T0SZ(x)         ((_AC(64, UL) - (x)) << TCR_T0SZ_OFFSET)
#define TCR_T1SZ(x)         ((_AC(64, UL) - (x)) << TCR_T1SZ_OFFSET)
#define TCR_TxSZ(x)         (TCR_T0SZ(x) | TCR_T1SZ(x))
#define TCR_TxSZ_WIDTH      6
#define TCR_T0SZ_MASK       (((_AC(1, UL) << TCR_TxSZ_WIDTH) - 1) << TCR_T0SZ_OFFSET)

#define TCR_IRGN0_SHIFT     8
#define TCR_IRGN0_MASK      (_AC(3, UL) << TCR_IRGN0_SHIFT)
#define TCR_IRGN0_NC        (_AC(0, UL) << TCR_IRGN0_SHIFT)
#define TCR_IRGN0_WBWA      (_AC(1, UL) << TCR_IRGN0_SHIFT)
#define TCR_IRGN0_WT        (_AC(2, UL) << TCR_IRGN0_SHIFT)
#define TCR_IRGN0_WBnWA     (_AC(3, UL) << TCR_IRGN0_SHIFT)

#define TCR_IRGN1_SHIFT     24
#define TCR_IRGN1_MASK      (_AC(3, UL) << TCR_IRGN1_SHIFT)
#define TCR_IRGN1_NC        (_AC(0, UL) << TCR_IRGN1_SHIFT)
#define TCR_IRGN1_WBWA      (_AC(1, UL) << TCR_IRGN1_SHIFT)
#define TCR_IRGN1_WT        (_AC(2, UL) << TCR_IRGN1_SHIFT)
#define TCR_IRGN1_WBnWA     (_AC(3, UL) << TCR_IRGN1_SHIFT)

#define TCR_IRGN_NC         (TCR_IRGN0_NC | TCR_IRGN1_NC)
#define TCR_IRGN_WBWA       (TCR_IRGN0_WBWA | TCR_IRGN1_WBWA)
#define TCR_IRGN_WT         (TCR_IRGN0_WT | TCR_IRGN1_WT)
#define TCR_IRGN_WBnWA      (TCR_IRGN0_WBnWA | TCR_IRGN1_WBnWA)
#define TCR_IRGN_MASK       (TCR_IRGN0_MASK | TCR_IRGN1_MASK)


#define TCR_ORGN0_SHIFT     10
#define TCR_ORGN0_MASK      (_AC(3, UL) << TCR_ORGN0_SHIFT)
#define TCR_ORGN0_NC        (_AC(0, UL) << TCR_ORGN0_SHIFT)
#define TCR_ORGN0_WBWA      (_AC(1, UL) << TCR_ORGN0_SHIFT)
#define TCR_ORGN0_WT        (_AC(2, UL) << TCR_ORGN0_SHIFT)
#define TCR_ORGN0_WBnWA     (_AC(3, UL) << TCR_ORGN0_SHIFT)

#define TCR_ORGN1_SHIFT     26
#define TCR_ORGN1_MASK      (_AC(3, UL) << TCR_ORGN1_SHIFT)
#define TCR_ORGN1_NC        (_AC(0, UL) << TCR_ORGN1_SHIFT)
#define TCR_ORGN1_WBWA      (_AC(1, UL) << TCR_ORGN1_SHIFT)
#define TCR_ORGN1_WT        (_AC(2, UL) << TCR_ORGN1_SHIFT)
#define TCR_ORGN1_WBnWA     (_AC(3, UL) << TCR_ORGN1_SHIFT)

#define TCR_ORGN_NC         (TCR_ORGN0_NC | TCR_ORGN1_NC)
#define TCR_ORGN_WBWA       (TCR_ORGN0_WBWA | TCR_ORGN1_WBWA)
#define TCR_ORGN_WT         (TCR_ORGN0_WT | TCR_ORGN1_WT)
#define TCR_ORGN_WBnWA      (TCR_ORGN0_WBnWA | TCR_ORGN1_WBnWA)
#define TCR_ORGN_MASK       (TCR_ORGN0_MASK | TCR_ORGN1_MASK)

#define TCR_SH0_SHIFT       12
#define TCR_SH0_MASK        (_AC(3, UL) << TCR_SH0_SHIFT)
#define TCR_SH0_INNER       (_AC(3, UL) << TCR_SH0_SHIFT)

#define TCR_SH1_SHIFT       28
#define TCR_SH1_MASK        (_AC(3, UL) << TCR_SH1_SHIFT)
#define TCR_SH1_INNER       (_AC(3, UL) << TCR_SH1_SHIFT)
#define TCR_SHARED          (TCR_SH0_INNER | TCR_SH1_INNER)

#define TCR_TG0_SHIFT       14
#define TCR_TG0_MASK        (_AC(3, UL) << TCR_TG0_SHIFT)
#define TCR_TG0_4K          (_AC(0, UL) << TCR_TG0_SHIFT)
#define TCR_TG0_64K         (_AC(1, UL) << TCR_TG0_SHIFT)
#define TCR_TG0_16K         (_AC(2, UL) << TCR_TG0_SHIFT)

#define TCR_TG1_SHIFT       30
#define TCR_TG1_MASK        (_AC(3, UL) << TCR_TG1_SHIFT)
#define TCR_TG1_16K         (_AC(1, UL) << TCR_TG1_SHIFT)
#define TCR_TG1_4K          (_AC(2, UL) << TCR_TG1_SHIFT)
#define TCR_TG1_64K         (_AC(3, UL) << TCR_TG1_SHIFT)

#define TCR_ASID16          (_AC(1, UL) << 36)
#define TCR_TBI0            (_AC(1, UL) << 37)
#define TCR_HA              (_AC(1, UL) << 39)
#define TCR_HD              (_AC(1, UL) << 40)

#define TCR_TG_FLAGS        TCR_TG0_4K | TCR_TG1_4K
#define TCR_CACHE_FLAGS     TCR_IRGN_WBWA | TCR_ORGN_WBWA

#endif /* __UKVM_MM_H__ */

