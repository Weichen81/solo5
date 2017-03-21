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

#ifndef __UKVM_CPU_H__
#define __UKVM_CPU_H__

#ifndef _BITUL

#ifdef __ASSEMBLY__
#define _AC(X,Y)	X
#define _AT(T,X)	X
#else
#define __AC(X,Y)	(X##Y)
#define _AC(X,Y)	__AC(X,Y)
#define _AT(T,X)	((T)(X))
#endif

#define _BITUL(x)	(_AC(1,UL) << (x))
#define _BITULL(x)	(_AC(1,ULL) << (x))

#endif

#define BITS_32 32
#define BITS_64 64

#define GENMASK32(h, l) \
    (((~0U) << (l)) & (~0U >> (BITS_32 - 1 - (h))))
#define GENMASK64(h, l) \
    (((~0ULL) << (l)) & (~0ULL >> (BITS_64 - 1 - (h))))

/* Define ELF64 format Image check for ARM64 */
#define CHECK_INVALID_ELF64_FORMAT_IMAGE(h) \
(                                           \
    (h).e_ident[EI_MAG0] != ELFMAG0 ||      \
    (h).e_ident[EI_MAG1] != ELFMAG1 ||      \
    (h).e_ident[EI_MAG2] != ELFMAG2 ||      \
    (h).e_ident[EI_MAG3] != ELFMAG3 ||      \
    (h).e_ident[EI_CLASS] != ELFCLASS64 ||  \
    (h).e_type != ET_EXEC ||                \
    (h).e_machine != EM_AARCH64             \
)

/* Normal registers are mapped as coprocessor 16. */
#define KVM_REG_ARM_CORE    (0x0010 << KVM_REG_ARM_COPROC_SHIFT)

#define ARM64_CORE_REG(x)   \
            (KVM_REG_ARM64 | KVM_REG_SIZE_U64 | \
            KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(x))

/*
 * KVM/ARM64 provides an interface to userspace to modify the
 * VM registers. This interface describe the register by index.
 * We have to define the index here for those registers that we
 * will modify.
 */
/* Architectural Feature Access Control Register */
#define CPACR_EL1               ARM64_SYS_REG(3, 0, 1, 0, 2)
#define _FPEN_NOTRAP            0x3
#define _FPEN_SHIFT             20
#define _FPEN_MASK              GENMASK32(21, 20)

#endif /* __UKVM_CPU_H__ */

