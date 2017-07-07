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
 * ukvm_elf.c: ELF loader.
 *
 * This module should be kept backend-independent and architectural
 * dependencies should be self-contained.
 */

#define _GNU_SOURCE
#include <err.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "ukvm.h"

#if defined(__aarch64__)
uint64_t ukvm_end_of_kernel_rodata, ukvm_end_of_kernel_etext;

static Elf64_Shdr *ukvm_kernel_elf_section_headers;
static char *ukvm_kernel_elf_section_names;
static int ukvm_kernel_elf_section_numbers;
#endif

static ssize_t pread_in_full(int fd, void *buf, size_t count, off_t offset)
{
    ssize_t total = 0;
    char *p = buf;

    if (count > SSIZE_MAX) {
        errno = E2BIG;
        return -1;
    }

    while (count > 0) {
        ssize_t nr;

        nr = pread(fd, p, count, offset);
        if (nr == 0)
            return total;
        else if (nr == -1 && errno == EINTR)
            continue;
        else if (nr == -1)
            return -1;

        count -= nr;
        total += nr;
        p += nr;
        offset += nr;
    }

    return total;
}

#if defined(__aarch64__)
static void ukvm_elf_load_section_headers(int fd, Elf64_Ehdr *hdr)
{
    Elf64_Shdr *shstrtab;
    ssize_t numb;
    size_t buflen;

    buflen = hdr->e_shentsize * hdr->e_shnum;
    ukvm_kernel_elf_section_headers = malloc(buflen);
    if (!ukvm_kernel_elf_section_headers)
        goto out_error;

    numb = pread_in_full(fd, ukvm_kernel_elf_section_headers,
                         buflen, hdr->e_shoff);
    if (numb < 0)
        goto out_error;

    shstrtab = ukvm_kernel_elf_section_headers + hdr->e_shstrndx;
    ukvm_kernel_elf_section_names = malloc(shstrtab->sh_size);
    if (!ukvm_kernel_elf_section_names)
        goto out_error;

    numb = pread_in_full(fd, ukvm_kernel_elf_section_names,
                         shstrtab->sh_size, shstrtab->sh_offset);
    if (numb < 0)
        goto out_error;

    ukvm_kernel_elf_section_numbers = hdr->e_shnum;

    return;

out_error:
    err(1, "Loading section headers from ELF image failed\n");
}

static Elf64_Shdr *ukvm_elf_get_section_header_by_name(char *name)
{
    Elf64_Shdr *section;
    int idx;

    for (idx = 0; idx < ukvm_kernel_elf_section_numbers; idx++) {
        section = ukvm_kernel_elf_section_headers + idx;

        /* Skip section without name */
        if (section->sh_name == 0)
            continue;

        if (!strcmp(name, ukvm_kernel_elf_section_names + section->sh_name))
            return section;
    }

    return NULL;
}

static void ukvm_get_info_from_elf(int fd_kernel, Elf64_Ehdr *elf_hdr)
{
    Elf64_Shdr *shdr;
    /*
     * AArch64 must use separate kvm_userspace_memory_region for readonly
     * and writeable memory. So we have to get .text, .rodata and .data
     * from elf image.
     */
    ukvm_elf_load_section_headers(fd_kernel, elf_hdr);

    /* The start of .rodata is the end of .text */
    shdr = ukvm_elf_get_section_header_by_name(".rodata");
    if (!shdr)
        err(1, "Could not find .rodata from guest image");
    ukvm_end_of_kernel_etext = shdr->sh_addr;

    /*
     * The kernel is a static image, so we don't have .got section. So
     * the address of .data is the beginning address of writeable data.
     */
    shdr = ukvm_elf_get_section_header_by_name(".data");
    if (!shdr)
        err(1, "Could not find .data from guest image");
    ukvm_end_of_kernel_rodata = shdr->sh_addr;

    /* We should not use following data anymore, free them */
    free(ukvm_kernel_elf_section_headers);
    free(ukvm_kernel_elf_section_names);
    ukvm_kernel_elf_section_numbers = 0;
}
#endif

/*
 * Load code from elf file into *mem and return the elf entry point
 * and the last byte of the program when loaded into memory. This
 * accounts not only for the last loaded piece of code from the elf,
 * but also for the zeroed out pieces that are not loaded and sould be
 * reserved.
 *
 * Memory will look like this after the elf is loaded:
 *
 * *mem                    *p_entry                   *p_end
 *   |             |                    |                |
 *   |    ...      | .text .rodata      |   .data .bss   |
 *   |             |        code        |   00000000000  |
 *   |             |  [PROT_EXEC|READ]  |                |
 *
 */
void ukvm_elf_load(const char *file, uint8_t *mem, size_t mem_size,
       ukvm_gpa_t *p_entry, ukvm_gpa_t *p_end)
{
    int fd_kernel;
    ssize_t numb;
    size_t buflen;
    Elf64_Off ph_off;
    Elf64_Half ph_entsz;
    Elf64_Half ph_cnt;
    Elf64_Half ph_i;
    Elf64_Phdr *phdr = NULL;
    Elf64_Ehdr hdr;

    /* elf entry point (on physical memory) */
    *p_entry = 0;
    /* highest byte of the program (on physical memory) */
    *p_end = 0;

    fd_kernel = open(file, O_RDONLY);
    if (fd_kernel == -1)
        goto out_error;

    numb = pread_in_full(fd_kernel, &hdr, sizeof(Elf64_Ehdr), 0);
    if (numb < 0)
        goto out_error;
    if (numb != sizeof(Elf64_Ehdr))
        goto out_invalid;

    /*
     * Validate program is in ELF64 format:
     * 1. EI_MAG fields 0, 1, 2, 3 spell ELFMAG('0x7f', 'E', 'L', 'F'),
     * 2. File contains 64-bit objects,
     * 3. Objects are Executable,
     * 4. Target instruction set architecture is set to x86_64.
     */
    if (hdr.e_ident[EI_MAG0] != ELFMAG0
            || hdr.e_ident[EI_MAG1] != ELFMAG1
            || hdr.e_ident[EI_MAG2] != ELFMAG2
            || hdr.e_ident[EI_MAG3] != ELFMAG3
            || hdr.e_ident[EI_CLASS] != ELFCLASS64
            || hdr.e_type != ET_EXEC
            || hdr.e_machine != EM_X86_64)
        goto out_invalid;

    ph_off = hdr.e_phoff;
    ph_entsz = hdr.e_phentsize;
    ph_cnt = hdr.e_phnum;
    buflen = ph_entsz * ph_cnt;

    phdr = malloc(buflen);
    if (!phdr)
        goto out_error;
    numb = pread_in_full(fd_kernel, phdr, buflen, ph_off);
    if (numb < 0)
        goto out_error;
    if (numb != buflen)
        goto out_invalid;

#if defined(__aarch64__)
    ukvm_get_info_from_elf(fd_kernel, &hdr);
#endif

    /*
     * Load all segments with the LOAD directive from the elf file at offset
     * p_offset, and copy that into p_addr in memory. The amount of bytes
     * copied is p_filesz.  However, each segment should be given
     * p_memsz aligned up to p_align bytes on memory.
     */
    for (ph_i = 0; ph_i < ph_cnt; ph_i++) {
        uint8_t *daddr;
        uint64_t _end;
        size_t offset = phdr[ph_i].p_offset;
        size_t filesz = phdr[ph_i].p_filesz;
        size_t memsz = phdr[ph_i].p_memsz;
        uint64_t paddr = phdr[ph_i].p_paddr;
        uint64_t align = phdr[ph_i].p_align;
        uint64_t result;
        int prot;

        if (phdr[ph_i].p_type != PT_LOAD)
            continue;

        if ((paddr >= mem_size) || add_overflow(paddr, filesz, result)
                || (result >= mem_size))
            goto out_invalid;
        if (add_overflow(paddr, memsz, result) || (result >= mem_size))
            goto out_invalid;
        /*
         * Verify that align is a non-zero power of 2 and safely compute
         * ((_end + (align - 1)) & -align).
         */
        if (align > 0 && (align & (align - 1)) == 0) {
            if (add_overflow(result, (align - 1), _end))
                goto out_invalid;
            _end = _end & -align;
        }
        else {
            _end = result;
        }
        if (_end > *p_end)
            *p_end = _end;

        daddr = mem + paddr;
        numb = pread_in_full(fd_kernel, daddr, filesz, offset);
        if (numb < 0)
            goto out_error;
        if (numb != filesz)
            goto out_invalid;
        memset(daddr + filesz, 0, memsz - filesz);

        prot = PROT_NONE;
        if (phdr[ph_i].p_flags & PF_R)
            prot |= PROT_READ;
        if (phdr[ph_i].p_flags & PF_W) {
#if defined(__aarch64__)
            if (paddr < ukvm_end_of_kernel_rodata)
                err(1, "WRITE permission could not allowed in readonly area\n");
#endif
            prot |= PROT_WRITE;
        }
        if (phdr[ph_i].p_flags & PF_X)
            prot |= PROT_EXEC;
        if (prot & PROT_WRITE && prot & PROT_EXEC)
            warnx("%s: Warning: phdr[%u] requests WRITE and EXEC permissions",
                  file, ph_i);
        if (mprotect(daddr, _end - paddr, prot) == -1)
            goto out_error;
    }

    free (phdr);
    close (fd_kernel);
    *p_entry = hdr.e_entry;
    return;

out_error:
    err(1, "%s", file);

out_invalid:
    errx(1, "%s: Exec format error", file);
}
