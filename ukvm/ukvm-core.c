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
#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/const.h>
#include <elf.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <poll.h>
#include <limits.h>

#include "ukvm-private.h"
#include "ukvm-modules.h"
#include "ukvm-cpu.h"
#include "ukvm-api.h"
#include "ukvm.h"

struct ukvm_module *modules[] = {
#ifdef UKVM_MODULE_BLK
    &ukvm_blk,
#endif
#ifdef UKVM_MODULE_NET
    &ukvm_net,
#endif
#ifdef UKVM_MODULE_GDB
    &ukvm_gdb,
#endif
    NULL,
};
#define NUM_MODULES ((sizeof(modules) / sizeof(struct ukvm_module *)) - 1)

ssize_t pread_in_full(int fd, void *buf, size_t count, off_t offset)
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
static void load_code(const char *file, uint8_t *mem,     /* IN */
                      uint64_t *p_entry, uint64_t *p_end) /* OUT */
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

        if (phdr[ph_i].p_type != PT_LOAD)
            continue;

        if ((paddr >= GUEST_SIZE) || add_overflow(paddr, filesz, result)
                || (result >= GUEST_SIZE))
            goto out_invalid;
        if (add_overflow(paddr, memsz, result) || (result >= GUEST_SIZE))
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

        /* Write-protect the executable segment */
        if (phdr[ph_i].p_flags & PF_X) {
            if (mprotect(daddr, _end - paddr, PROT_EXEC | PROT_READ) == -1)
                goto out_error;
        }
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

void ukvm_port_puts(uint8_t *mem, uint64_t paddr)
{
    GUEST_CHECK_PADDR(paddr, GUEST_SIZE, sizeof (struct ukvm_puts));
    struct ukvm_puts *p = (struct ukvm_puts *)(mem + paddr);

    GUEST_CHECK_PADDR(p->data, GUEST_SIZE, p->len);
    assert(write(1, mem + p->data, p->len) != -1);
}

void ukvm_port_poll(uint8_t *mem, uint64_t paddr)
{
    GUEST_CHECK_PADDR(paddr, GUEST_SIZE, sizeof (struct ukvm_poll));
    struct ukvm_poll *t = (struct ukvm_poll *)(mem + paddr);
    struct timespec ts;
    int rc, i, num_fds = 0;
    struct pollfd fds[NUM_MODULES];  /* we only support at most one
                                      * instance per module for now
                                      */

    for (i = 0; i < NUM_MODULES; i++) {
        int fd = modules[i]->get_fd();

        if (fd) {
            fds[num_fds].fd = fd;
            fds[num_fds].events = POLLIN;
            num_fds += 1;
        }
    }

    ts.tv_sec = t->timeout_nsecs / 1000000000ULL;
    ts.tv_nsec = t->timeout_nsecs % 1000000000ULL;

    /*
     * Guest execution is blocked during the ppoll() call, note that
     * interrupts will not be injected.
     */
    do {
        rc = ppoll(fds, num_fds, &ts, NULL);
    } while (rc == -1 && errno == EINTR);
    assert(rc >= 0);
    t->ret = rc;
}

static int vcpu_loop(struct kvm_run *run, int vcpufd, uint8_t *mem)
{
    int ret;

    /* Repeatedly run code and handle VM exits. */
    while (1) {
        int i, handled = 0;

        ret = ioctl(vcpufd, KVM_RUN, NULL);
        if (ret == -1 && errno == EINTR)
            continue;
        if (ret == -1) {
            if (errno == EFAULT) {
                struct kvm_regs regs;
                ret = ioctl(vcpufd, KVM_GET_REGS, &regs);
                if (ret == -1)
                    err(1, "KVM: ioctl (GET_REGS) failed after guest fault");
                err_exit_and_dump_pc(&regs, 1);
            }
            else
                err(1, "KVM: ioctl (RUN) failed");
        }

        for (i = 0; i < NUM_MODULES; i++) {
            if (!modules[i]->handle_exit(run, vcpufd, mem)) {
                handled = 1;
                break;
            }
        }

        if (handled)
            continue;

        switch (run->exit_reason) {
        case KVM_EXIT_HLT:
            /* Guest has halted the CPU, this is considered as a normal exit. */
            return 0;

        case KVM_EXIT_IO: {
            if (run->io.direction != KVM_EXIT_IO_OUT
                    || run->io.size != 4)
                errx(1, "Invalid guest port access: port=0x%x", run->io.port);

            uint64_t paddr =
                GUEST_PIO32_TO_PADDR((uint8_t *)run + run->io.data_offset);

            switch (run->io.port) {
            case UKVM_PORT_PUTS:
                ukvm_port_puts(mem, paddr);
                break;
            case UKVM_PORT_POLL:
                ukvm_port_poll(mem, paddr);
                break;
            default:
                errx(1, "Invalid guest port access: port=0x%x", run->io.port);
            }
            break;
        }

        case KVM_EXIT_FAIL_ENTRY:
            errx(1, "KVM: entry failure: hw_entry_failure_reason=0x%llx",
                 run->fail_entry.hardware_entry_failure_reason);

        case KVM_EXIT_INTERNAL_ERROR:
            errx(1, "KVM: internal error exit: suberror=0x%x",
                 run->internal.suberror);

        default:
            errx(1, "KVM: unhandled exit: exit_reason=0x%x", run->exit_reason);
        }
    }
}

int setup_modules(int vcpufd, uint8_t *mem)
{
    int i;

    for (i = 0; i < NUM_MODULES; i++) {
        if (modules[i]->setup(vcpufd, mem)) {
            warnx("Module `%s' setup failed", modules[i]->name);
            warnx("Please check you have correctly specified:\n    %s",
                   modules[i]->usage());
            return -1;
        }
    }
    return 0;
}

void sig_handler(int signo)
{
    errx(1, "Exiting on signal %d", signo);
}

static void usage(const char *prog)
{
    int m;

    fprintf(stderr, "usage: %s [ CORE OPTIONS ] [ MODULE OPTIONS ] [ -- ] "
            "KERNEL [ ARGS ]\n", prog);
    fprintf(stderr, "KERNEL is the filename of the unikernel to run.\n");
    fprintf(stderr, "ARGS are optional arguments passed to the unikernel.\n");
    fprintf(stderr, "Core options:\n");
    fprintf(stderr, "    --help (display this help)\n");
    fprintf(stderr, "Compiled-in module options:\n");
    for (m = 0; m < NUM_MODULES; m++)
        fprintf(stderr, "    %s\n", modules[m]->usage());
    if (!m)
        fprintf(stderr, "    (none)\n");
    exit(1);
}

int main(int argc, char **argv)
{
    int kvm, vmfd, vcpufd, ret;
    uint8_t *mem;
    struct kvm_run *run;
    size_t mmap_size;
    uint64_t elf_entry;
    uint64_t kernel_end;
    const char *prog;
    const char *elffile;
    int matched;

    prog = basename(*argv);
    argc--;
    argv++;

    while (*argv && *argv[0] == '-') {
        int j;

        if (strcmp("--help", *argv) == 0)
            usage(prog);

        if (strcmp("--", *argv) == 0) {
            /* Consume and stop arg processing */
            argc--;
            argv++;
            break;
        }

        matched = 0;
        for (j = 0; j < NUM_MODULES; j++) {
            if (modules[j]->handle_cmdarg(*argv) == 0) {
                /* Handled by module, consume and go on to next arg */
                matched = 1;
                argc--;
                argv++;
                break;
            }
        }
        if (!matched) {
            warnx("Invalid option: `%s'", *argv);
            usage(prog);
        }
    }

    /* At least one non-option argument required */
    if (*argv == NULL) {
        warnx("Missing KERNEL operand");
        usage(prog);
    }
    elffile = *argv;
    argc--;
    argv++;

    struct sigaction sa;
    memset (&sa, 0, sizeof (struct sigaction));
    sa.sa_handler = sig_handler;
    sigfillset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1)
        err(1, "Could not install signal handler");
    if (sigaction(SIGTERM, &sa, NULL) == -1)
        err(1, "Could not install signal handler");

    kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm == -1)
        err(1, "Could not open: /dev/kvm");

    /* Make sure we have the stable version of the API */
    ret = ioctl(kvm, KVM_GET_API_VERSION, NULL);
    if (ret == -1)
        err(1, "KVM: ioctl (GET_API_VERSION) failed");
    if (ret != 12)
        errx(1, "KVM: API version is %d, ukvm requires version 12", ret);

    vmfd = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vmfd == -1)
        err(1, "KVM: ioctl (CREATE_VM) failed");

    /* Check guest memory size */
    check_guest_memory_size(GUEST_SIZE);

    /* Allocate GUEST_SIZE page-aligned guest memory. */
    mem = mmap(NULL, GUEST_SIZE, PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED)
        err(1, "Error allocating guest memory");

    load_code(elffile, mem, &elf_entry, &kernel_end);

    /* Map a user memory for as physical memroy */
    setup_user_memory_for_guest(vmfd, 0, 0, mem, 0, GUEST_SIZE);


    /* enabling this seems to mess up our receiving of hlt instructions */
    /* ret = ioctl(vmfd, KVM_CREATE_IRQCHIP); */
    /* if (ret == -1) */
    /*     err(1, "KVM_CREATE_IRQCHIP"); */

    vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0);
    if (vcpufd == -1)
        err(1, "KVM: ioctl (CREATE_VCPU) failed");

    /* Setup x86 system registers and memory. */
    setup_system(vmfd, vcpufd, mem);

    /* Setup ukvm_boot_info and command line */
    setup_boot_info(mem, GUEST_SIZE, kernel_end, argc, argv);

    /* Initialize vcpu registers */
    setup_vcpu_init_register(vcpufd, elf_entry);

    /* Map the shared kvm_run structure and following data. */
    ret = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (ret == -1)
        err(1, "KVM: ioctl (GET_VCPU_MMAP_SIZE) failed");
    mmap_size = ret;
    if (mmap_size < sizeof(*run))
        errx(1, "KVM: invalid VCPU_MMAP_SIZE: %zd", mmap_size);
    run =
        mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd,
             0);
    if (run == MAP_FAILED)
        err(1, "KVM: VCPU mmap failed");

    setup_cpuid(kvm, vcpufd);

    if (setup_modules(vcpufd, mem))
        exit(1);

    return vcpu_loop(run, vcpufd, mem);
}
