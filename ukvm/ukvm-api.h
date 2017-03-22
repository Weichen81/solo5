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

#ifndef __UKVM_API_H__
#define __UKVM_API_H__

struct ukvm_mem_region_list {
    struct kvm_userspace_memory_region *regions;
    int count;
};

void setup_boot_info(uint8_t *mem,
                    uint64_t size,
                    uint64_t kernel_end,
                    int argc, char **argv);

void setup_system(int vmfd, int vcpufd, uint8_t *mem);

void setup_cpuid(int kvm, int vcpufd);

void setup_vcpu_init_register(int vcpufd, uint64_t reset_entry);

void setup_user_memory_for_guest(int vmfd, int slot,
                                 uint32_t flags, uint8_t *va_addr,
                                 uint64_t guest_phys_addr, uint32_t size);

void check_guest_memory_size(uint32_t size);

void err_exit_and_dump_pc(struct kvm_regs *regs, int exit_code);

#endif /* __UKVM_API_H__ */
