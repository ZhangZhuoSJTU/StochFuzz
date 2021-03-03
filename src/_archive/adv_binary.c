#include <assert.h>
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <gmodule.h>

#include "binary.h"
#include "buffer.h"
#include "elf_info.h"
#include "loader.h"
#include "utils.h"

#include "loader_bin.c"

/*
 * Set function pointer fptr into rax, and return assembly buffer
 */
static Buffer *__binary_load_fcnptr_into_rax(Binary *b, addr_t fptr);

/*
 * Emit loader for given binary b
 */
static Buffer *__binary_emit_loader(Binary *b);

static Buffer *__binary_load_fcnptr_into_rax(Binary *b, addr_t fptr) {
    Buffer *buf = z_buffer_create(NULL, 0);

    if (fptr <= INT32_MAX) {
        // mov $fptr32,%eax
        int32_t fptr32 = (int32_t)fptr;
        z_buffer_push(buf, 0xb8);
        z_buffer_append_raw(buf, (uint8_t *)&fptr32, sizeof(fptr32));
    } else {
        // movabs $fptr,%rax
        int64_t fptr64 = (int64_t)fptr;
        z_buffer_push(buf, 0x48);
        z_buffer_push(buf, 0xb8);
        z_buffer_append_raw(buf, (uint8_t *)&fptr64, sizeof(fptr64));
    }

    // Adjust for PIE
    if (z_elf_info_get_is_pie(b->elf)) {
        // addq %r12,%rax
        z_buffer_push(buf, 0x4c);
        z_buffer_push(buf, 0x01);
        z_buffer_push(buf, 0xe0);
    }

    return buf;
}

static Buffer *__binary_emit_loader(Binary *b) {
    /*
     * Stage 1: loader entry
     */
    Buffer *buf = z_buffer_create(loader_bin, loader_bin_len);

#ifdef SHOW_LOGO
    /*
     * Stage 1.5: show logo
     */
    // push rax
    // /* write(fd=0, buf='patched by izhuer\n', n=18) */
    // /* push b'patched by izhuer\n\x00' */
    // push 0x1010101 ^ 0xa72
    // xor dword ptr [rsp], 0x1010101
    // mov rax, 0x6575687a69207962
    // push rax
    // mov rax, 0x2064656863746170
    // push rax
    // mov rsi, rsp
    // xor edi, edi /* 0 */
    // push 0x12
    // pop rdx
    // /* call write() */
    // push SYS_write /* 1 */
    // pop rax
    // syscall
    // pop rax
    // pop rax
    // pop rax
    // pop rax
    const uint8_t logo[] = {
        0x50, 0x68, 0x73, 0xb,  0x1,  0x1,  0x81, 0x34, 0x24, 0x1,  0x1,
        0x1,  0x1,  0x48, 0xb8, 0x62, 0x79, 0x20, 0x69, 0x7a, 0x68, 0x75,
        0x65, 0x50, 0x48, 0xb8, 0x70, 0x61, 0x74, 0x63, 0x68, 0x65, 0x64,
        0x20, 0x50, 0x48, 0x89, 0xe6, 0x31, 0xff, 0x6a, 0x12, 0x5a, 0x6a,
        0x1,  0x58, 0xf,  0x5,  0x58, 0x58, 0x58, 0x58};
    z_buffer_append_raw(buf, logo, sizeof(logo));
#endif

    /*
     * Stage #2
     */

    // Step (1): Setup mmap() prot/flags parameters.
    int32_t prot = PROT_READ | PROT_EXEC;
    int32_t flags = MAP_PRIVATE | MAP_FIXED;

    // mov $prot,%edx
    z_buffer_push(buf, 0xba);
    z_buffer_append_raw(buf, (uint8_t *)&prot, sizeof(prot));

    // mov $flags,%r10d
    z_buffer_push(buf, 0x41);
    z_buffer_push(buf, 0xba);
    z_buffer_append_raw(buf, (uint8_t *)&flags, sizeof(flags));

    // TODO: Step (2): Emit calls to mmap() that load trampoline pages
    /*
     * Fill in.
     */

#ifdef LOAD_ORIGINAL
    // TODO: Step (2.5): Emit calls to mmap() that load original pages (if
    // necessary)
    /*
     * Fill in.
     */
#endif

    // Step (3): Close the fd:
    const uint8_t close_fd[] = {
        0x4c, 0x89, 0xc7,                    // movq %r8,%rdi
        0xb8,                                // mov $SYS_CLOSE,%eax
        0x03, 0x00, 0x00, 0x00, 0x0f, 0x05,  // syscall (close)
    };
    z_buffer_append_raw(buf, close_fd, sizeof(close_fd));

#ifdef LOAD_ORIGINAL
    // Step (3.5): Call the initialization routines (if any and necessary):
    /*
     * Fill in.
     */
#endif

    // Step (4): Setup jump to the real program/library entry address.
    Buffer *tmp = __binary_load_fcnptr_into_rax(b, b->original_entry);
    z_buffer_append(buf, tmp);
    z_buffer_destroy(tmp);

    // Step (5): Restore the register state (saved by loader entry):
    const uint8_t restore_state[] = {
        0x5f,        // popq %rdi
        0x5e,        // popq %rsi
        0x5a,        // popq %rdx
        0x59,        // popq %rcx
        0x41, 0x59,  // popq %r9
        0x41, 0x5a,  // popq %r10
        0x41, 0x5b,  // popq %r11
        0x41, 0x5c,  // popq %r12
        0x41, 0x5d,  // popq %r13
        0x41, 0x5e,  // popq %r14
        0x41, 0x5f,  // popq %r15
        0x41, 0x58,  // popq %r8
    };
    z_buffer_append_raw(buf, restore_state, sizeof(restore_state));

    // Step (6): Jump to real entry address:
    // jmpq *rax
    z_buffer_push(buf, 0xff);
    z_buffer_push(buf, 0xe0);

    return buf;
}

Z_API Binary *z_binary_open(const char *pathname) {
    // Create a Binary struct
    Binary *b = (Binary *)z_alloc(1, sizeof(Binary));
    b->pathname = pathname;

    // Read file and parse header
    b->patched_buf = z_buffer_read_file(pathname);
    b->elf = z_elf_info_extract(b->patched_buf);
    b->original_entry = (addr_t)(z_elf_info_get_ehdr(b->elf))->e_entry;

    // Trampoline information
    b->trampolines = g_hash_table_new(g_int64_hash, g_direct_equal);
    b->vaddrs = g_array_new(FALSE, TRUE, sizeof(addr_t));
    z_elf_info_dump_exec(b->elf);

    b->loader_offset = SIZE_MAX;
    b->need_emit = true;
    return b;
}

Z_API void z_binary_destory(Binary *b) {
    // TODO: destroy members in trampolines and vaddrs
    /*
     * Fill in.
     */
    g_hash_table_destroy(b->trampolines);
    g_array_free(b->vaddrs, TRUE);

    z_buffer_destroy(b->patched_buf);

    z_elf_info_destroy(b->elf);

    z_free(b);
}

Z_API void z_binary_save(Binary *b, const char *pathname) {
    // Emit binary if necessary
    z_binary_emit(b);

    // Write down patch content
    z_buffer_write_file(b->patched_buf, pathname);
}

Z_API void z_binary_emit(Binary *b) {
    // Loader must be patched at the tail of binary

    // Check whether current needs emiting
    if (!(b->need_emit)) return;

    Buffer *buf = b->patched_buf;

    // Step (0): if loader is already patched, remove it.
    if (b->loader_offset != SIZE_MAX) {
        z_buffer_truncate(buf, b->loader_offset);
        b->loader_offset = SIZE_MAX;
    }

    // TODO: Step (1): apply all trampolines
    /*
     * Fill in.
     */

    // Step (2): rewrite entry as loader address
    Elf64_Ehdr *ehdr = z_elf_info_get_ehdr(b->elf);
    ehdr->e_entry = (Elf64_Addr)LOADER_ADDRESS;

    // Step (3): emit loader
    //      1. align patched content to PAGE_SIZE
    size_t cur_size = z_buffer_get_size(buf);
    z_trace("current size of patched binary: %ld bytes", cur_size);
    if (cur_size % PAGE_SIZE != 0) {
        size_t padding_size = PAGE_SIZE - (cur_size % PAGE_SIZE);
        uint8_t *tmp_mem = z_alloc(padding_size, sizeof(uint8_t));
        z_buffer_append_raw(buf, tmp_mem, padding_size);
        z_free(tmp_mem);
    }
    assert(z_buffer_get_size(buf) % PAGE_SIZE == 0);
    //      2. update loader_offset
    b->loader_offset = z_buffer_get_size(buf);
    z_info("insert loader at offset %#lx", b->loader_offset);
    //      3. insert loader
    Buffer *loader_buf = __binary_emit_loader(b);
    z_buffer_append(buf, loader_buf);

    // Step (4): edit PT_NOTE for loader
    Elf64_Phdr *phdr = z_elf_info_get_phdr_note(b->elf);
    phdr->p_type = PT_LOAD;
    phdr->p_flags = PF_X | PF_R;
    phdr->p_offset = b->loader_offset;
    phdr->p_vaddr = (Elf64_Addr)LOADER_ADDRESS;
    phdr->p_paddr = (Elf64_Addr)NULL;
    phdr->p_filesz = z_buffer_get_size(loader_buf);
    phdr->p_memsz = z_buffer_get_size(loader_buf);
    phdr->p_align = PAGE_SIZE;

    z_buffer_destroy(loader_buf);

    // Update need_emit
    b->need_emit = false;
}
