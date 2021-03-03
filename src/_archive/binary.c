#include <assert.h>
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <gmodule.h>

#include "binary.h"
#include "buffer.h"
#include "elf_.h"
#include "loader.h"
#include "mem_file.h"
#include "trampoline.h"
#include "utils.h"

#define g_true TRUE
#define g_false FALSE

/*
 * Emit code for binary.
 */
#include "binary_emit.c"

static int __binary_vaddr_compare(size_t *a, size_t *b) {
    if (*a > *b)
        return 1;
    else if (*a == *b)
        return 0;
    else
        return -1;
}

Z_API void z_binary_insert_trampoline(Binary *b, Trampoline *t) {
    assert(b != NULL && t != NULL);

    // TODO: find base vaddr and check conflict.
    /*
     * Fill in.
     */

    addr_t t_vaddr = z_trampoline_get_vaddr(t);
    g_hash_table_insert(b->trampolines, GINT_TO_POINTER(t_vaddr), t);

    // TODO: use insert_and_sort
    g_array_append_val(b->vaddrs, t_vaddr);
}

Z_API Binary *z_binary_open(const char *in_filename, const char *out_filename) {
    // Create a Binary struct.
    Binary *b = (Binary *)z_alloc(1, sizeof(Binary));
    b->pathname = in_filename;
    b->out_filename = out_filename;

    // Read file and parse header.
    b->patched_buf = z_buffer_read_file(b->pathname);

    // Test for _MEM_FILE
    // Note: elf should be extracted right after fwrite, because we will use
    // ftell to know the size of elf.
    b->stream = NULL;
    b->elf = z_elf_open(b->pathname);
    b->original_entry = (addr_t)(z_elf_get_ehdr(b->elf))->e_entry;
    b->is_pie = z_elf_get_ehdr(b->elf)->e_type == ET_EXEC ? false : true;

#ifdef ZZ_FLAG
    // Calculate shadow .test segment (we use a trick on bit operation with
    // carefully-designed SHADOW_OFFSET).
    // Insert trampoline information meanwhile.
    //      1. create hash table and array.
    b->trampolines =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                              (GDestroyNotify)z_trampoline_destroy);
    b->vaddrs = g_array_new(g_false, g_true, sizeof(addr_t));
    //      2. dump trampolines for executable segments.
    Buffer *segments = z_elf_dump_exec(b->elf);
    addr_t ZZ_addr;
    for (Trampoline **t_ptr = (Trampoline **)z_buffer_get_raw_buf(segments);
         (*t_ptr) != NULL; t_ptr++) {
        Trampoline *t = *t_ptr;
        Trampoline *t_s = z_trampoline_create_shadow(t);

        ZZ_addr = z_trampoline_get_vaddr(t_s);

        addr_t t_vaddr = z_trampoline_get_vaddr(t);
        addr_t t_s_vaddr = z_trampoline_get_vaddr(t_s);

        g_hash_table_insert(b->trampolines, GSIZE_TO_POINTER(t_vaddr), t);
        g_hash_table_insert(b->trampolines, GSIZE_TO_POINTER(t_s_vaddr), t_s);

        g_array_append_val(b->vaddrs, t_vaddr);
        g_array_append_val(b->vaddrs, t_s_vaddr);
    }

    const uint8_t ZZ_raw_buf[] = {0x90};
    Buffer *ZZ_buf = z_buffer_create(ZZ_raw_buf, 1);
    addr_t ZZ_vaddr1 = ZZ_addr - 0x1000;
    Trampoline *ZZ_t1 =
        z_trampoline_create(ZZ_vaddr1, true, ZZ_buf, PROT_EXEC | PROT_READ);
    addr_t ZZ_vaddr2 = ZZ_addr - 0x3000;
    Trampoline *ZZ_t2 =
        z_trampoline_create(ZZ_vaddr2, true, ZZ_buf, PROT_EXEC | PROT_READ);
    z_buffer_destroy(ZZ_buf);

    g_hash_table_insert(b->trampolines, GSIZE_TO_POINTER(ZZ_vaddr1), ZZ_t1);
    g_hash_table_insert(b->trampolines, GSIZE_TO_POINTER(ZZ_vaddr2), ZZ_t2);

    g_array_append_val(b->vaddrs, ZZ_vaddr1);
    g_array_append_val(b->vaddrs, ZZ_vaddr2);

    g_array_sort(b->vaddrs, (GCompareFunc)__binary_vaddr_compare);
    z_buffer_destroy(segments);
#endif

    // Set patched meta-infomation.

    b->springboard_offset = SIZE_MAX;
    b->springboard_jmp_offset = SIZE_MAX;
    b->loader_offset = SIZE_MAX;
    b->need_emit = true;
    return b;
}

Z_API void z_binary_destroy(Binary *b) {
#ifdef ZZ_FLAG
    // Elements in hash table is automatically destoryed.
    g_hash_table_destroy(b->trampolines);

    // XXX: I am not sure whether I should use TRUE here.
    g_array_free(b->vaddrs, g_true);
#endif

    z_buffer_destroy(b->patched_buf);

    // z_mem_file_fclose(b->stream);

    z_elf_destroy(b->elf);

    z_free(b);
}

Z_API void z_binary_save(Binary *b) {
    // Emit binary if necessary
    z_binary_emit(b);

    // ZZ_TEST
    char zz[3] = {0};
    z_elf_write(b->elf, z_elf_get_trampolines_addr(b->elf) + PAGE_SIZE, 2,
                "zz");
    z_elf_read(b->elf, z_elf_get_trampolines_addr(b->elf) + PAGE_SIZE, 2, zz);
    z_info("ZZ: %s", zz);

    // sync
    z_elf_sync(b->elf);
    // Write down patch content
    // z_buffer_write_file(b->patched_buf, b->out_filename);
}
