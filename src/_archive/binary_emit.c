#include "loader_bin.c"  // Other headers should be loaded in binary.c

/*
 * Set function pointer fptr into rax, and return assembly buffer
 */
static Buffer *__binary_load_fcnptr_into_rax(Binary *b, addr_t fptr);

/*
 * Emit loader for given binary b
 */
static Buffer *__binary_emit_loader(Binary *b);

/*
 * Get mmap information
 */
static GHashTable *__binary_get_vmmap(Binary *b);

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
    if ((b->is_pie)) {
        // addq %r12,%rax
        z_buffer_push(buf, 0x4c);
        z_buffer_push(buf, 0x01);
        z_buffer_push(buf, 0xe0);
    }

    return buf;
}

static GHashTable *__binary_get_vmmap(Binary *b) {
    GHashTable *vmmap_table =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    addr_t mmap_start = 0;
    addr_t mmap_end = 0;
    for (int i = 0; i < b->vaddrs->len; i++) {
        addr_t vaddr = g_array_index(b->vaddrs, addr_t, i);
        assert(vaddr >= mmap_start);  // b->vaddrs is sorted.

        // Get trampoline.
        Trampoline *t =
            g_hash_table_lookup(b->trampolines, GSIZE_TO_POINTER(vaddr));

#ifndef LOAD_ORIGINAL
        if (!IS_CREATED(t)) continue;  // We won't patch original segment
#endif

        z_trace("find tramopline (%ld bytes) at %#lx", z_trampoline_get_size(t),
                vaddr);

        addr_t cur_mmap_start = (vaddr & (~(PAGE_SIZE - 1)));
        addr_t cur_mmap_end =
            ((vaddr + z_trampoline_get_size(t) - 1) & (~(PAGE_SIZE - 1))) +
            PAGE_SIZE;

        // Get current trampoline's mmap_start and mmap_end, and check
        // whether it can be mergied with previous one.
        if (mmap_start == 0 && mmap_end == 0) {
            // All previous pages are mmaped.
            mmap_start = cur_mmap_start;
            mmap_end = cur_mmap_end;
        } else {
            if (cur_mmap_start <= mmap_end) {
                // Nearby address
                mmap_end =
                    ((cur_mmap_end >= mmap_end) ? cur_mmap_end : mmap_end);
            } else {
                z_info("mmap target [vaddr: %#lx, size :%#lx]", mmap_start,
                       mmap_end - mmap_start);
                g_hash_table_insert(vmmap_table, GSIZE_TO_POINTER(mmap_start),
                                    GSIZE_TO_POINTER(mmap_end - mmap_start));

                // Reset mmap_start and mmap_end.
                mmap_start = 0;
                mmap_end = 0;
            }
        }
    }

    // Handle tail
    if (mmap_start != 0 && mmap_end != 0) {
        z_info("find mmap target [vaddr: %#lx, size :%#lx]", mmap_start,
               mmap_end - mmap_start);
        g_hash_table_insert(vmmap_table, GSIZE_TO_POINTER(mmap_start),
                            GSIZE_TO_POINTER(mmap_end - mmap_start));
    }

    return vmmap_table;
}

static Buffer *__binary_emit_loader(Binary *b) {
    /*
     * Stage 1: loader entry
     */
    Buffer *buf = z_buffer_create(loader_bin, loader_bin_len);

    /*
     * Stage #2
     */

    // Step (1): mmap all necessary virtual page
    GHashTable *vmmap_table = __binary_get_vmmap(b);
    do {
        int32_t prot = PROT_READ | PROT_EXEC | PROT_WRITE;
        int32_t flags = MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS;
        GList *vaddrs = g_hash_table_get_keys(vmmap_table);
        while (vaddrs != NULL) {
            addr_t vaddr = (addr_t)vaddrs->data;
            size_t size = (size_t)g_hash_table_lookup(vmmap_table,
                                                      GSIZE_TO_POINTER(vaddr));
            z_info(
                "mmap(%#lx, %#lx, PROT_READ | PROT_WRITE | PROT_EXEC, "
                "MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0)",
                vaddr, size);
            KS_ASM(
                "mov eax, %d;\n"
                "mov rdi, %#lx;\n"
                "mov esi, %#lx;\n"
                "mov edx, %#x;\n"
                "mov r10d, %#x;\n"
                "xor r8, r8;\n"
                "xor r9, r9;\n"
                "syscall;\n"
                "mov rbx, %#lx;\n"
                "cmp rax, rbx;\n"
                "jz succ_mmap;\n"
                "jmp r13;\n"
                "succ_mmap:;\n",
                SYS_mmap, vaddr, size, prot, flags, vaddr);
            z_buffer_append_raw(buf, ks_encode, ks_size);
            vaddrs = vaddrs->next;
        }
    } while (0);

    // TODO: Step (2): Emit calls to mmap() that load trampoline pages
    /*
     * Fill in.
     */

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
    KS_ASM(
        "pop rdi;\n"
        "pop rsi;\n"
        "pop rdx;\n"
        "pop rcx;\n"
        "pop r8;\n"
        "pop r9;\n"
        "pop r10;\n"
        "pop r11;\n"
        "pop r12;\n"
        "pop r13;\n"
        "pop r14;\n"
        "pop r15;\n");
    z_buffer_append_raw(buf, ks_encode, ks_size);

    // Step (6): Jump to real entry address:
    // jmp rax
    KS_ASM("jmp rax");
    z_buffer_append_raw(buf, ks_encode, ks_size);

    return buf;
}

Z_API void z_binary_emit(Binary *b) {
    // Loader must be patched at the tail of binary. Detailed memory layout of
    // patched ELF is shown in binary.h

    // Check whether current needs emiting
    if (!(b->need_emit)) return;

#ifdef ZZ_FLAG
    Buffer *buf = b->patched_buf;

    // Step (0): Update patch meta-information
    do {
        //      1. if loader is already patched, remove it.
        if (b->loader_offset != SIZE_MAX) {
            z_buffer_truncate(buf, b->loader_offset);
            b->loader_offset = SIZE_MAX;
        }
        //      2. if springboard is not set, set it. Set springboard's target
        //      as unknown meanwhile.
        if (b->springboard_offset == SIZE_MAX) {
            //      2.1 align buffer to PAGE_SIZE.
            size_t cur_size = z_buffer_get_size(buf);
            z_trace("current size of patched binary: %ld bytes", cur_size);
            if (cur_size % PAGE_SIZE != 0) {
                size_t padding_size = PAGE_SIZE - (cur_size % PAGE_SIZE);
                uint8_t *tmp_mem = z_alloc(padding_size, sizeof(uint8_t));
                z_buffer_append_raw(buf, tmp_mem, padding_size);
                z_free(tmp_mem);
            }
            assert(z_buffer_get_size(buf) % PAGE_SIZE == 0);
            b->springboard_offset = z_buffer_get_size(buf);

            //      2.2 store the state and put PIE base offset into %r12.
            KS_ASM(
                "push r15;\n"
                "push r14;\n"
                "push r13;\n"
                "push r12;\n"
                "push r11;\n"
                "push r10;\n"
                "push r9;\n"
                "push r8;\n"
                "push rcx;\n"
                "push rdx;\n"
                "push rsi;\n"
                "push rdi;\n"
                "lea r12, [rip-0x1b];\n"  // Be careful about the offset.
                "mov rdx, %#lx;\n"
                "sub r12, rdx;\n",
                SPRINGBOARD_ADDRESS);
            z_buffer_append_raw(buf, ks_encode, ks_size);

            //      2.3 set springboard.
            b->springboard_jmp_offset = z_buffer_get_size(buf);
            z_buffer_push(buf, 0xe9);
            z_buffer_push(buf, 0x00);
            z_buffer_push(buf, 0x00);
            z_buffer_push(buf, 0x00);
            z_buffer_push(buf, 0x00);
        } else {
            uint8_t *springboard_raw_ptr =
                z_buffer_seek(buf, b->springboard_jmp_offset, SEEK_SET);
            assert(*(springboard_raw_ptr++) == 0);
            memset(springboard_raw_ptr, 0x00, 4);
        }
        //      3. set need_emit as false
        b->need_emit = false;
    } while (0);

    // Step (1): apply all unpatched trampolines
    do {
        GList *trampolines = g_hash_table_get_values(b->trampolines);
        while (trampolines != NULL) {
            Trampoline *t = (Trampoline *)(trampolines->data);
            z_trace(
                "trying to patch trampoline [vaddr: %#lx, offset: %#lx, "
                "is_created: %d]",
                z_trampoline_get_vaddr(t), z_trampoline_get_offset(t),
                z_trampoline_get_is_created(t));
            if (IS_CREATED(t) && !IS_PATCHED(t)) {
                // Copy trampoline into buf.
                z_trampoline_set_offset(t, z_buffer_get_size(buf));
                z_buffer_append(buf, z_trampoline_get_buf(t));
                z_info(
                    "patch %lu bytes at offset %lu, which will be loaded into "
                    "%#lx",
                    z_trampoline_get_size(t), z_trampoline_get_offset(t),
                    z_trampoline_get_vaddr(t));
            }
            trampolines = trampolines->next;
        }
        g_list_free(trampolines);
    } while (0);

    // Step (2): fix springboard's target
    do {
        uint8_t *springboard_raw_ptr =
            z_buffer_seek(buf, b->springboard_jmp_offset, SEEK_SET);
        assert(*(springboard_raw_ptr++) == 0xe9);
        assert(*((uint32_t *)springboard_raw_ptr) == 0x0);
        uint32_t jmp_offset =
            z_buffer_get_size(buf) - b->springboard_jmp_offset;
        z_info("springboard jumps %ld bytes to the tail", jmp_offset);
        jmp_offset -= 5;
        memcpy(springboard_raw_ptr, &jmp_offset, 4);
    } while (0);

    // Step (3): emit loader
    //      2. update loader_offset
    b->loader_offset = z_buffer_get_size(buf);
    z_info("insert loader at offset %#lx", b->loader_offset);
    //      3. insert loader
    Buffer *loader_buf = __binary_emit_loader(b);
    z_buffer_append(buf, loader_buf);

    /*
     * Note that patched_buf is updated, elf needs to re-extract
     */
    z_elf_destroy(b->elf);
    b->elf = z_elf_extract(buf, false);

    // Step (4): rewrite entry as loader address
    Elf64_Ehdr *ehdr =
        z_elf_get_ehdr(b->elf);  // XXX: ELF pointer is invalid due to realloc
    ehdr->e_entry = (Elf64_Addr)SPRINGBOARD_ADDRESS;

    // Step (5): edit PT_NOTE
    Elf64_Phdr *phdr = z_elf_get_phdr_note(b->elf);
    phdr->p_type = PT_LOAD;
    phdr->p_flags = PF_X | PF_R;
    phdr->p_offset = b->springboard_offset;
    phdr->p_vaddr = (Elf64_Addr)SPRINGBOARD_ADDRESS;
    phdr->p_paddr = (Elf64_Addr)NULL;
    phdr->p_filesz = z_buffer_get_size(buf) - b->springboard_offset + 1;
    phdr->p_memsz = z_buffer_get_size(buf) - b->springboard_offset + 1;
    phdr->p_align = PAGE_SIZE;

    z_buffer_destroy(loader_buf);
#endif
}
