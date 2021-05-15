#include "binary.h"
#include "elf_.h"
#include "fork_server.h"
#include "interval_splay.h"
#include "loader.h"
#include "utils.h"

#include "x64_utils.c"

#include "fork_server_bin.c"
#include "loader_bin.c"

#define BINARY_MMAP_EXIST(b, addr)                                          \
    (g_hash_table_lookup(b->mmapped_pages, GSIZE_TO_POINTER(addr)) == NULL) \
        ? false                                                             \
        : true

#define BINARY_MMAP_INSERT(b, addr)                               \
    g_hash_table_insert(b->mmapped_pages, GSIZE_TO_POINTER(addr), \
                        GINT_TO_POINTER(1))

static const char null_buf[0x30] = {0};

/*
 * Align trampolines_addr
 */
Z_PRIVATE void __binary_align_trampolines_addr(Binary *b);

/*
 * Setup basic information for loader
 */
Z_PRIVATE void __binary_setup_loader(Binary *b);

/*
 * Setup lookup table
 */
Z_PRIVATE void __binary_setup_lookup_table(Binary *b);

/*
 * Setup fork server
 */
Z_PRIVATE void __binary_setup_fork_server(Binary *b);

/*
 * Setup trampoline zone
 */
Z_PRIVATE void __binary_setup_tp_zone(Binary *b);

/*
 * Setter and Getter
 */
DEFINE_GETTER(Binary, binary, ELF *, elf);
DEFINE_GETTER(Binary, binary, const char *, original_filename);
DEFINE_GETTER(Binary, binary, addr_t, trampolines_addr);
DEFINE_GETTER(Binary, binary, addr_t, shadow_main);
OVERLOAD_GETTER(Binary, binary, addr_t, shadow_code_addr) {
    return binary->trampolines_addr;
}

OVERLOAD_SETTER(Binary, binary, addr_t, shadow_start) {
    z_info("shadow _start address: %#lx", shadow_start);
    binary->shadow_start = shadow_start;

    if (sys_config.instrument_early) {
        // when -e option is given, we need to change the fork server to _start
        addr_t gadget_addr = binary->fork_server_addr + fork_server_bin_len;
        KS_ASM_JMP(gadget_addr, shadow_start);
        z_elf_write(binary->elf, gadget_addr, ks_size, ks_encode);
    } else {
        addr_t gadget_addr = binary->loader_addr + loader_bin_len;
        KS_ASM_JMP(gadget_addr, shadow_start);
        z_elf_write(binary->elf, gadget_addr, ks_size, ks_encode);
    }
}

OVERLOAD_SETTER(Binary, binary, addr_t, shadow_main) {
    if (sys_config.instrument_early) {
        EXITME("main function has not been detected");
    }

    z_info("shadow main address: %#lx", shadow_main);
    binary->shadow_main = shadow_main;
    addr_t gadget_addr = binary->fork_server_addr + fork_server_bin_len;
    KS_ASM_JMP(gadget_addr, shadow_main);
    z_elf_write(binary->elf, gadget_addr, ks_size, ks_encode);
}

OVERLOAD_SETTER(Binary, binary, ELFState, elf_state) {
    z_elf_set_state(binary->elf, elf_state);
}

Z_PRIVATE void __binary_align_trampolines_addr(Binary *b) {
    b->trampolines_addr = BITS_ALIGN_CELL(b->trampolines_addr, 3);
}

Z_PRIVATE void __binary_setup_loader(Binary *b) {
    // step (0). create basic data struction
    b->mmapped_pages =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    // current address for setting instruction
    addr_t loader_base = z_elf_get_loader_addr(b->elf);
    b->loader_addr = loader_base;
    addr_t cur_addr = loader_base;

    // step (1). set entrypoint to loader address
    z_elf_get_ehdr(b->elf)->e_entry = cur_addr;

    // step (2). set down loader
    z_elf_write(b->elf, cur_addr, loader_bin_len, loader_bin);
    cur_addr += loader_bin_len;

    // step (3). jump to original entrypoint
    addr_t loader_transfer_jmp_addr = cur_addr;
    KS_ASM_JMP(cur_addr, z_elf_get_ori_entry(b->elf));
    assert(ks_size == 5);
    z_elf_write(b->elf, cur_addr, ks_size, ks_encode);
    cur_addr += ks_size;

    // step (4). 8-byte alignment for following data
    cur_addr = BITS_ALIGN_CELL(cur_addr, 3);

    // step (5). set down loader_base
    z_elf_write(b->elf, cur_addr, sizeof(addr_t), &loader_base);
    cur_addr += sizeof(addr_t);

    // step (6). set down tp_addr
    // XXX: we will first set a NULL trampoline at trapoline zone
    addr_t trampolines_addr = z_elf_get_trampolines_addr(b->elf);
    assert(trampolines_addr % PAGE_SIZE == 0);
    z_elf_write(b->elf, cur_addr, sizeof(addr_t), &(trampolines_addr));
    cur_addr += sizeof(addr_t);

    // step (7). set down shared .text base address
    addr_t shared_text_addr = z_elf_get_shared_text_addr(b->elf);
    assert(shared_text_addr % PAGE_SIZE == 0);
    z_elf_write(b->elf, cur_addr, sizeof(addr_t), &(shared_text_addr));
    cur_addr += sizeof(addr_t);

    // step (8). store trampolines name
    const char *trampolines_name = z_elf_get_trampolines_name(b->elf);
    z_elf_write(b->elf, cur_addr, z_strlen(trampolines_name) + 1,
                trampolines_name);
    cur_addr += z_strlen(trampolines_name) + 1;

    // step (9). store lookup table name
    const char *lookup_tabname = z_elf_get_lookup_tabname(b->elf);
    z_elf_write(b->elf, cur_addr, z_strlen(lookup_tabname) + 1, lookup_tabname);
    cur_addr += z_strlen(lookup_tabname) + 1;

    // step (10). store pipeline filename
    const char *pipe_filename = z_elf_get_pipe_filename(b->elf);
    z_elf_write(b->elf, cur_addr, z_strlen(pipe_filename) + 1, pipe_filename);
    cur_addr += z_strlen(pipe_filename) + 1;

    // step (11). store pipeline filename
    const char *shared_text_name = z_elf_get_shared_text_name(b->elf);
    z_elf_write(b->elf, cur_addr, z_strlen(shared_text_name) + 1,
                shared_text_name);
    cur_addr += z_strlen(shared_text_name) + 1;

    // step (12). 16-byte alignment for fork server (avoid error in xmm)
    cur_addr = BITS_ALIGN_CELL(cur_addr, 4);

    // step (13). prepare the address of fork server
    b->fork_server_addr = cur_addr;
    z_info("fork server address: %#lx", b->fork_server_addr);
    if (sys_config.instrument_early) {
        // over-write the loader_transfer_jmp_addr to the fork server
        KS_ASM_JMP(loader_transfer_jmp_addr, b->fork_server_addr);
        assert(ks_size == 5);
        z_elf_write(b->elf, loader_transfer_jmp_addr, ks_size, ks_encode);
    } else {
        // redirect __libc_start_main into fork server address
        addr_t load_main = z_elf_get_load_main(b->elf);
        if (z_elf_get_is_pie(b->elf)) {
            // size of "lea rdi, [rip + xxx]" is 7
            KS_ASM(load_main, "lea rdi, [rip %+ld];",
                   b->fork_server_addr - load_main - 7);
        } else {
            KS_ASM(load_main, "mov rdi, %#lx;", b->fork_server_addr);
        }
        assert(ks_size == 7);
        z_elf_write(b->elf, load_main, ks_size, ks_encode);
    }
}

Z_PRIVATE void __binary_setup_fork_server(Binary *b) {
    // step (0). create basic data structure
    addr_t cur_addr = b->fork_server_addr;

    // step (1). set down fork server
    uint8_t *fork_server_code = z_alloc(fork_server_bin_len, sizeof(uint8_t));
    memcpy(fork_server_code, fork_server_bin, fork_server_bin_len);

    if (z_elf_is_statically_linked(b->elf) && sys_config.instrument_early) {
        // XXX: it is import to skip the TLS initialization for
        // statically-linked binaries when instrument_early option is on. Note
        // that if instrument_early is not on, we do not need to wipe off such
        // instructions because TLS will be initialized before main.
        // XXX: there is a bug for keystone to assemble such code, so we have to
        // encode it manually. See:
        // https://github.com/keystone-engine/keystone/issues/296

        /*
         * "mov DWORD PTR fs:0x2d0,eax;"
         * "mov DWORD PTR fs:0x2d4,eax;"
         */
        uint8_t tls_init_code[] = {0x64, 0x89, 0x04, 0x25, 0xd0, 0x02,
                                   0x00, 0x00, 0x64, 0x89, 0x04, 0x25,
                                   0xd4, 0x02, 0x00, 0x00};
        size_t tls_init_code_len = 16;

        // locate the code
        uint8_t *hole = memmem(fork_server_code, fork_server_bin_len,
                               tls_init_code, tls_init_code_len);
        if (!hole) {
            EXITME("TLS initialization code not found");
        }

        // wipe the code with nop
        memcpy(hole, z_x64_gen_nop(8), 8);
        memcpy(hole + 8, z_x64_gen_nop(8), 8);
    }

    z_elf_write(b->elf, cur_addr, fork_server_bin_len, fork_server_code);
    z_free(fork_server_code);
    cur_addr += fork_server_bin_len;

    // step (2). set jump gadget (default to original main/entrypoint)
    if (sys_config.instrument_early) {
        addr_t entrypoint_addr = z_elf_get_ori_entry(b->elf);
        KS_ASM_JMP(cur_addr, entrypoint_addr);
        z_elf_write(b->elf, cur_addr, ks_size, ks_encode);
        cur_addr += 5;
    } else {
        addr_t main_addr = z_elf_get_main(b->elf);
        KS_ASM_JMP(cur_addr, main_addr);
        z_elf_write(b->elf, cur_addr, ks_size, ks_encode);
        cur_addr += 5;
    }

    // step (3). 8-byte alignment for following data
    cur_addr = BITS_ALIGN_CELL(cur_addr, 3);

    // step (4). write down whether -e option is enabled
    uint64_t ei_enabled = (uint64_t)sys_config.instrument_early;
    z_elf_write(b->elf, cur_addr, sizeof(ei_enabled), &ei_enabled);
    cur_addr += sizeof(ei_enabled);

    // step (5). set random patch address
    // TODO: random patch is disable currently
    b->random_patch_addr = BITS_ALIGN_CELL(cur_addr, 3);
    b->random_patch_num = 0;
    z_info("random patch address: %#lx", b->random_patch_addr);
}

Z_PRIVATE void __binary_setup_lookup_table(Binary *b) {
    b->lookup_table_addr = z_elf_get_lookup_table_addr(b->elf);
}

Z_PRIVATE void __binary_setup_tp_zone(Binary *b) {
    b->trampolines_addr = z_elf_get_trampolines_addr(b->elf);
    b->last_tp_addr = b->trampolines_addr;

    // insert a NULL Trampoline to indicate terminal
    assert(sizeof(Trampoline) <= sizeof(null_buf));
    z_elf_write(b->elf, b->trampolines_addr, sizeof(Trampoline),
                (void *)null_buf);
    b->trampolines_addr += sizeof(Trampoline);
}

Z_API Binary *z_binary_open(const char *pathname) {
    // step (0). create a binary struct.
    Binary *b = STRUCT_ALLOC(Binary);
    b->original_filename = z_strdup(pathname);
    b->shadow_main = INVALID_ADDR;
    b->shadow_start = INVALID_ADDR;

    // step (1). setup elf
    b->elf = z_elf_open(b->original_filename);

    // step (2). setup loader
    __binary_setup_loader(b);

    // step (3). setup lookup table
    __binary_setup_lookup_table(b);

    // step (4). setup fork server
    __binary_setup_fork_server(b);

    // step (5). setup trampoline zone
    __binary_setup_tp_zone(b);

    return b;
}

Z_API void z_binary_destroy(Binary *b) {
    z_elf_destroy(b->elf);

    z_free((char *)b->original_filename);

    g_hash_table_destroy(b->mmapped_pages);

    z_free(b);
}

Z_API void z_binary_fsync(Binary *b) {
    // sync ELF
    z_elf_fsync(b->elf);
}

Z_API void z_binary_save(Binary *b, const char *pathname) {
    // save ELF
    z_elf_save(b->elf, pathname);
}

Z_API void z_binary_create_snapshot(Binary *b, const char *pathname) {
    z_elf_create_snapshot(b->elf, pathname);
}

Z_API void z_binary_insert_utp(Binary *b, addr_t utp_addr, const uint8_t *utp,
                               const size_t utp_size) {
    assert(b != NULL);

    if (utp_size > PAGE_SIZE) {
        EXITME("utp size is too large [%#lx]", utp_size);
    }

    Snode *snode = z_snode_create(utp_addr, utp_size, NULL, NULL);
    addr_t mmap_addr = 0;
    size_t mmap_size = 0;
    if (!z_elf_insert_utp(b->elf, snode, &mmap_addr, &mmap_size)) {
        EXITME("Insert utp into an overlapped region: %#lx", utp_addr);
    }

    z_trace("mmap address (%#lx) and size (%#lx)", mmap_addr, mmap_size);

    // update last tp
    addr_t next_tp_offset = b->trampolines_addr - b->last_tp_addr;
    z_elf_write(b->elf, b->last_tp_addr + offsetof(Trampoline, next_tp_offset),
                sizeof(size_t), &next_tp_offset);
    b->last_tp_addr = b->trampolines_addr;

    // emit this utp
    z_elf_write(b->elf, b->trampolines_addr + offsetof(Trampoline, mmap_addr),
                sizeof(void *), &mmap_addr);
    z_elf_write(b->elf, b->trampolines_addr + offsetof(Trampoline, mmap_size),
                sizeof(size_t), &mmap_size);
    z_elf_write(b->elf, b->trampolines_addr + offsetof(Trampoline, tp_addr),
                sizeof(void *), &utp_addr);
    z_elf_write(b->elf, b->trampolines_addr + offsetof(Trampoline, tp_size),
                sizeof(size_t), &utp_size);
    z_elf_write(b->elf,
                b->trampolines_addr + offsetof(Trampoline, next_tp_offset),
                sizeof(size_t), (char *)null_buf);
    b->trampolines_addr += sizeof(Trampoline);
    z_elf_write(b->elf, b->trampolines_addr, utp_size, utp);
    b->trampolines_addr += utp_size;

    __binary_align_trampolines_addr(b);
}

Z_API addr_t z_binary_insert_shadow_code(Binary *b, const uint8_t *sc,
                                         const size_t sc_size) {
    addr_t cur_shadow_addr = b->trampolines_addr;

    z_elf_write(b->elf, b->trampolines_addr, sc_size, sc);
    b->trampolines_addr += sc_size;

    return cur_shadow_addr;
}

Z_API void z_binary_update_lookup_table(Binary *b, addr_t ori_addr,
                                        addr_t shadow_addr) {
    Elf64_Shdr *text = z_elf_get_shdr_text(b->elf);
    addr_t text_addr = text->sh_addr;

    if (ori_addr < text_addr)
        EXITME("too small address (%#lx) compared to .text (%#lx)", ori_addr,
               text_addr);

    size_t cell_num = ori_addr - text_addr;
    if (cell_num > LOOKUP_TABLE_CELL_NUM)
        EXITME("too big address (%#lx) compared to .text (%#lx)", ori_addr,
               text_addr);
    addr_t cell_addr = b->lookup_table_addr + cell_num * LOOKUP_TABLE_CELL_SIZE;

    if (shadow_addr > LOOKUP_TABLE_CELL_MASK)
        EXITME("too big shadow address (%#lx)", shadow_addr);

    z_elf_write(b->elf, cell_addr, LOOKUP_TABLE_CELL_SIZE,
                (uint8_t *)(&shadow_addr));
}

Z_API bool z_binary_check_state(Binary *b, ELFState state) {
    return z_elf_check_state(b->elf, state);
}
