#ifndef __BINARY_H
#define __BINARY_H

#include "buffer.h"
#include "config.h"
#include "elf_.h"
#include "interval_splay.h"

#include <gmodule.h>

typedef addr_t bb_t;

/*
 * Binary: used to story patch meta-information.
 *
 * ELF virtual memory layout can be found in elf_.h
 */
STRUCT(Binary, {
    const char *original_filename;  // Path of input file
    ELF *elf;                       // Basic ELF information
    addr_t shadow_main;             // Address of shadow main function
    addr_t shadow_start;            // Address of shadow _start function

    // Loader
    addr_t loader_addr;  // Address of loader

    // Loader info for uTP (TramPolines for ucall/ujmp)
    // XXX: the mmapped_pages seems useless currently (delete it maybe?)
    GHashTable *mmapped_pages;  // Hashset of mmapped pages

    // Fork server and random patcher
    addr_t fork_server_addr;   // Address of fork server
    addr_t random_patch_addr;  // Address of random patch table
    addr_t random_patch_num;   // number of random patch table

    // Lookup table
    addr_t lookup_table_addr;  // Address of lookup table

    // Shadow Code and Trampolines
    addr_t trampolines_addr;  // Next avaiable address of trampolines
    addr_t last_tp_addr;
});

DECLARE_GETTER(Binary, binary, ELF *, elf);
DECLARE_GETTER(Binary, binary, const char *, original_filename);
DECLARE_GETTER(Binary, binary, addr_t, trampolines_addr);
DECLARE_GETTER(Binary, binary, addr_t, shadow_main);
DECLARE_GETTER(Binary, binary, addr_t, shadow_code_addr);
DECLARE_SETTER(Binary, binary, addr_t, shadow_main);
DECLARE_SETTER(Binary, binary, addr_t, shadow_start);
DECLARE_SETTER(Binary, binary, ELFState, elf_state);

/*
 * Construct a binary for given file.
 */
Z_API Binary *z_binary_open(const char *in_filename);

/*
 * Destructor of Binary
 */
Z_API void z_binary_destroy(Binary *b);

/*
 * Save binary
 */
Z_API void z_binary_save(Binary *b, const char *pathname);

/*
 * Create a snapshot for current Binary.
 * Differnt from z_binary_save, this Binary's main body (except loookup tabel
 * and shadow) will remain unchanged even future patches are applied.
 */
Z_API void z_binary_create_snapshot(Binary *b, const char *pathname);

/*
 * Insert a new uTP
 */
// XXX: currently we do not use uTP in the actual rewriting, but it will be
// extremely useful when we start to handle overlapped jmp bridges.
Z_API void z_binary_insert_utp(Binary *b, addr_t utp_addr, const uint8_t *utp,
                               const size_t utp_size);

/*
 * Insert a new piece of shadow code, and return the address of the shadow code
 */
Z_API addr_t z_binary_insert_shadow_code(Binary *b, const uint8_t *sc,
                                         const size_t sc_size);

/*
 * Notify binary that all shadow code has been inserted
 */
Z_API void z_binary_shadow_code_notify(Binary *b, addr_t shadow_main);

/*
 * Add a look up cell
 */
Z_API void z_binary_update_lookup_table(Binary *b, addr_t ori_addr,
                                        addr_t shadow_addr);

/*
 * Sync binary with underlying files
 */
Z_API void z_binary_fsync(Binary *b);

/*
 * Wrapper for z_elf_check_state()
 */
Z_API bool z_binary_check_state(Binary *b, ELFState state);
#endif
