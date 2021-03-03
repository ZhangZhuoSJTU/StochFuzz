#ifndef __BINARY_H
#define __BINARY_H

#include <stdint.h>

#include <gmodule.h>

#include "buffer.h"
#include "elf_.h"
#include "interval_splay.h"
#include "mem_file.h"
#include "trampoline.h"
#include "utils.h"

/*
 * Binary: Key structure, used to store patched and unpatched binary information
 */
typedef struct binary_t {
    const char *pathname;  // Path of input file
    ELF *elf;              // Basic ELF information

    _MEM_FILE *stream;  // _MEM_FILE for out stream

    // Should remove
    //
    const char *out_filename;

    // Following should go into ELF:
    //
    addr_t original_entry;  // Original entrypoint
    bool is_pie;            // ELF is compiled with PIE?

    // Glib example
    //
    GHashTable *trampolines;  // Trampolines
    GArray *vaddrs;           // Virtual addresses of rampolines

    Buffer *patched_buf;

    size_t
        springboard_offset;  // Offset of loader springboard, MAX is not patched
    size_t springboard_jmp_offset;  // Offset of the jump instruction in
                                    // springboard
    size_t loader_offset;  // Offset of patched loader, MAX if not patched
    bool need_emit;        // Does current binary need emiting?
} Binary;

/*
 * Construct a binary for given file.
 */
Z_API Binary *z_binary_open(const char *in_filename, const char *out_filename);

/*
 * Destructor of Binary
 */
Z_API void z_binary_destroy(Binary *b);

/*
 * Save binary into pathname.
 */
Z_API void z_binary_save(Binary *b);

/*
 * Emit binary into patched ELF.
 */
Z_API void z_binary_emit(Binary *b);

/*
 * Insert a trampoline into binary.
 */
Z_API void z_binary_insert_trampoline(Binary *b, Trampoline *t);

#endif
