#ifndef __DISASSEMBLER_H
#define __DISASSEMBLER_H

#include "binary.h"
#include "buffer.h"
#include "config.h"
#include "interval_splay.h"

STRUCT(Disassembler, {
    // Binary which needs disassembly
    Binary *binary;

    // disassembly
    GHashTable *superset_disasm;
    GHashTable *recursive_disasm;

    // Statistical data
    size_t patched_tp_count;
    size_t patched_utp_count;
    size_t failed_utp_count;

    // Regions that already are correctly disassemblied
    Splay *regions;

    // Unpatched control flow instructions
    GQueue *unpatched_cf_insts;
});

/*
 * Create a disassembler
 */
Z_API Disassembler *z_disassembler_create(Binary *b);

/*
 * Destroy a disassembler
 */
Z_API void z_disassembler_destroy(Disassembler *d);

/*
 * Recursive disassemble from given address
 */
Z_API void z_disassembler_disasm(Disassembler *d, addr_t addr, bool store_cf);

/*
 * Patch to CF instruction
 */
Z_API void z_disassembler_patch_cf(Disassembler *d);

#endif
