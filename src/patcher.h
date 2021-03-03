#ifndef __PATCHER_H
#define __PATCHER_H

#include "binary.h"
#include "buffer.h"
#include "config.h"
#include "crs_config.h"
#include "disassembler.h"

#include <gmodule.h>

STRUCT(Patcher, {
    Binary *binary;
    Disassembler *disassembler;

    // .text info
    addr_t text_addr;
    size_t text_size;

    // *all* possible crash points for patching (checkpoints)
    GHashTable *checkpoints;

    // patched bridge (bridge entrypoint)
    GHashTable *bridges;

    // CRS CMD information
    Buffer **cmd_buf_ptr;
});

/*
 * Create a patcher
 */
Z_API Patcher *z_patcher_create(Disassembler *d, Buffer **cmd_buf_ptr);

/*
 * Destroy a patcher
 */
Z_API void z_patcher_destroy(Patcher *p);

/*
 * Patch all instructions whose probabilities are high enough
 */
Z_API void z_patcher_patch_all(Patcher *p);

/*
 * Check whether address is a patched crash points (checkpoint)
 */
Z_API bool z_patcher_check(Patcher *p, addr_t addr);

/*
 * Patch address as a jump bridge
 */
Z_API void z_patcher_build_bridge(Patcher *p, addr_t ori_addr,
                                  addr_t shadow_addr);

/*
 * Patcher show details
 */
Z_API void z_patcher_describe(Patcher *p);

#endif
