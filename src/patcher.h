#ifndef __PATCHER_H
#define __PATCHER_H

#include "address_dictionary.h"
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
    Rptr *text_ptr;

    // addresses which are certainly known as code
    AddrDict(bool, certain_addresses);

    // XXX: followings are out-of-date
    // TODO: update to the new design
    // *all* possible crash points for patching (checkpoints)
    GHashTable *checkpoints;

    // patched bridge (bridge entrypoint)
    GHashTable *bridges;
});

/*
 * Create a patcher
 */
Z_API Patcher *z_patcher_create(Disassembler *d);

/*
 * Destroy a patcher
 */
Z_API void z_patcher_destroy(Patcher *p);

/*
 * Patcher show details
 */
Z_API void z_patcher_describe(Patcher *p);

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
 * Adjust the address of a given bridge. This function may also change current
 * patching.
 */
Z_API addr_t z_patcher_adjust_bridge_address(Patcher *p, addr_t addr);

#endif
