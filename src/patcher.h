#ifndef __PATCHER_H
#define __PATCHER_H

#include "address_dictionary.h"
#include "binary.h"
#include "buffer.h"
#include "config.h"
#include "crs_config.h"
#include "disassembler.h"

#include <gmodule.h>

// XXX: note that patchpoint has priority of:
//  PP_BRIDEG > PP_CERTAIN > PP_UNCERTAIN
typedef enum patchpoint_type {
    PP_INVALID = 0UL,
    PP_UNCERTAIN = 1UL,
    PP_CERTAIN = 2UL,
    PP_BRIDGE = 3UL,
} PPType;

STRUCT(Patcher, {
    Binary *binary;
    Disassembler *disassembler;

    // .text info
    addr_t text_addr;
    size_t text_size;
    Rptr *text_ptr;        // pointer to the shared .text section
    uint8_t *text_backup;  // original data before any patching

    // addresses which are certainly known as code
    //  for instruction boundary, the value is the length of instruction
    //  for other places, the value is zero
    AddrDict(uint8_t, certain_addresses);

    // patch information
    GSequence *uncertain_patches;
    AddrDictFast(bool, certain_patches);

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
 * Initial patching for the instructions whose probabilities are high enough
 */
Z_API void z_patcher_initially_patch(Patcher *p);

/*
 * Check whether address is a patched crash points (patch point)
 */
Z_API PPType z_patcher_check_patchpoint(Patcher *p, addr_t addr);

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
