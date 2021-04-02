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

// XXX: some fields of Patcher are essential to understand the underlying logic:
//
//  * certain_addresses: all the address which are *certainly* sure to be code
//                       bytes. The values of this dictionary have two types:
//                       the instruction size for each instruction boundary, and
//                       zero for the others.
//
//  * uncertain_patches: all the patches which are *uncertainly* sure. Most of
//                       them are patched based on the calculated probability.
//
//  *   certain_patches: all the patches which are *certainly* sure. The only
//                       patched value of this type is 0x2f (invalid). This kind
//                       of patches excludes the ones serve for bridge
//                       overlapping detection. It also exlucdes those code
//                       which was patched and has been revoked for delayed
//                       bridges.
//
//  *           bridges: all potential patch points which can help detect bridge
//                       overlapping.
//
//
// There are some relations between aforementioned fields.
//
//      keys(uncertain_patches).intersaction(keys(certain_addresses)) = EmptySet
//
//        keys(uncertain_patches).intersaction(keys(certain_patches)) = EmptySet
//                keys(uncertain_patches).intersaction(keys(bridges)) = EmptySet
//                  keys(certain_patches).intersaction(keys(bridges)) = EmptySet
//
//                              keys(certain_patches) in keys(certain_addresses)
//                                      keys(bridges) in keys(certain_addresses)
//
//      keys(certain_addresses)
//    -  (keys(certain_patches) + keys(bridges))
//    =  set(address which was patched and has been revoked for delayed bridges)
//
// Only uncertain_patches are involved in the delta debugging procedure.
STRUCT(Patcher, {
    Binary *binary;
    Disassembler *disassembler;

    bool pdisasm_enable;

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
    GHashTable *bridges;  // bridges detection points

    // others
    size_t patched_bridges;
    size_t delayed_bridges;
    size_t resolved_bridges;
    size_t adjusted_bridges;
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

/*
 * Show bridge stat
 */
Z_API void z_patcher_bridge_stats(Patcher *p);

#endif
