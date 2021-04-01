#include "diagnoser.h"
#include "utils.h"

/*
 * Update a crashpoint's information.
 */
Z_PRIVATE void __diagnoser_update_crashpoint_type(Diagnoser *g, addr_t addr,
                                                  CPType type);

/*
 * Handler a single crashpoint (the real function while handles patching).
 */
Z_PRIVATE void __diagnoser_handle_single_crashpoint(Diagnoser *g, addr_t addr,
                                                    CPType type);

/*
 * Validate a crashpoint, return INVALID_ADDR if it is an unintentional crash
 */
Z_PRIVATE addr_t __diagnoser_validate_crashpoint(Diagnoser *g, addr_t addr);

/*
 * Get the CPType of the given crashpoint
 */
Z_PRIVATE CPType __diagnoser_get_crashpoint_type(Diagnoser *g, addr_t addr,
                                                 addr_t real_addr);

/*
 * Patch the intentional crash
 */
Z_PRIVATE void __diagnoser_patch_crashpoint(Diagnoser *g, addr_t addr,
                                            CPType cp_type);

/*
 * Getter and Setter
 */
DEFINE_GETTER(Diagnoser, diagnoser, GHashTable *, crashpoints);

// XXX: note that __diagnoser_patch_crashpoint's parameter *cp_type* must be a
// single type (e.g., CP_INTERNAL), instead of multiple types (e.g., CP_RETADDR
// | CP_EXTERNAL)
Z_PRIVATE void __diagnoser_patch_crashpoint(Diagnoser *g, addr_t addr,
                                            CPType cp_type) {
    if (cp_type == CP_RETADDR) {
        // for CP_RETADDR, we want to also update other retaddrs who share the
        // same callee with the found one

        Buffer *retaddrs = z_rewriter_new_validate_retaddr(g->rewriter, addr);
        size_t n = z_buffer_get_size(retaddrs) / sizeof(addr_t);
        addr_t *addrs = (addr_t *)z_buffer_get_raw_buf(retaddrs);
        z_info("we found %d CP_RETADDR sharing the same callee", n);

        for (int i = 0; i < n; i++) {
            if (z_patcher_check_patchpoint(g->patcher, addrs[i]) == PP_BRIDGE) {
                continue;
            }
            __diagnoser_handle_single_crashpoint(g, addrs[i], cp_type);
        }

        z_buffer_destroy(retaddrs);
    } else {
        assert(!(cp_type & CP_RETADDR));
        __diagnoser_handle_single_crashpoint(g, addr, cp_type);
    }

    /*
     * TODO: re-analyze probability here
     */
}

Z_PRIVATE CPType __diagnoser_get_crashpoint_type(Diagnoser *g, addr_t addr,
                                                 addr_t real_addr) {
    if ((int64_t)addr < 0) {
        z_info("find new address [internal]: " COLOR(GREEN, "%#lx"), addr);
        return CP_INTERNAL;
    } else {
        // XXX: retaddr patch may cause crash when enabling pdisasm.
        // XXX: note that if diagnoser does not generate any CP_RETADDR, all
        // ret-related functions of rewriter will not be invoked and no
        // VCP_CALLEE will be generated. That is why this check is extremely
        // important.
        if (!z_disassembler_fully_support_prob_disasm(g->disassembler) &&
            z_rewriter_check_retaddr_crashpoint(g->rewriter, real_addr) &&
            real_addr == addr) {
            z_info("find new address [retaddr]: " COLOR(GREEN, "%#lx"),
                   real_addr);
            return CP_RETADDR;
        } else {
            z_info("find new address [external]: " COLOR(GREEN, "%#lx"),
                   real_addr);
            return CP_EXTERNAL;
        }
    }
}

Z_PRIVATE addr_t __diagnoser_validate_crashpoint(Diagnoser *g, addr_t addr) {
    assert(g != NULL);

    // step (1). check INVALID_ADDR
    if (addr == INVALID_ADDR) {
        return INVALID_ADDR;
    }

    // step (2). validate addr by different type
    if ((int64_t)addr < 0) {
        // it is caused by a missed ujmp/ucall entry
        addr = (~addr) + 1;
        if (z_disassembler_is_within_disasm_range(g->disassembler, addr) &&
            !z_disassembler_is_potential_inst_entrypoint(g->disassembler,
                                                         addr)) {
            return addr;
        } else {
            return INVALID_ADDR;
        }
    } else {
        // it is cause by patch
        if (z_patcher_check_patchpoint(g->patcher, addr) == PP_INVALID) {
            return INVALID_ADDR;
        } else {
            return addr;
        }
    }
}

// XXX: addr must be an adjusted address if needed
Z_API void __diagnoser_handle_single_crashpoint(Diagnoser *g, addr_t addr,
                                                CPType type) {
    if (!(type & CP_RETADDR)) {
        z_rewriter_rewrite(g->rewriter, addr);
    }
    if (!(type & CP_INTERNAL)) {
        // XXX: note that if it is a retaddr crashpoint, its corresponding
        // shadow code should not start with an AFL trampoline.
        addr_t shadow_addr = z_rewriter_get_shadow_addr(g->rewriter, addr);
        assert(shadow_addr != INVALID_ADDR);
        z_patcher_build_bridge(g->patcher, addr, shadow_addr);
    }

    // update crashpoint log
    __diagnoser_update_crashpoint_type(g, addr, type);
}

Z_PRIVATE void __diagnoser_update_crashpoint_type(Diagnoser *g, addr_t addr,
                                                  CPType type) {
    CPType type_ =
        (CPType)g_hash_table_lookup(g->crashpoints, GSIZE_TO_POINTER(addr));
    if ((type | type_) != type_) {
        // this check is very important, which is used to avoid modifying
        // g->crashpoints and invalidating any iterator associated with the
        // hash table
        g_hash_table_insert(g->crashpoints, GSIZE_TO_POINTER(addr),
                            GSIZE_TO_POINTER(type | type_));
    }
}

Z_API Diagnoser *z_diagnoser_create(Patcher *patcher, Rewriter *rewriter,
                                    Disassembler *disassembler) {
    Diagnoser *g = STRUCT_ALLOC(Diagnoser);

    g->binary = z_disassembler_get_binary(disassembler);

    g->patcher = patcher;
    g->rewriter = rewriter;
    g->disassembler = disassembler;

    g->crashpoints =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    const char *binary_filename = z_binary_get_original_filename(g->binary);
    g->cp_filename = z_strcat(CRASHPOINT_LOG_PREFIX, binary_filename);

    return g;
}

Z_API void z_diagnoser_destroy(Diagnoser *g) {
    g_hash_table_destroy(g->crashpoints);
    z_free((void *)g->cp_filename);
    z_free(g);
}

Z_API void z_diagnoser_read_crashpoint_log(Diagnoser *g) {
    if (z_access(g->cp_filename, F_OK)) {
        z_trace("log file for crashpoints (%s) does not exist", g->cp_filename);
        return;
    }

    Buffer *buffer = z_buffer_read_file(g->cp_filename);
    CrashPoint *cp = (CrashPoint *)z_buffer_get_raw_buf(buffer);
    size_t file_size = z_buffer_get_size(buffer);
    for (size_t i = 0; i < file_size; i += sizeof(CrashPoint), cp++) {
        // handle virtual crashpoints
        if (cp->type & VCP_CALLEE) {
            if (z_disassembler_fully_support_prob_disasm(g->disassembler)) {
                // TODO: skip this VCP_CALLEE instead of directly exiting
                EXITME(
                    "while pdisasm is fully enabled, currently we cannot "
                    "support this VCP_CALLEE: %#lx",
                    cp->addr);
            }
            z_rewriter_set_returned_callees(g->rewriter, cp->addr);
            if (!(cp->type = cp->type & (~VCP_CALLEE))) {
                continue;
            }
        }

        __diagnoser_update_crashpoint_type(g, cp->addr, cp->type);
    }

    z_buffer_destroy(buffer);
}

Z_API void z_diagnoser_write_crashpoint_log(Diagnoser *g) {
    // before write crashpoints, we need to store unlogged retaddr crashpoints
    {
        GHashTable *unlogged_retaddr_crashpoints =
            z_rewriter_get_unlogged_retaddr_crashpoints(g->rewriter);

        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, unlogged_retaddr_crashpoints);

        while (g_hash_table_iter_next(&iter, &key, &value)) {
            addr_t addr = (addr_t)key;
            __diagnoser_update_crashpoint_type(g, addr, CP_RETADDR);
        }
    }

    // update VCP_CALLEE
    {
        GHashTable *returned_callees =
            z_rewriter_get_returned_callees(g->rewriter);

        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, returned_callees);

        while (g_hash_table_iter_next(&iter, &key, &value)) {
            addr_t addr = (addr_t)key;
            __diagnoser_update_crashpoint_type(g, addr, VCP_CALLEE);
        }
    }

    {
#ifndef BINARY_SEARCH_INVALID_CRASH
        // write down all crashpoints
        FILE *f = z_fopen(g->cp_filename, "wb");
        CrashPoint cp = {
            .addr = INVALID_ADDR,
            .type = CP_NONE,
        };

        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, g->crashpoints);

        while (g_hash_table_iter_next(&iter, &key, &value)) {
            cp.addr = (addr_t)key;
            cp.type = (CPType)value;
            if (z_fwrite(&cp, sizeof(CrashPoint), 1, f) != 1) {
                EXITME("error on writing crashpoint log file");
            }
        }

        z_fclose(f);
#endif
    }
}

Z_API void z_diagnoser_apply_logged_crashpoints(Diagnoser *g) {
#define __SHOW_CP(addr, type)                                                  \
    do {                                                                       \
        z_info("logged crashpoint [%s%s%s%s%s]: " COLOR(GREEN, "%#lx"),        \
               ((type)&CP_INTERNAL) ? "internal" : "",                         \
               (((type)&CP_INTERNAL) && ((type)&CP_EXTERNAL)) ? "|" : "",      \
               ((type)&CP_EXTERNAL) ? "external" : "",                         \
               (((type) & (CP_INTERNAL | CP_EXTERNAL)) && ((type)&CP_RETADDR)) \
                   ? "|"                                                       \
                   : "",                                                       \
               ((type)&CP_RETADDR) ? "retaddr" : "", addr);                    \
    } while (0)

#define __APPLY_CPS(filter)                                                  \
    do {                                                                     \
        GHashTableIter iter;                                                 \
        gpointer key, value;                                                 \
        g_hash_table_iter_init(&iter, g->crashpoints);                       \
                                                                             \
        while (g_hash_table_iter_next(&iter, &key, &value)) {                \
            addr_t addr = (addr_t)key;                                       \
            addr_t type = (CPType)value & (filter);                          \
            if (!type) {                                                     \
                continue;                                                    \
            }                                                                \
            __SHOW_CP(addr, type);                                           \
                                                                             \
            if (type != CP_INTERNAL) {                                       \
                addr_t adjusted_addr =                                       \
                    z_patcher_adjust_bridge_address(g->patcher, addr);       \
                if (adjusted_addr != addr) {                                 \
                    if (type != CP_EXTERNAL) {                               \
                        /* TODO: this constrain should be relaxed. */        \
                        EXITME("invalid CP type for adjusted address: %#lx", \
                               adjusted_addr);                               \
                    }                                                        \
                    addr = adjusted_addr;                                    \
                }                                                            \
            }                                                                \
                                                                             \
            __diagnoser_handle_single_crashpoint(g, addr, type);             \
        }                                                                    \
    } while (0)

    // we do this in two round, where we first ignore CP_RETADDR, and then we
    // only work on CP_RETADDR. So that we can make sure all blocks are
    // identified before building ret bridgs.
    __APPLY_CPS(~CP_RETADDR);
    __APPLY_CPS(CP_RETADDR);

#undef __APPLY_CPS
#undef __SHOW_CP
}

Z_API CRSStatus z_diagnoser_new_crashpoint(Diagnoser *g, int status,
                                           addr_t addr) {
    // step (0). check whether the status is suspect
    if (!IS_SUSPECT_STATUS(status)) {
        z_info("non-suspect status: %d", status);
        return CRS_STATUS_OTHERS;
    }
    if (addr == CRS_INVALID_IP) {
        EXITME("the client exits as SUSPECT but no suspected address is sent");
    }

    // step (1). validate crashpoint
    addr_t real_addr = __diagnoser_validate_crashpoint(g, addr);
    // XXX: we have to adjust bridge patch pointer when real_addr is unchanged.
    if (real_addr == addr) {
        // in this case, it cannot be a CP_INTERNAL
        real_addr = z_patcher_adjust_bridge_address(g->patcher, real_addr);
    }

    // step (2). check whether real_addr is INVALID_ADDR
    if (real_addr == INVALID_ADDR) {
        z_error(COLOR(RED, "real crash! (%#lx)"), addr);
        return CRS_STATUS_CRASH;
    }

    // step (3). get CPType
    CPType cp_type = __diagnoser_get_crashpoint_type(g, addr, real_addr);

    // step (4). patch the intentional crash
    __diagnoser_patch_crashpoint(g, real_addr, cp_type);

    z_info("number of patched bridges: %d",
           z_patcher_get_patched_bridges(g->patcher));
    z_info("number of delayed bridges: %d",
           z_patcher_get_delayed_bridges(g->patcher));
    z_info("number of resolved bridges: %d",
           z_patcher_get_resolved_bridges(g->patcher));
    z_info("number of adjusted bridges: %d",
           z_patcher_get_adjusted_bridges(g->patcher));

    // step (5). check remmap
    if (z_binary_check_state(g->binary, ELFSTATE_SHADOW_EXTENDED)) {
        z_info("underlying shadow file is extended");

        // do not forget to disable the shadow_extened flag
        z_binary_set_elf_state(g->binary,
                               ELFSTATE_SHADOW_EXTENDED | ELFSTATE_DISABLE);

        return CRS_STATUS_REMMAP;
    } else {
        return CRS_STATUS_NONE;
    }
}
