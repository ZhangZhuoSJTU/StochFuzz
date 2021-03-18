#include "diagnoser.h"
#include "binary.h"
#include "utils.h"

/*
 * Update a crashpoint's information.
 */
Z_PRIVATE void __diagnoser_update_crashpoint_type(Diagnoser *g, addr_t addr,
                                                  CPType type);

// XXX: temporarily set a private function as public
// /*
//  * Handler a single crashpoint (the real function handling patching).
//  */
// Z_PRIVATE void __diagnoser_handle_single_crashpoint(Diagnoser *g, addr_t
// addr,
//                                                     CPType type);

/*
 * Getter and Setter
 */
DEFINE_GETTER(Diagnoser, diagnoser, GHashTable *, crashpoints);

Z_API void __diagnoser_handle_single_crashpoint(Diagnoser *g, addr_t addr,
                                                CPType type) {
    if (!(type & CP_RETADDR)) {
        z_rewriter_rewrite(g->rewriter, addr);
    }
    if (!(type & CP_INTERNAL)) {
        // XXX: note that if it is a retaddr crashpoint, its shadow address
        // should not be a trampoline code.
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

    g->patcher = patcher;
    g->rewriter = rewriter;
    g->disassembler = disassembler;

    Binary *binary = z_disassembler_get_binary(g->disassembler);
    const char *binary_filename = z_binary_get_original_filename(binary);

    g->crashpoints =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
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

#define __APPLY_CPS(filter)                                      \
    do {                                                         \
        GHashTableIter iter;                                     \
        gpointer key, value;                                     \
        g_hash_table_iter_init(&iter, g->crashpoints);           \
                                                                 \
        while (g_hash_table_iter_next(&iter, &key, &value)) {    \
            addr_t addr = (addr_t)key;                           \
            addr_t type = (CPType)value & (filter);              \
            if (!type) {                                         \
                continue;                                        \
            }                                                    \
            __SHOW_CP(addr, type);                               \
            __diagnoser_handle_single_crashpoint(g, addr, type); \
        }                                                        \
    } while (0)

    // we do this in two round, where we first ignore CP_RETADDR, and then we
    // only work on CP_RETADDR. So that we can make sure all blocks are
    // identified before building ret bridgs.
    __APPLY_CPS(~CP_RETADDR);
    __APPLY_CPS(CP_RETADDR);

#undef __APPLY_CPS
#undef __SHOW_CP
}
