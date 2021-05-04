#include "diagnoser.h"
#include "utils.h"

/*
 * Perform delta debugging to locate rewriting errors
 */
Z_PRIVATE CRSStatus __diagnoser_delta_debug(Diagnoser *g, int status,
                                            addr_t addr);

/*
 * Update a crashpoint's information.
 */
Z_PRIVATE void __diagnoser_update_crashpoint_type(Diagnoser *g, addr_t addr,
                                                  CPType type);

/*
 * Handler a single crashpoint (the real function while handles patching).
 */
Z_PRIVATE void __diagnoser_handle_single_crashpoint(Diagnoser *g, addr_t addr,
                                                    CPType type, bool is_real);

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
            // XXX: note that the following check is very necessary. Although
            // CP_RETADDR cannot be an internal PP_BRIDGE (i.e., overlapping
            // bridge), it can be a PP_BRIDGE after the patched jmp instruction.
            if (z_patcher_check_patchpoint(g->patcher, addrs[i]) == PP_BRIDGE) {
                continue;
            }

            __diagnoser_handle_single_crashpoint(g, addrs[i], cp_type, false);
        }

        z_buffer_destroy(retaddrs);
    } else {
        assert(!(cp_type & CP_RETADDR));
        __diagnoser_handle_single_crashpoint(g, addr, cp_type, true);
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
Z_PRIVATE void __diagnoser_handle_single_crashpoint(Diagnoser *g, addr_t addr,
                                                    CPType type, bool is_real) {
    assert(!is_real || !(type & CP_RETADDR));

    if (!(type & CP_RETADDR)) {
        // The recursive disassembly treats all library function as returnable.
        z_rewriter_rewrite(g->rewriter, addr);
    }

    if (!(type & CP_INTERNAL)) {
        // XXX: note that if it is a retaddr crashpoint, its corresponding
        // shadow code should not start with an AFL trampoline.
        addr_t shadow_addr = z_rewriter_get_shadow_addr(g->rewriter, addr);
        assert(shadow_addr != INVALID_ADDR);
        z_patcher_build_bridge(g->patcher, addr, shadow_addr, is_real);
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

// XXX: it is highly recommended to specify a timeout for AFL by its -t option.
// Otherwise, the auto-scaled timeout may cause incorrect error diagnosis (e.g.,
// the dd_status may change when timeout). more information can be found at
// https://github.com/google/AFL/blob/master/afl-fuzz.c#L3244
// XXX: note that we currently downgrade the delta debugging into a more
// efficient dup-binary-search. This simplified algorithm works well as the
// unintentional crash is caused by a single bad patch in most cases. The delta
// debugging algorithm can be easily brought back if necessary.

/*
 * XXX: to explain how and why the simplified algorithm works well, we first
 * need to give a definition about *key patch*.
 *
 * Key patch means if we remove this patch, the original unintentional crash
 * cannot be reproduced.
 *
 * The simplified algorithm works by first finding the last *key patch*. It
 * ignores all the patches after the last key patch. Then it checks if the
 * unintentional crash can be reproduced by only keeping the last DD_RANGE
 * uncertain patches(e.g., if the last key patch is 54-th patch and DD_RANGE ==
 * 32, then we only keep the 22-nd to 54-th patches).
 *
 * If the crash can be reproduced, it means all the rewriting errors are in the
 * DD_RANGE. Then it use binary search to find the first key patch and regard
 * all patches between the first and the last key patch are rewriting errors.
 *
 * If the crash cannot be repoduced, it only regards the last key patch as an
 * error and re-runs the program to detect other rewriting errors.
 *
 * The algorithm works beacuse of the following two observatoins.
 *
 * The first observation is that, all key patches must be rewritting erros. It
 * is because the correct patches are applied on the instructions and such
 * patches can only trigger intentional crashes (note that we can safeguard
 * non-crashing rewriting errors).
 *
 * The second observation is that, in most cases, an unintentional crash is
 * caused by a single rewriting error or a few continuous errors. It is because
 * the program is very sensitive to incorrect data flow. Once the data flow is
 * randomly polluted, the program is going to crash very soon.
 */
Z_PRIVATE CRSStatus __diagnoser_delta_debug(Diagnoser *g, int status,
                                            addr_t addr) {
#define __UPDATE_STAGE_AND_RETURN(stage, ret) \
    do {                                      \
        g->dd_stage = (stage);                \
        return (ret);                         \
    } while (0)

    if (!z_disassembler_fully_support_prob_disasm(g->disassembler)) {
        assert(g->dd_stage == DD_NONE);
        __UPDATE_STAGE_AND_RETURN(DD_NONE, CRS_STATUS_CRASH);
    }

    z_trace("error diagnosis for status (%d) at %#lx", status, addr);

    if (g->dd_stage == DD_NONE) {
        z_info(
            "check whether the crash is caused by rewriting errors by "
            "disabling all uncertain patches");

        // step (1). check whether there is any uncertain patches
        size_t n = z_patcher_uncertain_patches_n(g->patcher);
        if (!n) {
            // we do not need to wrap up the self correction procedure of
            // patcher here, because it has not been started.
            __UPDATE_STAGE_AND_RETURN(DD_NONE, CRS_STATUS_CRASH);
        }

        // step (2). set dd_status and dd_addr
        g->dd_status = status;
        g->dd_addr = addr;

        // step (3). enable delta debugging for patcher
        g->dd_high = n;
        z_patcher_self_correction_start(g->patcher);

        // step (4). disable all uncertain patches
        z_patcher_flip_uncertain_patches(g->patcher, false, -n);

        // step (5). update dd_stage and return
        __UPDATE_STAGE_AND_RETURN(DD_STAGE0, CRS_STATUS_DEBUG);
    }

    if (g->dd_stage == DD_STAGE0) {
        // step (1). check whether the unintentional crash can be reproduced, if
        // so, we can determine it is caused by a latent bug.
        if (status == g->dd_status && addr == g->dd_addr) {
            z_info(COLOR(RED, "a latent bug at %#lx with status %d"), addr,
                   status);
            z_patcher_self_correction_end(g->patcher);
            __UPDATE_STAGE_AND_RETURN(DD_NONE, CRS_STATUS_CRASH);
        }

        // step (2). it is caused by a rewriting error, let's setup the error
        // diagnosis.
        z_info("we encounter a rewriting error, let's do error diagnosis");
        g->dd_low = 0;
        g->dd_e_cur = 0;

        // step (3). set the mid for e_iter, and update e_iter
        int64_t mid = (g->dd_low + g->dd_high) >> 1;
        z_patcher_flip_uncertain_patches(g->patcher, false, mid - g->dd_e_cur);
        g->dd_e_cur = mid;

        // step (4). update stage and return
        __UPDATE_STAGE_AND_RETURN(DD_STAGE1, CRS_STATUS_DEBUG);
    }

    if (g->dd_stage == DD_STAGE1) {
        // step (1). update dd_low and dd_high
        if (status == g->dd_status && addr == g->dd_addr) {
            z_info(
                "error diagnosis stage 1: test e_iter within [0, %ld), "
                "reproduced: " COLOR(GREEN, "true"),
                g->dd_e_cur);
            g->dd_high = g->dd_e_cur;
        } else {
            z_info(
                "error diagnosis stage 1: test e_iter within [0, %ld), "
                "reproduced: " COLOR(RED, "false"),
                g->dd_e_cur);
            g->dd_low = g->dd_e_cur;
        }

        assert(g->dd_low != g->dd_high);

        // step (2). binary search
        if (g->dd_low + 1 == g->dd_high) {
            // step (2.1.1). the binary search is done, move e_iter to
            // g->dd_high
            z_patcher_flip_uncertain_patches(g->patcher, false,
                                             g->dd_high - g->dd_e_cur);
            g->dd_e_cur = g->dd_high;
            assert(g->dd_e_cur > 0);

            // step (2.1.2). check whether we need to go into DD_STAGE2
            if (g->dd_e_cur <= DD_RANGE) {
                // setup the binary search for s_iter
                g->dd_low = 0;
                g->dd_high = g->dd_e_cur;
                g->dd_s_cur = g->dd_low;

                // ready for s_iter binary search
                int64_t mid = (g->dd_low + g->dd_high) >> 1;
                z_patcher_flip_uncertain_patches(g->patcher, true,
                                                 mid - g->dd_s_cur);
                g->dd_s_cur = mid;
                __UPDATE_STAGE_AND_RETURN(DD_STAGE3, CRS_STATUS_DEBUG);
            } else {
                g->dd_s_cur = 0;
                int64_t target = g->dd_e_cur - DD_RANGE;
                z_patcher_flip_uncertain_patches(g->patcher, true,
                                                 target - g->dd_s_cur);
                g->dd_s_cur = target;
                __UPDATE_STAGE_AND_RETURN(DD_STAGE2, CRS_STATUS_DEBUG);
            }
        } else {
            // step (2.2.1). set the mid for e_iter, and update e_iter
            int64_t mid = (g->dd_low + g->dd_high) >> 1;
            z_patcher_flip_uncertain_patches(g->patcher, false,
                                             mid - g->dd_e_cur);
            g->dd_e_cur = mid;

            // step (2.2.2). update stage and return
            __UPDATE_STAGE_AND_RETURN(DD_STAGE1, CRS_STATUS_DEBUG);
        }
    }

    if (g->dd_stage == DD_STAGE2) {
        if (status == g->dd_status && addr == g->dd_addr) {
            z_info(
                "error diagnosis stage 2: dup-binary-search works for [%ld, "
                "%ld)",
                g->dd_s_cur, g->dd_e_cur);

            // goto DD_STAGE3 for s_iter binary search
            g->dd_low = g->dd_s_cur;
            g->dd_high = g->dd_e_cur;

            int64_t mid = (g->dd_low + g->dd_high) >> 1;
            z_patcher_flip_uncertain_patches(g->patcher, true,
                                             mid - g->dd_s_cur);
            g->dd_s_cur = mid;
            __UPDATE_STAGE_AND_RETURN(DD_STAGE3, CRS_STATUS_DEBUG);
        } else {
            // this branch means the distance between two rewriting errors are
            // relatively large. So we first repair the last rewriting error.
            z_info(
                "error diagnosis stage 2: the distance between two errors is "
                "large, let's first repair "
                "the last one: [%ld, %ld)",
                g->dd_e_cur - 1, g->dd_e_cur);
            assert(g->dd_e_cur - 1 >= g->dd_s_cur);
            z_patcher_flip_uncertain_patches(g->patcher, true,
                                             (g->dd_e_cur - 1) - g->dd_s_cur);
            z_patcher_self_correction_end(g->patcher);
            __UPDATE_STAGE_AND_RETURN(DD_NONE, CRS_STATUS_NOTHING);
        }
    }

    if (g->dd_stage == DD_STAGE3) {
        // step (1). update dd_low and dd_high
        if (status == g->dd_status && addr == g->dd_addr) {
            z_info(
                "error diagnosis stage 3: test s_iter within [%ld, %ld), "
                "reproduced: " COLOR(GREEN, "true"),
                g->dd_s_cur, g->dd_e_cur);
            g->dd_low = g->dd_s_cur;
        } else {
            z_info(
                "error diagnosis stage 3: test s_iter within [%ld, %ld), "
                "reproduced: " COLOR(RED, "false"),
                g->dd_s_cur, g->dd_e_cur);
            g->dd_high = g->dd_s_cur;
        }

        assert(g->dd_low != g->dd_high);

        // step (2). check whether the procedure is done
        if (g->dd_low + 1 == g->dd_high) {
            z_patcher_flip_uncertain_patches(g->patcher, true,
                                             g->dd_low - g->dd_s_cur);
            g->dd_s_cur = g->dd_low;
            z_info("locate the error: [%ld, %ld)", g->dd_s_cur, g->dd_e_cur);
            z_patcher_self_correction_end(g->patcher);
            __UPDATE_STAGE_AND_RETURN(DD_NONE, CRS_STATUS_NOTHING);
        }

        // step (3). continue binary search
        int64_t mid = (g->dd_low + g->dd_high) >> 1;
        z_patcher_flip_uncertain_patches(g->patcher, true, mid - g->dd_s_cur);
        g->dd_s_cur = mid;
        __UPDATE_STAGE_AND_RETURN(DD_STAGE3, CRS_STATUS_DEBUG);
    }

    EXITME("unreachable code");
    return CRS_STATUS_CRASH;  // used to emit warnings

#undef __UPDATE_STAGE_AND_RETURN
}

Z_API Diagnoser *z_diagnoser_create(Patcher *patcher, Rewriter *rewriter,
                                    Disassembler *disassembler) {
    Diagnoser *g = STRUCT_ALLOC(Diagnoser);

    g->binary = z_disassembler_get_binary(disassembler);

    g->patcher = patcher;
    g->rewriter = rewriter;
    g->disassembler = disassembler;

    // all other DD-related fields will be initilized when enabling DD.
    g->dd_stage = DD_NONE;

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

#define __APPLY_CPS(filter)                                              \
    do {                                                                 \
        GHashTableIter iter;                                             \
        gpointer key, value;                                             \
        g_hash_table_iter_init(&iter, g->crashpoints);                   \
                                                                         \
        while (g_hash_table_iter_next(&iter, &key, &value)) {            \
            addr_t addr = (addr_t)key;                                   \
            addr_t type = (CPType)value & (filter);                      \
            if (!type) {                                                 \
                continue;                                                \
            }                                                            \
            __SHOW_CP(addr, type);                                       \
                                                                         \
            if (type != CP_INTERNAL) {                                   \
                addr_t adjusted_addr =                                   \
                    z_patcher_adjust_bridge_address(g->patcher, addr);   \
                if (adjusted_addr != addr) {                             \
                    if (type != CP_EXTERNAL) {                           \
                        /* XXX: avoid change g->crashpints */            \
                                                                         \
                        /* XXX: this branch would happen when pdisasm */ \
                        /* is disabled, and a CP_RETADDR locates on   */ \
                        /* a bridge range.                            */ \
                        continue;                                        \
                    }                                                    \
                    addr = adjusted_addr;                                \
                }                                                        \
            }                                                            \
                                                                         \
            __diagnoser_handle_single_crashpoint(g, addr, type, false);  \
        }                                                                \
    } while (0)

    // we do this in two round, where we first ignore CP_RETADDR, and then we
    // only work on CP_RETADDR. So that we can make sure all blocks are
    // identified before building ret bridgs.
    __APPLY_CPS(~CP_RETADDR);
    __APPLY_CPS(CP_RETADDR);

#undef __APPLY_CPS
#undef __SHOW_CP

    z_rewriter_optimization_stats(g->rewriter);
    z_patcher_bridge_stats(g->patcher);
}

Z_API CRSStatus z_diagnoser_new_crashpoint(Diagnoser *g, int status,
                                           addr_t addr) {
    // step (0). check whether diagnoser is under delta debugging mode
    if (g->dd_stage != DD_NONE) {
        // the diagnoser is under delta debugging mode
        return __diagnoser_delta_debug(g, status, addr);
    }

    // step (1). check whether the status is suspect
    if (!IS_ABNORMAL_STATUS(status)) {
        return CRS_STATUS_NORMAL;
    }
    if (!IS_SUSPECT_STATUS(status)) {
        // it is an unintentional crash
        assert(g->dd_stage == DD_NONE);
        return __diagnoser_delta_debug(g, status, addr);
    }
    if (addr == CRS_INVALID_IP) {
        EXITME("the client exits as SUSPECT but no suspected address is sent");
    }

    // step (2). validate crashpoint
    addr_t real_addr = __diagnoser_validate_crashpoint(g, addr);
    // XXX: we have to adjust bridge patch pointer when real_addr is unchanged.
    if (real_addr == addr) {
        // in this case, it cannot be a CP_INTERNAL
        real_addr = z_patcher_adjust_bridge_address(g->patcher, real_addr);
    }

    // step (3). check whether real_addr is INVALID_ADDR
    if (real_addr == INVALID_ADDR) {
        // it is an unintentional crash
        z_info(COLOR(RED, "real crash with suspect status! (%#lx)"), addr);
        assert(g->dd_stage == DD_NONE);
        return __diagnoser_delta_debug(g, status, addr);
    }

    // step (4). get CPType
    CPType cp_type = __diagnoser_get_crashpoint_type(g, addr, real_addr);

    // step (5). patch the intentional crash
    __diagnoser_patch_crashpoint(g, real_addr, cp_type);

    z_rewriter_optimization_stats(g->rewriter);
    z_patcher_bridge_stats(g->patcher);

    // step (6). check remmap
    if (z_binary_check_state(g->binary, ELFSTATE_SHADOW_EXTENDED)) {
        z_info("underlying shadow file is extended");

        // do not forget to disable the shadow_extened flag
        z_binary_set_elf_state(g->binary,
                               ELFSTATE_SHADOW_EXTENDED | ELFSTATE_DISABLE);

        return CRS_STATUS_REMMAP;
    } else {
        return CRS_STATUS_NOTHING;
    }
}
