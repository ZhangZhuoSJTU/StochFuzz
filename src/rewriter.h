/*
 * rewriter.h
 * Copyright (C) 2021 Zhuo Zhang, Xiangyu Zhang
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __REWRITER_H
#define __REWRITER_H

#include "binary.h"
#include "buffer.h"
#include "config.h"
#include "disassembler.h"
#include "sys_optarg.h"

#include <gmodule.h>

STRUCT(Rewriter, {
    // Binary which nees to rewrite
    Binary *binary;

    // Disassembler
    Disassembler *disassembler;

    // Handlers
    Buffer *handlers;

    // Basic information
    GHashTable *shadow_code;
    GHashTable *rewritten_bbs;

    /*
     * meta-info for CP_RETADDR
     */
    // XXX: note that when pdisasm is fully supported, CP_RETADDR is disabled.
    // XXX: CP_RETADDR is only used for unknown library functions, which means
    // it is not for those internal calls or white-listed library calls.

    // patched retaddr, which is potential to be crashpoint
    GHashTable *potential_retaddrs;
    // for a given callee, all unpatched retaddr crashpoints associated with it
    GHashTable *unpatched_retaddrs;  // callee -> retaddrs

    // Statistical data
    size_t patched_safe_bg_count;
    size_t patched_unsafe_bg_count;
    size_t afl_trampoline_count;
    size_t optimized_flg_count;
    size_t optimized_gpr_count;
    size_t optimized_single_succ;

    // Internal data
    bool __main_rewritten;

    // rewriting optargs
    RewritingOptArgs *opts;
});

// which instruction needs to be handled
typedef bool (*REvent)(const cs_insn *);

// how to rewrite the instruction
typedef void (*RHandlerFcn)(Rewriter *, GHashTable *, cs_insn *,
                            addr_t ori_addr, addr_t ori_next_addr);

STRUCT(RHandler, {
    REvent event;
    RHandlerFcn fcn;
});

DECLARE_GETTER(RHandler, rhandler, REvent, evnet);
DECLARE_GETTER(RHandler, rhandler, RHandlerFcn, fcn);

/*
 * Create a REvent
 */
Z_API RHandler *z_rhandler_create(REvent event, RHandlerFcn fcn);

/*
 * Destroy a REvent
 */
Z_API void z_rhandler_destroy(RHandler *handler);

/*
 * Create a rewriter
 */
Z_API Rewriter *z_rewriter_create(Disassembler *d, RewritingOptArgs *opts);

/*
 * Destroy a rewrite
 */
Z_API void z_rewriter_destroy(Rewriter *r);

/*
 * Register a handler for rewriter
 */
Z_API void z_rewriter_register_handler(Rewriter *r, REvent event,
                                       RHandlerFcn fcn);

/*
 * Rewrite based on known knowledge
 */
Z_API void z_rewriter_rewrite(Rewriter *r, addr_t new_addr);

/*
 * Get the shadow address of given addr
 */
Z_API addr_t z_rewriter_get_shadow_addr(Rewriter *r, addr_t addr);

/*
 * Initial rewriting for those addresses known to be code
 */
Z_API void z_rewriter_initially_rewrite(Rewriter *r);

/*
 * Heuristics rewriting after rewriting main
 */
Z_RESERVED Z_API void z_rewriter_heuristics_rewrite(Rewriter *r);

/*
 * Check whether the address is a potential return address which is already
 * rewritten
 */
Z_API bool z_rewriter_check_retaddr_crashpoint(Rewriter *r, addr_t addr);

/*
 * Find a new validate retaddr and return all retaddrs who share the same call
 * with given retaddr. Note that destorying returned Buffer is not this
 * function's responsibility.
 */
Z_API Buffer *z_rewriter_new_validate_retaddr(Rewriter *r, addr_t retaddr);

/*
 * Show optimization stats
 */
Z_API void z_rewriter_optimization_stats(Rewriter *r);

#endif
