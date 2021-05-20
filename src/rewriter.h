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
    GHashTable *retaddr_crashpoints;
    // callees who will return
    GHashTable *returned_callees;
    // for a given callee, all potential retaddr crashpoints associated with it
    GHashTable *callee2retaddrs;
    // unlogged retaddr crashpoints because its callee is known to return
    GHashTable *unlogged_retaddr_crashpoints;

    // Statistical data
    size_t patched_safe_bg_count;
    size_t patched_unsafe_bg_count;
    size_t afl_trampoline_count;
    size_t optimized_flg_count;
    size_t optimized_gpr_count;
    size_t optimized_single_succ;

    // Internal data
    bool __main_rewritten;

    // system optargs
    SysOptArgs *opts;
});

DECLARE_GETTER(Rewriter, rewriter, GHashTable *, unlogged_retaddr_crashpoints);
DECLARE_GETTER(Rewriter, rewriter, GHashTable *, returned_callees);
DECLARE_SETTER(Rewriter, rewriter, addr_t, returned_callees);

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
Z_API Rewriter *z_rewriter_create(Disassembler *d, SysOptArgs *opts);

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
