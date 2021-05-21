#ifndef __UCFG_ANALYZER_H
#define __UCFG_ANALYZER_H

#include "buffer.h"
#include "capstone_.h"
#include "config.h"
#include "sys_optarg.h"

#include <capstone/capstone.h>
#include <gmodule.h>

/*
 * Light-weight instruction-level analyzer, which aims at analyzing conservative
 * use-def relation on the Universal CFG (UCFG).
 */
STRUCT(UCFG_Analyzer, {
    // basic instruction information
    GHashTable *insts;

    // register state for each instruction
    GHashTable *reg_states;

    // successors and predecessor
    //  note that it is possible to return preds/succs for an invalid address
    GHashTable *direct_preds;
    GHashTable *direct_succs;

    // eflags register analysis
    GHashTable *flg_finished_succs;
    GHashTable *flg_need_write;

    // general register analysis
    GHashTable *gpr_analyzed_succs;
    GHashTable *gpr_can_write;

    // system optargs
    SysOptArgs *opts;
});

/*
 * Create an ucfg_analyzer
 */
Z_API UCFG_Analyzer *z_ucfg_analyzer_create(SysOptArgs *opts);

/*
 * Destroy an ucfg_analyzer
 */
Z_API void z_ucfg_analyzer_destroy(UCFG_Analyzer *a);

/*
 * Add a new instruction into analyzing buffer, *maybe_duplicated* means it is
 * possible that UCFG_Analyzer already analyzes this address
 */
// XXX: note that it is ok if the predecessors of addr is unknown, which means
// it is safe to use this function even the superset disassembly is incomplete.
Z_API void z_ucfg_analyzer_add_inst(UCFG_Analyzer *a, addr_t addr,
                                    const cs_insn *inst, bool maybe_duplicated);

/*
 * Get succerrors without the call-fallthrough edges (return value will never be
 * NULL)
 */
Z_API Buffer *z_ucfg_analyzer_get_direct_successors(UCFG_Analyzer *a,
                                                    addr_t addr);

/*
 * Get predecessor without the call-fallthrough edges (return value will never
 * be NULL)
 */
Z_API Buffer *z_ucfg_analyzer_get_direct_predecessors(UCFG_Analyzer *a,
                                                      addr_t addr);

/*
 * Get *need-write* information for flag registers
 */
Z_API FLGState z_ucfg_analyzer_get_flg_need_write(UCFG_Analyzer *a,
                                                  addr_t addr);

/*
 * Get *can_write* information for general purpose registers
 */
Z_API GPRState z_ucfg_analyzer_get_gpr_can_write(UCFG_Analyzer *a, addr_t addr);

/*
 * Get register state for a given addr
 */
Z_API RegState *z_ucfg_analyzer_get_register_state(UCFG_Analyzer *a,
                                                   addr_t addr);

#endif
