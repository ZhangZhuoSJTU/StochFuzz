#ifndef __INST_ANALYZER_H
#define __INST_ANALYZER_H

#include "buffer.h"
#include "capstone_.h"
#include "config.h"

#include <capstone/capstone.h>
#include <gmodule.h>

/*
 * Light-weight instruction-level analyzer, which aims at analyzing conservative
 * use-def relation on an incomplete CFG.
 */
STRUCT(InstAnalyzer, {
    // basic instruction information
    GHashTable *insts;

    // register state for each instruction
    GHashTable *reg_states;

    // successors and predecessor
    //  note that it is possible to return preds/succs for an invalid address
    GHashTable *preds;
    GHashTable *succs;

    // eflags register analysis
    GHashTable *flg_finished_succs;
    GHashTable *flg_need_write;

    // general register analysis
    GHashTable *gpr_analyzed_succs;
    GHashTable *gpr_can_write;
});

/*
 * Create an inst_analyzer
 */
Z_API InstAnalyzer *z_inst_analyzer_create();

/*
 * Destroy an inst_analzyer
 */
Z_API void z_inst_analyzer_destroy(InstAnalyzer *a);

/*
 * Add a new instruction into analyzing buffer, *maybe_duplicated* means it is
 * possible that InstAnalyzer already analyzes this address
 */
Z_API void z_inst_analyzer_add_inst(InstAnalyzer *a, addr_t addr,
                                    const cs_insn *inst, bool maybe_duplicated);

/*
 * Get succerrors (return value will never be NULL)
 */
Z_API Buffer *z_inst_analyzer_get_successors(InstAnalyzer *a, addr_t addr);

/*
 * Get predecessor (return value will never be NULL)
 */
Z_API Buffer *z_inst_analyzer_get_predecessors(InstAnalyzer *a, addr_t addr);

/*
 * Get *need-write* information for flag registers
 */
Z_API FLGState z_inst_analyzer_get_flg_need_write(InstAnalyzer *a, addr_t addr);

/*
 * Get *can_write* information for general purpose registers
 */
Z_API GPRState z_inst_analyzer_get_gpr_can_write(InstAnalyzer *a, addr_t addr);

/*
 * Get register state for a given addr
 */
Z_API RegState *z_inst_analyzer_get_register_state(InstAnalyzer *a,
                                                   addr_t addr);

#endif
