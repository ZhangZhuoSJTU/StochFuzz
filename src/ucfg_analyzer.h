/*
 * ucfg_analyzer.h
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

#ifndef __UCFG_ANALYZER_H
#define __UCFG_ANALYZER_H

#include "binary.h"
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

    /*
     * successors and predecessor
     * XXX: note that it is possible to return preds/succs for an invalid
     * address
     *
     * all_preds = direct_preds U intra_preds
     * all_succs = direct_succs U intra_succs
     */
    // direct/explict successors and predecessors without call-fallthrough edges
    GHashTable *direct_preds;
    GHashTable *direct_succs;
    // intra-procedure successsors and predecessors
    GHashTable *intra_preds;
    GHashTable *intra_succs;
    // successors and predecessors with call-fallthrough edges
    GHashTable *all_preds;
    GHashTable *all_succs;

    // eflags register analysis
    GHashTable *flg_finished_succs;
    GHashTable *flg_need_write;

    // general register analysis
    GHashTable *gpr_analyzed_succs;
    GHashTable *gpr_can_write;

    // whether an inst can reach a RET inst via intra-procedure edges
    GHashTable *can_ret;

    // whether an inst can reach a security-chk-failed PLT call without any
    // condition and indirect edges
    GHashTable *sec_chk_failed;

    // rewriting optargs
    RewritingOptArgs *opts;

    Binary *binary;
});

/*
 * Create an ucfg_analyzer
 */
Z_API UCFG_Analyzer *z_ucfg_analyzer_create(Binary *binary,
                                            RewritingOptArgs *opts);

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
 * Get intra-procedure successors
 */
Z_API Buffer *z_ucfg_analyzer_get_intra_successors(UCFG_Analyzer *a,
                                                   addr_t addr);

/*
 * Get intra-procedure predecessors
 */
Z_API Buffer *z_ucfg_analyzer_get_intra_predecessors(UCFG_Analyzer *a,
                                                     addr_t addr);

/*
 * Get all successors
 */
Z_API Buffer *z_ucfg_analyzer_get_all_successors(UCFG_Analyzer *a, addr_t addr);

/*
 * Get all predecessors
 */
Z_API Buffer *z_ucfg_analyzer_get_all_predecessors(UCFG_Analyzer *a,
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

/*
 * Get whether an instruction belongs to a security_chk_failed block
 */
Z_API bool z_ucfg_analyzer_is_security_chk_failed(UCFG_Analyzer *a,
                                                  addr_t addr);

#endif
