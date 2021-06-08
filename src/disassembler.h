/*
 * disassembler.h
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

#ifndef __DISASSEMBLER_H
#define __DISASSEMBLER_H

#include "address_dictionary.h"
#include "binary.h"
#include "buffer.h"
#include "config.h"
#include "interval_splay.h"
#include "sys_optarg.h"
#include "ucfg_analyzer.h"

#include <capstone/capstone.h>
#include <gmodule.h>

STRUCT(Disassembler, {
    // Binary which needs disassembly
    Binary *binary;

    // .text info
    addr_t text_addr;
    size_t text_size;
    uint8_t *text_backup;

    // Disassembly
    GHashTable *superset_disasm;
    GHashTable *recursive_disasm;
    GHashTable *linear_disasm;
    PhantomType *prob_disasm;

    // Occluded address
    AddrDictFast(Buffer *, occ_addrs);

    // Pdisasm enable?
    bool enable_pdisasm;

    /*
     * Potential information.
     * These information is collected by linear and recursive disassembly. But
     * due to the inlined data, non-return function, or any other incomplete
     * analysis result, these information may be wrong.
     */
    // Entrypoints of *confidentially* disassemblied instructions
    GHashTable *potential_insts;
    // Entrypoints of *confidentially* disassemblied basic blocks
    GHashTable *potential_blocks;

    // Light-weight instruction-level analyzer;
    UCFG_Analyzer *ucfg_analyzer;

    // rewriting optargs
    RewritingOptArgs *opts;
});

/*
 * Getter and Setter
 */
DECLARE_GETTER(Disassembler, disassembler, Binary *, binary);
DECLARE_GETTER(Disassembler, disassembler, UCFG_Analyzer *, ucfg_analyzer);

/*
 * Create a disassembler
 */
Z_API Disassembler *z_disassembler_create(Binary *b, RewritingOptArgs *opts);

/*
 * Destroy a disassembler
 */
Z_API void z_disassembler_destroy(Disassembler *d);

/*
 * [P-Disasm API]
 * Return the probability of being an instruction entrypoint for the given
 * address.
 *
 * Return value:
 *   P = 1.0:       be very confident that addr is an instruction entrypoint
 *   0.0 < P < 1.0: based on P, greater P means higer confidence
 *   P = 0.0:       be very confident that addr is not an instruction entrypoint
 *   P = -0.0:      we have **very** strong evidence it is not an entrypoint
 */
Z_API double128_t z_disassembler_get_prob_disasm(Disassembler *d, addr_t addr);

Z_API void z_diassembler_update_prob_disasm(Disassembler *d, addr_t addr,
                                            bool is_inst);

/*
 * Probabilistic disassemble the whole binary
 */
Z_API void z_disassembler_prob_disasm(Disassembler *d);

/*
 * Get internal informaiton of probabilistic disassemble (in most case, this API
 * is used for debugging)
 */
Z_API void z_disassembler_get_prob_disasm_internal(
    Disassembler *d, addr_t addr, cs_insn **inst, uint32_t *scc_id,
    double128_t *inst_hint, double128_t *inst_lost, double128_t *data_hint,
    double128_t *D, double128_t *P);

/*
 * Check whether disassembler fully support prob-disasm
 */
Z_API bool z_disassembler_fully_support_prob_disasm(Disassembler *d);

/*
 * Superset disassemble one instruction at given address
 */
Z_API const cs_insn *z_disassembler_update_superset_disasm(Disassembler *d,
                                                           addr_t addr);

/*
 * Show the occludeds addresses of a given address
 */
Z_API Buffer *z_disassembler_get_occluded_addrs(Disassembler *d, addr_t addr);

/*
 * Recursive disassemble from given address
 */
// XXX: note that currently z_disassembler_recursive_disasm can only be called
// by z_rewriter_rewrite.
// TODO: it is a fault of our system design. We need to fix such strong
// coupling.
Z_API GQueue *z_disassembler_recursive_disasm(Disassembler *d, addr_t addr);

/*
 * Linear disassemble the whole binary
 */
Z_API GQueue *z_disassembler_linear_disasm(Disassembler *d);

/*
 * Get linear disasm
 */
Z_API cs_insn *z_disassembler_get_linear_disasm(Disassembler *d, addr_t addr);

/*
 * Get recursive disasm
 */
Z_API cs_insn *z_disassembler_get_recursive_disasm(Disassembler *d,
                                                   addr_t addr);

/*
 * Get superset disasm
 */
Z_API cs_insn *z_disassembler_get_superset_disasm(Disassembler *d, addr_t addr);

/*
 * Check whether address is a potential potential entrypoint
 */
Z_API bool z_disassembler_is_potential_block_entrypoint(Disassembler *d,
                                                        addr_t addr);

/*
 * Check whether address is a potential inst entrypoint
 */
Z_API bool z_disassembler_is_potential_inst_entrypoint(Disassembler *d,
                                                       addr_t addr);

/*
 * Check whether address is within disassemble range
 */
Z_API bool z_disassembler_is_within_disasm_range(Disassembler *d, addr_t addr);

#define __DISASSEMBLER_DEFINE_SUCC_AND_PRED(etype, rtype)               \
    Z_API Buffer *z_disassembler_get_##etype##_##rtype(Disassembler *d, \
                                                       addr_t addr)

__DISASSEMBLER_DEFINE_SUCC_AND_PRED(direct, predecessors);
__DISASSEMBLER_DEFINE_SUCC_AND_PRED(direct, successors);
__DISASSEMBLER_DEFINE_SUCC_AND_PRED(intra, predecessors);
__DISASSEMBLER_DEFINE_SUCC_AND_PRED(intra, successors);
__DISASSEMBLER_DEFINE_SUCC_AND_PRED(all, predecessors);
__DISASSEMBLER_DEFINE_SUCC_AND_PRED(all, successors);

#undef __DISASSEMBLER_DEFINE_SUCC_AND_PRED

#endif
