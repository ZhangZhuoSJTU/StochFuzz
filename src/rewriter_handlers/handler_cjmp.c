/*
 * handler_cjmp.c
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

#define REVENT z_capstone_is_cjmp
#define RHANDLER __rewriter_cjmp_handler

/*
 * Rewriter handler for cjmp instruction.
 */
Z_PRIVATE void __rewriter_cjmp_handler(Rewriter *r, GHashTable *holes,
                                       cs_insn *inst, addr_t ori_addr,
                                       addr_t ori_next_addr);

/*
 * Rewriter handler for JRCXZ, JECXZ and JCXZ instruction.
 */
Z_PRIVATE void __rewriter_cjmp_handler_for_rcx(Rewriter *r, GHashTable *holes,
                                               cs_insn *inst, addr_t ori_addr,
                                               addr_t ori_next_addr);

Z_PRIVATE void __rewriter_cjmp_handler_for_rcx(Rewriter *r, GHashTable *holes,
                                               cs_insn *inst, addr_t ori_addr,
                                               addr_t ori_next_addr) {
    if (inst->id == X86_INS_JCXZ) {
        EXITME("`jcxz' is not supported in 64-bit mode");
    }

    cs_detail *detail = inst->detail;
    cs_x86_op *op = &(detail->x86.operands[0]);
    assert(detail->x86.op_count == 1 && op->type == X86_OP_IMM);

    // get origianl branch address
    addr_t true_branch_addr = op->imm;
    addr_t false_branch_addr = ori_next_addr;

    if (!z_disassembler_get_superset_disasm(r->disassembler,
                                            true_branch_addr) ||
        !z_disassembler_get_superset_disasm(r->disassembler,
                                            false_branch_addr)) {
        // j*cxz can only do short jump, if this happend, it means we are
        // writing a false instruction
        z_warn("false instruction detected " CS_SHOW_INST(inst));
        return;
    }

    /*
     * We will rewrite the instruction in following format:
     *
     *      j*cxz hug:
     *      jmp shadow_false_branch;
     *  hug:
     *      jmp shadow_true_brach;
     *
     */

    switch (inst->id) {
        case X86_INS_JECXZ:
            // jecxz $+5
            z_binary_insert_shadow_code(r->binary,
                                        (const uint8_t *)"\x67\xe3\x05", 3);
            break;
        case X86_INS_JRCXZ:
            // jrcxz $+5
            z_binary_insert_shadow_code(r->binary, (const uint8_t *)"\xe3\x05",
                                        2);
            break;
        default:
            EXITME("invalid opcode " CS_SHOW_INST(inst));
    }

#define __GENERATE_SHADOW_JMP(tar_addr)                                  \
    do {                                                                 \
        addr_t shadow_addr = z_binary_get_shadow_code_addr(r->binary);   \
        addr_t shadow_tar_addr = (addr_t)g_hash_table_lookup(            \
            r->rewritten_bbs, GSIZE_TO_POINTER(tar_addr));               \
        if (shadow_tar_addr) {                                           \
            KS_ASM(shadow_addr, "jmp %#lx", shadow_tar_addr);            \
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);  \
            if (ks_size < 5) {                                           \
                z_binary_insert_shadow_code(                             \
                    r->binary, z_x64_gen_nop(5 - ks_size), 5 - ks_size); \
            }                                                            \
        } else {                                                         \
            uint64_t hole_buf = X86_INS_JMP;                             \
            shadow_addr = z_binary_insert_shadow_code(                   \
                r->binary, (uint8_t *)(&hole_buf),                       \
                __rewriter_get_hole_len(hole_buf));                      \
            g_hash_table_insert(holes, GSIZE_TO_POINTER(shadow_addr),    \
                                GSIZE_TO_POINTER(tar_addr));             \
        }                                                                \
    } while (0)

    __GENERATE_SHADOW_JMP(false_branch_addr);
    __GENERATE_SHADOW_JMP(true_branch_addr);
#undef __GENERATE_SHADOW_JMP
}

Z_PRIVATE bool __rewriter_cjmp_is_security_check(Rewriter *r, addr_t addr);

// check whether this cjmp is directly related to security check
Z_PRIVATE bool __rewriter_cjmp_is_security_check(Rewriter *r, addr_t addr) {
    // XXX: this function must be sound but does not need to be complete, since
    // we cannot skip any non-security-check cjmp but can afford the additional
    // efforts of flipping security check cjmp.

    Disassembler *d = r->disassembler;
    UCFG_Analyzer *a = z_disassembler_get_ucfg_analyzer(d);

    Buffer *succ_addrs_buf = z_disassembler_get_intra_successors(d, addr);
    size_t succ_n = z_buffer_get_size(succ_addrs_buf) / sizeof(addr_t);
    addr_t *succ_addrs = (addr_t *)z_buffer_get_raw_buf(succ_addrs_buf);

    bool is_security_check = false;
    for (int i = 0; i < succ_n; i++) {
        if (z_ucfg_analyzer_is_security_chk_failed(a, succ_addrs[i])) {
            is_security_check = true;
            break;
        }
    }

    if (is_security_check) {
        z_trace("find a security check: %#lx", addr);
        // update instrumentation_free_bbs
        for (int i = 0; i < succ_n; i++) {
            g_hash_table_add(r->instrumentation_free_bbs,
                             GSIZE_TO_POINTER(succ_addrs[i]));
        }
    }

    return is_security_check;
}

Z_PRIVATE void __rewriter_cjmp_handler(Rewriter *r, GHashTable *holes,
                                       cs_insn *inst, addr_t ori_addr,
                                       addr_t ori_next_addr) {
    __rewriter_cjmp_is_security_check(r, ori_addr);

    if (inst->id == X86_INS_JCXZ || inst->id == X86_INS_JECXZ ||
        inst->id == X86_INS_JRCXZ) {
        __rewriter_cjmp_handler_for_rcx(r, holes, inst, ori_addr,
                                        ori_next_addr);
        return;
    }

    cs_detail *detail = inst->detail;
    cs_x86_op *op = &(detail->x86.operands[0]);

    uint64_t hole_buf = 0;
    addr_t shadow_addr = z_binary_get_shadow_code_addr(r->binary);

    // no conditional indirect jump
    assert(detail->x86.op_count == 1 && op->type == X86_OP_IMM);
    addr_t cjmp_addr = op->imm;

    // first check cjmp_addr is inside .text
    if (!z_disassembler_get_superset_disasm(r->disassembler, cjmp_addr)) {
        // directly write
        KS_ASM(shadow_addr, "%s %#lx", cs_insn_name(cs, inst->id), cjmp_addr);
        z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
        return;
    }

    addr_t shadow_cjmp_addr = (addr_t)g_hash_table_lookup(
        r->rewritten_bbs, GSIZE_TO_POINTER(cjmp_addr));

    if (shadow_cjmp_addr) {
        KS_ASM(shadow_addr, "%s %#lx", cs_insn_name(cs, inst->id),
               shadow_cjmp_addr);
        z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
    } else {
        // cjmp ??? (HOLE)
        hole_buf = (uint64_t)inst->id;
        shadow_addr =
            z_binary_insert_shadow_code(r->binary, (uint8_t *)(&hole_buf),
                                        __rewriter_get_hole_len(hole_buf));
        g_hash_table_insert(holes, GSIZE_TO_POINTER(shadow_addr),
                            GSIZE_TO_POINTER(cjmp_addr));
    }
}
