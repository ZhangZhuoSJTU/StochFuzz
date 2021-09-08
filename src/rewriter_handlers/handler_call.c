/*
 * handler_call.c
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

#define REVENT z_capstone_is_call
#define RHANDLER __rewriter_call_handler

#define KS_ASM_PRESERVER_RETADDR(is_pie, shadow_addr, ori_next_addr) \
    do {                                                             \
        if ((is_pie)) {                                              \
            KS_ASM((shadow_addr),                                    \
                   "  call next;\n"                                  \
                   "next:\n"                                         \
                   "  sub [rsp], %#lx;\n",                           \
                   (shadow_addr) + 5 - (ori_next_addr));             \
        } else {                                                     \
            KS_ASM((shadow_addr), "push %#lx", (ori_next_addr));     \
        }                                                            \
    } while (0)

/*
 * Rewriter handler for call instruction.
 */
Z_PRIVATE void __rewriter_call_handler(Rewriter *r, GHashTable *holes,
                                       cs_insn *inst, addr_t ori_addr,
                                       addr_t ori_next_addr);

/*
 * Check whether it is a library call
 */
Z_PRIVATE const LFuncInfo *__rewriter_is_library_call(ELF *e, cs_insn *inst);

Z_PRIVATE const LFuncInfo *__rewriter_is_library_call(ELF *e, cs_insn *inst) {
    const LFuncInfo *rv = NULL;
    addr_t got_addr = INVALID_ADDR;

    cs_detail *detail = inst->detail;
    if (detail->x86.op_count != 1) {
        return NULL;
    }

    cs_x86_op *op = &(detail->x86.operands[0]);

    if (op->type == X86_OP_IMM) {
        // check call to PLT
        rv = z_elf_get_plt_info(e, op->imm);
    } else if (z_capstone_is_pc_related_ucall(inst, &got_addr) ||
               (!z_elf_get_is_pie(e) &&
                z_capstone_is_const_mem_ucall(inst, &got_addr))) {
        // check call to GOT
        rv = z_elf_get_got_info(e, got_addr);
    }

    if (!rv || rv->cfg_info == LCFG_OBJ || rv->ra_info == LRA_OBJ) {
        return NULL;
    } else {
        return rv;
    }
}

Z_PRIVATE void __rewriter_call_handler(Rewriter *r, GHashTable *holes,
                                       cs_insn *inst, addr_t ori_addr,
                                       addr_t ori_next_addr) {
    if (inst->id == X86_INS_LCALL) {
        // XXX: I am not so sure, but it seems lcall is no longer used in amd64
        z_warn("false instruction detected " CS_SHOW_INST(inst));
        return;
    }

    cs_detail *detail = inst->detail;
    cs_x86_op *op = &(detail->x86.operands[0]);

    addr_t shadow_addr = z_binary_get_shadow_code_addr(r->binary);

    ELF *e = z_binary_get_elf(r->binary);
    bool is_pie = z_elf_get_is_pie(e);

    // first let's correct the inst->address
    inst->address = shadow_addr;

    const LFuncInfo *lf_info = __rewriter_is_library_call(e, inst);

    /*
     * first handle library calls
     */
    if (lf_info) {
        assert(detail->x86.op_count == 1);
        if (op->type == X86_OP_IMM) {
            // call to PLT
            z_trace("find plt call %s @ %#lx", lf_info->name, ori_addr);

            addr_t callee_addr = op->imm;

            if (r->opts->safe_ret) {
                // direct write down the instruction
                KS_ASM_CALL(shadow_addr, callee_addr);
                z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
                z_binary_new_retaddr_entity(r->binary, shadow_addr + ks_size,
                                            ori_next_addr);
            } else if (lf_info->ra_info == LRA_UNUSED) {
                // direct write down the instruction
                KS_ASM_CALL(shadow_addr, callee_addr);
                z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
            } else {
                KS_ASM_PRESERVER_RETADDR(is_pie, shadow_addr, ori_next_addr);
                z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
                shadow_addr += ks_size;

                KS_ASM_JMP(shadow_addr, callee_addr);
                z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);

                // update retaddr information
                if (lf_info->cfg_info != LCFG_TERM &&
                    !g_hash_table_lookup(r->potential_retaddrs,
                                         GSIZE_TO_POINTER(ori_next_addr))) {
                    // we do not known whether this callee will return. Hence,
                    // it is a potential CP_RETADDR. Additionaly, it is the
                    // first time that we find this retaddr.
                    g_hash_table_insert(r->potential_retaddrs,
                                        GSIZE_TO_POINTER(ori_next_addr),
                                        GSIZE_TO_POINTER(callee_addr));
                    Buffer *buf = (Buffer *)g_hash_table_lookup(
                        r->unpatched_retaddrs, GSIZE_TO_POINTER(callee_addr));
                    if (!buf) {
                        buf = z_buffer_create(NULL, 0);
                        g_hash_table_insert(r->unpatched_retaddrs,
                                            GSIZE_TO_POINTER(callee_addr),
                                            (gpointer)buf);
                    }
                    z_buffer_append_raw(buf, (uint8_t *)&ori_next_addr,
                                        sizeof(ori_next_addr));
                }
            }

            return;
        }

        if (op->type == X86_OP_MEM) {
            // call to GOT
            z_trace("find got call %s @ %#lx", lf_info->name, ori_addr);

            if (r->opts->safe_ret) {
                // direct write down the instruction
                z_binary_insert_shadow_code(r->binary, inst->bytes, inst->size);
                z_binary_new_retaddr_entity(r->binary, shadow_addr + inst->size,
                                            ori_next_addr);
            } else if (lf_info->ra_info == LRA_UNUSED) {
                // direct write down the instruction
                z_binary_insert_shadow_code(r->binary, inst->bytes, inst->size);
            } else {
                // we first push the retaddr
                KS_ASM_PRESERVER_RETADDR(is_pie, shadow_addr, ori_next_addr);
                z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
                shadow_addr += ks_size;

                addr_t got_addr = INVALID_ADDR;
                if (z_capstone_is_pc_related_ucall(inst, &got_addr)) {
                    // jmp qword ptr [rip+xxx]
                    if (inst->size != 6) {
                        EXITME("invalid pc-related ucall " CS_SHOW_INST(inst));
                    }

                    int32_t off = got_addr - (shadow_addr + inst->size);
                    KS_ASM(shadow_addr, "jmp qword ptr [rip + %+d]", off);
                    if (ks_size != 6) {
                        EXITME("invalid pc-related ucall");
                    }

                    z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
                } else {
                    // jmp qword ptr [xxx]
                    KS_ASM(shadow_addr, "jmp %s", inst->op_str);
                    z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
                }

                // XXX: note that we do not update retaddr information here to
                // avoid some case where the GOT gets changed during execution
            }

            return;
        }

        EXITME("unreachable code");
    }

    if (detail->x86.op_count == 1 && op->type == X86_OP_IMM) {
        addr_t callee_addr = op->imm;
        // direct call

        /*
         * step [1]. first check callee_addr is inside .text
         */
        if (!z_disassembler_get_superset_disasm(r->disassembler, callee_addr)) {
            if (r->opts->safe_ret) {
                // directly write
                KS_ASM_CALL(shadow_addr, callee_addr);
                z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
                z_binary_new_retaddr_entity(r->binary, shadow_addr + ks_size,
                                            ori_next_addr);
            } else {
                KS_ASM_PRESERVER_RETADDR(is_pie, shadow_addr, ori_next_addr);
                z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
                shadow_addr += ks_size;

                KS_ASM_JMP(shadow_addr, callee_addr);
                z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
            }
            return;
        }

        /*
         * step [2]. get shadow callee and prepare hole_buf
         */
        uint64_t hole_buf = 0;
#ifndef NSINGLE_SUCC_OPT
        addr_t shadow_callee_addr;
        if (r->opts->disable_opt) {
            shadow_callee_addr = (addr_t)g_hash_table_lookup(
                r->rewritten_bbs, GSIZE_TO_POINTER(callee_addr));
            hole_buf = (uint64_t)X86_INS_JMP;
        } else {
            shadow_callee_addr = (addr_t)g_hash_table_lookup(
                r->shadow_code, GSIZE_TO_POINTER(callee_addr));
            hole_buf = (uint64_t)(-(int64_t)X86_INS_JMP);
            assert((int64_t)hole_buf < 0);

            r->optimized_single_succ += 1;
        }
#else
        addr_t shadow_callee_addr = (addr_t)g_hash_table_lookup(
            r->rewritten_bbs, GSIZE_TO_POINTER(callee_addr));
#endif

        /*
         * step [3]. rewrite and insrumentation
         */
        if (shadow_callee_addr) {
            if (r->opts->safe_ret) {
                KS_ASM_CALL(shadow_addr, shadow_callee_addr);
                z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
                z_binary_new_retaddr_entity(r->binary, shadow_addr + ks_size,
                                            ori_next_addr);
            } else {
                KS_ASM_PRESERVER_RETADDR(is_pie, shadow_addr, ori_next_addr);
                z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
                shadow_addr += ks_size;

                KS_ASM_JMP(shadow_addr, shadow_callee_addr);
                z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
            }
        } else {
            // rewrite return address
            if (r->opts->safe_ret) {
                // insert hole
                hole_buf = X86_INS_CALL;
                z_binary_insert_shadow_code(r->binary, (uint8_t *)(&hole_buf),
                                            __rewriter_get_hole_len(hole_buf));

                z_binary_new_retaddr_entity(
                    r->binary, shadow_addr + __rewriter_get_hole_len(hole_buf),
                    ori_next_addr);
            } else {
                KS_ASM_PRESERVER_RETADDR(is_pie, shadow_addr, ori_next_addr);
                z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
                shadow_addr += ks_size;

                // insert hole
                hole_buf = X86_INS_JMP;
                z_binary_insert_shadow_code(r->binary, (uint8_t *)(&hole_buf),
                                            __rewriter_get_hole_len(hole_buf));
            }

            g_hash_table_insert(holes, GSIZE_TO_POINTER(shadow_addr),
                                GSIZE_TO_POINTER(callee_addr));
        }
    } else {
        // indirect call
        addr_t text_addr = z_elf_get_shdr_text(e)->sh_addr;
        size_t text_size = z_elf_get_shdr_text(e)->sh_size;

        /*
         * step [1]. store target value
         */
        if (strstr(inst->op_str, "rip")) {
            // Handle PC-relative jmp: a good observation is that any
            // rip-relative jmp/call are equal to or longer than
            //          `push ??? PTR [rip + ???]`
            // Note that we need to keep `next instruction` at the same address

            // step [1]. get ks_size
            KS_ASM(INVALID_ADDR, "push %s", inst->op_str);
            assert(inst->size >= ks_size);

            // step [2]. padding
            if (inst->size > ks_size) {
                size_t padding_size = inst->size - ks_size;
                z_binary_insert_shadow_code(
                    r->binary, z_x64_gen_nop(padding_size), padding_size);
            }

            // step [3]. rewriting
            KS_ASM(shadow_addr + inst->size - ks_size, "push %s", inst->op_str);
            assert(z_binary_get_shadow_code_addr(r->binary) + ks_size ==
                   shadow_addr + inst->size);
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);

            shadow_addr += inst->size;
        } else {
            KS_ASM(shadow_addr, "push %s", inst->op_str);
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
            shadow_addr += ks_size;
        }

        /*
         * step [2]. rewrite ucall using hand-written assembly code
         */
        z_debug("rewrite ucall " CS_SHOW_INST(inst));
        // XXX: it is ok to directly use LOOKUP_TABLE_ADDR since the underlying
        // binary is not compiled with PIE.
        // XXX: call may not care about eflags
        // XXX: PIE fix
        KS_ASM(shadow_addr,
               "  mov [rsp - 128], rcx;\n"
               // "  mov [rsp - 120], rax;\n"
               // "  lahf;\n"
               // "  seto al;\n"
               "  pop rcx;\n"
               "  mov [rsp - 144], rcx;\n"
               /*
                * for addresses outside .text, directly go through
                */
               "  cmp rcx, %#lx;\n" // compare upper bound of .text
               "  jae hug;\n"
               "  sub rcx, %#lx;\n" // sub .text base and compare
               "  jb hug;\n"
               /*
                * update bitmap and prev_id
                */
               "  mov [rsp - 152], rdx;\n"
               "  mov [rsp - 160], rdi;\n"
               "  xor rdx, rdx;\n" // hug keystone (issue #295)
               "  mov rdi, qword ptr [" STRING(AFL_PREV_ID_PTR) " + rdx];\n"
               "  mov rdx, rcx;\n"
               "  shr rdx, " STRING(AFL_MAP_SIZE_POW2) ";\n"
               "  xor rdx, rcx;\n"
               "  and rdx, " STRING(AFL_MAP_SIZE_MASK) ";\n"
               "  xor rdi, rdx;\n"
               "  inc BYTE PTR [" STRING(AFL_MAP_ADDR) " + rdi];\n"
               "  xor rdi, rdi;\n" // hug keystone (issue #295)
               "  shr rdx, 1;\n"
               "  mov qword ptr [" STRING(AFL_PREV_ID_PTR) " + rdi], rdx;\n"
               "  mov rdi, [rsp - 160];\n"
               "  mov rdx, [rsp - 152];\n"
               /*
                * lookup target shadow address
                */
               "  shl rcx, " STRING(LOOKUP_TABLE_CELL_SIZE_POW2) ";\n"
               "  movsxd rcx, dword ptr [" STRING(LOOKUP_TABLE_ADDR) " + rcx];\n"
               "  mov [rsp - 144], rcx;\n"
               /*
                * go to target
                */
               "hug:\n"
               // "  add al, 127;\n"
               // "  sahf;\n"
               // "  mov rax, [rsp - 120 - 8];\n"
               "  mov rcx, [rsp - 128 - 8];\n",
               text_addr + text_size, text_addr);
        z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);

        // XXX: the below assembly is following the previous one
        shadow_addr += ks_size;
        if (r->opts->safe_ret) {
            KS_ASM(shadow_addr, "call qword ptr [rsp - 144]");
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
            z_binary_new_retaddr_entity(r->binary, shadow_addr + ks_size,
                                        ori_next_addr);
        } else {
            KS_ASM_PRESERVER_RETADDR(is_pie, shadow_addr, ori_next_addr);
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
            shadow_addr += ks_size;

            KS_ASM(shadow_addr, "jmp qword ptr [rsp - 144 + 8];\n");
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
        }
    }
}
