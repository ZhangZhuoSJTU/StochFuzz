#define REVENT z_capstone_is_call
#define RHANDLER __rewriter_call_handler

/*
 * Rewriter handler for call instruction for non-pie programs.
 */
Z_PRIVATE void __rewriter_call_handler_for_non_pie(Rewriter *r,
                                                   GHashTable *holes,
                                                   cs_insn *inst,
                                                   addr_t ori_addr,
                                                   addr_t ori_next_addr);

/*
 * Rewriter handler for call instruction for PIE programs.
 */
Z_PRIVATE void __rewriter_call_handler_for_pie(Rewriter *r, GHashTable *holes,
                                               cs_insn *inst, addr_t ori_addr,
                                               addr_t ori_next_addr);

/*
 * Rewriter handler for call instruction.
 */
Z_PRIVATE void __rewriter_call_handler(Rewriter *r, GHashTable *holes,
                                       cs_insn *inst, addr_t ori_addr,
                                       addr_t ori_next_addr);

Z_PRIVATE void __rewriter_call_handler(Rewriter *r, GHashTable *holes,
                                       cs_insn *inst, addr_t ori_addr,
                                       addr_t ori_next_addr) {
    if (inst->id == X86_INS_LCALL) {
        // XXX: I am not so sure, but it seems lcall is no longer used in amd64
        z_warn("false instruction detected " CS_SHOW_INST(inst));
        return;
    }

    ELF *e = z_binary_get_elf(r->binary);
    if (z_elf_get_is_pie(e)) {
        __rewriter_call_handler_for_pie(r, holes, inst, ori_addr,
                                        ori_next_addr);
    } else {
        __rewriter_call_handler_for_non_pie(r, holes, inst, ori_addr,
                                            ori_next_addr);
    }
}

Z_PRIVATE void __rewriter_call_handler_for_pie(Rewriter *r, GHashTable *holes,
                                               cs_insn *inst, addr_t ori_addr,
                                               addr_t ori_next_addr) {
    EXITME("call handler for PIE programs is unimplemented");
}

Z_PRIVATE void __rewriter_call_handler_for_non_pie(Rewriter *r,
                                                   GHashTable *holes,
                                                   cs_insn *inst,
                                                   addr_t ori_addr,
                                                   addr_t ori_next_addr) {
    assert(inst->id == X86_INS_CALL);

    cs_detail *detail = inst->detail;
    cs_x86_op *op = &(detail->x86.operands[0]);

    uint64_t hole_buf = 0;
    addr_t shadow_addr = z_binary_get_shadow_code_addr(r->binary);
    ELF *e = z_binary_get_elf(r->binary);

    if (detail->x86.op_count == 1 && op->type == X86_OP_IMM) {
        addr_t callee_addr = op->imm;
        // direct call

        /*
         * step [1]. first check callee_addr is inside .text
         */
        if (!z_disassembler_get_superset_disasm(r->disassembler, callee_addr)) {
#ifdef NGENERIC_PIC
            // directly write
            KS_ASM_CALL(shadow_addr, callee_addr);
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
#else
            KS_ASM(shadow_addr,
                   "push %#lx;\n"
                   "jmp %#lx;\n",
                   ori_next_addr, callee_addr);
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);

            // update retaddr meta-info
            if (g_hash_table_lookup(r->returned_callees,
                                    GSIZE_TO_POINTER(callee_addr))) {
                // this callee is known to return in future
                KS_ASM_JMP(ori_next_addr,
                           z_binary_get_shadow_code_addr(r->binary));
                z_elf_write(e, ori_next_addr, ks_size, ks_encode);
                g_hash_table_insert(r->unlogged_retaddr_crashpoints,
                                    GSIZE_TO_POINTER(ori_next_addr),
                                    GSIZE_TO_POINTER(true));
            } else if (!g_hash_table_lookup(r->retaddr_crashpoints,
                                            GSIZE_TO_POINTER(ori_next_addr))) {
                // we do not known whether this callee will return. Hence, it is
                // a potential CP_RETADDR. Additionaly, it is the first time
                // that we find this retaddr.
                g_hash_table_insert(r->retaddr_crashpoints,
                                    GSIZE_TO_POINTER(ori_next_addr),
                                    GSIZE_TO_POINTER(callee_addr));
                Buffer *buf = (Buffer *)g_hash_table_lookup(
                    r->callee2retaddrs, GSIZE_TO_POINTER(callee_addr));
                if (!buf) {
                    buf = z_buffer_create(NULL, 0);
                    g_hash_table_insert(r->callee2retaddrs,
                                        GSIZE_TO_POINTER(callee_addr),
                                        (gpointer)buf);
                }
                z_buffer_append_raw(buf, (uint8_t *)&ori_next_addr,
                                    sizeof(ori_next_addr));
            }
#endif
            return;
        }

        /*
         * step [2]. get shadow callee
         */
        addr_t shadow_callee_addr = (addr_t)g_hash_table_lookup(
            r->rewritten_bbs, GSIZE_TO_POINTER(callee_addr));

        /*
         * step [3]. rewrite and insrumentation
         */
        if (shadow_callee_addr) {
#ifdef NGENERIC_PIC
            KS_ASM(shadow_addr,
                   "push END;\n"
                   "jmp %#lx;\n"
                   "END:\n",
                   shadow_callee_addr);
#else
            KS_ASM(shadow_addr,
                   "push %#lx;\n"
                   "jmp %#lx;\n",
                   ori_next_addr, shadow_callee_addr);
#endif
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
        } else {
            // rewrite return address
#ifdef NGENERIC_PIC
            KS_ASM(shadow_addr,
                   "push END + %lu;\n"
                   "END:\n",
                   __rewriter_get_hole_len(X86_INS_JMP));
#else
            KS_ASM(shadow_addr, "push %#lx;\n", ori_next_addr);
#endif

            shadow_addr =
                z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
            shadow_addr += ks_size;

            // jmp ??? (HOLE)
            hole_buf = (uint64_t)X86_INS_JMP;
            shadow_addr =
                z_binary_insert_shadow_code(r->binary, (uint8_t *)(&hole_buf),
                                            __rewriter_get_hole_len(hole_buf));
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
                    r->binary, __rewriter_gen_nop(padding_size), padding_size);
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
        // XXX: call may not care about eflags
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
               "  jae fuck;\n"
               "  sub rcx, %#lx;\n" // sub .text base and compare
               "  jb fuck;\n"
               /*
                * update bitmap and prev_id
                */
               "  mov [rsp - 152], rdx;\n"
               "  mov [rsp - 160], rdi;\n"
               "  xor rdx, rdx;\n" // fuck keystone (issue #295)
               "  mov rdi, qword ptr [" STRING(AFL_PREV_ID_PTR) " + rdx];\n"
               "  mov rdx, rcx;\n"
               "  shr rdx, " STRING(AFL_MAP_SIZE_POW2) ";\n"
               "  xor rdx, rcx;\n"
               "  and rdx, " STRING(AFL_MAP_SIZE_MASK) ";\n"
               "  xor rdi, rdx;\n"
               "  inc BYTE PTR [" STRING(AFL_MAP_ADDR) " + rdi];\n"
               "  xor rdi, rdi;\n" // fuck keystone (issue #295)
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
               "fuck:\n"
               // "  add al, 127;\n"
               // "  sahf;\n"
               // "  mov rax, [rsp - 120 - 8];\n"
               "  mov rcx, [rsp - 128 - 8];\n"
#ifdef NGENERIC_PIC
               "  call qword ptr [rsp - 144];\n",
               text_addr + text_size, text_addr
#else
               "  push %#lx;\n"
               "  jmp qword ptr [rsp - 144 + 8];\n",
               text_addr + text_size, text_addr, ori_next_addr
#endif
               );
        z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
    }
}
