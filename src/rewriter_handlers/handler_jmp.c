#define REVENT z_capstone_is_jmp
#define RHANDLER __rewriter_jmp_handler

/*
 * Rewriter handler for jmp instruction.
 */
Z_PRIVATE void __rewriter_jmp_handler(Rewriter *r, GHashTable *holes,
                                      cs_insn *inst, addr_t ori_addr,
                                      addr_t ori_next_addr);

Z_PRIVATE void __rewriter_jmp_handler(Rewriter *r, GHashTable *holes,
                                      cs_insn *inst, addr_t ori_addr,
                                      addr_t ori_next_addr) {
    cs_detail *detail = inst->detail;
    cs_x86_op *op = &(detail->x86.operands[0]);

    uint64_t hole_buf = 0;
    ELF *e = z_binary_get_elf(r->binary);
    addr_t text_addr = z_elf_get_shdr_text(e)->sh_addr;
    size_t text_size = z_elf_get_shdr_text(e)->sh_size;

    if (detail->x86.op_count == 1 && op->type == X86_OP_IMM) {
        addr_t shadow_addr = z_binary_get_shadow_code_addr(r->binary);
        addr_t jmp_addr = op->imm;

        // first check jmp_addr is inside .text
        if (!z_disassembler_get_superset_disasm(r->disassembler, jmp_addr)) {
            // directly write
            KS_ASM_JMP(shadow_addr, jmp_addr);
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
            return;
        }

        r->optimized_single_succ += 1;

        addr_t shadow_jmp_addr = (addr_t)g_hash_table_lookup(
            r->rewritten_bbs, GSIZE_TO_POINTER(jmp_addr));

        if (shadow_jmp_addr) {
            KS_ASM_JMP(shadow_addr, shadow_jmp_addr);
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
        } else {
            // jmp ??? (HOLE)
            hole_buf = (uint64_t)X86_INS_JMP;
            shadow_addr =
                z_binary_insert_shadow_code(r->binary, (uint8_t *)(&hole_buf),
                                            __rewriter_get_hole_len(hole_buf));
            g_hash_table_insert(holes, GSIZE_TO_POINTER(shadow_addr),
                                GSIZE_TO_POINTER(jmp_addr));
        }
    } else {
        if (z_elf_get_is_pie(e)) {
            EXITME("ujmp handler for PIE binary is unimplemented");
        }

        // jmp may not jump out of .text (NO! z3 binary has such behaviour)
        z_debug("rewrite ujmp " CS_SHOW_INST(inst));

        // record the original shadow_addr for inst
        addr_t ori_shadow_addr = INVALID_ADDR;

        // store rcx value
        {
            addr_t shadow_addr = ori_shadow_addr =
                z_binary_get_shadow_code_addr(r->binary);
            KS_ASM(shadow_addr, "mov [rsp - 128], rcx;\n");
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
            shadow_addr += ks_size;
        }

        // translate jump instruction into mov instruction
        // XXX: note that if we simply push the target value on the stack,
        // the program may crash when it uses the value near the bootom of
        // the stack (e.g., mov rbx, [rsp - 8]). Hence, we use 'mov' instead
        // of 'push';
        if (strstr(inst->op_str, "rip")) {
            assert(ori_shadow_addr != INVALID_ADDR);

            // step [1]. get new instruction
            KS_ASM(INVALID_ADDR, "mov rcx, %s", inst->op_str);
            cs_inst = NULL;  // avoid double free inst
            CS_DISASM_RAW(ks_encode, ks_size, INVALID_ADDR, 1);
            cs_insn *new_inst = (cs_insn *)cs_inst;
            cs_inst = NULL;  // avoid double free new_inst

            // step [2]. calculate a possible starting address for the new mov
            // instruction, so that we can guarantee correctness:
            // new_shadow_addr + new_inst->size == ori_shadow_addr + inst->size
            addr_t new_shadow_addr =
                ori_shadow_addr + inst->size - new_inst->size;

            // step [3]. translate the instruction, so that:
            cs_insn *translated_inst =
                __rewriter_translate_shadow_inst(r, new_inst, new_shadow_addr);

            // step [4]. rewrite
            z_binary_insert_shadow_code(r->binary, translated_inst->bytes,
                                        translated_inst->size);

            // step [5]. free inst and new_inst
            cs_free(inst, 1);
            cs_free(new_inst, 1);
        } else {
            addr_t shadow_addr = z_binary_get_shadow_code_addr(r->binary);
            KS_ASM(shadow_addr, "mov rcx, %s", inst->op_str);
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
        }

        // do the addrss translation
        {
            addr_t shadow_addr = z_binary_get_shadow_code_addr(r->binary);
            KS_ASM(shadow_addr,
                   /*
                    * store rcx
                    */
                   "  mov [rsp - 112], rcx;"
                   /*
                    * store EFLAGS
                    */
                   "  mov [rsp - 120], rax;\n"
                   "  lahf;\n"
                   "  seto al;\n"
                   /*
                    * for addresses outside .text, directly go through
                    */
                   "  cmp rcx, %#lx;\n" // compare upper bound of .text
                   "  jae fuck;\n"
                   "  sub rcx, %#lx;\n" // sub .text base
                   "  jb fuck;\n"
                   /*
                    * update bitmap and prev_id
                    */
                   "  mov [rsp - 136], rdx;\n"
                   "  mov [rsp - 144], rdi;\n"
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
                   "  mov rdi, [rsp - 144];\n"
                   "  mov rdx, [rsp - 136];\n"
                   /*
                    * lookup target shadow address
                    */
                   "  shl rcx, " STRING(LOOKUP_TABLE_CELL_SIZE_POW2)  " ;\n"
                   "  movsxd rcx, dword ptr [" STRING(LOOKUP_TABLE_ADDR) " + rcx];\n"
                   "  mov [rsp - 112], rcx;\n"
                   /*
                    * go to target
                    */
                   "fuck:\n"
                   "  add al, 127;\n"
                   "  sahf;\n"
                   "  mov rax, [rsp - 120];\n"
                   "  mov rcx, [rsp - 128];\n"
                   "  jmp qword ptr [rsp - 112];\n",
                   text_addr + text_size, text_addr);
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
        }
    }
}
