#define REVENT z_capstone_is_loop
#define RHANDLER __rewriter_loop_handler

/*
 * Rewriter handler for loop instruction.
 */
Z_PRIVATE void __rewriter_loop_handler(Rewriter *r, GHashTable *holes,
                                       cs_insn *inst, addr_t ori_addr,
                                       addr_t ori_next_addr);

Z_PRIVATE void __rewriter_loop_handler(Rewriter *r, GHashTable *holes,
                                       cs_insn *inst, addr_t ori_addr,
                                       addr_t ori_next_addr) {
    cs_detail *detail = inst->detail;
    cs_x86_op *op = &(detail->x86.operands[0]);

    uint64_t hole_buf = 0;
    addr_t loop_addr = op->imm;
    addr_t shadow_addr = z_binary_get_shadow_code_addr(r->binary);

    // no conditional indirect jump
    assert(detail->x86.op_count == 1 && op->type == X86_OP_IMM);

    // get hand-written asm
    KS_ASM(shadow_addr,
           "    mov [rsp - 128], rax;\n"  // store context
           "    lahf;\n"
           "    seto al;\n"
           "    dec rcx;\n"
           "    jz out1;\n"
           "    add al, 127;\n"
           "    sahf;\n"
           "    mov rax, [rsp - 128];\n"
           "jmp_target:\n"
           "    jz 0x0;\n"
           "    jmp out2;\n"
           "out1:\n"
           "    add al, 127;\n"
           "    sahf;\n"
           "    mov rax, [rsp - 128];\n"
           "out2:\n");
    z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);

    ELF *e = z_binary_get_elf(r->binary);
    if (inst->id == X86_INS_LOOP) {
        // jmp ???
        hole_buf = (uint64_t)X86_INS_JMP;
        z_elf_write(e, shadow_addr + 0x16, __rewriter_get_hole_len(hole_buf),
                    (uint8_t *)(&hole_buf));
        g_hash_table_insert(holes, GSIZE_TO_POINTER(shadow_addr + 0x16),
                            GSIZE_TO_POINTER(loop_addr));
    } else if (inst->id == X86_INS_LOOPE) {
        // je ???
        hole_buf = (uint64_t)X86_INS_JE;
        z_elf_write(e, shadow_addr + 0x16, __rewriter_get_hole_len(hole_buf),
                    (uint8_t *)(&hole_buf));
        g_hash_table_insert(holes, GSIZE_TO_POINTER(shadow_addr + 0x16),
                            GSIZE_TO_POINTER(loop_addr));
    } else if (inst->id == X86_INS_LOOPNE) {
        // jne ???
        hole_buf = (uint64_t)X86_INS_JNE;
        z_elf_write(e, shadow_addr + 0x16, __rewriter_get_hole_len(hole_buf),
                    (uint8_t *)(&hole_buf));
        g_hash_table_insert(holes, GSIZE_TO_POINTER(shadow_addr + 0x16),
                            GSIZE_TO_POINTER(loop_addr));
    }
}
