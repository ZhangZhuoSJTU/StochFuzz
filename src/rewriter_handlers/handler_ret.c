#define REVENT z_capstone_is_ret
#define RHANDLER __rewriter_ret_handler

/*
 * Rewriter handler for ret instruction.
 */
Z_PRIVATE void __rewriter_ret_handler(Rewriter *r, GHashTable *holes,
                                      cs_insn *inst, addr_t ori_addr,
                                      addr_t ori_next_addr);

Z_PRIVATE void __rewriter_ret_handler(Rewriter *r, GHashTable *holes,
                                      cs_insn *inst, addr_t ori_addr,
                                      addr_t ori_next_addr) {
    if (r->opts->safe_ret) {
        z_binary_insert_shadow_code(r->binary, inst->bytes, inst->size);
        return;
    }

    // modern CPU will do nothing more except direct returning about `repz ret`
    // TODO: but we need to consider `ret n`
    addr_t shadow_addr = z_binary_get_shadow_code_addr(r->binary);
    ELF *e = z_binary_get_elf(r->binary);
    addr_t text_addr = z_elf_get_shdr_text(e)->sh_addr;
    size_t text_size = z_elf_get_shdr_text(e)->sh_size;

    if (z_elf_get_is_pie(e)) {
        EXITME("ret handler for PIE binary is unimplemented");
    } else {
        KS_ASM(shadow_addr,
               "  mov [rsp - 128], rcx;\n"
               // "  mov [rsp - 120], rax;\n"
               // "  lahf;\n"
               // "  seto al;\n"
               "  mov rcx, [rsp];\n"
               "  cmp rcx, %#lx;\n"
               "  jae fuck;\n"
               "  sub rcx, %#lx;\n"  // sub .text base
               "  jb fuck;\n"
               "  shl rcx, " STRING(LOOKUP_TABLE_CELL_SIZE_POW2) ";\n"
               "  movsxd rcx, dword ptr [" STRING(LOOKUP_TABLE_ADDR) " + rcx];\n"  // lookup table
               "  mov [rsp], rcx;\n"
               "fuck:\n"
               // "  add al, 127;\n"
               // "  sahf;\n"
               // "  mov rax, [rsp - 120];\n"
               "  mov rcx, [rsp - 128];\n"
               "  ret;\n",
               text_addr + text_size, text_addr);
    }
    z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
}
