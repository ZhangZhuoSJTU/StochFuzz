/*
 * rewriter_handler.c: pre-defined handler for rewriting different instruction.
 */

#include "fork_server.h"
#include "utils.h"

DEFINE_GETTER(RHandler, rhandler, REvent, event);
DEFINE_GETTER(RHandler, rhandler, RHandlerFcn, fcn);

Z_API RHandler *z_rhandler_create(REvent event, RHandlerFcn fcn) {
    STRUCT_ALLOC(RHandler, handler);
    handler->event = event;
    handler->fcn = fcn;

    return handler;
}

Z_API void z_rhandler_destroy(RHandler *handler) { z_free(handler); }

//////////////////////////////////////////////
// Pre-defined handlers (for cf-instruction)
//////////////////////////////////////////////

/*
 * Get control-flow hole size for different instruction types.
 */
static inline size_t __rewriter_get_hole_len(uint64_t id);

/*
 * Rewriter handler for call instruction for non-cpp programs.
 */
static void __rewriter_call_handler_for_non_cpp(Rewriter *r, GHashTable *holes,
                                                cs_insn *inst, addr_t ori_addr,
                                                addr_t ori_next_addr);

/*
 * Rewriter handler for call instruction for cpp programs.
 */
static void __rewriter_call_handler_for_cpp(Rewriter *r, GHashTable *holes,
                                            cs_insn *inst, addr_t ori_addr,
                                            addr_t ori_next_addr);

/*
 * Rewriter handler for call instruction.
 */
static void __rewriter_call_handler(Rewriter *r, GHashTable *holes,
                                    cs_insn *inst, addr_t ori_addr,
                                    addr_t ori_next_addr);

/*
 * Rewriter handler for jmp instruction.
 */
static void __rewriter_jmp_handler(Rewriter *r, GHashTable *holes,
                                   cs_insn *inst, addr_t ori_addr,
                                   addr_t ori_next_addr);

/*
 * Rewriter handler for cjmp instruction.
 */
static void __rewriter_cjmp_handler(Rewriter *r, GHashTable *holes,
                                    cs_insn *inst, addr_t ori_addr,
                                    addr_t ori_next_addr);

/*
 * Rewriter handler for loop instruction.
 */
static void __rewriter_loop_handler(Rewriter *r, GHashTable *holes,
                                    cs_insn *inst, addr_t ori_addr,
                                    addr_t ori_next_addr);

/*
 * Rewriter handler for ret instruction.
 */
static void __rewriter_ret_handler(Rewriter *r, GHashTable *holes,
                                   cs_insn *inst, addr_t ori_addr,
                                   addr_t ori_next_addr);

static inline size_t __rewriter_get_hole_len(uint64_t id) {
    switch (id) {
        case X86_INS_CALL:
        case X86_INS_JMP:
            return 5;
        case X86_INS_JAE:
        case X86_INS_JA:
        case X86_INS_JBE:
        case X86_INS_JB:
        case X86_INS_JE:
        case X86_INS_JGE:
        case X86_INS_JG:
        case X86_INS_JLE:
        case X86_INS_JL:
        case X86_INS_JNE:
        case X86_INS_JNO:
        case X86_INS_JNP:
        case X86_INS_JNS:
        case X86_INS_JO:
        case X86_INS_JP:
        case X86_INS_JS:
            return 6;
        case X86_INS_JECXZ:
            EXITME("temporarily not support for jecxz");
        case X86_INS_JRCXZ:
            EXITME("temporarily not support for jrcxz");
        case X86_INS_JCXZ:
            EXITME("jcxz is not supported in 64-bit mode");
        default:
            EXITME("invalid hole");
    }

    return 0;
}

static void __rewriter_call_handler(Rewriter *r, GHashTable *holes,
                                    cs_insn *inst, addr_t ori_addr,
                                    addr_t ori_next_addr) {
    ELF *e = z_binary_get_elf(r->binary);
    if (z_elf_get_is_cpp(e)) {
        __rewriter_call_handler_for_cpp(r, holes, inst, ori_addr,
                                        ori_next_addr);
    } else {
        __rewriter_call_handler_for_non_cpp(r, holes, inst, ori_addr,
                                            ori_next_addr);
    }
}

static void __rewriter_call_handler_for_cpp(Rewriter *r, GHashTable *holes,
                                            cs_insn *inst, addr_t ori_addr,
                                            addr_t ori_next_addr) {
    EXITME("call handler for CPP programs is unimplemented");
    // KS_ASM(shadow_addr,
    //        "  mov [rsp - 128], rcx;\n"
    //        // "  mov [rsp - 120], rax;\n"
    //        // "  lahf;\n"
    //        // "  seto al;\n"
    //        "  pop rcx;\n"
    //        "  mov [rsp - 144], rcx;\n"
    //        "  cmp rcx, %#lx;\n"
    //        "  jae fuck;\n"
    //        "  sub rcx, %#lx;\n"  // sub .text base
    //        "  jb fuck;\n"
    //        "  shl rcx, " STRING(LOOKUP_TABLE_CELL_SIZE_POW2) ";\n"
    //        "  movsxd rcx, dword ptr [" STRING(LOOKUP_TABLE_ADDR) " + rcx];\n"
    //        // lookup table "  mov [rsp - 144], rcx;\n" "fuck:\n" "  push
    //        %#lx;\n"
    //        // "  add al, 127;\n"
    //        // "  sahf;\n"
    //        // "  mov rax, [rsp - 120];\n"
    //        "  mov rcx, [rsp - 128];\n"
    //        "  jmp qword ptr [rsp - 144 + 8];\n",
    //        text_addr + text_size, text_addr, ori_next_addr);
}

static void __rewriter_call_handler_for_non_cpp(Rewriter *r, GHashTable *holes,
                                                cs_insn *inst, addr_t ori_addr,
                                                addr_t ori_next_addr) {
    assert(inst->id == X86_INS_CALL);

    cs_detail *detail = inst->detail;
    cs_x86_op *op = &(detail->x86.operands[0]);

    uint64_t hole_buf = 0;
    addr_t shadow_addr = z_binary_get_shadow_code_addr(r->binary);
    ELF *e = z_binary_get_elf(r->binary);
    assert(!z_elf_get_is_cpp(e));

    if (detail->x86.op_count == 1 && op->type == X86_OP_IMM) {
        addr_t callee_addr = op->imm;

        // step [1]. first check callee_addr is inside .text
        if (!z_disassembler_get_superset_disasm(r->disassembler, callee_addr)) {
            // directly write
            KS_ASM_CALL(shadow_addr, callee_addr);
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
            return;
        }

        // step [2]. get shadow callee
        addr_t shadow_callee_addr = (addr_t)g_hash_table_lookup(
            r->rewritten_bbs, GSIZE_TO_POINTER(callee_addr));

        // step [3]. rewrite and insrumentation
        if (shadow_callee_addr) {
            if (z_elf_get_is_pie(e)) {
                KS_ASM(shadow_addr,
                       "mov [rsp - 128], rdi;\n"
                       "lea rdi, [rip + END];\n"
                       "push rdi;\n"
                       "mov rdi, [rsp - 120];\n"
                       "jmp %#lx;\n"
                       "END:\n",
                       shadow_callee_addr);
            } else {
                KS_ASM(shadow_addr,
                       "push END;\n"
                       "jmp %#lx;\n"
                       "END:\n",
                       shadow_callee_addr);
            }
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
        } else {
            // rewrite return address
            if (z_elf_get_is_pie(e)) {
                KS_ASM(shadow_addr,
                       "mov [rsp - 128], rdi;\n"
                       "lea rdi, [rip + END + %lu];\n"
                       "push rdi;\n"
                       "mov rdi, [rsp - 120];\n"
                       "END:\n",
                       __rewriter_get_hole_len(X86_INS_JMP));
            } else {
                KS_ASM(shadow_addr,
                       "push END + %lu;\n"
                       "END:\n",
                       __rewriter_get_hole_len(X86_INS_JMP));
            }

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
        addr_t text_addr = z_elf_get_shdr_text(e)->sh_addr;
        size_t text_size = z_elf_get_shdr_text(e)->sh_size;
        if (strstr(inst->op_str, "rip")) {
            // Handle PC-relative jmp: a good observation is that any
            // rip-relative jmp/call are equal to or longer than
            //          `push ??? PTR [rip + ???]`
            KS_ASM(shadow_addr, "push %s", inst->op_str);
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
            assert(inst->size >= ks_size);
            if (inst->size > ks_size) {
                size_t padding_size = inst->size - ks_size;
                z_binary_insert_shadow_code(
                    r->binary, __rewriter_gen_nop(padding_size), padding_size);
            }
            shadow_addr += inst->size;
        } else {
            KS_ASM(shadow_addr, "push %s", inst->op_str);
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
            shadow_addr += ks_size;
        }

        if (z_elf_get_is_pie(e)) {
            EXITME("ucall handler for PIE binary is unimplemented");
        } else {
            z_debug("rewrite ucall " CS_SHOW_INST(inst));
            // call may not care about eflags
            KS_ASM(shadow_addr,
                   "  mov [rsp - 128], rcx;\n"
                   // "  mov [rsp - 120], rax;\n"
                   // "  lahf;\n"
                   // "  seto al;\n"
                   "  pop rcx;\n"
                   "  mov [rsp - 144], rcx;\n"
                   "  cmp rcx, %#lx;\n"
                   "  jae fuck;\n"
                   "  sub rcx, %#lx;\n"  // sub .text base
                   "  jb fuck;\n"
                   "  shl rcx, " STRING(LOOKUP_TABLE_CELL_SIZE_POW2) ";\n"
                   "  movsxd rcx, dword ptr [" STRING(LOOKUP_TABLE_ADDR) " + rcx];\n"  // lookup table "  mov [rsp - 144], rcx;\n"
                   "fuck:\n"
                   // "  add al, 127;\n"
                   // "  sahf;\n"
                   // "  mov rax, [rsp - 120 - 8];\n"
                   "  mov rcx, [rsp - 128 - 8];\n"
                   "  call qword ptr [rsp - 144];\n",
                   text_addr + text_size, text_addr);
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
        }
    }
}

static void __rewriter_jmp_handler(Rewriter *r, GHashTable *holes,
                                   cs_insn *inst, addr_t ori_addr,
                                   addr_t ori_next_addr) {
    cs_detail *detail = inst->detail;
    cs_x86_op *op = &(detail->x86.operands[0]);

    uint64_t hole_buf = 0;
    addr_t shadow_addr = z_binary_get_shadow_code_addr(r->binary);
    ELF *e = z_binary_get_elf(r->binary);
    addr_t text_addr = z_elf_get_shdr_text(e)->sh_addr;
    size_t text_size = z_elf_get_shdr_text(e)->sh_size;

    if (detail->x86.op_count == 1 && op->type == X86_OP_IMM) {
        addr_t jmp_addr = op->imm;

        // first check jmp_addr is inside .text
        if (!z_disassembler_get_superset_disasm(r->disassembler, jmp_addr)) {
            // directly write
            KS_ASM_JMP(shadow_addr, jmp_addr);
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
            return;
        }

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
        if (strstr(inst->op_str, "rip")) {
            // Handle PC-relative jmp: a good observation is that any
            // rip-relative jmp/call are equal to or longer than
            //          `push ??? PTR [rip + ???]`
            KS_ASM(shadow_addr, "push %s", inst->op_str);
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
            assert(inst->size >= ks_size);
            if (inst->size > ks_size) {
                size_t padding_size = inst->size - ks_size;
                z_binary_insert_shadow_code(
                    r->binary, __rewriter_gen_nop(padding_size), padding_size);
            }
            shadow_addr += inst->size;
        } else {
            KS_ASM(shadow_addr, "push %s", inst->op_str);
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
            shadow_addr += ks_size;
        }

        if (z_elf_get_is_pie(e)) {
            EXITME("ujmp handler for PIE binary is unimplemented");
        } else {
            z_debug("rewrite ujmp " CS_SHOW_INST(inst));
            // jmp may not jump our of .text (NO! z3 binary has such behaviour)
            KS_ASM(shadow_addr,
                   "  mov [rsp - 128], rcx;\n"
                   "  mov [rsp - 120], rax;\n"
                   "  lahf;\n"
                   "  seto al;\n"
                   "  mov rcx, [rsp];\n"
                   "  cmp rcx, %#lx;\n"
                   "  jae fuck;\n"
                   "  sub rcx, %#lx;\n"  // sub .text base
                   "  jb fuck;\n"
                   "  shl rcx, " STRING(LOOKUP_TABLE_CELL_SIZE_POW2)  " ;\n"
                   "  movsxd rcx, dword ptr [" STRING(LOOKUP_TABLE_ADDR) " + rcx];\n"  // lookup table
                   "  mov [rsp], rcx;\n"
                   "fuck:\n"
                   "  add al, 127;\n"
                   "  sahf;\n"
                   "  mov rax, [rsp - 120];\n"
                   "  mov rcx, [rsp - 128];\n"
                   "  ret;\n",
                   text_addr + text_size, text_addr);
            z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
        }
    }
}

static void __rewriter_cjmp_handler(Rewriter *r, GHashTable *holes,
                                    cs_insn *inst, addr_t ori_addr,
                                    addr_t ori_next_addr) {
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

static void __rewriter_loop_handler(Rewriter *r, GHashTable *holes,
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

static void __rewriter_ret_handler(Rewriter *r, GHashTable *holes,
                                   cs_insn *inst, addr_t ori_addr,
                                   addr_t ori_next_addr) {
    // modern CPU will do nothing more except direct returning about `repz ret`
    addr_t shadow_addr = z_binary_get_shadow_code_addr(r->binary);
    ELF *e = z_binary_get_elf(r->binary);
    addr_t text_addr = z_elf_get_shdr_text(e)->sh_addr;
    size_t text_size = z_elf_get_shdr_text(e)->sh_size;
    if (z_elf_get_is_cpp(e)) {
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
    } else {
        z_binary_insert_shadow_code(r->binary, inst->bytes, inst->size);
    }
}
