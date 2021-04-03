#include "rewriter.h"
#include "buffer.h"
#include "capstone_.h"
#include "config.h"
#include "inst_analyzer.h"
#include "utils.h"

#include <capstone/capstone.h>

#ifdef DEBUG
FILE *__debug_file = NULL;
#define __debug_printf(...) fprintf(__debug_file, __VA_ARGS__)
#endif

/*
 * Get a suitable length NOP
 */
Z_PRIVATE unsigned char *__rewriter_gen_nop(size_t n) {
    switch (n) {
        case 1:
            return (unsigned char *)"\x90";
        case 2:
            return (unsigned char *)"\x66\x90";
        case 3:
            return (unsigned char *)"\x0F\x1F\x00";
        case 4:
            return (unsigned char *)"\x0F\x1F\x40\x00";
        case 5:
            return (unsigned char *)"\x0F\x1F\x44\x00\x00";
        case 6:
            return (unsigned char *)"\x66\x0F\x1F\x44\x00\x00";
        case 7:
            return (unsigned char *)"\x0F\x1F\x80\x00\x00\x00\x00";
        case 8:
            return (unsigned char *)"\x0F\x1F\x84\x00\x00\x00\x00\x00";
        case 9:
            return (unsigned char *)"\x66\x0F\x1F\x84\x00\x00\x00\x00\x00";
        default:
            EXITME("invalid nop size: %d", n);
    }
    return NULL;
}

#define ASMLINE_FMT_SIZE 0x100

static char asmline_fmt[ASMLINE_FMT_SIZE];

// TODO: add BeforeBB/AfterBB/BeforeInst/AfterInst handler

/*
 * Function Pointer: compare two address
 */
Z_PRIVATE int __rewriter_compare_address(addr_t x, addr_t y, void *_z);

/*
 * Calculate uTP address, and store the new inst_addr into inst_addr
 */
Z_RESERVED Z_PRIVATE addr_t __rewriter_calculate_utp_addr(Rewriter *r,
                                                          addr_t *inst_addr,
                                                          size_t inst_size);
/*
 * Find a possible uTP address
 */
Z_RESERVED Z_PRIVATE bool __rewriter_patch_utp(Rewriter *r, addr_t ori_addr);

/*
 * Translate inst into shadow address
 */
Z_PRIVATE cs_insn *__rewriter_translate_shadow_inst(Rewriter *r, cs_insn *inst,
                                                    addr_t ori_addr);

/*
 * Generate an instruction of shadow code
 */
Z_PRIVATE void __rewriter_generate_shadow_inst(Rewriter *r, GHashTable *holes,
                                               cs_insn *inst, addr_t ori_addr,
                                               bool bb_entry);
/*
 * Generate a basic block of shadow code
 */
Z_PRIVATE void __rewriter_generate_shadow_block(
    Rewriter *r, GHashTable *holes, GQueue *instructions, addr_t ori_addr,
    cs_insn *(*disasm_func)(Disassembler *, addr_t));

/*
 * Fill in shadow holes
 */
Z_PRIVATE void __rewriter_fillin_shadow_hole(Rewriter *r, GHashTable *holes);

/*
 * Build bridgs
 */
Z_RESERVED Z_PRIVATE void __rewriter_build_bridges(Rewriter *r,
                                                   GQueue *instructions);

/*
 * Emit Trampoline based on analyzed results
 */
Z_PRIVATE void __rewriter_emit_trampoline(Rewriter *r, addr_t addr);

// XXX: this include must be placed here, to use above predeclared these
// prototypes
#include "rewriter_handlers/handler_main.c"

/*
 * Cound how many BB ID is conflicted
 */
Z_PRIVATE void __rewriter_count_conflicted_ids(Rewriter *r);

Z_PRIVATE void __rewriter_count_conflicted_ids(Rewriter *r) {
    size_t conflicts = 0;

    GHashTable *id_2_bb =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    GList *bbs = g_hash_table_get_keys(r->rewritten_bbs);

    for (GList *l = bbs; l != NULL; l = l->next) {
        addr_t bb_addr = (addr_t)(l->data);
        size_t bb_id = AFL_BB_ID(bb_addr);

        addr_t old_bb =
            (addr_t)g_hash_table_lookup(id_2_bb, GSIZE_TO_POINTER(bb_id));
        if (!old_bb) {
            g_hash_table_insert(id_2_bb, GSIZE_TO_POINTER(bb_id),
                                GSIZE_TO_POINTER(bb_addr));
        } else {
            conflicts += 1;
            z_trace("conflict: %#lx v/s %#lx (%#lx)", bb_addr, old_bb, bb_id);
        }
    }

    g_hash_table_destroy(id_2_bb);
    g_list_free(bbs);

    z_info("we have %d conflicted IDs in total", conflicts);
}

/*
 * Getter and Setter
 */
DEFINE_GETTER(Rewriter, rewriter, GHashTable *, unlogged_retaddr_crashpoints);
DEFINE_GETTER(Rewriter, rewriter, GHashTable *, returned_callees);
OVERLOAD_SETTER(Rewriter, rewriter, addr_t, returned_callees) {
    g_hash_table_insert(rewriter->returned_callees,
                        GSIZE_TO_POINTER(returned_callees),
                        GSIZE_TO_POINTER(true));
}

Z_RESERVED Z_PRIVATE bool __rewriter_patch_utp(Rewriter *r, addr_t ori_addr) {
    // [0] get instruction
    cs_insn *inst =
        z_disassembler_get_recursive_disasm(r->disassembler, ori_addr);
    assert(inst != NULL);

    // [1] get upt_addr
    addr_t new_inst_addr = ori_addr;
    addr_t utp_addr =
        __rewriter_calculate_utp_addr(r, &new_inst_addr, inst->size);

    // [2] validate uTP
    if (utp_addr == INVALID_ADDR) {
        return false;
    }

    // [3] get shadow_address
    addr_t shadow_addr = z_rewriter_get_shadow_addr(r, ori_addr);
    assert(shadow_addr != INVALID_ADDR);

    // [4] generate utp trampoline
    KS_ASM_JMP(utp_addr, shadow_addr);
    z_binary_insert_utp(r->binary, utp_addr, ks_encode, ks_size);

    // [5] generate patched code
    // KS_ASM_JMP(new_inst_addr, utp_addr);

    // [6] do patch
    // ELF *e = z_binary_get_elf(r->binary);
    // z_elf_write(e, new_inst_addr, ks_size, ks_encode);

    // [7] patch prefix code
    // if (new_inst_addr != ori_addr) {
    //     size_t padding_size = new_inst_addr - ori_addr;
    //     z_elf_write(e, ori_addr, padding_size,
    //                 __rewriter_gen_nop(padding_size));
    // }

    // [8] update count
    r->patched_unsafe_bg_count++;
    return true;
}

Z_RESERVED Z_PRIVATE addr_t __rewriter_calculate_utp_addr(Rewriter *r,
                                                          addr_t *inst_addr,
                                                          size_t inst_size) {
    ELF *e = z_binary_get_elf(r->binary);
    bool is_pie = z_elf_get_is_pie(e);

    // [1] get offset buf
    uint64_t tmp = 0;
    addr_t ori_inst_addr = *inst_addr;
    z_elf_read(e, ori_inst_addr, 8, (uint8_t *)(&tmp));

    // [2] prepare init pointer
    uint8_t *buffer = (uint8_t *)(&tmp) + 1;
    size_t buffer_size = inst_size - 1;

    // [3] prepare a utp snode
    Snode *utp =
        z_snode_create(0, __rewriter_get_hole_len(X86_INS_JMP), NULL, NULL);

    // [4] Brute-force OP inst_addr
    while ((int64_t)buffer_size >= 0) {
        int32_t *offset = (int32_t *)buffer;

        // [4.1] pre-check for non-pie (avoid cache miss)
        if (!is_pie && buffer[3] > 0x7f)
            goto NEXT;

        // [4.2] initial offset buf (a trick to avoid conflict)
        memset(buffer, 1, buffer_size);
        int32_t ori_offset = *offset;

        // [4.3] brute-force offset
        int64_t utp_addr = 0;
        do {
            utp_addr = (int64_t)(*inst_addr + 5) + (int64_t)(*offset);

            if (is_pie || utp_addr >= 0) {
                z_snode_set_addr(utp, (addr_t)utp_addr);
                if (z_elf_check_region_free(e, utp)) {
                    z_snode_destroy(utp);
                    return (addr_t)utp_addr;
                }
            }

            if (buffer_size == 0)
                goto NEXT;

            for (int32_t i = buffer_size - 1; i >= 0; i--) {
                if (buffer[i] != 0xff) {
                    buffer[i] += 1;
                    break;
                } else {
                    buffer[i] = 0x00;
                }
            }
        } while (*offset != ori_offset);

    NEXT:
        // [4.4] check next OP inst_addr
        (*inst_addr)++;
        buffer++;
        buffer_size--;
    }

    // [5] failed
    z_trace("fail to find suitable uTP address: %#lx", ori_inst_addr);
    z_snode_destroy(utp);
    return INVALID_ADDR;
}

Z_PRIVATE int __rewriter_compare_address(addr_t x, addr_t y, void *_z) {
    if (x == y)
        return 0;
    else if (x > y)
        return 1;
    else
        return -1;
}

Z_PRIVATE void __rewriter_emit_trampoline(Rewriter *r, addr_t addr) {
#ifndef BINARY_SEARCH_INVALID_CRASH
    InstAnalyzer *inst_analyzer =
        z_disassembler_get_inst_analyzer(r->disassembler);

    FLGState flg_state =
        z_inst_analyzer_get_flg_need_write(inst_analyzer, addr);
    GPRState gpr_state = z_inst_analyzer_get_gpr_can_write(inst_analyzer, addr);

    // update total number of tramplines
    r->afl_trampoline_count += 1;

    // update gpr state
    if (gpr_state) {
        r->optimized_gpr_count += 1;
    }

    if (!flg_state) {
        // no need to store eflags
        r->optimized_flg_count += 1;

        TP_EMIT(bitmap, addr, gpr_state);
        z_binary_insert_shadow_code(r->binary, tp_code, tp_size);
    } else {
        // need to store eflags
        TP_EMIT(context_save);
        z_binary_insert_shadow_code(r->binary, tp_code, tp_size);

        TP_EMIT(bitmap, addr, gpr_state & (~GPRSTATE_RAX));
        z_binary_insert_shadow_code(r->binary, tp_code, tp_size);

        TP_EMIT(context_restore);
        z_binary_insert_shadow_code(r->binary, tp_code, tp_size);
    }
#endif
}

Z_PRIVATE void __rewriter_fillin_shadow_hole(Rewriter *r, GHashTable *holes) {
    GList *shadow_addrs = g_hash_table_get_keys(holes);
    ELF *e = z_binary_get_elf(r->binary);

    for (GList *l = shadow_addrs; l != NULL; l = l->next) {
        addr_t shadow_inst_addr = (addr_t)(l->data);
        addr_t ori_tar_addr = (addr_t)g_hash_table_lookup(
            holes, GSIZE_TO_POINTER(shadow_inst_addr));

        addr_t shadow_tar_addr = (addr_t)g_hash_table_lookup(
            r->rewritten_bbs, GSIZE_TO_POINTER(ori_tar_addr));
        if (shadow_tar_addr == 0) {
            // XXX: ignore invalid hole as it may be false instruction
            z_warn("an invalid hole: %#lx <- %#lx", ori_tar_addr,
                   shadow_inst_addr);
            continue;
        }

        // get id and hole size
        uint32_t inst_id;
        z_elf_read(e, shadow_inst_addr, sizeof(uint32_t),
                   (uint8_t *)(&inst_id));

#ifndef NSINGLE_SUCC_OPT
        // check whether we need to do optimization
        if (!sys_config.disable_opt) {
            if ((int32_t)inst_id < 0) {
                // it is a trampoline-free transfer
                inst_id = (~inst_id) + 1;
                shadow_tar_addr = (addr_t)g_hash_table_lookup(
                    r->shadow_code, GSIZE_TO_POINTER(ori_tar_addr));
            }
        } else {
            assert((int32_t)inst_id >= 0);
        }
#endif

        size_t hole_size = __rewriter_get_hole_len(inst_id);

        // generate code
        KS_ASM(shadow_inst_addr, "%s %#lx", cs_insn_name(cs, inst_id),
               shadow_tar_addr);
        z_elf_write(e, shadow_inst_addr, ks_size, ks_encode);

        // padding hole
        assert(ks_size <= hole_size);
        if (ks_size < hole_size) {
            z_elf_write(e, shadow_inst_addr + ks_size, hole_size - ks_size,
                        __rewriter_gen_nop(hole_size - ks_size));
        }
    }

    g_list_free(shadow_addrs);
}

Z_PRIVATE cs_insn *__rewriter_translate_shadow_inst(Rewriter *r, cs_insn *inst,
                                                    addr_t ori_addr) {
    cs_detail *detail = inst->detail;

    for (int32_t i = 0; i < detail->x86.op_count; i++) {
        cs_x86_op *op = &(detail->x86.operands[i]);
        if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP) {
            goto TRANSLATE_RIP_INS;
        }
    }

    // PC non-related instruction, directly return
    assert(strstr(inst->op_str, "rip") == NULL);
    assert(strstr(inst->op_str, "eip") == NULL);
    return inst;

TRANSLATE_RIP_INS:
    z_trace(
        "rip-related memory access "
        "instruction " CS_SHOW_INST(inst));

    // step [1]. generate asmline fmt (FMTSTR ATTACK!!!)
    int64_t op_mem_disp = 0;

    // step [1.1]. generate mnemonic
    z_snprintf(asmline_fmt, ASMLINE_FMT_SIZE, "%s\t", inst->mnemonic);

    // step [1.2]. generate operands
    for (int32_t i = 0; i < detail->x86.op_count; i++) {
        cs_x86_op *op = &(detail->x86.operands[i]);
        switch (op->type) {
            case X86_OP_REG:
                z_snprintf(asmline_fmt + z_strlen(asmline_fmt),
                           ASMLINE_FMT_SIZE - z_strlen(asmline_fmt), "%s, ",
                           cs_reg_name(cs, op->reg));
                continue;
            case X86_OP_IMM:
                z_snprintf(asmline_fmt + z_strlen(asmline_fmt),
                           ASMLINE_FMT_SIZE - z_strlen(asmline_fmt), "%#lx, ",
                           op->imm);
                continue;
            case X86_OP_MEM:
                assert(op->mem.base == X86_REG_RIP);
                assert(op->mem.index == X86_REG_INVALID);

                /*
                 * XXX: keystone and capstone bug! For more information, please
                 * refer to
                 * https://github.com/keystone-engine/keystone/issues/92
                 */
                // TODO: build our own keystone and capstone (FUCK!)
                size_t hooked_size = op->size;
                if (inst->id == X86_INS_COMISS) {
                    hooked_size = 4;
                } else if (inst->id == X86_INS_COMISD) {
                    hooked_size = 8;
                }

                switch (hooked_size) {
                    case 1:
                        z_strcpy(asmline_fmt + z_strlen(asmline_fmt),
                                 "byte ptr [rip%+ld], ");
                        break;
                    case 2:
                        z_strcpy(asmline_fmt + z_strlen(asmline_fmt),
                                 "word ptr [rip%+ld], ");
                        break;
                    case 4:
                        z_strcpy(asmline_fmt + z_strlen(asmline_fmt),
                                 "dword ptr [rip%+ld], ");
                        break;
                    case 8:
                        z_strcpy(asmline_fmt + z_strlen(asmline_fmt),
                                 "qword ptr [rip%+ld], ");
                        break;
                    case 10:
                        z_strcpy(asmline_fmt + z_strlen(asmline_fmt),
                                 "fword ptr [rip%+ld], ");
                        break;
                    case 16:
                        z_strcpy(asmline_fmt + z_strlen(asmline_fmt),
                                 "xmmword ptr [rip%+ld], ");
                        break;
                    default:
                        z_strcpy(asmline_fmt + z_strlen(asmline_fmt),
                                 "[rip%+ld], ");
                        break;
                }
                op_mem_disp = op->mem.disp;
                continue;
            default:
                EXITME("invalid op type " CS_SHOW_INST(inst));
        }
    }

    // step [1.3]. add NULL at last comma
    assert(asmline_fmt[z_strlen(asmline_fmt) - 2] == ',');
    asmline_fmt[z_strlen(asmline_fmt) - 2] = '\x00';
    z_trace("generated asmline_fmt: %s", asmline_fmt);

    const addr_t ori_pc = ori_addr + inst->size;
    const addr_t shadow_addr = z_binary_get_shadow_code_addr(r->binary);

    addr_t shadow_pc = shadow_addr + inst->size;

    // step [2]. brute-force to find the suitable shadow_pc, starting from the
    // most possible address (the longest meanful x64 instruction is 15-byte)
    for (; shadow_pc < shadow_addr + 0x10; shadow_pc++) {
        // step [2.1]. asm and disasm (FMTSTR ATTACK!!!)
        KS_ASM(shadow_addr, asmline_fmt, ori_pc - shadow_pc + op_mem_disp);
        assert(ks_size > 0);
        CS_DISASM_RAW(ks_encode, ks_size, shadow_addr, 1);

        // step [2.2]. check and re-fit next pc address
        if (shadow_addr + cs_inst->size == shadow_pc) {
            // nice, break
            break;
        } else if (shadow_addr + cs_inst->size < shadow_pc) {
            // for short instruction,
            // easy to padding nop
            size_t padding_size = shadow_pc - cs_inst->size - shadow_addr;
            z_binary_insert_shadow_code(
                r->binary, __rewriter_gen_nop(padding_size), padding_size);
            break;
        }

        // we need to check bigger shadow pc
    }

    assert(z_binary_get_shadow_code_addr(r->binary) + cs_inst->size ==
           shadow_pc);
    return (cs_insn *)cs_inst;
}

Z_PRIVATE void __rewriter_generate_shadow_inst(Rewriter *r, GHashTable *holes,
                                               cs_insn *inst, addr_t ori_addr,
                                               bool bb_entry) {
    // step [0]. get next address, we must do this before translation
    addr_t ori_next_addr = ori_addr + inst->size;

    /*
     * XXX: for the basic block entrypoints' address mapping, there is a silght
     * difference between r->rewritten_bbs and LOOKUP_TABLE:
     *      r->rewritten_bbs maps the bb entrypoint address to its instrumented
     * bitmap code's shadow address (it serves for handlers to find shadown
     * tranfer target);
     *      LOOKUP_TABLE maps the bb entrypoint address to its own shadow
     * address (it serves for on-the-fly translattion of indirect call/jmp);
     *
     * In shore, for a given bb entrypoint, r->rewritten_bbs's mapping
     * value is always samller than LOOKUP_TABLE's.
     *
     */
    /*
     * XXX: it is very important to distinguish r->rewritten_bbs and
     * LOOKUP_TABLE. Note that LOOKUP_TABLE is used for indirect call/jmp's
     * dynamic mapping, and these indirect call/jmp's targets are very different
     * to identify. Hence, it is possible that their targets are already
     * rewritten but not identified as block entrypoints. In that case, the best
     * we can do is to instrument AFL_TRAMPOLINE at the tail of these indirect
     * call/jmp, and directly tranfer to the shadow address (w/o
     * AFL_TRAMPOLINE). And r->rewritten_bbs is used for direct call/jmp at
     * rewriting time. When rewriting a direct call/jmp, it is possible its
     * target is not rewritten. Hence, we use holes and r->rewritten_bbs to lazy
     * update the target address. As these direct call/jmp's targets can always
     * be identified as block entrypoints, we do not need to instrument
     * AFL_TRAMPOLINE at their tails (to reduce memory usage).
     *
     */

    // step [1]. handle entry of basic block
    if (bb_entry) {
        size_t shadow_addr = z_binary_get_shadow_code_addr(r->binary);
        // step [1.1]. update rewritten_bbs
        if (!g_hash_table_lookup(r->rewritten_bbs,
                                 GSIZE_TO_POINTER(ori_addr))) {
            g_hash_table_insert(r->rewritten_bbs, GSIZE_TO_POINTER(ori_addr),
                                GSIZE_TO_POINTER(shadow_addr));
        }

        // step [1.2] insert trampolines based on optimization
        __rewriter_emit_trampoline(r, ori_addr);
    }

    // step [2]. update shadow code
    if (!g_hash_table_lookup(r->shadow_code, GSIZE_TO_POINTER(ori_addr))) {
        size_t shadow_addr = z_binary_get_shadow_code_addr(r->binary);
        // we store the first apperance of each instruction
        g_hash_table_insert(r->shadow_code, GSIZE_TO_POINTER(ori_addr),
                            GSIZE_TO_POINTER(shadow_addr));
        z_binary_update_lookup_table(r->binary, ori_addr, shadow_addr);
    }

    if (sys_config.trace_pc) {
        // trace previous pc
        KS_ASM_CONST_MOV(RW_PAGE_INFO_ADDR(prev_pc), ori_addr);
        z_binary_insert_shadow_code(r->binary, ks_encode, ks_size);
    }

#ifdef DEBUG
    __debug_printf("%#lx -> %#lx:\n", ori_addr,
                   z_binary_get_shadow_code_addr(r->binary));
    __debug_printf("\told inst " CS_SHOW_INST(inst));
    __debug_printf("\n");
#endif
    // step [3]. translate rip-related instrution
    //      XXX: note that inserting any new code between step [3] and step [4]
    //      will cause wrong instrumentation.
    inst = __rewriter_translate_shadow_inst(r, inst, ori_addr);

#ifdef DEBUG
    __debug_printf("\tnew inst " CS_SHOW_INST(inst));
    __debug_printf("\n");
#endif

    // step [4]. check handlers
    RHandler **handlers = (RHandler **)z_buffer_get_raw_buf(r->handlers);
    size_t n = z_buffer_get_size(r->handlers) / sizeof(RHandler *);
    for (size_t i = 0; i < n; i++) {
        REvent event = z_rhandler_get_event(handlers[i]);
        RHandlerFcn fcn = z_rhandler_get_fcn(handlers[i]);
        if ((*event)(inst)) {
            (*fcn)(r, holes, inst, ori_addr, ori_next_addr);
            return;
        }
    }

    // for unhandled instruction, we simply rewrite it
    z_binary_insert_shadow_code(r->binary, inst->bytes, inst->size);
    return;
}

/*
 * XXX: For every BB entrypoint found by Disassembler, Rewriter should not
 * inject any AFL_TRAMPOLINE until a terminator instruction is found. In other
 * words, if we consider a basic block's complete body starting from its
 * entrypoint and ending at its terminator instruction (ret, jmp, int, or any
 * other preivilege instrution), every disassembler-found basic block should
 * have its own unique copy of its complete body, and these copies do not
 * overlap with each other.
 *
 * Maintaining this property will help us on:
 *      1. Any Disassembler's false positive of indentifying basic blocks will
 *      not impact Rewriter's correctness;
 *      2. Fuzzing speed can be optimized. When a basic block is reached, it is
 *      meaningless to record any fall-through edge within this basic block.
 *      This design naturely avoids recording these fall-through edges;
 *
 * Variable *bb_entry* is the key to maintain this property.
 */
/*
 * XXX: Above idea is very reasonable. *However*, it does not consider the cache
 * hit rate and forking overhead. In other words, if every disassembly-found
 * block has an own copy of its complete body, the memory usage will increase.
 * Therefore, the cache hit rate will quickly drop down. When the program is
 * large (e.g., openssl), the missing hit will siginificately influence the
 * execution speed. We have test the fuzzing speed w/ and w/o above
 * optimization, and the results are shown this optimization does hurt
 * performance.
 *
 * Hence, we decide to disable this optimization right now.
 */
/*
 * XXX: FALL_THROUGH opt can be enabled by jumping over the trampoline. However,
 * considering we can almost elimiate all EFLAGS saving, the overhead of an AFL
 * trampoline may be smaller than the one caused by a jump instruction.
 * TODO: decide whether we need to enable FALL_THROUGH (note that in SotchFuzz
 * paper, this optimization is enabled)
 */
/*
 * XXX: It is ok for our tool to instrument false instructions or block
 * entrypoint, as long as the false rate it limited. Note that when the false
 * rate increases, the number of memory usage (influencing cache hit rate) and
 * extra-false AFL_TRAMPOLINE will increase, reasulting a low execution speed.
 * That is why we abandon pre- linear disassembly.
 *
 * However, keep in mind that, for our tool, it is very critical to avoid
 * missing any instruction or block entrypoint.
 */
Z_PRIVATE void __rewriter_generate_shadow_block(
    Rewriter *r, GHashTable *holes, GQueue *instructions, addr_t bb_addr,
    cs_insn *(*disasm_func)(Disassembler *, addr_t)) {
    // step [1]. basic information
    cs_insn *inst = NULL;
    addr_t ori_addr = bb_addr;
    bool bb_entry = true;  // whether next instrution is a BB entrypoint

    // step [2]. check whether this block is handled
    if (g_hash_table_lookup(r->rewritten_bbs, GSIZE_TO_POINTER(bb_addr))) {
        // we already rewrite this basic block
        return;
    }

    // step [3]. rewrite code one by one
    do {
        inst = (*disasm_func)(r->disassembler, ori_addr);

        // step [3.1]. check this address is valid and update instructions
        //      Note that it is possible inst is NULL, as no-return / inline
        //      data may cause incorrect disasm.
        if (!inst) {
            return;
        }
        if (instructions) {
            if (!g_hash_table_lookup(r->shadow_code,
                                     GSIZE_TO_POINTER(ori_addr))) {
                g_queue_push_tail(instructions, GSIZE_TO_POINTER(ori_addr));
            }
        }

#ifdef BINARY_SEARCH_DEBUG_REWRITER
        if (ori_addr <= BINARY_SEARCH_DEBUG_REWRITER) {
            if (bb_entry) {
                g_hash_table_insert(r->rewritten_bbs,
                                    GSIZE_TO_POINTER(ori_addr),
                                    GSIZE_TO_POINTER(ori_addr));
            }
            g_hash_table_insert(r->shadow_code, GSIZE_TO_POINTER(ori_addr),
                                GSIZE_TO_POINTER(ori_addr));
            z_binary_update_lookup_table(r->binary, ori_addr, ori_addr);
            z_elf_write(r->binary->elf, ori_addr, inst->size, inst->bytes);
        } else
#endif
        {
            // step [3.2]. rewrite the single instruction
            __rewriter_generate_shadow_inst(r, holes, inst, ori_addr, bb_entry);
        }

        bb_entry = !!z_disassembler_is_potential_block_entrypoint(
            r->disassembler, ori_addr + inst->size);

#ifdef FALL_THROUGH_OPT
        if (bb_entry &&
            !(z_capstone_is_cjmp(inst) || z_capstone_is_loop(inst) ||
              z_capstone_is_terminator(inst))) {
            // XXX: insert a short jmp instruction here
        }
#endif

        // step [3.3]. update cur_addr
        ori_addr += inst->size;
    } while (!z_capstone_is_terminator(inst));

    return;
}

Z_RESERVED Z_PRIVATE void __rewriter_build_bridges(Rewriter *r,
                                                   GQueue *instructions) {
    assert(r != NULL && instructions != NULL);

    ELF *e = z_binary_get_elf(r->binary);
    bool prev_patched = false;
    addr_t prev_addr = INVALID_ADDR;

    while (!g_queue_is_empty(instructions)) {
        addr_t cur_addr = (addr_t)g_queue_pop_tail(instructions);

        assert(prev_addr > cur_addr);

        cs_insn *ori_inst =
            z_disassembler_get_recursive_disasm(r->disassembler, cur_addr);

        assert(ori_inst != NULL);
        assert(ori_inst->size + cur_addr <= prev_addr);

        // get shadow_addr
        addr_t shadow_addr = z_rewriter_get_shadow_addr(r, cur_addr);
        assert(shadow_addr != INVALID_ADDR);

        // check ori_inst->size
        if (ori_inst->size >= __rewriter_get_hole_len(X86_INS_JMP)) {
            // build bridge
            KS_ASM_JMP(cur_addr, shadow_addr);
            z_elf_write(e, cur_addr, ks_size, ks_encode);

            // update statistic
            r->patched_safe_bg_count++;
            prev_patched = true;
        } else {
            // if previous instruction is patched, we ignore here
            if (prev_patched) {
                prev_patched = false;
                goto NEXT;
            }

            // we only do crashed brideg on continued instructions
            if (prev_addr != cur_addr + ori_inst->size) {
                prev_patched = false;
                goto NEXT;
            }

            cs_insn *prev_inst =
                z_disassembler_get_recursive_disasm(r->disassembler, prev_addr);
            assert(prev_inst != NULL);

            // we only do patch within two instruction
            if (ori_inst->size + prev_inst->size <
                __rewriter_get_hole_len(X86_INS_JMP)) {
                prev_patched = false;
                goto NEXT;
            }

            // test for next instruction
            uint8_t tmp_buf[16] = {0};
            z_elf_read(e, cur_addr, sizeof(tmp_buf), tmp_buf);
            KS_ASM_JMP(cur_addr, shadow_addr);
            memcpy(tmp_buf, ks_encode, ks_size);

            CS_DISASM_RAW(tmp_buf + ori_inst->size,
                          sizeof(tmp_buf) - ori_inst->size,
                          cur_addr + ori_inst->size, 1);

            if (cs_count == 0) {
                // invalid, nice
                z_elf_write(e, cur_addr, ks_size, ks_encode);

                // update statistic
                r->patched_unsafe_bg_count++;
                prev_patched = true;
            } else {
                prev_patched = false;
            }
        }

    NEXT:
        prev_addr = cur_addr;
    }
}

Z_API Rewriter *z_rewriter_create(Disassembler *d) {
    Rewriter *r = STRUCT_ALLOC(Rewriter);

    r->disassembler = d;
    r->binary = z_disassembler_get_binary(d);

    // init basic information
    r->shadow_code =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    r->rewritten_bbs =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    // init potential returen address info
    r->retaddr_crashpoints =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    r->returned_callees =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    r->callee2retaddrs = g_hash_table_new_full(
        g_direct_hash, g_direct_equal, NULL, (GDestroyNotify)&z_buffer_destroy);
    r->unlogged_retaddr_crashpoints =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    // init statistical data
    r->patched_safe_bg_count = 0;
    r->patched_unsafe_bg_count = 0;
    r->afl_trampoline_count = 0;
    r->optimized_flg_count = 0;
    r->optimized_gpr_count = 0;
    r->optimized_single_succ = 0;

    // init handlers
    r->handlers = z_buffer_create(NULL, 0);

    r->__main_rewritten = false;

    __rewriter_init_predefined_handler(r);

#ifdef DEBUG
    __debug_file = fopen("shadow.log", "w");
#endif

    return r;
}

Z_API void z_rewriter_rewrite_beyond_main(Rewriter *r) {
    if (r->__main_rewritten) {
        EXITME(
            "z_rewriter_rewrite_beyond_main should execute before "
            "z_rewriter_rewrite_main");
    }

    ELF *e = z_binary_get_elf(r->binary);

// init and fini
#define __REWRITE_FCN_FROM_REG(type, reg)                                     \
    do {                                                                      \
        addr_t type##_addr = z_elf_get_##type(e);                             \
        z_rewriter_rewrite(r, type##_addr);                                   \
        addr_t shadow_##type##_addr =                                         \
            z_rewriter_get_shadow_addr(r, type##_addr);                       \
        if (shadow_##type##_addr == INVALID_ADDR) {                           \
            break;                                                            \
        }                                                                     \
                                                                              \
        addr_t load_##type = z_elf_get_load_##type(e);                        \
        assert(z_rewriter_get_shadow_addr(r, load_##type) == INVALID_ADDR);   \
        assert(z_disassembler_get_recursive_disasm(r->disassembler,           \
                                                   load_##type) == NULL);     \
        assert(z_disassembler_get_linear_disasm(r->disassembler,              \
                                                load_##type) == NULL);        \
        if (z_elf_get_is_pie(e)) {                                            \
            KS_ASM(load_##type, "lea " #reg ", [rip %+ld];",                  \
                   shadow_##type##_addr - load_##type - 7);                   \
        } else {                                                              \
            KS_ASM(load_##type, "mov " #reg ", %#lx;", shadow_##type##_addr); \
        }                                                                     \
        assert(ks_size == 7);                                                 \
        z_elf_write(e, load_##type, ks_size, ks_encode);                      \
        z_disassembler_update_superset_disasm(r->disassembler, load_##type);  \
    } while (0)

    __REWRITE_FCN_FROM_REG(init, rcx);
    __REWRITE_FCN_FROM_REG(fini, r8);
#undef __REWRITE_FCN_FROM_REG

// .init.array and .fini array
#define __REWRITE_FCN_FROM_ARRAY(type)                               \
    do {                                                             \
        Rptr *array = NULL;                                          \
        size_t array_size = 0;                                       \
        addr_t array_addr = INVALID_ADDR;                            \
                                                                     \
        Elf64_Shdr *type##_array = z_elf_get_shdr_##type##_array(e); \
        if (!type##_array) {                                         \
            break;                                                   \
        }                                                            \
        array_size = type##_array->sh_size;                          \
        array_addr = type##_array->sh_addr;                          \
        array = z_elf_vaddr2ptr(e, array_addr);                      \
        for (int i = 0; i < array_size / sizeof(addr_t); i++) {      \
            addr_t fcn = *z_rptr_get_ptr(array, addr_t);             \
            z_info("." #type ".array[%d]: %#lx", i, fcn);            \
            z_rewriter_rewrite(r, fcn);                              \
            addr_t shadow_fcn = z_rewriter_get_shadow_addr(r, fcn);  \
            *z_rptr_get_ptr(array, addr_t) = shadow_fcn;             \
            z_rptr_inc(array, addr_t, 1);                            \
        }                                                            \
        z_rptr_destroy(array);                                       \
    } while (0)

    __REWRITE_FCN_FROM_ARRAY(init);
    __REWRITE_FCN_FROM_ARRAY(fini);
#undef __REWRITE_FCN_FROM_ARRAY

    // start
    addr_t start_addr = z_elf_get_ori_entry(e);
    z_rewriter_rewrite(r, start_addr);
    // update shadow start
    addr_t shadow_start_addr = z_rewriter_get_shadow_addr(r, start_addr);
    assert(shadow_start_addr != INVALID_ADDR);
    z_binary_set_shadow_start(r->binary, shadow_start_addr);
}

Z_API void z_rewriter_rewrite_main(Rewriter *r) {
    if (r->__main_rewritten) {
        EXITME("z_rewriter_rewrite_main already executed");
    }

    ELF *e = z_binary_get_elf(r->binary);
    addr_t main_addr = z_elf_get_main(e);

    // rewrite main
    z_rewriter_rewrite(r, main_addr);

    // update shadow main
    addr_t shadow_main_addr = z_rewriter_get_shadow_addr(r, main_addr);
    assert(shadow_main_addr != INVALID_ADDR);
    z_binary_set_shadow_main(r->binary, shadow_main_addr);

    // update __main_rewritten
    r->__main_rewritten = true;
}

// XXX: note that its underlying disassembly (linear) is not completed.
// XXX: useless and hence unused!
Z_RESERVED Z_API void z_rewriter_heuristics_rewrite(Rewriter *r) {
    assert(r != NULL);

    if (!r->__main_rewritten) {
        EXITME(
            "z_rewriter_heuristics_rewrite should execute after "
            "z_rewriter_rewrite_main");
    }

    // step [1]. request disassembler to recursive disassemble code
    GQueue *new_bbs = z_disassembler_linear_disasm(r->disassembler);
    z_trace("find %d new basic blocks by linear disassembly",
            g_queue_get_length(new_bbs));

    g_queue_sort(new_bbs, (GCompareDataFunc)__rewriter_compare_address, NULL);

    // step [2]. prepare cf_related hole
    GHashTable *cf_related_holes =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    // step [3]. rewrite all new basci blocks
    while (!g_queue_is_empty(new_bbs)) {
        addr_t bb_addr = (addr_t)g_queue_pop_head(new_bbs);

        // rewrite the whole basic block
        __rewriter_generate_shadow_block(r, cf_related_holes, NULL, bb_addr,
                                         &z_disassembler_get_linear_disasm);
    }

    // step [4]. fill in all cf_related holes
    __rewriter_fillin_shadow_hole(r, cf_related_holes);

    // step [5]. destroy structure to avoid memleak
    g_hash_table_destroy(cf_related_holes);
    g_queue_free(new_bbs);

    if (sys_config.count_conflict) {
        __rewriter_count_conflicted_ids(r);
    }
}

Z_API void z_rewriter_destroy(Rewriter *r) {
    RHandler **handlers = (RHandler **)z_buffer_get_raw_buf(r->handlers);
    for (int32_t i = 0; i < z_buffer_get_size(r->handlers) / sizeof(RHandler *);
         i++)
        z_rhandler_destroy(handlers[i]);
    z_buffer_destroy(r->handlers);

    g_hash_table_destroy(r->shadow_code);
    g_hash_table_destroy(r->rewritten_bbs);

    g_hash_table_destroy(r->retaddr_crashpoints);
    g_hash_table_destroy(r->returned_callees);
    g_hash_table_destroy(r->callee2retaddrs);
    g_hash_table_destroy(r->unlogged_retaddr_crashpoints);

    z_free(r);

#ifdef DEBUG
    fclose(__debug_file);
#endif
}

Z_API void z_rewriter_register_handler(Rewriter *r, REvent event,
                                       RHandlerFcn fcn) {
    RHandler *handler = z_rhandler_create(event, fcn);
    z_buffer_append_raw(r->handlers, (uint8_t *)(&handler), sizeof(RHandler *));
}

Z_API void z_rewriter_rewrite(Rewriter *r, addr_t new_addr) {
    assert(r != NULL);

    z_trace("rewrite new target: %#lx", new_addr);

    // step [1]. request disassembler to recursive disassemble code
    GQueue *new_bbs =
        z_disassembler_recursive_disasm(r->disassembler, new_addr);
    z_trace("find %d new basic blocks", g_queue_get_length(new_bbs));

    g_queue_sort(new_bbs, (GCompareDataFunc)__rewriter_compare_address, NULL);

    // step [2]. prepare cf_related hole
    GHashTable *cf_related_holes =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    // step [3]. rewrite all new basci blocks
    while (!g_queue_is_empty(new_bbs)) {
        addr_t bb_addr = (addr_t)g_queue_pop_head(new_bbs);

        // rewrite the whole basic block
        __rewriter_generate_shadow_block(r, cf_related_holes, NULL, bb_addr,
                                         &z_disassembler_get_recursive_disasm);
    }

    // step [4]. fill in all cf_related holes
    __rewriter_fillin_shadow_hole(r, cf_related_holes);

    // step [5]. destroy structure to avoid memleak
    g_hash_table_destroy(cf_related_holes);
    g_queue_free(new_bbs);

    if (sys_config.count_conflict) {
        __rewriter_count_conflicted_ids(r);
    }
}

Z_API void z_rewriter_optimization_stats(Rewriter *r) {
    z_info("number of optimized FLG savings: %6d / %d", r->optimized_flg_count,
           r->afl_trampoline_count);
    z_info("number of optimized GPR savings: %6d / %d", r->optimized_gpr_count,
           r->afl_trampoline_count);
    z_info("number of optimized trampolines: %6d / %d",
           r->optimized_single_succ, r->afl_trampoline_count);
}

Z_API addr_t z_rewriter_get_shadow_addr(Rewriter *r, addr_t addr) {
    addr_t shadow_addr =
        (addr_t)g_hash_table_lookup(r->rewritten_bbs, GSIZE_TO_POINTER(addr));

    if (!shadow_addr) {
        shadow_addr =
            (addr_t)g_hash_table_lookup(r->shadow_code, GSIZE_TO_POINTER(addr));
    }

    if (shadow_addr) {
        return shadow_addr;
    } else {
        return INVALID_ADDR;
    }
}

Z_API bool z_rewriter_check_retaddr_crashpoint(Rewriter *r, addr_t addr) {
    return !!g_hash_table_lookup(r->retaddr_crashpoints,
                                 GSIZE_TO_POINTER(addr));
}

// XXX: every time we find a new retaddr, we will do following things:
//  1. mark its corresponding callee as returnable (generate a VCP_CALLEE later)
//  2. find all the retaddrs associated with this VCP_CALLEE and patch them
Z_API Buffer *z_rewriter_new_validate_retaddr(Rewriter *r, addr_t retaddr) {
    assert(
        g_hash_table_lookup(r->retaddr_crashpoints, GSIZE_TO_POINTER(retaddr)));

    // step (1). find corresponding callee
    addr_t callee = (addr_t)g_hash_table_lookup(r->retaddr_crashpoints,
                                                GSIZE_TO_POINTER(retaddr));
    if (!callee) {
        // this may happen when the target binary is multi-thread
        return z_buffer_create(NULL, 0);
    }

    // step (2). mark callee as returnable
    g_hash_table_insert(r->returned_callees, GSIZE_TO_POINTER(callee),
                        GSIZE_TO_POINTER(true));

    // step (3). get all retaddrs and remove the entity
    Buffer *buf = (Buffer *)g_hash_table_lookup(r->callee2retaddrs,
                                                GSIZE_TO_POINTER(callee));
    assert(buf);
    g_hash_table_steal(r->callee2retaddrs, GSIZE_TO_POINTER(callee));

    return buf;
}
