#include <elf.h>

#include <capstone/capstone.h>
#include <gmodule.h>

#include "disassembler.h"
#include "elf_.h"
#include "interval_splay.h"
#include "restricted_ptr.h"
#include "utils.h"

static const uint64_t nop_buf = 0x9090909090909090;

/*
 * Function Pointer: destroy a cs_insn
 */
static void __disassembler_free_cs_insn(cs_insn *inst);

/*
 * Function Pointer: compare two address
 */
static int __disassembler_compare_address(addr_t x, addr_t y, void *_z);

/*
 * Patch a uTP
 */
static inline void __disassembler_patch_utp(Disassembler *d, addr_t inst_addr,
                                            cs_insn *inst);

/*
 * Patch a TP
 */
static inline void __disassembler_patch_tp(Disassembler *d, addr_t inst_addr,
                                           cs_insn *inst);

/*
 * Superset disassembly
 */
static inline void __disassembler_superset_disasm(Disassembler *d);

/*
 * Analyse instruction group, return whether need to continue analysis.
 */
static inline bool __disassembler_analyze_inst(Disassembler *d, cs_insn *inst,
                                               addr_t *target);

/*
 * Disassembly _start / .init / .fini / main
 */
static inline void __disassembler_pre_disasm(Disassembler *d);

/*
 * Get possible address of utp
 */
static inline addr_t __disassembler_calculate_utp_addr(Disassembler *d,
                                                       addr_t *inst_addr,
                                                       size_t utp_size,
                                                       cs_insn *inst);

//////////////////////////////////////
// UTP PATCH MAIN CODE START HERE
//////////////////////////////////////
static inline void __disassembler_patch_direct_cjmp_utp(Disassembler *d,
                                                        addr_t inst_addr,
                                                        cs_insn *inst) {
    // [1] get upt_addr
    TP_SIZE(cjmp);
    size_t utp_size = tp_size;
    addr_t new_inst_addr = inst_addr;
    addr_t utp_addr =
        __disassembler_calculate_utp_addr(d, &new_inst_addr, utp_size, inst);

    // [2] validate uTP
    if (utp_addr == ADDR_MAX) {
        d->failed_utp_count++;
        return;
    }

    // [2] basic information
    ELF *e = z_binary_get_elf(d->binary);
    addr_t cjmp_t_addr = (addr_t)(inst->detail->x86.operands[0].imm);
    addr_t cjmp_f_addr = inst_addr + inst->size;
    uint32_t cjmp_id = inst->id;

    // [3] generate utp trampoline
    TP_EMIT_CJMP(utp_addr, cjmp_id, cjmp_t_addr, cjmp_f_addr);
    z_binary_insert_utp(d->binary, utp_addr, tp_code, tp_size);

    // [4] generate patched code
    KS_ASM_JMP(new_inst_addr, utp_addr);

    // [5] do patch
    z_elf_write(e, new_inst_addr, ks_size, ks_encode);

    // [6] patch prefix code
    if (new_inst_addr != inst_addr)
        z_elf_write(e, inst_addr, new_inst_addr - inst_addr, &nop_buf);

    // [7] update count
    d->patched_utp_count++;
}

static inline void __disassembler_patch_direct_jmp_utp(Disassembler *d,
                                                       addr_t inst_addr,
                                                       cs_insn *inst) {
    // [1] get upt_addr
    TP_SIZE(jmp);
    size_t utp_size = tp_size;
    addr_t new_inst_addr = inst_addr;
    addr_t utp_addr =
        __disassembler_calculate_utp_addr(d, &new_inst_addr, utp_size, inst);

    // [2] validate uTP
    if (utp_addr == ADDR_MAX) {
        d->failed_utp_count++;
        return;
    }

    // [2] basic information
    ELF *e = z_binary_get_elf(d->binary);
    addr_t jmp_addr = (addr_t)(inst->detail->x86.operands[0].imm);

    // [3] generate utp trampoline
    TP_EMIT_JMP(utp_addr, jmp_addr);
    z_binary_insert_utp(d->binary, utp_addr, tp_code, tp_size);

    // [4] generate patched code
    KS_ASM_JMP(new_inst_addr, utp_addr);

    // [5] do patch
    z_elf_write(e, new_inst_addr, ks_size, ks_encode);

    // [6] patch prefix code
    if (new_inst_addr != inst_addr)
        z_elf_write(e, inst_addr, new_inst_addr - inst_addr, &nop_buf);

    // [7] update count
    d->patched_utp_count++;
}

//////////////////////////////////////
// TP PATCH MAIN CODE START HERE
//////////////////////////////////////
static inline void __disassembler_patch_direct_cjmp_tp(Disassembler *d,
                                                       addr_t inst_addr,
                                                       cs_insn *inst) {
    // [1] basic information
    addr_t cjmp_t_addr = (addr_t)(inst->detail->x86.operands[0].imm);
    addr_t cjmp_f_addr = inst_addr + inst->size;
    bb_t bb_id = BINARY_CJMP_ID(inst_addr, cjmp_t_addr);

    // [2] insert TP (CJMP cannot have conflict BB_ID)
    addr_t tp_addr = z_binary_next_tp_addr(d->binary);
    TP_EMIT_CJMP(tp_addr, inst->id, cjmp_t_addr, cjmp_f_addr);
    z_binary_insert_tp(d->binary, bb_id, tp_code, tp_size);

    // [3] Generate patched code
    KS_ASM_JMP(inst_addr, tp_addr);

    // [4] Do patch
    ELF *e = z_binary_get_elf(d->binary);
    z_elf_write(e, inst_addr, ks_size, ks_encode);

    // [5] Update count
    d->patched_tp_count++;
}

static inline void __disassembler_patch_direct_jmp_tp(Disassembler *d,
                                                      addr_t inst_addr,
                                                      cs_insn *inst) {
    // [1] basic information
    addr_t jmp_addr = (addr_t)(inst->detail->x86.operands[0].imm);

    // [2] check existed TP
    bb_t bb_id = BINARY_JMP_ID(jmp_addr);
    addr_t tp_addr = z_binary_search_tp(d->binary, bb_id);

    // [3] insert TP if needed
    if (tp_addr == ADDR_MAX) {
        tp_addr = z_binary_next_tp_addr(d->binary);
        TP_EMIT_JMP(tp_addr, jmp_addr);
        z_binary_insert_tp(d->binary, bb_id, tp_code, tp_size);
    }

    // [4] Generate patched code
    KS_ASM_JMP(inst_addr, tp_addr);

    // [5] Do patch
    ELF *e = z_binary_get_elf(d->binary);
    z_elf_write(e, inst_addr, ks_size, ks_encode);

    // [6] Update count
    d->patched_tp_count++;
}

static inline void __disassembler_patch_direct_call_tp(Disassembler *d,
                                                       addr_t inst_addr,
                                                       cs_insn *inst) {
    // [1] basic information
    addr_t continuation_addr = inst_addr + inst->size;
    addr_t callee_addr = (addr_t)(inst->detail->x86.operands[0].imm);

    // [2] check existed TP
    bb_t bb_id = BINARY_CALL_ID(callee_addr);
    addr_t tp_addr = z_binary_search_tp(d->binary, bb_id);

    // [3] insert TP if needed
    if (tp_addr == ADDR_MAX) {
        tp_addr = z_binary_next_tp_addr(d->binary);
        TP_EMIT_CALL(tp_addr, callee_addr, continuation_addr);
        z_binary_insert_tp(d->binary, bb_id, tp_code, tp_size);
    }

    // [4] Generate patched code
    KS_ASM_CALL(inst_addr, tp_addr);

    // [5] Do patch
    ELF *e = z_binary_get_elf(d->binary);
    z_elf_write(e, inst_addr, ks_size, ks_encode);

    // [6] Update count
    d->patched_tp_count++;
}

static inline addr_t __disassembler_calculate_utp_addr(Disassembler *d,
                                                       addr_t *inst_addr,
                                                       size_t utp_size,
                                                       cs_insn *inst) {
    ELF *e = z_binary_get_elf(d->binary);
    bool is_pie = z_elf_get_is_pie(e);

    // [1] get offset buf
    uint64_t tmp = 0;
    addr_t ori_inst_addr = *inst_addr;
    z_elf_read(e, ori_inst_addr, 8, (uint8_t *)(&tmp));

    // [2] prepare init pointer
    uint8_t *buffer = (uint8_t *)(&tmp) + 1;
    size_t buffer_size = inst->size - 1;

    // [3] prepare a utp snode
    Snode *utp = z_snode_create(0, utp_size, NULL, NULL);

    // [4] Brute-force OP inst_addr
    while ((int64_t)buffer_size >= 0) {
        int32_t *offset = (int32_t *)buffer;

        // [4.1] pre-check for non-pie
        if (!is_pie && buffer[3] > 0x7f) goto NEXT;

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

            if (buffer_size == 0) goto NEXT;

            for (size_t i = buffer_size - 1; i >= 0; i--) {
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
    z_warn("fail to find suitable uTP address: %#lx", ori_inst_addr);
    z_snode_destroy(utp);
    return ADDR_MAX;
}

static inline void __disassembler_patch_utp(Disassembler *d, addr_t inst_addr,
                                            cs_insn *inst) {
    assert(d != NULL);

    cs_detail *detail = inst->detail;

    if (detail->x86.operands[0].type == X86_OP_IMM) {
        // direct call/jmp/cjmp
        if (inst->id == X86_INS_CALL) {
            EXITME("There is no short CALL!");
        } else if (inst->id == X86_INS_JMP) {
            __disassembler_patch_direct_jmp_utp(d, inst_addr, inst);
        } else {
            __disassembler_patch_direct_cjmp_utp(d, inst_addr, inst);
        }
    } else {
        // indirect call/jmp
    }
}

static inline void __disassembler_patch_tp(Disassembler *d, addr_t inst_addr,
                                           cs_insn *inst) {
    assert(d != NULL);

    cs_detail *detail = inst->detail;

    if (detail->x86.operands[0].type == X86_OP_IMM) {
        // direct call/jmp/cjmp
        if (inst->id == X86_INS_CALL) {
            __disassembler_patch_direct_call_tp(d, inst_addr, inst);
        } else if (inst->id == X86_INS_JMP) {
            __disassembler_patch_direct_jmp_tp(d, inst_addr, inst);
        } else {
            __disassembler_patch_direct_cjmp_tp(d, inst_addr, inst);
        }
    } else {
        // indirect call/jmp
    }
}

static void __disassembler_free_cs_insn(cs_insn *inst) { cs_free(inst, 1); }

static int __disassembler_compare_address(addr_t x, addr_t y, void *_z) {
    if (x == y)
        return 0;
    else if (x > y)
        return -1;
    else
        return 1;
}

static inline void __disassembler_pre_disasm(Disassembler *d) {
    ELF *e = z_binary_get_elf(d->binary);

    // _start
    addr_t entrypoint = z_elf_get_ori_entry(e);
    z_disassembler_disasm(d, entrypoint, false);

    // .init
    addr_t _init = z_elf_get_shdr_init(e)->sh_addr;
    z_disassembler_disasm(d, _init, false);

    // .fini
    addr_t _fini = z_elf_get_shdr_fini(e)->sh_addr;
    z_disassembler_disasm(d, _fini, false);

    Rptr *array = NULL;
    size_t array_size = 0;
    addr_t array_addr = ADDR_MAX;

    // .init.array
    Elf64_Shdr *init_array = z_elf_get_shdr_init_array(e);
    array_size = init_array->sh_size;
    array_addr = init_array->sh_addr;
    array = z_elf_vaddr2ptr(e, array_addr);
    for (int i = 0; i < array_size / sizeof(addr_t); i++) {
        addr_t fcn = *RPTR_DEFER(array, addr_t);
        z_disassembler_disasm(d, fcn, false);
    }
    z_rptr_destroy(array);

    // .fini.array
    Elf64_Shdr *fini_array = z_elf_get_shdr_fini_array(e);
    array_size = fini_array->sh_size;
    array_addr = fini_array->sh_addr;
    array = z_elf_vaddr2ptr(e, array_addr);
    for (int i = 0; i < array_size / sizeof(addr_t); i++) {
        addr_t fcn = *RPTR_DEFER(array, addr_t);
        z_disassembler_disasm(d, fcn, false);
    }
    z_rptr_destroy(array);

    // main
    z_disassembler_disasm(d, z_elf_get_main(e), true);
}

static inline bool __disassembler_analyze_inst(Disassembler *d, cs_insn *inst,
                                               addr_t *target) {
    cs_detail *detail = inst->detail;
    for (int i = 0; i < detail->groups_count; i++) {
        switch (detail->groups[i]) {
            case X86_GRP_BRANCH_RELATIVE:
            case X86_GRP_JUMP:
            case X86_GRP_CALL:
                if ((detail->x86.op_count == 1) &&
                    (detail->x86.operands[0].type == X86_OP_IMM)) {
                    // direct call and direct/condition jump
                    *target = detail->x86.operands[0].imm;

                    if (inst->id == X86_INS_JMP)
                        return false;
                    else
                        // call and contidional jump
                        // XXX: for call we may need a no-return
                        // analysis
                        return true;
                }

                // indirect call/jump
                z_trace("indirect call/jmp: %#lx\t\t%s %s (%d bytes)",
                        inst->address, inst->mnemonic, inst->op_str,
                        inst->size);
                if (inst->id == X86_INS_CALL)
                    return true;
                else
                    return false;

            case X86_GRP_RET:
            case X86_GRP_INT:
            case X86_GRP_IRET:
            case X86_GRP_PRIVILEGE:
                return false;

            default:
                break;
        }
    }

    return true;
}

static inline void __disassembler_superset_disasm(Disassembler *d) {
    assert(d);

    // step (0). get .text section range.
    ELF *e = z_binary_get_elf(d->binary);
    Elf64_Shdr *text = z_elf_get_shdr_text(e);
    addr_t text_addr = text->sh_addr;
    size_t text_size = text->sh_size;

    z_info("start superset disassembly in [%#lx, %#lx]", text_addr,
           text_size + text_addr - 1);

    // step (1). get code buf
    Rptr *buf = z_elf_vaddr2ptr(e, text_addr);

    // step (2). disassembly
    CS_DETAIL_ON;
    for (addr_t cur_addr = text_addr; cur_addr < text_addr + text_size;
         cur_addr++) {
        CS_DISASM(buf, cur_addr, 1);
        if (cs_count == 1) {
            g_hash_table_insert(d->superset_disasm, GSIZE_TO_POINTER(cur_addr),
                                (gpointer)cs_inst);

            z_trace("superset disassembly: %#lx:\t\t%s %s [%d]", cur_addr,
                    cs_inst->mnemonic, cs_inst->op_str,
                    cs_inst->detail->groups_count);

            cs_inst = NULL;  // avoid double free
        }
        RPTR_INCR(buf, uint8_t, 1);
    }
    CS_DETAIL_OFF;

    z_info("superset disassembly done, found %ld instructions",
           g_hash_table_size(d->superset_disasm));

    // step (3). remember to free code buffer
    z_rptr_destroy(buf);
}

Z_API Disassembler *z_disassembler_create(Binary *b) {
    STRUCT_ALLOC(Disassembler, d);

    d->binary = b;

    d->patched_tp_count = 0;
    d->patched_utp_count = 0;
    d->failed_utp_count = 0;

    d->superset_disasm =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                              (GDestroyNotify)(&__disassembler_free_cs_insn));
    d->recursive_disasm =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    // recursive_disasm does not free cs_insn, freed by superset_disasm

    d->regions = z_splay_create(&z_direct_merge);
    g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    d->unpatched_cf_insts = g_queue_new();

    __disassembler_superset_disasm(d);

    __disassembler_pre_disasm(d);

    return d;
}

Z_API void z_disassembler_destroy(Disassembler *d) {
    g_hash_table_destroy(d->superset_disasm);
    g_hash_table_destroy(d->recursive_disasm);
    g_queue_free(d->unpatched_cf_insts);

    z_splay_destroy(d->regions);
    z_free(d);
}

Z_API void z_disassembler_disasm(Disassembler *d, addr_t addr, bool store_cf) {
    assert(d);
    z_trace("disassemble at %#lx", addr);

    // step (0). get .text section range.
    // We do not disassembly any code outside this range.
    ELF *e = z_binary_get_elf(d->binary);
    Elf64_Shdr *text = z_elf_get_shdr_text(e);
    addr_t text_addr = text->sh_addr;
    size_t text_size = text->sh_size;
    z_trace(".text section: [%#lx, %#lx]", text_addr,
            text_addr + text_size - 1);
    if (!((addr >= text_addr) && (addr - text_addr < text_size))) {
        z_trace("%#lx is out of .text section", addr);
        return;
    }

    // step (1). init queue
    GQueue *q = g_queue_new();
    g_queue_push_tail(q, GSIZE_TO_POINTER(addr));

    // step (2). disassembly until no new target
    while (!g_queue_is_empty(q)) {
        // step (2.1). get starting address
        addr_t bb_addr = (addr_t)g_queue_pop_head(q);
        addr_t cur_addr = bb_addr;
        cs_insn *inst = NULL;

        z_trace("recursive disassembly: BB address [%#lx]", bb_addr);

        // step (2.2). disassembly basic block
        while (true) {
            // [1]. check whether this region is disassembled
            if (z_splay_search(d->regions, cur_addr)) break;

            // [2]. get corresponding instruction
            cs_insn *tmp = (cs_insn *)g_hash_table_lookup(
                d->superset_disasm, GSIZE_TO_POINTER(cur_addr));

            // [3]. check whether it is a valid instruction
            if (tmp == NULL) {
                z_warn("go into an invalid address: %#lx", cur_addr);
                if (inst != NULL)
                    z_warn("previous instruction: %#lx\t\t%s %s", inst->address,
                           inst->mnemonic, inst->op_str);
                break;
            }

            // [4]. add into recursive_disasm;
            inst = tmp;
            z_trace("recursive disassembly: %#lx:\t\t%s %s [%d]", cur_addr,
                    inst->mnemonic, inst->op_str, inst->detail->groups_count);
            g_hash_table_insert(d->recursive_disasm, GSIZE_TO_POINTER(cur_addr),
                                (gpointer)inst);

            // [5]. analyze instruction group
            addr_t target_addr = ADDR_MAX;
            bool do_more = __disassembler_analyze_inst(d, inst, &target_addr);
            z_trace("find target addresss: %#lx", target_addr);

            // [6]. update target
            if (target_addr >= text_addr &&
                target_addr - text_addr < text_size) {
                if (store_cf) {
                    if (inst->size < 5)
                        z_trace(
                            "short direct jmp/call: %#lx\t\t%s %s (%d bytes)",
                            inst->address, inst->mnemonic, inst->op_str,
                            inst->size);
                    else
                        z_trace(
                            "normal direct jmp/call: %#lx\t\t%s %s (%d bytes)",
                            inst->address, inst->mnemonic, inst->op_str,
                            inst->size);
                    g_queue_push_tail(d->unpatched_cf_insts,
                                      GSIZE_TO_POINTER(cur_addr));
                }
                z_trace("find target addresss: %#lx", target_addr);
                g_queue_push_tail(q, GSIZE_TO_POINTER(target_addr));
            } else if (store_cf && target_addr == ADDR_MAX) {
                // check indirect call
                if (inst->id == X86_INS_CALL || inst->id == X86_INS_JMP)
                    g_queue_push_tail(d->unpatched_cf_insts,
                                      GSIZE_TO_POINTER(cur_addr));
            }

            // [7]. update cur_addr
            cur_addr += inst->size;

            // [8]. break if needed
            if (!do_more) break;
        }

        // step (2.3). calculate BB size and insert into regions
        size_t bb_size = cur_addr - bb_addr;
        if (bb_size == 0) continue;
        Snode *node = z_snode_create(bb_addr, bb_size, NULL, NULL);
        node = z_splay_insert(d->regions, node);
        assert(node != NULL);
    }

    // step (3). free queue
    g_queue_free(q);

    // step (4). output how many instruction are correctly disassembly
    z_info("we have %ld correct instructions disassemblied",
           g_hash_table_size(d->recursive_disasm));
    z_info("with %ld unpatched jmp/call",
           g_queue_get_length(d->unpatched_cf_insts));
}

Z_API void z_disassembler_patch_cf(Disassembler *d) {
    assert(d != NULL);

    g_queue_sort(d->unpatched_cf_insts,
                 (GCompareDataFunc)(&__disassembler_compare_address), NULL);

    while (!g_queue_is_empty(d->unpatched_cf_insts)) {
        addr_t cf_addr = (addr_t)g_queue_pop_head(d->unpatched_cf_insts);
        z_trace("work on %#lx", cf_addr);

        cs_insn *inst = (cs_insn *)g_hash_table_lookup(
            d->recursive_disasm, GSIZE_TO_POINTER(cf_addr));
        assert(inst != NULL);

        // XXX: remember to fix patched pre-jmp (new idea!)

        if (inst->size >= 5)
            __disassembler_patch_tp(d, cf_addr, inst);
        else
            __disassembler_patch_utp(d, cf_addr, inst);
    }

    z_info("total patched TP: %ld", d->patched_tp_count);
    z_info("total patched uTP: %ld", d->patched_utp_count);
    z_info("total failed uTP: %ld", d->failed_utp_count);
}
