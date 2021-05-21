#include "disassembler.h"
#include "capstone_.h"
#include "elf_.h"
#include "interval_splay.h"
#include "restricted_ptr.h"
#include "utils.h"

#include <capstone/capstone.h>
#include <elf.h>
#include <gmodule.h>

#include "prob_disasm/prob_disasm_complete.c"
#include "prob_disasm/prob_disasm_simple.c"

#define SUPERSET_DISASM_THRESHOLD 0x400000

/*
 * Runtime binding for probabilistic disassembly
 */
#define __disassembler_invoke_prob_disasm(d, func, __args...) \
    ({ (d->enable_pdisasm ? func(__args) : func##_S(__args)); })

/*
 * Function Pointer: destroy a cs_insn
 */
Z_PRIVATE void __disassembler_free_cs_insn(cs_insn *inst);

/*
 * Superset disassembly
 */
Z_PRIVATE void __disassembler_superset_disasm(Disassembler *d);

/*
 * Check whether underlying binary has inlined data (potentially)
 */
Z_PRIVATE bool __disassembler_has_inlined_data(Disassembler *d);

/*
 * Analyse instruction group, return whether need to continue analysis.
 */
Z_PRIVATE bool __disassembler_analyze_inst(cs_insn *inst, addr_t *target);

/*
 * Disassembly _start / .init / .fini / main
 */
Z_RESERVED Z_PRIVATE void __disassembler_pre_disasm(Disassembler *d);

/*
 * Getter and Setter
 */
DEFINE_GETTER(Disassembler, disassembler, Binary *, binary);
DEFINE_GETTER(Disassembler, disassembler, UCFG_Analyzer *, ucfg_analyzer);
DEFINE_GETTER(Disassembler, disassembler, bool, enable_pdisasm);

Z_PRIVATE void __disassembler_free_cs_insn(cs_insn *inst) { cs_free(inst, 1); }

/*
 * XXX: This function is out of date. Hence, there is no guarantee to use it.
 */
Z_RESERVED Z_PRIVATE void __disassembler_pre_disasm(Disassembler *d) {
    ELF *e = z_binary_get_elf(d->binary);

    z_info("disassemble .init/.fini");

    GQueue *bbs = g_queue_new();

    // _start
    addr_t entrypoint = z_elf_get_ori_entry(e);
    g_queue_push_tail(bbs, GSIZE_TO_POINTER(entrypoint));

    // .init
    addr_t _init = z_elf_get_init(e);
    z_info(".init: %#lx", _init);
    g_queue_push_tail(bbs, GSIZE_TO_POINTER(_init));

    // .fini
    addr_t _fini = z_elf_get_fini(e);
    z_info(".fini: %#lx", _fini);
    g_queue_push_tail(bbs, GSIZE_TO_POINTER(_fini));

    Rptr *array = NULL;
    size_t array_size = 0;
    addr_t array_addr = INVALID_ADDR;

    // .init.array
    Elf64_Shdr *init_array = z_elf_get_shdr_init_array(e);
    array_size = init_array->sh_size;
    array_addr = init_array->sh_addr;
    array = z_elf_vaddr2ptr(e, array_addr);
    for (int i = 0; i < array_size / sizeof(addr_t); i++) {
        addr_t fcn = *z_rptr_get_ptr(array, addr_t);
        z_info(".init.array[%d]: %#lx", i, fcn);
        g_queue_push_tail(bbs, GSIZE_TO_POINTER(fcn));
        z_rptr_inc(array, addr_t, 1);
    }
    z_rptr_destroy(array);

    // .fini.array
    Elf64_Shdr *fini_array = z_elf_get_shdr_fini_array(e);
    array_size = fini_array->sh_size;
    array_addr = fini_array->sh_addr;
    array = z_elf_vaddr2ptr(e, array_addr);
    for (int i = 0; i < array_size / sizeof(addr_t); i++) {
        addr_t fcn = *z_rptr_get_ptr(array, addr_t);
        z_info(".fini.array[%d]: %#lx", i, fcn);
        g_queue_push_tail(bbs, GSIZE_TO_POINTER(fcn));
        z_rptr_inc(array, addr_t, 1);
    }
    z_rptr_destroy(array);

    // disassemble without call
    while (!g_queue_is_empty(bbs)) {
        addr_t bb_addr = (addr_t)g_queue_pop_head(bbs);

        addr_t cur_addr = bb_addr;
        cs_insn *inst = NULL;

        do {
            if (g_hash_table_lookup(d->potential_insts,
                                    GSIZE_TO_POINTER(cur_addr))) {
                break;
            }

            inst = z_disassembler_get_superset_disasm(d, cur_addr);
            if (inst == NULL) {
                break;
            }

            g_hash_table_insert(d->recursive_disasm, GSIZE_TO_POINTER(cur_addr),
                                (gpointer)inst);

            if (z_capstone_is_jmp(inst) || z_capstone_is_cjmp(inst) ||
                z_capstone_is_loop(inst) || z_capstone_is_xbegin(inst)) {
                cs_detail *detail = inst->detail;
                if ((detail->x86.op_count == 1) &&
                    (detail->x86.operands[0].type == X86_OP_IMM)) {
                    g_queue_push_tail(
                        bbs, GSIZE_TO_POINTER(detail->x86.operands[0].imm));
                }
            }

            cur_addr += inst->size;
        } while (!z_capstone_is_terminator(inst));
    }

    z_info("disassemble .init/.fini done");
    z_info("we have %ld correct instructions disassemblied",
           g_hash_table_size(d->recursive_disasm));
}

// XXX: here we simply check whether linear disassembly can decode all
// instructions (which seems good enough for most cases), but we can have
// advanced algorithms in the future (e.g., using entropy or data hints from
// probabilistic disassembly)
Z_PRIVATE bool __disassembler_has_inlined_data(Disassembler *d) {
    assert(d != NULL);

    addr_t cur_addr = d->text_addr;
    do {
        cs_insn *cur_inst = z_disassembler_get_superset_disasm(d, cur_addr);
        if (!cur_inst) {
            return true;
        }
        cur_addr += cur_inst->size;
    } while (cur_addr < d->text_addr + d->text_size);

    return false;
}

// XXX: we do not use UCFG_Analyzer here, as the following code runs faster than
// a searching operation in hashmap. Note that the following code will happen
// during fuzzing
Z_PRIVATE bool __disassembler_analyze_inst(cs_insn *inst, addr_t *targets) {
    assert(inst != NULL);

    cs_detail *detail = inst->detail;

    if (z_capstone_is_cjmp(inst) || z_capstone_is_loop(inst)) {
        assert((detail->x86.op_count == 1) &&
               (detail->x86.operands[0].type == X86_OP_IMM));

        *(targets++) = inst->address + inst->size;
        *targets = detail->x86.operands[0].imm;

    } else if (z_capstone_is_jmp(inst) || z_capstone_is_call(inst) ||
               z_capstone_is_xbegin(inst)) {
        if ((detail->x86.op_count == 1) &&
            (detail->x86.operands[0].type == X86_OP_IMM)) {
            // direct call and direct/condition jump
            *targets = detail->x86.operands[0].imm;
        } else {
            // indirect call/jump
            z_trace("indirect call/jmp " CS_SHOW_INST(inst));
        }
    }

    return !z_capstone_is_terminator(inst);
}

Z_PRIVATE void __disassembler_superset_disasm(Disassembler *d) {
    assert(d);

    // step (0). get .text section range.
    ELF *e = z_binary_get_elf(d->binary);
    addr_t text_addr = d->text_addr;
    size_t text_size = d->text_size;

    z_info("start superset disassembly in [%#lx, %#lx]", text_addr,
           text_size + text_addr - 1);

    // step (1). get code buf
    Rptr *buf = z_elf_vaddr2ptr(e, text_addr);

    // step (2). disassembly
    for (addr_t cur_addr = text_addr; cur_addr < text_addr + text_size;
         cur_addr++) {
        CS_DISASM(buf, cur_addr, 1);
        if (cs_count == 1) {
            z_ucfg_analyzer_add_inst(d->ucfg_analyzer, cur_addr, cs_inst,
                                     false);
            g_hash_table_insert(d->superset_disasm, GSIZE_TO_POINTER(cur_addr),
                                (gpointer)cs_inst);
            z_addr_dict_set(d->occ_addrs, cur_addr, z_buffer_create(NULL, 0));

            z_trace("superset disassembly " CS_SHOW_INST(cs_inst));

            cs_inst = NULL;  // avoid double free
        }
        z_rptr_inc(buf, uint8_t, 1);
    }

    z_info("superset disassembly done, found %ld instructions",
           g_hash_table_size(d->superset_disasm));

    // step (3). remember to free code buffer
    z_rptr_destroy(buf);

    // step (4). calculate occluded address
    for (addr_t cur_addr = text_addr; cur_addr < text_addr + text_size;
         cur_addr++) {
        // validation
        cs_insn *inst = (cs_insn *)g_hash_table_lookup(
            d->superset_disasm, GSIZE_TO_POINTER(cur_addr));
        if (!inst) {
            continue;
        }

        // find all possible occluded instructions
        for (addr_t occ_addr = cur_addr + 1; occ_addr < cur_addr + inst->size;
             occ_addr++) {
            cs_insn *occ_inst = (cs_insn *)g_hash_table_lookup(
                d->superset_disasm, GSIZE_TO_POINTER(occ_addr));
            if (!occ_inst) {
                continue;
            }

            // update both
            z_buffer_append_raw(z_addr_dict_get(d->occ_addrs, cur_addr),
                                (uint8_t *)&occ_addr, sizeof(occ_addr));
            z_buffer_append_raw(z_addr_dict_get(d->occ_addrs, occ_addr),
                                (uint8_t *)&cur_addr, sizeof(cur_addr));
        }
    }
}

Z_API Disassembler *z_disassembler_create(Binary *b, SysOptArgs *opts) {
    Disassembler *d = STRUCT_ALLOC(Disassembler);

    d->opts = opts;

    d->binary = b;

    d->superset_disasm =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                              (GDestroyNotify)(&__disassembler_free_cs_insn));
    d->recursive_disasm =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    // recursive_disasm does not free cs_insn, freed by superset_disasm
    d->linear_disasm =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    // linear_disasm does not free cs_insn, freed by superset_disasm
    d->prob_disasm = NULL;

    d->potential_insts =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    d->potential_blocks =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    d->ucfg_analyzer = z_ucfg_analyzer_create(d->opts);

    // we choose to superset disassemble relative-small binary
    ELF *e = z_binary_get_elf(d->binary);
    Elf64_Shdr *text = z_elf_get_shdr_text(e);
    d->text_addr = text->sh_addr;
    d->text_size = text->sh_size;

    // get occluded address
    z_addr_dict_init(d->occ_addrs, d->text_addr, d->text_size);

    if (d->text_size <= SUPERSET_DISASM_THRESHOLD) {
        z_info(".text section (%#lx bytes) is suitable for pre-disasm",
               d->text_size);

        // do not backup .text
        d->text_backup = NULL;

        __disassembler_superset_disasm(d);
    } else {
        z_info(".text section (%#lx bytes) is not suitable for pre-disasm",
               d->text_size);

        d->text_backup = z_alloc(d->text_size, sizeof(uint8_t));
        Rptr *ptr = z_elf_vaddr2ptr(e, d->text_addr);
        z_rptr_memcpy(d->text_backup, ptr, d->text_size);
        z_rptr_destroy(ptr);
    }

    d->enable_pdisasm =
        (!d->opts->force_linear) &&
        (d->opts->force_pdisasm || __disassembler_has_inlined_data(d));
    z_info("enable probabilistic disassembly: %s",
           d->enable_pdisasm ? "true" : "false");

    __disassembler_invoke_prob_disasm(d, __disassembler_pdisasm_create, d);
    return d;
}

Z_API void z_disassembler_destroy(Disassembler *d) {
    __disassembler_invoke_prob_disasm(d, __disassembler_pdisasm_destroy, d);

    g_hash_table_destroy(d->superset_disasm);
    g_hash_table_destroy(d->recursive_disasm);
    g_hash_table_destroy(d->linear_disasm);

    if (d->text_backup) {
        z_free(d->text_backup);
    }

    g_hash_table_destroy(d->potential_insts);
    g_hash_table_destroy(d->potential_blocks);

    z_addr_dict_destroy(d->occ_addrs, &z_buffer_destroy);

    z_ucfg_analyzer_destroy(d->ucfg_analyzer);

    z_free(d);
}

Z_API void z_disassembler_get_prob_disasm_internal(
    Disassembler *d, addr_t addr, cs_insn **inst, uint32_t *scc_id,
    double128_t *inst_hint, double128_t *inst_lost, double128_t *data_hint,
    double128_t *D, double128_t *P) {
    __disassembler_invoke_prob_disasm(d, __disassembler_pdisasm_get_internal, d,
                                      addr, inst, scc_id, inst_hint, inst_lost,
                                      data_hint, D, P);
}

Z_API void z_disassembler_prob_disasm(Disassembler *d) {
    __disassembler_invoke_prob_disasm(d, __disassembler_pdisasm_start, d);
}

Z_API double128_t z_disassembler_get_prob_disasm(Disassembler *d, addr_t addr) {
    return __disassembler_invoke_prob_disasm(
        d, __disassembler_pdisasm_get_inst_prob, d, addr);
}

Z_API void z_diassembler_update_prob_disasm(Disassembler *d, addr_t addr,
                                            bool is_inst) {
    __disassembler_invoke_prob_disasm(d, __disassembler_pdisasm_update, d, addr,
                                      is_inst);
}

// XXX: note that this function is not completed.
Z_API GQueue *z_disassembler_linear_disasm(Disassembler *d) {
    assert(d != NULL);

    // step (0). get .text section range.
    addr_t text_addr = d->text_addr;
    size_t text_size = d->text_size;

    // step (1). other structures
    addr_t cur_addr = text_addr;
    GQueue *bbs = g_queue_new();
    g_queue_push_tail(bbs, GSIZE_TO_POINTER(cur_addr));  // first addr is a BB

    // step (2). linear disassembler
    GQueue *tmp_bbs = g_queue_new();
    GQueue *tmp_insts = g_queue_new();
    while (cur_addr < text_addr + text_size) {
        bool valid_bb = true;
        addr_t tmp_cur_addr = cur_addr;

        // step (2.1) use inner loop to check whether current basic block is
        // valid. Note that when the inner exits, the tmp_cur_addr is always the
        // next no-tried instruction address
        do {
            cs_insn *inst = z_disassembler_get_superset_disasm(d, tmp_cur_addr);

            // check instruction itself
            if (inst == NULL) {
                z_trace("invalid instruction in linear disassembly: %#lx",
                        tmp_cur_addr);
                valid_bb = false;
                break;
            }

            // check branch instructions and update basic block information
            cs_detail *detail = inst->detail;
            if ((z_capstone_is_call(inst) || z_capstone_is_cjmp(inst) ||
                 z_capstone_is_xbegin(inst) || z_capstone_is_loop(inst) ||
                 z_capstone_is_jmp(inst)) &&  // check instruction type
                ((detail->x86.op_count == 1) &&
                 (detail->x86.operands[0].type ==
                  X86_OP_IMM))  // check direct transfer
            ) {
                addr_t tar_addr = detail->x86.operands[0].imm;
                if (tar_addr >= text_addr && tar_addr < text_addr + text_size) {
                    // target address inside .text
                    // TODO: acutally, we should check for linear disassembly
                    // result, instead of superset disassembly!
                    if (z_disassembler_get_superset_disasm(d, tar_addr)) {
                        g_queue_push_tail(tmp_bbs, GSIZE_TO_POINTER(tar_addr));
                    } else {
                        z_trace(
                            "invalid instruction in linear disassembly "
                            "(target): %#lx",
                            tmp_cur_addr);
                        valid_bb = false;
                        break;
                    }
                }
            }

            // TODO: do not forget cjmp and loop's false branch

            // update instruction
            g_queue_push_tail(tmp_insts, GSIZE_TO_POINTER(tmp_cur_addr));

            // update tmp_cur_addr
            tmp_cur_addr += inst->size;

            // if inst is terminator, break temporary try
            if (z_capstone_is_terminator(inst)) {
                break;
            }
        } while (tmp_cur_addr < text_addr + text_size);

        if (valid_bb) {
            // step (2.2): if valid, update bbs and insts, and update cur_addr.
            //      Note that original cur_addr is another bb entrypoint.
            g_queue_push_tail(bbs, GSIZE_TO_POINTER(cur_addr));
            g_hash_table_insert(d->potential_blocks, GSIZE_TO_POINTER(cur_addr),
                                GSIZE_TO_POINTER(true));
            while (!g_queue_is_empty(tmp_bbs)) {
                addr_t bb_addr = (addr_t)g_queue_pop_head(tmp_bbs);
                g_queue_push_tail(bbs, GSIZE_TO_POINTER(bb_addr));
                g_hash_table_insert(d->potential_blocks,
                                    GSIZE_TO_POINTER(bb_addr),
                                    GSIZE_TO_POINTER(true));
            }
            while (!g_queue_is_empty(tmp_insts)) {
                addr_t inst_addr = (addr_t)g_queue_pop_head(tmp_insts);
                cs_insn *inst =
                    z_disassembler_get_superset_disasm(d, inst_addr);
                assert(inst);
                g_hash_table_insert(d->linear_disasm,
                                    GSIZE_TO_POINTER(inst_addr),
                                    (gpointer)inst);
                g_hash_table_insert(d->potential_insts,
                                    GSIZE_TO_POINTER(inst_addr),
                                    (gpointer)inst);
            }
            cur_addr = tmp_cur_addr;
        } else {
            // setp (2.3): if not valid, inc cur_addr and clear tmp_bbs/_insts
            g_queue_clear(tmp_bbs);
            g_queue_clear(tmp_insts);
            cur_addr += 1;
        }
    }

    g_queue_free(tmp_bbs);
    g_queue_free(tmp_insts);

    z_info("we have %ld instruction linearly disassemblied",
           g_hash_table_size(d->linear_disasm));

    z_info("with %ld basic block entrys", g_queue_get_length(bbs));

    return bbs;
}

Z_API GQueue *z_disassembler_recursive_disasm(Disassembler *d, addr_t addr) {
    assert(d);
    z_trace("disassemble at %#lx", addr);

    GQueue *new_bbs = g_queue_new();

    // step (0). get .text section range.
    // We do not disassembly any code outside this range.
    addr_t text_addr = d->text_addr;
    size_t text_size = d->text_size;
    z_trace(".text section: [%#lx, %#lx]", text_addr,
            text_addr + text_size - 1);
    if (!((addr >= text_addr) && (addr - text_addr < text_size))) {
        z_warn("%#lx is out of .text section", addr);
        return new_bbs;
    }

    // step (1). check addr is an new BB (XXX: this might be wrong)
    if (!g_hash_table_lookup(d->potential_blocks, GSIZE_TO_POINTER(addr))) {
        g_queue_push_tail(new_bbs, GSIZE_TO_POINTER(addr));
        g_hash_table_insert(d->potential_blocks, GSIZE_TO_POINTER(addr),
                            GSIZE_TO_POINTER(true));
    }

    // step (2). init queue
    GQueue *q = g_queue_new();
    g_queue_push_tail(q, GSIZE_TO_POINTER(addr));

    // step (3). disassembly until no new target
    while (!g_queue_is_empty(q)) {
        // step (3.1). get starting address
        addr_t bb_addr = (addr_t)g_queue_pop_head(q);
        addr_t cur_addr = bb_addr;
        cs_insn *inst = NULL;

        z_trace("recursive disassembly: BB address [%#lx]", bb_addr);

        // step (3.2). disassembly basic block
        while (true) {
            // [1]. check whether this region is disassembled
            if (g_hash_table_lookup(d->potential_insts,
                                    GSIZE_TO_POINTER(cur_addr))) {
                break;
            }

            // [2]. get corresponding instruction
            cs_insn *tmp = z_disassembler_get_superset_disasm(d, cur_addr);

            // [3]. check whether it is a valid instruction
            if (tmp == NULL) {
                z_warn("go into an invalid address: %#lx", cur_addr);
                if (inst != NULL) {
                    z_warn("previous instruction " CS_SHOW_INST(inst));
                }
                break;
            }

            // [4]. add into recursive_disasm and update potential instruction
            inst = tmp;
            z_trace("recursive disassembly " CS_SHOW_INST(inst));
            g_hash_table_insert(d->recursive_disasm, GSIZE_TO_POINTER(cur_addr),
                                (gpointer)inst);
            g_hash_table_insert(d->potential_insts, GSIZE_TO_POINTER(cur_addr),
                                (gpointer)inst);

            // [5]. analyze instruction group
            addr_t target_addrs[2] = {INVALID_ADDR, INVALID_ADDR};
            bool do_more = __disassembler_analyze_inst(inst, target_addrs);
            z_trace("find target addresss: %#lx %#lx", target_addrs[0],
                    target_addrs[1]);

            // [6]. update target
            for (int i = 0; i < 2; i++) {
                addr_t target_addr = target_addrs[i];
                if (target_addr >= text_addr &&
                    target_addr - text_addr < text_size) {
                    g_queue_push_tail(q, GSIZE_TO_POINTER(target_addr));

                    z_trace("find new target: %#lx", target_addr);

                    if (!g_hash_table_lookup(d->potential_blocks,
                                             GSIZE_TO_POINTER(target_addr))) {
                        g_queue_push_tail(new_bbs,
                                          GSIZE_TO_POINTER(target_addr));

                        g_hash_table_insert(d->potential_blocks,
                                            GSIZE_TO_POINTER(target_addr),
                                            GSIZE_TO_POINTER(true));
                    }
                }
            }

            // [7]. update cur_addr
            cur_addr += inst->size;

            // [8]. break if needed
            if (!do_more) {
                break;
            }
        }
    }

    // step (4). free queue
    g_queue_free(q);

    // step (5). output how many instruction are correctly disassembly
    z_info("number of new basic blocks      : %ld",
           g_queue_get_length(new_bbs));
    z_info("number of rewritten instructions: %ld",
           g_hash_table_size(d->recursive_disasm));

    return new_bbs;
}

// update superset disasm
Z_API const cs_insn *z_disassembler_update_superset_disasm(Disassembler *d,
                                                           addr_t addr) {
    const cs_insn *res = NULL;

    addr_t text_addr = d->text_addr;
    size_t text_size = d->text_size;
    if (addr < text_addr || addr >= text_addr + text_size) {
        EXITME("try to re-disasm an invalid address: %#lx", addr);
    }

    if (z_disassembler_is_potential_inst_entrypoint(d, addr)) {
        EXITME("try to re-disasm a validated address: %#lx", addr);
    }

    ELF *e = z_binary_get_elf(d->binary);
    Rptr *ptr = z_elf_vaddr2ptr(e, addr);
    CS_DISASM(ptr, addr, 1);
    if (cs_count == 1) {
        // update superset disassembly
        // XXX: the z_ucfg_analyzer_add_inst must be placed before
        // g_hash_table_insert, as the g_hash_table_insert may free the original
        // instruction
        z_ucfg_analyzer_add_inst(d->ucfg_analyzer, addr, cs_inst, true);
        g_hash_table_insert(d->superset_disasm, GSIZE_TO_POINTER(addr),
                            (gpointer)cs_inst);
        res = cs_inst;

        // update backup
        if (d->text_backup) {
            size_t off = addr - text_addr;
            memcpy(d->text_backup + off, res->bytes, res->size);
        }

        cs_inst = NULL;  // avoid double free
    } else {
        EXITME("invalid instruction at %#lx", addr);
    }

    z_rptr_destroy(ptr);
    assert(res != NULL);
    return res;
}

Z_API cs_insn *z_disassembler_get_superset_disasm(Disassembler *d,
                                                  addr_t addr) {
    cs_insn *inst = (cs_insn *)g_hash_table_lookup(d->superset_disasm,
                                                   GSIZE_TO_POINTER(addr));

    // check whether we need to update superset disasm
    if (d->text_backup && (!inst)) {
        // step(1). check addr in .text (we only consider code in .text)
        addr_t text_addr = d->text_addr;
        size_t text_size = d->text_size;
        if (addr < text_addr || addr >= text_addr + text_size) {
            return NULL;
        }

        // step(2). disasm non-disassembled instruction
        size_t off1 = addr - text_addr;
        size_t off2 = text_size - off1;
        CS_DISASM_RAW(d->text_backup + off1, off2, addr, 1);
        if (cs_count == 1) {
            z_ucfg_analyzer_add_inst(d->ucfg_analyzer, addr, cs_inst, false);
            g_hash_table_insert(d->superset_disasm, GSIZE_TO_POINTER(addr),
                                (gpointer)cs_inst);

            z_trace("superset disassembly " CS_SHOW_INST(cs_inst));

            inst = (cs_insn *)cs_inst;
            cs_inst = NULL;  // avoid double free
        }
    }

    return inst;
}

Z_API cs_insn *z_disassembler_get_recursive_disasm(Disassembler *d,
                                                   addr_t addr) {
    return (cs_insn *)g_hash_table_lookup(d->recursive_disasm,
                                          GSIZE_TO_POINTER(addr));
}

Z_API cs_insn *z_disassembler_get_linear_disasm(Disassembler *d, addr_t addr) {
    return (cs_insn *)g_hash_table_lookup(d->linear_disasm,
                                          GSIZE_TO_POINTER(addr));
}

Z_API bool z_disassembler_is_potential_block_entrypoint(Disassembler *d,
                                                        addr_t addr) {
    return !!g_hash_table_lookup(d->potential_blocks, GSIZE_TO_POINTER(addr));
}

Z_API bool z_disassembler_is_potential_inst_entrypoint(Disassembler *d,
                                                       addr_t addr) {
    return !!g_hash_table_lookup(d->potential_insts, GSIZE_TO_POINTER(addr));
}

Z_API bool z_disassembler_is_within_disasm_range(Disassembler *d, addr_t addr) {
    return !!(addr >= d->text_addr && addr < (d->text_addr + d->text_size));
}

Z_API Buffer *z_disassembler_get_occluded_addrs(Disassembler *d, addr_t addr) {
    cs_insn *inst = z_disassembler_get_superset_disasm(d, addr);
    if (!inst) {
        return NULL;
    }

    if (!z_addr_dict_exist(d->occ_addrs, addr)) {
        // occluded address hasn't been analyzed
        z_addr_dict_set(d->occ_addrs, addr, z_buffer_create(NULL, 0));

        // note that the longest x86/64 instruction is 15-bytes
        for (addr_t occ_addr = addr - 14; occ_addr < addr + inst->size;
             occ_addr++) {
            cs_insn *occ_inst = z_disassembler_get_superset_disasm(d, occ_addr);
            if (!occ_inst) {
                continue;
            }

            if (occ_addr < addr && occ_addr + occ_inst->size > addr) {
                goto SUCC;
            }
            if (occ_addr > addr && addr + inst->size > occ_addr) {
                goto SUCC;
            }
            continue;

        SUCC:
            z_buffer_append_raw(z_addr_dict_get(d->occ_addrs, addr),
                                (uint8_t *)&occ_addr, sizeof(occ_addr));
        }
    }

    return z_addr_dict_get(d->occ_addrs, addr);
}

Z_API bool z_disassembler_fully_support_prob_disasm(Disassembler *d) {
    return !z_strcmp("ProbDisassembler", STRUCT_TYPE(d->prob_disasm));
}

Z_API Buffer *z_disassembler_get_direct_predecessors(Disassembler *d,
                                                     addr_t addr) {
    // force superset disasm
    if (d->text_backup) {
        z_disassembler_get_superset_disasm(d, addr);
    }

    return z_ucfg_analyzer_get_direct_predecessors(d->ucfg_analyzer, addr);
}

Z_API Buffer *z_disassembler_get_direct_successors(Disassembler *d,
                                                   addr_t addr) {
    // force superset disasm
    if (d->text_backup) {
        z_disassembler_get_superset_disasm(d, addr);
    }

    return z_ucfg_analyzer_get_direct_successors(d->ucfg_analyzer, addr);
}
