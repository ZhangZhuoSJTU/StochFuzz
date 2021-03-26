#include "patcher.h"
#include "interval_splay.h"
#include "iterator.h"
#include "utils.h"

#include <math.h>

#define PATCH_THRESHOLD 0.99999
#define PATCH_RET_DEPTH 20

static const char __invalid_inst_buf[16] = {0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f,
                                            0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f,
                                            0x2f, 0x2f, 0x2f, 0x2f};

/*
 * When the underlying disassembler does not fully support prob-disasm, we
 * directly patch all possible instructions without calculating pathcing
 * candidates.
 */
Z_PRIVATE void __patcher_patch_all_S(Patcher *p);

/*
 * When the underlying fully supports prob-disasm, we need to carefully decide
 * which the patch candidates are.
 */
Z_PRIVATE void __patcher_patch_all_F(Patcher *p);

/*
 * Real patching function
 */
Z_PRIVATE void __patcher_patch(Patcher *p, addr_t addr, size_t size,
                               const void *buf);

/*
 * Find new certain addresses via BFS
 */
Z_PRIVATE void __patcher_bfs_certain_addresses(Patcher *p, addr_t addr);

/*
 * Patch a new certain address
 */
Z_PRIVATE void __patcher_patch_certain_address(Patcher *p, addr_t addr,
                                               bool is_inst_boundary);

Z_PRIVATE void __patcher_patch_certain_address(Patcher *p, addr_t addr,
                                               bool is_inst_boundary) {
    assert(!z_addr_dict_exist(p->certain_addresses, addr));

    // step (1). set certain_addresses
    z_addr_dict_set(p->certain_addresses, addr, is_inst_boundary);

    // step (2). patch underlying binary
    __patcher_patch(p, addr, 1, __invalid_inst_buf);

    // TODO: update to uncertain_/certain_ patches
    g_hash_table_insert(p->checkpoints, GSIZE_TO_POINTER(addr),
                        GSIZE_TO_POINTER(1));
}

Z_PRIVATE void __patcher_bfs_certain_addresses(Patcher *p, addr_t addr) {
    // step (0). a quick check of whether addr is already known
    if (z_addr_dict_exist(p->certain_addresses, addr)) {
        return;
    }

    Disassembler *d = p->disassembler;
    addr_t text_addr = p->text_addr;
    size_t text_size = p->text_size;

    // step (1). BFS to find all certain addresses
    GQueue *queue = g_queue_new();
    g_queue_push_tail(queue, GSIZE_TO_POINTER(addr));

    while (!g_queue_is_empty(queue)) {
        // step (3.1). pop from queue and get basic information
        addr_t cur_addr = (addr_t)g_queue_pop_head(queue);

        // step (3.2). update certain_addresses (true means it is an instruction
        // boundary, otherwise false)
        if (z_addr_dict_exist(p->certain_addresses, cur_addr)) {
            // XXX: there are two cases of duplicate updating:
            //  a: we push the same instruction into the queue twice
            //  b: there is an overlapping instruction caused by *LOCK* prefix
            // The other two assertions have the same situation.
            assert(z_addr_dict_get(p->certain_addresses, cur_addr) ||
                   (z_addr_dict_get(p->certain_addresses, cur_addr - 1) &&
                    z_disassembler_get_superset_disasm(d, cur_addr - 1)
                            ->detail->x86.prefix[0] == X86_PREFIX_LOCK));
            continue;
        }

        cs_insn *cur_inst = z_disassembler_get_superset_disasm(d, cur_addr);
        assert(cur_inst);
        z_trace("find a certain address " CS_SHOW_INST(cur_inst));

        for (int i = 0; i < cur_inst->size; i++) {
            if (z_addr_dict_exist(p->certain_addresses, cur_addr + i)) {
                // XXX: avoid rewriting the instruction boundary
                assert(i == 1 &&
                       z_addr_dict_get(p->certain_addresses, cur_addr + i) &&
                       cur_inst->detail->x86.prefix[0] == X86_PREFIX_LOCK);
                break;
            }
            __patcher_patch_certain_address(p, cur_addr + i, i == 0);
        }

        // step (3.3). check successors
        Iter(addr_t, succ_addrs);
        z_iter_init_from_buf(succ_addrs,
                             z_disassembler_get_successors(d, cur_addr));
        while (!z_iter_is_empty(succ_addrs)) {
            addr_t succ_addr = *(z_iter_next(succ_addrs));

            // ignore the one which is not in .text
            if (succ_addr < text_addr || succ_addr >= text_addr + text_size) {
                continue;
            }

            if (z_addr_dict_exist(p->certain_addresses, succ_addr)) {
                assert(z_addr_dict_get(p->certain_addresses, cur_addr) ||
                       (z_addr_dict_get(p->certain_addresses, cur_addr - 1) &&
                        z_disassembler_get_superset_disasm(d, cur_addr - 1)
                                ->detail->x86.prefix[0] == X86_PREFIX_LOCK));
                continue;
            }

            g_queue_push_tail(queue, GSIZE_TO_POINTER(succ_addr));
        }
        z_iter_destroy(succ_addrs);
    }

    // step (2). free queue
    g_queue_free(queue);
}

Z_PRIVATE void __patcher_patch(Patcher *p, addr_t addr, size_t size,
                               const void *buf) {
    ELF *e = z_binary_get_elf(p->binary);
    z_elf_write(e, addr, size, buf);
}

Z_PRIVATE void __patcher_patch_all_F(Patcher *p) {
    Disassembler *d = p->disassembler;
    ELF *e = z_binary_get_elf(p->binary);

    addr_t text_addr = p->text_addr;
    size_t text_size = p->text_size;

    // we first patch call/cjmp/jmp (at least 5 bytes)
    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
        if (z_disassembler_get_prob_disasm(d, addr) < PATCH_THRESHOLD) {
            goto NEXT_ADDR;
        }

        cs_insn *inst = z_disassembler_get_superset_disasm(d, addr);
        assert(inst);

        if (!z_capstone_is_call(inst) && !z_capstone_is_ret(inst) &&
            !z_capstone_is_cjmp(inst) && !z_capstone_is_jmp(inst)) {
            goto NEXT_ADDR;
        }

        // check RET without number
        if (z_capstone_is_ret(inst) && inst->detail->x86.op_count) {
            goto NEXT_ADDR;
        }

        addr_t end_addr = addr + inst->size;
        addr_t cur_addr = addr;

        // guarantee at least 5 bytes
        while (end_addr - cur_addr < 5) {
            Iter(addr_t, pred_addrs);
            z_iter_init_from_buf(pred_addrs,
                                 z_disassembler_get_predecessors(d, cur_addr));

            bool found = false;
            addr_t pred_addr = INVALID_ADDR;

            while (!z_iter_is_empty(pred_addrs)) {
                addr_t pred_addr_ = *(z_iter_next(pred_addrs));

                // check the operand is not single-byte-length
                cs_insn *pred_inst_ =
                    z_disassembler_get_superset_disasm(d, pred_addr_);
                if (!pred_inst_) {
                    continue;
                }
                cs_detail *pred_detail_ = pred_inst_->detail;
                if (pred_detail_->x86.op_count >= 1) {
                    if (pred_detail_->x86.operands[0].size == 1) {
                        continue;
                    }
                }

                // check probability
                if (z_disassembler_get_prob_disasm(d, pred_addr_) <
                    PATCH_THRESHOLD) {
                    continue;
                }

                // multiple valid predecessors
                if (found) {
                    goto NEXT_ADDR;
                }

                found = true;
                pred_addr = pred_addr_;
            }

            if (!found) {
                goto NEXT_ADDR;
            }

            cs_insn *pred_inst =
                z_disassembler_get_superset_disasm(d, pred_addr);

            if (z_capstone_is_call(pred_inst) || z_capstone_is_ret(pred_inst) ||
                z_capstone_is_cjmp(pred_inst) || z_capstone_is_jmp(pred_inst) ||
                pred_addr + pred_inst->size != cur_addr) {
                goto NEXT_ADDR;
            }

            cur_addr = pred_addr;
        }

        // TODO: advanced patching
        // check no prior checkpoints are call/cjmp/jmp
        // Iter(addr_t, occ_addrs);
        // z_iter_init_from_buf(occ_addrs,
        //                      z_disassembler_get_occluded_addrs(d, cur_addr));
        // while (!z_iter_is_empty(occ_addrs)) {
        //     addr_t occ_addr = *(z_iter_next(occ_addrs));
        //     if (occ_addr >= cur_addr) {
        //         continue;
        //     }
        //     cs_insn *occ_inst = z_disassembler_get_superset_disasm(d,
        //     occ_addr); assert(occ_inst); if (z_capstone_is_call(occ_inst) ||
        //     z_capstone_is_cjmp(occ_inst) ||
        //         z_capstone_is_jmp(occ_inst)) {
        //         goto NEXT_ADDR;
        //     }
        // }

#ifdef BINARY_SEARCH_DEBUG_PATCHER
        if (cur_addr <= BINARY_SEARCH_DEBUG_PATCHER) {
            continue;
        }
#endif

        z_elf_write(e, cur_addr, 1, __invalid_inst_buf);
        g_hash_table_insert(p->checkpoints, GSIZE_TO_POINTER(cur_addr),
                            GSIZE_TO_POINTER(1));

    NEXT_ADDR:
        continue;
    }

    // we then patch returan address for normal call and plt call
    GQueue *bfs = g_queue_new();
    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
        double128_t addr_prob = z_disassembler_get_prob_disasm(d, addr);
        if (addr_prob < PATCH_THRESHOLD) {
            continue;
        }

        cs_insn *inst = z_disassembler_get_superset_disasm(d, addr);
        assert(inst);

        if (!z_capstone_is_call(inst)) {
            continue;
        }

        cs_detail *detail = inst->detail;
        if ((detail->x86.op_count != 1) ||
            (detail->x86.operands[0].type != X86_OP_IMM)) {
            continue;
        }

        addr_t callee_addr = detail->x86.operands[0].imm;
        if (!z_elf_check_plt(e, callee_addr) &&
            (callee_addr < text_addr || callee_addr >= text_addr + text_size)) {
            continue;
        }

        addr_t ret_addr = addr + inst->size;

        if (!z_elf_check_plt(e, callee_addr)) {
            g_queue_push_tail(bfs, GSIZE_TO_POINTER(ret_addr));
            size_t bfs_n = 0;
            bool valid = false;

            while (!g_queue_is_empty(bfs)) {
                addr_t cur_addr = (addr_t)g_queue_pop_head(bfs);
                if (z_disassembler_get_prob_disasm(d, cur_addr) >=
                    PATCH_THRESHOLD) {
                    valid = true;
                    break;
                }

                Iter(addr_t, succ_addrs);
                z_iter_init_from_buf(
                    succ_addrs, z_disassembler_get_successors(d, cur_addr));

                while (!z_iter_is_empty(succ_addrs)) {
                    addr_t succ_addr = *(z_iter_next(succ_addrs));
                    if ((bfs_n++) < PATCH_RET_DEPTH) {
                        g_queue_push_tail(bfs, GSIZE_TO_POINTER(succ_addr));
                    }
                }

                if (bfs_n >= PATCH_RET_DEPTH) {
                    break;
                }
            }
            g_queue_clear(bfs);

            if (!valid) {
                continue;
            }
        } else {
            double128_t ret_P = z_disassembler_get_prob_disasm(d, ret_addr);
            if (copysignl(1.0, ret_P) < 0.0) {
                continue;
            }
        }

#ifdef BINARY_SEARCH_DEBUG_PATCHER
        if (ret_addr <= BINARY_SEARCH_DEBUG_PATCHER) {
            continue;
        }
#endif

        z_elf_write(e, ret_addr, 1, __invalid_inst_buf);
        g_hash_table_insert(p->checkpoints, GSIZE_TO_POINTER(ret_addr),
                            GSIZE_TO_POINTER(1));
    }
}

Z_PRIVATE void __patcher_patch_all_S(Patcher *p) {
    addr_t text_addr = p->text_addr;
    size_t text_size = p->text_size;

    Disassembler *d = p->disassembler;

    addr_t cur_addr = text_addr;
    while (cur_addr < text_addr + text_size) {
#ifdef BINARY_SEARCH_DEBUG_PATCHER
        if (cur_addr <= BINARY_SEARCH_DEBUG_PATCHER) {
            cur_addr += 1;
            continue;
        }
#endif

        if (z_disassembler_get_prob_disasm(d, cur_addr) < PATCH_THRESHOLD) {
            cur_addr += 1;
            continue;
        }

        cs_insn *cur_inst = z_disassembler_get_superset_disasm(d, cur_addr);
        assert(cur_inst);
        z_trace("handle instruction: " CS_SHOW_INST(cur_inst));

        // TODO: handle the overlapping instruction introduced by *LOCK* prefix
        size_t i = 0;
        do {
            if (z_disassembler_get_prob_disasm(d, cur_addr) < PATCH_THRESHOLD) {
                EXITME("invalid address for simple pdisasm " CS_SHOW_INST(
                    cur_inst));
            }

            __patcher_patch_certain_address(p, cur_addr, i == 0);

            cur_addr += 1;
            i += 1;
        } while (i < cur_inst->size);
    }
}

Z_API void z_patcher_describe(Patcher *p) {
    // first do patching
    z_patcher_patch_all(p);

    Disassembler *d = p->disassembler;
    addr_t text_addr = p->text_addr;
    size_t text_size = p->text_size;

    z_sayf("%-7s%-25s%-25s%-25s%-25s%-25s%-8s%-60s%-5s%s\n", "status",
           "inst hint", "inst lost", "data hint", "D", "P", "SCC", "inst",
           "size", " succs");

    Buffer *checkpoints = z_buffer_create(NULL, 0);

    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
        cs_insn *inst = NULL;
        uint32_t scc_id = 0;
        double128_t inst_hint = NAN;
        double128_t inst_lost = NAN;
        double128_t data_hint = NAN;
        double128_t D = NAN;
        double128_t P = NAN;

        z_disassembler_get_prob_disasm_internal(d, addr, &inst, &scc_id,
                                                &inst_hint, &inst_lost,
                                                &data_hint, &D, &P);

        const char *status = "";
        if (g_hash_table_lookup(p->checkpoints, GSIZE_TO_POINTER(addr))) {
            status = "C";
            z_buffer_append_raw(checkpoints, (uint8_t *)&addr, sizeof(addr));
        }

        if (!isnan(data_hint) && !isinf(data_hint) &&
            data_hint > 10000000000000000000.0) {
            z_sayf("%-7s%-25.12Lf%-25.2Lf%-25Le%-25.12Lf%+-25.12Lf", status,
                   inst_hint, inst_lost, data_hint, D, P);
        } else {
            z_sayf("%-7s%-25.12Lf%-25.2Lf%-25.2Lf%-25.12Lf%+-25.12Lf", status,
                   inst_hint, inst_lost, data_hint, D, P);
        }
        if (inst) {
            z_sayf("%-8d", scc_id);
            const char *inst_str = z_alloc_printf(CS_SHOW_INST(inst));
            z_sayf("%-60s%-5d", inst_str, inst->size);
            z_free((void *)inst_str);
            Iter(addr_t, succ_addrs);
            z_iter_init_from_buf(succ_addrs,
                                 z_disassembler_get_successors(d, addr));
            while (!z_iter_is_empty(succ_addrs)) {
                z_sayf(" {%#lx}", *(z_iter_next(succ_addrs)));
            }
            z_sayf("\n");
        } else {
            z_sayf("%-8d(%#lx:\tinvalid)\n", scc_id, addr);
        }
    }

    z_buffer_write_file(checkpoints, "checkpoints.log");
    z_buffer_destroy(checkpoints);
}

Z_API Patcher *z_patcher_create(Disassembler *d) {
    Patcher *p = STRUCT_ALLOC(Patcher);

    p->disassembler = d;
    p->binary = z_disassembler_get_binary(d);

    ELF *e = z_binary_get_elf(p->binary);
    Elf64_Shdr *text = z_elf_get_shdr_text(e);
    p->text_addr = text->sh_addr;
    p->text_size = text->sh_size;

    z_addr_dict_init(p->certain_addresses, p->text_addr, p->text_size);

    p->checkpoints =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    p->bridges =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    return p;
}

Z_API void z_patcher_destroy(Patcher *p) {
    z_addr_dict_destroy(p->certain_addresses);

    g_hash_table_destroy(p->checkpoints);
    g_hash_table_destroy(p->bridges);
    z_free(p);
}

Z_API void z_patcher_patch_all(Patcher *p) {
    assert(p != NULL);

    // do prob-disassemble first
    z_disassembler_prob_disasm(p->disassembler);

    // fill all patch candidates as HLT (0xf4) or ILLEGAL INSTRUCTION (0x2f)
    if (!z_disassembler_fully_support_prob_disasm(p->disassembler)) {
        __patcher_patch_all_S(p);
    } else {
        __patcher_patch_all_F(p);
    }
}

Z_API bool z_patcher_check(Patcher *p, addr_t addr) {
#ifdef BINARY_SEARCH_DEBUG_REWRITER
    z_warn(
        "when debuging rewriter, real crashes may cause unintentional "
        "behaviors");
#endif

    return !!g_hash_table_lookup(p->checkpoints, GSIZE_TO_POINTER(addr));
}

// TODO: it is a very simple jump instruction patch currently, we may leverage
// E9Patch tech in the future
Z_API void z_patcher_build_bridge(Patcher *p, addr_t ori_addr,
                                  addr_t shadow_addr) {
#ifdef BINARY_SEARCH_DEBUG_REWRITER
    // avoid infinite loop
    ELF *e = z_binary_get_elf(p->binary);
    if (ori_addr == shadow_addr) {
        cs_insn *inst =
            z_disassembler_get_superset_disasm(p->disassembler, ori_addr);
        z_elf_write(e, ori_addr, inst->size, inst->bytes);
        return;
    }
#endif

#ifdef BINARY_SEARCH_DEBUG_PATCHER
    // this bridge building may be caused by retaddr
    if (ori_addr <= BINARY_SEARCH_DEBUG_PATCHER) {
        return;
    }
#endif

    // update certain_addresses
    __patcher_bfs_certain_addresses(p, ori_addr);

    addr_t ori_bridge =
        (addr_t)g_hash_table_lookup(p->bridges, GSIZE_TO_POINTER(ori_addr));
    if (ori_bridge) {
        // it is possible when the address is regarded as external crashpoint
        // and then regarded as retaddr
        if (ori_bridge != ori_addr) {
            EXITME("overlapped bridge detected: %#lx / %#lx", ori_addr,
                   ori_bridge);
        }
        return;
    }

    KS_ASM_JMP(ori_addr, shadow_addr);
    for (size_t off = 0; off < ks_size; off++) {
        g_hash_table_insert(p->bridges, GSIZE_TO_POINTER(ori_addr + off),
                            GSIZE_TO_POINTER(ori_addr));
        // revoke checkpoints
        g_hash_table_remove(p->checkpoints, GSIZE_TO_POINTER(ori_addr + off));
    }
    __patcher_patch(p, ori_addr, ks_size, ks_encode);
}

Z_API addr_t z_patcher_adjust_bridge_address(Patcher *p, addr_t addr) {
    // TODO: support bridge adjustment
    return addr;
}
