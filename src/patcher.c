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
Z_PRIVATE void __patcher_simply_patch(Patcher *p);

/*
 * When the underlying fully supports prob-disasm, we need to carefully decide
 * which the patch candidates are.
 */
Z_PRIVATE void __patcher_fully_patch(Patcher *p);

/*
 * Do patch on the fly: private API to patch the client when the daemon is up
 */
Z_PRIVATE void __patcher_do_patch_on_the_fly(Patcher *p, addr_t addr,
                                             size_t size, const void *buf);

Z_PRIVATE void __patcher_do_patch_on_the_fly(Patcher *p, addr_t addr,
                                             size_t size, const void *buf) {
    ELF *e = z_binary_get_elf(p->binary);

    z_elf_write(e, addr, size, buf);

    if (*p->cmd_buf_ptr) {
        // update patch command
        CRSCmd cmd;
        cmd.type = CRS_CMD_REWRITE;
        cmd.addr = addr;
        cmd.size = size;

        assert(sizeof(cmd.buf) >= size);
        memcpy((void *)cmd.buf, buf, size);

        // append into cmd_buf_ptr
        z_buffer_append_raw(*p->cmd_buf_ptr, (uint8_t *)&cmd, sizeof(cmd));
    }
}

Z_PRIVATE void __patcher_fully_patch(Patcher *p) {
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

Z_PRIVATE void __patcher_simply_patch(Patcher *p) {
    addr_t text_addr = p->text_addr;
    size_t text_size = p->text_size;

    Disassembler *d = p->disassembler;
    ELF *e = z_binary_get_elf(p->binary);
    Rptr *text_ptr = z_elf_vaddr2ptr(e, text_addr);

    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
#ifdef BINARY_SEARCH_DEBUG_PATCHER
        if (addr <= BINARY_SEARCH_DEBUG_PATCHER) {
            continue;
        }
#endif

        if (z_disassembler_get_prob_disasm(d, addr) > PATCH_THRESHOLD) {
            g_hash_table_insert(p->checkpoints, GSIZE_TO_POINTER(addr),
                                GSIZE_TO_POINTER(1));
            RPTR_MEMSET(text_ptr, 0x2f, sizeof(uint8_t));
        }

        RPTR_INCR(text_ptr, uint8_t, 1);
    }

    z_rptr_destroy(text_ptr);
}

Z_API void z_patcher_describe(Patcher *p) {
    // first do patching
    z_patcher_patch_all(p);

    Disassembler *d = p->disassembler;
    addr_t text_addr = p->text_addr;
    size_t text_size = p->text_size;

    printf("%-7s%-25s%-25s%-25s%-25s%-25s%-8s%-60s%-5s%s\n", "status",
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
            printf("%-7s%-25.12Lf%-25.2Lf%-25Le%-25.12Lf%+-25.12Lf", status,
                   inst_hint, inst_lost, data_hint, D, P);
        } else {
            printf("%-7s%-25.12Lf%-25.2Lf%-25.2Lf%-25.12Lf%+-25.12Lf", status,
                   inst_hint, inst_lost, data_hint, D, P);
        }
        if (inst) {
            printf("%-8d", scc_id);
            const char *inst_str = z_alloc_printf(CS_SHOW_INST(inst));
            printf("%-60s%-5d", inst_str, inst->size);
            z_free((void *)inst_str);
            Iter(addr_t, succ_addrs);
            z_iter_init_from_buf(succ_addrs,
                                 z_disassembler_get_successors(d, addr));
            while (!z_iter_is_empty(succ_addrs)) {
                printf(" {%#lx}", *(z_iter_next(succ_addrs)));
            }
            printf("\n");
        } else {
            printf("%-8d(%#lx:\tinvalid)\n", scc_id, addr);
        }
    }

    z_buffer_write_file(checkpoints, "checkpoints.log");
    z_buffer_destroy(checkpoints);
}

Z_API Patcher *z_patcher_create(Disassembler *d, Buffer **cmd_buf_ptr) {
    Patcher *p = STRUCT_ALLOC(Patcher);

    p->disassembler = d;
    p->binary = z_disassembler_get_binary(d);

    ELF *e = z_binary_get_elf(p->binary);
    Elf64_Shdr *text = z_elf_get_shdr_text(e);
    p->text_addr = text->sh_addr;
    p->text_size = text->sh_size;

    p->checkpoints =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    p->bridges =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    p->cmd_buf_ptr = cmd_buf_ptr;

    return p;
}

Z_API void z_patcher_destroy(Patcher *p) {
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
        __patcher_simply_patch(p);
    } else {
        __patcher_fully_patch(p);
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
    __patcher_do_patch_on_the_fly(p, ori_addr, ks_size, ks_encode);
}
