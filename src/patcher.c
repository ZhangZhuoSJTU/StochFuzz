#include "patcher.h"
#include "capstone_.h"
#include "interval_splay.h"
#include "iterator.h"
#include "utils.h"

#include <math.h>

#define PATCH_THRESHOLD 0.99999
#define PATCH_RET_DEPTH 20
#define BRIDGE_PRE_DEPTH 5

static const char __invalid_inst_buf[16] = {0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f,
                                            0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f,
                                            0x2f, 0x2f, 0x2f, 0x2f};

typedef struct bridge_point_t {
    addr_t bridge_addr;
    addr_t source_addr;
    addr_t max_addr;  // used for revoke bridge patching
} BridgePoint;

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
 * Flip uncertain patches (used in delta debugging mode)
 */
Z_PRIVATE void __patcher_flip_uncertain_patch(Patcher *p, addr_t addr,
                                              bool is_enable);

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
 * Patch a new certain address, return whether this patch is successfully
 * applied.
 */
Z_PRIVATE bool __patcher_patch_certain_address(Patcher *p, addr_t addr,
                                               uint8_t inst_size);

/*
 * Patch a new uncertain address, return whether this patch is successfully
 * applied.
 */
Z_PRIVATE bool __patcher_patch_uncertain_address(Patcher *p, addr_t addr);

/*
 * Compare two address
 */
Z_PRIVATE int32_t __patcher_compare_address(addr_t a, addr_t b, void *_data);

Z_PRIVATE int32_t __patcher_compare_address(addr_t a, addr_t b, void *_data) {
    assert(!_data);
    if (a < b) {
        return -1;
    } else if (a > b) {
        return 1;
    } else {
        return 0;
    }
}

Z_PRIVATE void __patcher_flip_uncertain_patch(Patcher *p, addr_t addr,
                                              bool is_enable) {
    if (is_enable) {
        __patcher_patch(p, addr, 1, __invalid_inst_buf);
    } else {
        size_t off = addr - p->text_addr;
        if (off >= p->text_size) {
            EXITME("invalid address: %#lx", addr);
        }
        __patcher_patch(p, addr, 1, p->text_backup + off);
    }
}

Z_PRIVATE bool __patcher_patch_uncertain_address(Patcher *p, addr_t addr) {
    // step (1). check whether this address is certain
    if (z_addr_dict_exist(p->certain_addresses, addr)) {
        return false;
    }

    // step (2). check whether it is already patched as uncertain patch
    if (g_sequence_lookup(p->uncertain_patches, GSIZE_TO_POINTER(addr),
                          (GCompareDataFunc)__patcher_compare_address, NULL)) {
        return false;
    }

    // step (3). patch underlying binary
    __patcher_patch(p, addr, 1, __invalid_inst_buf);

    // step (4). update uncertain_patches
    g_sequence_insert_sorted(p->uncertain_patches, GSIZE_TO_POINTER(addr),
                             (GCompareDataFunc)__patcher_compare_address, NULL);

    return true;
}

Z_PRIVATE bool __patcher_patch_certain_address(Patcher *p, addr_t addr,
                                               uint8_t inst_size) {
    // XXX: one address cannot be set as certain twice (except for the ones
    // which are revoked for adjusting bridges)
    if (z_addr_dict_exist(p->certain_addresses, addr)) {
        return false;
    }
    z_trace("certain patch: %#lx", addr);

    // step (1). set certain_addresses
    z_addr_dict_set(p->certain_addresses, addr, inst_size);

    // step (2). patch underlying binary
    __patcher_patch(p, addr, 1, __invalid_inst_buf);

    // step (3). update certain_patches and uncertain_patches
    z_addr_dict_set(p->certain_patches, addr, true);
    GSequenceIter *iter =
        g_sequence_lookup(p->uncertain_patches, GSIZE_TO_POINTER(addr),
                          (GCompareDataFunc)__patcher_compare_address, NULL);
    if (iter) {
        g_sequence_remove(iter);
    }

    return true;
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
            __patcher_patch_certain_address(p, cur_addr + i,
                                            (i == 0 ? cur_inst->size : 0));
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
                assert(z_addr_dict_get(p->certain_addresses, succ_addr) ||
                       (z_addr_dict_get(p->certain_addresses, succ_addr - 1) &&
                        z_disassembler_get_superset_disasm(d, succ_addr - 1)
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
    assert(addr >= p->text_addr);

    // if addr < p->text_addr, the following inc must be out-of-bounded.
    z_rptr_inc(p->text_ptr, uint8_t, addr - p->text_addr);
    z_rptr_memcpy(p->text_ptr, buf, size);
    z_rptr_reset(p->text_ptr);
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
        // check no prior patchpoints are call/cjmp/jmp
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

        __patcher_patch_uncertain_address(p, cur_addr);

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

        __patcher_patch_uncertain_address(p, ret_addr);
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

            __patcher_patch_certain_address(p, cur_addr,
                                            (i == 0 ? cur_inst->size : 0));

            cur_addr += 1;
            i += 1;
        } while (i < cur_inst->size);
    }
}

Z_API void z_patcher_describe(Patcher *p) {
    if (p->s_iter || p->e_iter) {
        EXITME("cannot make requests when delta debugging mode is enable");
    }

    // first do patching
    z_patcher_initially_patch(p);

    Disassembler *d = p->disassembler;
    addr_t text_addr = p->text_addr;
    size_t text_size = p->text_size;

    z_sayf("%-7s%-25s%-25s%-25s%-25s%-25s%-8s%-60s%-5s%s\n", "status",
           "inst hint", "inst lost", "data hint", "D", "P", "SCC", "inst",
           "size", " succs");

    Buffer *patchpoints = z_buffer_create(NULL, 0);

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
        PPType pp_type = z_patcher_check_patchpoint(p, addr);
        if (pp_type != PP_INVALID) {
            if (pp_type == PP_CERTAIN) {
                status = "CC";
            } else if (pp_type == PP_UNCERTAIN) {
                status = "UC";
            } else if (pp_type == PP_BRIDGE) {
                status = "BC";
            }
            z_buffer_append_raw(patchpoints, (uint8_t *)&addr, sizeof(addr));
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

    z_buffer_write_file(patchpoints, "patchpoints.log");
    z_buffer_destroy(patchpoints);
}

Z_API Patcher *z_patcher_create(Disassembler *d) {
    Patcher *p = STRUCT_ALLOC(Patcher);

    p->disassembler = d;
    p->binary = z_disassembler_get_binary(d);

    p->pdisasm_enable = z_disassembler_fully_support_prob_disasm(d);

    ELF *e = z_binary_get_elf(p->binary);
    Elf64_Shdr *text = z_elf_get_shdr_text(e);
    p->text_addr = text->sh_addr;
    p->text_size = text->sh_size;
    p->text_ptr = z_elf_vaddr2ptr(e, p->text_addr);
    p->text_backup = NULL;

    z_addr_dict_init(p->certain_addresses, p->text_addr, p->text_size);

    z_addr_dict_init(p->certain_patches, p->text_addr, p->text_size);
    p->uncertain_patches = g_sequence_new(NULL);
    p->bridges = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                       (GDestroyNotify)(&z_free));

    p->s_iter = NULL;
    p->e_iter = NULL;

    p->patched_bridges = 0;
    p->delayed_bridges = 0;
    p->resolved_bridges = 0;
    p->adjusted_bridges = 0;

    return p;
}

Z_API void z_patcher_destroy(Patcher *p) {
    z_addr_dict_destroy(p->certain_addresses);
    z_addr_dict_destroy(p->certain_patches);
    g_sequence_free(p->uncertain_patches);

    g_hash_table_destroy(p->bridges);

    z_rptr_destroy(p->text_ptr);

    if (p->text_backup) {
        z_free(p->text_backup);
    }

    z_free(p);
}

Z_API void z_patcher_initially_patch(Patcher *p) {
    assert(p != NULL);
    if (p->s_iter || p->e_iter) {
        EXITME("cannot do initial patch in delta debugging mode");
    }

    // backup .text
    if (p->text_backup) {
        EXITME("backed up .text before initial patching");
    }
    p->text_backup = z_alloc(p->text_size, sizeof(uint8_t));
    z_rptr_memcpy(p->text_backup, p->text_ptr, p->text_size);

    // do prob-disassemble first
    z_disassembler_prob_disasm(p->disassembler);

    // fill all patch candidates as HLT (0xf4) or ILLEGAL INSTRUCTION (0x2f)
    if (!p->pdisasm_enable) {
        __patcher_patch_all_S(p);
    } else {
        __patcher_patch_all_F(p);
    }
}

Z_API PPType z_patcher_check_patchpoint(Patcher *p, addr_t addr) {
    if (p->s_iter || p->e_iter) {
        EXITME("cannot make requests when delta debugging mode is enable");
    }

#ifdef BINARY_SEARCH_DEBUG_REWRITER
    z_warn(
        "when debuging rewriter, real crashes may cause unintentional "
        "behaviors");
#endif

    // step (0). check whether addr is in .text (some real crash points are in
    // the shadow code)
    if (addr < p->text_addr || addr >= p->text_addr + p->text_size) {
        return PP_INVALID;
    }

    // step (1). check certain patches
    if (z_addr_dict_exist(p->certain_patches, addr)) {
        return PP_CERTAIN;
    }

    // step (2). check uncertain patches
    GSequenceIter *iter =
        g_sequence_lookup(p->uncertain_patches, GSIZE_TO_POINTER(addr),
                          (GCompareDataFunc)__patcher_compare_address, NULL);
    if (iter) {
        return PP_UNCERTAIN;
    }

    // step (3). check bridge
    if (g_hash_table_lookup(p->bridges, GSIZE_TO_POINTER(addr))) {
        return PP_BRIDGE;
    }

    return PP_INVALID;
}

// TODO: BINARY_SEARCH_DEBUG_XXX may cause bugs for the following new code
//
// TODO: it is a basic jump instruction patching algorithm (w/ auto fix and
// delayed patching) currently, we may leverage E9Patch tech in the future
//
// XXX: following is a typical bridge layout (before and after patching), where
// symbol "|" denotes an instruction boundary.
//
//                      Bytes: B B B B B B B B B B B B B B B B B B B B B B B
//  ---------------------------------------------------------------------------
//            Before patching:
//                             |---|-|-----|-------|---|-----|-----|-------|
//
//  ---------------------------------------------------------------------------
//             After patching:
//                             |*******|???|-------|---|-----|-----|-------|
//
//         overlapping inst A:     |---------------------|
//         overlapping inst B:       |-|
//
//                jump values: J J J J J
//            patching values:           P P P P P P P P P P P P P P P P P P
//
//              bridge points: X   X X  X  X       X   X   X
//       left certain patches:                               C C C C C C C C
//
//   bridge-related addresses: A A A A A A A A A A A A A A A
//
Z_API void z_patcher_build_bridge(Patcher *p, addr_t ori_addr,
                                  addr_t shadow_addr, bool is_real) {
    if (p->s_iter || p->e_iter) {
        EXITME("cannot build bridge in delta debugging mode");
    }

    Disassembler *d = p->disassembler;

#ifdef BINARY_SEARCH_DEBUG_REWRITER
    // avoid infinite loop
    ELF *e = z_binary_get_elf(p->binary);
    if (ori_addr == shadow_addr) {
        cs_insn *inst = z_disassembler_get_superset_disasm(d, ori_addr);
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

    // step (0). check ori_addr range
    if (ori_addr < p->text_addr || ori_addr >= p->text_addr + p->text_size) {
        EXITME("invalid address for bridge: %#lx", ori_addr);
    }

    // step (1). update certain_addresses
    // TODO: update pdisasm
    __patcher_bfs_certain_addresses(p, ori_addr);

    // step (2). check whether there is a bridge already built on current addr
    BridgePoint *ori_bp = (BridgePoint *)g_hash_table_lookup(
        p->bridges, GSIZE_TO_POINTER(ori_addr));
    if (ori_bp) {
        // It is possible when the address is regarded as external crashpoint
        // and then regarded as retaddr.
        // Additionally, note that even if this is a fake crashpoint, it still
        // cannot be a non-leading PP_BRIDGE (i.e., the starting point of a
        // bridge), as ori_addr should have been adjusted.
        if (ori_bp->bridge_addr != ori_addr) {
            EXITME("strange overlapped bridge detected: %#lx / %#lx", ori_addr,
                   ori_bp->bridge_addr);
        }
        return;
    }
    if (!ori_bp && !z_addr_dict_exist(p->certain_patches, ori_addr)) {
        if (!is_real) {
            // XXX: it is possible that a fake bridge, which is not triggered by
            // a control flow crash, is added on code for another delayed
            // bridge.
            // XXX: a very typical case for this branch is, when pdisasm is
            // fully enabled:
            //  1. For an unsafe crashpoint A, we resolved this unsafety by
            //  adding a new crashpoint B.
            //  2. Crashpoint B was triggered, but it is still unsafe and cannot
            //  be resolved. So we delayed it.
            //  3. Both A and B are logged. But later, when applying the log, B
            //  is first applied.
            return;
        }
        EXITME("invalid bridge address: %#lx", ori_addr);
    }

    // some important variables for futher operations
    bool safe_patch = true;
    bool bridge_patched = false;
    addr_t bridge_sources[20];  // the longest x64 inst is 15-bytes (5 + 15)
    addr_t bridge_max_addr = ori_addr;
    memset(bridge_sources, 0, sizeof(bridge_sources));

    // step (3). all 5 bytes need to be certain patches
    for (size_t i = 0; i < 5; i++) {
        if (!z_addr_dict_exist(p->certain_patches, ori_addr + i)) {
            z_info(
                "find an unsafe bridge patching, try to resolve it... "
                "(failed address %#lx, based on bridge address %#lx)",
                ori_addr + i, ori_addr);
            safe_patch = false;
            break;
        }
    }

    // step (4). pre-patch bridge and additionally check whether current patch
    // is valid (for overlapping instructions).
    if (safe_patch) {
        // step (4.1). pre-patch bridge (and revoke certain patches).
        {
            bridge_patched = true;
            KS_ASM_JMP(ori_addr, shadow_addr);
            __patcher_patch(p, ori_addr, ks_size, ks_encode);
            assert(ks_size == 5);

            for (size_t off = 0; off < 5; off++) {
                // revoke patchpoints of PP_CERTAIN
                // XXX: note that the uncertain patchpoints have already be
                // replaced by certain ones in step (1).
                z_addr_dict_remove(p->certain_patches, ori_addr + off);
            }
        }

        // step (4.2). additionally check whether current patch is valid (for
        // overlapping instructions)
        {
            // step (4.2.0). set up bridge starting point
            bridge_sources[0] = ori_addr;

            // XXX: The first element is the target address and the second
            // element is the source address.
            GQueue *queue = g_queue_new();

            // step (4.2.1). insert the sources of overlapping instruction
            for (size_t off = 1; off < 5; off++) {
                if (z_addr_dict_get(p->certain_addresses, ori_addr + off)) {
                    g_queue_push_tail(queue, GSIZE_TO_POINTER(ori_addr + off));
                    g_queue_push_tail(queue, GSIZE_TO_POINTER(ori_addr + off));
                }
            }

            // step (4.2.2). validate all possible overlapping instructions
            while (!g_queue_is_empty(queue)) {
                addr_t cur_addr = (addr_t)g_queue_pop_head(queue);
                addr_t src_addr = (addr_t)g_queue_pop_head(queue);

                size_t cur_off = cur_addr - ori_addr;

                z_rptr_inc(p->text_ptr, uint8_t, cur_addr - p->text_addr);
                CS_DISASM(p->text_ptr, cur_addr, 1);
                z_rptr_reset(p->text_ptr);

                // update bridge information
                {
                    if (cur_addr > bridge_max_addr) {
                        bridge_max_addr = cur_addr;
                    }
                    if (!bridge_sources[cur_off] ||
                        src_addr < bridge_sources[cur_off]) {
                        bridge_sources[cur_off] = src_addr;
                    }
                }

                // TODO: handle control flow transfer instruction (e.g., set
                // unsafe_patch once any control flow transfer instruction is
                // involved)

                // invalid instruction (nice!)
                if (cs_count == 0) {
                    continue;
                }

                // check whether the successor is still in the bridge
                addr_t next_addr = cur_addr + cs_inst->size;
                size_t next_off = cur_off + cs_inst->size;
                if (next_addr < ori_addr + 5) {
                    g_queue_push_tail(queue, GSIZE_TO_POINTER(next_addr));
                    g_queue_push_tail(queue, GSIZE_TO_POINTER(src_addr));
                    continue;
                }

                // check whether the successor is a certain patch
                if (z_addr_dict_exist(p->certain_patches, next_addr)) {
                    // additionally handle the next instruction
                    if (next_addr > bridge_max_addr) {
                        bridge_max_addr = next_addr;
                    }
                    if (!bridge_sources[next_off] ||
                        src_addr < bridge_sources[next_off]) {
                        bridge_sources[next_off] = src_addr;
                    }
                    continue;
                }

                z_info(
                    "find an unsafe bridge patching, try to resolve it... "
                    "(failed address %#lx, based on bridge address %#lx)",
                    next_addr, ori_addr);
                safe_patch = false;
                break;
            }

            g_queue_free(queue);
        }

        // step (4.3). check all affected addresses are in certain_patches.
        if (safe_patch) {
            for (addr_t cur_addr = ori_addr + 5; cur_addr <= bridge_max_addr;
                 cur_addr++) {
                if (!z_addr_dict_exist(p->certain_patches, cur_addr)) {
                    safe_patch = false;
                    break;
                }
            }
        }
    }

    // step (5). if it is a safe patch, update bridge information
    if (safe_patch) {
        for (addr_t cur_addr = ori_addr; cur_addr <= bridge_max_addr;
             cur_addr++) {
            assert(
                !g_hash_table_lookup(p->bridges, GSIZE_TO_POINTER(cur_addr)));
            size_t off = cur_addr - ori_addr;

            // XXX: remember to revoke certain_patches
            if (z_addr_dict_exist(p->certain_patches, cur_addr)) {
                z_addr_dict_remove(p->certain_patches, cur_addr);
            }

            // first check whether it is a patch-influenced detection point
            if (bridge_sources[off]) {
                BridgePoint *bp = z_alloc(1, sizeof(BridgePoint));
                bp->bridge_addr = ori_addr;
                bp->source_addr = bridge_sources[off];
                bp->max_addr = bridge_max_addr;

                g_hash_table_insert(p->bridges, GSIZE_TO_POINTER(cur_addr),
                                    (gpointer)bp);
                continue;
            }

            // actually, all affected instruction boudnaries in jmp patching
            // shoud be handled before
            assert(
                !(off < 5 && z_addr_dict_get(p->certain_addresses, cur_addr)));

            // then chech it is an inst boundary before the patched jmp inst
            if (off >= 5 && z_addr_dict_get(p->certain_addresses, cur_addr)) {
                BridgePoint *bp = z_alloc(1, sizeof(BridgePoint));
                bp->bridge_addr = ori_addr;
                bp->source_addr = cur_addr;
                bp->max_addr = bridge_max_addr;

                g_hash_table_insert(p->bridges, GSIZE_TO_POINTER(cur_addr),
                                    (gpointer)bp);
                continue;
            }
        }

        p->patched_bridges += 1;
        return;
    }

    // step (6). for unsafe patches, we need first revoke the patched bridge
    if (bridge_patched) {
        // XXX: all 5 bytes, which are patched as bridge (jmp), was origianlly
        // certain patches. So we can safely reset them as certain patches.
        z_rptr_inc(p->text_ptr, uint8_t, ori_addr - p->text_addr);
        z_rptr_memcpy(p->text_ptr, __invalid_inst_buf, 5);
        z_rptr_reset(p->text_ptr);

        for (size_t i = 0; i < 5; i++) {
            z_addr_dict_set(p->certain_patches, ori_addr + i, true);
        }
    }

    // step (7). for unsafe patches, we try to resolve it
    // XXX: note that we can only resolve such unsafe patches when pdisasm is
    // fully supported, because only uncertain patches, which do not exist when
    // pidasm is not fully supported, can help fix the unsafe patches.
    if (p->pdisasm_enable) {
        bool new_uncertain_patch = false;

        // XXX: the first element is the target address, the second is the depth
        GQueue *queue = g_queue_new();

        // step (7.1). find all possible uncertain precedessor patches
        g_queue_push_tail(queue, GSIZE_TO_POINTER(ori_addr));
        g_queue_push_tail(queue, GSIZE_TO_POINTER(0));

        while (!g_queue_is_empty(queue)) {
            addr_t cur_addr = (addr_t)g_queue_pop_head(queue);
            size_t depth = (size_t)g_queue_pop_head(queue);

            if (depth > BRIDGE_PRE_DEPTH) {
                continue;
            }

            // get predecessors
            Iter(addr_t, pred_addrs);
            z_iter_init_from_buf(pred_addrs,
                                 z_disassembler_get_predecessors(d, cur_addr));

            while (!z_iter_is_empty(pred_addrs)) {
                // pred_addr must in .text (it may be incomplete when
                // pre-superset diaasm is not enable)
                addr_t pred_addr = *(z_iter_next(pred_addrs));

                // check prob
                if (z_disassembler_get_prob_disasm(d, pred_addr) <
                    PATCH_THRESHOLD) {
                    continue;
                }

                // there are some cases where the following predicate is false:
                //  case (1). pred_addr is in certain_addresses
                //  case (2). pred_addr already be patched as uncertain patches
                //      case (2.a). pred_addr is patched by this BFS
                //      case (2.b). pred_addr is patched by others
                if (!__patcher_patch_uncertain_address(p, pred_addr)) {
                    continue;
                }

                new_uncertain_patch = true;
                g_queue_push_tail(queue, GSIZE_TO_POINTER(pred_addr));
                g_queue_push_tail(queue, GSIZE_TO_POINTER(depth + 1));
            }

            z_iter_destroy(pred_addrs);
        }

        g_queue_free(queue);

        // step (7.2) return if we can resolve it by the next execution
        if (new_uncertain_patch) {
            p->resolved_bridges += 1;
            return;
        }
    }

    // step (8). if we cannot resolve it, we delay the patches
    // XXX: avoid touch other patch points
    z_info("fail to resolve the unsafe patch, let's delay it: %#lx", ori_addr);
    {
        z_rptr_inc(p->text_ptr, uint8_t, ori_addr - p->text_addr);
        addr_t cur_addr = ori_addr;

        while (z_addr_dict_exist(p->certain_addresses, cur_addr) &&
               z_addr_dict_exist(p->certain_patches, cur_addr)) {
            assert(z_addr_dict_get(p->certain_addresses, cur_addr));

            cs_insn *cur_inst = z_disassembler_get_superset_disasm(d, cur_addr);
            assert(cur_inst);

            z_rptr_memcpy(p->text_ptr, cur_inst->bytes, cur_inst->size);

            for (size_t i = 0; i < cur_inst->size; i++) {
                // XXX: in this case, cur_addr + i belongs to neighter bridges
                // nor certain_patches, but it belongs to certain_addresses. It
                // is a special case for delayed bridges.
                z_addr_dict_remove(p->certain_patches, cur_addr + i);
            }

            // we end at terminator (e.g., ret) or call
            if (z_capstone_is_terminator(cur_inst) ||
                z_capstone_is_call(cur_inst)) {
                break;
            }

            cur_addr += cur_inst->size;
            z_rptr_inc(p->text_ptr, uint8_t, cur_inst->size);
        }

        z_rptr_reset(p->text_ptr);

        p->delayed_bridges += 1;
    }

    return;
}

Z_API void z_patcher_bridge_stats(Patcher *p) {
    z_info("number of patched bridges : %d", p->patched_bridges);
    z_info("number of delayed bridges : %d", p->delayed_bridges);
    z_info("number of resolved bridges: %d", p->resolved_bridges);
    z_info("number of adjusted bridges: %d", p->adjusted_bridges);
}

Z_API addr_t z_patcher_adjust_bridge_address(Patcher *p, addr_t addr) {
    if (p->s_iter || p->e_iter) {
        EXITME("cannot adjust bridge in delta debugging mode");
    }

    BridgePoint *bp = g_hash_table_lookup(p->bridges, GSIZE_TO_POINTER(addr));

    // case (1). this is not a bridge point, and we do nothing.
    if (!bp) {
        return addr;
    }

    // case (2). this is the bridge starting point, and we do nothing too.
    if (bp->bridge_addr == addr) {
        return addr;
    }

    // case (3). this crash is caused by an overlapping instruction. We need to
    // revoke this bridge patching.
    addr_t bridge_addr = bp->bridge_addr;
    addr_t source_addr = bp->source_addr;
    addr_t max_addr = bp->max_addr;
    z_info("detect a solvable bridge overlapping: %#lx / %#lx", addr,
           bridge_addr);

    // step (1). revoke the tail part of bridge (after source_addr), if
    // necessary
    if (source_addr < bridge_addr + 5) {
        size_t tail_size = bridge_addr + 5 - source_addr;

        z_rptr_inc(p->text_ptr, uint8_t, source_addr - p->text_addr);
        z_rptr_memcpy(p->text_ptr, __invalid_inst_buf, tail_size);
        z_rptr_reset(p->text_ptr);
    }

    // step (2). revoke the head part of bridge (before source_addr)
    {
        assert(source_addr > bridge_addr);
        size_t head_size = source_addr - bridge_addr;

        // XXX: these addresses are also the special cases for delayed bridges.
        // Again, them do not belong to certain_patches and bridges, but belong
        // to certain_addresses.
        z_rptr_inc(p->text_ptr, uint8_t, bridge_addr - p->text_addr);
        z_rptr_memcpy(p->text_ptr,
                      p->text_backup + (bridge_addr - p->text_addr), head_size);
        z_rptr_reset(p->text_ptr);
    }

    // step (3). remove all associated bridge information and reset some as
    // certain patches
    {
        for (addr_t cur_addr = bridge_addr; cur_addr <= max_addr; cur_addr++) {
            if (cur_addr >= source_addr) {
                z_addr_dict_set(p->certain_patches, cur_addr, true);
            }

            g_hash_table_remove(p->bridges, GSIZE_TO_POINTER(cur_addr));
        }
    }

    p->adjusted_bridges += 1;

    return source_addr;
}

Z_API size_t z_patcher_uncertain_patches_n(Patcher *p) {
    if (p->s_iter || p->e_iter) {
        EXITME("cannot make requests when delta debugging mode is enable");
    }

    return g_sequence_get_length(p->uncertain_patches);
}

Z_API void z_patcher_self_correction_start(Patcher *p) {
    if (p->s_iter || p->e_iter) {
        EXITME("self correction procedure already started");
    }

    p->s_iter = g_sequence_get_begin_iter(p->uncertain_patches);
    p->e_iter = g_sequence_get_end_iter(p->uncertain_patches);
}

Z_API void z_patcher_self_correction_end(Patcher *p) {
    if (!p->s_iter || !p->e_iter) {
        EXITME("self correction procedure did not start");
    }

    // step (1). repair the buggy rewriting
    // TODO

    // step (2). enable all uncertain patches
    // XXX: note that current all the uncertain patches are disabled
    GSequenceIter *iter = g_sequence_get_begin_iter(p->uncertain_patches);
    while (!g_sequence_iter_is_end(iter)) {
        __patcher_flip_uncertain_patch(p, (addr_t)g_sequence_get(iter), true);
        iter = g_sequence_iter_next(iter);
    }

    // step (3). disable the s_iter and e_iter flags
    p->s_iter = NULL;
    p->e_iter = NULL;
}

Z_API void z_patcher_test_uncertain_patches(Patcher *p, bool is_s_iter,
                                            int64_t off) {
    if (!p->s_iter || !p->e_iter) {
        EXITME("self correction procedure did not start");
    }
    if (!off) {
        return;
    }

    // step (1). prepart basic infomation
    GSequenceIter *iter = (is_s_iter ? p->s_iter : p->e_iter);
    GSequenceIter *(*change_iter)(GSequenceIter *) =
        ((off > 0) ? &g_sequence_iter_next : &g_sequence_iter_prev);
    size_t steps = ((off < 0) ? (size_t)(-off) : (size_t)off);

    // is_enable | is_s_iter | off > 0
    // ----------+-----------+----------------
    // True      | True      | False (off < 0)
    // True      | False     | True  (off > 0)
    // False     | True      | True  (off > 0)
    // False     | False     | False (off < 0)
    bool is_enable = (!!is_s_iter) ^ (!!(off > 0));

    // step (2). flip uncertain patches
    bool do_before_change = (off > 0);
    for (size_t i = 0; i < steps; i++) {
        if (do_before_change) {
            __patcher_flip_uncertain_patch(p, (addr_t)g_sequence_get(iter),
                                           is_enable);
        }

        GSequenceIter *tmp = (*change_iter)(iter);
        assert(tmp != iter);
        iter = tmp;

        if (!do_before_change) {
            __patcher_flip_uncertain_patch(p, (addr_t)g_sequence_get(iter),
                                           is_enable);
        }
    }

    // step (3). update s_iter/e_iter
    if (is_s_iter) {
        p->s_iter = iter;
    } else {
        p->e_iter = iter;
    }
    assert(p->s_iter && p->e_iter);
    // it is also possible that s_iter == e_iter
    assert(__patcher_compare_address((addr_t)g_sequence_get(p->s_iter),
                                     (addr_t)g_sequence_get(p->e_iter),
                                     NULL) <= 0);
}
