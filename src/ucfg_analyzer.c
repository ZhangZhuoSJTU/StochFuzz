#include "ucfg_analyzer.h"
#include "elf_.h"
#include "iterator.h"
#include "library_functions/library_functions.h"
#include "utils.h"

// XXX: there are three types of UCFG edges:
//  DIRECT_UEDGE              : call edges to the callee
//  INTRA_UEDGE               : call-fallthrough edges
//  DIRECT_UEDGE | INTRA_UEDGE: other control flow edges
typedef enum ucfg_edge_t {
    DIRECT_UEDGE = (1 << 0),
    INTRA_UEDGE = (1 << 1),
} UEdge;

#define __UCFG_ANALYZER_GHASHTABLE_GET_BUFFER(t, k)        \
    ({                                                     \
        Buffer *buf = (Buffer *)g_hash_table_lookup(t, k); \
        if (!buf) {                                        \
            buf = z_buffer_create(NULL, 0);                \
            g_hash_table_insert(t, k, (gpointer)buf);      \
        }                                                  \
        buf;                                               \
    })

/*
 * Initial analysis for each instruction (calculate direct successors and
 * predecessors)
 */
Z_PRIVATE void __ucfg_analyzer_init_analyze(UCFG_Analyzer *a, addr_t addr,
                                            const cs_insn *inst);

/*
 * Advanced analysis for each instruction (gpr & flg's use-def)
 */
Z_PRIVATE void __ucfg_analyzer_advance_analyze(UCFG_Analyzer *a, addr_t addr,
                                               const cs_insn *inst);

/*
 * Use-def analysis for eflag reigster
 */
Z_PRIVATE void __ucfg_analyzer_analyze_flg(UCFG_Analyzer *a, addr_t addr,
                                           const cs_insn *inst);

/*
 * Use-def analysis for general purpose register
 */
Z_PRIVATE void __ucfg_analyzer_analyze_gpr(UCFG_Analyzer *a, addr_t addr,
                                           const cs_insn *inst);

/*
 * Returning / non-returning functions analysis: whether a given inst (at addr)
 * can reach a RET instruction via intra-procedure edges
 */
Z_PRIVATE void __ucfg_analyzer_analyze_ret(UCFG_Analyzer *a, addr_t addr,
                                           const cs_insn *inst);

/*
 * Add predecessor and successor relation
 */
Z_PRIVATE void __ucfg_analyzer_new_pred_and_succ(UCFG_Analyzer *a,
                                                 addr_t src_addr,
                                                 addr_t dst_addr, UEdge edge);

/*
 * Check whether two instructions are consistent, so that simply replacing one
 * with another one will not influence current analysis result
 */
Z_PRIVATE bool __ucfg_analyzer_check_consistent(const cs_insn *inst_alice,
                                                const cs_insn *inst_bob);

Z_PRIVATE void __ucfg_analyzer_analyze_ret(UCFG_Analyzer *a, addr_t addr,
                                           const cs_insn *inst) {
    if (a->opts->disable_callthrough) {
        return;
    }

    // this addr cannot be in a->can_ret now
    assert(!g_hash_table_lookup(a->can_ret, GSIZE_TO_POINTER(addr)));

    // step (1). add intra-procedure edges if inst is calling a returning
    // function
    if (z_capstone_is_call(inst)) {
        Buffer *succ_buf = z_ucfg_analyzer_get_intra_successors(a, addr);

        if (!z_buffer_get_size(succ_buf)) {
            // XXX: no intra-procedure successor found
            cs_detail *detail = inst->detail;

            if ((detail->x86.op_count == 1) &&
                (detail->x86.operands[0].type == X86_OP_IMM)) {
                addr_t callee_addr = detail->x86.operands[0].imm;
                if (callee_addr != addr + inst->size &&
                    g_hash_table_lookup(a->can_ret,
                                        GSIZE_TO_POINTER(callee_addr))) {
                    // XXX: avoid duplicated edges
                    z_trace("call-fallthrough: %#lx -> %#lx", addr,
                            addr + inst->size);

                    __ucfg_analyzer_new_pred_and_succ(
                        a, addr, addr + inst->size, INTRA_UEDGE);
                    if (z_unlikely(!z_buffer_get_size(succ_buf))) {
                        EXITME("invalid intra-procedure successors");
                    }
                }
            }
        }
    }

    // step (2). check whether current address is returnable
    GQueue *queue = g_queue_new();  // queue for back trace
    {
        if (z_capstone_is_ret(inst)) {
            // it is a RET instruction
            g_hash_table_add(a->can_ret, GSIZE_TO_POINTER(addr));
            g_queue_push_tail(queue, GSIZE_TO_POINTER(addr));
        } else {
            // this is all intra-procedure success
            Iter(addr_t, intra_succs);
            z_iter_init_from_buf(intra_succs,
                                 z_ucfg_analyzer_get_intra_successors(a, addr));

            // other instructions
            while (!z_iter_is_empty(intra_succs)) {
                addr_t succ_addr = *(z_iter_next(intra_succs));
                if (g_hash_table_lookup(a->can_ret,
                                        GSIZE_TO_POINTER(succ_addr))) {
                    g_hash_table_add(a->can_ret, GSIZE_TO_POINTER(addr));
                    g_queue_push_tail(queue, GSIZE_TO_POINTER(addr));
                    break;
                }
            }
            z_iter_destroy(intra_succs);
        }
    }

    // step (3). update all predecessors
    while (!g_queue_is_empty(queue)) {
        addr_t cur_addr = (addr_t)g_queue_pop_head(queue);
        z_trace("find returanable address: %#lx", cur_addr);
        assert(g_hash_table_lookup(a->can_ret, GSIZE_TO_POINTER(cur_addr)));

        // step (3.1). first update calls if cur_addr is a function entrypoint
        Iter(addr_t, direct_preds);
        z_iter_init_from_buf(
            direct_preds, z_ucfg_analyzer_get_direct_predecessors(a, cur_addr));
        while (!z_iter_is_empty(direct_preds)) {
            addr_t pred_addr = *(z_iter_next(direct_preds));
            const cs_insn *pred_inst = (const cs_insn *)g_hash_table_lookup(
                a->insts, GSIZE_TO_POINTER(pred_addr));
            // pred_inst cannot be NULL
            assert(pred_inst);

            if (!z_capstone_is_call(pred_inst)) {
                continue;
            }

            addr_t call_addr = pred_addr;
            addr_t fallthrough_addr = call_addr + pred_inst->size;

            if (fallthrough_addr == cur_addr) {
                // XXX: avoid duplicated edges
                continue;
            }

            if (z_buffer_get_size(
                    z_ucfg_analyzer_get_intra_successors(a, call_addr))) {
                continue;
            }

            __ucfg_analyzer_new_pred_and_succ(a, call_addr, fallthrough_addr,
                                              INTRA_UEDGE);
            if (g_hash_table_lookup(a->can_ret,
                                    GSIZE_TO_POINTER(fallthrough_addr))) {
                z_trace("call-fallthrough: %#lx -> %#lx", call_addr,
                        fallthrough_addr);
                g_hash_table_add(a->can_ret, GSIZE_TO_POINTER(call_addr));
                g_queue_push_tail(queue, GSIZE_TO_POINTER(call_addr));
            }
        }
        z_iter_destroy(direct_preds);

        // step (3.2) update all intra-procedure predecessors
        Iter(addr_t, intra_preds);
        z_iter_init_from_buf(
            intra_preds, z_ucfg_analyzer_get_intra_predecessors(a, cur_addr));
        while (!z_iter_is_empty(intra_preds)) {
            addr_t pred_addr = *(z_iter_next(intra_preds));
            if (!g_hash_table_lookup(a->can_ret, GSIZE_TO_POINTER(pred_addr))) {
                g_hash_table_add(a->can_ret, GSIZE_TO_POINTER(pred_addr));
                g_queue_push_tail(queue, GSIZE_TO_POINTER(pred_addr));
            }
        }
        z_iter_destroy(intra_preds);
    }

    // destroy queue
    g_queue_free(queue);
}

Z_PRIVATE void __ucfg_analyzer_analyze_gpr(UCFG_Analyzer *a, addr_t addr,
                                           const cs_insn *inst) {
    if (a->opts->disable_opt) {
        return;
    }

    // step (0). check whether addr is analyzed
    if (g_hash_table_lookup(a->gpr_can_write, GSIZE_TO_POINTER(addr))) {
        return;
    }

    // step (1). update gpr_analyzed_succs
    {
        // check addr's succs
        Buffer *succs = z_ucfg_analyzer_get_direct_successors(a, addr);
        assert(succs != NULL);
        size_t succ_n = z_buffer_get_size(succs) / sizeof(addr_t);
        addr_t *succs_array = (addr_t *)z_buffer_get_raw_buf(succs);

        size_t analyzed_succ_n = 0;
        for (int i = 0; i < succ_n; i++) {
            if (g_hash_table_lookup(a->gpr_can_write,
                                    GSIZE_TO_POINTER(succs_array[i]))) {
                analyzed_succ_n += 1;
            }
        }
        g_hash_table_insert(a->gpr_analyzed_succs, GSIZE_TO_POINTER(addr),
                            GSIZE_TO_POINTER(analyzed_succ_n));

        // update addr's direct preds
        Buffer *preds = z_ucfg_analyzer_get_direct_predecessors(a, addr);
        assert(preds != NULL);
        size_t pred_n = z_buffer_get_size(preds) / sizeof(addr_t);
        addr_t *preds_array = (addr_t *)z_buffer_get_raw_buf(preds);
        for (int i = 0; i < pred_n; i++) {
            addr_t pred = preds_array[i];
            size_t pred_analyzed_succs = (size_t)g_hash_table_lookup(
                a->gpr_analyzed_succs, GSIZE_TO_POINTER(pred));
            g_hash_table_insert(a->gpr_analyzed_succs, GSIZE_TO_POINTER(pred),
                                GSIZE_TO_POINTER(pred_analyzed_succs + 1));
        }
    }

    // step (2). push addr into analysis queue
    GQueue *queue = g_queue_new();
    g_queue_push_tail(queue, GSIZE_TO_POINTER(addr));

    // step (3). do analysis and propogate the result
    while (!g_queue_is_empty(queue)) {
        // step (3.1). pop from queue and get basic information
        addr_t cur_addr = (addr_t)g_queue_pop_head(queue);

        Buffer *preds = z_ucfg_analyzer_get_direct_predecessors(a, cur_addr);
        assert(preds != NULL);
        size_t pred_n = z_buffer_get_size(preds) / sizeof(addr_t);

        Buffer *succs = z_ucfg_analyzer_get_direct_successors(a, cur_addr);
        assert(succs != NULL);
        size_t succ_n = z_buffer_get_size(succs) / sizeof(addr_t);

        RegState *rs = (RegState *)g_hash_table_lookup(
            a->reg_states, GSIZE_TO_POINTER(cur_addr));
        // XXX: a good observation is that for a given address, its known
        // successors must be added before it. And according to the logic of
        // z_ucfg_analyzer_add_inst, any instruction will be analyzed once it is
        // added into analyzer. Hence, we can sure any instruction in the queue
        // is already analyzed (except addr itself).
        assert(rs != NULL);

        // step (3.2). calculate succs_can_write
        size_t analyzed_succ_n = (size_t)g_hash_table_lookup(
            a->gpr_analyzed_succs, GSIZE_TO_POINTER(cur_addr));
        assert(succ_n >= analyzed_succ_n);

        GPRState succs_can_write = GPRSTATE_ALL + 1;

        if (succ_n != 0 && succ_n == analyzed_succ_n) {
            // assume succs_can_write all registers
            succs_can_write |= GPRSTATE_ALL;

            // all succs are analyzed
            addr_t *succs_array = (addr_t *)z_buffer_get_raw_buf(succs);
            for (int i = 0; i < succ_n; i++) {
                GPRState succ_can_write = 0;
                if (cur_addr == succs_array[i]) {
                    // handle self-loop!
                    succ_can_write = GPRSTATE_ALL + 1;
                } else {
                    succ_can_write = (GPRState)g_hash_table_lookup(
                        a->gpr_can_write, GSIZE_TO_POINTER(succs_array[i]));
                }
                assert(succ_can_write);
                succs_can_write &= succ_can_write;
            }
        }

        // step (3.3). calcualte can_write for cur_addr.
        // According to datalog disassembly
        // (https://www.usenix.org/conference/usenixsecurity20/presentation/flores-montoya)
        // section 5.1, the x64 architecture zeroes the upper part of 64 bits
        // registers whenever the corresponding 32 bits register is written.
        GPRState can_write = GPRSTATE_ALL + 1;
        can_write |= rs->gpr_write_32_64 | succs_can_write;
        can_write &= (~rs->gpr_read);

        // step (3.4). update predecessors
        GPRState ori_can_write = (GPRState)g_hash_table_lookup(
            a->gpr_can_write, GSIZE_TO_POINTER(cur_addr));
        if (ori_can_write != can_write) {
            assert((uint64_t)can_write > (uint64_t)ori_can_write);
            addr_t *preds_array = (addr_t *)z_buffer_get_raw_buf(preds);
            for (int i = 0; i < pred_n; i++) {
                g_queue_push_tail(queue, GSIZE_TO_POINTER(preds_array[i]));
            }
            // update can_write
            g_hash_table_insert(a->gpr_can_write, GSIZE_TO_POINTER(cur_addr),
                                GSIZE_TO_POINTER(can_write));
        }
    }

    g_queue_free(queue);

    return;
}

Z_PRIVATE void __ucfg_analyzer_analyze_flg(UCFG_Analyzer *a, addr_t addr,
                                           const cs_insn *inst) {
    if (a->opts->disable_opt) {
        return;
    }

    // step (0). check whether addr is analyzed
    if (g_hash_table_lookup(a->flg_need_write, GSIZE_TO_POINTER(addr))) {
        return;
    }
    GQueue *queue = g_queue_new();

    // step (1). check whether it is ready to analyze
    {
        Buffer *succs = z_ucfg_analyzer_get_direct_successors(a, addr);
        assert(succs != NULL);
        size_t succ_n = z_buffer_get_size(succs) / sizeof(addr_t);
        addr_t *succs_array = (addr_t *)z_buffer_get_raw_buf(succs);

        // step (1.1). update flg_finished succs
        size_t finished_succ_n = 0;
        for (int i = 0; i < succ_n; i++) {
            if (g_hash_table_lookup(a->flg_need_write,
                                    GSIZE_TO_POINTER(succs_array[i]))) {
                finished_succ_n += 1;
            }
        }
        g_hash_table_insert(a->flg_finished_succs, GSIZE_TO_POINTER(addr),
                            GSIZE_TO_POINTER(finished_succ_n));

        RegState *rs = (RegState *)g_hash_table_lookup(a->reg_states,
                                                       GSIZE_TO_POINTER(addr));
        assert(rs != NULL);

        // step (1.2). check whether it is ready
        if (rs->flg_write == FLGSTATE_ALL || rs->flg_read == FLGSTATE_ALL) {
            // case A: writing/reading all means it is ready to analyze
            g_queue_push_tail(queue, GSIZE_TO_POINTER(addr));
        } else if (z_capstone_is_call(inst) || z_capstone_is_ret(inst)) {
            // case B: we are trying to do an intra-procedure analysis
            g_queue_push_tail(queue, GSIZE_TO_POINTER(addr));
        } else if (succ_n == 0) {
            // case C: for instruction without successors, it is ready to
            // analyze
            g_queue_push_tail(queue, GSIZE_TO_POINTER(addr));
        } else if (succ_n == finished_succ_n) {
            // case D: all successors are done with analysis (it actually can be
            // mergied into case C, but for clarity we set it as an individual
            // case)
            g_queue_push_tail(queue, GSIZE_TO_POINTER(addr));
        }
    }

    // step (2). do analysis and propagate the result
    while (!g_queue_is_empty(queue)) {
        // step (2.1). pop from queue and set a flag on result (distinguished
        // from non-existed key)
        addr_t cur_addr = (addr_t)g_queue_pop_head(queue);
        const cs_insn *cur_inst = (const cs_insn *)g_hash_table_lookup(
            a->insts, GSIZE_TO_POINTER(cur_addr));
        assert(cur_inst);

        FLGState need_write = FLGSTATE_ALL + 1;
        assert(!g_hash_table_lookup(a->flg_need_write,
                                    GSIZE_TO_POINTER(cur_addr)));

        // step (2.2). basic infomration
        Buffer *preds = z_ucfg_analyzer_get_direct_predecessors(a, cur_addr);
        assert(preds != NULL);
        size_t pred_n = z_buffer_get_size(preds) / sizeof(addr_t);

        Buffer *succs = z_ucfg_analyzer_get_direct_successors(a, cur_addr);
        assert(succs != NULL);
        size_t succ_n = z_buffer_get_size(succs) / sizeof(addr_t);

        RegState *rs = (RegState *)g_hash_table_lookup(
            a->reg_states, GSIZE_TO_POINTER(cur_addr));
        assert(rs != NULL);

        // step (2.3). calculate need to write
        if (rs->flg_write == FLGSTATE_ALL) {
            // case A.1: write all
            need_write |= 0;
        } else if (rs->flg_read == FLGSTATE_ALL) {
            // case A.2: read all
            need_write |= FLGSTATE_ALL;
        } else if (z_capstone_is_call(cur_inst) ||
                   z_capstone_is_ret(cur_inst)) {
            // case B: call & ret
            need_write |= 0;
        } else if (succ_n == 0) {
            // case C: no successors
            need_write |= FLGSTATE_ALL;
        } else if (succ_n ==
                   (size_t)g_hash_table_lookup(a->flg_finished_succs,
                                               GSIZE_TO_POINTER(cur_addr))) {
            FLGState post_need_write = 0;
            addr_t *succs_array = (addr_t *)z_buffer_get_raw_buf(succs);
            for (int i = 0; i < succ_n; i++) {
                FLGState succ_need_write = (FLGState)g_hash_table_lookup(
                    a->flg_need_write, GSIZE_TO_POINTER(succs_array[i]));
                assert(succ_need_write);
                post_need_write |= succ_need_write;
            }
            need_write |= post_need_write & (FLGSTATE_ALL ^ rs->flg_write);
        } else {
            EXITME("incomplete address in analysis: %#lx", cur_addr);
        }

        // step (2.4). do not forget flag read by it self
        need_write |= rs->flg_read;

        // step (2.5). update need_write
        g_hash_table_insert(a->flg_need_write, GSIZE_TO_POINTER(cur_addr),
                            GSIZE_TO_POINTER(need_write));

        // step (2.6). update predecessors' information
        addr_t *preds_array = (addr_t *)z_buffer_get_raw_buf(preds);
        for (int i = 0; i < pred_n; i++) {
            addr_t pred = preds_array[i];
            // it is very important to check whether pred is analyzed
            if (g_hash_table_lookup(a->flg_need_write,
                                    GSIZE_TO_POINTER(pred))) {
                continue;
            }
            size_t pred_finish_succs = (size_t)g_hash_table_lookup(
                a->flg_finished_succs, GSIZE_TO_POINTER(pred));
            pred_finish_succs += 1;
            g_hash_table_insert(a->flg_finished_succs, GSIZE_TO_POINTER(pred),
                                GSIZE_TO_POINTER(pred_finish_succs));
            if (pred_finish_succs ==
                (size_t)(z_buffer_get_size(
                             z_ucfg_analyzer_get_direct_successors(a, pred)) /
                         sizeof(addr_t))) {
                g_queue_push_tail(queue, GSIZE_TO_POINTER(pred));
            }
        }
    }

    g_queue_free(queue);
}

Z_PRIVATE void __ucfg_analyzer_advance_analyze(UCFG_Analyzer *a, addr_t addr,
                                               const cs_insn *inst) {
    __ucfg_analyzer_analyze_flg(a, addr, inst);
    __ucfg_analyzer_analyze_gpr(a, addr, inst);
    __ucfg_analyzer_analyze_ret(a, addr, inst);
}

Z_PRIVATE bool __ucfg_analyzer_check_consistent(const cs_insn *inst_alice,
                                                const cs_insn *inst_bob) {
    // check size
    if (inst_alice->size != inst_bob->size) {
        return false;
    }

    // control-flow-related instructions always change analysis result
    {
        const cs_insn *inst = inst_alice;
        if (z_capstone_is_jmp(inst) || z_capstone_is_call(inst) ||
            z_capstone_is_xbegin(inst) || z_capstone_is_cjmp(inst) ||
            z_capstone_is_loop(inst) || z_capstone_is_ret(inst) ||
            z_capstone_is_terminator(inst)) {
            z_trace("CFG related instructions");
            return false;
        }
    }

    // first check instruction type
    if (inst_alice->id != inst_bob->id) {
        z_trace("inconsistent instruction types");
        return false;
    }

    cs_detail *detail_alice = inst_alice->detail;
    cs_detail *detail_bob = inst_bob->detail;

    // then check operands
    if (detail_alice->x86.op_count != detail_bob->x86.op_count) {
        z_trace("inconsistent operand count");
        return false;
    }

    // check individual operand
    for (int i = 0; i < detail_alice->x86.op_count; i++) {
        cs_x86_op *op_alice = &(detail_alice->x86.operands[i]);
        cs_x86_op *op_bob = &(detail_bob->x86.operands[i]);
        if (op_alice->type != op_bob->type) {
            z_trace("inconsisten operand type");
            return false;
        }
        switch (op_alice->type) {
            case X86_OP_REG:
                if (op_alice->reg != op_bob->reg) {
                    z_trace("inconsisten operand register");
                    return false;
                }
                break;
            case X86_OP_MEM:
                if (op_alice->mem.segment != op_bob->mem.segment) {
                    z_trace("inconsisten operand mem segment");
                    return false;
                }
                if (op_alice->mem.base != op_bob->mem.base) {
                    z_trace("inconsisten operand mem base");
                    return false;
                }
                if (op_alice->mem.index != op_bob->mem.index) {
                    z_trace("inconsisten operand mem index");
                    return false;
                }
                break;
            default:
                break;
        }
    }

    return true;
}

Z_PRIVATE void __ucfg_analyzer_new_pred_and_succ(UCFG_Analyzer *a,
                                                 addr_t src_addr,
                                                 addr_t dst_addr, UEdge edge) {
#ifdef DEBUG

#define __NEW_RELATION(relation, from_addr, to_addr)                         \
    do {                                                                     \
        Buffer *buf = NULL;                                                  \
        if (!(buf = g_hash_table_lookup(a->relation,                         \
                                        GSIZE_TO_POINTER(from_addr)))) {     \
            buf = z_buffer_create(NULL, 0);                                  \
            g_hash_table_insert(a->relation, GSIZE_TO_POINTER(from_addr),    \
                                (gpointer)buf);                              \
        }                                                                    \
                                                                             \
        addr_t *targets = (addr_t *)z_buffer_get_raw_buf(buf);               \
        size_t n = z_buffer_get_size(buf) / sizeof(addr_t);                  \
        for (size_t i = 0; i < n; i++) {                                     \
            if (targets[i] == (to_addr)) {                                   \
                EXITME("duplicated " #relation " for %#lx->%#lx", from_addr, \
                       to_addr);                                             \
            }                                                                \
        }                                                                    \
                                                                             \
        z_buffer_append_raw(buf, (uint8_t *)&(to_addr), sizeof(to_addr));    \
    } while (0)

#else

#define __NEW_RELATION(relation, from_addr, to_addr)                      \
    do {                                                                  \
        Buffer *buf = NULL;                                               \
        if (!(buf = g_hash_table_lookup(a->relation,                      \
                                        GSIZE_TO_POINTER(from_addr)))) {  \
            buf = z_buffer_create(NULL, 0);                               \
            g_hash_table_insert(a->relation, GSIZE_TO_POINTER(from_addr), \
                                (gpointer)buf);                           \
        }                                                                 \
        z_buffer_append_raw(buf, (uint8_t *)&(to_addr), sizeof(to_addr)); \
    } while (0)

#endif

    if (edge & DIRECT_UEDGE) {
        __NEW_RELATION(direct_succs, src_addr, dst_addr);
        __NEW_RELATION(direct_preds, dst_addr, src_addr);
    }

    if (edge & INTRA_UEDGE) {
        __NEW_RELATION(intra_succs, src_addr, dst_addr);
        __NEW_RELATION(intra_preds, dst_addr, src_addr);
    }

    __NEW_RELATION(all_succs, src_addr, dst_addr);
    __NEW_RELATION(all_preds, dst_addr, src_addr);

#undef __NEW_RELATION
}

Z_PRIVATE void __ucfg_analyzer_init_analyze(UCFG_Analyzer *a, addr_t addr,
                                            const cs_insn *inst) {
    assert(inst != NULL);

    cs_detail *detail = inst->detail;

    if (z_capstone_is_cjmp(inst) || z_capstone_is_loop(inst)) {
        assert((detail->x86.op_count == 1) &&
               (detail->x86.operands[0].type == X86_OP_IMM));

        // avoid dupilicated succs/preds
        if (true) {
            __ucfg_analyzer_new_pred_and_succ(a, addr, addr + inst->size,
                                              DIRECT_UEDGE | INTRA_UEDGE);
        }
        if (detail->x86.operands[0].imm != addr + inst->size) {
            __ucfg_analyzer_new_pred_and_succ(a, addr,
                                              detail->x86.operands[0].imm,
                                              DIRECT_UEDGE | INTRA_UEDGE);
        }

    } else if (z_capstone_is_jmp(inst) || z_capstone_is_xbegin(inst)) {
        if ((detail->x86.op_count == 1) &&
            (detail->x86.operands[0].type == X86_OP_IMM)) {
            __ucfg_analyzer_new_pred_and_succ(a, addr,
                                              detail->x86.operands[0].imm,
                                              DIRECT_UEDGE | INTRA_UEDGE);
        }
    } else if (z_capstone_is_call(inst)) {
        ELF *e = z_binary_get_elf(a->binary);
        if ((detail->x86.op_count == 1) &&
            (detail->x86.operands[0].type == X86_OP_IMM)) {
            // get callee first
            addr_t callee_addr = detail->x86.operands[0].imm;

            // add the inter-procedure edge (the call edge)
            __ucfg_analyzer_new_pred_and_succ(a, addr, callee_addr,
                                              DIRECT_UEDGE);

            // check plt
            const LFuncInfo *lf_info = z_elf_get_plt_info(e, callee_addr);
            if (lf_info && lf_info->cfg_info == LCFG_RET) {
                if (callee_addr == addr + inst->size) {
                    EXITME("invalid PLT call: " CS_SHOW_INST(inst));
                }
                __ucfg_analyzer_new_pred_and_succ(a, addr, addr + inst->size,
                                                  INTRA_UEDGE);
            }
        } else {
            // let check GOT call
            addr_t got_addr = INVALID_ADDR;
            if (z_capstone_is_pc_related_ucall(inst, &got_addr) ||
                (!z_elf_get_is_pie(e) &&
                 z_capstone_is_const_mem_ucall(inst, &got_addr))) {
                const LFuncInfo *lf_info = z_elf_get_got_info(e, got_addr);
                if (lf_info && lf_info->cfg_info == LCFG_RET) {
                    __ucfg_analyzer_new_pred_and_succ(
                        a, addr, addr + inst->size, INTRA_UEDGE);
                }
            }
        }
    } else if (z_capstone_is_terminator(inst)) {
        // do nothing for terminator
    } else {
        __ucfg_analyzer_new_pred_and_succ(a, addr, addr + inst->size,
                                          DIRECT_UEDGE | INTRA_UEDGE);
    }
}

Z_API UCFG_Analyzer *z_ucfg_analyzer_create(Binary *binary, SysOptArgs *opts) {
    UCFG_Analyzer *a = STRUCT_ALLOC(UCFG_Analyzer);

    a->binary = binary;

    a->opts = opts;

    a->insts = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    a->reg_states = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                          (GDestroyNotify)(&z_free));

    a->direct_preds =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                              (GDestroyNotify)(&z_buffer_destroy));
    a->direct_succs =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                              (GDestroyNotify)(&z_buffer_destroy));
    a->intra_preds = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                           (GDestroyNotify)(&z_buffer_destroy));
    a->intra_succs = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                           (GDestroyNotify)(&z_buffer_destroy));
    a->all_preds = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                         (GDestroyNotify)(&z_buffer_destroy));
    a->all_succs = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                         (GDestroyNotify)(&z_buffer_destroy));

    a->flg_finished_succs =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    a->flg_need_write =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    a->gpr_analyzed_succs =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    a->gpr_can_write =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    a->can_ret =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    return a;
}

Z_API void z_ucfg_analyzer_destroy(UCFG_Analyzer *a) {
    g_hash_table_destroy(a->insts);
    g_hash_table_destroy(a->reg_states);
    g_hash_table_destroy(a->direct_preds);
    g_hash_table_destroy(a->direct_succs);
    g_hash_table_destroy(a->intra_preds);
    g_hash_table_destroy(a->intra_succs);
    g_hash_table_destroy(a->all_preds);
    g_hash_table_destroy(a->all_succs);
    g_hash_table_destroy(a->flg_finished_succs);
    g_hash_table_destroy(a->flg_need_write);
    g_hash_table_destroy(a->gpr_analyzed_succs);
    g_hash_table_destroy(a->gpr_can_write);
    g_hash_table_destroy(a->can_ret);

    z_free(a);
}

Z_API void z_ucfg_analyzer_add_inst(UCFG_Analyzer *a, addr_t addr,
                                    const cs_insn *inst,
                                    bool maybe_duplicated) {
    assert(a != NULL);

    if (maybe_duplicated) {
        cs_insn *ori_inst =
            (cs_insn *)g_hash_table_lookup(a->insts, GSIZE_TO_POINTER(addr));
        if (ori_inst) {
            if (!__ucfg_analyzer_check_consistent(ori_inst, inst)) {
                EXITME("inconsistent instruction update " CS_SHOW_INST(inst));
            }
            g_hash_table_insert(a->insts, GSIZE_TO_POINTER(addr),
                                (gpointer)inst);
            return;
        }
    }

    // update insts
    assert(!g_hash_table_lookup(a->insts, GSIZE_TO_POINTER(addr)));
    g_hash_table_insert(a->insts, GSIZE_TO_POINTER(addr), (gpointer)inst);

    // update register states
    RegState *rs = z_capstone_get_register_state(inst);
    g_hash_table_insert(a->reg_states, GSIZE_TO_POINTER(addr), (gpointer)rs);

    /*
     * XXX: it is important that following analysis happens in order and
     * closely.
     */
    // initial analysis
    __ucfg_analyzer_init_analyze(a, addr, inst);
    // advanced analysis
    __ucfg_analyzer_advance_analyze(a, addr, inst);
}

Z_API Buffer *z_ucfg_analyzer_get_direct_successors(UCFG_Analyzer *a,
                                                    addr_t addr) {
    assert(a != NULL);
    return __UCFG_ANALYZER_GHASHTABLE_GET_BUFFER(a->direct_succs,
                                                 GSIZE_TO_POINTER(addr));
}

Z_API Buffer *z_ucfg_analyzer_get_direct_predecessors(UCFG_Analyzer *a,
                                                      addr_t addr) {
    assert(a != NULL);
    return __UCFG_ANALYZER_GHASHTABLE_GET_BUFFER(a->direct_preds,
                                                 GSIZE_TO_POINTER(addr));
}

Z_API Buffer *z_ucfg_analyzer_get_intra_successors(UCFG_Analyzer *a,
                                                   addr_t addr) {
    assert(a != NULL);
    return __UCFG_ANALYZER_GHASHTABLE_GET_BUFFER(a->intra_succs,
                                                 GSIZE_TO_POINTER(addr));
}

Z_API Buffer *z_ucfg_analyzer_get_intra_predecessors(UCFG_Analyzer *a,
                                                     addr_t addr) {
    assert(a != NULL);
    return __UCFG_ANALYZER_GHASHTABLE_GET_BUFFER(a->intra_preds,
                                                 GSIZE_TO_POINTER(addr));
}

Z_API Buffer *z_ucfg_analyzer_get_all_successors(UCFG_Analyzer *a,
                                                 addr_t addr) {
    assert(a != NULL);
    return __UCFG_ANALYZER_GHASHTABLE_GET_BUFFER(a->all_succs,
                                                 GSIZE_TO_POINTER(addr));
}

Z_API Buffer *z_ucfg_analyzer_get_all_predecessors(UCFG_Analyzer *a,
                                                   addr_t addr) {
    assert(a != NULL);
    return __UCFG_ANALYZER_GHASHTABLE_GET_BUFFER(a->all_preds,
                                                 GSIZE_TO_POINTER(addr));
}

Z_API FLGState z_ucfg_analyzer_get_flg_need_write(UCFG_Analyzer *a,
                                                  addr_t addr) {
    FLGState state = (FLGState)g_hash_table_lookup(a->flg_need_write,
                                                   GSIZE_TO_POINTER(addr));
    if (!state) {
        // there is not enough infomration to analyze this address
        return FLGSTATE_ALL;
    } else {
        return state & FLGSTATE_ALL;
    }
}

Z_API GPRState z_ucfg_analyzer_get_gpr_can_write(UCFG_Analyzer *a,
                                                 addr_t addr) {
    GPRState state =
        (GPRState)g_hash_table_lookup(a->gpr_can_write, GSIZE_TO_POINTER(addr));
    return state & GPRSTATE_ALL;
}

Z_API RegState *z_ucfg_analyzer_get_register_state(UCFG_Analyzer *a,
                                                   addr_t addr) {
    return (RegState *)g_hash_table_lookup(a->reg_states,
                                           GSIZE_TO_POINTER(addr));
}

#undef __UCFG_ANALYZER_GHASHTABLE_GET_BUFFER
