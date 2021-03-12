/*
 * Register info
 */
typedef struct reg_info_t {
    GPRState gpr;
    XMMState xmm;
    YMMState ymm;
    ZMMState zmm;
} RegInfo;

/*
 * Coolect hints from registers' use-def
 */
Z_PRIVATE void __prob_disassembler_reg_hints_dfs(
    ProbDisassembler *pd, GHashTable *seen,
    Buffer *(*get_next)(InstAnalyzer *, addr_t),
    void (*update_info)(ProbDisassembler *, addr_t, RegInfo *), addr_t cur_addr,
    RegInfo *info, bool is_first_addr);

/*
 * Data length threshold
 */
#define STRING_LENGTH_THRESHOLD 6
#define VALUE_LENGTH_THRESHOLD 4
#define CONFIDENT_LENGTH_THRESHOLD 100

/*
 * Code pattern distance
 */
#define CMP_CJMP_DISTANCE 2
#define ARG_CALL_DISTANCE 2

/*
 * Collect control-flow-related hints
 */
Z_PRIVATE void __prob_disassembler_collect_cf_hints(ProbDisassembler *pd);

/*
 * Collect pop-ret hints
 */
Z_PRIVATE void __prob_disassembler_collect_pop_ret_hints(ProbDisassembler *pd);

/*
 * Collect cmp/test-cjmp hints
 */
Z_PRIVATE void __prob_disassembler_collect_cmp_cjmp_hints(ProbDisassembler *pd);

/*
 * Collect arg-call hints
 */
Z_PRIVATE void __prob_disassembler_collect_arg_call_hints(ProbDisassembler *pd);

/*
 * Collect register-related hints
 */
Z_PRIVATE void __prob_disassembler_collect_reg_hints(ProbDisassembler *pd);

/*
 * Collect string hints
 */
Z_PRIVATE void __prob_disassembler_collect_str_hints(ProbDisassembler *pd);

/*
 * Collect value hints
 */
Z_PRIVATE void __prob_disassembler_collect_value_hints(ProbDisassembler *pd);

Z_PRIVATE void __prob_disassembler_reg_hints_dfs(
    ProbDisassembler *pd, GHashTable *seen,
    Buffer *(*get_next)(InstAnalyzer *, addr_t),
    void (*update_info)(ProbDisassembler *, addr_t, RegInfo *), addr_t cur_addr,
    RegInfo *info, bool is_first_addr) {
    Disassembler *d = pd->base;

    // step [0]. if info in zero, we do not need to go deeper
    if (!info->gpr && !info->xmm && !info->ymm && !info->zmm) {
        return;
    }

    // step [1]. check cur_addr is valid
    if (!z_disassembler_get_superset_disasm(d, cur_addr)) {
        return;
    }

    // step [2]. get all necessary information
    Iter(addr_t, next_addrs);
    z_iter_init_from_buf(next_addrs, (*get_next)(d->inst_analyzer, cur_addr));

    // step [3]. collect hints and update next info
    RegInfo backup_info = *info;
    if (!is_first_addr) {
        (*update_info)(pd, cur_addr, info);
    }

    // step [4]. go deep
    while (!z_iter_is_empty(next_addrs)) {
        addr_t next_addr = *(z_iter_next(next_addrs));
        // check seen
        if (g_hash_table_lookup(seen, GSIZE_TO_POINTER(next_addr))) {
            continue;
        }
        g_hash_table_insert(seen, GSIZE_TO_POINTER(next_addr),
                            GSIZE_TO_POINTER(1));

        // deep search
        __prob_disassembler_reg_hints_dfs(pd, seen, get_next, update_info,
                                          next_addr, info, false);
    }

    // step [5]. restore info
    *info = backup_info;
}

Z_PRIVATE void __prob_disassembler_collect_cf_hints(ProbDisassembler *pd) {
    // step [0]. create call_/jmp_ targets and other basic information
    GHashTable *call_targets =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                              (GDestroyNotify)(&z_buffer_destroy));
    GHashTable *jmp_targets =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                              (GDestroyNotify)(&z_buffer_destroy));

    Disassembler *d = pd->base;

    ELF *e = z_binary_get_elf(pd->binary);
    addr_t text_addr = pd->text_addr;
    size_t text_size = pd->text_size;

    addr_t init_addr = z_elf_get_shdr_init(e)->sh_addr;
    size_t init_size = z_elf_get_shdr_init(e)->sh_size;

    addr_t fini_addr = z_elf_get_shdr_fini(e)->sh_addr;
    size_t fini_size = z_elf_get_shdr_fini(e)->sh_size;

    size_t plt_n = z_elf_get_plt_n(e);

    // step [2]. main loop to check all instruction
    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
        // step [2.1]. get corresponding instruction
        cs_insn *inst = z_disassembler_get_superset_disasm(d, addr);
        if (!inst) {
            continue;
        }

        // step [2.2]. check the instruction only has one imm operand
        cs_detail *detail = inst->detail;
        if ((detail->x86.op_count != 1) ||
            (detail->x86.operands[0].type != X86_OP_IMM)) {
            continue;
        }

        // step [2.3]. handle different cf transfer instruction
        addr_t target = detail->x86.operands[0].imm;

#define __COLLECT_CF_TARGET(TYPE, plt_check, targets)                       \
    do {                                                                    \
        /* pre-check invalid prefix */                                      \
        if (*((uint32_t *)(inst->detail->x86.prefix))) {                    \
            z_trace("find invalid prefix: " CS_SHOW_INST(inst));            \
            continue;                                                       \
        }                                                                   \
                                                                            \
        /* additional check for invalid prefix: FUCK capstone */            \
        KS_ASM(inst->address, "%s %s", inst->mnemonic, inst->op_str);       \
        if (ks_size != inst->size) {                                        \
            z_trace("find invalid prefix: " CS_SHOW_INST(inst));            \
            continue;                                                       \
        }                                                                   \
                                                                            \
        /* check PLT transfer */                                            \
        if (z_elf_check_plt(e, target)) {                                   \
            /* for PLT transfer, we have further check */                   \
            if (plt_check) {                                                \
                z_trace("find PLT " #TYPE ": " CS_SHOW_INST(inst));         \
                __prob_disassembler_update_inst_hint(                       \
                    pd, addr, HINT(PLT_##TYPE, BASE_CF(inst) * plt_n));     \
            }                                                               \
            continue;                                                       \
        }                                                                   \
                                                                            \
        /* check outsider transfer */                                       \
        if ((target < text_addr || target >= text_addr + text_size) &&      \
            (target < init_addr || target >= init_addr + init_size) &&      \
            (target < fini_addr || target >= fini_addr + fini_size)) {      \
            z_trace("find outside " #TYPE ": " CS_SHOW_INST(inst));         \
            __prob_disassembler_update_inst_lost(                           \
                pd, addr, LOST(OUTSIDE_##TYPE, BASE_CF(inst) * text_size)); \
            continue;                                                       \
        }                                                                   \
                                                                            \
        /* check target is valid */                                         \
        if (!z_disassembler_get_superset_disasm(d, target)) {               \
            continue;                                                       \
        }                                                                   \
                                                                            \
        /* check it does not jump into its next instruction */              \
        if (target == inst->address + inst->size) {                         \
            continue;                                                       \
        }                                                                   \
                                                                            \
        /* maintain a relation from dst address to src address */           \
        Buffer *dst2src =                                                   \
            g_hash_table_lookup((targets), GSIZE_TO_POINTER(target));       \
        if (!dst2src) {                                                     \
            dst2src = z_buffer_create(NULL, 0);                             \
            g_hash_table_insert((targets), GSIZE_TO_POINTER(target),        \
                                (gpointer)(dst2src));                       \
        }                                                                   \
        z_buffer_append_raw(dst2src, (uint8_t *)&addr, sizeof(addr));       \
    } while (0)

        if (z_capstone_is_call(inst)) {
            __COLLECT_CF_TARGET(CALL, inst->size == 5, call_targets);
        } else if (z_capstone_is_jmp(inst) || z_capstone_is_cjmp(inst)) {
            __COLLECT_CF_TARGET(
                JMP, (inst->size == 5 && z_capstone_is_jmp(inst)), jmp_targets);
        }

#undef __COLLECT_CF_TARGET
    }

    // step [3]. collect hints from converged calls
    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
        Buffer *callers_buf =
            (Buffer *)g_hash_table_lookup(call_targets, GSIZE_TO_POINTER(addr));
        if (!callers_buf) {
            continue;
        }

        Iter(addr_t, callers);
        z_iter_init_from_buf(callers, callers_buf);
        assert(!z_iter_is_empty(callers));
        if (z_iter_get_size(callers) == 1) {
            continue;
        }

        while (!z_iter_is_empty(callers)) {
            addr_t caller = *(z_iter_next(callers));

            cs_insn *caller_inst =
                z_disassembler_get_superset_disasm(d, caller);
            assert(caller_inst);
            __prob_disassembler_update_inst_hint(
                pd, caller,
                HINT(CONVERGED_CALL,
                     BASE_CF(caller_inst) / (z_iter_get_size(callers) - 1)));
        }
    }
    g_hash_table_destroy(call_targets);

    // step [4]. collect hints from converged jumps and cross jumps
    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
        Buffer *jmp_sources_buf =
            (Buffer *)g_hash_table_lookup(jmp_targets, GSIZE_TO_POINTER(addr));
        if (!jmp_sources_buf) {
            continue;
        }

        Iter(addr_t, jmp_sources);
        z_iter_init_from_buf(jmp_sources, jmp_sources_buf);
        assert(!z_iter_is_empty(jmp_sources));

        // step [4.1]. collect hints from converged jumps
        size_t jmp_sources_n = z_iter_get_size(jmp_sources);
        if (jmp_sources_n > 1) {
            while (!z_iter_is_empty(jmp_sources)) {
                addr_t jmp_source = *(z_iter_next(jmp_sources));

                cs_insn *jmp_source_inst =
                    z_disassembler_get_superset_disasm(d, jmp_source);
                assert(jmp_source_inst);
                __prob_disassembler_update_inst_hint(
                    pd, jmp_source,
                    HINT(CONVERGED_JMP,
                         BASE_CF(jmp_source_inst) / (jmp_sources_n - 1)));
            }
        }

        // step [4.2]. collect hints from crossed jumps
        assert(addr > 7);
        // As the longest jump, which we will consider, is 7-bytes
        for (size_t pred = addr - 7; pred < addr; pred++) {
            // get predecessors
            cs_insn *pred_inst = z_disassembler_get_superset_disasm(d, pred);
            if (!pred_inst) {
                goto NEXT_PRED;
            }

            // check cross
            if (pred + pred_inst->size != addr) {
                goto NEXT_PRED;
            }

            // check pred is jmp and cjmp
            if (!z_capstone_is_jmp(pred_inst) &&
                !z_capstone_is_cjmp(pred_inst)) {
                goto NEXT_PRED;
            }

            // check pred's succs are valid
            Iter(addr_t, pred_succs);
            z_iter_init_from_buf(pred_succs, z_inst_analyzer_get_successors(
                                                 d->inst_analyzer, pred));

            while (!z_iter_is_empty(pred_succs)) {
                addr_t pred_succ = *(z_iter_next(pred_succs));
                if (!z_disassembler_get_superset_disasm(d, pred_succ)) {
                    goto NEXT_PRED;
                }
            }

            // collect hints for pred, where we assume most crossed jump is only
            // 1-byte
            __prob_disassembler_update_inst_hint(
                pd, pred, HINT(CROSSED_JMP, BASE_CF_RAW(1) / jmp_sources_n));

            // collect hints for jump sources
            z_iter_reset(jmp_sources);
            while (!z_iter_is_empty(jmp_sources)) {
                addr_t jmp_source = *(z_iter_next(jmp_sources));

                z_trace("find crossed JMP: %#lx - %#lx", pred, jmp_source);
                cs_insn *jmp_source_inst =
                    z_disassembler_get_superset_disasm(d, jmp_source);
                assert(jmp_source_inst);
                __prob_disassembler_update_inst_hint(
                    pd, jmp_source,
                    HINT(CROSSED_JMP,
                         BASE_CF(jmp_source_inst) / jmp_sources_n));
            }

        NEXT_PRED:;
        }
    }
    g_hash_table_destroy(jmp_targets);
}

/*
 * Functions for updating info.
 * Note that following two functions will only be used during dfs
 */
Z_PRIVATE void __update_info_for_usedef_reg_hint(ProbDisassembler *pd,
                                                 addr_t addr, RegInfo *info) {
    Disassembler *d = pd->base;

    RegState *rs = z_inst_analyzer_get_register_state(d->inst_analyzer, addr);
    assert(rs);

    if (rs->gpr_write_32_64 & info->gpr) {
        __prob_disassembler_update_inst_hint(pd, addr,
                                             HINT(USEDEF_GPR, BASE_REG));
        info->gpr &= (~rs->gpr_write_32_64);
    }

#define __SSE_TEMPLATE(T)                                                     \
    do {                                                                      \
        if (rs->T##_write & info->T) {                                        \
            __prob_disassembler_update_inst_hint(pd, addr,                    \
                                                 HINT(USEDEF_SSE, BASE_REG)); \
            info->T &= (~rs->T##_write);                                      \
        }                                                                     \
    } while (0)

    __SSE_TEMPLATE(xmm);
    __SSE_TEMPLATE(ymm);
    __SSE_TEMPLATE(zmm);

#undef __SSE_TEMPLATE
}

Z_PRIVATE void __update_info_for_killed_reg_hint(ProbDisassembler *pd,
                                                 addr_t addr, RegInfo *info) {
    Disassembler *d = pd->base;

    RegState *rs = z_inst_analyzer_get_register_state(d->inst_analyzer, addr);
    assert(rs);

    if (rs->gpr_write_32_64 & info->gpr) {
        __prob_disassembler_update_inst_lost(pd, addr,
                                             LOST(KILLED_GPR, BASE_REG));
        info->gpr &= (~rs->gpr_write_32_64);
    }
    if (rs->gpr_read_32_64 & info->gpr) {
        info->gpr &= (~rs->gpr_read_32_64);
    }

#define __SSE_TEMPLATE(T)                                                     \
    do {                                                                      \
        if (rs->T##_write & info->T) {                                        \
            __prob_disassembler_update_inst_lost(pd, addr,                    \
                                                 LOST(KILLED_SSE, BASE_REG)); \
            info->T &= (~rs->T##_write);                                      \
        }                                                                     \
        if (rs->T##_read & info->T) {                                         \
            info->T &= (~rs->T##_read);                                       \
        }                                                                     \
    } while (0)

    __SSE_TEMPLATE(xmm);
    __SSE_TEMPLATE(ymm);
    __SSE_TEMPLATE(zmm);

#undef __SSE_TEMPLATE
}

Z_PRIVATE void __prob_disassembler_collect_reg_hints(ProbDisassembler *pd) {
    Disassembler *d = pd->base;
    addr_t text_addr = pd->text_addr;
    size_t text_size = pd->text_size;

    GHashTable *seen =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    RegInfo info = {};

    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
        RegState *rs =
            z_inst_analyzer_get_register_state(d->inst_analyzer, addr);
        if (!rs) {
            continue;
        }

        /*
         * step [1]. get use-def hints
         */
        info.gpr = rs->gpr_read_32_64;
        info.xmm = rs->xmm_read;
        info.ymm = rs->ymm_read;
        info.zmm = rs->zmm_read;

        g_hash_table_remove_all(seen);
        g_hash_table_insert(seen, GSIZE_TO_POINTER(addr), GSIZE_TO_POINTER(1));

        __prob_disassembler_reg_hints_dfs(
            pd, seen, &z_inst_analyzer_get_predecessors,
            &__update_info_for_usedef_reg_hint, addr, &info, true);

        /*
         * step [2]. get killed hints
         */
        info.gpr = rs->gpr_write_32_64 & (~rs->gpr_read_32_64);
        info.xmm = rs->xmm_write & (~rs->xmm_read);
        info.ymm = rs->ymm_write & (~rs->ymm_read);
        info.zmm = rs->zmm_write & (~rs->zmm_read);

        g_hash_table_remove_all(seen);
        g_hash_table_insert(seen, GSIZE_TO_POINTER(addr), GSIZE_TO_POINTER(1));

        __prob_disassembler_reg_hints_dfs(
            pd, seen, &z_inst_analyzer_get_predecessors,
            &__update_info_for_killed_reg_hint, addr, &info, true);
    }
}

Z_PRIVATE void __prob_disassembler_collect_pop_ret_hints(ProbDisassembler *pd) {
    Disassembler *d = pd->base;
    addr_t text_addr = pd->text_addr;
    size_t text_size = pd->text_size;

    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
        cs_insn *inst = z_disassembler_get_superset_disasm(d, addr);
        if (!inst) {
            continue;
        }

        if (inst->id != X86_INS_POP) {
            continue;
        }

        size_t pop_n = 0;
        addr_t cur_addr = addr;
        cs_insn *cur_inst = inst;
        bool pop_ret = false;

        while (true) {
            pop_n += 1;
            cur_addr += cur_inst->size;
            cur_inst = z_disassembler_get_superset_disasm(d, cur_addr);

            if (!cur_inst) {
                break;
            }
            if (cur_inst->id == X86_INS_RET) {
                pop_ret = true;
                break;
            }
            if (cur_inst->id != X86_INS_POP) {
                break;
            }
        }

        if (!pop_ret) {
            continue;
        }

        z_trace("find %d pop at %#lx", pop_n, addr);
        __prob_disassembler_update_inst_hint(pd, addr,
                                             HINT(POP_RET, BASE_REG / pop_n));
    }
}

Z_PRIVATE void __prob_disassembler_collect_str_hints(ProbDisassembler *pd) {
    addr_t text_addr = pd->text_addr;
    size_t text_size = pd->text_size;

    ELF *e = z_binary_get_elf(pd->binary);
    Rptr *text_ptr = z_elf_vaddr2ptr(e, text_addr);

    // collect all string-like hints
    addr_t prev_string = INVALID_ADDR;
    addr_t prev_null = INVALID_ADDR;
    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
        uint8_t c = *(RPTR_DEFER(text_ptr, uint8_t));
        if (!c) {
            if (prev_string != INVALID_ADDR) {
                // we ignore null during string scanning
                prev_null = addr;
            }
        } else if (isprint(c)) {
            if (prev_string == INVALID_ADDR) {
                prev_string = addr;
                prev_null = INVALID_ADDR;
            }
        } else {
            if (prev_string != INVALID_ADDR && prev_null != INVALID_ADDR) {
                assert(prev_null > prev_string);
                size_t n = prev_null - prev_string;
                if (n > STRING_LENGTH_THRESHOLD) {
                    z_trace("find string starting from %#lx with %d bytes",
                            prev_string, n);
                    double128_t hint;
                    if (n < CONFIDENT_LENGTH_THRESHOLD) {
                        hint = HINT(STRING, BASE_STRING(n));
                    } else {
                        hint = +INFINITY;
                    }
                    for (addr_t cur_addr = prev_string; cur_addr <= prev_null;
                         cur_addr++) {
                        __prob_disassembler_update_data_hint(pd, cur_addr,
                                                             hint);
                    }
                }
            }
            prev_string = INVALID_ADDR;
            prev_null = INVALID_ADDR;
        }

        RPTR_INCR(text_ptr, uint8_t, 1);
    }

    z_rptr_destroy(text_ptr);
}

Z_PRIVATE void __prob_disassembler_collect_value_hints(ProbDisassembler *pd) {
/*
 * Macro to collect continuous numerical number:
 *      T: type (int16_t, int32_t, int64_t)
 *      B: bit offset of size (1, 2, 3)
 *      L: length threshold
 *      C: count zero and 0xff
 */
#define __COLLECT_VALUE_HINTS(T, B, L, C)                                    \
    do {                                                                     \
        assert(sizeof(T) == (1 << B));                                       \
                                                                             \
        addr_t text_addr = pd->text_addr;                                    \
        size_t text_size = pd->text_size;                                    \
        double128_t threshold = __pow_in_4(0x100, (B));                      \
        z_trace("threshold: %Lf", threshold);                                \
                                                                             \
        /* alignment */                                                      \
        text_size = BITS_ALIGN_FLOOR(text_addr + text_size, (B));            \
        text_addr = BITS_ALIGN_CELL(text_addr, (B));                         \
        text_size -= text_addr;                                              \
        z_trace("aligned range: [%#lx, %#lx]", text_addr,                    \
                text_addr + text_size - 1);                                  \
        assert(!(text_addr % sizeof(T)));                                    \
        assert(!(text_size % sizeof(T)));                                    \
                                                                             \
        ELF *e = z_binary_get_elf(pd->binary);                               \
        Rptr *text_ptr = z_elf_vaddr2ptr(e, text_addr);                      \
                                                                             \
        /* collect continued likely numerical value */                       \
        addr_t numerical_addr = INVALID_ADDR;                                \
        double128_t numerical_val = 0.0;                                     \
        for (addr_t addr = text_addr; addr < text_addr + text_size;          \
             addr += sizeof(T)) {                                            \
            T val = *(RPTR_DEFER(text_ptr, T));                              \
            double128_t val_f = (double128_t)val;                            \
            size_t n = (addr - numerical_addr) >> (B);                       \
                                                                             \
            if (numerical_addr == INVALID_ADDR) {                            \
                /* the first value */                                        \
                numerical_addr = addr;                                       \
                numerical_val = val_f;                                       \
            } else if ((!(C)) && (val == 0 || val == -1)) {                  \
                /* we ignore 0 and 0xfff..ff. Hence, do nothing. */          \
            } else if (fabsl(numerical_val - val_f) < threshold) {           \
                /* valid numerical number */                                 \
                numerical_val =                                              \
                    (numerical_val / (n + 1)) * n + (val_f / (n + 1));       \
            } else {                                                         \
                if (n > (L)) {                                               \
                    z_trace(                                                 \
                        "find %d-byte numerical array from %#lx with %d "    \
                        "elements (mean: %.2Lf)",                            \
                        sizeof(T), numerical_addr, n, numerical_val);        \
                    double128_t hint;                                        \
                    if (n < CONFIDENT_LENGTH_THRESHOLD) {                    \
                        hint = HINT(VALUE,                                   \
                                    BASE_VALUE(1 << (B), threshold * 2, n)); \
                    } else {                                                 \
                        hint = +INFINITY;                                    \
                    }                                                        \
                    for (addr_t cur_addr = numerical_addr; cur_addr < addr;  \
                         cur_addr++) {                                       \
                        __prob_disassembler_update_data_hint(pd, cur_addr,   \
                                                             hint);          \
                    }                                                        \
                }                                                            \
                                                                             \
                numerical_addr = addr;                                       \
                numerical_val = val_f;                                       \
            }                                                                \
                                                                             \
            RPTR_INCR(text_ptr, T, 1);                                       \
        }                                                                    \
                                                                             \
        z_rptr_destroy(text_ptr);                                            \
    } while (0)

    __COLLECT_VALUE_HINTS(int8_t, 0, VALUE_LENGTH_THRESHOLD << 2, true);
    __COLLECT_VALUE_HINTS(int16_t, 1, VALUE_LENGTH_THRESHOLD << 2, false);
    __COLLECT_VALUE_HINTS(int32_t, 2, VALUE_LENGTH_THRESHOLD << 1, false);
    __COLLECT_VALUE_HINTS(int64_t, 3, VALUE_LENGTH_THRESHOLD << 0, false);

#undef __COLLECT_VALUE_HINTS
}

Z_PRIVATE void __prob_disassembler_collect_cmp_cjmp_hints(
    ProbDisassembler *pd) {
    Disassembler *d = pd->base;
    addr_t text_addr = pd->text_addr;
    size_t text_size = pd->text_size;

    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
        cs_insn *inst = z_disassembler_get_superset_disasm(d, addr);

        // check valid
        if (!inst) {
            continue;
        }

        // check cmp and test
        if (inst->id != X86_INS_TEST && inst->id != X86_INS_CMP) {
            continue;
        }

        // try to find a cjmp within CMP_CJMP_DISTANCE
        bool found_cjmp = false;
        addr_t cur_addr = addr;
        cs_insn *cur_inst = inst;
        Iter(addr_t, succ_addrs);

        for (size_t i = 0; i < CMP_CJMP_DISTANCE; i++) {
            z_iter_init_from_buf(succ_addrs,
                                 z_disassembler_get_successors(d, cur_addr));
            if (z_iter_get_size(succ_addrs) != 1) {
                break;
            }

            addr_t succ_addr = *(z_iter_next(succ_addrs));
            if (succ_addr != cur_addr + cur_inst->size) {
                break;
            }

            // switch into next address
            cur_addr = succ_addr;
            cur_inst = z_disassembler_get_superset_disasm(d, cur_addr);

            if (!cur_inst) {
                break;
            }

            if (z_capstone_is_cjmp(cur_inst)) {
                found_cjmp = true;
                break;
            }
        }

        if (found_cjmp) {
            z_trace("find cmp-cjmp pattern at %#lx - %#lx", addr, cur_addr);
            __prob_disassembler_update_inst_hint(
                pd, addr, HINT(CMP_CJMP, __pow_in_4(BASE_INS, 2)));
        }
    }
}

Z_PRIVATE void __prob_disassembler_collect_arg_call_hints(
    ProbDisassembler *pd) {
    Disassembler *d = pd->base;
    addr_t text_addr = pd->text_addr;
    size_t text_size = pd->text_size;

    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
        cs_insn *inst = z_disassembler_get_superset_disasm(d, addr);

        // check valid
        if (!inst) {
            continue;
        }

        // check mov
        if (inst->id != X86_INS_MOV) {
            continue;
        }

        // check the rdi and rsi
        cs_detail *detail = inst->detail;
        if (detail->x86.operands[0].type != X86_OP_REG) {
            continue;
        }
        if (detail->x86.operands[0].reg != X86_REG_RDI &&
            detail->x86.operands[0].reg != X86_REG_RSI) {
            continue;
        }

        // try to find a call within ARG_CALL_DISTANCE
        bool found_call = false;
        addr_t cur_addr = addr;
        cs_insn *cur_inst = inst;
        Iter(addr_t, succ_addrs);

        for (size_t i = 0; i < ARG_CALL_DISTANCE; i++) {
            z_iter_init_from_buf(succ_addrs,
                                 z_disassembler_get_successors(d, cur_addr));
            if (z_iter_get_size(succ_addrs) != 1) {
                break;
            }

            addr_t succ_addr = *(z_iter_next(succ_addrs));
            if (succ_addr != cur_addr + cur_inst->size) {
                break;
            }

            // switch into next address
            cur_addr = succ_addr;
            cur_inst = z_disassembler_get_superset_disasm(d, cur_addr);

            if (!cur_inst) {
                break;
            }

            if (z_capstone_is_call(cur_inst)) {
                found_call = true;
                break;
            }
        }

        if (found_call) {
            z_trace("find arg-call pattern at %#lx - %#lx", addr, cur_addr);
            __prob_disassembler_update_inst_hint(
                pd, addr, HINT(ARG_CALL, __pow_in_4(BASE_INS, 2)));
        }
    }
}
