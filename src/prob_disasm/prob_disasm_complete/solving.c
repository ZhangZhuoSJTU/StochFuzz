/*
 * Normalize probabilities
 */
Z_PRIVATE void __prob_disassembler_normalize_prob(ProbDisassembler *pd);

/*
 * Restrain probabilities based on control flow constrains
 */
Z_PRIVATE void __prob_disassembler_restrain_prob(ProbDisassembler *pd);

/*
 * Spread hints to occluded instructions
 */
Z_PRIVATE void __prob_disassembler_spread_hints(ProbDisassembler *pd);

#define __DECLARE_RESTRAIN(T, op)                                              \
    Z_PRIVATE void __prob_disassembler_restrain_##T(ProbDisassembler *pd) {    \
        addr_t text_addr = pd->text_addr;                                      \
        size_t text_size = pd->text_size;                                      \
                                                                               \
        /* step [1]. calculate better T for each scc */                        \
        AddrDict(double128_t, dag_better);                                     \
        z_addr_dict_init(dag_better, 0, pd->scc_n);                            \
        for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {  \
            double128_t T = NAN;                                               \
            __prob_disassembler_get_##T(pd, addr, &T);                         \
            assert(!isnan(T));                                                 \
                                                                               \
            uint32_t scc_id = z_addr_dict_get(pd->addr2sccid, addr);           \
                                                                               \
            if (z_addr_dict_exist(dag_better, scc_id)) {                       \
                double128_t T##_ = z_addr_dict_get(dag_better, scc_id);        \
                if (T op T##_) {                                               \
                    z_addr_dict_set(dag_better, scc_id, T);                    \
                }                                                              \
            } else {                                                           \
                z_addr_dict_set(dag_better, scc_id, T);                        \
            }                                                                  \
        }                                                                      \
                                                                               \
        /* step [2]. restrain T */                                             \
        for (GList *l = pd->topo->tail; l != NULL; l = l->prev) {              \
            uint32_t scc_id = (uint32_t)l->data;                               \
                                                                               \
            assert(z_addr_dict_exist(dag_better, scc_id));                     \
                                                                               \
            double128_t T = z_addr_dict_get(dag_better, scc_id);               \
                                                                               \
            GHashTable *pred_scc_ids = z_addr_dict_get(pd->dag_preds, scc_id); \
            GList *list_pred_scc_ids = g_hash_table_get_keys(pred_scc_ids);    \
            for (GList *ll = list_pred_scc_ids; ll != NULL; ll = ll->next) {   \
                uint32_t pred_scc_id = (uint32_t)ll->data;                     \
                                                                               \
                double128_t pred_##T =                                         \
                    z_addr_dict_get(dag_better, pred_scc_id);                  \
                                                                               \
                if (T op pred_##T) {                                           \
                    z_addr_dict_set(dag_better, pred_scc_id, T);               \
                }                                                              \
            }                                                                  \
            g_list_free(list_pred_scc_ids);                                    \
        }                                                                      \
                                                                               \
        /* step [3]. reassign T for each address */                            \
        for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {  \
            uint32_t scc_id = z_addr_dict_get(pd->addr2sccid, addr);           \
                                                                               \
            assert(z_addr_dict_exist(dag_better, scc_id));                     \
                                                                               \
            __prob_disassembler_reset_##T(                                     \
                pd, addr, z_addr_dict_get(dag_better, scc_id));                \
        }                                                                      \
                                                                               \
        z_addr_dict_destroy(dag_better);                                       \
    }

__DECLARE_RESTRAIN(D, >);
__DECLARE_RESTRAIN(P, <);

#undef __DECLARE_RESTRAIN

Z_PRIVATE void __prob_disassembler_normalize_prob(ProbDisassembler *pd) {
    Disassembler *d = pd->base;
    addr_t text_addr = pd->text_addr;
    size_t text_size = pd->text_size;

    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
        double128_t D = NAN;
        __prob_disassembler_get_D(pd, addr, &D);
        assert(!isnan(D));

        // check P first to make sure a 100% data is still data
        double128_t P = NAN;
        if (__prob_disassembler_get_P(pd, addr, &P)) {
            if (__double128_equal(P, 0.0)) {
                continue;
            }
        }

        if (__double128_equal(D, 1.0)) {
            __prob_disassembler_reset_P(pd, addr, 0.0);
            continue;
        }

        if (__double128_equal(D, 0.0)) {
            __prob_disassembler_reset_P(pd, addr, 1.0);
            continue;
        }

        double128_t s = 1.0 / D;

        if (isinf(s)) {
            __prob_disassembler_reset_P(pd, addr, 1.0);
            continue;
        }

        Iter(addr_t, occ_addrs);
        z_iter_init_from_buf(occ_addrs,
                             z_disassembler_get_occluded_addrs(d, addr));

        while (!z_iter_is_empty(occ_addrs)) {
            addr_t occ_addr = *(z_iter_next(occ_addrs));

            double128_t occ_D = NAN;
            __prob_disassembler_get_D(pd, occ_addr, &occ_D);
            assert(!isnan(occ_D));

            if (__double128_equal(occ_D, 0.0)) {
                s = +INFINITY;
            } else {
                s += 1.0 / occ_D;
            }
        }
        assert(!isnan(s));

        double128_t final_P = (1.0 / D) / s;
        assert(!isnan(final_P));
        if (!isnan(P)) {
            size_t n = pd->round_n;
            assert(n);

            final_P = (final_P / (n + 1)) * n + P / (n + 1);
        }

        __prob_disassembler_reset_P(pd, addr, final_P);
    }

    __prob_disassembler_restrain_P(pd);
}

Z_PRIVATE void __prob_disassembler_restrain_prob(ProbDisassembler *pd) {
    __prob_disassembler_restrain_D(pd);
}

Z_PRIVATE void __prob_disassembler_spread_hints(ProbDisassembler *pd) {
    Disassembler *d = pd->base;
    addr_t text_addr = pd->text_addr;
    size_t text_size = pd->text_size;

    // step [1]. use RH to update D, and reset any D bigger than 1.0 as 1.0
    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
        double128_t RH = NAN;
        if (__prob_disassembler_get_RH(pd, addr, &RH)) {
            __prob_disassembler_update_D(pd, addr, RH);
        }

        cs_insn *inst = z_disassembler_get_superset_disasm(d, addr);
        if (!inst) {
            assert(isnan(RH) || isinf(RH));  // we may update inst_lost as +inf
            __prob_disassembler_reset_D(pd, addr, 1.0);
        }

        double128_t D = NAN;
        if (__prob_disassembler_get_D(pd, addr, &D)) {
            // XXX: when D is nan or inf, it means addr has a very strong data
            // hint and a strong inst hint. As we are trying to avoid false
            // postive, in this case, we will set it as data.
            if (isnan(D) || isinf(D) || D > 1.0) {
                __prob_disassembler_reset_D(pd, addr, 1.0);
            }
        }
    }

    // step [2]. spread D into occluded instructions
    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
        double128_t min_D = NAN;

        // ignore the ones already with D value
        if (__prob_disassembler_get_D(pd, addr, &min_D)) {
            continue;
        }

        assert(z_disassembler_get_occluded_addrs(d, addr));

        Iter(addr_t, occ_addrs);
        z_iter_init_from_buf(occ_addrs,
                             z_disassembler_get_occluded_addrs(d, addr));

        while (!z_iter_is_empty(occ_addrs)) {
            addr_t occ_addr = *(z_iter_next(occ_addrs));
            double128_t D = NAN;

            if (__prob_disassembler_get_D(pd, occ_addr, &D)) {
                if (isnan(min_D) || D < min_D) {
                    min_D = D;
                }
            }
        }

        // XXX: note here, for a given address, if all addresses occluded with
        // it are 100% data, it should be data. (the threshold 1.0 can be
        // changed in the future -- maybe)
        // TODO: the logic here is weird.
        if (isnan(min_D) || __double128_equal(min_D, 1.0)) {
            __prob_disassembler_reset_D(pd, addr, 1.0);
        } else {
            __prob_disassembler_reset_D(pd, addr, 1.0 - min_D);
        }
    }
}
