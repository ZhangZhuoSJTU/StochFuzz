/*
 * Propogate instruction hints
 */
Z_PRIVATE void __prob_disassembler_propogate_inst_hints(ProbDisassembler *pd);

Z_PRIVATE void __prob_disassembler_propogate_inst_hints(ProbDisassembler *pd) {
    // step [0]. basic information
    Disassembler *d = pd->base;
    addr_t text_addr = pd->text_addr;
    size_t text_size = pd->text_size;

    // step [1]. aggregate all hints within a SCC
    AddrDict(double128_t, dag_hints);
    z_addr_dict_init(dag_hints, 0, pd->scc_n);

    // XXX: invalid_sccs means those SCCs whose likelihook of being instructions
    // is quite small. Hence, we stop propogation when reaching them. Note that
    // it is different from those SCCs in pd->dag_dead which are 100% not
    // instruction boundaries.
    AddrDictFast(bool, invalid_sccs);
    z_addr_dict_init(invalid_sccs, 0, pd->scc_n);

    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
        // check addr is valid
        uint32_t scc_id = z_addr_dict_get(pd->addr2sccid, addr);
        if (!scc_id) {
            continue;
        }

        // check invalid_scc
        if (z_addr_dict_exist(pd->dag_P, scc_id) &&
            z_addr_dict_get(pd->dag_P, scc_id) < PROPAGATE_P) {
            if (!z_addr_dict_exist(invalid_sccs, scc_id)) {
                z_addr_dict_set(invalid_sccs, scc_id, true);
                z_addr_dict_set(dag_hints, scc_id, 1.0);
            }

            continue;
        }

        // we do not use hints of very rare instructions
        // TODO: get a instruction distribution to weaken the hints instead of
        // directly disabling it.
        cs_insn *inst = z_disassembler_get_superset_disasm(d, addr);
        if (z_capstone_is_rare(inst)) {
            continue;
        }

        // update aggragated hints
        double128_t addr_hint = NAN;
        if (__prob_disassembler_get_H(pd, addr, &addr_hint)) {
            if (!z_addr_dict_exist(dag_hints, scc_id)) {
                // new hints
                z_addr_dict_set(dag_hints, scc_id, addr_hint);
            } else {
                z_addr_dict_set(dag_hints, scc_id,
                                z_addr_dict_get(dag_hints, scc_id) * addr_hint);
            }
        }
    }

    // step [2]. find all predecessors of invalid scc (only for first round)
    if (!pd->round_n) {
        GQueue *queue = g_queue_new();
        g_queue_push_tail(queue, GSIZE_TO_POINTER(0));

        AddrDictFast(bool, seen);
        z_addr_dict_init(seen, 0, pd->scc_n);
        z_addr_dict_set(seen, 0, true);

        while (!g_queue_is_empty(queue)) {
            uint32_t scc_id = (uint32_t)g_queue_pop_head(queue);

            // update dag_hints and invalid_sccs
            z_addr_dict_set(pd->dag_dead, scc_id, true);
            z_addr_dict_set(invalid_sccs, scc_id, true);
            z_addr_dict_set(dag_hints, scc_id, 1.0);

            // find predecessors
            GHashTable *dag_preds = z_addr_dict_get(pd->dag_preds, scc_id);
            GList *list_dag_preds = g_hash_table_get_keys(dag_preds);
            for (GList *l = list_dag_preds; l != NULL; l = l->next) {
                uint32_t pred_scc_id = (uint32_t)l->data;
                if (z_addr_dict_exist(seen, pred_scc_id)) {
                    continue;
                }
                z_addr_dict_set(seen, pred_scc_id, true);
                g_queue_push_tail(queue, GSIZE_TO_POINTER(pred_scc_id));
            }
            g_list_free(list_dag_preds);
        }

        g_queue_free(queue);
        z_addr_dict_destroy(seen);
    }

    // step [3]. propogate hints
    for (GList *l = pd->topo->head; l != NULL; l = l->next) {
        uint32_t scc_id = (uint32_t)l->data;

        // check scc without any hint
        if (!z_addr_dict_exist(dag_hints, scc_id)) {
            continue;
        }

        // check invalid scc. If so, stop propagation.
        if (z_addr_dict_exist(invalid_sccs, scc_id)) {
            continue;
        }

        // get hints
        double128_t scc_hint = z_addr_dict_get(dag_hints, scc_id);

        // propogate hints
        GHashTable *dag_succs = z_addr_dict_get(pd->dag_succs, scc_id);

        GList *list_dag_succs = g_hash_table_get_keys(dag_succs);
        for (GList *ll = list_dag_succs; ll != NULL; ll = ll->next) {
            uint32_t succ_scc_id = (uint32_t)ll->data;

            if (!z_addr_dict_exist(dag_hints, succ_scc_id)) {
                z_addr_dict_set(dag_hints, succ_scc_id, scc_hint);
            } else {
                z_addr_dict_set(
                    dag_hints, succ_scc_id,
                    z_addr_dict_get(dag_hints, succ_scc_id) * scc_hint);
            }
        }
        g_list_free(list_dag_succs);
    }
    z_addr_dict_destroy(invalid_sccs);

    // step [4]. update RH for each address
    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
        // ignore invalid instruction
        uint32_t scc_id = z_addr_dict_get(pd->addr2sccid, addr);
        if (!scc_id) {
            continue;
        }

        if (!z_addr_dict_exist(dag_hints, scc_id)) {
            continue;
        }

        double128_t scc_hint = z_addr_dict_get(dag_hints, scc_id);

        __prob_disassembler_update_RH(pd, addr, scc_hint);
    }
    z_addr_dict_destroy(dag_hints);
}
