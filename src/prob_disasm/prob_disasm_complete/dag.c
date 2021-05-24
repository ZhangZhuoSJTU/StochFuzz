/*
 * dag.c
 * Copyright (C) 2021 Zhuo Zhang, Xiangyu Zhang
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Tarjan data
 */
typedef struct tarjan_info_t {
    AddrDict(uint32_t, low);
    AddrDict(uint32_t, dfn);
    uint32_t addr_n;
} TarjanInfo;

/*
 * Tarjan algorithm to calculate SCC (return low[cur_addr])
 */
Z_PRIVATE void __prob_disassembler_tarjan(ProbDisassembler *pd,
                                          TarjanInfo *info, GQueue *stack,
                                          GHashTable *in_stack,
                                          addr_t cur_addr);

/*
 * Bulid DAG using Tarjan algorithm
 */
Z_PRIVATE void __prob_disassembler_build_dag(ProbDisassembler *pd);

Z_PRIVATE void __prob_disassembler_tarjan(ProbDisassembler *pd,
                                          TarjanInfo *info, GQueue *stack,
                                          GHashTable *in_stack,
                                          addr_t cur_addr) {
    // step [0]. basic info
    Disassembler *d = pd->base;

    // step [1]. update low and dfn
    z_addr_dict_set(info->low, cur_addr, info->addr_n);
    z_addr_dict_set(info->dfn, cur_addr, info->addr_n);
    info->addr_n++;

    // step [2]. push into stack
    g_queue_push_tail(stack, GSIZE_TO_POINTER(cur_addr));
    g_hash_table_insert(in_stack, GSIZE_TO_POINTER(cur_addr),
                        GSIZE_TO_POINTER(1));

    // step [3]. get nexts
    size_t n = 0;
    addr_t *next_addrs = NULL;
    if (!__prob_disassembler_get_propogate_successors(pd, cur_addr, &n,
                                                      &next_addrs)) {
        EXITME("invalid successors");
    }

    // step [5]. main loop
    for (size_t i = 0; i < n; i++) {
        addr_t next_addr = next_addrs[i];

        // step [5.1]. check whether next_addr is valid instruction
        if (!z_disassembler_get_superset_disasm(d, next_addr)) {
            continue;
        }

        // step [5.2]. for non-visited next_addr
        if (!z_addr_dict_exist(info->low, next_addr)) {
            assert(!z_addr_dict_exist(info->dfn, next_addr));
            __prob_disassembler_tarjan(pd, info, stack, in_stack, next_addr);

            uint32_t cur_low = z_addr_dict_get(info->low, cur_addr);
            uint32_t next_low = z_addr_dict_get(info->low, next_addr);

            if (next_low < cur_low) {
                z_addr_dict_set(info->low, cur_addr, next_low);
            }
        } else if (g_hash_table_lookup(in_stack, GSIZE_TO_POINTER(next_addr))) {
            uint32_t cur_low = z_addr_dict_get(info->low, cur_addr);
            uint32_t next_dfn = z_addr_dict_get(info->dfn, next_addr);

            if (next_dfn < cur_low) {
                z_addr_dict_set(info->low, cur_addr, next_dfn);
            }
        }
    }

    // step [6]. get SCC
    if (z_addr_dict_get(info->dfn, cur_addr) ==
        z_addr_dict_get(info->low, cur_addr)) {
        uint32_t scc_id = pd->scc_n++;
        while (!g_queue_is_empty(stack)) {
            addr_t poped_addr = (addr_t)g_queue_pop_tail(stack);
            g_hash_table_remove(in_stack, GSIZE_TO_POINTER(poped_addr));

            z_addr_dict_set(pd->addr2sccid, poped_addr, scc_id);

            if (poped_addr == cur_addr) {
                break;
            }
        }
    }
}

Z_PRIVATE void __prob_disassembler_build_dag(ProbDisassembler *pd) {
    /*
     * step [0]. basic stuff
     */
    Disassembler *d = pd->base;
    addr_t text_addr = pd->text_addr;
    size_t text_size = pd->text_size;

    /*
     * step [1]. initialization members
     */
    z_addr_dict_init(pd->addr2sccid, pd->text_addr, pd->text_size);
    pd->scc_n = 1;  // XXX: scc_id == 0 is reserved for invalid instructions

    /*
     * step [2]. use Tarjan to calculate SCC
     */
    {
        TarjanInfo *info = z_alloc(1, sizeof(TarjanInfo));
        info->addr_n = 0;
        z_addr_dict_init(info->low, text_addr, text_size);
        z_addr_dict_init(info->dfn, text_addr, text_size);

        GQueue *stack = g_queue_new(); /* stack */
        GHashTable *in_stack =         /* whehter addr is in stack */
            g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

        for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
            // check whether addr is handled
            if (z_addr_dict_exist(pd->addr2sccid, addr)) {
                assert(z_addr_dict_exist(info->low, addr));
                assert(z_addr_dict_exist(info->dfn, addr));
                continue;
            }

            // check cur_addr is valid
            if (!z_disassembler_get_superset_disasm(d, addr)) {
                z_addr_dict_set(pd->addr2sccid, addr, 0);
                continue;
            }

            // do tarjan
            __prob_disassembler_tarjan(pd, info, stack, in_stack, addr);

            assert(g_queue_is_empty(stack));
            assert(!g_hash_table_size(in_stack));
        }

        z_info("we found %d SCCs in the superset control flow graph",
               pd->scc_n);

        // free memory
        g_hash_table_destroy(in_stack);
        g_queue_free(stack);
        z_addr_dict_destroy(info->low);
        z_addr_dict_destroy(info->dfn);
        z_free(info);
    }

    /*
     * step [3]. build DAG
     */
    z_addr_dict_init(pd->dag_succs, 0, pd->scc_n);
    z_addr_dict_init(pd->dag_preds, 0, pd->scc_n);
    z_addr_dict_init(pd->dag_dead, 0, pd->scc_n);

    z_addr_dict_init(pd->dag_P, 0, pd->scc_n);

    AddrDict(uint32_t, dag_preds_n); /* used for toposord */
    z_addr_dict_init(dag_preds_n, 0, pd->scc_n);

    {
        // step [3.1]. init all necessary members
        for (uint32_t scc_id = 0; scc_id < pd->scc_n; scc_id++) {
            z_addr_dict_set(dag_preds_n, scc_id, 0);
            z_addr_dict_set(pd->dag_succs, scc_id,
                            g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                                  NULL, NULL));
            z_addr_dict_set(pd->dag_preds, scc_id,
                            g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                                  NULL, NULL));
        }

        // step [3.2]. construct DAG based on each address's information
        for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
            // ignore invalid instructions
            assert(z_addr_dict_exist(pd->addr2sccid, addr));
            uint32_t scc_id = z_addr_dict_get(pd->addr2sccid, addr);
            if (!scc_id) {
                continue;
            }

            // get dag_succs
            GHashTable *dag_succs = z_addr_dict_get(pd->dag_succs, scc_id);

            // get succ_addrs
            size_t n = 0;
            addr_t *succ_addrs = NULL;
            if (!__prob_disassembler_get_propogate_successors(pd, addr, &n,
                                                              &succ_addrs)) {
                EXITME("invalid successors");
            }

            for (int i = 0; i < n; i++) {
                addr_t succ_addr = succ_addrs[i];

                // check succ_addr is in .text (we cannot know the outside info)
                // XXX: OUTSIDE LOST already handles this
                uint32_t succ_scc_id;
                if (succ_addr < text_addr ||
                    succ_addr >= text_addr + text_size) {
                    continue;
                }

                assert(z_addr_dict_exist(pd->addr2sccid, succ_addr));
                succ_scc_id = z_addr_dict_get(pd->addr2sccid, succ_addr);

                // and not equal to scc_id
                if (succ_scc_id == scc_id) {
                    continue;
                }

                // check whether succ_scc is in dag_succs and insert if not
                if (!g_hash_table_lookup(dag_succs,
                                         GSIZE_TO_POINTER(succ_scc_id))) {
                    // update dag_succs
                    g_hash_table_insert(dag_succs,
                                        GSIZE_TO_POINTER(succ_scc_id),
                                        GSIZE_TO_POINTER(1));

                    // update dag_preds_n
                    z_addr_dict_set(
                        dag_preds_n, succ_scc_id,
                        z_addr_dict_get(dag_preds_n, succ_scc_id) + 1);

                    // update dag_preds
                    g_hash_table_insert(
                        z_addr_dict_get(pd->dag_preds, succ_scc_id),
                        GSIZE_TO_POINTER(scc_id), GSIZE_TO_POINTER(1));
                }
            }
        }

#ifdef DEBUG
        /*
         * step [3.3]. check the correctness of DAG
         */
        size_t edge_n = 0;
        for (uint32_t scc_id = 0; scc_id < pd->scc_n; scc_id++) {
            assert(z_addr_dict_exist(dag_preds_n, scc_id));
            assert(z_addr_dict_exist(pd->dag_succs, scc_id));
            assert(z_addr_dict_exist(pd->dag_preds, scc_id));

            GHashTable *dag_succs = z_addr_dict_get(pd->dag_succs, scc_id);
            GHashTable *dag_preds = z_addr_dict_get(pd->dag_preds, scc_id);

            assert(z_addr_dict_get(dag_preds_n, scc_id) ==
                   g_hash_table_size(dag_preds));

            GList *list_dag_succs = g_hash_table_get_keys(dag_succs);
            for (GList *l = list_dag_succs; l != NULL; l = l->next) {
                edge_n++;
                uint32_t succ_scc_id = (uint32_t)l->data;
                assert(g_hash_table_lookup(
                    z_addr_dict_get(pd->dag_preds, succ_scc_id),
                    GSIZE_TO_POINTER(scc_id)));
            }
            g_list_free(list_dag_succs);
        }
        assert(edge_n);
        z_info("there are %d edges in contructed DAG", edge_n);
#endif
    }

    /*
     * step [4]. topo-sort
     */
    pd->topo = g_queue_new();
    {
        GQueue *queue = g_queue_new();

        // first find all nodes without preds
        for (uint32_t scc_id = 0; scc_id < pd->scc_n; scc_id++) {
            if (!z_addr_dict_get(dag_preds_n, scc_id)) {
                g_queue_push_tail(queue, GSIZE_TO_POINTER(scc_id));
            }
        }

        // get topo
        while (!g_queue_is_empty(queue)) {
            uint32_t scc_id = (uint32_t)g_queue_pop_head(queue);
            g_queue_push_tail(pd->topo, GSIZE_TO_POINTER(scc_id));

            GHashTable *dag_succs = z_addr_dict_get(pd->dag_succs, scc_id);

            GList *list_dag_succs = g_hash_table_get_keys(dag_succs);
            for (GList *l = list_dag_succs; l != NULL; l = l->next) {
                uint32_t succ_scc_id = (uint32_t)l->data;

                assert(z_addr_dict_exist(dag_preds_n, succ_scc_id));
                z_addr_dict_set(dag_preds_n, succ_scc_id,
                                z_addr_dict_get(dag_preds_n, succ_scc_id) - 1);

                if (!z_addr_dict_get(dag_preds_n, succ_scc_id)) {
                    g_queue_push_tail(queue, GSIZE_TO_POINTER(succ_scc_id));
                }
            }
            g_list_free(list_dag_succs);
        }
        assert(g_queue_get_length(pd->topo) == pd->scc_n);

        g_queue_free(queue);
    }
    z_addr_dict_destroy(dag_preds_n);
}
