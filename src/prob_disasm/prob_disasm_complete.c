#include "../buffer.h"
#include "../disassembler.h"
#include "../iterator.h"
#include "../restricted_ptr.h"

#include <ctype.h>
#include <math.h>

typedef enum dynamic_hint_type_t {
    DHINT_NONE = 0,
    DHINT_CODE = 1,  // XXX: we skip 0 for easy use of GHashTable
    DHINT_DATA,
} DHintType;

typedef struct dynamic_hint_t {
    addr_t addr;
    DHintType type;
} DHint;

///////////////////////////////////
// ProbDisassembler
///////////////////////////////////

STRUCT(ProbDisassembler, {
    // pointer to Disassembler, so that we can call some functions of
    // Disassembler (it looks like inheritance but not really)
    Disassembler *base;

    AddrDict(double128_t, H);
    AddrDict(double128_t, RH);
    AddrDict(double128_t, P);
    AddrDict(double128_t, D);

    AddrDict(double128_t, inst_lost);
    AddrDict(double128_t, data_hint);

    // basic information
    Binary *binary;
    addr_t text_addr;
    size_t text_size;

    // logged dynamic hints (i.e., certain code/data information collected
    // during previous runs)
    const char *dhint_filename;
    GHashTable *dynamic_hints;

    // DAG information
    // TODO: we should do this for other address-keyed hash table.
    uint32_t scc_n;
    AddrDict(uint32_t, addr2sccid);
    AddrDictFast(GHashTable *, dag_succs);
    AddrDictFast(GHashTable *, dag_preds);
    AddrDictFast(bool, dag_dead);
    GQueue *topo;

    AddrDict(double128_t, dag_P);

    // how many round we have played
    size_t round_n;
});

#define __GET_PDISASM(d) ((ProbDisassembler *)((d)->prob_disasm))
#define __SET_PDISASM(d, v)                    \
    do {                                       \
        (d)->prob_disasm = (PhantomType *)(v); \
    } while (0)

#define INIT_ROUND_N 3
#define PROPAGATE_P 0.1
#define STRONG_DATA_HINT 1e52

///////////////////////////////////
// All hints and losts value
///////////////////////////////////

// base
#define __BASE_CF (1.0 / 256.0)
#define __BASE_REG (1.0 / 16.0)
#define __BASE_INS (1.0 / 502.0)  // it is naively/semi-randomly picked by me
#define __BASE_PRINTABLE_CHAR (256.0 / 95.0)
#define __BASE_VALUE (256.0)

#define BASE_CF(INST) \
    (__pow_in_4(__BASE_CF, (INST)->detail->x86.encoding.imm_size))
#define BASE_CF_RAW(N) (__pow_in_4(__BASE_CF, (N)))
#define BASE_REG (__BASE_REG)
#define BASE_INS (__BASE_INS)
#define BASE_STRING(N) (__pow_in_n(__BASE_PRINTABLE_CHAR, (N)))
#define BASE_VALUE(L, R, N) \
    (__pow_in_n(__pow_in_n(__BASE_VALUE, (L)) / (R), (N)))

// hint weights: bigger weight means higher confidence
#define __HINT_PLT_CALL_WEIGHT (100000.0)
#define __HINT_PLT_JMP_WEIGHT (0.5)
#define __HINT_CONVERGED_CALL_WEIGHT (1.0)
#define __HINT_CONVERGED_JMP_WEIGHT (1.0)
#define __HINT_CROSSED_JMP_WEIGHT (1.0)
#define __HINT_USEDEF_GPR_WEIGHT (1.0)
#define __HINT_USEDEF_SSE_WEIGHT (0.5)
#define __HINT_POP_RET_WEIGHT (1.0)
#define __HINT_CMP_CJMP_WEIGHT (1.0)
#define __HINT_ARG_CALL_WEIGHT (1.0)
// data hint is different, higher means lower confidence
#define __HINT_STRING_WEIGHT \
    (0.00001 * (1.0 / 256.0))  // TODO: check the string is valid instead of
                               // assigning a very small weight
#define __HINT_VALUE_WEIGHT (1.0)

// hint functions
#define HINT(TYPE, BASE) ((1.0 / (__HINT_##TYPE##_WEIGHT)) * (BASE))

// lost weights: bigger weight means higher confidence
#define __LOST_OUTSIDE_CALL_WEIGHT (+INFINITY)
#define __LOST_OUTSIDE_JMP_WEIGHT (+INFINITY)
#define __LOST_KILLED_GPR_WEIGHT (1.0)
#define __LOST_KILLED_SSE_WEIGHT (2.0)

// lost functions
#define LOST(TYPE, BASE) ((__LOST_##TYPE##_WEIGHT) * (1.0 / (BASE)))

///////////////////////////////////
// Useful functions
///////////////////////////////////

/*
 * Securely check whether two double128_t variables are equal
 */
Z_PRIVATE bool __double128_equal(double128_t a, double128_t b) {
    double128_t max_val = (fabsl(a) > fabsl(b) ? fabsl(a) : fabsl(b));
    return (fabsl(a - b) <= max_val * LDBL_EPSILON);
}

/*
 * simple function to calculate pow
 */
Z_PRIVATE double128_t __pow_in_4(double128_t base, size_t n) {
    double128_t res = base;
    switch (n) {
        case 4:
            res = res * res;
        case 2:
            res = res * res;
            break;
        case 3:
            res = res * res * res;
        case 1:
            break;
        case 0:
            if (__double128_equal(base, 0.0)) {
                res = NAN;
            } else {
                res = 1.0;
            }
            break;
        default:
            EXITME("invalid pow: %d", n);
    }
    return res;
}

/*
 * fast function to calculate pow when n is integer
 */
Z_PRIVATE double128_t __pow_in_n(double128_t base, size_t n) {
    double128_t res = 1.0;
    double128_t cur = base;
    while (n > 0) {
        if (n & 1) {
            res *= cur;
        }
        cur = cur * cur;
        n >>= 1;
    }

    return res;
}

///////////////////////////////////
// Getter and Setter
///////////////////////////////////

#define PROB_DISASSEMBLER_DEFINE_PRIVATE_SETTER(T)                          \
    Z_PRIVATE void __prob_disassembler_update_##T(                          \
        ProbDisassembler *pd, addr_t addr, double128_t T) {                 \
        if (!z_addr_dict_exist(pd->T, addr)) {                              \
            z_addr_dict_set(pd->T, addr, T);                                \
        } else {                                                            \
            z_addr_dict_set(pd->T, addr, z_addr_dict_get(pd->T, addr) * T); \
        }                                                                   \
    }

#define PROB_DISASSEMBLER_DEFINE_PRIVATE_GETTER(T)                            \
    Z_PRIVATE bool __prob_disassembler_get_##T(ProbDisassembler *pd,          \
                                               addr_t addr, double128_t *T) { \
        if (!z_addr_dict_exist(pd->T, addr)) {                                \
            return false;                                                     \
        } else {                                                              \
            *T = z_addr_dict_get(pd->T, addr);                                \
            return true;                                                      \
        }                                                                     \
    }

#define PROB_DISASSEMBLER_DEFINE_PRIVATE_RESETTER(T)                           \
    Z_PRIVATE void __prob_disassembler_reset_##T(ProbDisassembler *pd,         \
                                                 addr_t addr, double128_t T) { \
        z_addr_dict_set(pd->T, addr, T);                                       \
    }

PROB_DISASSEMBLER_DEFINE_PRIVATE_SETTER(H);
PROB_DISASSEMBLER_DEFINE_PRIVATE_SETTER(RH);
PROB_DISASSEMBLER_DEFINE_PRIVATE_SETTER(D);
PROB_DISASSEMBLER_DEFINE_PRIVATE_SETTER(inst_lost);
PROB_DISASSEMBLER_DEFINE_PRIVATE_SETTER(data_hint);

PROB_DISASSEMBLER_DEFINE_PRIVATE_RESETTER(H);
PROB_DISASSEMBLER_DEFINE_PRIVATE_RESETTER(RH);
PROB_DISASSEMBLER_DEFINE_PRIVATE_RESETTER(D);
PROB_DISASSEMBLER_DEFINE_PRIVATE_RESETTER(inst_lost);
PROB_DISASSEMBLER_DEFINE_PRIVATE_RESETTER(data_hint);
PROB_DISASSEMBLER_DEFINE_PRIVATE_RESETTER(P);

PROB_DISASSEMBLER_DEFINE_PRIVATE_GETTER(H);
PROB_DISASSEMBLER_DEFINE_PRIVATE_GETTER(RH);
PROB_DISASSEMBLER_DEFINE_PRIVATE_GETTER(D);
PROB_DISASSEMBLER_DEFINE_PRIVATE_GETTER(inst_lost);
PROB_DISASSEMBLER_DEFINE_PRIVATE_GETTER(data_hint);
PROB_DISASSEMBLER_DEFINE_PRIVATE_GETTER(P);

#define __prob_disassembler_update_inst_hint __prob_disassembler_update_H
#define __prob_disassembler_get_inst_hint __prob_disassembler_get_H
#define __prob_disassembler_reset_inst_hint __prob_disassembler_reset_H

///////////////////////////////////
// Local functions
///////////////////////////////////

/*
 * Get successors for propogating instruction hints. It is a very helpful
 * wrapper function to customize propogation rule for instruction hints.
 */
Z_PRIVATE bool __prob_disassembler_get_propogate_successors(
    ProbDisassembler *pd, addr_t addr, size_t *n, addr_t **succs);

/*
 * Apply hints and losts into working environment (RH/D/P), and remove previous
 * data when there are no hint and lost. (playground = H + RH + D + P, and H is
 * for inst_hint)
 */
Z_PRIVATE void __prob_disassembler_refresh_playground(ProbDisassembler *pd);

///////////////////////////////////
// Components
///////////////////////////////////

// XXX: note that we should import following components here, as they might use
// above local functions.
#include "prob_disasm_complete/dag.c"
#include "prob_disasm_complete/hints.c"
#include "prob_disasm_complete/propagation.c"
#include "prob_disasm_complete/solving.c"

///////////////////////////////////
// Test Code
///////////////////////////////////

#ifdef DEBUG

Z_RESERVED Z_PRIVATE bool __prob_disassembler_path_dfs(
    ProbDisassembler *pd, Buffer *(*get_next)(UCFG_Analyzer *, addr_t),
    GQueue *stack, GHashTable *seen, addr_t cur_addr, addr_t target) {
    Disassembler *d = pd->base;

    cs_insn *inst = z_disassembler_get_superset_disasm(d, cur_addr);
    if (!inst) {
        return false;
    }

    g_queue_push_tail(stack, (gpointer)(inst));

    if (cur_addr == target) {
        return true;
    }

    Iter(addr_t, next_addrs);
    z_iter_init_from_buf(next_addrs, (*get_next)(d->ucfg_analyzer, cur_addr));

    while (!z_iter_is_empty(next_addrs)) {
        addr_t next_addr = *(z_iter_next(next_addrs));

        if (g_hash_table_lookup(seen, GSIZE_TO_POINTER(next_addr))) {
            continue;
        }

        g_hash_table_insert(seen, GSIZE_TO_POINTER(next_addr),
                            GSIZE_TO_POINTER(1));

        if (__prob_disassembler_path_dfs(pd, get_next, stack, seen, next_addr,
                                         target)) {
            return true;
        }
    }

    g_queue_pop_tail(stack);
    return false;
}

Z_RESERVED Z_PRIVATE void __prob_disassembler_search_path(ProbDisassembler *pd,
                                                          addr_t src,
                                                          addr_t dst) {
    GHashTable *seen =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    GQueue *stack = g_queue_new();

    if (!__prob_disassembler_path_dfs(pd, &z_ucfg_analyzer_get_all_successors,
                                      stack, seen, src, dst)) {
        EXITME("cannot reach %#lx from %#lx", dst, src);
    } else {
        while (!g_queue_is_empty(stack)) {
            cs_insn *inst = (cs_insn *)g_queue_pop_head(stack);
            z_info(CS_SHOW_INST(inst));
        }
    }

    g_hash_table_destroy(seen);
    g_queue_free(stack);
}

#endif

Z_PRIVATE void __prob_disassembler_refresh_playground(ProbDisassembler *pd) {
    addr_t text_addr = pd->text_addr;
    size_t text_size = pd->text_size;

#ifdef DEBUG
    // remove dag_P first (it is improtant for the following checking at step 3)
    for (uint32_t scc_id = 0; scc_id < pd->scc_n; scc_id++) {
        z_addr_dict_remove(pd->dag_P, scc_id);
        assert(!z_addr_dict_exist(pd->dag_P, scc_id));
    }
#endif

    for (addr_t addr = text_addr; addr < text_addr + text_size; addr++) {
        // step [1]. apply inst_lost into RH
        double128_t inst_lost = NAN;
        if (__prob_disassembler_get_inst_lost(pd, addr, &inst_lost)) {
            __prob_disassembler_reset_RH(pd, addr, inst_lost);
        } else {
            z_addr_dict_remove(pd->RH, addr);
            assert(!z_addr_dict_exist(pd->RH, addr));
        }

        // step [2]. apply data_hint into D
        double128_t data_hint = NAN;
        if (__prob_disassembler_get_data_hint(pd, addr, &data_hint)) {
            __prob_disassembler_reset_D(pd, addr, data_hint);
        } else {
            z_addr_dict_remove(pd->D, addr);
            assert(!z_addr_dict_exist(pd->D, addr));
        }

        // step [3]. update dag P
        double128_t P = NAN;
        if (__prob_disassembler_get_P(pd, addr, &P)) {
            uint32_t scc_id = z_addr_dict_get(pd->addr2sccid, addr);
#ifdef DEBUG
            if (z_addr_dict_exist(pd->dag_P, scc_id) &&
                z_addr_dict_get(pd->dag_P, scc_id) != P) {
                EXITME("inconsistent dag P: %#lx (%Le) v/s %d (%Le)", addr, P,
                       scc_id, z_addr_dict_get(pd->dag_P, scc_id));
            }
#endif
            z_addr_dict_set(pd->dag_P, scc_id, P);
            // XXX: note that we do not perform z_addr_dict_remove(pd->P, addr)
            // here. It is mainly beacuse we want to maintain a feature that if
            // an address was thought as 100% non-instruction before, the
            // address should always be non-instruction.
        }
    }
}

Z_PRIVATE bool __prob_disassembler_get_propogate_successors(
    ProbDisassembler *pd, addr_t addr, size_t *n, addr_t **succs) {
    Disassembler *d = pd->base;

    cs_insn *inst = z_disassembler_get_superset_disasm(d, addr);
    if (!inst) {
        return false;
    }

    Buffer *succs_buf =
        z_ucfg_analyzer_get_all_successors(d->ucfg_analyzer, addr);
    assert(succs_buf);

    // XXX:  option one: propogate hints through fall-through edges for calls
    // ------
    // if (z_capstone_is_call(inst)) {
    //     addr_t next_addr = addr + inst->size;
    //     z_buffer_append_raw(succs_buf, (uint8_t *)&next_addr,
    //                         sizeof(next_addr));
    // }
    // ------

    *n = z_buffer_get_size(succs_buf) / sizeof(addr_t);
    *succs = (addr_t *)z_buffer_get_raw_buf(succs_buf);

    return true;
}

///////////////////////////////////
// ProbDisassembler Pubilc API
///////////////////////////////////

Z_PRIVATE double128_t z_prob_disassembler_get_inst_prob(ProbDisassembler *pd,
                                                        addr_t addr) {
    if (addr < pd->text_addr || addr >= pd->text_addr + pd->text_size) {
        return 0.0;
    }

    double128_t P = NAN;
    __prob_disassembler_get_P(pd, addr, &P);
    assert(!isnan(P));

    if (!__double128_equal(P, 0.0)) {
        return P;
    }

    // additionally check dag_dead and very huge data hint
    double128_t data_hint = NAN;
    if (__prob_disassembler_get_data_hint(pd, addr, &data_hint)) {
        if (data_hint > STRONG_DATA_HINT) {
            return -0.0;
        }
    }

    uint32_t scc_id = z_addr_dict_get(pd->addr2sccid, addr);
    if (z_addr_dict_exist(pd->dag_dead, scc_id)) {
        return -0.0;
    }

    return P;
}

Z_PRIVATE void z_prob_disassembler_get_internal(
    ProbDisassembler *pd, addr_t addr, cs_insn **inst, uint32_t *scc_id,
    double128_t *inst_hint, double128_t *inst_lost, double128_t *data_hint,
    double128_t *D, double128_t *P) {
    Disassembler *d = pd->base;

    *inst = z_disassembler_get_superset_disasm(d, addr);
    *scc_id = z_addr_dict_get(pd->addr2sccid, addr);

    __prob_disassembler_get_inst_hint(pd, addr, inst_hint);
    __prob_disassembler_get_inst_lost(pd, addr, inst_lost);
    __prob_disassembler_get_data_hint(pd, addr, data_hint);
    __prob_disassembler_get_D(pd, addr, D);

    *P = z_prob_disassembler_get_inst_prob(pd, addr);
}

Z_PRIVATE void z_prob_disassembler_update(ProbDisassembler *pd, addr_t addr,
                                          bool is_inst, bool need_log) {
    if (is_inst) {
        // we have known for sure this addr is an instruction boundary
        __prob_disassembler_reset_inst_hint(pd, addr, 0.0);
        z_addr_dict_remove(pd->inst_lost, addr);
        z_addr_dict_remove(pd->data_hint, addr);
    } else {
        // we have known for sure this addr is not an instruction boundary
        z_addr_dict_remove(pd->H, addr);  // inst_hint
        __prob_disassembler_reset_inst_lost(pd, addr, +INFINITY);
        // XXX: resetting data_hint should be more carefully handled as there
        // are two cases of is_inst == false: 1) inside an instrution and 2)
        // data
        __prob_disassembler_reset_data_hint(pd, addr, +INFINITY);
    }

    if (need_log) {
        // log the hint
        DHintType type = (is_inst ? DHINT_CODE : DHINT_DATA);

#ifdef DEBUG
        DHintType old_type = (DHintType)g_hash_table_lookup(
            pd->dynamic_hints, GSIZE_TO_POINTER(addr));
        if (old_type && (old_type != type)) {
            EXITME("inconstatn type of the dynamic hint at %#lx", addr);
        }
#endif

        g_hash_table_insert(pd->dynamic_hints, GSIZE_TO_POINTER(addr),
                            GSIZE_TO_POINTER(type));
    }
}

Z_PRIVATE void z_prob_disassembler_start(ProbDisassembler *pd) {
    /*
     * step [1]. collect hints if we haven't: please refer to
     * *prob_disasm_complete/hints.c*
     */
    if (!pd->round_n) {
        // calculate static hints
        __prob_disassembler_collect_cf_hints(pd);
        __prob_disassembler_collect_reg_hints(pd);
        __prob_disassembler_collect_pop_ret_hints(pd);
        __prob_disassembler_collect_cmp_cjmp_hints(pd);
        __prob_disassembler_collect_arg_call_hints(pd);
        __prob_disassembler_collect_str_hints(pd);
        __prob_disassembler_collect_value_hints(pd);

        // apply logged dynamic hint
        {
            GHashTableIter iter;
            gpointer key, value;
            g_hash_table_iter_init(&iter, pd->dynamic_hints);

            while (g_hash_table_iter_next(&iter, &key, &value)) {
                addr_t addr = (addr_t)key;
                bool is_inst = ((DHintType)value == DHINT_CODE);
                z_prob_disassembler_update(pd, addr, is_inst, false);
            }
        }

        z_info("probabilistic disassembly: hints collection done");
    }

    /*
     * step [2]. play several rounds to calculate probabilities
     */
    do {
        /*
         * step [2.1]. refresh playground
         */
        __prob_disassembler_refresh_playground(pd);

        /*
         * step [2]. propogate hints:
         *      refer to *prob_disasm_complete/propagation.c*
         */
        __prob_disassembler_propogate_inst_hints(pd);
        // TODO: __prob_disassembler_propogate_data_hints(pd);
        z_trace("probabilistic disassembly: hints propagation done");

        /*
         * step [3]. spread hints: refer to *prob_disasm_complete/solving.c*
         */
        __prob_disassembler_spread_hints(pd);
        z_trace("probabilistic disassembly: hints spreading done");

        /*
         * step [4]. restrain probabilities:
         *      refer to *prob_disasm_complete/solving.c*
         */
        __prob_disassembler_restrain_prob(pd);
        z_trace("probabilistic disassembly: probability restraint done");

        /*
         * step [5]. normalized probabilities:
         *      refer to *prob_disasm_complete/solving.c*
         */
        __prob_disassembler_normalize_prob(pd);
        z_trace("probabilistic disassembly: probability normalization done");

        pd->round_n += 1;
        z_info("probabilistic disassembly round %d done", pd->round_n);
    } while (pd->round_n < INIT_ROUND_N);
}

Z_PRIVATE ProbDisassembler *z_prob_disassembler_create(Disassembler *d) {
    ProbDisassembler *pd = STRUCT_ALLOC(ProbDisassembler);

    pd->base = d;

    pd->binary = d->binary;
    pd->text_addr = d->text_addr;
    pd->text_size = d->text_size;

    pd->round_n = 0;

    // read p-disasm file
    pd->dynamic_hints =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    const char *original_filename = z_binary_get_original_filename(d->binary);
    pd->dhint_filename = z_strcat(PDISASM_FILENAME_PREFIX, original_filename);
    {
        if (!z_access(pd->dhint_filename, F_OK)) {
            z_info(
                "pdisasm file exists, so we will read those pre-calcualted "
                "hints");
            Buffer *buf = z_buffer_read_file(pd->dhint_filename);

            size_t n = z_buffer_get_size(buf) / sizeof(DHint);
            DHint *hints = (DHint *)z_buffer_get_raw_buf(buf);

            // XXX: note that we will apply those dynamic hints after collecting
            // static hints.
            for (size_t i = 0; i < n; i++) {
                g_hash_table_insert(pd->dynamic_hints,
                                    GSIZE_TO_POINTER(hints[i].addr),
                                    GSIZE_TO_POINTER(hints[i].type));
            }

            z_buffer_destroy(buf);
        }
    }

    /*
     * H: instruction hint source for each address, which is also the
     * update point for all *instruction hints*.
     */
    z_addr_dict_init(pd->H, pd->text_addr, pd->text_size);

    /*
     * RH: Propogated instruction hints for each address, which is the
     * result of hint propogation, and also the update point of all
     * *instruction losts*.
     *
     * Additionally, we do not propogate instruction losts.
     */
    z_addr_dict_init(pd->RH, pd->text_addr, pd->text_size);
    z_addr_dict_init(pd->inst_lost, pd->text_addr, pd->text_size);

    /*
     * D: final probabilities of eash address to be data, which is also the
     * update point of all *data hints*.
     */
    z_addr_dict_init(pd->D, pd->text_addr, pd->text_size);
    z_addr_dict_init(pd->data_hint, pd->text_addr, pd->text_size);

    /*
     * P: final probabilities of each address to be instructoin.
     */
    z_addr_dict_init(pd->P, pd->text_addr, pd->text_size);

    /*
     * dag building: please refer to: *prob_disasm_complete/dag.c*
     */
    __prob_disassembler_build_dag(pd);

    return pd;
}

Z_PRIVATE void z_prob_disassembler_destroy(ProbDisassembler *pd) {
    // XXX: note that *base* should not be destroyed here.
    z_addr_dict_destroy(pd->H);
    z_addr_dict_destroy(pd->RH);
    z_addr_dict_destroy(pd->P);
    z_addr_dict_destroy(pd->D);

    z_addr_dict_destroy(pd->inst_lost);
    z_addr_dict_destroy(pd->data_hint);

    z_addr_dict_destroy(pd->addr2sccid);
    z_addr_dict_destroy(pd->dag_succs, &g_hash_table_destroy);
    z_addr_dict_destroy(pd->dag_preds, &g_hash_table_destroy);
    z_addr_dict_destroy(pd->dag_dead);
    g_queue_free(pd->topo);

    z_addr_dict_destroy(pd->dag_P);

    // write down dynamic hints
    {
        FILE *f = z_fopen(pd->dhint_filename, "wb");
        DHint hint = {
            .addr = INVALID_ADDR,
            .type = DHINT_NONE,
        };

        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, pd->dynamic_hints);

        while (g_hash_table_iter_next(&iter, &key, &value)) {
            hint.addr = (addr_t)key;
            hint.type = (DHintType)value;
            if (z_fwrite(&hint, sizeof(DHint), 1, f) != 1) {
                EXITME("error on writing dynamic hint file");
            }
        }

        z_fclose(f);
    }
    z_free((char *)pd->dhint_filename);
    g_hash_table_destroy(pd->dynamic_hints);

    z_free(pd);
}

///////////////////////////////////
// Disassembler Private API
///////////////////////////////////

Z_PRIVATE void __disassembler_pdisasm_create(Disassembler *d) {
    __SET_PDISASM(d, z_prob_disassembler_create(d));
}

Z_PRIVATE void __disassembler_pdisasm_destroy(Disassembler *d) {
    z_prob_disassembler_destroy(__GET_PDISASM(d));
}

Z_PRIVATE void __disassembler_pdisasm_start(Disassembler *d) {
    z_prob_disassembler_start(__GET_PDISASM(d));
}

Z_PRIVATE double128_t __disassembler_pdisasm_get_inst_prob(Disassembler *d,
                                                           addr_t addr) {
    return z_prob_disassembler_get_inst_prob(__GET_PDISASM(d), addr);
}

Z_PRIVATE void __disassembler_pdisasm_get_internal(
    Disassembler *d, addr_t addr, cs_insn **inst, uint32_t *scc_id,
    double128_t *inst_hint, double128_t *inst_lost, double128_t *data_hint,
    double128_t *D, double128_t *P) {
    z_prob_disassembler_get_internal(__GET_PDISASM(d), addr, inst, scc_id,
                                     inst_hint, inst_lost, data_hint, D, P);
}

Z_PRIVATE void __disassembler_pdisasm_update(Disassembler *d, addr_t addr,
                                             bool is_inst) {
    z_prob_disassembler_update(__GET_PDISASM(d), addr, is_inst, true);
}

#undef __GET_PDISASM
#undef __SET_PDISASM
