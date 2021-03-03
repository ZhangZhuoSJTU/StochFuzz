#include "tp_dispatcher.h"
#include "afl_config.h"
#include "utils.h"

#include "trampolines/trampolines.h"

#define TPD_LOCATE_HOLE(haystack, haystacklen, needle, needlelen, err)   \
    ({                                                                   \
        void *p = memmem((void *)(haystack), (size_t)(haystacklen),      \
                         (void *)(needle), (size_t)(needlelen));         \
        if (p == NULL) {                                                 \
            EXITME(err);                                                 \
        }                                                                \
        assert(memmem(p + (size_t)(needlelen),                           \
                      (size_t)(haystacklen) - (p - (void *)(haystack)) - \
                          (size_t)(needlelen),                           \
                      (void *)(needle), (size_t)(needlelen)) == NULL);   \
        p;                                                               \
    })

/*
 * Create a TPCode
 */
Z_PRIVATE TPCode *__tp_code_create(size_t size);

/*
 * Destroy a TPcode
 */
Z_PRIVATE void __tp_code_destroy(TPCode *tpc);

/*
 * Emit TPCode
 */
Z_PRIVATE const uint8_t *__tp_code_emit(TPCode *tpc, uint16_t id,
                                        size_t *size_ptr);

/*
 * Append raw code into TPCode
 */
Z_PRIVATE void __tp_code_append_raw(TPCode *tpc, const uint8_t *buf,
                                    size_t size);

/*
 * Locate holes in TPCode
 */
Z_PRIVATE void __tp_code_locate_holes(TPCode *tpc, uint16_t id_hole,
                                      uint16_t shr_id_hole);

Z_PRIVATE void __tp_code_destroy(TPCode *tpc) {
    z_free(tpc->code);
    z_free(tpc);
}

Z_PRIVATE TPCode *__tp_code_create(size_t size) {
    TPCode *tpc = z_alloc(1, sizeof(TPCode));
    tpc->code = z_alloc(size, sizeof(uint8_t));
    tpc->len = 0;
    tpc->capacity = size;
    tpc->id_hole = tpc->shr_id_hole = NULL;
    return tpc;
}

Z_PRIVATE void __tp_code_locate_holes(TPCode *tpc, uint16_t id_hole,
                                      uint16_t shr_id_hole) {
    tpc->id_hole = (uint16_t *)TPD_LOCATE_HOLE(
        tpc->code, tpc->len, &id_hole, sizeof(id_hole), "missing id hole");
    tpc->shr_id_hole =
        (uint16_t *)TPD_LOCATE_HOLE(tpc->code, tpc->len, &shr_id_hole,
                                    sizeof(shr_id_hole), "missing shr id hole");
}

Z_PRIVATE void __tp_code_append_raw(TPCode *tpc, const uint8_t *buf,
                                    size_t size) {
    if (tpc->len + size > tpc->capacity) {
        EXITME("TPCode execceds its total capacity");
    }
    memcpy(tpc->code + tpc->len, buf, size);
    tpc->len += size;
}

Z_PRIVATE const uint8_t *__tp_code_emit(TPCode *tpc, uint16_t id,
                                        size_t *size_ptr) {
    *(tpc->id_hole) = (id);
    *(tpc->shr_id_hole) = ((id) >> 1);
    *(size_ptr) = tpc->len;
    return tpc->code;
}

Z_API void z_tp_dispatcher_destroy(TPDispatcher *tpd) {
    __tp_code_destroy(tpd->bitmap);

#define __DESTROY_TPCODE_FOR_REG(REG) __tp_code_destroy(tpd->bitmap_##REG)
    CAPSTONE_FORALL_GPR(__DESTROY_TPCODE_FOR_REG);
#undef __DESTROY_TPCODE_FOR_REG

    z_free(tpd);
}

Z_API TPDispatcher *z_tp_dispatcher_create() {
    TPDispatcher *tpd = STRUCT_ALLOC(TPDispatcher);

    /*
     * Context Save
     */
    tpd->context_save = context_save_bin;
    tpd->context_save_len = context_save_bin_len;

    /*
     * Context Restore
     */
    tpd->context_restore = context_restore_bin;
    tpd->context_restore_len = context_restore_bin_len;

    /*
     * Register bitmap
     */
#define __GENERATE_TPCODE_FOR_REG(REG)                                       \
    do {                                                                     \
        tpd->bitmap_##REG =                                                  \
            __tp_code_create(__BITMAP_##REG##_END - __BITMAP_##REG);         \
        __tp_code_append_raw(tpd->bitmap_##REG, bitmap_bin + __BITMAP_##REG, \
                             __BITMAP_##REG##_END - __BITMAP_##REG);         \
        __tp_code_locate_holes(tpd->bitmap_##REG, bitmap_id_hole,            \
                               bitmap_shr_id_hole);                          \
    } while (0)

    CAPSTONE_FORALL_GPR(__GENERATE_TPCODE_FOR_REG);

#undef __GENERATE_TPCODE_FOR_REG

    /*
     * Bitmap (w/ push and pop GPR): we choose RDI here
     */
    tpd->bitmap = __tp_code_create(tpd->bitmap_RDI->len + 0x10);
    // 'push rdi'
    KS_ASM(INVALID_ADDR, "mov [rsp - 152], rdi");
    __tp_code_append_raw(tpd->bitmap, ks_encode, ks_size);
    // rdi bitmap
    __tp_code_append_raw(tpd->bitmap, tpd->bitmap_RDI->code,
                         tpd->bitmap_RDI->len);
    // 'pop rdi'
    KS_ASM(INVALID_ADDR, "mov rdi, [rsp - 152]");
    __tp_code_append_raw(tpd->bitmap, ks_encode, ks_size);
    // find holes
    __tp_code_locate_holes(tpd->bitmap, bitmap_id_hole, bitmap_shr_id_hole);

    return tpd;
}

Z_API const uint8_t *z_tp_dispatcher_emit_context_save(TPDispatcher *tpd,
                                                       size_t *size) {
    *size = tpd->context_save_len;
    return (const uint8_t *)tpd->context_save;
}

Z_API const uint8_t *z_tp_dispatcher_emit_context_restore(TPDispatcher *tpd,
                                                          size_t *size) {
    *size = tpd->context_restore_len;
    return (const uint8_t *)tpd->context_restore;
}

Z_API const uint8_t *z_tp_dispatcher_emit_bitmap(TPDispatcher *tpd,
                                                 size_t *size, addr_t addr,
                                                 GPRState state) {
#define __EMIT_TP_FOR_REG(REG)                                               \
    do {                                                                     \
        if (state & GPRSTATE_##REG) {                                        \
            return __tp_code_emit(tpd->bitmap_##REG, AFL_BB_ID(addr), size); \
        }                                                                    \
    } while (0)

    CAPSTONE_FORALL_GPR(__EMIT_TP_FOR_REG);

#undef __EMIT_TP_FOR_REG

    return __tp_code_emit(tpd->bitmap, AFL_BB_ID(addr), size);
}
