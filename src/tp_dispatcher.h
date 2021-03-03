#ifndef __TP_DISPATCHER_H
#define __TP_DISPATCHER_H

#include "capstone_.h"
#include "config.h"

// XXX: we avoid using Buffer as raw pointer can be faster. Note that TP_EMIT
// will be invocated during fuzzing.
typedef struct tp_code_t {
    uint8_t *code;
    size_t len;
    size_t capacity;
    uint16_t *id_hole;
    uint16_t *shr_id_hole;
} TPCode;

STRUCT(TPDispatcher, {
    uint8_t *context_save;
    size_t context_save_len;

    uint8_t *context_restore;
    size_t context_restore_len;

    TPCode *bitmap;

    TPCode *bitmap_RAX;
    TPCode *bitmap_RBX;
    TPCode *bitmap_RCX;
    TPCode *bitmap_RDX;
    TPCode *bitmap_RBP;
    TPCode *bitmap_RDI;
    TPCode *bitmap_RSI;
    TPCode *bitmap_R8;
    TPCode *bitmap_R9;
    TPCode *bitmap_R10;
    TPCode *bitmap_R11;
    TPCode *bitmap_R12;
    TPCode *bitmap_R13;
    TPCode *bitmap_R14;
    TPCode *bitmap_R15;
});

/*
 * Create a tp_dispatcher.
 */
Z_API TPDispatcher *z_tp_dispatcher_create();

/*
 * Destroy a tp_dispatcher.
 */
Z_API void z_tp_dispatcher_destroy(TPDispatcher *tpd);

/*
 * Emit a Context Saving TP
 */
Z_API const uint8_t *z_tp_dispatcher_emit_context_save(TPDispatcher *tpd,
                                                       size_t *size);

/*
 * Emit a Context Restoring TP
 */
Z_API const uint8_t *z_tp_dispatcher_emit_context_restore(TPDispatcher *tpd,
                                                          size_t *size);

/*
 * Emit a bitmap TP
 */
Z_API const uint8_t *z_tp_dispatcher_emit_bitmap(TPDispatcher *tpd,
                                                 size_t *size, addr_t addr,
                                                 GPRState state);

#endif
