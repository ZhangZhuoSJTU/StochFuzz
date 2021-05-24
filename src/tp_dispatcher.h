/*
 * tp_dispatcher.h
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
