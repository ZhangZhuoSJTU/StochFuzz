#ifndef __CAPSTONE__H
#define __CAPSTONE__H

/*
 * My own wrapper for capstone, which aims at extracting information from known
 * cs_insn structures. CS_DISASM is not included in this file because it is used
 * for disassembly instead of check cs_insn's features.
 */

#include "config.h"

#include <capstone/capstone.h>

/*
 * General Purposed Register
 */
#define CAPSTONE_FORALL_GPR(STATEMENT) \
    do {                               \
        STATEMENT(RAX);                \
        STATEMENT(RBX);                \
        STATEMENT(RCX);                \
        STATEMENT(RDX);                \
        STATEMENT(RBP);                \
        STATEMENT(RDI);                \
        STATEMENT(RSI);                \
        STATEMENT(R8);                 \
        STATEMENT(R9);                 \
        STATEMENT(R10);                \
        STATEMENT(R11);                \
        STATEMENT(R12);                \
        STATEMENT(R13);                \
        STATEMENT(R14);                \
        STATEMENT(R15);                \
    } while (0)

typedef enum gpr_state_t {
    GPRSTATE_RAX = (1UL << 0),
    GPRSTATE_RBX = (1UL << 1),
    GPRSTATE_RCX = (1UL << 2),
    GPRSTATE_RDX = (1UL << 3),
    GPRSTATE_RDI = (1UL << 4),
    GPRSTATE_RSI = (1UL << 5),
    GPRSTATE_RBP = (1UL << 6),  // <-- NO RSP HERE
    GPRSTATE_R8 = (1UL << 7),
    GPRSTATE_R9 = (1UL << 8),
    GPRSTATE_R10 = (1UL << 9),
    GPRSTATE_R11 = (1UL << 10),
    GPRSTATE_R12 = (1UL << 11),
    GPRSTATE_R13 = (1UL << 12),
    GPRSTATE_R14 = (1UL << 13),
    GPRSTATE_R15 = (1UL << 14),

    GPRSTATE_ALL = ((1UL << 15) - 1),
} GPRState;

/*
 * EFLAGS Register
 */
#define CAPSTONE_FORALL_FLG(STATEMENT) \
    do {                               \
        STATEMENT(OF);                 \
        STATEMENT(SF);                 \
        STATEMENT(ZF);                 \
        STATEMENT(AF);                 \
        STATEMENT(CF);                 \
        STATEMENT(PF);                 \
    } while (0)

typedef enum flg_state_t {
    FLGSTATE_OF = (1UL << 0),
    FLGSTATE_SF = (1UL << 1),
    FLGSTATE_ZF = (1UL << 2),
    FLGSTATE_AF = (1UL << 3),
    FLGSTATE_CF = (1UL << 4),
    FLGSTATE_PF = (1UL << 5),

    FLGSTATE_ALL = ((1UL << 6) - 1),
} FLGState;

/*
 * SSE Register
 */
#define CAPSTONE_FORALL_SSE(T, STATEMENT) \
    do {                                  \
        STATEMENT(T, 0);                  \
        STATEMENT(T, 1);                  \
        STATEMENT(T, 2);                  \
        STATEMENT(T, 3);                  \
        STATEMENT(T, 4);                  \
        STATEMENT(T, 5);                  \
        STATEMENT(T, 6);                  \
        STATEMENT(T, 7);                  \
        STATEMENT(T, 8);                  \
        STATEMENT(T, 9);                  \
        STATEMENT(T, 10);                 \
        STATEMENT(T, 11);                 \
        STATEMENT(T, 12);                 \
        STATEMENT(T, 13);                 \
        STATEMENT(T, 14);                 \
        STATEMENT(T, 15);                 \
    } while (0)

#define __SSE_DEFINE(T, N) T##STATE_##T##N = (1UL << N)
#define __SSE_DEFINE_ALL(enum_name, T) \
    typedef enum enum_name {           \
        __SSE_DEFINE(T, 0),            \
        __SSE_DEFINE(T, 1),            \
        __SSE_DEFINE(T, 2),            \
        __SSE_DEFINE(T, 3),            \
        __SSE_DEFINE(T, 4),            \
        __SSE_DEFINE(T, 5),            \
        __SSE_DEFINE(T, 6),            \
        __SSE_DEFINE(T, 7),            \
        __SSE_DEFINE(T, 8),            \
        __SSE_DEFINE(T, 9),            \
        __SSE_DEFINE(T, 10),           \
        __SSE_DEFINE(T, 11),           \
        __SSE_DEFINE(T, 12),           \
        __SSE_DEFINE(T, 13),           \
        __SSE_DEFINE(T, 14),           \
        __SSE_DEFINE(T, 15),           \
                                       \
        T##STATE_ALL = ~(0UL),         \
    } T##State;

__SSE_DEFINE_ALL(xmm_state_t, XMM);
__SSE_DEFINE_ALL(ymm_state_t, YMM);
__SSE_DEFINE_ALL(zmm_state_t, ZMM);

#undef __SSE_DEFINE_ALL
#undef __SSE_DEFINE

STRUCT(RegState, {
    GPRState gpr_read;
    GPRState gpr_read_32_64;
    GPRState gpr_write;
    GPRState gpr_write_32_64;
    FLGState flg_read;
    FLGState flg_write;
    XMMState xmm_read;
    XMMState xmm_write;
    YMMState ymm_read;
    YMMState ymm_write;
    ZMMState zmm_read;
    ZMMState zmm_write;
});

Z_API bool z_capstone_is_call(const cs_insn *inst);

Z_API bool z_capstone_is_jmp(const cs_insn *inst);

Z_API bool z_capstone_is_cjmp(const cs_insn *inst);

Z_API bool z_capstone_is_loop(const cs_insn *inst);

Z_API bool z_capstone_is_xbegin(const cs_insn *inst);

Z_API bool z_capstone_is_ret(const cs_insn *inst);

Z_API bool z_capstone_is_terminator(const cs_insn *inst);

Z_API bool z_capstone_is_rare(cs_insn *inst);

Z_API RegState *z_capstone_get_register_state(const cs_insn *inst);

Z_API void z_capstone_show_gpr_state(GPRState gpr_state);

Z_API void z_capstone_show_flg_state(FLGState flg_state);

#endif
