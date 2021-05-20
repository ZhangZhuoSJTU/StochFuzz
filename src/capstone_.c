#include "capstone_.h"
#include "utils.h"

#define __FLG_READ(F) static uint64_t __FLG_READ_##F = X86_EFLAGS_TEST_##F
__FLG_READ(OF);
__FLG_READ(SF);
__FLG_READ(ZF);
__FLG_READ(AF);
__FLG_READ(CF);
__FLG_READ(PF);
#undef __FLG_READ

#define __FLG_WRITE(F)                                                      \
    static uint64_t __FLG_WRITE_##F =                                       \
        X86_EFLAGS_MODIFY_##F | X86_EFLAGS_RESET_##F | X86_EFLAGS_SET_##F | \
        X86_EFLAGS_UNDEFINED_##F
__FLG_WRITE(OF);
__FLG_WRITE(SF);
__FLG_WRITE(ZF);
__FLG_WRITE(AF);
__FLG_WRITE(CF);
__FLG_WRITE(PF);
#undef __FLA_WRITE

/*
 * Mapping a eflag action into individual flag's read state
 */
Z_PRIVATE FLGState __capstone_mapping_flg_read(uint64_t flg_state);

/*
 * Mapping a eflag action into individual flag's write state
 */
Z_PRIVATE FLGState __capstone_mapping_flg_write(uint64_t flg_state);

/*
 * Mapping CAPSTONE general purpose register info into GPRState. Here we mapping
 * a sub-register into its complete form.
 *
 * More information please refer to
 *   https://www.tortall.net/projects/yasm/manual/html/arch-x86-registers.html.
 */
Z_PRIVATE GPRState __capstone_mapping_pgr(x86_reg reg_id);

/*
 * Filter CAPSTONE general purpose register, we only need 32-bit and 64-bit GPR
 * here
 */
Z_PRIVATE GPRState __capstone_filter_pgr(x86_reg reg_id);

Z_PRIVATE FLGState __capstone_mapping_flg_write(uint64_t flg_state) {
#define __FLG_MAPPING_WRITE(fs, F)         \
    do {                                   \
        if (flg_state & __FLG_WRITE_##F) { \
            (fs) |= FLGSTATE_##F;          \
        }                                  \
    } while (0)

    FLGState fs = 0;
    __FLG_MAPPING_WRITE(fs, OF);
    __FLG_MAPPING_WRITE(fs, SF);
    __FLG_MAPPING_WRITE(fs, ZF);
    __FLG_MAPPING_WRITE(fs, AF);
    __FLG_MAPPING_WRITE(fs, CF);
    __FLG_MAPPING_WRITE(fs, PF);
    return fs;

#undef __FLG_MAPPING_WRITE
}

Z_PRIVATE FLGState __capstone_mapping_flg_read(uint64_t flg_state) {
#define __FLG_MAPPING_READ(fs, F)         \
    do {                                  \
        if (flg_state & __FLG_READ_##F) { \
            (fs) |= FLGSTATE_##F;         \
        }                                 \
    } while (0)

    FLGState fs = 0;
    __FLG_MAPPING_READ(fs, OF);
    __FLG_MAPPING_READ(fs, SF);
    __FLG_MAPPING_READ(fs, ZF);
    __FLG_MAPPING_READ(fs, AF);
    __FLG_MAPPING_READ(fs, CF);
    __FLG_MAPPING_READ(fs, PF);
    return fs;

#undef __FLG_MAPPING_READ
}

Z_PRIVATE GPRState __capstone_mapping_pgr(x86_reg reg_id) {
#define __GPR_MAPPING_1(T) \
    case X86_REG_##T##H:   \
    case X86_REG_##T##L:   \
    case X86_REG_##T##X:   \
    case X86_REG_E##T##X:  \
    case X86_REG_R##T##X:  \
        return GPRSTATE_R##T##X

#define __GPR_MAPPING_2(T) \
    case X86_REG_##T:      \
    case X86_REG_##T##L:   \
    case X86_REG_E##T:     \
    case X86_REG_R##T:     \
        return GPRSTATE_R##T

#define __GPR_MAPPING_3(T) \
    case X86_REG_##T##B:   \
    case X86_REG_##T##W:   \
    case X86_REG_##T##D:   \
    case X86_REG_##T:      \
        return GPRSTATE_##T

    switch (reg_id) {
        __GPR_MAPPING_1(A);
        __GPR_MAPPING_1(B);
        __GPR_MAPPING_1(C);
        __GPR_MAPPING_1(D);

        __GPR_MAPPING_2(DI);
        __GPR_MAPPING_2(SI);
        __GPR_MAPPING_2(BP);

        __GPR_MAPPING_3(R8);
        __GPR_MAPPING_3(R9);
        __GPR_MAPPING_3(R10);
        __GPR_MAPPING_3(R11);
        __GPR_MAPPING_3(R12);
        __GPR_MAPPING_3(R13);
        __GPR_MAPPING_3(R14);
        __GPR_MAPPING_3(R15);

        default:
            return 0;
    }

#undef __GPR_MAPPING_1
#undef __GPR_MAPPING_2
#undef __GPR_MAPPING_3
}

Z_PRIVATE GPRState __capstone_filter_pgr(x86_reg reg_id) {
#define __GPR_FILTER_1(T) \
    case X86_REG_E##T##X: \
    case X86_REG_R##T##X: \
        return GPRSTATE_R##T##X

#define __GPR_FILTER_2(T) \
    case X86_REG_E##T:    \
    case X86_REG_R##T:    \
        return GPRSTATE_R##T

#define __GPR_FILTER_3(T) \
    case X86_REG_##T##D:  \
    case X86_REG_##T:     \
        return GPRSTATE_##T

    switch (reg_id) {
        __GPR_FILTER_1(A);
        __GPR_FILTER_1(B);
        __GPR_FILTER_1(C);
        __GPR_FILTER_1(D);

        __GPR_FILTER_2(DI);
        __GPR_FILTER_2(SI);
        __GPR_FILTER_2(BP);

        __GPR_FILTER_3(R8);
        __GPR_FILTER_3(R9);
        __GPR_FILTER_3(R10);
        __GPR_FILTER_3(R11);
        __GPR_FILTER_3(R12);
        __GPR_FILTER_3(R13);
        __GPR_FILTER_3(R14);
        __GPR_FILTER_3(R15);

        default:
            return 0;
    }

#undef __GPR_FILTER_1
#undef __GPR_FILTER_2
#undef __GPR_FILTER_3
}

Z_API bool z_capstone_is_call(const cs_insn *inst) {
    return (inst->id == X86_INS_CALL) || (inst->id == X86_INS_LCALL);
}

Z_API bool z_capstone_is_jmp(const cs_insn *inst) {
    return (inst->id == X86_INS_JMP) || (inst->id == X86_INS_LJMP);
}

Z_API bool z_capstone_is_xbegin(const cs_insn *inst) {
    return inst->id == X86_INS_XBEGIN;
}

Z_API bool z_capstone_is_ret(const cs_insn *inst) {
    return inst->id == X86_INS_RET;
}

Z_API bool z_capstone_is_loop(const cs_insn *inst) {
    switch (inst->id) {
        case X86_INS_LOOP:
        case X86_INS_LOOPE:
        case X86_INS_LOOPNE:
            return true;
        default:
            return false;
    }
}
Z_API bool z_capstone_is_cjmp(const cs_insn *inst) {
    switch (inst->id) {
        case X86_INS_JAE:
        case X86_INS_JA:
        case X86_INS_JBE:
        case X86_INS_JB:
        case X86_INS_JCXZ:
        case X86_INS_JECXZ:
        case X86_INS_JE:
        case X86_INS_JGE:
        case X86_INS_JG:
        case X86_INS_JLE:
        case X86_INS_JL:
        case X86_INS_JNE:
        case X86_INS_JNO:
        case X86_INS_JNP:
        case X86_INS_JNS:
        case X86_INS_JO:
        case X86_INS_JP:
        case X86_INS_JRCXZ:
        case X86_INS_JS:
            return true;
        default:
            return false;
    }
}

Z_API bool z_capstone_is_terminator(const cs_insn *inst) {
    // TODO: better non-return analysis? (light-weight approach)
    if (z_capstone_is_jmp(inst))
        return true;
    if (z_capstone_is_cjmp(inst))
        return false;
    if (z_capstone_is_call(inst))
        return false;
    if (z_capstone_is_loop(inst))
        return false;
    if (z_capstone_is_xbegin(inst))
        return false;

    // check HLT first
    if (inst->id == X86_INS_HLT) {
        return true;
    }

    cs_detail *detail = inst->detail;
    for (int32_t i = 0; i < detail->groups_count; i++) {
        switch (detail->groups[i]) {
            case X86_GRP_JUMP:
            case X86_GRP_CALL:
            case X86_GRP_BRANCH_RELATIVE:
                EXITME(
                    "branch-relative instruction should be catched before "
                    "[%#lx:\t%s %s]",
                    inst->address, inst->mnemonic, inst->op_str);
            /*
             * instructions in RET and IRET group will change the control flow,
             * but most instructions (except HLT) in INT and PRIVILEGE groups
             * seem not. Please refer to
             * https://github.com/aquynh/capstone/blob/master/arch/X86/X86MappingInsn_reduce.inc
             * for more information
             */
            case X86_GRP_RET:
            case X86_GRP_IRET:
                return true;
            case X86_GRP_INT:
            case X86_GRP_PRIVILEGE:
            default:
                continue;
        }
    }

    return false;
}

Z_API bool z_capstone_is_rare(const cs_insn *inst) {
    // we maintain a rare instruction list to benifit hint collection
    switch (inst->id) {
        case X86_INS_OUT:
        case X86_INS_OUTSB:
        case X86_INS_OUTSD:
        case X86_INS_OUTSW:
        case X86_INS_IN:
        case X86_INS_IRETD:
        case X86_INS_FLD:
        case X86_INS_ENTER:
        case X86_INS_XCHG:
            return true;
        default:
            return false;
    }
}

Z_API RegState *z_capstone_get_register_state(const cs_insn *inst) {
    RegState *rs = STRUCT_ALLOC(RegState);

    // step (1). get grp
    cs_regs regs_read, regs_write;
    uint8_t regs_read_count, regs_write_count;
    if (cs_regs_access(cs, inst, regs_read, &regs_read_count, regs_write,
                       &regs_write_count)) {
        EXITME("fail on cs_regs_access");
    }
    rs->gpr_read = rs->gpr_write = 0;
    rs->gpr_read_32_64 = rs->gpr_write_32_64 = 0;
    // step (1.1). read
    for (int i = 0; i < regs_read_count; i++) {
        rs->gpr_read |= __capstone_mapping_pgr(regs_read[i]);
        rs->gpr_read_32_64 |= __capstone_filter_pgr(regs_read[i]);
    }
    // step (1.2). write
    for (int i = 0; i < regs_write_count; i++) {
        rs->gpr_write |= __capstone_mapping_pgr(regs_write[i]);
        rs->gpr_write_32_64 |= __capstone_filter_pgr(regs_write[i]);
    }

    // step (2). get sse
#define __SSE_MAPPING(T, N, reg, states) \
    do {                                 \
        if ((reg) == X86_REG_##T##N) {   \
            (states) |= T##STATE_##T##N; \
        }                                \
    } while (0)

#define __SSE_MAPPING_FOR_ALL(T, reg, states) \
    do {                                      \
        __SSE_MAPPING(T, 0, reg, states);     \
        __SSE_MAPPING(T, 1, reg, states);     \
        __SSE_MAPPING(T, 2, reg, states);     \
        __SSE_MAPPING(T, 3, reg, states);     \
        __SSE_MAPPING(T, 4, reg, states);     \
        __SSE_MAPPING(T, 5, reg, states);     \
        __SSE_MAPPING(T, 6, reg, states);     \
        __SSE_MAPPING(T, 7, reg, states);     \
        __SSE_MAPPING(T, 8, reg, states);     \
        __SSE_MAPPING(T, 9, reg, states);     \
        __SSE_MAPPING(T, 10, reg, states);    \
        __SSE_MAPPING(T, 11, reg, states);    \
        __SSE_MAPPING(T, 12, reg, states);    \
        __SSE_MAPPING(T, 13, reg, states);    \
        __SSE_MAPPING(T, 14, reg, states);    \
        __SSE_MAPPING(T, 15, reg, states);    \
    } while (0)

    for (int i = 0; i < regs_read_count; i++) {
        __SSE_MAPPING_FOR_ALL(XMM, regs_read[i], rs->xmm_read);
        __SSE_MAPPING_FOR_ALL(YMM, regs_read[i], rs->ymm_read);
        __SSE_MAPPING_FOR_ALL(ZMM, regs_read[i], rs->zmm_read);
    }
    for (int i = 0; i < regs_write_count; i++) {
        __SSE_MAPPING_FOR_ALL(XMM, regs_write[i], rs->xmm_write);
        __SSE_MAPPING_FOR_ALL(YMM, regs_write[i], rs->ymm_write);
        __SSE_MAPPING_FOR_ALL(ZMM, regs_write[i], rs->zmm_write);
    }

#undef __SSE_MAPPING
#undef __SSE_MAPPING_FOR_ALL

    // step (3). get flg
    rs->flg_read = rs->flg_write = 0;
    // step (3.0). check FPU first
    for (int i = 0; i < inst->detail->groups_count; i++) {
        if (inst->detail->groups[i] == X86_GRP_FPU) {
            goto DONE;
        }
    }
    // step (3.1). get flg state
    rs->flg_read = __capstone_mapping_flg_read(inst->detail->x86.eflags);
    rs->flg_write = __capstone_mapping_flg_write(inst->detail->x86.eflags);

    /*
     * XXX: capstone: *sbb* and *adc* instructions do not have any TEST_CF bit.
     * Hence, we use a very conservative approach to get rs->flg_read. Please
     * refer to https://github.com/aquynh/capstone/issues/1696 for more
     * information.
     *
     * However, we do not remove previous rs->flg_read code. Maybe one day we
     * can patch capstone to enable a more powerful optimization.
     */
    // TODO: prepare our own patch for capstone and keystone.
    for (int i = 0; i < regs_read_count; i++) {
        if (regs_read[i] == X86_REG_EFLAGS) {
            rs->flg_read = FLGSTATE_ALL;
            break;
        }
    }

DONE:
    return rs;
}

// XXX: call qword byte [xxx]
Z_API bool z_capstone_is_const_mem_ucall(const cs_insn *inst,
                                         addr_t *addr_ptr) {
    // assign INVALID_ADDR to addr_ptr
    *addr_ptr = INVALID_ADDR;

    // first check that it is a jump instruction
    if (inst->id != X86_INS_CALL) {
        return false;
    }

    // then check that it only has one operand
    cs_detail *detail = inst->detail;
    if (detail->x86.op_count != 1) {
        return false;
    }

    // then check the operand is a qword memory
    cs_x86_op *op = &(detail->x86.operands[0]);
    if (op->type != X86_OP_MEM || op->mem.base != X86_REG_INVALID ||
        op->mem.index != X86_REG_INVALID || op->size != 8) {
        return false;
    }

    // update addr_ptr
    *addr_ptr = op->mem.disp;
    return true;
}

// XXX: call qword byte [rip+xxx]
Z_API bool z_capstone_is_pc_related_ucall(const cs_insn *inst,
                                          addr_t *addr_ptr) {
    // assign INVALID_ADDR to addr_ptr
    *addr_ptr = INVALID_ADDR;

    // first check that it is a jump instruction
    if (inst->id != X86_INS_CALL) {
        return false;
    }

    // then check that it only has one operand
    cs_detail *detail = inst->detail;
    if (detail->x86.op_count != 1) {
        return false;
    }

    // then check the operand is a qword memory
    cs_x86_op *op = &(detail->x86.operands[0]);
    if (op->type != X86_OP_MEM || op->mem.base != X86_REG_RIP ||
        op->mem.index != X86_REG_INVALID || op->size != 8) {
        return false;
    }

    // update addr_ptr
    *addr_ptr = inst->address + inst->size + op->mem.disp;
    return true;
}

// XXX: jmp qword byte [xxx]
Z_API bool z_capstone_is_const_mem_ujmp(const cs_insn *inst, addr_t *addr_ptr) {
    // assign INVALID_ADDR to addr_ptr
    *addr_ptr = INVALID_ADDR;

    // first check that it is a jump instruction
    if (inst->id != X86_INS_JMP) {
        return false;
    }

    // then check that it only has one operand
    cs_detail *detail = inst->detail;
    if (detail->x86.op_count != 1) {
        return false;
    }

    // then check the operand is a qword memory
    cs_x86_op *op = &(detail->x86.operands[0]);
    if (op->type != X86_OP_MEM || op->mem.base != X86_REG_INVALID ||
        op->mem.index != X86_REG_INVALID || op->size != 8) {
        return false;
    }

    // update addr_ptr
    *addr_ptr = op->mem.disp;
    return true;
}

// XXX: jmp qword byte [rip+xxx]
Z_API bool z_capstone_is_pc_related_ujmp(const cs_insn *inst,
                                         addr_t *addr_ptr) {
    // assign INVALID_ADDR to addr_ptr
    *addr_ptr = INVALID_ADDR;

    // first check that it is a jump instruction
    if (inst->id != X86_INS_JMP) {
        return false;
    }

    // then check that it only has one operand
    cs_detail *detail = inst->detail;
    if (detail->x86.op_count != 1) {
        return false;
    }

    // then check the operand is a qword memory
    cs_x86_op *op = &(detail->x86.operands[0]);
    if (op->type != X86_OP_MEM || op->mem.base != X86_REG_RIP ||
        op->mem.index != X86_REG_INVALID || op->size != 8) {
        return false;
    }

    // update addr_ptr
    *addr_ptr = inst->address + inst->size + op->mem.disp;
    return true;
}

Z_API void z_capstone_show_gpr_state(GPRState gpr_state) {
    z_info(
        "rax %d | rbx %d | rcx %d | rdx %d | rdi %d | rsi %d | rbp %d | r8 %d "
        "| r9 %d | r10 %d | r11 %d | r12 %d | r13 %d | r14 %d | r15 %d",
        (gpr_state >> 0) & 1UL, (gpr_state >> 1) & 1UL, (gpr_state >> 2) & 1UL,
        (gpr_state >> 3) & 1UL, (gpr_state >> 4) & 1UL, (gpr_state >> 5) & 1UL,
        (gpr_state >> 6) & 1UL, (gpr_state >> 7) & 1UL, (gpr_state >> 8) & 1UL,
        (gpr_state >> 9) & 1UL, (gpr_state >> 10) & 1UL,
        (gpr_state >> 11) & 1UL, (gpr_state >> 12) & 1UL,
        (gpr_state >> 13) & 1UL, (gpr_state >> 14) & 1UL);
}

Z_API void z_capstone_show_flg_state(FLGState flg_state) {
    z_info("OF %d | SF %d | ZF %d | AF %d | CF %d | PF %d",
           (flg_state >> 0) & 1UL, (flg_state >> 1) & 1UL,
           (flg_state >> 2) & 1UL, (flg_state >> 3) & 1UL,
           (flg_state >> 4) & 1UL, (flg_state >> 5) & 1UL);
}
