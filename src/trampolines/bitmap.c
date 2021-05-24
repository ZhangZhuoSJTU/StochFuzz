/*
 * bitmap.c
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

#include "../afl_config.h"

#define __BITMAP_FOR_REG(REG)                                          \
    /****************************************************************/ \
    /* set symbol name */                                              \
    ".globl __BITMAP_" STRING(REG) "\n"                                \
    ".type __BITMAP_" STRING(REG) ",@function\n"                       \
    "__BITMAP_" STRING(REG)":\n"                                       \
    /* get prev_id */                                                  \
    "\tmov " STRING(REG) ", [" STRING(AFL_PREV_ID_PTR) "];\n"          \
    /* inc bitmap */                                                   \
    "\txor " STRING(REG) ", 0xDEAD;\n"                                 \
    "\tinc BYTE PTR [" STRING(AFL_MAP_ADDR) " + " STRING(REG) "];\n"   \
    /* update prev_id */                                               \
    "\tmov QWORD PTR [" STRING(AFL_PREV_ID_PTR) "], 0xBEEF;\n"         \
    /* set symbol end  */                                              \
    ".globl __BITMAP_" STRING(REG) "_END\n"                            \
    ".type __BITMAP_" STRING(REG) "_END,@function\n"                   \
    "__BITMAP_" STRING(REG)"_END:\n"                                   \
    /****************************************************************/

asm(".intel_syntax noprefix\n"
    ".globl _entry\n"
    ".type _entry,@function\n"
    "_entry:\n"

    __BITMAP_FOR_REG(RAX)  // FORCE NEWLINE
    __BITMAP_FOR_REG(RBX)  // FORCE NEWLINE
    __BITMAP_FOR_REG(RCX)  // FORCE NEWLINE
    __BITMAP_FOR_REG(RDX)  // FORCE NEWLINE
    __BITMAP_FOR_REG(RDI)  // FORCE NEWLINE
    __BITMAP_FOR_REG(RSI)  // FORCE NEWLINE
    __BITMAP_FOR_REG(RBP)  // FORCE NEWLINE
    __BITMAP_FOR_REG(R8)   // FORCE NEWLINE
    __BITMAP_FOR_REG(R9)   // FORCE NEWLINE
    __BITMAP_FOR_REG(R10)  // FORCE NEWLINE
    __BITMAP_FOR_REG(R11)  // FORCE NEWLINE
    __BITMAP_FOR_REG(R12)  // FORCE NEWLINE
    __BITMAP_FOR_REG(R13)  // FORCE NEWLINE
    __BITMAP_FOR_REG(R14)  // FORCE NEWLINE
    __BITMAP_FOR_REG(R15)  // FORCE NEWLINE
);

#undef __BITMAP_FOR_REG
