/*
 * context_restor.c
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
 * COPY FROM AFL
 *
 * - popf is *awfully* slow, which is why we're doing the lahf / sahf +
 *  overflow test trick. Unfortunately, this forces us to taint eax / rax, but
 *  this dependency on a commonly-used register still beats the alternative of
 *  using pushf / popf.
 *
 *  One possible optimization is to avoid touching flags by using a circular
 *  buffer that stores just a sequence of current locations, with the XOR stuff
 *  happening offline. Alas, this doesn't seem to have a huge impact:
 *
 *  https://groups.google.com/d/msg/afl-users/MsajVf4fRLo/2u6t88ntUBIJ
 */

/*
 * IT SEEMS PUSH/POP generate register is a little bit faster than MOV RSP
 */

asm(".intel_syntax noprefix\n"
    ".globl _entry\n"
    ".type _entry,@function\n"
    "_entry:\n"

    // restore EFLAGS
    "\tadd al, 127;\n"
    "\tsahf;\n"

    // restore rdi and rax
    "\tmov rax, [rsp - 144];\n");
