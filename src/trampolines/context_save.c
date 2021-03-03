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

    // store rdi and rax
    "\tmov [rsp - 144], rax;\n"

    // store EFLAGS
    "\tlahf;\n"
    "\tseto al;\n");
