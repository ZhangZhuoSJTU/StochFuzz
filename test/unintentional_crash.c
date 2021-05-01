#define ASMSTR(S) "\t" S "\n"

int main(int argc, char **argv) {
    asm volatile(
        ASMSTR(".intel_syntax noprefix")

        ASMSTR("dec rdi;")
        ASMSTR("test rdi, rdi;")
        ASMSTR("jne Y;")
        ASMSTR("jmp B;")
        ASMSTR("jmp A;")
        ASMSTR("jmp Z;")
        ASMSTR("jmp A;")
        ASMSTR("jmp Z;")
        ASMSTR("jmp A;")
        ASMSTR("jmp Z;")
        ASMSTR("jmp A;")
        ASMSTR("jmp Z;")
        ASMSTR("jmp A;")
        ASMSTR("jmp Z;")
        ASMSTR("jmp A;")
        ASMSTR("jmp Z;")

        ASMSTR(".global Y")
        ASMSTR("Y:")
        ASMSTR("xor rbx, rbx")
        ASMSTR("mov bx, word ptr [X];")
        ASMSTR("sub rbx, 0xf1dc;")
        ASMSTR("push rbx;")
        ASMSTR("lea r8, [rip + A];")

        ASMSTR(".global A")
        ASMSTR("A:")
        ASMSTR("pop r9;")
        ASMSTR("add r8, r9;")
        ASMSTR("call r8;")

        ASMSTR(".global Z")
        ASMSTR("Z:")
        ASMSTR("call A;")
        ASMSTR(".global X")
        ASMSTR("X:")
        ASMSTR("jmp A;")

        ASMSTR(".global B")
        ASMSTR("B:")
        ASMSTR("mov rax, 60;")
        ASMSTR("mov rdi, 0;")
        ASMSTR("syscall;")

        ASMSTR("ret;")

        ASMSTR(".att_syntax;")
        );
}
