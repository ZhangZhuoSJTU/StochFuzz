/*
 * Check whether current CPU support AVX512. To compile, use following command:
 *
 *      clang -mavx512f check_avx512.c -o check_avx512
 */

#include <stdint.h>
#include <stdio.h>

#define BUF_SIZE 0x10000
unsigned char buffer[BUF_SIZE];

int main(int argc, char **argv) {
    register uintptr_t dst asm("rdi") = (uintptr_t)buffer;
    register uintptr_t n asm("rcx") = (uintptr_t)BUF_SIZE;

    asm volatile(
        ".intel_syntax noprefix\n"
        "  xor rax, rax;\n"
        "  vpbroadcastd zmm16, eax;\n"
        "  lea rax, [rdi + rcx];\n"
        "  sub rdi, rax;\n"
        "loop:\n"
        "  vmovdqa64 [rax + rdi], zmm16;\n"
        "  add rdi, 0x40;\n"
        "  jnz loop;\n"
        :
        : "r"(dst), "r"(n)
        : "rax", "zmm16", "memory");

    return 0;
}
