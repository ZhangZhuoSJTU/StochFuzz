/*
 * asm_syscall.h
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

#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define NO_INLINE __attribute__((__noinline__))
#define NO_RETURN __attribute__((__noreturn__))

#define Z_SYSCALL __attribute__((unused)) static

#define ASM_STRING(name, content)       \
    ".global " #name                    \
    "\n"                                \
    ".type " #name ",@function\n" #name \
    ":\n"                               \
    ".ascii \"" content                 \
    "\"\n"                              \
    ".byte 0x00\n"

/*
 * Kernal sigaction (unlike glibc wrapper)
 */
struct kernel_sigaction {
    void (*k_sa_handler)(int, siginfo_t *, void *);
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    unsigned long sa_mask;
};

Z_SYSCALL unsigned long sys_prctl(unsigned long option_0, unsigned long arg2_0,
                                  unsigned long arg3_0, unsigned long arg4_0,
                                  unsigned long arg5_0) {
    register uintptr_t option asm("rdi") = (uintptr_t)option_0;
    register uintptr_t arg2 asm("rsi") = (uintptr_t)arg2_0;
    register uintptr_t arg3 asm("rdx") = (uintptr_t)arg3_0;
    register uintptr_t arg4 asm("r10") = (uintptr_t)arg4_0;
    register uintptr_t arg5 asm("r8") = (uintptr_t)arg5_0;
    register uintptr_t err asm("rax");

    asm volatile(
        "mov $157, %%eax\n\t"  // SYS_PRCTL
        "syscall"
        : "=rax"(err)
        : "r"(option), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5)
        : "rcx", "r11");

    return (unsigned long)err;
}

Z_SYSCALL unsigned long sys_clone(unsigned long clone_flags_0,
                                  unsigned long newsp_0, pid_t *parent_tidptr_0,
                                  pid_t *child_tidptr_0, void *tls_val_0) {
    register uintptr_t clone_flags asm("rdi") = (uintptr_t)clone_flags_0;
    register uintptr_t newsp asm("rsi") = (uintptr_t)newsp_0;
    register uintptr_t parent_tidptr asm("rdx") = (uintptr_t)parent_tidptr_0;
    register uintptr_t child_tidptr asm("r10") = (uintptr_t)child_tidptr_0;
    register uintptr_t tls_val asm("r8") = (uintptr_t)tls_val_0;
    register uintptr_t err asm("rax");

    asm volatile(
        "mov $56, %%eax\n\t"  // SYS_CLONE
        "syscall"
        : "=rax"(err)
        : "r"(clone_flags), "r"(newsp), "r"(parent_tidptr), "r"(child_tidptr),
          "r"(tls_val)
        : "rcx", "r11");

    return (unsigned long)err;
}

Z_SYSCALL unsigned long sys_mmap(unsigned long addr_0, unsigned long len_0,
                                 unsigned long prot_0, unsigned long flags_0,
                                 unsigned long fd_0, unsigned long off_0) {
    register uintptr_t addr asm("rdi") = (uintptr_t)addr_0;
    register uintptr_t len asm("rsi") = (uintptr_t)len_0;
    register uintptr_t prot asm("rdx") = (uintptr_t)prot_0;
    register uintptr_t flags asm("r10") = (uintptr_t)flags_0;
    register uintptr_t fd asm("r8") = (uintptr_t)fd_0;
    register uintptr_t off asm("r9") = (uintptr_t)off_0;
    register uintptr_t err asm("rax");

    asm volatile(
        "mov $9, %%eax\n\t"  // SYS_MMAP
        "syscall"
        : "=rax"(err)
        : "r"(addr), "r"(len), "r"(prot), "r"(flags), "r"(fd), "r"(off)
        : "rcx", "r11");

    return (unsigned long)err;
}

Z_SYSCALL int sys_mprotect(unsigned long start_0, size_t len_0,
                           unsigned long prot_0) {
    register uintptr_t start asm("rdi") = (uintptr_t)start_0;
    register uintptr_t len asm("rsi") = (uintptr_t)len_0;
    register uintptr_t prot asm("rdx") = (uintptr_t)prot_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $10, %%eax\n\t"  // SYS_MPROTECT
        "syscall"
        : "=rax"(err)
        : "r"(start), "r"(len), "r"(prot)
        : "rcx", "r11");

    return (int)err;
}

Z_SYSCALL int sys_open(const char *filename_0, int flags_0, int mode_0) {
    register uintptr_t filename asm("rdi") = (uintptr_t)filename_0;
    register uintptr_t flags asm("rsi") = (uintptr_t)flags_0;
    register uintptr_t mode asm("rdx") = (uintptr_t)mode_0;
    register intptr_t fd asm("rax");

    asm volatile(
        "mov $2, %%eax\n\t"  // SYS_OPEN
        "syscall"
        : "=rax"(fd)
        : "r"(filename), "r"(flags), "r"(mode)
        : "rcx", "r11");

    return (int)fd;
}

Z_SYSCALL int sys_pipe(int *pipefd_0) {
    register uintptr_t pipefd asm("rdi") = (uintptr_t)pipefd_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $22, %%eax\n\t"  // SYS_PIPE
        "syscall"
        : "=rax"(err)
        : "r"(pipefd)
        : "rcx", "r11");

    return (int)err;
}

Z_SYSCALL int sys_close(int fd_0) {
    register uintptr_t fd asm("rdi") = (uintptr_t)fd_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $3, %%eax\n\t"  // SYS_CLOSE
        "syscall"
        : "=rax"(err)
        : "r"(fd)
        : "rcx", "r11");

    return (int)err;
}

Z_SYSCALL int sys_rt_sigaction(int sig_0, struct kernel_sigaction *act_0,
                               struct kernel_sigaction *oact_0,
                               size_t sigsetsize_0) {
    register uintptr_t sig asm("rdi") = (uintptr_t)sig_0;
    register uintptr_t act asm("rsi") = (uintptr_t)act_0;
    register uintptr_t oact asm("rdx") = (uintptr_t)oact_0;
    register uintptr_t sigsetsize asm("r10") = (uintptr_t)sigsetsize_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $13, %%eax\n\t"  // SYS_RT_SIGACTION
        "syscall"
        : "=rax"(err)
        : "r"(sig), "r"(act), "r"(oact), "r"(sigsetsize)
        : "rcx", "r11");

    return (int)err;
}

Z_SYSCALL int sys_connect(int fd_0, struct sockaddr *addr_0, int addrlen_0) {
    register uintptr_t fd asm("rdi") = (uintptr_t)fd_0;
    register uintptr_t addr asm("rsi") = (uintptr_t)addr_0;
    register uintptr_t addrlen asm("rdx") = (uintptr_t)addrlen_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $42, %%eax\n\t"  // SYS_CONNECT
        "syscall"
        : "=rax"(err)
        : "r"(fd), "r"(addr), "r"(addrlen)
        : "rcx", "r11");

    return (int)err;
}

Z_SYSCALL int sys_socket(int family_0, int type_0, int protocol_0) {
    register uintptr_t family asm("rdi") = (uintptr_t)family_0;
    register uintptr_t type asm("rsi") = (uintptr_t)type_0;
    register uintptr_t protocol asm("rdx") = (uintptr_t)protocol_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $41, %%eax\n\t"  // SYS_SOCKET
        "syscall"
        : "=rax"(err)
        : "r"(family), "r"(type), "r"(protocol)
        : "rcx", "r11");

    return (int)err;
}

Z_SYSCALL int sys_write(int fd_0, const char *buf_0, size_t len_0) {
    register uintptr_t fd asm("rdi") = (uintptr_t)fd_0;
    register uintptr_t buf asm("rsi") = (uintptr_t)buf_0;
    register uintptr_t len asm("rdx") = (uintptr_t)len_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $1, %%eax\n\t"  // SYS_WRITE
        "syscall"
        : "=rax"(err)
        : "r"(fd), "r"(buf), "r"(len)
        : "rcx", "r11");

    return (int)err;
}

Z_SYSCALL int sys_sigaltstack(stack_t *uss_0, stack_t *uoss_0) {
    register uintptr_t uss asm("rdi") = (uintptr_t)uss_0;
    register uintptr_t uoss asm("rsi") = (uintptr_t)uoss_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $131, %%eax\n\t"  // SYS_SIGALTSTACK
        "syscall"
        : "=rax"(err)
        : "r"(uss), "r"(uoss)
        : "rcx", "r11");

    return (int)err;
}

Z_SYSCALL int sys_dup2(int oldfd_0, int newfd_0) {
    register uintptr_t oldfd asm("rdi") = (uintptr_t)oldfd_0;
    register uintptr_t newfd asm("rsi") = (uintptr_t)newfd_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $33, %%eax\n\t"  // SYS_DUP2
        "syscall"
        : "=rax"(err)
        : "r"(oldfd), "r"(newfd)
        : "rcx", "r11");

    return (int)err;
}

Z_SYSCALL int sys_fstat(unsigned int fd_0, struct stat *buf_0) {
    register uintptr_t fd asm("rdi") = (uintptr_t)fd_0;
    register uintptr_t buf asm("rsi") = (uintptr_t)buf_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $5, %%eax\n\t"  // SYS_FSTAT
        "syscall"
        : "=rax"(err)
        : "r"(fd), "r"(buf)
        : "rcx", "r11");

    return (int)err;
}

Z_SYSCALL int sys_exit(int error_code_0) {
    register uintptr_t error_code asm("rdi") = (uintptr_t)error_code_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $60, %%eax\n\t"  // SYS_EXIT
        "syscall"
        : "=rax"(err)
        : "r"(error_code)
        : "rcx", "r11");

    return (int)err;
}

Z_SYSCALL int sys_kill(pid_t pid_0, int sig_0) {
    register uintptr_t pid asm("rdi") = (uintptr_t)pid_0;
    register uintptr_t sig asm("rsi") = (uintptr_t)sig_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $62, %%eax\n\t"  // SYS_KILL
        "syscall"
        : "=rax"(err)
        : "r"(pid), "r"(sig)
        : "rcx", "r11");

    return (int)err;
}

Z_SYSCALL int sys_msync(unsigned long start_0, size_t len_0, int flags_0) {
    register uintptr_t start asm("rdi") = (uintptr_t)start_0;
    register uintptr_t len asm("rsi") = (uintptr_t)len_0;
    register uintptr_t flags asm("rdx") = (uintptr_t)flags_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $26, %%eax\n\t"  // SYS_MSYNC
        "syscall"
        : "=rax"(err)
        : "r"(start), "r"(len), "r"(flags)
        : "rcx", "r11");

    return (int)err;
}

Z_SYSCALL int sys_read(int fd_0, const char *buf_0, size_t len_0) {
    register uintptr_t fd asm("rdi") = (uintptr_t)fd_0;
    register uintptr_t buf asm("rsi") = (uintptr_t)buf_0;
    register uintptr_t len asm("rdx") = (uintptr_t)len_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $0, %%eax\n\t"  // SYS_READ
        "syscall"
        : "=rax"(err)
        : "r"(fd), "r"(buf), "r"(len)
        : "rcx", "r11");

    return (int)err;
}

Z_SYSCALL pid_t sys_wait4(pid_t pid_0, int *wstatus_0, int options_0,
                          struct rusage *rusage_0) {
    register uintptr_t pid asm("rdi") = (uintptr_t)pid_0;
    register uintptr_t wstatus asm("rsi") = (uintptr_t)wstatus_0;
    register uintptr_t options asm("rdx") = (uintptr_t)options_0;
    register uintptr_t rusage asm("r10") = (uintptr_t)rusage_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $61, %%eax\n\t"  // SYS_WAIT4
        "syscall"
        : "=rax"(err)
        : "r"(pid), "r"(wstatus), "r"(options), "r"(rusage)
        : "rcx", "r11");

    return (pid_t)err;
}

Z_SYSCALL void *sys_shmat(int shmid_0, const void *shmaddr_0, int shmflg_0) {
    register uintptr_t shmid asm("rdi") = (uintptr_t)shmid_0;
    register uintptr_t shmaddr asm("rsi") = (uintptr_t)shmaddr_0;
    register uintptr_t shmflg asm("rdx") = (uintptr_t)shmflg_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $30, %%eax\n\t"  // SYS_SHMAT
        "syscall"
        : "=rax"(err)
        : "r"(shmid), "r"(shmaddr), "r"(shmflg)
        : "rcx", "r11");

    return (void *)err;
}

Z_SYSCALL pid_t sys_getpid() {
    register intptr_t err asm("rax");

    asm volatile(
        "mov $39, %%eax\n\t"  // SYS_GETPID
        "syscall"
        : "=rax"(err)
        :
        : "rcx", "r11");

    return (pid_t)err;
}

Z_SYSCALL pid_t sys_fork() {
    register intptr_t err asm("rax");

    asm volatile(
        "mov $57, %%eax\n\t"  // SYS_FORK
        "syscall"
        : "=rax"(err)
        :
        : "rcx", "r11");

    return (pid_t)err;
}

Z_SYSCALL int sys_setpgid(pid_t pid_0, pid_t pgid_0) {
    register uintptr_t pid asm("rdi") = (uintptr_t)pid_0;
    register uintptr_t pgid asm("rsi") = (uintptr_t)pgid_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $109, %%eax\n\t"  // SYS_SETPGID
        "syscall"
        : "=rax"(err)
        : "r"(pid), "r"(pgid)
        : "rcx", "r11");

    return (int)err;
}

Z_SYSCALL int sys_munmap(unsigned long addr_0, size_t len_0) {
    register uintptr_t addr asm("rdi") = (uintptr_t)addr_0;
    register uintptr_t len asm("rsi") = (uintptr_t)len_0;
    register intptr_t err asm("rax");

    asm volatile(
        "mov $11, %%eax\n\t"  // SYS_MUNMAP
        "syscall"
        : "=rax"(err)
        : "r"(addr), "r"(len)
        : "rcx", "r11");

    return (int)err;
}
