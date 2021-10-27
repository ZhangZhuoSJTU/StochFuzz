/*
 * the code inside asm(".globl _entry\n ...")
 * Copyright (C) 2021 National University of Singapore
 * Copyright (C) 2021 Zhuo Zhang, Xiangyu Zhang
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */
// XXX: the code inside the asm(".globl _entry\n ...") is modified based on
// https://github.com/GJDuck/e9patch/blob/master/src/e9patch/e9loader.cpp

/*
 * other parts of loader.c
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
 * Layout of patched binary (on disk):
 *
 *         padding                              padding
 *            |                                    |
 *            V                                    V
 * | ori ELF |.| loader (see below) | fork server |.| trampolines (see below) |
 *  \_____________________  _______________________/ \___________  __________/
 *                        \/                                     \/
 *                   <INPUT_ELF>                     SHADOW_PREFIX.<INPUT_ELF>
 */

/*
 * Layout of loader:
 *
 * | loader | jmp 2 ori entrypoint | loader base | TP base | TP size | names |
 *                                                    |
 *                                                    |
 * +--------------------------------------------------+
 * |
 * V
 * | trampoline 1 | shadow code | trampoline 2| ... | trampoline n |
 *        ^
 *        |
 *        |
 *        +-- | mmap addr | mmap size | TP addr | TP size | next TP off | data |
 *
 *
 *  For trampolines meta data:
 *
 *    +----------------+-----------+-----------+----------+----------+
 *    |      Type      | mmap addr | mmap size | TP addr  | TP size  |
 *    +----------------+-----------+-----------+----------+----------+
 *    |  uTP (w/ mmap) |  Non-NULL |  Non-NULL | Non-NULL | Non-NULL |
 *    +----------------+-----------+-----------+----------+----------+
 *    | uTP (w/o mmap) |    NULL   |    NULL   | Non-NULL | Non-NULL |
 *    +----------------+-----------+-----------+----------+----------+
 *    |      TP        |    NULL   |    NULL   |   NULL   | Non-NULL |
 *    +----------------+-----------+-----------+----------+----------+
 *    |    Terminal    |    NULL   |    NULL   |   NULL   |   NULL   |
 *    +----------------+-----------+-----------+----------+----------+
 *
 */

#include "loader.h"

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <signal.h>
#include <sys/prctl.h>

#include "asm_utils.c"

#define SA_RESTORER 0x04000000

#ifdef DEBUG
extern const char loader_logo_str[];
extern const char suspect_signal_info_str[];
extern const char loader_err_str[];
extern const char prctl_err_str[];
extern const char handler_err_str[];
#endif

extern void restorer();

asm(
    /*
     * Entry into stage #1 (loader).  We:
     *  (0) save all registers
     *  (1) call loader_output_running_path() if necessary
     *  (2) setup stage parameters for loader_load()
     *  (3) call loader_load() to mmap and copy data to target virtual addr
     *  (4) restore all registers
     *  (5) jump to original entrypoint
     */
    ".globl _entry\n"
    ".type _entry,@function\n"
    "_entry:\n"

    // (0) save registers (meanwhile storing variable *envp*)
    "\tpushq %r15;\n"
    "\tpushq %r14;\n"
    "\tpushq %r13;\n"
    "\tpushq %r12;\n"
    "\tpushq %r11;\n"
    "\tpushq %r10;\n"
    "\tpushq %r9;\n"
    "\tpushq %r8;\n"
    "\tpushq %rcx;\n"
    "\tpushq %rdx;\n"
    "\tpushq %rsi;\n"
    "\tpushq %rdi;\n"

    // (1) call loader_output_running_path()
    "\tmovq 0x68(%rsp), %rdi;\n"  // XXX: note that the magic number 0x68 is
                                  // associated with how many registers we
                                  // pushed on the stack
    "\tcallq loader_output_running_path;\n"  // Show current path

    // (2) setup stage parameters for loader_load()
    "\tlea __etext(%rip), %rdi;\n"
    "\taddq $4, %rdi;\n"
    "\tshrq $3, %rdi;\n"
    "\tincq %rdi;\n"
    "\tshlq $3, %rdi;\n"  // cur_addr in __binary_setup_loader step (4) binary.c
    "\tmovq (%rdi), %rbx;\n"
    "\tleaq _entry(%rip), %rdx;\n"
    "\tsubq %rbx, %rdx;\n"      // program base into %rdx (size_t rip_base)
    "\tleaq 24(%rdi), %rcx;\n"  // names in %rcx (const char *name)
    "\tmovq 16(%rdi), %rsi;\n"
    "\taddq %rdx, %rsi;\n"  // .text base into %rsi (void *shared_text_base)
    "\tmovq 8(%rdi), %rdi;\n"
    "\taddq %rdx, %rdi;\n"  // TP chunk base into %rdi (Trampoline *tp)
    "\tmovq %rax, %r8;\n"   // pathname into %r8 (const char *pathname)

    // (3) mmap and copy data to target virtual addr
    "\tcld;\n"                // set DF register
    "\tcallq loader_load;\n"  // call loader_load()

    // (4) restore all registers
    "\tpopq %rdi;\n"
    "\tpopq %rsi;\n"
    "\tpopq %rdx;\n"
    "\tpopq %rcx;\n"
    "\tpopq %r8;\n"
    "\tpopq %r9;\n"
    "\tpopq %r10;\n"
    "\tpopq %r11;\n"
    "\tpopq %r12;\n"
    "\tpopq %r13;\n"
    "\tpopq %r14;\n"
    "\tpopq %r15;\n"

    // (5) jump to original entrypoint
    // The springboard to original entrypoint will be placed at the end of the
    // (.text) section.
    "\tjmp __etext\n"

    /*
     * restore function for rt_sigaction
     */
    ".global restorer\n"
    ".type restorer,@function\n"
    "restorer:\n"
    "\tmov $15,%rax;\n"
    "\tsyscall;\n"
    "\tret;\n"

/*
 * The following defines the read-only data used by the loader.
 * Note that we define the data as executable code to keep everything
 * in the (.text) section.
 */
#ifdef DEBUG
    ASM_STRING(loader_logo_str, "\\033[32mpatched by " OURTOOL
                                ", current running path: \\033[0m")
    // suspect signal info string
    ASM_STRING(suspect_signal_info_str, "suspect signal occurs, with ")
    // prctl error
    ASM_STRING(prctl_err_str, "prctl error")
    // handler error
    ASM_STRING(handler_err_str, "signal handler error")
    // loader error
    ASM_STRING(loader_err_str, "loader: loading error")
#endif

);

static void loader_memcpy(void *dst_0, void *src_0, size_t n_0) {
    register uintptr_t dst asm("rdi") = (uintptr_t)dst_0;
    register uintptr_t src asm("rsi") = (uintptr_t)src_0;
    register uintptr_t n asm("rcx") = (uintptr_t)(n_0);

    asm volatile(
        "movq %%rcx, %%rdx\n\t"
        "andq $7, %%rdx\n\t"
        "shrq $3, %%rcx\n\t"
        "rep movsq\n\t"
        "movq %%rdx, %%rcx\n\t"
        "rep movsb\n\t"
        :
        : "r"(dst), "r"(src), "r"(n)
        : "rdx");
}

/*
 * mmap a fake AFL_SHARED_MEMORY to avoid instrumentation before main
 */
static inline void loader_mmap_fake_shared_memory() {
    unsigned long shared_mem_addr = AFL_MAP_ADDR;
    size_t shared_mem_size = AFL_MAP_SIZE;

    if (sys_mmap(shared_mem_addr, shared_mem_size, PROT_READ | PROT_WRITE,
                 MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1,
                 0) != shared_mem_addr) {
        utils_error(loader_err_str, true);
    }

    shared_mem_addr = CRS_MAP_ADDR;
    shared_mem_size = CRS_MAP_SIZE;
    if (sys_mmap(shared_mem_addr, shared_mem_size, PROT_READ | PROT_WRITE,
                 MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1,
                 0) != shared_mem_addr) {
        utils_error(loader_err_str, true);
    }
}

/*
 * mmap a R/W data page at fixed address RW_PAGE_ADDR, and store rip base into
 * the first qword.
 */
static inline void loader_mmap_data_page(size_t rip_base) {
    if (sys_mmap(RW_PAGE_ADDR, RW_PAGE_SIZE, PROT_READ | PROT_WRITE,
                 MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1,
                 0) != RW_PAGE_ADDR) {
        utils_error(loader_err_str, true);
    }

    RW_PAGE_INFO(program_base) = (addr_t)rip_base;
}

/*
 * signal handler
 */
static void loader_catch_suspect_signals(int signal, siginfo_t *siginfo,
                                         void *context) {
    uint64_t rip = ((ucontext_t *)context)->uc_mcontext.gregs[REG_RIP];

#ifdef DEBUG
    uint64_t client_pid = RW_PAGE_INFO(client_pid);

    char s[0x40] = "";
    s[0] = 'r';
    s[1] = 'i';
    s[2] = 'p';
    s[3] = ':';
    s[4] = ' ';
    utils_num2hexstr(s + 5, rip);
    s[21] = '(';
    utils_num2hexstr(s + 22, client_pid);
    s[38] = ',';
    s[39] = ' ';
    utils_num2hexstr(s + 40, sys_getpid());
    s[56] = ')';
    s[57] = '\n';
    s[58] = '\x00';
    utils_puts(suspect_signal_info_str, false);
    utils_puts(s, false);
#endif

    rip -= RW_PAGE_INFO(program_base);

    // XXX: For an *UNKNOWN* reason, pipe CRS_DATA_FD sometimes is broken,
    // resulting in an incorrect patching schedule. Hence, we adopt shared
    // memory to sent crashed PC. Note that CRS_DATA_FD is still valid in dry
    // run, for compatibility. In the future, we will abandon this pipe.
    if (RW_PAGE_INFO(daemon_attached)) {
        // we need a lock to avoid race condition
        if (!__sync_lock_test_and_set((uint32_t *)CRS_INFO_ADDR(lock), 1)) {
            CRS_INFO(crash_ip) = (addr_t)rip;
            CRS_INFO(self_fired) = 1UL;
        } else {
            // we pause this process here. Note that we are fine with pause()
            // here.
            sys_pause();
        }
    } else {
        // we only need to send rip, since a successful communication indicates
        // a signal fired
        if (sys_write(CRS_DATA_FD, (char *)(&rip), 8) != 8) {
            utils_error(handler_err_str, true);
        }
    }

    // it would be better to kill all the process in the group
    sys_kill(0, SIGKILL);
}

/*
 * Register signal handlers for suspect signals to send crash site information.
 */
static inline void loader_set_signal_handler(addr_t rip_base) {
    /*
     * Before we set signal handler, we will first mmap a new stack for the
     * handler. As such, even if the stack gets polluted, we can send the crash
     * address to the daemon. More details can be found in:
     *   https://man7.org/linux/man-pages/man2/sigaltstack.2.html
     *   https://stackoverflow.com/questions/39297207/catching-sigsegv-when-triggered-by-corrupt-stack
     */
    addr_t ss_addr = rip_base + SIGNAL_STACK_ADDR;
    if (sys_mmap(ss_addr, SIGNAL_STACK_SIZE, PROT_READ | PROT_WRITE,
                 MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0) != ss_addr) {
        utils_error(loader_err_str, true);
    }
    stack_t ss = {
        .ss_sp = (void *)ss_addr,
        .ss_flags = 0,
        .ss_size = SIGNAL_STACK_SIZE,
    };
    sys_sigaltstack(&ss, NULL);

    struct kernel_sigaction sa = {};

    sa.k_sa_handler = &loader_catch_suspect_signals;
    sa.sa_flags = SA_SIGINFO | SA_RESTORER | SA_ONSTACK;
    sa.sa_restorer = &restorer;

    if (sys_rt_sigaction(SIGSEGV, &sa, NULL, _NSIG / 8)) {
        utils_error(loader_err_str, true);
    }

    if (sys_rt_sigaction(SIGILL, &sa, NULL, _NSIG / 8)) {
        utils_error(loader_err_str, true);
    }

    // XXX: overlapping bridges may cause SIGTRAP
    if (sys_rt_sigaction(SIGTRAP, &sa, NULL, _NSIG / 8)) {
        utils_error(loader_err_str, true);
    }
}

/*
 * Install seccomp filter to avoid modify suspect signal handler
 */
static inline void loader_set_seccomp() {
    if (sys_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        utils_error(prctl_err_str, true);
    }

    /*
     * Use compiled seccomp rule (bytecode) to avoid compilation difference
     *
     *    int error = 0;
     *    struct sock_filter filter[] = {
     *        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
     *                 (offsetof(struct seccomp_data, nr))),
     *        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigaction, 0, 5),
     *        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
     *                 (offsetof(struct seccomp_data, args[0]))),
     *        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGTRAP, 4, 0),
     *        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGUSR1, 3, 0),
     *        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGSEGV, 2, 0),
     *        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGILL, 1, 0),
     *        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
     *        BPF_STMT(BPF_RET | BPF_K,
     *                 SECCOMP_RET_ERRNO | (error & SECCOMP_RET_DATA))};
     *
     */

    register struct sock_filter *filter asm("rax");
    asm volatile(
        "  leaq _filter(%%rip), %%rax\n\t"
        "  jmp _out\n\t"
        "_filter:\n\t"
        ".ascii \""
        "\\040\\000\\000\\000\\000\\000\\000\\000"  // 0. BPF_STMT
        "\\025\\000\\000\\005\\015\\000\\000\\000"  // 1. BPF_JUMP
        "\\040\\000\\000\\000\\020\\000\\000\\000"  // 2. BPF_STMT
        "\\025\\000\\004\\000\\005\\000\\000\\000"  // 3. BPF_JUMP
        "\\025\\000\\003\\000\\012\\000\\000\\000"  // 4. BPF_JUMP
        "\\025\\000\\002\\000\\013\\000\\000\\000"  // 5. BPF_JUMP
        "\\025\\000\\001\\000\\004\\000\\000\\000"  // 6. BPF_JUMP
        "\\006\\000\\000\\000\\000\\000\\377\\177"  // 7. BPF_STMT
        "\\006\\000\\000\\000\\000\\000\\005\\000"  // 8. BPF_STME
        "\"\n\t"
        "_out:"
        : "=rax"(filter)
        :
        :);

    struct sock_fprog prog = {
        .len = 9,  // (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (sys_prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (unsigned long)(&prog),
                  0, 0)) {
        utils_error(prctl_err_str, true);
    }
}

/*
 * Load ujmp/ucall trampolines, and set a W/R page tp store global data
 */
NO_INLINE void loader_load(Trampoline *tp, void *shared_text_base,
                           size_t rip_base, const char *name,
                           const char *pathname) {
    void *mmap_addr, *tp_addr;
    unsigned long mmap_size, tp_size, next_tp_offset;

    // in case we send SIGKILL to all the parent signal
    sys_setpgid(0, 0);  // ignore errors

    loader_set_signal_handler((addr_t)rip_base);
    loader_set_seccomp();

    loader_mmap_data_page(rip_base);
    loader_mmap_fake_shared_memory();

    // get related path
    // (XXX: check overflow? but the longest path on linux is only 0x100 bytes)
    char fullpath[0x200];
    const char *slash_ = NULL;
    for (int i = 0; i < 0x200; i++) {
        char c = pathname[i];
        fullpath[i] = c;
        if (c == '/') {
            slash_ = fullpath + i;
        }
        if (!c) {
            break;
        }
    }

    char *cur_ = NULL;
    if (slash_) {
        // get last slash symbol
        cur_ = (char *)slash_ + 1;
    } else {
        cur_ = fullpath;
    }

#define __PARSE_FILENAME(dir, s)   \
    do {                           \
        int i = 0;                 \
        do {                       \
            (dir)[i++] = *((s)++); \
        } while (*s);              \
        (s)++;                     \
        (dir)[i] = '\x00';         \
    } while (0)

    // shadow file
    __PARSE_FILENAME(cur_, name);
    utils_strcpy(RW_PAGE_INFO(shadow_path), fullpath);
    utils_puts(RW_PAGE_INFO(shadow_path), true);
    RW_PAGE_INFO(shadow_size) = utils_mmap_external_file(
        fullpath, false, (unsigned long)tp, PROT_READ | PROT_EXEC);
    RW_PAGE_INFO(shadow_base) = (addr_t)tp;

    // lookup table file
    __PARSE_FILENAME(cur_, name);
    utils_strcpy(RW_PAGE_INFO(lookup_tab_path), fullpath);
    utils_puts(RW_PAGE_INFO(lookup_tab_path), true);
    addr_t lookup_table_addr = rip_base + LOOKUP_TABLE_ADDR;
    RW_PAGE_INFO(lookup_tab_base) = lookup_table_addr;
    RW_PAGE_INFO(lookup_tab_size) =
        utils_mmap_external_file(fullpath, false, lookup_table_addr, PROT_READ);

    // pipe file
    __PARSE_FILENAME(cur_, name);
    utils_strcpy(RW_PAGE_INFO(pipe_path), fullpath);
    utils_puts(RW_PAGE_INFO(pipe_path), true);

    // shared .text file
    __PARSE_FILENAME(cur_, name);
    utils_strcpy(RW_PAGE_INFO(shared_text_path), fullpath);
    utils_puts(RW_PAGE_INFO(shared_text_path), true);
    RW_PAGE_INFO(shared_text_size) = utils_mmap_external_file(
        fullpath, true, (unsigned long)shared_text_base, PROT_READ | PROT_EXEC);
    RW_PAGE_INFO(shared_text_base) = (addr_t)shared_text_base;

    // retaddr mapping file
    __PARSE_FILENAME(cur_, name);
    utils_strcpy(RW_PAGE_INFO(retaddr_mapping_path), fullpath);
    utils_puts(RW_PAGE_INFO(retaddr_mapping_path), true);
    addr_t retaddr_mapping_addr = rip_base + RETADDR_MAPPING_ADDR;
    RW_PAGE_INFO(retaddr_mapping_base) = retaddr_mapping_addr;
    RW_PAGE_INFO(retaddr_mapping_size) = utils_mmap_external_file(
        fullpath, false, retaddr_mapping_addr, PROT_READ | PROT_WRITE);
    if (*((int64_t *)retaddr_mapping_addr) == -1) {
        // retaddr mapping is useless
        uint64_t ori_size = RW_PAGE_INFO(retaddr_mapping_size);
        if (sys_munmap(retaddr_mapping_addr, ori_size)) {
            utils_error(loader_err_str, true);
        }
        RW_PAGE_INFO(retaddr_mapping_used) = false;
        RW_PAGE_INFO(retaddr_mapping_size) = 0;
    } else {
        RW_PAGE_INFO(retaddr_mapping_used) = true;
        // set the function pointer as NULL
        *((void **)retaddr_mapping_addr + 1) = NULL;
        // remap the page as read only
        utils_mmap_external_file(fullpath, true, retaddr_mapping_addr,
                                 PROT_READ);
    }

#undef __PARSE_FILENAME

    // set the client pid as the pid of fork server (loader) itself
    // it will be updated every time we fork a new process
    RW_PAGE_INFO(client_pid) = sys_getpid();

    // XXX: currently TP mapping is not used but reserved for advanced patching.
    // However, note that we still to maintain it as it can be quite useful in
    // the futuer
    while (true) {
        // get every TP's meta-data
        mmap_addr = tp->mmap_addr;
        mmap_size = tp->mmap_size;
        tp_addr = tp->tp_addr;
        tp_size = tp->tp_size;
        next_tp_offset = tp->next_tp_offset;

        // check whether the tp needs to mmap
        if (mmap_addr != NULL && mmap_size != 0) {
            if (sys_mmap((unsigned long)mmap_addr + rip_base, mmap_size,
                         // XXX: PROT_READ | PROT_WRITE | PROT_EXEC ?
                         PROT_READ | PROT_EXEC,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1,
                         0) != (unsigned long)mmap_addr + rip_base) {
                utils_error(loader_err_str, true);
            }
        }

        // check whether the tp needs to memcpy
        if (tp_addr != NULL && tp_size != 0) {
            loader_memcpy(tp_addr + rip_base, tp->tp, tp_size);
        }

        // check terminal
        if (next_tp_offset == 0) {
            break;
        }

        tp = (void *)tp + next_tp_offset;
    }
}

NO_INLINE const char *loader_output_running_path(const char *pathname) {
    utils_puts(loader_logo_str, false);
    utils_puts(pathname, true);
    return pathname;
}
