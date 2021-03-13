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
extern const char sigsegv_sigill_info_str[];
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
    "\tleaq _entry(%rip), %rsi;\n"
    "\tsubq %rbx, %rsi;\n"      // program base into %rsi (size_t rip_base)
    "\tleaq 16(%rdi), %rdx;\n"  // names in %rdx (const char *name)
    "\tmovq 8(%rdi), %rdi;\n"
    "\taddq %rsi, %rdi;\n"  // TP chunk base into %rdi (Trampoline *tp)
    "\tmovq %rax, %rcx;\n"  // pathname into %rcx (const char *pathname)

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
    ASM_STRING(loader_logo_str,
               "\\033[32mpatched by izhuer, current running path: \\033[0m")
    // sigsegv and sigill info string
    ASM_STRING(sigsegv_sigill_info_str, "SIGSEGV/SIGILL occurs, with ")
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

    RW_PAGE_INFO(program_base) = (void *)rip_base;
}

/*
 * signal handler
 */
static void loader_catch_sigsegv_and_sigill(int signal, siginfo_t *siginfo,
                                            void *context) {
    uint64_t rip = ((ucontext_t *)context)->uc_mcontext.gregs[REG_RIP];
    uint64_t client_pid = RW_PAGE_INFO(client_pid);
    uint64_t self_pid = sys_getpid();

#ifdef DEBUG
    char s[0x40] = "";
    s[0] = 'r';
    s[1] = 'i';
    s[2] = 'p';
    s[3] = ':';
    s[4] = ' ';
    utils_num2hexstr(s + 5, rip);
    s[21] = '(';
    utils_num2hexstr(s + 22, self_pid);
    s[38] = ')';
    s[39] = '\n';
    s[40] = '\x00';
    utils_puts(sigsegv_sigill_info_str, false);
    utils_puts(s, false);
#endif

    rip -= (uint64_t)(RW_PAGE_INFO(program_base));

    // XXX: For an *UNKNOWN* reason, pipe CRS_DATA_FD sometimes is broken,
    // resulting in an incorrect patching schedule. Hence, we adopt shared
    // memory to sent crashed PC. Note that CRS_DATA_FD is still valid in dry
    // run, for compatibility. In the future, we will abandon this pipe.
    if (RW_PAGE_INFO(daemon_attached)) {
        *((addr_t *)CRS_CRASHIP_ADDR) = rip;
    } else {
        if (sys_write(CRS_DATA_FD, (char *)(&rip), 8) != 8) {
            utils_error(handler_err_str, true);
        }
    }

    sys_kill(client_pid, SIGUSR1);  // kill client
    sys_kill(self_pid, SIGUSR1);    // kill itself, if it is not the client
}

/*
 * Register signal handlers for SIGSEGV and SIGILL to send crash site
 * information.
 */
static inline void loader_set_signal_handler() {
    struct kernel_sigaction sa = {};

    sa.k_sa_handler = &loader_catch_sigsegv_and_sigill;
    sa.sa_flags = SA_SIGINFO | SA_RESTORER;
    sa.sa_restorer = &restorer;

    if (sys_rt_sigaction(SIGSEGV, &sa, NULL, _NSIG / 8)) {
        utils_error(loader_err_str, true);
    }

    if (sys_rt_sigaction(SIGILL, &sa, NULL, _NSIG / 8)) {
        utils_error(loader_err_str, true);
    }
}

/*
 * Install seccomp filter to avoid modify SIGSEGV/SIGILL handler
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
     *        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigaction, 0, 4),
     *        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
     *                 (offsetof(struct seccomp_data, args[0]))),
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
        "\\025\\000\\000\\004\\015\\000\\000\\000"  // 1. BPF_JUMP
        "\\040\\000\\000\\000\\020\\000\\000\\000"  // 2. BPF_STMT
        "\\025\\000\\003\\000\\012\\000\\000\\000"  // 3. BPF_JUMP
        "\\025\\000\\002\\000\\013\\000\\000\\000"  // 4. BPF_JUMP
        "\\025\\000\\001\\000\\004\\000\\000\\000"  // 5. BPF_JUMP
        "\\006\\000\\000\\000\\000\\000\\377\\177"  // 6. BPF_STMT
        "\\006\\000\\000\\000\\000\\000\\005\\000"  // 7. BPF_STME
        "\"\n\t"
        "_out:"
        : "=rax"(filter)
        :
        :);

    struct sock_fprog prog = {
        .len = 8,  // (unsigned short)(sizeof(filter) / sizeof(filter[0])),
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
NO_INLINE void loader_load(Trampoline *tp, size_t rip_base, const char *name,
                           const char *pathname) {
    void *mmap_addr, *tp_addr;
    unsigned long mmap_size, tp_size, next_tp_offset;

    loader_set_signal_handler();
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
        fullpath, (unsigned long)tp + rip_base, PROT_READ | PROT_EXEC);
    // lookup table file
    __PARSE_FILENAME(cur_, name);
    utils_strcpy(RW_PAGE_INFO(lookup_tab_path), fullpath);
    utils_puts(RW_PAGE_INFO(lookup_tab_path), true);
    RW_PAGE_INFO(lookup_tab_size) =
        utils_mmap_external_file(fullpath, LOOKUP_TABLE_ADDR, PROT_READ);
    // pipe file
    __PARSE_FILENAME(cur_, name);
    utils_strcpy(RW_PAGE_INFO(pipe_path), fullpath);
    utils_puts(RW_PAGE_INFO(pipe_path), true);

#undef __PARSE_FILENAME

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
