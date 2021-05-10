/*
 * Frontend for OURTOOL
 */

#include "afl_config.h"
#include "libstochfuzz.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>

/*
 * Display usage hints.
 */
static void usage(const char *argv0, int ret_status);

/*
 * Parse arguments
 */
static inline int parse_args(int argc, const char **argv);

/*
 * Handle different modes
 */
static inline void mode_disasm(int argc, const char **argv);

static inline void mode_patch(int argc, const char **argv);

static inline void mode_view(int argc, const char **argv);

static inline void mode_run(int argc, const char **argv);

static inline void mode_start(int argc, const char **argv);

static void usage(const char *argv0, int ret_status) {
    z_sayf(
        "\n%s [ options ] -- target_binary [ ... ] \n\n"

        "Mode settings:\n\n"

        "  -S            - start a background daemon and wait for a fuzzer to "
        "attach (defualt mode)\n"
        "  -R            - dry run target_binary with given arguments and "
        "incrementally rewrites it following the executed path\n"
        "  -P            - patch target_binary without incremental rewriting\n"
        "  -D            - probabilistic disassembly without rewriting\n"
        "  -V            - show currently observed breakpoints\n\n"

        "Rewriting settings:\n\n"

        "  -g            - trace previous PC\n"
        "  -c            - count the number of basic blocks with conflicting "
        "hash values\n"
        "  -d            - disable instrumentation optimization\n"
        "  -r            - assume the return addresses are only used by RET "
        "instructions\n"
        "  -f            - forcedly assume there is data interleaving with "
        "code\n\n"

        "Other stuff:\n\n"

        "  -h            - print this help\n"
        "  -t msec       - timeout for each attached fuzzing run "
        "(default timeout: %u ms)\n"
        "  -l level      - log level, including TRACE, DEBUG, INFO, WARN, "
        "ERROR, and FATAL (default level: INFO)\n\n",

        argv0, SYS_TIMEOUT);

    exit(ret_status);
}

static int parse_args(int argc, const char **argv) {
    z_sayf(COLOR(CYAN, OURTOOL) " " COLOR(
        BRIGHT, VERSION) " by <zhan3299@purdue.edu>\n");

    bool timeout_given = false;
    bool log_level_given = false;

    int opt = 0;
    while ((opt = getopt(argc, (char *const *)argv, "+SRPDVgcdrfnht:l:")) > 0) {
        switch (opt) {
#define __MODE_CASE(c, m)                                   \
    case c:                                                 \
        if (sys_config.mode != SYSMODE_NONE) {              \
            EXITME("multiple mode settings not supported"); \
        }                                                   \
        sys_config.mode = SYSMODE_##m;                      \
        break;
            __MODE_CASE('S', DAEMON);
            __MODE_CASE('R', RUN);
            __MODE_CASE('P', PATCH);
            __MODE_CASE('D', DISASM);
            __MODE_CASE('V', VIEW);
#undef __MODE_CASE

#define __SETTING_CASE(c, m) \
    case c:                  \
        sys_config.m = true; \
        break;
            __SETTING_CASE('g', trace_pc);
            __SETTING_CASE('c', count_conflict);
            __SETTING_CASE('d', disable_opt);
            __SETTING_CASE('r', safe_ret);
            __SETTING_CASE('f', force_pdisasm);
            // This is a secret undocumented option! It is mainly used for
            // Github Actions which has memory limitation. Forcely using linear
            // disassembly (which means not doing pre-disassembly and patching
            // all .text) makes smaller memory usage.
            __SETTING_CASE('n', force_linear);
#undef __SETTING_CASE

#define __LOG_LEVEL_STRCASECMP(l, s)        \
    do {                                    \
        if (!strcasecmp(#l, s)) {           \
            sys_config.log_level = LOG_##l; \
            goto DONE;                      \
        }                                   \
    } while (0)
            case 'l':
                if (log_level_given) {
                    EXITME("multiple -l options not supported");
                }
                log_level_given = true;
                __LOG_LEVEL_STRCASECMP(TRACE, optarg);
                __LOG_LEVEL_STRCASECMP(DEBUG, optarg);
                __LOG_LEVEL_STRCASECMP(INFO, optarg);
                __LOG_LEVEL_STRCASECMP(WARN, optarg);
                __LOG_LEVEL_STRCASECMP(ERROR, optarg);
                __LOG_LEVEL_STRCASECMP(FATAL, optarg);
                z_warn("invalid log level: \"%s\"", optarg);
            DONE:
                break;
#undef __LOG_LEVEL_STRCASECMP

            case 't':
                if (timeout_given) {
                    EXITME("multiple -t options not supported");
                }
                timeout_given = true;
                if (z_sscanf(optarg, "%lu", &sys_config.timeout) < 1) {
                    EXITME("bad syntax used for -t");
                }
                break;

            case 'h':
                usage(argv[0], 0);
                break;

            default:
                usage(argv[0], 1);
        }
    }

    // Validating arguments

    if (argc == optind) {
        usage(argv[0], 1);
    }

    if (sys_config.mode == SYSMODE_NONE) {
        sys_config.mode = SYSMODE_DAEMON;
    }

    if (sys_config.mode == SYSMODE_DISASM) {
        // Under disasm mode, we forcely use probabilistic disassembly
        sys_config.force_pdisasm = true;
        sys_config.force_linear = false;
    }

    if (sys_config.force_pdisasm && sys_config.force_linear) {
        EXITME("-f and -n cannot be set together");
    }

    return optind;
}

int main(int argc, const char **argv) {
    assert(PAGE_SIZE == 0x1000);
    assert(PAGE_SIZE_POW2 == 12);

    int next_idx = parse_args(argc, argv);
    argc -= next_idx;
    argv += next_idx;

    z_log_set_level(sys_config.log_level);
    Z_INIT;

    switch (sys_config.mode) {
        case SYSMODE_DAEMON:
            mode_start(argc, argv);
            break;

        case SYSMODE_RUN:
            mode_run(argc, argv);
            break;

        case SYSMODE_PATCH:
            mode_patch(argc, argv);
            break;

        case SYSMODE_DISASM:
            mode_disasm(argc, argv);
            break;

        case SYSMODE_VIEW:
            mode_view(argc, argv);
            break;

        default:
            EXITME("unreachable");
    }

    Z_FINI;

    return 0;
}

static inline void mode_patch(int argc, const char **argv) {
    const char *target = argv[0];
    z_info("target binary: %s", target);

    Core *core = z_core_create(target);
    z_core_activate(core);
    z_core_destroy(core);
}

static inline void mode_disasm(int argc, const char **argv) {
    const char *target = argv[0];
    z_info("target binary: %s", target);

    Core *core = z_core_create(target);

    z_diagnoser_apply_logged_crashpoints(core->diagnoser);
    z_patcher_describe(core->patcher);

    z_core_destroy(core);
}

static inline void mode_view(int argc, const char **argv) {
    const char *target = argv[0];
    z_info("target binary: %s", target);

    Core *core = z_core_create(target);
    GQueue *cps = z_diagnoser_get_crashpoints(core->diagnoser);

    GList *l = cps->head;

    z_sayf("%-20s%-10s%-6s\n", "Address", "CPType", "Real?");
    while (l != NULL) {
        addr_t addr = (addr_t)l->data;

        l = l->next;
        CPType type = (CPType)l->data;

        l = l->next;
        bool is_real = !!(l->data);

        z_sayf("%-#20lx%-10s%-6s\n", addr, z_cptype_string(type),
               (is_real ? "True" : "False"));

        l = l->next;
    }

    z_core_destroy(core);
}

static inline void mode_run(int argc, const char **argv) {
    const char *target = argv[0];
    z_info("target binary: %s", target);

    Core *core = z_core_create(target);
    z_core_activate(core);
    int status = z_core_perform_dry_run(core, argc, argv);
    z_core_destroy(core);

    if (IS_ABNORMAL_STATUS(status)) {
        z_info(COLOR(RED, "not a normal exit (status: %#x)"), status);
    }

    // follow how the client is terminated
    if (WIFEXITED(status)) {
        exit(WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        kill(getpid(), WTERMSIG(status));
    } else {
        kill(getpid(), WSTOPSIG(status));
    }
}

static inline void mode_start(int argc, const char **argv) {
#ifdef BINARY_SEARCH_INVALID_CRASH
    EXITME(
        "daemon mode is not supported when doing binary search for invalid "
        "crash");
#else
    const char *target = argv[0];
    z_info("target binary: %s", target);
    Core *core = z_core_create(target);
    z_core_activate(core);
    z_core_start_daemon(core, INVALID_FD);
    z_core_destroy(core);
#endif
}
