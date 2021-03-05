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
        "(auto-scaled, ??? ms)\n\n",

        argv0);

    exit(ret_status);
}

static int parse_args(int argc, const char **argv) {
    z_sayf(COLOR(CYAN, OURTOOL) " " COLOR(
        BRIGHT, VERSION) " by <zhan3299@purdue.edu>\n");

    bool timeout_given = false;

    int opt = 0;
    while ((opt = getopt(argc, (char *const *)argv, "+SRPDVgcdrfht:")) > 0) {
        switch (opt) {
#define __MODE_CASE(c, m)                           \
    case c:                                         \
        if (sys_config.mode != SYSMODE_NONE) {      \
            EXITME("trying to set multiple modes"); \
        }                                           \
        sys_config.mode = SYSMODE_##m;              \
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
#undef __SETTING_CASE

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
            default:
                usage(argv[0], 1);
        }
    }

    if (argc == optind) {
        usage(argv[0], 1);
    }

    if (sys_config.mode == SYSMODE_NONE) {
        sys_config.mode = SYSMODE_DAEMON;
    }

    return optind;
}

int main(int argc, const char **argv) {
    assert(PAGE_SIZE == 0x1000);
    assert(PAGE_SIZE_POW2 == 12);

    int next_idx = parse_args(argc, argv);
    argc -= next_idx;
    argv += next_idx;

    z_log_set_level(LOG_INFO);
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

    z_patcher_describe(core->patcher);

    z_core_destroy(core);
}

static inline void mode_view(int argc, const char **argv) {
    const char *target = argv[0];
    z_info("target binary: %s", target);

    Core *core = z_core_create(target);
    GHashTable *cps = z_core_get_crashpoints(core);

    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, cps);

    z_sayf("%-18s%-18s\n", "Address", "CPType");
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        addr_t addr = (addr_t)key;
        addr_t type = (CPType)value & (~VCP_CALLEE);
        if (!type) {
            continue;
        }
        z_sayf("%-#18lx%s%s%s%s%s\n", addr,
               (type & CP_INTERNAL) ? "INTERNAL" : "",
               ((type & CP_INTERNAL) && (type & CP_EXTERNAL)) ? " & " : "",
               (type & CP_EXTERNAL) ? "EXTERNAL" : "",
               ((type & (CP_INTERNAL | CP_EXTERNAL)) && (type & CP_RETADDR))
                   ? " & "
                   : "",
               (type & CP_RETADDR) ? "RETADDR" : "");
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

    if (IS_SUSPECT_STATUS(status)) {
        EXITME("not a normal exit (status: %#x)", status);
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
