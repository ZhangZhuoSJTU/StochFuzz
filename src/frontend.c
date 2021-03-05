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

static void cmd_disasm(int argc, const char **argv);

static void cmd_patch(int argc, const char **argv);

static void cmd_view(int argc, const char **argv);

static void cmd_run(int argc, const char **argv);

static void cmd_start(int argc, const char **argv);

/*
 * Display usage hints.
 */
static void usage(const char *argv0) {
    z_sayf(
        "\n%s [ options ] -- target_binary [ ... ] \n\n"

        "Mode settings:\n\n"

        "  -s            - start a background daemon and wait for a fuzzer to "
        "attach (default mode)\n"
        "  -r            - dry run target_binary with given arguments and "
        "incrementally rewrites it following the executed path\n"
        "  -p            - patch target_binary without incremental rewriting\n"
        "  -d            - probabilistic disassembly without rewriting\n"
        "  -v            - show currently observed breakpoints\n\n"

        "Rewriting settings:\n\n"

        "  -T            - trace previous PC\n"
        "  -C            - count the number of basic blocks with conflicting "
        "hash values\n"
        "  -P            - disable instrumentation optimization\n"
        "  -R            - assume the return addresses are only used by RET "
        "instructions\n"
        "  -I            - forcedly assume there is data interleaving with "
        "code\n\n"

        "Other stuff:\n\n"

        "  -t msec       - timeout for each attached fuzzing run "
        "(auto-scaled, ??? ms)\n\n",

        argv0);

    exit(1);
}

int main(int argc, const char **argv) {
    assert(PAGE_SIZE == 0x1000);
    assert(PAGE_SIZE_POW2 == 12);

    if (argc <= 2) {
        usage(argv[0]);
    }

    z_log_set_level(LOG_INFO);
    Z_INIT;

    if (!strcasecmp(argv[1], "PATCH")) {
        cmd_patch(argc - 2, argv + 2);
    } else if (!strcasecmp(argv[1], "VIEW")) {
        cmd_view(argc - 2, argv + 2);
    } else if (!strcasecmp(argv[1], "DISASM")) {
        cmd_disasm(argc - 2, argv + 2);
    } else if (!strcasecmp(argv[1], "RUN")) {
        cmd_run(argc - 2, argv + 2);
    } else if (!strcasecmp(argv[1], "START")) {
        cmd_start(argc - 2, argv + 2);
    } else {
        z_error("invalid command: %s", argv[1]);
    }

    Z_FINI;

    return 0;
}

static void cmd_patch(int argc, const char **argv) {
    const char *target = argv[0];
    z_info("target binary: %s", target);

    Core *core = z_core_create(target);
    z_core_activate(core);
    z_core_destroy(core);
}

static void cmd_disasm(int argc, const char **argv) {
    const char *target = argv[0];
    z_info("target binary: %s", target);

    Core *core = z_core_create(target);

    z_patcher_describe(core->patcher);

    z_core_destroy(core);
}

static void cmd_view(int argc, const char **argv) {
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

static void cmd_run(int argc, const char **argv) {
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

static void cmd_start(int argc, const char **argv) {
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
