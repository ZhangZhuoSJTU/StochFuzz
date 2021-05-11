/*
 * Backend of OURTOOL
 */
#ifndef __CORE_H
#define __CORE_H

#include "binary.h"
#include "buffer.h"
#include "config.h"
#include "diagnoser.h"
#include "disassembler.h"
#include "patcher.h"
#include "rewriter.h"

#include <gmodule.h>

#include <sys/time.h>

/*
 * Core
 */
STRUCT(Core, {
    Binary *binary;
    Disassembler *disassembler;
    Patcher *patcher;
    Rewriter *rewriter;
    Diagnoser *diagnoser;

    // timeout info
    pid_t client_pid;
    struct itimerval it;

    // shared memory information
    int shm_id;
    addr_t shm_addr;

    // shared memory of AFL
    int afl_shm_id;
    uint8_t *afl_trace_bits;

    // unix domain information
    int sock_fd;
});

/*
 * Dry run without starting any server
 */
Z_PUBLIC int z_core_perform_dry_run(Core *core, int argc, const char **argv);

/*
 * Start a daemon server to automatically patch any running program
 * (note that only one connection at a time)
 */
Z_PUBLIC void z_core_start_daemon(Core *core, int notify_fd);

/*
 * Create OURTOOL Core
 */
Z_PUBLIC Core *z_core_create(const char *pathname);

/*
 * Destroy OURTOOL Core
 */
Z_PUBLIC void z_core_destroy(Core *core);

/*
 * Activate core analysis
 */
Z_PUBLIC void z_core_activate(Core *core);

/*
 * Disattach core from underlaying executable
 */
Z_PUBLIC void z_core_detach(Core *core);

/*
 * Attach core to attach to its underlaying executable
 */
Z_PUBLIC void z_core_attach(Core *core);

#endif
