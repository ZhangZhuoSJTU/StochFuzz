/*
 * Backend of OURTOOL
 */
#ifndef __CORE_H
#define __CORE_H

#include "binary.h"
#include "buffer.h"
#include "config.h"
#include "disassembler.h"
#include "patcher.h"
#include "rewriter.h"

#include <sys/time.h>

/*
 * CrashPoint Type
 *
 *      CP_INTERNAL:    need to disassemble address
 *      CP_EXTERNAL:    need to disassembly address and build jump bridge
 *      CP_RETADDR:     need to build jump bridge
 *
 *      VCP_CALLEE:     virtual crashpoint (returnable callee)
 */
typedef enum cp_type_t {
    /*
     * Real crashpoint
     */
    CP_NONE = 0UL,
    CP_INTERNAL = (1UL << 0),  // internal indirect call/jump
    CP_EXTERNAL = (1UL << 1),  // external callback from library
    CP_RETADDR = (1UL << 2),   // return address when calling library

    /*
     * followings are virtual crashpoints, which means it is not a real
     * crashpoint, but meanful information related with crashpoint
     */
    VCP_CALLEE = (1UL << 3),  // callees that is known to be going to return
} CPType;

/*
 * CrashPoint Log
 */
typedef struct crash_point_t {
    addr_t addr;
    CPType type;
} CrashPoint;

/*
 * Core
 */
STRUCT(Core, {
    Binary *binary;
    Disassembler *disassembler;
    Patcher *patcher;
    Rewriter *rewriter;

    GHashTable *crashpoints;
    const char *crashpoint_log;

    // timeout info
    pid_t client_pid;
    struct itimerval it;

    // shared memory information
    int shm_id;
    addr_t shm_addr;

    // unix domain information
    int sock_fd;
});

DECLARE_GETTER(Core, core, GHashTable *, crashpoints);

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
 * Find new valid address
 */
Z_PUBLIC void z_core_new_address(Core *core, addr_t addr, CPType cp_type);

/*
 * Validate address
 */
Z_PUBLIC bool z_core_validate_address(Core *core, addr_t *addr_ptr,
                                      CPType *cp_type);

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
