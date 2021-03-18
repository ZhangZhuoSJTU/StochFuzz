#ifndef __DIAGNOSER_H
#define __DIAGNOSER_H

#include "config.h"
#include "disassembler.h"
#include "patcher.h"
#include "rewriter.h"

#include <gmodule.h>

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
 * Diagnoser distinguishes the intentional crashes and the unintentional ones,
 * while it also manages the schedule of self-recovering.
 */
STRUCT(Diagnoser, {
    Patcher *patcher;
    Rewriter *rewriter;
    Disassembler *disassembler;

    GHashTable *crashpoints;
    const char *cp_filename;
});

DECLARE_GETTER(Diagnoser, diagnoser, GHashTable *, crashpoints);

/*
 * Create diagnoser
 */
Z_API Diagnoser *z_diagnoser_create(Patcher *patcher, Rewriter *rewriter,
                                    Disassembler *disassembler);

/*
 * Destroy diagnoser
 */
Z_API void z_diagnoser_destroy(Diagnoser *g);

/*
 * Read crashpoint information from logfile
 */
Z_API void z_diagnoser_read_crashpoint_log(Diagnoser *g);

/*
 * Log down crashpoints' informationnn
 */
Z_API void z_diagnoser_write_crashpoint_log(Diagnoser *g);

/*
 * Apply all logged crashpoints
 */
Z_API void z_diagnoser_apply_logged_crashpoints(Diagnoser *g);

// XXX: temporarily set a private function as public
Z_API void __diagnoser_handle_single_crashpoint(Diagnoser *g, addr_t addr,
                                                CPType type);

#endif
