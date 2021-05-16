#ifndef __DIAGNOSER_H
#define __DIAGNOSER_H

#include "binary.h"
#include "config.h"
#include "crs_config.h"
#include "disassembler.h"
#include "patcher.h"
#include "rewriter.h"
#include "sys_optarg.h"

#include <gmodule.h>

/*
 * CrashPoint Type
 *
 *      CP_INTERNAL:    need to disassemble address
 *      CP_EXTERNAL:    need to disassembly address and build jump bridge
 *      CP_RETADDR:     need to build jump bridge
 */
// XXX: CP_RETADDR are only used when pdisasm is not fully supported. Note that
// in this situation, even we misidentify a CP_RETADDR, it would not impact the
// rewriting procedure (i.e., any wrong bridge will got fixed later / not
// uncertain_patches in Patcher).
typedef enum cp_type_t {
    CP_NONE = 0UL,
    CP_INTERNAL,  // internal indirect call/jump
    CP_EXTERNAL,  // external callback from library
    CP_RETADDR,   // return address when calling library
} CPType;

#define z_cptype_string(t)              \
    ((type == CP_INTERNAL) ? "INTERNAL" \
                           : ((type == CP_EXTERNAL) ? "EXTERNAL" : "RETADDR"))

/*
 * Logged CrashPoint
 */
typedef struct crash_point_t {
    addr_t addr;
    CPType type;
    bool is_real;
} CrashPoint;

/*
 * The range of Dup-Binary-Search
 */
#define DD_RANGE 4

/*
 * Stage for delta debugging mode
 */
typedef enum delta_debugging_stage {
    DD_STAGE0,  // validate whether it is a rewriting error
    DD_STAGE1,  // binary search to locate the e_iter in Patcher
    DD_STAGE2,  // validate whether all rewriting errors are in a DD_RANGE
    DD_STAGE3,  // binary search to locate the s_iter in Pacther

    DD_NONE = -1,  // not in the delta debugging mode
} DDStage;

/*
 * Diagnoser distinguishes the intentional crashes and the unintentional ones,
 * while it also manages the schedule of self-recovering.
 */
STRUCT(Diagnoser, {
    Binary *binary;

    Patcher *patcher;
    Rewriter *rewriter;
    Disassembler *disassembler;

    DDStage dd_stage;
    int dd_status;
    addr_t dd_addr;
    uint32_t dd_cov;
    // used for distinguishing crash and checking runs
    CRSStatus dd_crs_status;
    const char *dd_banner;
    // used for dup-binary-search (int64_t to avoid overflow)
    int64_t dd_low;
    int64_t dd_high;
    int64_t dd_s_cur;
    int64_t dd_e_cur;

    // XXX: for effeciency, a CrashPoint struct is broken into three elements in
    // the queue.
    GQueue *crashpoints;
    const char *cp_filename;

    // system optargs
    SysOptArgs *opts;
});

DECLARE_GETTER(Diagnoser, diagnoser, GQueue *, crashpoints);

/*
 * Create diagnoser
 */
Z_API Diagnoser *z_diagnoser_create(Patcher *patcher, Rewriter *rewriter,
                                    Disassembler *disassembler,
                                    SysOptArgs *opts);

/*
 * Destroy diagnoser
 */
Z_API void z_diagnoser_destroy(Diagnoser *g);

/*
 * Read recorded crashpoints from log file
 */
Z_API void z_diagnoser_read_crashpoint_log(Diagnoser *g);

/*
 * Log down recorded crashpoints
 */
Z_API void z_diagnoser_write_crashpoint_log(Diagnoser *g);

/*
 * Apply all logged crashpoints
 */
Z_API void z_diagnoser_apply_logged_crashpoints(Diagnoser *g);

/*
 * Find a new crashpoint, and diagnoser will validate this crashpoint and does
 * patch accordingly.
 */
Z_API CRSStatus z_diagnoser_new_crashpoint(Diagnoser *g, int status,
                                           addr_t addr, uint32_t cov,
                                           bool check_run_enabled);

#endif
