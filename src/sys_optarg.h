#ifndef __SYS_OPTARGS_H
#define __SYS_OPTARGS_H

#include "config.h"

/*
 * Default system options
 */
#define SYS_TIMEOUT 2000UL
#define SYS_CHECK_EXECS 200000

/*
 * System mode
 */
typedef enum system_mode_t {
    SYSMODE_NONE,
    SYSMODE_DAEMON,
    SYSMODE_RUN,
    SYSMODE_PATCH,
    SYSMODE_DISASM,
    SYSMODE_VIEW,
} SysMode;

typedef struct system_optargs_t {
    SysMode mode;

    bool trace_pc;
    bool count_conflict;
    bool disable_opt;
    bool safe_ret;
    bool instrument_early;
    bool force_pdisasm;
    bool force_linear;  // secret option

    int32_t log_level;

    uint64_t timeout;

    uint32_t check_execs;
} SysOptArgs;

extern SysOptArgs sys_optargs;

#endif
