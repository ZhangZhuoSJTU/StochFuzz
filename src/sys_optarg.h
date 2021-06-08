/*
 * sys_optarg.h
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

/*
 * Rewriting options
 */
typedef struct rewriting_optargs_t {
    bool trace_pc;
    bool count_conflict;
    bool disable_opt;
    bool safe_ret;
    bool instrument_early;
    bool force_pdisasm;
    bool disable_callthrough;
    bool force_linear;  // secret option
} RewritingOptArgs;

typedef struct system_optargs_t {
    SysMode mode;

    RewritingOptArgs r;

    int32_t log_level;

    uint64_t timeout;

    uint32_t check_execs;
} SysOptArgs;

extern SysOptArgs sys_optargs;

#endif
