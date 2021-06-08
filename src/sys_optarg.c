/*
 * sys_optarg.c
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

#include "sys_optarg.h"
#include "utils.h"

SysOptArgs sys_optargs = {
    .mode = SYSMODE_NONE,
    .r =
        {
            .trace_pc = false,
            .count_conflict = false,
            .disable_opt = false,
            .safe_ret = false,
            .instrument_early = false,
            .force_pdisasm = false,
            .disable_callthrough = false,
            .force_linear = false,
        },
    .log_level = LOG_INFO,
    .timeout = SYS_TIMEOUT,
    .check_execs = SYS_CHECK_EXECS,
};
