/*
 * core.h
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
#include "sys_optarg.h"

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
    uint8_t *afl_trace_bits;

    // unix domain information
    int sock_fd;

    // system otpargs
    SysOptArgs *opts;
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
Z_PUBLIC Core *z_core_create(const char *pathname, SysOptArgs *opts);

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
