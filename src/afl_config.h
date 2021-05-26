/*
 * afl_config.h
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

#ifndef __AFL_CONFIG_H
#define __AFL_CONFIG_H

#include "config.h"

/*
 * XXX: Attaching SHM at a fixed address allows around 10% perf gain. see
 * https://github.com/google/AFL/blob/master/afl-as.h#L71.
 *
 * Note that it is reasonable for a binary-instrumented tool to fix the address,
 * as we can know the memory layout comparied with from assemble view.
 *
 */
/*
 * TODO: when rewritting, dynamically calculate the fixed AFL_MAP_ADDR.
 */
#define AFL_FORKSRV_FD 198
#define AFL_SHM_ENV "__AFL_SHM_ID"
#define AFL_MAP_SIZE_POW2 16
#define AFL_MAP_SIZE (1 << AFL_MAP_SIZE_POW2)
#define AFL_MAP_ADDR (RW_PAGE_ADDR + 0x10000)
#define AFL_PREV_ID_PTR (RW_PAGE_ADDR + 0x8)
#define AFL_MAP_SIZE_MASK ((1 << AFL_MAP_SIZE_POW2) - 1)

// #define AFL_BB_ID(x) ((((x) >> 4) ^ ((x) << 8)) & AFL_MAP_SIZE_MASK)
// AFL_BB_ID Algorithm used in AFL-QEMU, but it seems bad on static binary
// rewriting

#define AFL_BB_ID(x) (((x) ^ ((x) >> AFL_MAP_SIZE_POW2)) & AFL_MAP_SIZE_MASK)

#define AFL_HASH_CONST 0xa5b35705

#endif
