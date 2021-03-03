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
// AFL_BB_ID Algorithm used in AFL-QEMU, but it seems bad on statical rewrite

#define AFL_BB_ID(x) (((x) ^ ((x) >> AFL_MAP_SIZE_POW2)) & AFL_MAP_SIZE_MASK)

#endif
