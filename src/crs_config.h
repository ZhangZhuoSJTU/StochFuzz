/*
 * CRS (Crash Site) configuration
 */
#ifndef __CRS_CONFIG_H
#define __CRS_CONFIG_H

#include "afl_config.h"

typedef enum crs_cmd_type_t {
    CRS_CMD_NONE = 0x0,
    CRS_CMD_REMMAP,
    CRS_CMD_REWRITE,
    CRS_CMD_MPROTECT,
} CRSCmdType;

typedef struct crs_cmd_t {
    CRSCmdType type;
    union {
        const char buf[0x8];
        uint64_t data;
    };
    addr_t addr;
    size_t size;
} CRSCmd;

enum {
    CRS_STATUS_NONE,        // nothing to do for fork server
    CRS_STATUS_REMMAP,      // fork server needs to remmap shadow code
    CRS_STATUS_CRASH = -1,  // a crash in the subject program
};

/*
 * Memory layout of CRS shared memory:
 *
 *  |- cmds (CRS_CMDBUF_SIZE) -| |- crashed address (sizeof(addr_t)) -|
 */

#define CRS_MAP_SIZE_POW2 PAGE_SIZE_POW2
#define CRS_MAP_SIZE (1 << CRS_MAP_SIZE_POW2)
#define CRS_CMDBUF_SIZE (CRS_MAP_SIZE - sizeof(addr_t))

#define CRS_MAP_ADDR (AFL_MAP_ADDR + AFL_MAP_SIZE)
#define CRS_CRASHIP_ADDR (CRS_MAP_ADDR + CRS_CMDBUF_SIZE)

#define CRS_MAP_MAX_CMD_N (CRS_CMDBUF_SIZE / sizeof(CRSCmd))

#define CRS_COMM_FD 222

// TODO: CRS_DATA_FD is only used in dry run since now. But dry run does need a
// better communication approach in the future.
#define CRS_DATA_FD 233

#define CRS_INVALID_IP 0x1996083019961219

#endif
