/*
 * CRS (Crash Site) configuration
 */
#ifndef __CRS_CONFIG_H
#define __CRS_CONFIG_H

#include "afl_config.h"

typedef enum crs_status_t {
    CRS_STATUS_NOTHING,  // nothing to do for fork server
    CRS_STATUS_REMMAP,   // fork server needs to remmap shadow code
    CRS_STATUS_DEBUG,    // the program are set into delta debugging mode
    CRS_STATUS_CRASH,    // a crash in the subject program

    // XXX: note that fork server would not receive CRS_STATUS_NORMAL
    CRS_STATUS_NORMAL = -1,  // normal exit without crash
} CRSStatus;

/*
 * [CRS_INFO] The crash site information needed by self-patching
 */
typedef struct __crs_info_t {
    addr_t crash_ip;
} __CRSInfo;

#define CRS_MAP_SIZE_POW2 PAGE_SIZE_POW2
#define CRS_MAP_SIZE (1 << CRS_MAP_SIZE_POW2)
#define CRS_MAP_ADDR (AFL_MAP_ADDR + AFL_MAP_SIZE)

#define CRS_USED_SIZE sizeof(__CRSInfo)

#define CRS_INFO(field) (((__CRSInfo *)CRS_MAP_ADDR)->field)
#define CRS_INFO_BASE(addr, field) (((__CRSInfo *)(addr))->field)

#define CRS_COMM_FD 222

// TODO: CRS_DATA_FD is only used in dry run since now. But dry run does need a
// better communication approach in the future.
#define CRS_DATA_FD 233

#define CRS_INVALID_IP 0x1996083019961219

#endif
