/*
 * crs_config.h
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
    CRS_STATUS_NORMAL,   // normal exit without crash
} CRSStatus;

/*
 * [CRS_INFO] The crash site information needed by self-patching
 */
typedef struct __crs_info_t {
    uint32_t lock;
    addr_t crash_ip;
    size_t self_fired;
} __CRSInfo;

#define CRS_MAP_SIZE_POW2 PAGE_SIZE_POW2
#define CRS_MAP_SIZE (1 << CRS_MAP_SIZE_POW2)
#define CRS_MAP_ADDR (AFL_MAP_ADDR + AFL_MAP_SIZE)

#define CRS_USED_SIZE sizeof(__CRSInfo)

#define CRS_INFO(field) (((__CRSInfo *)CRS_MAP_ADDR)->field)
#define CRS_INFO_BASE(addr, field) (((__CRSInfo *)(addr))->field)
#define CRS_INFO_ADDR(f) (CRS_MAP_ADDR + offsetof(__CRSInfo, f))

#define CRS_COMM_FD 222

// TODO: CRS_DATA_FD is only used in dry run since now. But dry run does need a
// better communication approach in the future.
#define CRS_DATA_FD 233

#define CRS_INVALID_IP 0x1996083019961219

#endif
