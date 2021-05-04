#ifndef __FORK_SERVER_H
#define __FORK_SERVER_H

#include "afl_config.h"
#include "crs_config.h"
#include "loader.h"

typedef enum crs_loop_type {
    CRS_LOOP_NONE = 0,  // not a crs loop
    CRS_LOOP_INCR,      // crs loop caused by incremental rewriting
    CRS_LOOP_DEBUG,     // crs loop caused by delta debugging
} CRSLoopType;

#endif
