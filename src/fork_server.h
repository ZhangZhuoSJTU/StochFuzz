#ifndef __FORK_SERVER_H
#define __FORK_SERVER_H

#include "afl_config.h"
#include "crs_config.h"
#include "loader.h"

typedef enum crs_loop_type {
    CRSLoopNone = 0,  // not a crs loop
    CRSLoopFix,       // crs loop caused by incremental rewriting
    CRSLoopDebug,     // crs loop caused by delta debugging
} CRSLoopType;

#endif
