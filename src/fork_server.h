#ifndef __FORK_SERVER_H
#define __FORK_SERVER_H

#include "afl_config.h"
#include "crs_config.h"
#include "loader.h"

typedef struct patch_entry_t {
    unsigned long addr;
    unsigned long size;
} PatchEntry;

#endif
