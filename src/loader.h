#ifndef __LOADER_H
#define __LOADER_H

#include "crs_config.h"

typedef struct trampoline_t {
    void *mmap_addr;
    unsigned long mmap_size;
    void *tp_addr;
    unsigned long tp_size;
    unsigned long next_tp_offset;
    unsigned char tp[];
} Trampoline;

#endif
