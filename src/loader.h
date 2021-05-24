/*
 * loader.h
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
