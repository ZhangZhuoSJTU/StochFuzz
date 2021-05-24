/*
 * fork_server.h
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
