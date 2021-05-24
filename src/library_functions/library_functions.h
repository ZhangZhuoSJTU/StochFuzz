/*
 * library_functions.h
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

#ifndef __LIBRARY_FUNCTIONS_H
#define __LIBRARY_FUNCTIONS_H

#include "../config.h"

// whether the library function will return to caller
typedef enum lcfg_info_t {
    LCFG_OBJ,  // this is not an imported function but an object
    LCFG_UNK,
    LCFG_RET,
    LCFG_TERM,
} LCFGInfo;

// whether the retaddr pushed by `call` instructions is used
typedef enum lra_info_t {
    LRA_OBJ,  // this is not an imported function but an object
    LRA_UNK,
    LRA_USED,
    LRA_UNUSED,
} LRAInfo;

typedef struct lfunc_info_t {
    const char *name;
    LCFGInfo cfg_info;
    LRAInfo ra_info;
} LFuncInfo;

Z_API void z_libfunc_init();

Z_API void z_libfunc_fini();

Z_API const LFuncInfo *z_libfunc_get_info(const char *name);

Z_API const LFuncInfo *z_libfunc_default();

#endif
