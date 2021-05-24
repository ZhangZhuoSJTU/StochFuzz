/*
 * library_functions.c
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

#include "library_functions.h"
#include "../utils.h"

#include <gmodule.h>

/*
 * Create a LFuncInfo
 */
Z_PRIVATE LFuncInfo *__lfunc_info_create(const char *name, LCFGInfo cfg_info,
                                         LRAInfo ra_info);

/*
 * Destroy a LFuncInfo
 */
Z_PRIVATE void __lfunc_info_destroy(LFuncInfo *info);

/*
 * Load data into database
 */
Z_PRIVATE void __libfunc_load(GHashTable *d);

Z_PRIVATE LFuncInfo *__lfunc_info_create(const char *name, LCFGInfo cfg_info,
                                         LRAInfo ra_info) {
    LFuncInfo *rv = z_alloc(1, sizeof(LFuncInfo));
    rv->name = z_strdup(name);
    rv->cfg_info = cfg_info;
    rv->ra_info = ra_info;
    return rv;
}

Z_PRIVATE void __lfunc_info_destroy(LFuncInfo *info) {
    z_free((void *)info->name);
    z_free(info);
}

// XXX: the file must be included here.
#include "library_functions_load.c"

GHashTable *lf_info = NULL;

Z_API void z_libfunc_init() {
    if (lf_info) {
        return;
    }

    lf_info =
        g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)&z_free,
                              (GDestroyNotify)&__lfunc_info_destroy);

    __libfunc_load(lf_info);
}

Z_API void z_libfunc_fini() {
    if (lf_info) {
        g_hash_table_destroy(lf_info);
        lf_info = NULL;
    }
}

Z_API const LFuncInfo *z_libfunc_get_info(const char *name) {
    if (!lf_info) {
        z_libfunc_init();
    }

    LFuncInfo *rv = (LFuncInfo *)g_hash_table_lookup(lf_info, (gpointer)name);
    if (!rv) {
        rv = __lfunc_info_create(name, LCFG_UNK, LRA_UNK);
        g_hash_table_insert(lf_info, (gpointer)z_strdup(name), (gpointer)rv);
    }

    return rv;
}

const LFuncInfo default_func_info = {
    .name = NULL,
    .cfg_info = LCFG_UNK,
    .ra_info = LRA_UNK,
};

Z_API const LFuncInfo *z_libfunc_default() { return &default_func_info; }
