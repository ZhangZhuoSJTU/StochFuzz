/*
 * restricted_ptr.c
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

#include "restricted_ptr.h"
#include "utils.h"

/*
 * Setter and Getter
 */
DEFINE_GETTER(Rptr, rptr, size_t, size);

Z_PRIVATE void __rptr_check_null(Rptr *rptr) {
    if (z_rptr_is_null(rptr)) {
        EXITME("rptr is NULL");
    }
}

Z_API Rptr *z_rptr_create(uint8_t *base_ptr, size_t size) {
    Rptr *rptr = STRUCT_ALLOC(Rptr);
    rptr->base_ptr = base_ptr;
    rptr->raw_ptr = base_ptr;
    rptr->size = size;
    return rptr;
}

Z_API void z_rptr_destroy(Rptr *rptr) { z_free(rptr); }

Z_API void *z_rptr_safe_raw_ptr(Rptr *rptr, size_t n) {
    __rptr_check_null(rptr);
    if (rptr->size < n) {
        EXITME("restricted pointer's size is smaller than memcpy size");
    }
    return rptr->raw_ptr;
}

Z_API void z_rptr_memcpy_to(Rptr *rptr, uint8_t *src, size_t size) {
    __rptr_check_null(rptr);
    if (rptr->size < size) {
        EXITME("restricted pointer's size is smaller than memcpy size");
    }
    memcpy(rptr->raw_ptr, src, size);
}

Z_API void z_rptr_memcpy_from(Rptr *rptr, uint8_t *dst, size_t size) {
    __rptr_check_null(rptr);
    if (rptr->size < size) {
        EXITME("restricted pointer's size is smaller than memcpy size");
    }
    memcpy(dst, rptr->raw_ptr, size);
}

Z_API void z_rptr_truncate(Rptr *rptr, size_t n) {
    __rptr_check_null(rptr);
    if (n > rptr->size) {
        EXITME("truncate pointer to a bigger size");
    }
    rptr->size = n;
}
