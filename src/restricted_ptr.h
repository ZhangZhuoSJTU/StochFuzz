/*
 * restricted_ptr.h
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

#ifndef __RESTRICTED_PTR_H
#define __RESTRICTED_PTR_H

#include "config.h"

#define __IS_RPTR(x) _Generic((x), Rptr * : true, default : false)

#define z_rptr_get_ptr(rptr, type) \
    ((type *)z_rptr_safe_raw_ptr(rptr, sizeof(type)))

#define z_rptr_is_null(rptr) \
    (((rptr) == NULL) || ((rptr)->raw_ptr == NULL) || ((rptr)->size == 0))

#define z_rptr_inc(rptr, type, n)                             \
    do {                                                      \
        if ((rptr)->size < (n) * sizeof(type)) {              \
            EXITME("restricted pointer's size is too small"); \
        }                                                     \
        (rptr)->raw_ptr += (n) * sizeof(type);                \
        (rptr)->size -= (n) * sizeof(type);                   \
    } while (0)

#define z_rptr_memset(s, c, n)                                \
    do {                                                      \
        if ((s)->size < n) {                                  \
            EXITME("restricted pointer's size is too small"); \
        }                                                     \
        memset((s)->raw_ptr, c, n);                           \
    } while (0)

#define z_rptr_memcpy(dst, src, n)                                  \
    do {                                                            \
        if (__IS_RPTR(dst)) {                                       \
            z_rptr_memcpy_to((Rptr *)(dst), (uint8_t *)(src), n);   \
        } else {                                                    \
            z_rptr_memcpy_from((Rptr *)(src), (uint8_t *)(dst), n); \
        }                                                           \
    } while (0)

#define z_rptr_reset(rptr)                                  \
    do {                                                    \
        (rptr)->size += (rptr)->raw_ptr - (rptr)->base_ptr; \
        (rptr)->raw_ptr = (rptr)->base_ptr;                 \
    } while (0)

STRUCT(Rptr, {
    uint8_t *base_ptr;
    uint8_t *raw_ptr;
    size_t size;
});

/*
 * Setter and Getter
 */
DECLARE_GETTER(Rptr, rptr, size_t, size);

/*
 * Create a restricted pointer.
 */
Z_API Rptr *z_rptr_create(uint8_t *base_ptr, size_t size);

/*
 * Destroy a restricted pointer.
 */
Z_API void z_rptr_destroy(Rptr *rptr);

/*
 * Safely return a raw ptr
 */
Z_API void *z_rptr_safe_raw_ptr(Rptr *rptr, size_t n);

/*
 * memcpy to Rptr
 */
Z_API void z_rptr_memcpy_to(Rptr *rptr, uint8_t *src, size_t size);

/*
 * memcpy from Rptr
 */
Z_API void z_rptr_memcpy_from(Rptr *rptr, uint8_t *dst, size_t size);

/*
 * Truncate a Pptr to n
 */
Z_API void z_rptr_truncate(Rptr *rptr, size_t n);

#endif
