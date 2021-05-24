/*
 * iterator.h
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

#ifndef __ITERATOR_H
#define __ITERATOR_H

#include "buffer.h"
#include "config.h"

// force evaluation
#define __ITERATOR_2(x, y) __Iter_##y##_##x##_t
#define __ITERATOR_1(x, y) __ITERATOR_2(x, y)
#define __ITERATOR(x) __ITERATOR_1(x, __COUNTER__)

/*
 * Iterator, only for local usage
 */
#define Iter(type, name)      \
    struct __ITERATOR(name) { \
        type *__ptr;          \
        size_t __i;           \
        size_t __n;           \
    } name

#define z_iter_init(iter, ptr, n)                      \
    do {                                               \
        if (!ptr) {                                    \
            EXITME("try to init an invalid iterator"); \
        }                                              \
        (iter).__ptr = (typeof((iter).__ptr))(ptr);    \
        (iter).__i = 0;                                \
        (iter).__n = (n);                              \
    } while (0)

#define z_iter_init_from_buf(iter, buf)                                \
    do {                                                               \
        assert(buf);                                                   \
        z_iter_init((iter), z_buffer_get_raw_buf(buf),                 \
                    z_buffer_get_size(buf) / sizeof(*((iter).__ptr))); \
    } while (0)

#define z_iter_next(iter)                      \
    ({                                         \
        typeof((iter).__ptr) __res = NULL;     \
                                               \
        if ((iter).__i < (iter).__n) {         \
            __res = (iter).__ptr + (iter).__i; \
            (iter).__i++;                      \
        }                                      \
                                               \
        __res;                                 \
    })

#define z_iter_is_empty(iter) ((iter).__i >= (iter).__n)

#define z_iter_get_size(iter) ((iter).__n)

#define z_iter_reset(iter) \
    do {                   \
        (iter).__i = 0;    \
    } while (0)

#define z_iter_destroy(iter) /* empty */

#endif
