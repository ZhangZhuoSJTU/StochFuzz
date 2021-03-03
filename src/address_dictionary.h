#ifndef __ADDRESS_DICTIONARY_H
#define __ADDRESS_DICTIONARY_H

#include "config.h"
#include "utils.h"

// force evaluation
#define __ADDR_DICT_NAME_2(x, y) __AddrDict_##y##_##x##_t
#define __ADDR_DICT_NAME_1(x, y) __ADDR_DICT_NAME_2(x, y)
#define __ADDR_DICT_NAME(x) __ADDR_DICT_NAME_1(x, __COUNTER__)

/*
 * Address dictionary uses a contiguous memory to store data, and uses key as
 * index to access. Compared with GHashTable, it is a much more efficient
 * approach to build a hash table who uses address as key and is likely to use
 * all addresses.
 *
 * Note that we use macro to simulate template in C++.
 */
#define AddrDict(type, name)        \
    struct __ADDR_DICT_NAME(name) { \
        type *__data;               \
        uint64_t *__used;           \
        addr_t __base;              \
        size_t __size;              \
    } name

/*
 * AddrDict without checking existence.
 * It is very helpful for hash tables whose value cannot be zero.
 */
#define AddrDictFast(type, name)    \
    struct __ADDR_DICT_NAME(name) { \
        type *__data;               \
        PhantomType *__used;        \
        addr_t __base;              \
        size_t __size;              \
    } name

#define z_addr_dict_init(dict, base_addr, size)                                \
    do {                                                                       \
        (dict).__base = (base_addr);                                           \
        (dict).__size = (size);                                                \
        (dict).__data = z_alloc((dict).__size, sizeof(*((dict).__data)));      \
        if (_Generic(((dict).__used), PhantomType *                            \
                     : false, default                                          \
                     : true)) {                                                \
            (dict).__used = z_alloc((dict).__size / 64 + 1, sizeof(uint64_t)); \
        } else {                                                               \
            (dict).__used = NULL;                                              \
        }                                                                      \
    } while (0)

#define z_addr_dict_check_addr(dict, addr)                         \
    do {                                                           \
        if ((addr) < (dict).__base ||                              \
            (addr) >= (dict).__base + (dict).__size) {             \
            EXITME("out-of-boundry access in address dictionary"); \
        }                                                          \
    } while (0)

#define z_addr_dict_exist(dict, addr)                         \
    ({                                                        \
        bool res;                                             \
        z_addr_dict_check_addr(dict, addr);                   \
                                                              \
        size_t __off = (addr) - (dict).__base;                \
                                                              \
        if (_Generic(((dict).__used), PhantomType *           \
                     : false, default                         \
                     : true)) {                               \
            size_t __off_div = __off / 64;                    \
            size_t __off_mod = __off % 64;                    \
            uint64_t *__bits = (uint64_t *)((dict).__used);   \
            res = !!(__bits[__off_div] & (1UL << __off_mod)); \
        } else {                                              \
            res = !!((dict).__data[__off]);                   \
        }                                                     \
                                                              \
        res;                                                  \
    })

#define z_addr_dict_set(dict, addr, val)                    \
    do {                                                    \
        z_addr_dict_check_addr(dict, addr);                 \
                                                            \
        size_t __off = (addr) - (dict).__base;              \
        (dict).__data[__off] = (val);                       \
                                                            \
        if ((dict).__used) {                                \
            size_t __off_div = __off / 64;                  \
            size_t __off_mod = __off % 64;                  \
            uint64_t *__bits = (uint64_t *)((dict).__used); \
            __bits[__off_div] |= (1UL << __off_mod);        \
        }                                                   \
    } while (0)

#define z_addr_dict_get(dict, addr)                               \
    ({                                                            \
        z_addr_dict_check_addr(dict, addr);                       \
        if (!z_addr_dict_exist(dict, addr)) {                     \
            EXITME("uninitialized access in address dictionary"); \
        }                                                         \
        (dict).__data[(addr) - (dict).__base];                    \
    })

#define z_addr_dict_get_data(dict) ((dict).__data)
#define z_addr_dict_get_base(dict) ((dict).__base)
#define z_addr_dict_get_size(dict) ((dict).__size)

#define z_addr_dict_remove(dict, addr)                      \
    do {                                                    \
        z_addr_dict_check_addr(dict, addr);                 \
        size_t __off = (addr) - (dict).__base;              \
        (dict).__data[__off] = 0;                           \
                                                            \
        if ((dict).__used) {                                \
            size_t __off_div = __off / 64;                  \
            size_t __off_mod = __off % 64;                  \
            uint64_t *__bits = (uint64_t *)((dict).__used); \
            __bits[__off_div] &= (~(1UL << __off_mod));     \
        }                                                   \
    } while (0)

/*
 * z_addr_dist_destroy should support variable numbers of arguments
 */
#define __addr_dict_destroy_opt_0(...)
#define __addr_dict_destroy_opt_1(...)
#define __addr_dict_destroy_opt_2(dict, func)              \
    do {                                                   \
        for (size_t __i = 0; __i < (dict).__size; __i++) { \
            addr_t __addr = (dict).__base + __i;           \
            if (z_addr_dict_exist(dict, __addr)) {         \
                (*(func))((dict).__data[__i]);             \
            }                                              \
        }                                                  \
    } while (0)

#define __addr_dict_destroy_choose(a, b, c, f, ...) f

#define __addr_dict_destroy_data(...)                                  \
    __addr_dict_destroy_choose(, ##__VA_ARGS__,                        \
                               __addr_dict_destroy_opt_2(__VA_ARGS__), \
                               __addr_dict_destroy_opt_1(__VA_ARGS__), \
                               __addr_dict_destroy_opt_0(__VA_ARGS__))

#define __addr_dict_destroy_self(dict, ...) \
    do {                                    \
        z_free((dict).__data);              \
        z_free((dict).__used);              \
    } while (0)

#define z_addr_dict_destroy(...)               \
    do {                                       \
        __addr_dict_destroy_data(__VA_ARGS__); \
        __addr_dict_destroy_self(__VA_ARGS__); \
    } while (0)

#endif
