#ifndef __RESTRICTED_PTR_H
#define __RESTRICTED_PTR_H

#include "config.h"

#define __IS_RPTR(x) _Generic((x), Rptr * : true, default : false)

#define z_rptr_get_ptr(rptr, type) \
    ((type *)z_rptr_safe_raw_ptr(rptr, sizeof(type)))

#define z_rptr_is_null(rptr) \
    ((rptr == NULL) || (rptr->raw_ptr == NULL) || (rptr->size == 0))

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

STRUCT(Rptr, {
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
Z_API Rptr *z_rptr_create(uint8_t *raw_ptr, size_t size);

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
