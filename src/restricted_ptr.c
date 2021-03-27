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

Z_API Rptr *z_rptr_create(uint8_t *raw_ptr, size_t size) {
    Rptr *rptr = STRUCT_ALLOC(Rptr);
    rptr->raw_ptr = raw_ptr;
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
