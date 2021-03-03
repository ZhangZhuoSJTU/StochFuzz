#ifndef __TRAMPOLINE_H
#define __TRAMPOLINE_H

#include <stdbool.h>
#include <stdint.h>

#include "buffer.h"
#include "utils.h"

#define IS_PATCHED(t) (t->offset != SIZE_MAX)
#define IS_CREATED(t) (t->is_created)

/*
 * Trampoline
 */
typedef struct trampoline_t {
    addr_t vaddr;     // Virtual address of trampoline
    bool is_created;  // This trumpoline is created by ZeroPatch?
    size_t offset;    // Current offset in patched binary,
                      //   MAX size_t if not patched
    Buffer *buf;      // Buffer for trampoline
    int prot;         // Prot for mmap
} Trampoline;

/*
 * Setter and Getter
 */
DECLARE_SETTER(Trampoline, trampoline, size_t, offset);
DECLARE_GETTER(Trampoline, trampoline, size_t, offset);
DECLARE_GETTER(Trampoline, trampoline, addr_t, vaddr);
DECLARE_GETTER(Trampoline, trampoline, bool, is_created);
DECLARE_GETTER(Trampoline, trampoline, Buffer *, buf);
DECLARE_GETTER(Trampoline, trampoline, int, prot);
DECLARE_GETTER(Trampoline, trampoline, size_t, size);

/*
 * Create a trampoline based on given information.
 * If buf is NULL, return an empty trampline. Note that buf will not be reversed
 * by created trampoline.
 */
Z_API Trampoline *z_trampoline_create(addr_t vaddr, bool is_created,
                                      Buffer *buf, int prot);

/*
 * Destructor of trampoline.
 */
Z_API void z_trampoline_destroy(Trampoline *t);

/*
 * Create a shadow text for given trampoline.
 */
Z_API Trampoline *z_trampoline_create_shadow(Trampoline *t);

#endif
