#include "stdbool.h"
#include "stdint.h"

#include "buffer.h"
#include "loader.h"
#include "trampoline.h"
#include "utils.h"

/*
 * Setter and Getter
 */
DEFINE_SETTER(Trampoline, trampoline, size_t, offset);
DEFINE_GETTER(Trampoline, trampoline, size_t, offset);
DEFINE_GETTER(Trampoline, trampoline, addr_t, vaddr);
DEFINE_GETTER(Trampoline, trampoline, bool, is_created);
DEFINE_GETTER(Trampoline, trampoline, Buffer *, buf);
DEFINE_GETTER(Trampoline, trampoline, int, prot);

/*
 * Overloaded Setter and Getter
 */
OVERLOAD_GETTER(Trampoline, trampoline, size_t, size) {
    assert(trampoline != NULL);
    return z_buffer_get_size(trampoline->buf);
}

Z_API Trampoline *z_trampoline_create(addr_t vaddr, bool is_created,
                                      Buffer *buf, int prot) {
    Trampoline *t = (Trampoline *)z_alloc(1, sizeof(Trampoline));
    t->vaddr = vaddr;
    t->offset = SIZE_MAX;
    t->is_created = is_created;
    if (buf != NULL) {
        t->buf = z_buffer_dup(buf);
    } else {
        t->buf = z_buffer_create(NULL, 0);
    }
    t->prot = prot;
    return t;
}

Z_API void z_trampoline_destroy(Trampoline *t) {
    assert(t != NULL);
    z_buffer_destroy(t->buf);
    z_free(t);
}

Z_API Trampoline *z_trampoline_create_shadow(Trampoline *t) {
    assert(t != NULL);
    assert((t->vaddr & SHADOW_OFFSET) == 0);

    Trampoline *t_s = (Trampoline *)z_alloc(1, sizeof(Trampoline));
    t_s->vaddr = (t->vaddr | SHADOW_OFFSET);
    t_s->offset = SIZE_MAX;
    t_s->is_created = true;
    t_s->buf = z_buffer_dup(t->buf);
    t_s->prot = t->prot;

    z_info("create shadow segment at %#lx", t_s->vaddr);

    return t_s;
}
