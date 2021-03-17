#include "diagnoser.h"
#include "utils.h"

Z_API Diagnoser *z_diagnoser_create(Patcher *p, Rewriter *r) {
    Diagnoser *g = STRUCT_ALLOC(Diagnoser);

    g->patcher = p;
    g->rewriter = r;

    return g;
}

Z_API void z_diagnoser_destroy(Diagnoser *g) { z_free(g); }
