#ifndef __DIAGNOSER_H
#define __DIAGNOSER_H

#include "config.h"
#include "patcher.h"
#include "rewriter.h"

/*
 * Diagnoser distinguishes the intentional crashes and the unintentional ones,
 * while it also manages the schedule of self-recovering.
 */
STRUCT(Diagnoser, {
    Patcher *patcher;
    Rewriter *rewriter;
});

/*
 * Create diagnoser
 */
Z_API Diagnoser *z_diagnoser_create(Patcher *p, Rewriter *r);

/*
 * Destroy diagnoser
 */
Z_API void z_diagnoser_destroy(Diagnoser *g);

#endif
