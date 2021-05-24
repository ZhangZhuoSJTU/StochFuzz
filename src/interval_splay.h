/*
 * interval_splay.h
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

#ifndef __INTERVAL_SPLAY_H
#define __INTERVAL_SPLAY_H

#include "buffer.h"
#include "config.h"

/*
 * Use SPLAY tree to support interval operations
 */

#define SPLAY_LEFT 0
#define SPLAY_RIGHT 1
#define SPLAY_NUM_CHILDREN 2

STRUCT(Snode, {
    // We'll make this an array so that we can make some operations symmetric.
    STRUCT_REALNAME(Snode) * child[SPLAY_NUM_CHILDREN];
    // Key for splay
    addr_t addr;
    // Length of interval
    size_t len;
    // Data, NULL if not existing
    void *data;
    // Function used to free data
    void (*data_destroy)(void *);
});

STRUCT(Splay, {
    Snode *root;
    size_t node_count;
    void *(*merge_fcn)(void *, void *);
});

#define SPLAY_EMPTY NULL
#define SPLAY_ROOT(splay, node) \
    do {                        \
        assert(splay != NULL);  \
        node = splay->root;     \
    } while (0)

/*
 * Setter and Getter
 */
DECLARE_SETTER(Snode, snode, addr_t, addr);
DECLARE_SETTER(Snode, snode, size_t, len);
DECLARE_SETTER(Snode, snode, void *, data);

DECLARE_GETTER(Snode, snode, addr_t, lower_bound);
DECLARE_GETTER(Snode, snode, addr_t, upper_bound);
DECLARE_GETTER(Snode, snode, size_t, len);
DECLARE_GETTER(Snode, snode, void *, data);
DECLARE_GETTER(Splay, splay, size_t, node_count);

/*
 * Pack a Snode from scratch.
 */
Z_API Snode *z_snode_create(addr_t addr, size_t len, void *data,
                            void (*data_destroy)(void *));

/*
 * Unpack a Snode and its data.
 */
Z_API void z_snode_destroy(Snode *node);

/*
 * Create a splay.
 *
 * merge_fcn is used to merge data, and **NULL indicates the intervals will
 * not merge**.
 *
 * Note that is Snode's responsibility to free the alloced memory, instead of
 * merge_fcn.
 */
Z_API Splay *z_splay_create(void *(*merge_fcn)(void *, void *));

/*
 * Free all elements of splay, and replace it with SPLAY_EMPTY.
 */
Z_API void z_splay_destroy(Splay *splay);

/*
 * Insert an element into splay, and return the inserted node, NULL if
 * overlaping.
 */
Z_API Snode *z_splay_insert(Splay *splay, Snode *node);

/*
 * Delete Snode starting from addr from splay.
 * Return the delted node, NULL if the addr does not exist.
 */
Z_API Snode *z_splay_delete(Splay *splay, addr_t addr);

/*
 * Check whether node is overlapped with some nodes inside splay.
 * Return true if overlap, false otherwise.
 */
Z_API bool z_splay_interval_overlap(Splay *splay, Snode *node);

/*
 * Search a snode containint addr, return NULL if not exist.
 */
Z_API Snode *z_splay_search(Splay *splay, addr_t addr);

/*
 * Return the Snode with max address.
 */
Z_API inline Snode *z_splay_max(Splay *splay);

/*
 * Return the Snode with min address.
 */
Z_API inline Snode *z_splay_min(Splay *splay);

/*
 * Return a list of Snode * in order.
 */
Z_API Buffer *z_splay_sorted_list(Splay *splay);

/*
 * Pretty-print the contents of splay
 */
Z_API void z_splay_print(Splay *splay);

/*
 * Default merging function: do nothing;
 */
Z_API void *z_direct_merge(void *_x, void *_y);

#endif
