#include "interval_splay.h"
#include "utils.h"

/*
 * Print contents of a tree, indented by depth.
 */
Z_PRIVATE void __splay_print_indented(Snode *root, int depth);

/*
 * Rotate child in given direction to root
 */
Z_PRIVATE void __splay_rotate(Snode **root, int direction);

/*
 * Link operations for top-down splay
 *
 * This pastes a node in as !d-most node in subtree on side d
 */
Z_PRIVATE void __splay_link(Snode ***hook, int d, Snode *node);

/*
 * Splay last element on path to target to root
 *
 * NOTE! Remember to link parent with splay-ed subtree
 */
Z_PRIVATE Snode *__splay(Snode **root, addr_t target);

/*
 * Return a list of Snode * in order, based on root.
 */
Z_PRIVATE Buffer *__splay_sorted_list(Snode *root);

/*
 * Setter and Getter
 */
DEFINE_SETTER(Snode, snode, addr_t, addr);
DEFINE_SETTER(Snode, snode, size_t, len);
DEFINE_SETTER(Snode, snode, void *, data);

DEFINE_GETTER(Snode, snode, size_t, len);
DEFINE_GETTER(Snode, snode, void *, data);
DEFINE_GETTER(Splay, splay, size_t, node_count);

/*
 * Overloaded Setter and Getter
 */
OVERLOAD_GETTER(Snode, snode, addr_t, lower_bound) { return snode->addr; }

OVERLOAD_GETTER(Snode, snode, addr_t, upper_bound) {
    return snode->addr + snode->len - 1;
}

/*
 * How far to indent each level of the tree.
 */
#define SPLAY_INDENTATION_LEVEL 2

Z_PRIVATE void __splay_print_indented(Snode *root, int depth) {
    int i;

    if (root != SPLAY_EMPTY) {
        __splay_print_indented(root->child[SPLAY_LEFT], depth + 1);

        for (i = 0; i < SPLAY_INDENTATION_LEVEL * depth; i++) {
            putchar(' ');
        }
        z_sayf("[%ld, %ld](%p)\n", root->addr, root->addr + root->len - 1,
               root->data);

        __splay_print_indented(root->child[SPLAY_RIGHT], depth + 1);
    }
}

Z_PRIVATE void __splay_rotate(Snode **root, int direction) {
    Snode *x;
    Snode *y;
    Snode *b;

    /*
     *      y           x
     *     / \         / \
     *    x   C  <=>  A   y
     *   / \             / \
     *  A   B           B   C
     */

    y = *root;
    assert(y);
    x = y->child[direction];
    assert(x);
    b = x->child[!direction];

    /* do the rotation */
    *root = x;
    x->child[!direction] = y;
    y->child[direction] = b;
}

Z_PRIVATE void __splay_link(Snode ***hook, int d, Snode *node) {
    *hook[d] = node;
    // Strictly speaking we don't need to do this, but it allows printing the
    // partial trees.
    node->child[!d] = NULL;
    hook[d] = &node->child[!d];
}

Z_PRIVATE Snode *__splay(Snode **root, addr_t target) {
    Snode *t;
    Snode *child;
    Snode *grandchild;
    Snode *top[SPLAY_NUM_CHILDREN];   /* accumulator trees that will become
                                              subtrees of new root */
    Snode **hook[SPLAY_NUM_CHILDREN]; /* where to link new elements into
                                              accumulator trees */
    int d;
    int dChild;      /* direction of child */
    int dGrandchild; /* direction of grandchild */

    // we don't need to keep following this pointer, we'll just fix it at the
    // end.
    assert(root != NULL);
    t = *root;

    // Don't do anything to an empty tree.
    if (t == SPLAY_EMPTY) {
        return NULL;
    }

    // Ok, tree is not empty, start chopping it up.
    for (d = 0; d < SPLAY_NUM_CHILDREN; d++) {
        top[d] = NULL;
        hook[d] = &top[d];
    }

    // Keep going until we hit the addr or we would hit a null pointer in the
    // child.
    while (t->addr != target &&
           (child = t->child[dChild = t->addr < target]) != NULL) {
        // Child is not null.
        grandchild = child->child[dGrandchild = child->addr < target];

        if (grandchild == NULL || child->addr == target) {
            /* zig case; paste root into opposite-side hook */
            __splay_link(hook, !dChild, t);
            t = child;
            /* we can break because we know we will hit child == NULL next */
            break;
        } else if (dChild == dGrandchild) {
            /* zig-zig case */
            /* rotate and then hook up child */
            /* grandChild becomes new root */
            __splay_rotate(&t, dChild);
            __splay_link(hook, !dChild, child);
            t = grandchild;
        } else {
            /* zig-zag case */
            /* root goes to !dChild, child goes to dChild, grandchild goes to
             * root */
            __splay_link(hook, !dChild, t);
            __splay_link(hook, dChild, child);
            t = grandchild;
        }
    }

    // Now reassemble the tree.
    // t's children go in hooks, top nodes become t's new children.
    for (d = 0; d < SPLAY_NUM_CHILDREN; d++) {
        *hook[d] = t->child[d];
        t->child[d] = top[d];
    }

    // And put t back in *root.
    return (*root = t);
}

Z_PRIVATE Buffer *__splay_sorted_list(Snode *root) {
    Buffer *list = NULL;

    assert(root != NULL);
    if (root->child[SPLAY_LEFT] != NULL)
        list = __splay_sorted_list(root->child[SPLAY_LEFT]);
    else
        list = z_buffer_create(NULL, 0);

    z_buffer_append_raw(list, (const uint8_t *)&root, sizeof(Snode *));

    if (root->child[SPLAY_RIGHT] != NULL) {
        Buffer *rlist = __splay_sorted_list(root->child[SPLAY_RIGHT]);
        z_buffer_append(list, rlist);
        z_buffer_destroy(rlist);
    }

    return list;
}

Z_API Snode *z_snode_create(addr_t addr, size_t len, void *data,
                            void (*data_destroy)(void *)) {
    assert(len > 0);
    Snode *e = STRUCT_ALLOC(Snode);
    e->addr = addr;
    e->len = len;
    e->data = data;
    e->data_destroy = data_destroy;
    return e;
}

Z_API void z_snode_destroy(Snode *node) {
    if (node != NULL) {
        if (node->data_destroy)
            (*(node->data_destroy))(node->data);
        z_free(node);
    } else {
        z_trace("try to delete a NULL node");
    }
}

Z_API Splay *z_splay_create(void *(*merge_fcn)(void *, void *)) {
    Splay *t = STRUCT_ALLOC(Splay);
    t->root = SPLAY_EMPTY;
    t->node_count = 0;
    t->merge_fcn = merge_fcn;
    return t;
}

Z_API void z_splay_destroy(Splay *splay) {
    // We want to avoid doing this recursively, because the tree might be deep.
    // So we will repeatedly delete the root until the tree is empty.
    while (splay->root) {
        Snode *e = z_splay_delete(splay, splay->root->addr);
        z_snode_destroy(e);
    }
    assert(splay->node_count == 0);
    z_free(splay);
}

Z_API bool z_splay_interval_overlap(Splay *splay, Snode *node) {
    Snode *t = NULL;

    __splay(&(splay->root), node->addr);
    SPLAY_ROOT(splay, t);

    // If splay is empty, return false
    if (t == SPLAY_EMPTY)
        return false;

    // If addr already exists, return true;
    if (t->addr == node->addr)
        return true;

    if (t->addr < node->addr) {
        Snode *e = t->child[SPLAY_RIGHT];
        if (t->addr + t->len > node->addr)
            return true;
        if (e != NULL) {
            // Try to find the smallest node in the right tree
            t->child[SPLAY_RIGHT] = __splay(&e, 0);
            if (node->addr + node->len > e->addr)
                return true;
        }
    } else {
        Snode *e = t->child[SPLAY_LEFT];
        if (node->addr + node->len > t->addr)
            return true;
        if (e != NULL) {
            // Try to find the biggest node in the left tree
            t->child[SPLAY_LEFT] = __splay(&e, ADDR_MAX);
            if (e->addr + e->len > node->addr)
                return true;
        }
    }

    return false;
}

Z_API Snode *z_splay_insert(Splay *splay, Snode *node) {
    Snode *e;
    Snode *t;
    int d;  // Which side of e to put old root on

    if (z_splay_interval_overlap(splay, node)) {
        // Overlap
        z_trace("node([%ld, %ld]) is overlapped with existed nodes", node->addr,
                node->addr + node->len - 1);
        return NULL;
    }

    __splay(&(splay->root), node->addr);
    SPLAY_ROOT(splay, t);

    e = node;

    if (t == NULL) {
        e->child[SPLAY_LEFT] = e->child[SPLAY_RIGHT] = NULL;
    } else {
        // Split tree and put e on top.
        // We know t is closest to e, so we don't have to move anything else.
        d = t->addr > e->addr;
        e->child[d] = t;
        e->child[!d] = t->child[!d];
        t->child[!d] = NULL;
    }

    // Either way we stuff e in *splay.
    splay->root = e;
    splay->node_count += 1;

    // Check merge.
    if (splay->merge_fcn) {
        Snode *left = e->child[SPLAY_LEFT];
        Snode *right = e->child[SPLAY_RIGHT];
        if (left != NULL)
            e->child[SPLAY_LEFT] = __splay(&left, ADDR_MAX);
        if (right != NULL)
            e->child[SPLAY_RIGHT] = __splay(&right, 0);

        if ((left != NULL) && (left->addr + left->len == e->addr)) {
            Snode *deleted = z_splay_delete(splay, left->addr);
            assert(deleted == left);
            e->addr = left->addr;
            e->len += left->len;
            e->data = (*(splay->merge_fcn))(left->data, e->data);
            z_snode_destroy(deleted);
        }

        if ((right != NULL) && (e->addr + e->len == right->addr)) {
            Snode *deleted = z_splay_delete(splay, right->addr);
            assert(deleted == right);
            e->len += right->len;
            e->data = (*(splay->merge_fcn))(e->data, right->data);
            z_snode_destroy(deleted);
        }
    }

    return e;
}

Z_API Snode *z_splay_delete(Splay *splay, addr_t addr) {
    Snode *left;
    Snode *right;
    Snode *deleted = NULL;

    __splay(&(splay->root), addr);

    if (splay->root && splay->root->addr == addr) {
        // Save pointers to kids.
        left = splay->root->child[SPLAY_LEFT];
        right = splay->root->child[SPLAY_RIGHT];

        deleted = splay->root;
        splay->node_count -= 1;
        assert(splay->node_count >= 0);

        // If left is empty, just return right.
        if (left == NULL) {
            splay->root = right;
        } else {
            // First splay max element in left to top.
            __splay(&left, ADDR_MAX);

            // Now paste in right subtree.
            left->child[SPLAY_RIGHT] = right;

            // Return left
            splay->root = left;
        }
    } else {
        z_trace("node([%ld, ?]) does not exist", addr);
    }

    return deleted;
}

Z_API Snode *z_splay_search(Splay *splay, addr_t addr) {
    assert(splay != NULL);
    Snode *t;

    if (splay->root == NULL)
        return NULL;

    __splay(&(splay->root), addr);

    SPLAY_ROOT(splay, t);
    if (t->addr <= addr) {
        if (z_snode_get_upper_bound(t) >= addr)
            return t;
        else
            return NULL;
    } else {
        if (t->child[SPLAY_LEFT]) {
            __splay(&(t->child[SPLAY_LEFT]), ADDR_MAX);
            if (z_snode_get_lower_bound(t->child[SPLAY_LEFT]) <= addr &&
                z_snode_get_upper_bound(t->child[SPLAY_LEFT]) >= addr)
                return t->child[SPLAY_LEFT];
            else
                return NULL;
        } else {
            return NULL;
        }
    }
}

Z_API inline Snode *z_splay_max(Splay *splay) {
    assert(splay != NULL);
    return __splay(&(splay->root), ADDR_MAX);
}

Z_API inline Snode *z_splay_min(Splay *splay) {
    assert(splay != NULL);
    return __splay(&(splay->root), 0);
}

Z_API Buffer *z_splay_sorted_list(Splay *splay) {
    if (splay->root)
        return __splay_sorted_list(splay->root);
    else
        return NULL;
}

Z_API void z_splay_print(Splay *splay) {
    Snode *t;
    SPLAY_ROOT(splay, t);
    z_sayf("number of current nodes: %ld\n", z_splay_get_node_count(splay));
    __splay_print_indented(t, 0);
}

Z_API void *z_direct_merge(void *_x, void *_y) { return NULL; }
