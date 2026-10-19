/*
 * Copyright (c) 2026 Fastly, Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <stdlib.h>
#include "picotls.h"
#include "quicly/bplus_ranges.h"

#define FANOUT QUICLY_BPLUS_RANGES_FANOUT
/**
 * minimum number of entries in a node other than the root
 */
#define MIN_ENTRIES (FANOUT / 2)
/**
 * Bounds the descent path kept on the stack. As non-root nodes hold at least MIN_ENTRIES entries, a tree of this height holds more
 * than 2 * 8^11 ranges; `add` returns QUICLY_ERROR_STATE_EXHAUSTION instead of growing beyond it.
 */
#define MAX_HEIGHT 12
/**
 * The number of ranges is capped so that the receive window can be maintained even in the worst case, where every one of the two
 * packets being sent are lost and each packet carries >= ~512 bytes of the stream (see https://github.com/h2o/quicly/issues/278).
 * The cap is at least MIN_MAX_RANGES so that streams with small windows carrying small frames can tolerate some loss.
 */
#define BYTES_PER_RANGE 1024
#define MIN_MAX_RANGES 63

struct st_quicly_bplus_ranges_path_t {
    quicly_bplus_ranges_node_t *nodes[MAX_HEIGHT];
    /**
     * index of the child being chosen in `nodes[level]`, for non-leaf levels
     */
    size_t slots[MAX_HEIGHT];
};

#define EMPTY_RANGE ((quicly_range_t){UINT64_MAX, UINT64_MAX})

static void init_leaf(quicly_bplus_ranges_node_t *node)
{
    for (size_t i = 0; i < FANOUT; ++i)
        node->ranges[i] = EMPTY_RANGE;
}

/**
 * returns the number of ranges in the leaf whose start is <= x
 */
static size_t leaf_count_le(const quicly_bplus_ranges_node_t *leaf, uint64_t x)
{
    size_t n = 0;
    for (size_t i = 0; i < FANOUT; ++i)
        n += leaf->ranges[i].start <= x;
    return n;
}

/**
 * returns the number of keys in the non-leaf node that are <= x, which is the index of the child to descend into
 */
static size_t keys_count_le(const quicly_bplus_ranges_node_t *node, uint64_t x)
{
    size_t n = 0;
    for (size_t i = 0; i < FANOUT - 1; ++i)
        n += node->keys[i] <= x;
    return n;
}

/**
 * Returns if the node has an entry at given index; as entries are packed, this tells if the node has more than `index` entries. For
 * non-leaf nodes, the entry is the child, which exists if the key preceding it is in use; `index` must therefore be non-zero.
 */
static int has_entry(const quicly_bplus_ranges_node_t *node, int is_leaf, size_t index)
{
    return is_leaf ? node->ranges[index].start != UINT64_MAX : node->keys[index - 1] != UINT64_MAX;
}

/**
 * Moves the entries of an array from `src` to `dst`, where `end` is the end of the array. When moving up, the entries that would go
 * beyond `end` are dropped; when moving down, the slots being vacated at the end are filled by the sentinel. Children have no
 * sentinel, as their presence is determined by the keys.
 */
static void move_ranges(quicly_range_t *dst, quicly_range_t *end, quicly_range_t *src)
{
    if (dst < src) {
        while (src < end)
            *dst++ = *src++;
        while (dst < end)
            *dst++ = EMPTY_RANGE;
    } else {
        for (size_t i = end - dst; i-- != 0;)
            dst[i] = src[i];
    }
}

static void move_keys(uint64_t *dst, uint64_t *end, uint64_t *src)
{
    if (dst < src) {
        while (src < end)
            *dst++ = *src++;
        while (dst < end)
            *dst++ = UINT64_MAX;
    } else {
        for (size_t i = end - dst; i-- != 0;)
            dst[i] = src[i];
    }
}

static void move_children(quicly_bplus_ranges_node_t **dst, quicly_bplus_ranges_node_t **end, quicly_bplus_ranges_node_t **src)
{
    if (dst < src) {
        while (src < end)
            *dst++ = *src++;
    } else {
        for (size_t i = end - dst; i-- != 0;)
            dst[i] = src[i];
    }
}

/**
 * returns if `ranges->last` points into the given leaf; `ranges->last` must be non-NULL
 */
static int holds_last(quicly_bplus_ranges_t *ranges, quicly_bplus_ranges_node_t *leaf)
{
    return (uintptr_t)ranges->last - (uintptr_t)leaf->ranges < sizeof(leaf->ranges);
}

static size_t calc_max_ranges(quicly_bplus_ranges_t *ranges, uint64_t max_committed)
{
    uint64_t first_end = ranges->num_ranges != 0 ? ranges->first.ranges[0].end : 0;
    assert(first_end <= max_committed);
    uint64_t max_ranges = (max_committed - first_end) / BYTES_PER_RANGE + 1;
    return max_ranges < MIN_MAX_RANGES ? MIN_MAX_RANGES : max_ranges;
}

/**
 * Descends to the leaf that contains the last range whose start is <= x. Returns the number of ranges in that leaf whose start is
 * <= x; zero is returned only when no such range exists, in which case the leaf is the first leaf.
 */
static size_t descend(quicly_bplus_ranges_t *ranges, uint64_t x, struct st_quicly_bplus_ranges_path_t *path)
{
    quicly_bplus_ranges_node_t *node = ranges->root;

    for (size_t level = 0; level + 1 < ranges->height; ++level) {
        size_t slot = keys_count_le(node, x);
        path->nodes[level] = node;
        path->slots[level] = slot;
        node = node->children[slot];
    }
    path->nodes[ranges->height - 1] = node;

    return leaf_count_le(node, x);
}

/**
 * updates the separator that refers to the smallest start found under `path->nodes[level]`
 */
static void update_separator(struct st_quicly_bplus_ranges_path_t *path, size_t level, uint64_t new_min)
{
    while (level-- != 0) {
        if (path->slots[level] != 0) {
            path->nodes[level]->keys[path->slots[level] - 1] = new_min;
            return;
        }
    }
}

/**
 * Splits a full node by moving its high half to `high`, returning the key that separates the two.
 */
static uint64_t split_node(quicly_bplus_ranges_t *ranges, quicly_bplus_ranges_node_t *node, quicly_bplus_ranges_node_t *high,
                           int is_leaf)
{
    if (is_leaf) {
        for (size_t i = 0; i < MIN_ENTRIES; ++i) {
            high->ranges[i] = node->ranges[MIN_ENTRIES + i];
            high->ranges[MIN_ENTRIES + i] = EMPTY_RANGE;
            node->ranges[MIN_ENTRIES + i] = EMPTY_RANGE;
        }
        /* if the node holds `last`, it is the last entry of the node, which is in the high half */
        if (holds_last(ranges, node))
            ranges->last = high->ranges + (ranges->last - node->ranges - MIN_ENTRIES);
        return high->ranges[0].start;
    } else {
        uint64_t sep = node->keys[MIN_ENTRIES - 1];
        for (size_t i = 0; i < MIN_ENTRIES - 1; ++i) {
            high->keys[i] = node->keys[MIN_ENTRIES + i];
            high->keys[MIN_ENTRIES - 1 + i] = UINT64_MAX;
            node->keys[MIN_ENTRIES + i] = UINT64_MAX;
        }
        high->keys[FANOUT - 2] = UINT64_MAX;
        node->keys[MIN_ENTRIES - 1] = UINT64_MAX;
        for (size_t i = 0; i < MIN_ENTRIES; ++i)
            high->children[i] = node->children[MIN_ENTRIES + i];
        return sep;
    }
}

/**
 * inserts `key` and the child following it at `slot` of a non-leaf node that is not full
 */
static void insert_child(quicly_bplus_ranges_node_t *node, size_t slot, uint64_t key, quicly_bplus_ranges_node_t *child)
{
    move_keys(node->keys + slot + 1, node->keys + (FANOUT - 1), node->keys + slot);
    node->keys[slot] = key;
    move_children(node->children + slot + 2, node->children + FANOUT, node->children + slot + 1);
    node->children[slot + 1] = child;
}

/**
 * Inserts a range that does not overlap or touch any existing range at `pos` of the leaf found at the bottom of `path`, splitting
 * full nodes from the bottom up. The nodes being needed are allocated before anything is modified.
 */
static quicly_error_t insert_range(quicly_bplus_ranges_t *ranges, struct st_quicly_bplus_ranges_path_t *path, size_t pos,
                                   uint64_t start, uint64_t end)
{
    size_t leaf_level = ranges->height - 1, level, num_new_nodes = 0, new_node_index = 0;
    quicly_bplus_ranges_node_t *new_nodes[MAX_HEIGHT + 1];

    /* allocate a node for each of the leaf and its ancestors that are full, and one for the new root if all of them are full */
    for (level = ranges->height; level-- != 0 && has_entry(path->nodes[level], level == leaf_level, FANOUT - 1);)
        ++num_new_nodes;
    if (num_new_nodes == ranges->height) {
        if (ranges->height == MAX_HEIGHT)
            return QUICLY_ERROR_STATE_EXHAUSTION;
        ++num_new_nodes;
    }
    for (size_t i = 0; i < num_new_nodes; ++i) {
        if ((new_nodes[i] = malloc(sizeof(*new_nodes[i]))) == NULL) {
            while (i-- != 0)
                free(new_nodes[i]);
            return PTLS_ERROR_NO_MEMORY;
        }
    }

    /* insert to leaf, splitting it if full; when inserting at the split point, the range goes to the low half */
    quicly_bplus_ranges_node_t *node = path->nodes[leaf_level], *high = NULL;
    uint64_t sep = 0;
    if (num_new_nodes != 0) {
        high = new_nodes[new_node_index++];
        sep = split_node(ranges, node, high, 1);
        if (pos > MIN_ENTRIES) {
            node = high;
            pos -= MIN_ENTRIES;
        }
    }
    move_ranges(node->ranges + pos + 1, node->ranges + FANOUT, node->ranges + pos);
    node->ranges[pos] = (quicly_range_t){start, end};
    if (ranges->last == NULL) {
        ranges->last = node->ranges + pos;
    } else if (holds_last(ranges, node)) {
        ++ranges->last;
    }
    ++ranges->num_ranges;

    /* insert the high half of the split node to the parent, splitting the parent if full */
    for (level = leaf_level; high != NULL; --level) {
        if (level == 0) {
            quicly_bplus_ranges_node_t *root = new_nodes[new_node_index++];
            root->keys[0] = sep;
            for (size_t i = 1; i < FANOUT - 1; ++i)
                root->keys[i] = UINT64_MAX;
            root->children[0] = ranges->root;
            root->children[1] = high;
            ranges->root = root;
            ++ranges->height;
            break;
        }
        quicly_bplus_ranges_node_t *parent = path->nodes[level - 1], *child = high;
        size_t slot = path->slots[level - 1];
        uint64_t child_sep = sep;
        high = NULL;
        if (has_entry(parent, 0, FANOUT - 1)) {
            high = new_nodes[new_node_index++];
            sep = split_node(ranges, parent, high, 0);
            if (slot >= MIN_ENTRIES) {
                parent = high;
                slot -= MIN_ENTRIES;
            }
        }
        insert_child(parent, slot, child_sep, child);
    }

    assert(new_node_index == num_new_nodes);
    return 0;
}

/**
 * Removes the range at `pos` of the leaf found at the bottom of `path`, rebalancing the tree. When two nodes are merged, the high
 * one is freed; therefore `first` is never freed.
 */
static void delete_range(quicly_bplus_ranges_t *ranges, struct st_quicly_bplus_ranges_path_t *path, size_t pos)
{
    size_t level = ranges->height - 1;
    quicly_bplus_ranges_node_t *node = path->nodes[level];

    /* remove from leaf */
    move_ranges(node->ranges + pos, node->ranges + FANOUT, node->ranges + pos + 1);
    if (holds_last(ranges, node))
        --ranges->last;
    --ranges->num_ranges;
    if (pos == 0)
        update_separator(path, level, node->ranges[0].start);

    /* Rebalance, while `node` has MIN_ENTRIES - 1 entries. The sibling is the high one unless `node` is the last child; as the
     * sibling has at least MIN_ENTRIES entries, it is merged if it has exactly that many, otherwise an entry is borrowed. */
    for (; level != 0 && !has_entry(node, level == ranges->height - 1, MIN_ENTRIES - 1); --level) {
        int is_leaf = level == ranges->height - 1;
        quicly_bplus_ranges_node_t *parent = path->nodes[level - 1], *low, *high;
        size_t slot = path->slots[level - 1], num_low, sep;
        if (slot + 1 < FANOUT && has_entry(parent, 0, slot + 1)) {
            sep = slot;
            low = node;
            high = parent->children[slot + 1];
            num_low = MIN_ENTRIES - 1;
            if (has_entry(high, is_leaf, MIN_ENTRIES)) {
                /* borrow the first entry of `high` */
                if (is_leaf) {
                    low->ranges[num_low] = high->ranges[0];
                    move_ranges(high->ranges, high->ranges + FANOUT, high->ranges + 1);
                    parent->keys[sep] = high->ranges[0].start;
                    if (holds_last(ranges, high))
                        --ranges->last;
                } else {
                    low->keys[num_low - 1] = parent->keys[sep];
                    low->children[num_low] = high->children[0];
                    parent->keys[sep] = high->keys[0];
                    move_keys(high->keys, high->keys + (FANOUT - 1), high->keys + 1);
                    move_children(high->children, high->children + FANOUT, high->children + 1);
                }
                break;
            }
        } else {
            sep = slot - 1;
            low = parent->children[sep];
            high = node;
            num_low = MIN_ENTRIES;
            if (has_entry(low, is_leaf, MIN_ENTRIES)) {
                /* borrow the last entry of `low` */
                num_low = is_leaf ? leaf_count_le(low, UINT64_MAX - 1) : keys_count_le(low, UINT64_MAX - 1) + 1;
                if (is_leaf) {
                    move_ranges(high->ranges + 1, high->ranges + FANOUT, high->ranges);
                    high->ranges[0] = low->ranges[num_low - 1];
                    low->ranges[num_low - 1] = EMPTY_RANGE;
                    parent->keys[sep] = high->ranges[0].start;
                    if (holds_last(ranges, high))
                        ++ranges->last;
                } else {
                    move_keys(high->keys + 1, high->keys + (FANOUT - 1), high->keys);
                    move_children(high->children + 1, high->children + FANOUT, high->children);
                    high->keys[0] = parent->keys[sep];
                    high->children[0] = low->children[num_low - 1];
                    parent->keys[sep] = low->keys[num_low - 2];
                    low->keys[num_low - 2] = UINT64_MAX;
                }
                break;
            }
        }
        /* merge `high` into `low`; the two hold 2 * MIN_ENTRIES - 1 entries in total */
        size_t num_high = 2 * MIN_ENTRIES - 1 - num_low;
        if (is_leaf) {
            for (size_t i = 0; i < num_high; ++i)
                low->ranges[num_low + i] = high->ranges[i];
            if (holds_last(ranges, high))
                ranges->last = low->ranges + num_low + (ranges->last - high->ranges);
        } else {
            low->keys[num_low - 1] = parent->keys[sep];
            for (size_t i = 0; i < num_high - 1; ++i)
                low->keys[num_low + i] = high->keys[i];
            for (size_t i = 0; i < num_high; ++i)
                low->children[num_low + i] = high->children[i];
        }
        free(high);
        move_keys(parent->keys + sep, parent->keys + (FANOUT - 1), parent->keys + sep + 1);
        move_children(parent->children + sep + 1, parent->children + FANOUT, parent->children + sep + 2);
        node = parent;
    }

    /* shrink the tree if the root has only one child */
    if (ranges->height > 1 && !has_entry(ranges->root, 0, 1)) {
        quicly_bplus_ranges_node_t *old_root = ranges->root;
        ranges->root = old_root->children[0];
        --ranges->height;
        free(old_root);
    }
}

/**
 * frees the descendants of a non-leaf node, except for `first` which is not allocated
 */
static void free_children(quicly_bplus_ranges_t *ranges, quicly_bplus_ranges_node_t *node, size_t height)
{
    for (size_t i = 0; i == 0 || (i < FANOUT && has_entry(node, 0, i)); ++i) {
        quicly_bplus_ranges_node_t *child = node->children[i];
        if (height > 2)
            free_children(ranges, child, height - 1);
        if (child != &ranges->first)
            free(child);
    }
}

void quicly_bplus_ranges_clear(quicly_bplus_ranges_t *ranges)
{
    if (ranges->height > 1) {
        free_children(ranges, ranges->root, ranges->height);
        free(ranges->root);
    }
    init_leaf(&ranges->first);
    ranges->num_ranges = 0;
    ranges->height = 1;
    ranges->root = &ranges->first;
    ranges->last = NULL;
}

quicly_error_t quicly_bplus_ranges_add(quicly_bplus_ranges_t *ranges, uint64_t start, uint64_t end, uint64_t max_committed)
{
    struct st_quicly_bplus_ranges_path_t path;

    assert(start <= end);

    if (start == end)
        return 0;

    /* fast path; when the range starts within or right after the last range, only the last range can be touched */
    if (ranges->last != NULL && ranges->last->start <= start && start <= ranges->last->end) {
        if (ranges->last->end < end)
            ranges->last->end = end;
        return 0;
    }

    /* find the last range whose start is <= end */
    size_t num_le = descend(ranges, end, &path);
    quicly_bplus_ranges_node_t *leaf = path.nodes[ranges->height - 1];

    /* insert if the range does not overlap or touch any of the existing ranges */
    if (num_le == 0 || leaf->ranges[num_le - 1].end < start) {
        if (ranges->num_ranges >= calc_max_ranges(ranges, max_committed))
            return QUICLY_ERROR_STATE_EXHAUSTION;
        return insert_range(ranges, &path, num_le, start, end);
    }

    /* Merge, starting from the last range that touches. The range is extended, then merged into its predecessor while the
     * predecessor touches. The predecessor is looked up by descending from the root only when it is not in the same leaf. */
    size_t pos = num_le - 1;
    quicly_range_t *r = leaf->ranges + pos;
    if (r->end < end)
        r->end = end;
    while (start < r->start) {
        quicly_range_t *pred;
        if (pos != 0) {
            pred = r - 1;
        } else if (leaf == &ranges->first) {
            break;
        } else {
            struct st_quicly_bplus_ranges_path_t pred_path;
            size_t pred_num_le = descend(ranges, r->start - 1, &pred_path);
            pred = pred_path.nodes[ranges->height - 1]->ranges + pred_num_le - 1;
        }
        if (pred->end < start)
            break;
        uint64_t pred_start = pred->start;
        pred->end = r->end;
        delete_range(ranges, &path, pos);
        if (pred_start <= start)
            return 0;
        /* more ranges might touch; locate the predecessor, as the deletion might have moved it */
        pos = descend(ranges, pred_start, &path) - 1;
        leaf = path.nodes[ranges->height - 1];
        r = leaf->ranges + pos;
    }
    if (start < r->start) {
        r->start = start;
        if (pos == 0)
            update_separator(&path, ranges->height - 1, start);
    }

    return 0;
}
