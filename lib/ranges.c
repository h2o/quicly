/*
 * Copyright (c) 2017 Fastly, Kazuho Oku
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
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "quicly/ranges.h"

#define COPY(dst, src, n)                                                                                                          \
    do {                                                                                                                           \
        size_t _n = (n);                                                                                                           \
        if (_n != 0)                                                                                                               \
            memcpy((dst), (src), sizeof(struct st_quicly_range_t) * _n);                                                           \
    } while (0)
#define MOVE(dst, src, n)                                                                                                          \
    do {                                                                                                                           \
        size_t _n = (n);                                                                                                           \
        if (_n != 0)                                                                                                               \
            memmove((dst), (src), sizeof(struct st_quicly_range_t) * _n);                                                          \
    } while (0)

static int insert_at(quicly_ranges_t *ranges, uint64_t start, uint64_t end, size_t slot)
{
    if (ranges->num_ranges == ranges->capacity) {
        size_t new_capacity = ranges->capacity < 4 ? 4 : ranges->capacity * 2;
        struct st_quicly_range_t *new_ranges = malloc(new_capacity * sizeof(*new_ranges));
        if (new_ranges == NULL)
            return -1;
        COPY(new_ranges, ranges->ranges, slot);
        COPY(new_ranges + slot + 1, ranges->ranges + slot, ranges->num_ranges - slot);
        if (ranges->ranges != &ranges->_initial)
            free(ranges->ranges);
        ranges->ranges = new_ranges;
        ranges->capacity = new_capacity;
    } else {
        MOVE(ranges->ranges + slot + 1, ranges->ranges + slot, ranges->num_ranges - slot);
    }
    ranges->ranges[slot] = (struct st_quicly_range_t){start, end};
    ++ranges->num_ranges;
    return 0;
}

static inline int merge_update(quicly_ranges_t *ranges, uint64_t start, uint64_t end, size_t slot, size_t end_slot)
{
    if (start < ranges->ranges[slot].start)
        ranges->ranges[slot].start = start;
    ranges->ranges[slot].end = end < ranges->ranges[end_slot].end ? ranges->ranges[end_slot].end : end;

    if (slot != end_slot)
        quicly_ranges_shrink(ranges, slot + 1, end_slot + 1);

    return 0;
}

int quicly_ranges_update(quicly_ranges_t *ranges, uint64_t start, uint64_t end)
{
    size_t slot, end_slot;

    if (ranges->num_ranges == 0) {
        return insert_at(ranges, start, end, 0);
    } else if (ranges->ranges[ranges->num_ranges - 1].end < start) {
        return insert_at(ranges, start, end, ranges->num_ranges);
    }

    /* find the slot that should contain `end` */
    for (slot = ranges->num_ranges - 1;; --slot) {
        if (ranges->ranges[slot].start <= end)
            break;
        if (slot == 0)
            return insert_at(ranges, start, end, 0);
    }
    end_slot = slot;

    /* find the slot that should contain `start` */
    do {
        if (ranges->ranges[slot].end == start) {
            return merge_update(ranges, start, end, slot, end_slot);
        } else if (ranges->ranges[slot].end < start) {
            if (slot++ == end_slot) {
                return insert_at(ranges, start, end, slot);
            } else {
                return merge_update(ranges, start, end, slot, end_slot);
            }
        }
    } while (slot-- != 0);

    return merge_update(ranges, start, end, 0, end_slot);
}

void quicly_ranges_shrink(quicly_ranges_t *ranges, size_t start, size_t end)
{
    if (start != end) {
        MOVE(ranges->ranges + start, ranges->ranges + end, ranges->num_ranges - end);
        ranges->num_ranges -= end - start;
        if (ranges->capacity > 4 && ranges->num_ranges * 3 <= ranges->capacity) {
            size_t new_capacity = ranges->capacity / 2;
            struct st_quicly_range_t *new_ranges = realloc(ranges->ranges, new_capacity * sizeof(*new_ranges));
            if (new_ranges != NULL) {
                ranges->ranges = new_ranges;
                ranges->capacity = new_capacity;
            }
        }
    }
}
