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
#include "quicly/ack.h"

const quicly_sent_t quicly_sentmap__end_iter = {UINT64_MAX, INT64_MAX};

void quicly_sentmap_dispose(quicly_sentmap_t *map)
{
    struct st_quicly_sent_block_t *block;

    while ((block = map->head) != NULL) {
        map->head = block->next;
        free(block);
    }
}

struct st_quicly_sent_block_t *quicly_sentmap__new_block(quicly_sentmap_t *map)
{
    struct st_quicly_sent_block_t *block;

    if ((block = malloc(sizeof(*block))) == NULL)
        return NULL;

    block->next = NULL;
    block->total = 0;
    block->alive = 0;
    if (map->tail != NULL) {
        map->tail->next = block;
        map->tail = block;
    } else {
        map->head = map->tail = block;
    }

    return block;
}

struct st_quicly_sent_block_t **quicly_sentmap__release_block(quicly_sentmap_t *map, struct st_quicly_sent_block_t **ref)
{
    static const struct st_quicly_sent_block_t dummy = {NULL};
    static const struct st_quicly_sent_block_t *const dummy_ref = &dummy;
    struct st_quicly_sent_block_t *block = *ref;

    if (block->next != NULL) {
        *ref = block->next;
        assert((*ref)->alive != 0);
    } else {
        assert(block == map->tail);
        if (ref == &map->head) {
            map->head = NULL;
            map->tail = NULL;
        } else {
            map->tail = (void *)((char *)ref - offsetof(struct st_quicly_sent_block_t, next));
            map->tail->next = NULL;
        }
        ref = (struct st_quicly_sent_block_t **)&dummy_ref;
    }

    free(block);
    return ref;
}
