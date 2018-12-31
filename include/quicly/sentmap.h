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
#ifndef quicly_sentmap_h
#define quicly_sentmap_h

#include <assert.h>
#include <stdint.h>
#include "quicly/constants.h"
#include "quicly/maxsender.h"
#include "quicly/sendbuf.h"

struct st_quicly_conn_t;
typedef struct st_quicly_sent_t quicly_sent_t;

typedef int (*quicly_sent_acked_cb)(struct st_quicly_conn_t *conn, int is_acked, quicly_sent_t *data);

struct st_quicly_sent_t {
    uint64_t packet_number;
    int64_t sent_at;
    quicly_sent_acked_cb acked;
    uint8_t ack_epoch;        /* epoch to be acked in */
    uint8_t is_in_flight : 1; /* if the entry is in-flight (ack-eliciting entry that has not yet been deemed lost) */
    union {
        struct {
            quicly_range_t range;
        } ack;
        struct {
            quicly_stream_id_t stream_id;
            quicly_sendstate_sent_t args;
        } stream;
        struct {
            quicly_stream_id_t stream_id;
            quicly_maxsender_sent_t args;
        } max_stream_data;
        struct {
            quicly_maxsender_sent_t args;
        } max_data;
        struct {
            quicly_maxsender_sent_t args;
        } max_stream_id;
        struct {
            quicly_maxsender_sent_t args;
        } stream_id_blocked;
        struct {
            quicly_stream_id_t stream_id;
        } stream_state_sender;
        struct {
            size_t bytes_in_flight;
        } cc;
    } data;
};

struct st_quicly_sent_block_t {
    /**
     * next block if exists (or NULL)
     */
    struct st_quicly_sent_block_t *next;
    /**
     * number of entries in the block
     */
    size_t num_entries;
    /**
     * insertion index within `entries`
     */
    size_t next_insert_at;
    /**
     * slots
     */
    quicly_sent_t entries[16];
};

typedef struct st_quicly_sentmap_t {
    /**
     * the linked list includes entries that are deemed lost (up to 3*SRTT) as well
     */
    struct st_quicly_sent_block_t *head, *tail;
    /**
     * number of entries with `quicly_sent_t::is_in_flight` flag set to true
     */
    size_t num_in_flight;
} quicly_sentmap_t;

typedef struct st_quicly_sentmap_iter_t {
    quicly_sent_t *p;
    size_t count;
    struct st_quicly_sent_block_t **ref;
} quicly_sentmap_iter_t;

extern const quicly_sent_t quicly_sentmap__end_iter;

static void quicly_sentmap_init(quicly_sentmap_t *map);
void quicly_sentmap_dispose(quicly_sentmap_t *map);
static quicly_sent_t *quicly_sentmap_allocate(quicly_sentmap_t *map, uint64_t packet_number, uint64_t now,
                                              quicly_sent_acked_cb acked, uint8_t ack_epoch, int is_inflight);
static int quicly_sentmap_is_empty(quicly_sentmap_t *map);
static quicly_sent_t *quicly_sentmap_get_tail(quicly_sentmap_t *map);
struct st_quicly_sent_block_t *quicly_sentmap__new_block(quicly_sentmap_t *map);
static int quicly_sentmap_on_ack(quicly_sentmap_t *map, int is_acked, quicly_sent_t *sent, struct st_quicly_conn_t *conn);
static void quicly_sentmap_init_iter(quicly_sentmap_t *map, quicly_sentmap_iter_t *iter);
static quicly_sent_t *quicly_sentmap_get(quicly_sentmap_iter_t *iter);
static void quicly_sentmap_next(quicly_sentmap_iter_t *iter);
static void quicly_sentmap_release(quicly_sentmap_t *map, quicly_sentmap_iter_t *iter);
struct st_quicly_sent_block_t **quicly_sentmap__release_block(quicly_sentmap_t *map, struct st_quicly_sent_block_t **ref);

/* inline definitions */

inline void quicly_sentmap_init(quicly_sentmap_t *map)
{
    map->head = NULL;
    map->tail = NULL;
}

inline quicly_sent_t *quicly_sentmap_allocate(quicly_sentmap_t *map, uint64_t packet_number, uint64_t now,
                                              quicly_sent_acked_cb acked, uint8_t ack_epoch, int is_inflight)
{
    struct st_quicly_sent_block_t *block;

    if ((block = map->tail) == NULL || block->next_insert_at == sizeof(block->entries) / sizeof(block->entries[0])) {
        if ((block = quicly_sentmap__new_block(map)) == NULL)
            return NULL;
    }

    quicly_sent_t *sent = block->entries + block->next_insert_at++;
    ++block->num_entries;

    sent->packet_number = packet_number;
    sent->sent_at = now;
    sent->acked = acked;
    sent->ack_epoch = ack_epoch;
    if (is_inflight) {
        sent->is_in_flight = 1;
        ++map->num_in_flight;
    } else {
        sent->is_in_flight = 0;
    }

    return sent;
}

inline int quicly_sentmap_is_empty(quicly_sentmap_t *map)
{
    return map->head == NULL;
}

inline quicly_sent_t *quicly_sentmap_get_tail(quicly_sentmap_t *map)
{
    return map->tail->entries + map->tail->next_insert_at - 1;
}

inline int quicly_sentmap_on_ack(quicly_sentmap_t *map, int is_acked, quicly_sent_t *sent, struct st_quicly_conn_t *conn)
{
    int ret;

    if (sent->is_in_flight || is_acked) {
        if ((ret = sent->acked(conn, is_acked, sent)) != 0)
            return ret;
    }

    if (sent->is_in_flight) {
        sent->is_in_flight = 0;
        --map->num_in_flight;
    }
    return 0;
}

inline void quicly_sentmap_init_iter(quicly_sentmap_t *map, quicly_sentmap_iter_t *iter)
{
    iter->ref = &map->head;
    if (map->head != NULL) {
        assert(map->head->num_entries != 0);
        for (iter->p = map->head->entries; iter->p->acked == NULL; ++iter->p)
            ;
        iter->count = map->head->num_entries;
    } else {
        iter->p = (quicly_sent_t *)&quicly_sentmap__end_iter;
        iter->count = 0;
    }
}

inline quicly_sent_t *quicly_sentmap_get(quicly_sentmap_iter_t *iter)
{
    return iter->p;
}

inline void quicly_sentmap_next(quicly_sentmap_iter_t *iter)
{
    if (--iter->count != 0) {
        ++iter->p;
    } else if (*(iter->ref = &(*iter->ref)->next) == NULL) {
        iter->p = (quicly_sent_t *)&quicly_sentmap__end_iter;
        iter->count = 0;
        return;
    } else {
        assert((*iter->ref)->num_entries != 0);
        iter->count = (*iter->ref)->num_entries;
        iter->p = (*iter->ref)->entries;
    }
    while (iter->p->acked == NULL)
        ++iter->p;
}

inline void quicly_sentmap_release(quicly_sentmap_t *map, quicly_sentmap_iter_t *iter)
{
    assert(iter->p->acked != NULL);
    assert(!iter->p->is_in_flight);
    iter->p->acked = NULL;

    struct st_quicly_sent_block_t *block = *iter->ref;
    if (--block->num_entries == 0) {
        iter->ref = quicly_sentmap__release_block(map, iter->ref);
        block = *iter->ref;
        iter->p = block->entries - 1;
        iter->count = block->num_entries + 1;
    }
}

#endif
