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
#include "picotls.h"
#include "quicly/sentmap.h"

const quicly_sent_packet_t quicly_sentmap__end_iter = {UINT64_MAX, INT64_MAX};

static void next_entry(quicly_sentmap_iter_t *iter)
{
    if (--iter->count != 0) {
        ++iter->p;
    } else if (*(iter->ref = &(*iter->ref)->next) == NULL) {
        iter->p = (quicly_sent_packet_t *)&quicly_sentmap__end_iter;
        iter->count = 0;
        return;
    } else {
        assert((*iter->ref)->num_entries != 0);
        iter->count = (*iter->ref)->num_entries;
        iter->p = (*iter->ref)->entries;
    }
    while (iter->p->ack_epoch == UINT8_MAX)
        ++iter->p;
}

static struct st_quicly_sent_block_t **free_block(quicly_sentmap_t *map, struct st_quicly_sent_block_t **ref)
{
    static const struct st_quicly_sent_block_t dummy = {NULL};
    static const struct st_quicly_sent_block_t *const dummy_ref = &dummy;
    struct st_quicly_sent_block_t *block = *ref;

    assert(block->num_entries == 0);

    if (block->next != NULL) {
        *ref = block->next;
        assert((*ref)->num_entries != 0);
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

static void discard_entry(quicly_sentmap_t *map, quicly_sentmap_iter_t *iter)
{
    assert(iter->p->ack_epoch != UINT8_MAX);
    iter->p->ack_epoch = UINT8_MAX;
    if (iter->p->num_frames > PTLS_ELEMENTSOF(iter->p->_frames.embedded))
        free(iter->p->_frames.detached.base);

    struct st_quicly_sent_block_t *block = *iter->ref;
    if (--block->num_entries == 0) {
        iter->ref = free_block(map, iter->ref);
        block = *iter->ref;
        iter->p = block->entries - 1;
        iter->count = block->num_entries + 1;
    }
}

void quicly_sentmap_dispose(quicly_sentmap_t *map)
{
    quicly_sentmap_iter_t iter;

    quicly_sentmap_init_iter(map, &iter);

    while (iter.p->packet_number != UINT64_MAX) {
        discard_entry(map, &iter);
        --map->num_packets;
        next_entry(&iter);
    }

    assert(map->num_packets == 0);
    assert(map->head == NULL);
}

int quicly_sentmap_prepare(quicly_sentmap_t *map, uint64_t packet_number, int64_t now, uint8_t ack_epoch)
{
    assert(map->_pending_packet == NULL);

    struct st_quicly_sent_block_t *block;

    if ((block = map->tail) == NULL || block->next_insert_at == PTLS_ELEMENTSOF(block->entries)) {
        if ((block = quicly_sentmap__new_block(map)) == NULL)
            return PTLS_ERROR_NO_MEMORY;
    }

    map->_pending_packet = block->entries + block->next_insert_at++;
    ++block->num_entries;

    *map->_pending_packet = (quicly_sent_packet_t){packet_number, now, ack_epoch};

    return 0;
}

quicly_sent_t *quicly_sentmap_allocate(quicly_sentmap_t *map, quicly_sent_acked_cb acked)
{
    quicly_sent_packet_t *packet = map->_pending_packet;
    quicly_sent_t *sent;

    if (packet->num_frames < PTLS_ELEMENTSOF(packet->_frames.embedded)) {
        sent = packet->_frames.embedded + packet->num_frames++;
    } else {
        if (packet->num_frames == PTLS_ELEMENTSOF(packet->_frames.embedded)) {
            quicly_sent_t *frames;
            size_t capacity = PTLS_ELEMENTSOF(packet->_frames.embedded) * 2;
            if ((frames = malloc(sizeof(*frames) * capacity)) == NULL)
                return NULL;
            memcpy(frames, packet->_frames.embedded, sizeof(packet->_frames.embedded));
            packet->_frames.detached.base = frames;
            packet->_frames.detached.capacity = capacity;
        } else if (packet->num_frames == packet->_frames.detached.capacity) {
            quicly_sent_t *frames;
            size_t capacity = packet->_frames.detached.capacity * 2;
            if ((frames = realloc(packet->_frames.detached.base, sizeof(*frames) * capacity)) == NULL)
                return NULL;
            packet->_frames.detached.base = frames;
            packet->_frames.detached.capacity = capacity;
        }
        sent = packet->_frames.detached.base + packet->num_frames++;
    }

    sent->acked = acked;
    return sent;
}

struct st_quicly_sent_block_t *quicly_sentmap__new_block(quicly_sentmap_t *map)
{
    struct st_quicly_sent_block_t *block;

    if ((block = malloc(sizeof(*block))) == NULL)
        return NULL;

    block->next = NULL;
    block->num_entries = 0;
    block->next_insert_at = 0;
    if (map->tail != NULL) {
        map->tail->next = block;
        map->tail = block;
    } else {
        map->head = map->tail = block;
    }

    return block;
}

void quicly_sentmap_skip(quicly_sentmap_iter_t *iter)
{
    next_entry(iter);
}

int quicly_sentmap_update(quicly_sentmap_t *map, quicly_sentmap_iter_t *iter, quicly_sentmap_event_t event)
{
    quicly_sent_packet_t *packet = iter->p;
    int clear_cc_bytes_in_flight = 0, ret = 0;

    assert(packet != &quicly_sentmap__end_iter);
    assert(packet->ack_epoch != UINT8_MAX);

    /* update CC state unless the event is PTO */
    if (packet->cc_bytes_in_flight != 0 && event != QUICLY_SENTMAP_EVENT_PTO) {
        assert(map->bytes_in_flight >= packet->cc_bytes_in_flight);
        map->bytes_in_flight -= packet->cc_bytes_in_flight;
        clear_cc_bytes_in_flight = 1;
    }

    /* invoke the frame-level callbacks when the frames are inflight or if it has been late-acked */
    if (event == QUICLY_SENTMAP_EVENT_ACKED || packet->frames_in_flight) {
        quicly_sent_t *frames = packet->num_frames <= PTLS_ELEMENTSOF(packet->_frames.embedded) ? packet->_frames.embedded
                                                                                                : packet->_frames.detached.base;
        for (size_t i = 0; i < packet->num_frames; ++i) {
            quicly_sent_t *sent = frames + i;
            if ((ret = sent->acked(map, packet, event == QUICLY_SENTMAP_EVENT_ACKED, sent)) != 0)
                goto Exit;
        }
    }

    if (event == QUICLY_SENTMAP_EVENT_ACKED || event == QUICLY_SENTMAP_EVENT_EXPIRED) {
        discard_entry(map, iter);
        --map->num_packets;
    } else {
        if (clear_cc_bytes_in_flight)
            packet->cc_bytes_in_flight = 0;
        packet->frames_in_flight = 0;
    }

    next_entry(iter);

Exit:
    return ret;
}

int quicly_sentmap__type_packet(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    assert(!"quicly_sentmap__type_packet cannot be called");
    return QUICLY_TRANSPORT_ERROR_INTERNAL;
}
