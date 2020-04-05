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
#include "picotls.h"
#include "quicly/sentmap.h"

void quicly_sentmap_init(quicly_sentmap_t *map)
{
    *map = (quicly_sentmap_t){NULL};
    map->_.pkt_list.next = &map->_.pkt_list;
    map->_.pkt_list.prev = &map->_.pkt_list;
    map->_.packet_number = UINT64_MAX;
    map->_.sent_at = INT64_MAX;
}

void quicly_sentmap_commit(quicly_sentmap_t *map, uint16_t bytes_in_flight)
{
    assert(quicly_sentmap_is_open(map));

    if (bytes_in_flight != 0) {
        quicly_sent_packet_t *p = (quicly_sent_packet_t *)map->_.pkt_list.prev;
        p->ack_eliciting = 1;
        p->bytes_in_flight = bytes_in_flight;
        map->bytes_in_flight += bytes_in_flight;
    }
    map->is_open = 0;
}

static inline quicly_sent_packet_t *allocate_packet(uint16_t frames)
{
    quicly_sent_packet_t *packet = calloc(1, offsetof(quicly_sent_packet_t, frames) + frames * sizeof(quicly_sent_frame_t));
    if (packet == NULL)
        return NULL;
    packet->frame_capacity = frames;
    return packet;
}

quicly_sent_frame_t *quicly_sentmap_allocate_frame(quicly_sentmap_t *map, quicly_sent_acked_cb acked)
{
    assert(quicly_sentmap_is_open(map));

    quicly_sent_packet_t *p = (quicly_sent_packet_t *)map->_.pkt_list.prev;
    /* grow the packet if it is full */
    if (p->used_frames == p->frame_capacity) {
        quicly_sent_packet_t *new_p = allocate_packet(p->frame_capacity * 2);
        if (!new_p)
            return NULL;
        memcpy(new_p, p, offsetof(quicly_sent_packet_t, frames) + p->frame_capacity * sizeof(quicly_sent_frame_t));
        new_p->frame_capacity = p->frame_capacity * 2;
        p->pkt_list.prev->next = &new_p->pkt_list;
        p->pkt_list.next->prev = &new_p->pkt_list;
        p = new_p;
    }

    assert(p->used_frames < p->frame_capacity);
    quicly_sent_frame_t *frame = &p->frames[p->used_frames];
    p->used_frames++;
    frame->acked = acked;
    return frame;
}

int quicly_sentmap_prepare(quicly_sentmap_t *map, uint64_t packet_number, int64_t now, uint8_t ack_epoch)
{
    assert(!quicly_sentmap_is_open(map));

    quicly_sent_packet_t *new_packet = allocate_packet(QUICLY_SENTMAP_DEFAULT_FRAMES_PER_PACKET);
    if (new_packet == NULL) {
        return PTLS_ERROR_NO_MEMORY;
    }
    new_packet->packet_number = packet_number;
    new_packet->sent_at = now;
    new_packet->ack_epoch = ack_epoch;

    map->_.pkt_list.prev->next = &new_packet->pkt_list;
    new_packet->pkt_list.prev = map->_.pkt_list.prev;
    map->_.pkt_list.prev = &new_packet->pkt_list;
    new_packet->pkt_list.next = &map->_.pkt_list;

    map->is_open = 1;
    return 0;
}

static inline void discard_packet(quicly_sentmap_t *map, quicly_sent_packet_t *packet)
{
    assert(packet);
    assert(&packet->pkt_list != &map->_.pkt_list); /* not the end of the list */

    packet->pkt_list.prev->next = packet->pkt_list.next;
    packet->pkt_list.next->prev = packet->pkt_list.prev;

    free(packet);
}

int quicly_sentmap_update(quicly_sentmap_t *map, quicly_sentmap_iter_t *iter, quicly_sentmap_event_t event,
                          struct st_quicly_conn_t *conn)
{
    quicly_sent_packet_t *packet;
    int notify_lost = 0, ret = 0, i = 0;

    assert(!quicly_sentmap_iter_is_end(iter));

    /* save packet pointer */
    packet = (quicly_sent_packet_t *)iter->p;

    /* update packet-level metrics (make adjustments to notify the loss when discarding a packet that is still deemed inflight) */
    if (packet->bytes_in_flight != 0) {
        if (event == QUICLY_SENTMAP_EVENT_EXPIRED)
            notify_lost = 1;
        assert(map->bytes_in_flight >= packet->bytes_in_flight);
        map->bytes_in_flight -= packet->bytes_in_flight;
    }
    packet->bytes_in_flight = 0;

    /* move iterator to next packet */
    quicly_sentmap_skip(iter);

    /* iterate through the frames */
    for (i = 0; i < packet->used_frames; i++) {
        quicly_sent_frame_t *frame = &packet->frames[i];
        if (notify_lost && ret == 0)
            ret = frame->acked(conn, packet, frame, QUICLY_SENTMAP_EVENT_LOST);
        if (ret == 0)
            ret = frame->acked(conn, packet, frame, event);
    }

    /* Remove packet from sentmap, unless it is deemed lost. If lost, then hold on to this packet until removed by a
     * QUICLY_SENTMAP_EVENT_EXPIRED event. */
    if (event != QUICLY_SENTMAP_EVENT_LOST)
        discard_packet(map, packet);

    return ret;
}

void quicly_sentmap_dispose(quicly_sentmap_t *map)
{
    while (map->_.pkt_list.next != &map->_.pkt_list) {
        discard_packet(map, (quicly_sent_packet_t *)map->_.pkt_list.next);
    }
}
