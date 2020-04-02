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

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdint.h>
#include "quicly/constants.h"
#include "quicly/maxsender.h"
#include "quicly/sendstate.h"

#define QUICLY_SENTMAP_DEFAULT_FRAMES_PER_PACKET 8

struct st_quicly_conn_t;

typedef struct st_quicly_sent_packet_t quicly_sent_packet_t;
typedef struct st_quicly_sent_frame_t quicly_sent_frame_t;

typedef enum en_quicly_sentmap_event_t {
    /**
     * a packet (or a frame) has been acked
     */
    QUICLY_SENTMAP_EVENT_ACKED,
    /**
     * a packet (or a frame) is deemed lost
     */
    QUICLY_SENTMAP_EVENT_LOST,
    /**
     * a packet (or a frame) is being removed from the sentmap (e.g., after 3 pto, the epoch being discarded)
     */
    QUICLY_SENTMAP_EVENT_EXPIRED
} quicly_sentmap_event_t;

typedef int (*quicly_sent_acked_cb)(struct st_quicly_conn_t *conn, const quicly_sent_packet_t *packet, quicly_sent_frame_t *data,
                                    quicly_sentmap_event_t event);

struct st_quicly_sent_frame_t {
    quicly_sent_acked_cb acked;
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
            int uni;
            quicly_maxsender_sent_t args;
        } max_streams;
        struct {
            int uni;
            quicly_maxsender_sent_t args;
        } streams_blocked;
        struct {
            quicly_stream_id_t stream_id;
        } stream_state_sender;
        struct {
            int is_inflight;
            uint64_t generation;
        } new_token;
    } data;
};

typedef struct st_dlist_t {
    struct st_dlist_t *prev;
    struct st_dlist_t *next;
} dlist_t;

struct st_quicly_sent_packet_t {
    dlist_t pkt_list;
    /**
     *
     */
    uint64_t packet_number;
    /**
     *
     */
    int64_t sent_at;
    /**
     * epoch to be acked in
     */
    uint8_t ack_epoch;
    /**
     *
     */
    uint8_t ack_eliciting : 1;
    /**
     * number of bytes in-flight for the packet (becomes zero once deemed lost)
     */
    uint16_t bytes_in_flight;
    /**
     * number of frame slots available
     */
    uint16_t frame_capacity;
    /**
     * number of used frame slots
     */
    uint16_t used_frames;
    /**
     * variable length array of frames composing the packet
     */
    quicly_sent_frame_t frames[];
};

/**
 * quicly_sentmap_t is a structure that holds a list of sent objects being tracked.  The list is a list of packet header and
 * frame-level objects of that packet.  Packet header is identified by quicly_sent_t::acked being quicly_sent__type_header.
 *
 * The transport writes to the sentmap in the following way:
 * 1. call quicly_sentmap_prepare
 * 2. repeatedly call quicly_sentmap_allocate to allocate frame-level objects and initialize them
 * 3. call quicly_sentmap_commit
 *
 * The transport iterates (and mutates) the sentmap in the following way:
 * 1. call quicly_sentmap_init_iter
 * 2. call quicly_sentmap_get to obtain the packet header that the iterator points to
 * 3. call quicly_sentmap_update to update the states of the packet that the iterator points to (as well as the state of the frames
 *    that were part of the packet) and move the iterator to the next packet header.  The function is also used for discarding
 * entries from the sent map.
 * 4. call quicly_sentmap_skip to move the iterator to the next packet header
 *
 * Note that quicly_sentmap_update and quicly_sentmap_skip move the iterator to the next packet header.
 */
typedef struct st_quicly_sentmap_t {
    /**
     * "fake" packet, used for its linked list, and as a valid end value for the iterator
     * the linked list includes entries that are deemed lost (up to 3*SRTT) as well
     */
    quicly_sent_packet_t _;
    /**
     * bytes in-flight
     */
    size_t bytes_in_flight;
    /**
     * is non-NULL between prepare and commit, pointing to the packet header that is being written to
     */
    uint8_t is_open;

} quicly_sentmap_t;

typedef struct st_quicly_sentmap_iter_t {
    dlist_t *p;
} quicly_sentmap_iter_t;

/**
 * initializes the sentmap
 */
void quicly_sentmap_init(quicly_sentmap_t *map);
/**
 * frees all the data contained in the sentmap
 */
void quicly_sentmap_dispose(quicly_sentmap_t *map);

/**
 * if transaction is open (i.e. between prepare and commit)
 */
static int quicly_sentmap_is_open(quicly_sentmap_t *map);
/**
 * prepares a write
 */
int quicly_sentmap_prepare(quicly_sentmap_t *map, uint64_t packet_number, int64_t now, uint8_t ack_epoch);
/**
 * commits a write
 */
void quicly_sentmap_commit(quicly_sentmap_t *map, uint16_t bytes_in_flight);
/**
 * Allocates a slot to contain a callback for a frame.  The function MUST be called after _prepare but before _commit.
 */
quicly_sent_frame_t *quicly_sentmap_allocate_frame(quicly_sentmap_t *map, quicly_sent_acked_cb acked);
/**
 * initializes the iterator
 */
static void quicly_sentmap_init_iter(quicly_sentmap_t *map, quicly_sentmap_iter_t *iter);
/**
 * returns the current packet pointed to by the iterator
 */
static const quicly_sent_packet_t *quicly_sentmap_get(quicly_sentmap_iter_t *iter);
/**
 * advances the iterator to the next packet
 */
static void quicly_sentmap_skip(quicly_sentmap_iter_t *iter);
/**
 * checks wether the iterator reached the end of the sentmap
 */
static int8_t quicly_sentmap_iter_is_end(quicly_sentmap_iter_t *iter);
/**
 * updates the state of the packet being pointed to by the iterator, _and advances to the next packet_
 */
int quicly_sentmap_update(quicly_sentmap_t *map, quicly_sentmap_iter_t *iter, quicly_sentmap_event_t event,
                          struct st_quicly_conn_t *conn);

/* inline definitions */

static inline const quicly_sent_packet_t *quicly_sentmap_get(quicly_sentmap_iter_t *iter)
{
    assert(iter->p);
    return (quicly_sent_packet_t *)iter->p;
}

static inline int8_t quicly_sentmap_iter_is_end(quicly_sentmap_iter_t *iter)
{
    return quicly_sentmap_get(iter)->packet_number == UINT64_MAX;
}

static inline int quicly_sentmap_is_open(quicly_sentmap_t *map)
{
    return map->is_open;
}

static inline void quicly_sentmap_init_iter(quicly_sentmap_t *map, quicly_sentmap_iter_t *iter)
{
    iter->p = map->_.pkt_list.next;
}

static inline void quicly_sentmap_skip(quicly_sentmap_iter_t *iter)
{
    iter->p = iter->p->next;
}

#ifdef __cplusplus
}
#endif

#endif
