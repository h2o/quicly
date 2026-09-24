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
#ifndef quicly_maxsender_h
#define quicly_maxsender_h

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include "quicly/constants.h"

typedef struct st_quicly_maxsender_t {
    /**
     * maximum value being announced (never decreases)
     */
    int64_t max_committed;
    /**
     * set when a frame carrying `max_committed` is deemed lost; cleared when `max_committed` is sent again or acked
     */
    unsigned lost : 1;
    /**
     * set when the remote peer reports being blocked at `max_committed`; a new value is sent as soon as one greater than
     * `max_committed` becomes available, regardless of the update ratio
     */
    unsigned remote_blocked : 1;
} quicly_maxsender_t;

typedef struct st_quicly_maxsender_sent_t {
    uint64_t value;
} quicly_maxsender_sent_t;

static void quicly_maxsender_init(quicly_maxsender_t *m, int64_t initial_value);
static void quicly_maxsender_dispose(quicly_maxsender_t *m);
/**
 * Called when the remote peer reports being blocked at `blocked_at`. If the value is the latest one being sent, the next value is
 * sent as soon as it becomes available. Otherwise, the report is ignored, as a greater value is either inflight or being resent.
 */
static void quicly_maxsender_blocked(quicly_maxsender_t *m, uint64_t blocked_at);
/**
 * Returns if a new value (`buffered_from + window_size`) should be sent. This is the case when the latest value has been lost, when
 * the remote peer is blocked and the new value is greater than the latest one, or when the latest value falls within
 * `update_ratio` of the window.
 */
static int quicly_maxsender_should_send_max(quicly_maxsender_t *m, int64_t buffered_from, uint32_t window_size,
                                            uint32_t update_ratio);
/**
 * Returns if a BLOCKED frame carrying `local_max` should be sent; i.e., if it has not been sent yet, or if it has been lost. The
 * function does not determine if the endpoint is blocked; the caller must call it only while being blocked by `local_max`.
 */
static int quicly_maxsender_should_send_blocked(quicly_maxsender_t *m, int64_t local_max);
static void quicly_maxsender_record(quicly_maxsender_t *m, int64_t value, quicly_maxsender_sent_t *sent);
/**
 * Updates the state when the frame recorded as `sent` is acked or deemed lost. Returns if `max_committed` needs to be sent again
 * for it to reach the peer; i.e., if the frame carried `max_committed` and has been deemed lost.
 */
static int quicly_maxsender_on_ack(quicly_maxsender_t *m, quicly_maxsender_sent_t *sent, int acked);

/* inline definitions */

inline void quicly_maxsender_init(quicly_maxsender_t *m, int64_t initial_value)
{
    m->max_committed = initial_value;
    m->lost = 0;
    m->remote_blocked = 0;
}

inline void quicly_maxsender_dispose(quicly_maxsender_t *m)
{
    (void)m;
}

inline void quicly_maxsender_blocked(quicly_maxsender_t *m, uint64_t blocked_at)
{
    if (blocked_at == (uint64_t)m->max_committed)
        m->remote_blocked = 1;
}

inline int quicly_maxsender_should_send_max(quicly_maxsender_t *m, int64_t buffered_from, uint32_t window_size,
                                            uint32_t update_ratio)
{
    /* resend if the latest value has been lost */
    if (m->lost)
        return 1;

    if (m->remote_blocked && buffered_from + window_size > m->max_committed)
        return 1;

    /* ratio is permil (1/1024) */
    int64_t threshold = buffered_from + ((int64_t)window_size * update_ratio) / 1024;
    return m->max_committed <= threshold;
}

inline int quicly_maxsender_should_send_blocked(quicly_maxsender_t *m, int64_t local_max)
{
    /* resend if the latest value has been lost */
    if (m->lost)
        return 1;

    /* send if the value is new */
    return m->max_committed < local_max;
}

inline void quicly_maxsender_record(quicly_maxsender_t *m, int64_t value, quicly_maxsender_sent_t *sent)
{
    assert(value >= m->max_committed);
    if (value > m->max_committed)
        m->remote_blocked = 0;
    m->max_committed = value;
    m->lost = 0;
    sent->value = value;
}

inline int quicly_maxsender_on_ack(quicly_maxsender_t *m, quicly_maxsender_sent_t *sent, int acked)
{
    /* a frame carrying an older value needs no action, as a newer one carrying `max_committed` has been sent */
    if ((int64_t)sent->value != m->max_committed)
        return 0;

    /* an ACK might be a late one, arriving after the frame has been deemed lost */
    m->lost = !acked;
    return m->lost;
}

#ifdef __cplusplus
}
#endif

#endif
