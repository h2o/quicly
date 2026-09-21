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
#include "quicly/constants.h"
#include "quicly/recvstate.h"

void quicly_recvstate_init(quicly_recvstate_t *state)
{
    quicly_ranges_init_with_range(&state->received, 0, 0);
    state->data_off = 0;
    state->eos = UINT64_MAX;
    state->reliable_size = UINT64_MAX;
    state->app_error_code = 0;
}

void quicly_recvstate_init_closed(quicly_recvstate_t *state)
{
    quicly_ranges_init(&state->received);
    state->data_off = 0;
    state->eos = 0;
    state->reliable_size = UINT64_MAX;
    state->app_error_code = 0;
}

void quicly_recvstate_dispose(quicly_recvstate_t *state)
{
    quicly_ranges_clear(&state->received);
}

quicly_error_t quicly_recvstate_update(quicly_recvstate_t *state, uint64_t off, size_t *len, int is_fin, size_t max_ranges)
{
    assert(!quicly_recvstate_transfer_complete(state));

    /* eos handling */
    if (state->eos == UINT64_MAX) {
        if (is_fin) {
            state->eos = off + *len;
            if (state->eos < state->received.ranges[state->received.num_ranges - 1].end)
                return QUICLY_TRANSPORT_ERROR_FINAL_SIZE;
        }
    } else {
        if (off + *len > state->eos)
            return QUICLY_TRANSPORT_ERROR_FINAL_SIZE;
        /* Once the final size is known it cannot change (RFC 9000 section 4.5). The check is necessary because a stream that has
         * been reset with a non-zero reliable size keeps receiving, hence the FIN can arrive after the reset (section 5.1 of
         * draft-ietf-quic-reliable-stream-reset). */
        if (is_fin && off + *len != state->eos)
            return QUICLY_TRANSPORT_ERROR_FINAL_SIZE;
    }

    /* no state change; entire data has already been received */
    if (off + *len <= state->data_off) {
        *len = 0;
        if (state->received.ranges[0].end == state->eos)
            goto Complete;
        return 0;
    }

    /* adjust if partially received */
    if (off < state->data_off) {
        size_t delta = state->data_off - off;
        off += delta;
        *len -= delta;
    }

    /* update received range */
    if (*len != 0) {
        int ret;
        if ((ret = quicly_ranges_add(&state->received, off, off + *len)) != 0)
            return ret;
        if (state->received.num_ranges > max_ranges)
            return QUICLY_ERROR_STATE_EXHAUSTION;
    }
    if (state->received.num_ranges == 1 && state->received.ranges[0].start == 0 && state->received.ranges[0].end == state->eos)
        goto Complete;

    return 0;

Complete:
    quicly_ranges_clear(&state->received);
    return 0;
}

quicly_error_t quicly_recvstate_reset_at(quicly_recvstate_t *state, uint64_t eos_at, uint64_t reliable_size,
                                         uint64_t *bytes_missing)
{
    quicly_error_t ret;

    assert(!quicly_recvstate_transfer_complete(state));
    assert(reliable_size <= eos_at);

    /* validate */
    if (state->eos != UINT64_MAX && state->eos != eos_at)
        return QUICLY_TRANSPORT_ERROR_FINAL_SIZE;
    if (eos_at < state->received.ranges[state->received.num_ranges - 1].end)
        return QUICLY_TRANSPORT_ERROR_FINAL_SIZE;

    /* Section 5.2 of draft-ietf-quic-reliable-stream-reset: as the sender is only allowed to reduce the reliable size, a greater
     * value can only be the result of reordering, and is to be ignored (rather than being an error). */
    if (reliable_size >= state->reliable_size) {
        *bytes_missing = 0;
        return 0;
    }

    /* the final size is now known; see RFC 9000 section 4.5 */
    state->eos = eos_at;
    state->reliable_size = reliable_size;

    uint64_t received_upto = state->received.ranges[state->received.num_ranges - 1].end;

    /* Record the offsets at and above the reliable size as received, as the peer is no longer expected to deliver them (section
     * 5.2). Doing so lets the transfer complete as soon as the bytes below the reliable size have been received (section 5.3),
     * retaining the ranges below that offset until then. Note that the bytes that have been received above the reliable size are
     * retained as well; delivering them to the application is permitted (section 5). */
    if ((ret = quicly_ranges_add(&state->received, reliable_size, eos_at)) != 0)
        return ret;

    /* Report the offsets that have just been marked as received even though their data will never arrive, so that the caller can
     * account for them in connection-level flow control; the peer has done the same when sending the reset. The offsets that remain
     * to be received are left out, as they are accounted for when they arrive. */
    *bytes_missing = state->received.ranges[state->received.num_ranges - 1].end - received_upto;

    /* Clear the received ranges if the transfer is complete, as that is how completion is represented; see
     * `quicly_recvstate_transfer_complete`. */
    if (state->received.num_ranges == 1 && state->received.ranges[0].start == 0 && state->received.ranges[0].end == eos_at)
        quicly_ranges_clear(&state->received);

    return 0;
}

quicly_error_t quicly_recvstate_reset(quicly_recvstate_t *state, uint64_t eos_at, uint64_t *bytes_missing)
{
    /* a RESET_STREAM frame is equivalent to a RESET_STREAM_AT frame carrying a reliable size of zero; see section 5.2 of
     * draft-ietf-quic-reliable-stream-reset */
    return quicly_recvstate_reset_at(state, eos_at, 0, bytes_missing);
}
