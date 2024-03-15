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

static int reliable_reset_is_satisfied(quicly_recvstate_t *state)
{
    assert(state->reliable_size != UINT64_MAX);
    assert(state->received.num_ranges != 0);
    return state->received.ranges[0].start == 0 && state->reliable_size <= state->received.ranges[0].end;
}

void quicly_recvstate_init(quicly_recvstate_t *state)
{
    quicly_ranges_init_with_range(&state->received, 0, 0);
    state->data_off = 0;
    state->eos = UINT64_MAX;
    state->reliable_size = UINT64_MAX;
}

void quicly_recvstate_init_closed(quicly_recvstate_t *state)
{
    quicly_ranges_init(&state->received);
    state->data_off = 0;
    state->eos = 0;
    state->reliable_size = 0;
}

void quicly_recvstate_dispose(quicly_recvstate_t *state)
{
    quicly_ranges_clear(&state->received);
}

int quicly_recvstate_update(quicly_recvstate_t *state, uint64_t off, size_t *len, int is_fin, size_t max_ranges)
{
    int ret;

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
        if ((ret = quicly_ranges_add(&state->received, off, off + *len)) != 0)
            return ret;
        if (state->received.num_ranges > max_ranges)
            return QUICLY_ERROR_STATE_EXHAUSTION;
    }
    if (state->reliable_size == UINT64_MAX) {
        if (state->received.num_ranges == 1 && state->received.ranges[0].start == 0 && state->received.ranges[0].end == state->eos)
            goto Complete;
    } else {
        if (reliable_reset_is_satisfied(state))
            goto Complete;
    }

    return 0;

Complete:
    quicly_ranges_clear(&state->received);
    return 0;
}

int quicly_recvstate_reset(quicly_recvstate_t *state, uint64_t final_size, uint64_t reliable_size, uint64_t *bytes_missing)
{
    assert(!quicly_recvstate_transfer_complete(state));

    /* validate */
    if (state->eos != UINT64_MAX && state->eos != final_size)
        return QUICLY_TRANSPORT_ERROR_FINAL_SIZE;
    if (final_size < state->received.ranges[state->received.num_ranges - 1].end)
        return QUICLY_TRANSPORT_ERROR_FINAL_SIZE;

    /* calculate bytes missing */
    *bytes_missing = final_size - state->received.ranges[state->received.num_ranges - 1].end;

    state->reliable_size = reliable_size;

    /* if all stream bytes that have to be received have been received, clear the received range to indicate that */
    if (reliable_reset_is_satisfied(state)) {
        quicly_ranges_clear(&state->received);
    } else {
        /* otherwise, retain offsets to be used later when more STREAM frames are received */
        state->eos = final_size;
    }

    return 0;
}
