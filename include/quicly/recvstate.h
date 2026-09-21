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
#ifndef quicly_recvstate_h
#define quicly_recvstate_h

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stddef.h>
#include "picotls.h"
#include "quicly/constants.h"
#include "quicly/ranges.h"

typedef struct st_quicly_recvstate_t {
    /**
     * ranges that have been received (starts and remains non-empty until transfer completes)
     */
    quicly_ranges_t received;
    /**
     * starting offset of data
     */
    uint64_t data_off;
    /**
     * end_of_stream offset (or UINT64_MAX)
     */
    uint64_t eos;
    /**
     * number of bytes that the peer remains committed to deliver even though the stream has been reset, as conveyed by the Reliable
     * Size field of the RESET_STREAM_AT frame (draft-ietf-quic-reliable-stream-reset); UINT64_MAX until a reset is received. Once
     * set, the transfer completes when all the bytes below this offset have been received, rather than when all the bytes below
     * `eos` have been received (section 5.3). A RESET_STREAM frame maps to a value of zero (section 5.2).
     */
    uint64_t reliable_size;
    /**
     * application protocol error code carried by the reset that has been received; meaningful only when `reliable_size` is not
     * UINT64_MAX. Retained so that a subsequent reset changing the value can be rejected (section 5.2 of the same draft).
     */
    uint64_t app_error_code;
} quicly_recvstate_t;

void quicly_recvstate_init(quicly_recvstate_t *state);
void quicly_recvstate_init_closed(quicly_recvstate_t *state);
void quicly_recvstate_dispose(quicly_recvstate_t *state);
static int quicly_recvstate_transfer_complete(quicly_recvstate_t *state);
static size_t quicly_recvstate_bytes_available(quicly_recvstate_t *state);
/**
 * Records that the range identified by (off, *len) has been received. When 0 (success) is returned, *len contains the number of
 * bytes that might have been newly received and therefore need to be written to the receive buffer (this number of bytes counts
 * backward from the end of given range).
 */
quicly_error_t quicly_recvstate_update(quicly_recvstate_t *state, uint64_t off, size_t *len, int is_fin, size_t max_ranges);
/**
 * Records the reception of a reset carrying the given final size and reliable size; see draft-ietf-quic-reliable-stream-reset.
 * `*bytes_missing` is set to the number of bytes below `eos_at` that will never be received, so that the caller can account for
 * them in connection-level flow control. Note that the transfer does not necessarily complete, as the peer remains committed to
 * delivering the bytes below `reliable_size`; use `quicly_recvstate_transfer_complete` to tell.
 */
quicly_error_t quicly_recvstate_reset_at(quicly_recvstate_t *state, uint64_t eos_at, uint64_t reliable_size,
                                         uint64_t *bytes_missing);
/**
 * Equivalent to calling `quicly_recvstate_reset_at` with `reliable_size` being zero, which is how a RESET_STREAM frame is handled.
 */
quicly_error_t quicly_recvstate_reset(quicly_recvstate_t *state, uint64_t eos_at, uint64_t *bytes_missing);

/* inline definitions */

inline int quicly_recvstate_transfer_complete(quicly_recvstate_t *state)
{
    return state->received.num_ranges == 0;
}

inline size_t quicly_recvstate_bytes_available(quicly_recvstate_t *state)
{
    uint64_t total;

    if (quicly_recvstate_transfer_complete(state)) {
        /* Once the transfer completes, every byte below `eos` is available, unless the stream has been reset with a smaller
         * reliable size, in which case only the bytes below that offset are guaranteed to have been received. The latter can be
         * below `data_off`, as bytes beyond the reliable size may have been consumed before the reset was received. */
        total = state->eos < state->reliable_size ? state->eos : state->reliable_size;
        if (total < state->data_off)
            total = state->data_off;
    } else {
        total = state->received.ranges[0].end;
    }

    assert(state->data_off <= total);
    return total - state->data_off;
}

#ifdef __cplusplus
}
#endif

#endif
