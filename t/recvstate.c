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
#include "quicly/recvstate.h"
#include "test.h"

#define MAX_RANGES 64

/**
 * receives `len` bytes at `off`, asserting that all of them are to be applied
 */
static void receive(quicly_recvstate_t *state, uint64_t off, size_t len, int is_fin)
{
    size_t apply_len = len;
    ok(quicly_recvstate_update(state, off, &apply_len, is_fin, MAX_RANGES) == 0);
    ok(apply_len == len);
}

static void test_reset_reliable_size_zero(void)
{
    quicly_recvstate_t legacy, at;
    uint64_t legacy_missing, at_missing;

    /* drive the two states identically, then reset one through `quicly_recvstate_reset` and the other through
     * `quicly_recvstate_reset_at` with a reliable size of zero; the two are expected to be equivalent */
    quicly_recvstate_init(&legacy);
    quicly_recvstate_init(&at);
    receive(&legacy, 0, 10, 0);
    receive(&at, 0, 10, 0);
    receive(&legacy, 20, 10, 0);
    receive(&at, 20, 10, 0);

    ok(quicly_recvstate_reset(&legacy, 100, &legacy_missing) == 0);
    ok(quicly_recvstate_reset_at(&at, 100, 0, &at_missing) == 0);

    ok(legacy_missing == 70); /* 100 - 30 */
    ok(at_missing == legacy_missing);
    ok(quicly_recvstate_transfer_complete(&legacy));
    ok(quicly_recvstate_transfer_complete(&at));
    ok(at.received.num_ranges == legacy.received.num_ranges);
    ok(at.data_off == legacy.data_off);
    ok(at.eos == legacy.eos);
    ok(at.reliable_size == legacy.reliable_size);
    ok(quicly_recvstate_bytes_available(&at) == quicly_recvstate_bytes_available(&legacy));

    quicly_recvstate_dispose(&legacy);
    quicly_recvstate_dispose(&at);
}

static void test_retain_prefix(void)
{
    quicly_recvstate_t state;
    uint64_t bytes_missing;

    quicly_recvstate_init(&state);
    receive(&state, 0, 10, 0);
    receive(&state, 60, 10, 0);

    ok(quicly_recvstate_reset_at(&state, 100, 50, &bytes_missing) == 0);
    ok(bytes_missing == 30); /* offsets [70, 100) are the ones that have been given up on */
    ok(state.eos == 100);
    ok(state.reliable_size == 50);

    /* the prefix below the reliable size is retained, whereas the range above it is absorbed into the offsets that are no longer
     * expected to be delivered */
    ok(state.received.num_ranges == 2);
    ok(state.received.ranges[0].start == 0);
    ok(state.received.ranges[0].end == 10);
    ok(state.received.ranges[1].start == 50);
    ok(state.received.ranges[1].end == 100);

    /* the transfer is incomplete while [10, 50) is outstanding */
    ok(!quicly_recvstate_transfer_complete(&state));
    ok(quicly_recvstate_bytes_available(&state) == 10);

    quicly_recvstate_dispose(&state);
}

static void test_receive_after_reset(void)
{
    quicly_recvstate_t state;
    uint64_t bytes_missing;

    quicly_recvstate_init(&state);
    receive(&state, 0, 10, 0);

    ok(quicly_recvstate_reset_at(&state, 100, 50, &bytes_missing) == 0);
    ok(bytes_missing == 90);
    ok(!quicly_recvstate_transfer_complete(&state));

    /* a fragment that does not close the gap below the reliable size keeps the transfer incomplete */
    receive(&state, 20, 10, 0);
    ok(!quicly_recvstate_transfer_complete(&state));
    ok(quicly_recvstate_bytes_available(&state) == 10);

    /* data beyond the reliable size is accepted rather than being rejected as a final size error */
    receive(&state, 80, 10, 0);
    ok(!quicly_recvstate_transfer_complete(&state));

    /* the FIN can arrive after the reset, as long as it agrees on the final size */
    receive(&state, 90, 10, 1);
    ok(!quicly_recvstate_transfer_complete(&state));

    receive(&state, 10, 10, 0);
    ok(!quicly_recvstate_transfer_complete(&state)); /* [0, 30) received, but the reliable size is 50 */

    /* closing the gap below the reliable size completes the transfer, and only the bytes below that offset are reported */
    receive(&state, 30, 20, 0);
    ok(quicly_recvstate_transfer_complete(&state));
    ok(quicly_recvstate_bytes_available(&state) == 50);

    quicly_recvstate_dispose(&state);
}

static void test_reset_lowering_reliable_size(void)
{
    quicly_recvstate_t state;
    uint64_t bytes_missing;

    quicly_recvstate_init(&state);
    receive(&state, 0, 20, 0);
    ok(quicly_recvstate_reset_at(&state, 100, 50, &bytes_missing) == 0);
    ok(bytes_missing == 80);
    ok(!quicly_recvstate_transfer_complete(&state));

    /* lowering the reliable size shrinks the prefix that is still expected */
    ok(quicly_recvstate_reset_at(&state, 100, 30, &bytes_missing) == 0);
    ok(bytes_missing == 0); /* every offset below the final size has already been accounted for */
    ok(state.reliable_size == 30);
    ok(!quicly_recvstate_transfer_complete(&state));
    ok(state.received.num_ranges == 2);
    ok(state.received.ranges[0].end == 20);
    ok(state.received.ranges[1].start == 30);

    /* lowering it to an offset that has already been received completes the transfer at once */
    ok(quicly_recvstate_reset_at(&state, 100, 20, &bytes_missing) == 0);
    ok(bytes_missing == 0);
    ok(quicly_recvstate_transfer_complete(&state));
    ok(quicly_recvstate_bytes_available(&state) == 20);

    quicly_recvstate_dispose(&state);
}

static void test_reset_raising_reliable_size(void)
{
    quicly_recvstate_t state;
    uint64_t bytes_missing;

    quicly_recvstate_init(&state);
    receive(&state, 0, 10, 0);
    ok(quicly_recvstate_reset_at(&state, 100, 30, &bytes_missing) == 0);
    ok(bytes_missing == 90);

    /* reordering can deliver a greater reliable size afterwards; such a reset is ignored rather than being an error */
    ok(quicly_recvstate_reset_at(&state, 100, 60, &bytes_missing) == 0);
    ok(bytes_missing == 0);
    ok(state.reliable_size == 30);
    ok(state.received.num_ranges == 2);
    ok(state.received.ranges[1].start == 30);
    ok(!quicly_recvstate_transfer_complete(&state));

    /* a repetition of the same reliable size changes nothing either */
    ok(quicly_recvstate_reset_at(&state, 100, 30, &bytes_missing) == 0);
    ok(bytes_missing == 0);
    ok(state.reliable_size == 30);
    ok(state.received.ranges[1].start == 30);

    /* whereas a RESET_STREAM, being equivalent to a reliable size of zero, is accepted and completes the transfer */
    ok(quicly_recvstate_reset(&state, 100, &bytes_missing) == 0);
    ok(bytes_missing == 0);
    ok(state.reliable_size == 0);
    ok(quicly_recvstate_transfer_complete(&state));
    ok(quicly_recvstate_bytes_available(&state) == 0);

    quicly_recvstate_dispose(&state);
}

static void test_reliable_size_is_final_size(void)
{
    quicly_recvstate_t state;
    uint64_t bytes_missing;

    quicly_recvstate_init(&state);
    receive(&state, 0, 10, 0);

    /* a reliable size equal to the final size commits the peer to delivering the entire stream, hence nothing is given up on */
    ok(quicly_recvstate_reset_at(&state, 30, 30, &bytes_missing) == 0);
    ok(bytes_missing == 0);
    ok(state.eos == 30);
    ok(state.reliable_size == 30);
    ok(!quicly_recvstate_transfer_complete(&state));
    ok(state.received.num_ranges == 1);
    ok(state.received.ranges[0].end == 10);

    receive(&state, 10, 20, 0);
    ok(quicly_recvstate_transfer_complete(&state));
    ok(quicly_recvstate_bytes_available(&state) == 30);

    quicly_recvstate_dispose(&state);
}

static void test_final_size_errors(void)
{
    quicly_recvstate_t state;
    uint64_t bytes_missing;
    size_t apply_len;

    /* a reset cannot give a final size below the offsets that have been received */
    quicly_recvstate_init(&state);
    receive(&state, 0, 10, 0);
    ok(quicly_recvstate_reset_at(&state, 5, 5, &bytes_missing) == QUICLY_TRANSPORT_ERROR_FINAL_SIZE);
    quicly_recvstate_dispose(&state);

    /* nor can it change a final size that is already known */
    quicly_recvstate_init(&state);
    receive(&state, 0, 10, 0);
    ok(quicly_recvstate_reset_at(&state, 100, 50, &bytes_missing) == 0);
    ok(quicly_recvstate_reset_at(&state, 101, 50, &bytes_missing) == QUICLY_TRANSPORT_ERROR_FINAL_SIZE);
    ok(quicly_recvstate_reset_at(&state, 99, 50, &bytes_missing) == QUICLY_TRANSPORT_ERROR_FINAL_SIZE);

    /* neither can a FIN that arrives after the reset */
    apply_len = 10;
    ok(quicly_recvstate_update(&state, 80, &apply_len, 1, MAX_RANGES) == QUICLY_TRANSPORT_ERROR_FINAL_SIZE);
    apply_len = 10;
    ok(quicly_recvstate_update(&state, 100, &apply_len, 1, MAX_RANGES) == QUICLY_TRANSPORT_ERROR_FINAL_SIZE);
    quicly_recvstate_dispose(&state);
}

void test_recvstate(void)
{
    subtest("reset-reliable-size-zero", test_reset_reliable_size_zero);
    subtest("retain-prefix", test_retain_prefix);
    subtest("receive-after-reset", test_receive_after_reset);
    subtest("reset-lowering-reliable-size", test_reset_lowering_reliable_size);
    subtest("reset-raising-reliable-size", test_reset_raising_reliable_size);
    subtest("reliable-size-is-final-size", test_reliable_size_is_final_size);
    subtest("final-size-errors", test_final_size_errors);
}
