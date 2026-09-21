/*
 * Copyright (c) 2026 Fastly, Zac Shenker
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
#include "quicly/sendstate.h"
#include "test.h"

#define CHECK_RANGES(r, ...)                                                                                                       \
    do {                                                                                                                           \
        static const struct st_quicly_range_t expected[] = {__VA_ARGS__};                                                          \
        ok((r)->num_ranges == PTLS_ELEMENTSOF(expected));                                                                          \
        size_t i;                                                                                                                  \
        for (i = 0; i != (r)->num_ranges && i != PTLS_ELEMENTSOF(expected); ++i) {                                                 \
            ok((r)->ranges[i].start == expected[i].start);                                                                         \
            ok((r)->ranges[i].end == expected[i].end);                                                                             \
        }                                                                                                                          \
    } while (0)

/**
 * Builds a state in which `size_inflight` bytes have been sent at least once, the application having more data to write.
 */
static void init_with_sent(quicly_sendstate_t *state, uint64_t size_inflight)
{
    int ret;

    quicly_sendstate_init(state);
    ret = quicly_sendstate_activate(state);
    ok(ret == 0);
    ret = quicly_ranges_subtract(&state->pending, 0, size_inflight);
    ok(ret == 0);
    state->size_inflight = size_inflight;
}

static void record_lost(quicly_sendstate_t *state, uint64_t start, uint64_t end)
{
    quicly_sendstate_sent_t args = {start, end};
    int ret = quicly_sendstate_lost(state, &args);
    ok(ret == 0);
}

static size_t record_acked(quicly_sendstate_t *state, uint64_t start, uint64_t end)
{
    quicly_sendstate_sent_t args = {start, end};
    size_t bytes_to_shift;
    int ret = quicly_sendstate_acked(state, &args, &bytes_to_shift);
    ok(ret == 0);
    return bytes_to_shift;
}

static int ranges_are_equal(quicly_ranges_t *x, quicly_ranges_t *y)
{
    size_t i;

    if (x->num_ranges != y->num_ranges)
        return 0;
    for (i = 0; i != x->num_ranges; ++i)
        if (x->ranges[i].start != y->ranges[i].start || x->ranges[i].end != y->ranges[i].end)
            return 0;
    return 1;
}

/**
 * A Reliable Size of zero is logically equivalent to a reset without partial delivery.
 */
static void test_reliable_size_zero(void)
{
    quicly_sendstate_t reset, reset_at;
    int ret;

    init_with_sent(&reset, 1000);
    init_with_sent(&reset_at, 1000);
    record_acked(&reset, 0, 200);
    record_acked(&reset_at, 0, 200);
    record_lost(&reset, 400, 600);
    record_lost(&reset_at, 400, 600);
    ok(ranges_are_equal(&reset.acked, &reset_at.acked));
    ok(ranges_are_equal(&reset.pending, &reset_at.pending));

    quicly_sendstate_reset(&reset);
    ret = quicly_sendstate_reset_at(&reset_at, 0);
    ok(ret == 0);

    ok(reset.final_size == reset_at.final_size);
    ok(reset.size_inflight == reset_at.size_inflight);
    ok(ranges_are_equal(&reset.acked, &reset_at.acked));
    ok(reset_at.pending.num_ranges == 0);
    ok(ranges_are_equal(&reset.pending, &reset_at.pending));
    ok(quicly_sendstate_transfer_complete(&reset));
    ok(quicly_sendstate_transfer_complete(&reset_at));

    quicly_sendstate_dispose(&reset);
    quicly_sendstate_dispose(&reset_at);
}

/**
 * Bytes below the Reliable Size continue to be sent and retransmitted, while the ones above are dropped.
 */
static void test_retain_below_reliable_size(void)
{
    quicly_sendstate_t state;
    int ret;

    init_with_sent(&state, 1000);
    record_acked(&state, 0, 200);
    record_lost(&state, 200, 400);
    record_lost(&state, 700, 900);
    CHECK_RANGES(&state.pending, {200, 400}, {700, 900}, {1000, UINT64_MAX});

    ret = quicly_sendstate_reset_at(&state, 600);
    ok(ret == 0);
    ok(state.final_size == 1000);
    CHECK_RANGES(&state.pending, {200, 400});
    CHECK_RANGES(&state.acked, {0, 200}, {600, 1001});
    ok(!quicly_sendstate_transfer_complete(&state));

    /* a loss below the Reliable Size is scheduled for retransmission, one at or above it is not */
    record_lost(&state, 400, 600);
    CHECK_RANGES(&state.pending, {200, 600});
    record_lost(&state, 600, 1000);
    CHECK_RANGES(&state.pending, {200, 600});

    /* the transfer completes once all the bytes below the Reliable Size are acked, the send buffer being fully retired */
    ok(record_acked(&state, 200, 400) == 200);
    ok(!quicly_sendstate_transfer_complete(&state));
    ok(record_acked(&state, 400, 600) == 600);
    ok(state.pending.num_ranges == 0);
    ok(quicly_sendstate_transfer_complete(&state));

    quicly_sendstate_dispose(&state);
}

/**
 * The Reliable Size can be reduced by a second reset, dropping the bytes that are no longer to be delivered.
 */
static void test_lower_reliable_size(void)
{
    quicly_sendstate_t state;
    int ret;

    init_with_sent(&state, 1000);
    record_acked(&state, 0, 100);
    record_lost(&state, 100, 300);
    record_lost(&state, 400, 600);

    ret = quicly_sendstate_reset_at(&state, 700);
    ok(ret == 0);
    CHECK_RANGES(&state.pending, {100, 300}, {400, 600});
    CHECK_RANGES(&state.acked, {0, 100}, {700, 1001});

    ret = quicly_sendstate_reset_at(&state, 500);
    ok(ret == 0);
    CHECK_RANGES(&state.pending, {100, 300}, {400, 500});
    CHECK_RANGES(&state.acked, {0, 100}, {500, 1001});
    ok(!quicly_sendstate_transfer_complete(&state));

    /* the final size does not change, and reducing the Reliable Size to zero is identical to a plain reset */
    ret = quicly_sendstate_reset_at(&state, 0);
    ok(ret == 0);
    ok(state.final_size == 1000);
    ok(state.pending.num_ranges == 0);
    CHECK_RANGES(&state.acked, {0, 1001});
    ok(quicly_sendstate_transfer_complete(&state));

    quicly_sendstate_dispose(&state);
}

/**
 * A Reliable Size equal to the final size retains every byte of the stream.
 */
static void test_reliable_size_eq_final_size(void)
{
    quicly_sendstate_t state;
    int ret;

    init_with_sent(&state, 1000);
    ret = quicly_ranges_subtract(&state.pending, 1000, UINT64_MAX); /* the application wrote 1000 bytes in total */
    ok(ret == 0);

    ret = quicly_sendstate_reset_at(&state, 1000);
    ok(ret == 0);
    ok(state.final_size == 1000);
    ok(state.pending.num_ranges == 0);
    ok(!quicly_sendstate_transfer_complete(&state));

    record_lost(&state, 0, 1000);
    CHECK_RANGES(&state.pending, {0, 1000});
    ok(record_acked(&state, 0, 1000) == 1000);
    ok(quicly_sendstate_transfer_complete(&state));

    quicly_sendstate_dispose(&state);
}

/**
 * The transfer completes at once if every byte below the Reliable Size has already been acked.
 */
static void test_already_acked(void)
{
    quicly_sendstate_t state;
    int ret;

    init_with_sent(&state, 1000);
    record_acked(&state, 0, 600);

    ret = quicly_sendstate_reset_at(&state, 600);
    ok(ret == 0);
    ok(state.pending.num_ranges == 0);
    CHECK_RANGES(&state.acked, {0, 1001});
    ok(quicly_sendstate_transfer_complete(&state));

    quicly_sendstate_dispose(&state);
}

/**
 * Resetting a stream that has been shut down without the FIN bit having been sent reduces the final size to the amount of data that
 * has been sent, as that is the value that the RESET_STREAM_AT frame declares.
 */
static void test_after_shutdown(void)
{
    quicly_sendstate_t state;
    int ret;

    init_with_sent(&state, 400);
    ret = quicly_sendstate_shutdown(&state, 1000);
    ok(ret == 0);
    record_lost(&state, 100, 200);
    CHECK_RANGES(&state.pending, {100, 200}, {400, 1001});

    ret = quicly_sendstate_reset_at(&state, 300);
    ok(ret == 0);
    ok(state.final_size == 400);
    CHECK_RANGES(&state.pending, {100, 200});
    CHECK_RANGES(&state.acked, {0, 0}, {300, 401});
    ok(!quicly_sendstate_transfer_complete(&state));

    record_acked(&state, 100, 200);
    ok(!quicly_sendstate_transfer_complete(&state));
    ok(record_acked(&state, 0, 100) == 200);
    ok(!quicly_sendstate_transfer_complete(&state));
    ok(record_acked(&state, 200, 300) == 200);
    ok(quicly_sendstate_transfer_complete(&state));

    quicly_sendstate_dispose(&state);
}

/**
 * The Reliable Size may cover bytes that have not been sent yet; those bytes become pending.
 */
static void test_above_size_inflight(void)
{
    quicly_sendstate_t state;
    int ret;

    init_with_sent(&state, 400);
    record_lost(&state, 100, 200);
    CHECK_RANGES(&state.pending, {100, 200}, {400, UINT64_MAX});

    ret = quicly_sendstate_reset_at(&state, 600);
    ok(ret == 0);
    ok(state.final_size == 600);
    CHECK_RANGES(&state.pending, {100, 200}, {400, 600});
    CHECK_RANGES(&state.acked, {0, 0}, {600, 601});
    ok(!quicly_sendstate_transfer_complete(&state));

    /* reducing the Reliable Size before the frame is sent reduces the final size as well */
    ret = quicly_sendstate_reset_at(&state, 500);
    ok(ret == 0);
    ok(state.final_size == 500);
    CHECK_RANGES(&state.pending, {100, 200}, {400, 500});
    CHECK_RANGES(&state.acked, {0, 0}, {500, 501});

    ok(record_acked(&state, 0, 100) == 100);
    record_acked(&state, 100, 200);
    ok(!quicly_sendstate_transfer_complete(&state));
    ok(record_acked(&state, 200, 500) == 300);
    ok(quicly_sendstate_transfer_complete(&state));

    quicly_sendstate_dispose(&state);

    /* the bytes are committed to even when `pending` does not already extend above `size_inflight` */
    init_with_sent(&state, 400);
    ret = quicly_ranges_subtract(&state.pending, 400, UINT64_MAX);
    ok(ret == 0);
    ok(state.pending.num_ranges == 0);

    ret = quicly_sendstate_reset_at(&state, 600);
    ok(ret == 0);
    ok(state.final_size == 600);
    CHECK_RANGES(&state.pending, {400, 600});
    ok(record_acked(&state, 0, 600) == 600);
    ok(quicly_sendstate_transfer_complete(&state));

    quicly_sendstate_dispose(&state);
}

void test_sendstate(void)
{
    subtest("reliable-size-zero", test_reliable_size_zero);
    subtest("retain-below-reliable-size", test_retain_below_reliable_size);
    subtest("lower-reliable-size", test_lower_reliable_size);
    subtest("reliable-size-eq-final-size", test_reliable_size_eq_final_size);
    subtest("already-acked", test_already_acked);
    subtest("after-shutdown", test_after_shutdown);
    subtest("above-size-inflight", test_above_size_inflight);
}
