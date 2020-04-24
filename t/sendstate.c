/*
 * Copyright (c) 2020 Fastly, Kazuho Oku
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
#include "test.h"
#include "../lib/sendstate.c"

static void test_reduction(void)
{
    static const size_t packet_size = 10;
    quicly_sendstate_t s;
    int ret;

    quicly_sendstate_init(&s);
    quicly_sendstate_activate(&s);

    /* send 128 packets */
    ret = quicly_ranges_subtract(&s.pending, 0, packet_size * max_ranges * 4);
    assert(ret == 0);

    /* sack every odd-numbered packet */
    size_t i;
    for (i = 0; i < max_ranges * 2; ++i) {
        quicly_sendstate_sent_t sent = {
            .start = i * packet_size,
            .end = (i + 1) * packet_size,
        };
        if (i % 2 == 0) {
            ret = quicly_sendstate_lost(&s, &sent);
            ok(ret == 0);
        } else {
            size_t bytes_to_shift = 0x55555555;
            ret = quicly_sendstate_acked(&s, &sent, 1, &bytes_to_shift);
            ok(ret == 0);
            ok(bytes_to_shift == 0);
        }
        ok(s.acked.num_ranges <= max_ranges);
        ok(s.pending.num_ranges <= max_ranges);
    }

    ok(s.acked.num_ranges == max_ranges);
    ok(s.acked.ranges[0].start == 0);
    ok(s.acked.ranges[0].end == 0);
    for (i = 1; i < max_ranges; ++i) {
        ok(s.acked.ranges[i].start == (i * 2 - 1) * packet_size);
        ok(s.acked.ranges[i].end == i * 2 * packet_size);
    }

    ok(s.pending.num_ranges == max_ranges);
    for (i = 0; i < max_ranges - 1; ++i) {
        ok(s.pending.ranges[i].start == i * 2 * packet_size);
        ok(s.pending.ranges[i].end == (i * 2 + 1) * packet_size);
    }
    ok(s.pending.ranges[max_ranges - 1].start == (max_ranges - 1) * 2 * packet_size);
    ok(s.pending.ranges[max_ranges - 1].end == UINT64_MAX);

    quicly_sendstate_dispose(&s);
}

void test_sendstate(void)
{
    subtest("reduction", test_reduction);
}
