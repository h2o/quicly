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
#include "quicly/frame.h"
#include "test.h"

static void test_ack_decode(void)
{
    {
        uint8_t pat[] = {0xa0, 0, 0xfe, 0x34, 0x56, 0x78};
        quicly_ack_frame_t decoded;

        const uint8_t *src = pat + 1;
        ok(quicly_decode_ack_frame(pat[0], &src, pat + sizeof(pat), &decoded) == 0);
        ok(src == pat + sizeof(pat));
        ok(decoded.largest_acknowledged == 0xfe);
        ok(decoded.num_gaps == 0);
        ok(decoded.ack_delay == 0x3456);
        ok(decoded.ack_block_lengths[0] == 0x79);
        ok(decoded.smallest_acknowledged == 0xfe - 0x79 + 1);
    }

    {
        uint8_t pat[] = {0xb5, 2, 0, 0xfe, 0xdc, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};
        quicly_ack_frame_t decoded;

        const uint8_t *src = pat + 1;
        ok(quicly_decode_ack_frame(pat[0], &src, pat + sizeof(pat), &decoded) == 0);
        ok(src == pat + sizeof(pat));
        ok(decoded.largest_acknowledged == 0xfedc);
        ok(decoded.num_gaps == 2);
        ok(decoded.ack_delay == 0x1011);
        ok(decoded.ack_block_lengths[0] == 0x1214);
        ok(decoded.gaps[0] == 0x14);
        ok(decoded.ack_block_lengths[1] == 0x1516);
        ok(decoded.gaps[1] == 0x17);
        ok(decoded.ack_block_lengths[2] == 0x1819);
        ok(decoded.smallest_acknowledged == 0xfedc - 0x1214 - 0x14 - 0x1516 - 0x17 - 0x1819 + 1);
    }
}

static void test_ack_encode(void)
{
    quicly_ranges_t ranges;
    size_t range_index;
    quicly_ack_frame_encode_params_t params;
    uint8_t buf[256], *end;
    const uint8_t *src;
    quicly_ack_frame_t decoded;

    quicly_ranges_init(&ranges);
    quicly_ranges_update(&ranges, 0x12, 0x13);

    quicly_determine_encode_ack_frame_params(&ranges, &params);
    ok(params.largest_acknowledged_mode == 0);
    ok(params.block_length_mode == 0);
    range_index = 0;
    end = quicly_encode_ack_frame(buf, buf + sizeof(buf), &ranges, &range_index, &params);
    ok(end - buf == params.min_capacity_excluding_num_blocks);

    quicly_ranges_dispose(&ranges);

    src = buf + 1;
    ok(quicly_decode_ack_frame(src[-1], &src, end, &decoded) == 0);
    ok(src == end);
    ok(decoded.num_gaps == 0);
    ok(decoded.largest_acknowledged == 0x12);
    ok(decoded.ack_block_lengths[0] == 1);

    /* TODO add more */
}

static void test_mozquic(void)
{
    quicly_stream_frame_t frame;
    static const char *mess = "\xc5\0\0\0\0\0\0\xb6\x16\x03";
    const uint8_t *p = (void *)mess, type_flags = *p++;
    quicly_decode_stream_frame(type_flags, &p, p + 9, &frame);
}

void test_frame(void)
{
    subtest("ack-decode", test_ack_decode);
    subtest("ack-encode", test_ack_encode);
    subtest("mozquic", test_mozquic);
}
