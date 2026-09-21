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

static void test_ack_decode_underflow(void)
{
    quicly_ack_frame_t decoded;

    { /* ack pn=0 */
        const uint8_t pat[] = {0, 0, 0, 0}, *src = pat;
        ok(quicly_decode_ack_frame(&src, pat + sizeof(pat), &decoded, 0) == 0);
        ok(src == pat + sizeof(pat));
        ok(decoded.largest_acknowledged == 0);
        ok(decoded.num_gaps == 0);
        ok(decoded.ack_block_lengths[0] == 1);
        ok(decoded.smallest_acknowledged == 0);
    }
    { /* underflow in first block length */
        const uint8_t pat[] = {0, 0, 0, 1}, *src = pat;
        ok(quicly_decode_ack_frame(&src, pat + sizeof(pat), &decoded, 0) != 0);
    }

    { /* frame with gap going down to pn=0 */
        const uint8_t pat[] = {2, 0, 1, 0, 0, 0}, *src = pat;
        ok(quicly_decode_ack_frame(&src, pat + sizeof(pat), &decoded, 0) == 0);
        ok(src == pat + sizeof(pat));
        ok(decoded.largest_acknowledged == 2);
        ok(decoded.num_gaps == 1);
        ok(decoded.ack_block_lengths[0] == 1);
        ok(decoded.ack_block_lengths[1] == 1);
        ok(decoded.smallest_acknowledged == 0);
    }

    { /* additional block length going negative */
        const uint8_t pat[] = {2, 0, 1, 0, 0, 1}, *src = pat;
        ok(quicly_decode_ack_frame(&src, pat + sizeof(pat), &decoded, 0) != 0);
    }
    { /* gap going negative */
        const uint8_t pat[] = {2, 0, 1, 0, 3, 0}, *src = pat;
        ok(quicly_decode_ack_frame(&src, pat + sizeof(pat), &decoded, 0) != 0);
    }
}

static void test_ack_decode(void)
{
    {
        const uint8_t pat[] = {0x34, 0x00, 0x00, 0x11}, *src = pat;
        quicly_ack_frame_t decoded;
        ok(quicly_decode_ack_frame(&src, pat + sizeof(pat), &decoded, 0) == 0);
        ok(src == pat + sizeof(pat));
        ok(decoded.largest_acknowledged == 0x34);
        ok(decoded.num_gaps == 0);
        ok(decoded.ack_block_lengths[0] == 0x12);
        ok(decoded.smallest_acknowledged == 0x34 - 0x12 + 1);
    }

    {
        const uint8_t pat[] = {0x34, 0x00, 0x02, 0x00, 0x01, 0x02, 0x03, 0x04}, *src = pat;
        quicly_ack_frame_t decoded;
        ok(quicly_decode_ack_frame(&src, pat + sizeof(pat), &decoded, 0) == 0);
        ok(src == pat + sizeof(pat));
        ok(decoded.largest_acknowledged == 0x34);
        ok(decoded.num_gaps == 2);
        ok(decoded.ack_block_lengths[0] == 1);
        ok(decoded.gaps[0] == 2);
        ok(decoded.ack_block_lengths[1] == 3);
        ok(decoded.gaps[1] == 4);
        ok(decoded.ack_block_lengths[2] == 5);
        ok(decoded.smallest_acknowledged == 0x34 - 1 - 2 - 3 - 4 - 5 + 1);
    }

    { /* Bogus ACK Frame larger than the internal buffer */
        uint8_t pat[1024], *end = pat;
        const uint8_t *src = pat;
        uint64_t i, range_sum;
        quicly_ack_frame_t decoded;
        end = quicly_encodev(end, 0xFA00);
        end = quicly_encodev(end, 0);
        end = quicly_encodev(end, QUICLY_ACK_MAX_GAPS + 30); // with excess ranges
        end = quicly_encodev(end, 8);
        for (i = 0; i < QUICLY_ACK_MAX_GAPS + 30; ++i) {
            end = quicly_encodev(end, i);      // gap
            end = quicly_encodev(end, i % 10); // ack-range
        }

        ok(quicly_decode_ack_frame(&src, end, &decoded, 0) == 0);
        ok(decoded.largest_acknowledged == 0xFA00);
        ok(decoded.ack_delay == 0);
        ok(decoded.num_gaps == QUICLY_ACK_MAX_GAPS);
        ok(decoded.ack_block_lengths[0] == 8 + 1); // first ack-range
        range_sum = decoded.ack_block_lengths[0];
        for (i = 0; i < decoded.num_gaps; ++i) {
            ok(decoded.gaps[i] == i + 1);
            ok(decoded.ack_block_lengths[i + 1] == (i % 10) + 1);
            range_sum += decoded.gaps[i] + decoded.ack_block_lengths[i + 1];
        }
        ok(src == end); // decoded the entire frame
        ok(decoded.smallest_acknowledged == 0xFA00 - range_sum + 1);
    }

    subtest("underflow", test_ack_decode_underflow);
}

static void test_ack_encode(void)
{
    quicly_ranges_t ranges;
    uint8_t buf[256], *end;
    const uint8_t *src;
    quicly_ack_frame_t decoded;
    uint64_t ecn_counts[3] = {};

    quicly_ranges_init(&ranges);
    quicly_ranges_add(&ranges, 0x12, 0x14);

    /* encode */
    end = quicly_encode_ack_frame(buf, buf + sizeof(buf), &ranges, ecn_counts, 63);
    ok(end - buf == 5);
    /* decode */
    src = buf + 1;
    ok(quicly_decode_ack_frame(&src, end, &decoded, 0) == 0);
    ok(src == end);
    ok(decoded.ack_delay == 63);
    ok(decoded.num_gaps == 0);
    ok(decoded.largest_acknowledged == 0x13);
    ok(decoded.ack_block_lengths[0] == 2);
    ok(decoded.ecn_counts[0] == 0);
    ok(decoded.ecn_counts[1] == 0);
    ok(decoded.ecn_counts[2] == 0);

    quicly_ranges_add(&ranges, 0x10, 0x11);
    ecn_counts[0] = 12;
    ecn_counts[1] = 34;
    ecn_counts[2] = 56;

    /* encode */
    end = quicly_encode_ack_frame(buf, buf + sizeof(buf), &ranges, ecn_counts, 63);
    ok(end - buf == 10);
    /* decode */
    src = buf + 1;
    ok(quicly_decode_ack_frame(&src, end, &decoded, 1) == 0);
    ok(src == end);
    ok(decoded.ack_delay == 63);
    ok(decoded.num_gaps == 1);
    ok(decoded.largest_acknowledged == 0x13);
    ok(decoded.ack_block_lengths[0] == 2);
    ok(decoded.gaps[0] == 1);
    ok(decoded.ack_block_lengths[1] == 1);
    ok(decoded.ecn_counts[0] == 12);
    ok(decoded.ecn_counts[1] == 34);
    ok(decoded.ecn_counts[2] == 56);

    quicly_ranges_clear(&ranges);
}

static void test_reset_stream_at_boundaries(void)
{
    static const uint64_t values[] = {0, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903};

    for (size_t i = 0; i != PTLS_ELEMENTSOF(values); ++i) {
        uint64_t value = values[i];
        size_t expected_size = 1 + 4 * quicly_encodev_capacity(value);
        uint8_t buf[QUICLY_RST_AT_FRAME_CAPACITY], *end;
        const uint8_t *src;
        quicly_reset_stream_at_frame_t decoded;

        ok(expected_size <= QUICLY_RST_AT_FRAME_CAPACITY);
        end = quicly_encode_reset_stream_at_frame(buf, value, value, value, value);
        ok((size_t)(end - buf) == expected_size);
        src = buf + 1;
        ok(quicly_decode_reset_stream_at_frame(&src, end, &decoded) == 0);
        ok(src == end);
        ok(decoded.stream_id == value);
        ok(decoded.app_error_code == value);
        ok(decoded.final_size == value);
        ok(decoded.reliable_size == value);
    }
}

static void test_reset_stream_at_reliable_size(void)
{
    uint8_t buf[QUICLY_RST_AT_FRAME_CAPACITY], *end;
    const uint8_t *src;
    quicly_reset_stream_at_frame_t decoded;

    { /* nothing to deliver */
        end = quicly_encode_reset_stream_at_frame(buf, 4, 0, 1000, 0);
        src = buf + 1;
        ok(quicly_decode_reset_stream_at_frame(&src, end, &decoded) == 0);
        ok(src == end);
        ok(decoded.reliable_size == 0);
    }

    { /* everything to deliver */
        end = quicly_encode_reset_stream_at_frame(buf, 4, 0, 1000, 1000);
        src = buf + 1;
        ok(quicly_decode_reset_stream_at_frame(&src, end, &decoded) == 0);
        ok(src == end);
        ok(decoded.final_size == 1000);
        ok(decoded.reliable_size == 1000);
    }

    { /* reliable size beyond final size */
        end = quicly_encode_reset_stream_at_frame(buf, 4, 0, 1000, 1001);
        src = buf + 1;
        ok(quicly_decode_reset_stream_at_frame(&src, end, &decoded) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
    }
}

static void test_reset_stream_at_truncated(void)
{
    uint8_t buf[QUICLY_RST_AT_FRAME_CAPACITY];
    uint8_t *end = quicly_encode_reset_stream_at_frame(buf, 12, 1017, 1000000, 65535);

    for (size_t size = 1; size < (size_t)(end - buf); ++size) {
        const uint8_t *src = buf + 1;
        quicly_reset_stream_at_frame_t decoded;
        ok(quicly_decode_reset_stream_at_frame(&src, buf + size, &decoded) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
    }
}

static void test_reset_stream_at_codec(void)
{
    uint8_t buf[QUICLY_RST_AT_FRAME_CAPACITY], *end;
    const uint8_t *src;
    quicly_reset_stream_at_frame_t decoded;

    end = quicly_encode_reset_stream_at_frame(buf, 12, 1017, 1000000, 65535);
    ok(buf[0] == QUICLY_FRAME_TYPE_RESET_STREAM_AT);
    ok(end - buf == 1 + 1 + 2 + 4 + 4);
    src = buf + 1;
    ok(quicly_decode_reset_stream_at_frame(&src, end, &decoded) == 0);
    ok(src == end);
    ok(decoded.stream_id == 12);
    ok(decoded.app_error_code == 1017);
    ok(decoded.final_size == 1000000);
    ok(decoded.reliable_size == 65535);

    subtest("boundaries", test_reset_stream_at_boundaries);
    subtest("reliable-size", test_reset_stream_at_reliable_size);
    subtest("truncated", test_reset_stream_at_truncated);
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
    subtest("reset-stream-at", test_reset_stream_at_codec);
    subtest("mozquic", test_mozquic);
}
