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
#include <assert.h>
#include "quicly/frame.h"

void quicly_determine_encode_ack_frame_params(quicly_ranges_t *ranges, quicly_ack_frame_encode_params_t *params)
{
    static const unsigned encoding_mode[] = {3, 3, 3, 3, 2, 2, 1, 0, 0};

    assert(ranges->num_ranges != 0);

    params->largest_acknowledged_mode = encoding_mode[quicly_clz64(ranges->ranges[ranges->num_ranges - 1].end - 1) / 8];

    size_t i = ranges->num_ranges - 1;
    uint64_t max_ack_block_length = ranges->ranges[i].end - ranges->ranges[i].start - 1;
    if (i != 0) {
        do {
            --i;
            size_t bl = ranges->ranges[i].end - ranges->ranges[i].start;
            if (bl > max_ack_block_length)
                max_ack_block_length = bl;
        } while (i != 0);
    }

    params->block_length_mode = encoding_mode[quicly_clz64(max_ack_block_length) / 8];
    params->min_capacity_excluding_num_blocks = 1 + (1 << params->largest_acknowledged_mode) + 2 + (1 << params->block_length_mode);
}

uint8_t *quicly_encode_ack_frame(uint8_t *dst, uint8_t *dst_end, quicly_ranges_t *ranges, size_t *range_index,
                                 const quicly_ack_frame_encode_params_t *params)
{
    uint8_t type = QUICLY_FRAME_TYPE_ACK | (*range_index != 0 ? 0x10 : 0) | (params->largest_acknowledged_mode << 2) |
                   params->block_length_mode,
            *num_gaps_at = NULL;
    unsigned largest_acknowledged_length = 1 << params->largest_acknowledged_mode,
             block_length_length = 1 << params->block_length_mode;

    *dst++ = type;
    if (*range_index != 0) {
        num_gaps_at = dst++;
        *num_gaps_at = 0;
    }
    dst = quicly_encodev(dst, largest_acknowledged_length, ranges->ranges[*range_index].end - 1);
    dst = quicly_encode16(dst, 0); /* TODO ack_delay */
    dst = quicly_encodev(dst, block_length_length, ranges->ranges[*range_index].end - ranges->ranges[*range_index].start - 1);

    if (--*range_index != SIZE_MAX) {
        do {
            if (dst_end - dst < 1 + block_length_length)
                break;
            uint64_t gap = ranges->ranges[*range_index + 1].start - ranges->ranges[*range_index].end;
            if (gap > 255)
                break;
            *dst++ = gap;
            dst = quicly_encodev(dst, block_length_length, ranges->ranges[*range_index].end - ranges->ranges[*range_index].start);
            --*range_index;
            if (++*num_gaps_at == 255)
                break;
        } while (*range_index != SIZE_MAX);
    }

    return dst;
}

int quicly_decode_ack_frame(uint8_t type_flags, const uint8_t **src, const uint8_t *end, quicly_ack_frame_t *frame)
{
    unsigned largest_ack_size, ack_block_length_size, i;

    /* obtain num_gaps, num_ts, largest_ack_size, ack_block_size */
    if (end - *src < 4)
        return QUICLY_ERROR_INVALID_FRAME_DATA;
    if ((type_flags & 0x10) != 0) {
        frame->num_gaps = *(*src)++;
    } else {
        frame->num_gaps = 0;
    }
    largest_ack_size = 1 << (type_flags >> 2 & 3);
    ack_block_length_size = 1 << (type_flags & 3);

    /* size check */
    unsigned remaining = largest_ack_size + 2 + (1 + ack_block_length_size) * (frame->num_gaps + 1) - 1;
    if (end - *src < remaining)
        return QUICLY_ERROR_INVALID_FRAME_DATA;

    frame->largest_acknowledged = quicly_decodev(src, largest_ack_size);
    frame->ack_delay = quicly_decode16(src);

    frame->smallest_acknowledged = frame->largest_acknowledged + 1;
    frame->ack_block_lengths[0] = quicly_decodev(src, ack_block_length_size) + 1;
    frame->smallest_acknowledged -= frame->ack_block_lengths[0];
    for (i = 0; i != frame->num_gaps; ++i) {
        frame->gaps[i] = *(*src)++;
        frame->smallest_acknowledged -= frame->gaps[i];
        frame->ack_block_lengths[i + 1] = quicly_decodev(src, ack_block_length_size);
        frame->smallest_acknowledged -= frame->ack_block_lengths[i + 1];
    }

    return 0;
}
