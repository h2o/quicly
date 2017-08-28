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
#ifndef quicly_frame_h
#define quicly_frame_h

#include <stddef.h>
#include <stdint.h>
#include "picotls.h"
#include "quicly/error.h"
#include "quicly/ranges.h"

#define QUICLY_FRAME_TYPE_PADDING 0
#define QUICLY_FRAME_TYPE_RST_STREAM 1
#define QUICLY_FRAME_TYPE_MAX_DATA 4
#define QUICLY_FRAME_TYPE_MAX_STREAM_DATA 5
#define QUICLY_FRAME_TYPE_STOP_SENDING 0xc
#define QUICLY_FRAME_TYPE_STREAM 0xc0
#define QUICLY_FRAME_TYPE_STREAM_BIT_FIN 0x20
#define QUICLY_FRAME_TYPE_STREAM_BIT_DATA_LENGTH 1
#define QUICLY_FRAME_TYPE_ACK 0xa0

#define QUICLY_MAX_DATA_FRAME_SIZE (1 + 8)
#define QUICLY_MAX_STREAM_DATA_FRAME_SIZE (1 + 4 + 8)
#define QUICLY_RST_FRAME_SIZE (1 + 4 + 4 + 8)
#define QUICLY_STOP_SENDING_FRAME_SIZE (1 + 4 + 4)

static uint16_t quicly_decode16(const uint8_t **src);
static uint32_t quicly_decode32(const uint8_t **src);
static uint64_t quicly_decode64(const uint8_t **src);
static uint64_t quicly_decodev(const uint8_t **src, size_t size);
static uint8_t *quicly_encode16(uint8_t *p, uint16_t v);
static uint8_t *quicly_encode32(uint8_t *p, uint32_t v);
static uint8_t *quicly_encode64(uint8_t *p, uint64_t v);
static uint8_t *quicly_encodev(uint8_t *p, size_t size, uint64_t v);
static unsigned quicly_clz32(uint32_t v);
static unsigned quicly_clz64(uint64_t v);

static void quicly_determine_stream_frame_field_lengths(uint32_t stream_id, uint64_t offset, size_t *stream_id_length,
                                                        size_t *offset_length);
static uint8_t *quicly_encode_stream_frame_header(uint8_t *dst, int is_fin, uint32_t stream_id, size_t stream_id_length,
                                                  uint64_t offset, size_t offset_length, size_t data_length);

typedef struct st_quicly_stream_frame_t {
    uint32_t stream_id;
    unsigned is_fin : 1;
    uint64_t offset;
    ptls_iovec_t data;
} quicly_stream_frame_t;

static int quicly_decode_stream_frame(uint8_t type_flags, const uint8_t **src, const uint8_t *end, quicly_stream_frame_t *frame);

static uint8_t *quicly_encode_rst_stream_frame(uint8_t *dst, uint32_t stream_id, uint32_t reason, uint64_t final_offset);

typedef struct st_quicly_rst_stream_frame {
    uint32_t stream_id;
    uint32_t reason;
    uint64_t final_offset;
} quicly_rst_stream_frame_t;

static int quicly_decode_rst_stream_frame(const uint8_t **src, const uint8_t *end, quicly_rst_stream_frame_t *frame);

static uint8_t *quicly_encode_max_data_frame(uint8_t *dst, uint64_t max_data_kb);

typedef struct st_quicly_max_data_frame_t {
    uint64_t max_data_kb;
} quicly_max_data_frame_t;

static int quicly_decode_max_data_frame(const uint8_t **src, const uint8_t *end, quicly_max_data_frame_t *frame);

static uint8_t *quicly_encode_max_stream_data_frame(uint8_t *dst, uint32_t stream_id, uint64_t max_stream_data);

typedef struct st_quicly_max_stream_data_frame_t {
    uint32_t stream_id;
    uint64_t max_stream_data;
} quicly_max_stream_data_frame_t;

static int quicly_decode_max_stream_data_frame(const uint8_t **src, const uint8_t *end, quicly_max_stream_data_frame_t *frame);

static uint8_t *quicly_encode_stop_sending_frame(uint8_t *dst, uint32_t stream_id, uint32_t reason);

typedef struct st_quicly_stop_sending_frame_t {
    uint32_t stream_id;
    uint32_t reason;
} quicly_stop_sending_frame_t;

static int quicly_decode_stop_sending_frame(const uint8_t **src, const uint8_t *end, quicly_stop_sending_frame_t *frame);

typedef struct st_quicly_ack_frame_encode_params_t {
    unsigned largest_acknowledged_mode;
    unsigned block_length_mode;
    size_t min_capacity_excluding_num_blocks;
} quicly_ack_frame_encode_params_t;

void quicly_determine_encode_ack_frame_params(quicly_ranges_t *ranges, quicly_ack_frame_encode_params_t *params);
static size_t quicly_ack_frame_get_minimum_capacity(quicly_ack_frame_encode_params_t *params, size_t range_index);
uint8_t *quicly_encode_ack_frame(uint8_t *dst, uint8_t *dst_end, quicly_ranges_t *ranges, size_t *range_index,
                                 const quicly_ack_frame_encode_params_t *params);

typedef struct st_quicly_ack_frame_t {
    uint64_t largest_acknowledged;
    uint64_t smallest_acknowledged;
    uint16_t ack_delay;
    uint8_t num_gaps;
    uint64_t ack_block_lengths[257];
    uint8_t gaps[256];
} quicly_ack_frame_t;

int quicly_decode_ack_frame(uint8_t type_flags, const uint8_t **src, const uint8_t *end, quicly_ack_frame_t *frame);

/* inline definitions */

inline uint16_t quicly_decode16(const uint8_t **src)
{
    uint16_t v = (uint16_t)(*src)[0] << 8 | (*src)[1];
    *src += 2;
    return v;
}

inline uint32_t quicly_decode32(const uint8_t **src)
{
    uint32_t v = (uint32_t)(*src)[0] << 24 | (uint32_t)(*src)[1] << 16 | (uint32_t)(*src)[2] << 8 | (*src)[3];
    *src += 4;
    return v;
}

inline uint64_t quicly_decode64(const uint8_t **src)
{
    uint64_t v = (uint64_t)(*src)[0] << 56 | (uint64_t)(*src)[1] << 48 | (uint64_t)(*src)[2] << 40 | (uint64_t)(*src)[3] << 32 |
                 (uint64_t)(*src)[4] << 24 | (uint64_t)(*src)[5] << 16 | (uint64_t)(*src)[6] << 8 | (*src)[7];
    *src += 8;
    return v;
}

inline uint64_t quicly_decodev(const uint8_t **src, size_t size)
{
    uint64_t v = 0;

    do {
        v = v << 8 | *(*src)++;
    } while (--size != 0);
    return v;
}

inline uint8_t *quicly_encode16(uint8_t *p, uint16_t v)
{
    *p++ = (uint8_t)(v >> 8);
    *p++ = (uint8_t)v;
    return p;
}

inline uint8_t *quicly_encode32(uint8_t *p, uint32_t v)
{
    *p++ = (uint8_t)(v >> 24);
    *p++ = (uint8_t)(v >> 16);
    *p++ = (uint8_t)(v >> 8);
    *p++ = (uint8_t)v;
    return p;
}

inline uint8_t *quicly_encode64(uint8_t *p, uint64_t v)
{
    *p++ = (uint8_t)(v >> 56);
    *p++ = (uint8_t)(v >> 48);
    *p++ = (uint8_t)(v >> 40);
    *p++ = (uint8_t)(v >> 32);
    *p++ = (uint8_t)(v >> 24);
    *p++ = (uint8_t)(v >> 16);
    *p++ = (uint8_t)(v >> 8);
    *p++ = (uint8_t)v;
    return p;
}

inline uint8_t *quicly_encodev(uint8_t *p, size_t size, uint64_t v)
{
    size *= 8;
    do {
        size -= 8;
        *p++ = (uint8_t)(v >> size);
    } while (size != 0);
    return p;
}

inline unsigned quicly_clz32(uint32_t v)
{
    QUICLY_BUILD_ASSERT(sizeof(unsigned) == 4);
    return v != 0 ? __builtin_clz(v) : 32;
}

inline unsigned quicly_clz64(uint64_t v)
{
    QUICLY_BUILD_ASSERT(sizeof(long long) == 8);
    return v != 0 ? __builtin_clzll(v) : 64;
}

inline void quicly_determine_stream_frame_field_lengths(uint32_t stream_id, uint64_t offset, size_t *stream_id_length,
                                                        size_t *offset_length)
{
    static const unsigned stream_id_length_table[] = {4, 3, 2, 1, 1};
    static const uint8_t offset_length_table[] = {8, 8, 4, 2, 0};

    *stream_id_length = stream_id_length_table[quicly_clz32(stream_id) / 8];
    *offset_length = offset_length_table[quicly_clz64(offset) / 16];
}

inline uint8_t *quicly_encode_stream_frame_header(uint8_t *dst, int is_fin, uint32_t stream_id, size_t stream_id_length,
                                                  uint64_t offset, size_t offset_length, size_t data_length)
{
    *dst++ = QUICLY_FRAME_TYPE_STREAM | is_fin << 5 | (stream_id_length - 1) << 3 | offset_length | data_length <= UINT16_MAX;
    dst = quicly_encodev(dst, stream_id_length, stream_id);
    if (offset_length != 0)
        dst = quicly_encodev(dst, offset_length, offset);
    if (data_length <= UINT16_MAX)
        dst = quicly_encode16(dst, data_length);
    return dst;
}

inline int quicly_decode_stream_frame(uint8_t type_flags, const uint8_t **src, const uint8_t *end, quicly_stream_frame_t *frame)
{
    { /* obtain stream_id */
        unsigned stream_id_length = ((type_flags >> 3) & 3) + 1;
        if (end - *src < stream_id_length)
            return QUICLY_ERROR_INVALID_FRAME_DATA;
        frame->stream_id = (uint32_t)quicly_decodev(src, stream_id_length);
    }

    { /* obtain offset */
        unsigned offset_mode = type_flags >> 1 & 3;
        if (offset_mode == 0) {
            frame->offset = 0;
        } else {
            unsigned offset_length = 1 << offset_mode;
            if (end - *src < offset_length)
                return QUICLY_ERROR_INVALID_FRAME_DATA;
            frame->offset = quicly_decodev(src, offset_length);
        }
    }

    /* obtain data */
    if ((type_flags & QUICLY_FRAME_TYPE_STREAM_BIT_DATA_LENGTH) != 0) {
        if (end - *src < 2)
            return QUICLY_ERROR_INVALID_FRAME_DATA;
        uint16_t data_length = quicly_decode16(src);
        if (end - *src < data_length)
            return QUICLY_ERROR_INVALID_FRAME_DATA;
        frame->data = ptls_iovec_init(*src, data_length);
        *src += data_length;
    } else {
        frame->data = ptls_iovec_init(*src, end - *src);
        *src = end;
    }

    /* fin bit */
    frame->is_fin = (type_flags & QUICLY_FRAME_TYPE_STREAM_BIT_FIN) != 0;
    if (!frame->is_fin && frame->data.len == 0)
        return QUICLY_ERROR_EMPTY_STREAM_FRAME_NO_FIN;

    return 0;
}

inline uint8_t *quicly_encode_rst_stream_frame(uint8_t *dst, uint32_t stream_id, uint32_t reason, uint64_t final_offset)
{
    *dst++ = QUICLY_FRAME_TYPE_RST_STREAM;
    dst = quicly_encode32(dst, stream_id);
    dst = quicly_encode32(dst, reason);
    dst = quicly_encode64(dst, final_offset);
    return dst;
}

inline int quicly_decode_rst_stream_frame(const uint8_t **src, const uint8_t *end, quicly_rst_stream_frame_t *frame)
{
    if (end - *src < 4 + 4 + 8)
        return QUICLY_ERROR_INVALID_FRAME_DATA;
    frame->stream_id = quicly_decode32(src);
    frame->reason = quicly_decode32(src);
    frame->final_offset = quicly_decode64(src);
    return 0;
}

inline uint8_t *quicly_encode_max_data_frame(uint8_t *dst, uint64_t max_data_kb)
{
    *dst++ = QUICLY_FRAME_TYPE_MAX_DATA;
    dst = quicly_encode64(dst, max_data_kb);
    return dst;
}

inline int quicly_decode_max_data_frame(const uint8_t **src, const uint8_t *end, quicly_max_data_frame_t *frame)
{
    if (end - *src < 8)
        return QUICLY_ERROR_INVALID_FRAME_DATA;
    frame->max_data_kb = quicly_decode64(src);
    return 0;
}

inline uint8_t *quicly_encode_max_stream_data_frame(uint8_t *dst, uint32_t stream_id, uint64_t max_stream_data)
{
    *dst++ = QUICLY_FRAME_TYPE_MAX_STREAM_DATA;
    dst = quicly_encode32(dst, stream_id);
    dst = quicly_encode64(dst, max_stream_data);
    return dst;
}

inline int quicly_decode_max_stream_data_frame(const uint8_t **src, const uint8_t *end, quicly_max_stream_data_frame_t *frame)
{
    if (end - *src < 4 + 8)
        return QUICLY_ERROR_INVALID_FRAME_DATA;
    frame->stream_id = quicly_decode32(src);
    frame->max_stream_data = quicly_decode64(src);
    return 0;
}

inline uint8_t *quicly_encode_stop_sending_frame(uint8_t *dst, uint32_t stream_id, uint32_t reason)
{
    *dst++ = QUICLY_FRAME_TYPE_STOP_SENDING;
    dst = quicly_encode32(dst, stream_id);
    dst = quicly_encode32(dst, reason);
    return dst;
}

inline int quicly_decode_stop_sending_frame(const uint8_t **src, const uint8_t *end, quicly_stop_sending_frame_t *frame)
{
    if (end - *src < 4 + 4)
        return QUICLY_ERROR_INVALID_FRAME_DATA;
    frame->stream_id = quicly_decode32(src);
    frame->reason = quicly_decode32(src);
    return 0;
}

inline size_t quicly_ack_frame_get_minimum_capacity(quicly_ack_frame_encode_params_t *params, size_t range_index)
{
    return params->min_capacity_excluding_num_blocks + (range_index != 0);
}

#endif
