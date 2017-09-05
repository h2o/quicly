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
#include "quicly/maxsender.h"

uint32_t quicly_maxsender_should_update_stream_id(quicly_maxsender_t *m, uint32_t next_stream_id, uint32_t num_open_streams,
                                                  uint32_t initial_max_stream_id, uint32_t update_ratio)
{
    uint32_t avail_sent, avail_actual, send_value;

    /* round-up */
    next_stream_id = (next_stream_id + 1) & 0xfffffffe;

    avail_sent = m->max_sent >= next_stream_id - 2 ? (uint32_t)m->max_sent - (next_stream_id - 2) : 0;
    avail_actual = initial_max_stream_id - num_open_streams * 2;

    /* ratio check */
    if (((uint64_t)avail_actual * update_ratio) / 1024 < avail_sent)
        return 0;

    /* calculate the actual value to send as well as making adjustments */
    send_value = next_stream_id + avail_actual - 2;
    if (send_value >= 0xfffffffe)
        send_value = 0xfffffffe;

    /* do not send one value more than once */
    if (send_value == m->max_sent)
        return 0;

    return (uint32_t)send_value;
}
