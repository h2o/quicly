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
#include "quicly/recvbuf.h"

void quicly_recvbuf_init(quicly_recvbuf_t *buf, quicly_recvbuf_change_cb on_change)
{
    quicly_ranges_init(&buf->received);
    quicly_ranges_update(&buf->received, 0, 0);
    quicly_buffer_init(&buf->data);
    buf->data_off = 0;
    buf->eos = UINT64_MAX;
    buf->on_change = on_change;
}

void quicly_recvbuf_dispose(quicly_recvbuf_t *buf)
{
    quicly_buffer_dispose(&buf->data);
    quicly_ranges_dispose(&buf->received);
}

int quicly_recvbuf_write(quicly_recvbuf_t *buf, uint64_t offset, const void *p, size_t len)
{
    int ret;

    if ((ret = quicly_ranges_update(&buf->received, offset, offset + len)) != 0)
        return ret;
    if ((ret = quicly_buffer_write(&buf->data, offset - buf->data_off, p, len)) != 0)
        return ret;
    return 0;
}

int quicly_recvbuf_mark_eos(quicly_recvbuf_t *buf, uint64_t eos_at)
{
    if (buf->eos == UINT64_MAX) {
        buf->eos = eos_at;
        return 0;
    }
    return buf->eos == eos_at ? 0 : QUICLY_ERROR_TBD;
}
