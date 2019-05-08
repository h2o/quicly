/*
 * Copyright (c) 2018 Fastly, Kazuho Oku
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
#include <stdlib.h>
#include <string.h>
#include "quicly/streambuf.h"

int quicly_streambuf_create(quicly_stream_t *stream, size_t sz)
{
    quicly_streambuf_t *sbuf;

    assert(sz >= sizeof(*sbuf));
    assert(stream->data == NULL);

    if ((sbuf = malloc(sz)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    memset(&sbuf->egress, 0, sizeof(sbuf->egress));
    ptls_buffer_init(&sbuf->ingress, "", 0);
    if (sz != sizeof(*sbuf))
        memset((char *)sbuf + sizeof(*sbuf), 0, sz - sizeof(*sbuf));

    stream->data = sbuf;
    return 0;
}

void quicly_streambuf_destroy(quicly_stream_t *stream, int err)
{
    quicly_streambuf_t *sbuf = stream->data;
    size_t i;

    for (i = 0; i != sbuf->egress.vecs.size; ++i) {
        quicly_streambuf_sendvec_t *vec = sbuf->egress.vecs.entries + i;
        if (vec->cb->discard != NULL)
            vec->cb->discard(vec);
    }
    free(sbuf->egress.vecs.entries);
    ptls_buffer_dispose(&sbuf->ingress);
    free(sbuf);
    stream->data = NULL;
}

void quicly_streambuf_egress_shift(quicly_stream_t *stream, size_t delta)
{
    quicly_streambuf_t *sbuf = stream->data;
    size_t i;

    for (i = 0; delta != 0; ++i) {
        assert(i < sbuf->egress.vecs.size);
        quicly_streambuf_sendvec_t *first_vec = sbuf->egress.vecs.entries + i;
        size_t bytes_in_first_vec = first_vec->len - sbuf->egress.off_in_first_vec;
        if (delta < bytes_in_first_vec) {
            sbuf->egress.off_in_first_vec += delta;
            break;
        }
        delta -= bytes_in_first_vec;
        if (first_vec->cb->discard != NULL)
            first_vec->cb->discard(first_vec);
        sbuf->egress.off_in_first_vec = 0;
    }
    if (i != 0) {
        if (sbuf->egress.vecs.size != i) {
            memmove(sbuf->egress.vecs.entries, sbuf->egress.vecs.entries + i,
                    (sbuf->egress.vecs.size - i) * sizeof(*sbuf->egress.vecs.entries));
            sbuf->egress.vecs.size -= i;
        } else {
            free(sbuf->egress.vecs.entries);
            sbuf->egress.vecs.entries = NULL;
            sbuf->egress.vecs.size = 0;
            sbuf->egress.vecs.capacity = 0;
        }
    }
    quicly_stream_sync_sendbuf(stream, 0);
}

int quicly_streambuf_egress_emit(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all)
{
    quicly_streambuf_t *sbuf = stream->data;
    size_t vec_index, capacity = *len;
    int ret;

    off += sbuf->egress.off_in_first_vec;
    for (vec_index = 0; capacity != 0 && vec_index < sbuf->egress.vecs.size; ++vec_index) {
        quicly_streambuf_sendvec_t *vec = sbuf->egress.vecs.entries + vec_index;
        if (off < vec->len) {
            size_t bytes_flatten = vec->len - off;
            int partial = 0;
            if (capacity < bytes_flatten) {
                bytes_flatten = capacity;
                partial = 1;
            }
            if ((ret = vec->cb->flatten(vec, dst, off, bytes_flatten)) != 0)
                return ret;
            dst = (uint8_t *)dst + bytes_flatten;
            capacity -= bytes_flatten;
            off = 0;
            if (partial)
                break;
        } else {
            off -= vec->len;
        }
    }

    if (capacity == 0 && vec_index < sbuf->egress.vecs.size) {
        *wrote_all = 0;
    } else {
        *len = *len - capacity;
        *wrote_all = 1;
    }

    return 0;
}

int quicly_streambuf_egress_write_vec(quicly_stream_t *stream, const quicly_streambuf_sendvec_callbacks_t *cb, void *cbdata,
                                      size_t len)
{
    quicly_streambuf_t *sbuf = stream->data;

    assert(sbuf->egress.vecs.size <= sbuf->egress.vecs.capacity);

    if (sbuf->egress.vecs.size == sbuf->egress.vecs.capacity) {
        quicly_streambuf_sendvec_t *new_entries;
        size_t new_capacity = sbuf->egress.vecs.capacity == 0 ? 4 : sbuf->egress.vecs.capacity * 2;
        if ((new_entries = realloc(sbuf->egress.vecs.entries, new_capacity * sizeof(*sbuf->egress.vecs.entries))) == NULL)
            return PTLS_ERROR_NO_MEMORY;
        sbuf->egress.vecs.entries = new_entries;
        sbuf->egress.vecs.capacity = new_capacity;
    }
    sbuf->egress.vecs.entries[sbuf->egress.vecs.size++] = (quicly_streambuf_sendvec_t){cb, cbdata, len};
    sbuf->egress.bytes_written += len;

    return quicly_stream_sync_sendbuf(stream, 1);
}

static int flatten_raw(quicly_streambuf_sendvec_t *vec, void *dst, size_t off, size_t len)
{
    memcpy(dst, (uint8_t *)vec->cbdata + off, len);
    return 0;
}

static void discard_raw(quicly_streambuf_sendvec_t *vec)
{
    free(vec->cbdata);
}

int quicly_streambuf_egress_write(quicly_stream_t *stream, const void *src, size_t len)
{
    static const quicly_streambuf_sendvec_callbacks_t raw_callbacks = {flatten_raw, discard_raw};
    char *bytes = NULL;
    int ret;

    assert(quicly_sendstate_is_open(&stream->sendstate));

    if ((bytes = malloc(len)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Error;
    }
    memcpy(bytes, src, len);
    if ((ret = quicly_streambuf_egress_write_vec(stream, &raw_callbacks, bytes, len)) != 0)
        goto Error;
    return 0;

Error:
    free(bytes);
    return ret;
}

int quicly_streambuf_egress_shutdown(quicly_stream_t *stream)
{
    quicly_streambuf_t *sbuf = stream->data;
    quicly_sendstate_shutdown(&stream->sendstate, sbuf->egress.bytes_written);
    return quicly_stream_sync_sendbuf(stream, 1);
}

void quicly_streambuf_ingress_shift(quicly_stream_t *stream, size_t delta)
{
    quicly_streambuf_t *sbuf = stream->data;

    assert(delta <= sbuf->ingress.off);
    sbuf->ingress.off -= delta;
    memmove(sbuf->ingress.base, sbuf->ingress.base + delta, sbuf->ingress.off);

    quicly_stream_sync_recvbuf(stream, delta);
}

ptls_iovec_t quicly_streambuf_ingress_get(quicly_stream_t *stream)
{
    quicly_streambuf_t *sbuf = (quicly_streambuf_t *)stream->data;
    size_t avail;

    if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
        avail = sbuf->ingress.off;
    } else if (stream->recvstate.data_off < stream->recvstate.received.ranges[0].end) {
        avail = stream->recvstate.received.ranges[0].end - stream->recvstate.data_off;
    } else {
        avail = 0;
    }

    return ptls_iovec_init(sbuf->ingress.base, avail);
}

int quicly_streambuf_ingress_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    quicly_streambuf_t *sbuf = stream->data;

    if (len != 0) {
        int ret;
        if ((ret = ptls_buffer_reserve(&sbuf->ingress, off + len - sbuf->ingress.off)) != 0)
            return ret;
        memcpy(sbuf->ingress.base + off, src, len);
        if (sbuf->ingress.off < off + len)
            sbuf->ingress.off = off + len;
    }
    return 0;
}
