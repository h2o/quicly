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
#ifndef quicly_streambuf_h
#define quicly_streambuf_h

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include "picotls.h"
#include "quicly.h"

typedef struct st_quicly_streambuf_sendvec_t quicly_streambuf_sendvec_t;

/**
 * Callback that flattens the contents of an iovec.
 * @param dst the destination
 * @param off offset within the iovec from where serialization should happen
 * @param len number of bytes to serialize
 * @return 0 if successful, otherwise an error code
 */
typedef int (*quicly_streambuf_sendvec_flatten_cb)(quicly_streambuf_sendvec_t *vec, void *dst, size_t off, size_t len);
/**
 * An optional callback that is called when an iovec is discarded
 */
typedef void (*quicly_streambuf_sendvec_discard_cb)(quicly_streambuf_sendvec_t *vec);

typedef struct st_quicly_streambuf_sendvec_callbacks_t {
    quicly_streambuf_sendvec_flatten_cb flatten;
    quicly_streambuf_sendvec_discard_cb discard;
} quicly_streambuf_sendvec_callbacks_t;

struct st_quicly_streambuf_sendvec_t {
    const quicly_streambuf_sendvec_callbacks_t *cb;
    void *cbdata;
    size_t len;
};

/**
 * The simple stream buffer.  The API assumes that stream->data points to quicly_streambuf_t.  Applications can extend the structure
 * by passing arbitrary size to `quicly_streambuf_create`.
 */
typedef struct st_quicly_streambuf_t {
    struct {
        struct {
            quicly_streambuf_sendvec_t *entries;
            size_t size, capacity;
        } vecs;
        size_t off_in_first_vec;
        uint64_t bytes_written;
    } egress;
    ptls_buffer_t ingress;
} quicly_streambuf_t;

int quicly_streambuf_create(quicly_stream_t *stream, size_t sz);
void quicly_streambuf_destroy(quicly_stream_t *stream, int err);
void quicly_streambuf_egress_shift(quicly_stream_t *stream, size_t delta);
int quicly_streambuf_egress_emit(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all);
int quicly_streambuf_egress_write(quicly_stream_t *stream, const void *src, size_t len);
int quicly_streambuf_egress_write_vec(quicly_stream_t *stream, const quicly_streambuf_sendvec_callbacks_t *cb, void *cbdata,
                                      size_t len);
int quicly_streambuf_egress_shutdown(quicly_stream_t *stream);
void quicly_streambuf_ingress_shift(quicly_stream_t *stream, size_t delta);
ptls_iovec_t quicly_streambuf_ingress_get(quicly_stream_t *stream);
int quicly_streambuf_ingress_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);

#ifdef __cplusplus
}
#endif

#endif
