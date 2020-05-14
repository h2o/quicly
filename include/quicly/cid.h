/*
 * Copyright (c) 2020 Fastly, Inc.
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

#ifndef cid_h
#define cid_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>
#include "picotls.h"
#include "quicly/constants.h"

typedef struct st_quicly_cid_t quicly_cid_t;

struct st_quicly_cid_t {
    uint8_t cid[QUICLY_MAX_CID_LEN_V1];
    uint8_t len;
};

static void quicly_set_cid(quicly_cid_t *dest, ptls_iovec_t src);
static int quicly_cid_is_equal(const quicly_cid_t *cid, ptls_iovec_t vec);

inline int quicly_cid_is_equal(const quicly_cid_t *cid, ptls_iovec_t vec)
{
    return cid->len == vec.len && memcmp(cid->cid, vec.base, vec.len) == 0;
}

inline void quicly_set_cid(quicly_cid_t *dest, ptls_iovec_t src)
{
    memcpy(dest->cid, src.base, src.len);
    dest->len = src.len;
}

#ifdef __cplusplus
}
#endif

#endif
