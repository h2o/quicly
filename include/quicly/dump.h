/*
 * Copyright (c) 2019 Fastly, Kazuho Oku
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
#ifndef quicly_dump_h
#define quicly_dump_h

#include <sys/types.h>
#include <sys/socket.h>
#include "picotls.h"
#include "quicly.h"
#include "quicly/sentmap.h"

#define QUICLY_DUMPF(...)                                                                                                          \
    do {                                                                                                                           \
        if ((ret = quicly_dumpf(buf, __VA_ARGS__)) != 0)                                                                           \
            goto Exit;                                                                                                             \
    } while (0)
#define QUICLY__DUMP_FUNC(func, ...)                                                                                               \
    do {                                                                                                                           \
        if ((ret = func(__VA_ARGS__, buf)) != 0)                                                                                   \
            goto Exit;                                                                                                             \
    } while (0)

int quicly_dumpf(ptls_buffer_t *buf, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
int quicly_dumpstr(const char *s, ptls_buffer_t *buf);
#define QUICLY_DUMPSTR(s) QUICLY__DUMP_FUNC(quicly_dumpstr, (s))
int quicly_dumphex(const void *base, size_t len, ptls_buffer_t *buf);
#define QUICLY_DUMPHEX(base, len) QUICLY__DUMP_FUNC(quicly_dumphex, (base), (len))
int quicly_dump_sockaddr(struct sockaddr *sa, ptls_buffer_t *buf);
#define QUICLY_DUMP_SOCKADDR(sa) QUICLY__DUMP_FUNC(quicly_dump_sockaddr, (sa))
int quicly_dump_ranges(quicly_ranges_t *ranges, ptls_buffer_t *buf);
#define QUICLY_DUMP_RANGES(ranges) QUICLY__DUMP_FUNC(quicly_dump_ranges, (ranges))
int quicly_dump_maxsender(quicly_maxsender_t *sender, ptls_buffer_t *buf);
#define QUICLY_DUMP_MAXSENDER(sender) QUICLY__DUMP_FUNC(quicly_dump_maxsender, (sender))
int quicly_dump_recvstate(quicly_recvstate_t *state, ptls_buffer_t *buf);
#define QUICLY_DUMP_RECVSTATE(state) QUICLY__DUMP_FUNC(quicly_dump_recvstate, (state))
int quicly_dump_sendstate(quicly_sendstate_t *state, ptls_buffer_t *buf);
#define QUICLY_DUMP_SENDSTATE(state) QUICLY__DUMP_FUNC(quicly_dump_sendstate, (state))
int quicly_dump_sentmap(quicly_sentmap_t *map, ptls_buffer_t *buf);
#define QUICLY_DUMP_SENTMAP(map) QUICLY__DUMP_FUNC(quicly_dump_sentmap, (map))
int quicly_dump_cid_plaintext(const quicly_cid_plaintext_t *cid, ptls_buffer_t *buf);
#define QUICLY_DUMP_CID_PLAINTEXT(cid) QUICLY__DUMP_FUNC(quicly_dump_cid_plaintext, (cid))
int quicly_dump_sender_state(quicly_sender_state_t *state, ptls_buffer_t *buf);
#define QUICLY_DUMP_SENDER_STATE(state) QUICLY__DUMP_FUNC(quicly_dump_sender_state, (state))

#endif
