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
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "picotls.h"
#include "quicly/dump.h"

int quicly_dumpf(ptls_buffer_t *buf, const char *fmt, ...)
{
    va_list args;
    int ret;

    va_start(args, fmt);
    size_t space = buf->capacity - buf->off;
    int len = vsnprintf((char *)(buf->base + buf->off), buf->capacity - buf->off, fmt, args);
    va_end(args);

    if (len >= space) {
        if ((ret = ptls_buffer_reserve(buf, len + 1)) != 0)
            return ret;
        va_start(args, fmt);
        vsprintf((char *)(buf->base + buf->off), fmt, args);
        va_end(args);
    }

    buf->off += len;

    return 0;
}

int quicly_dumpstr(const char *s, ptls_buffer_t *buf)
{
    int ret;

    if (s != NULL) {
        /* FIXME handle quotes, non-printable chars */
        size_t len = strlen(s);
        if ((ret = ptls_buffer_reserve(buf, len + 3)) != 0)
            goto Exit;
        buf->base[buf->off++] = '"';
        memcpy(buf->base + buf->off, s, len);
        buf->off += len;
        buf->base[buf->off++] = '"';
        buf->base[buf->off] = '\0';
    } else {
        QUICLY_DUMPF("null");
    }

Exit:
    return 0;
}

int quicly_dumphex(const void *_base, size_t len, ptls_buffer_t *buf)
{
    const uint8_t *base = _base;
    size_t i;
    int ret;

    if (base == NULL) {
        QUICLY_DUMPF("null");
    } else {
        if ((ret = ptls_buffer_reserve(buf, len * 2 + 3)) != 0)
            return ret;
        buf->base[buf->off++] = '"';
        for (i = 0; i != len; ++i) {
            buf->base[buf->off++] = "0123456789abcdef"[base[i] >> 4];
            buf->base[buf->off++] = "0123456789abcdef"[base[i] & 0xf];
        }
        buf->base[buf->off++] = '"';
        buf->base[buf->off] = '\0';
    }

Exit:
    return ret;
}

int quicly_dump_sockaddr(struct sockaddr *sa, ptls_buffer_t *buf)
{
    int ret;

    switch (sa->sa_family) {
    case AF_INET: {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        uint32_t addr = ntohl(sin->sin_addr.s_addr);
        QUICLY_DUMPF("{\"address\": \"%" PRIu32 ".%" PRIu32 ".%" PRIu32 ".%" PRIu32 "\", \"port\": %" PRIu16 "}", addr >> 24,
                     (addr >> 16) & 255, (addr >> 8) & 255, addr & 255, ntohs(sin->sin_port));
    } break;
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
        QUICLY_DUMPF("{\"address\": ");
        QUICLY_DUMPHEX(sin6->sin6_addr.s6_addr, sizeof(sin6->sin6_addr.s6_addr));
        QUICLY_DUMPF(", \"port\": %" PRIu16 "}", ntohs(sin6->sin6_port));
    } break;
    default:
        QUICLY_DUMPF("{\"address\": \"unknown family\"}");
        break;
    }

Exit:
    return ret;
}

int quicly_dump_ranges(quicly_ranges_t *ranges, ptls_buffer_t *buf)
{
    size_t i;
    int ret;

    QUICLY_DUMPF("[");
    for (i = 0; i != ranges->num_ranges; ++i) {
        if (i != 0)
            QUICLY_DUMPF(", ");
        QUICLY_DUMPF("[%" PRIu64 ", %" PRIu64 "]", ranges->ranges[i].start, ranges->ranges[i].end);
    }
    QUICLY_DUMPF("]");

Exit:
    return ret;
}

int quicly_dump_maxsender(quicly_maxsender_t *sender, ptls_buffer_t *buf)
{
    int ret;

    if (sender != NULL) {
        QUICLY_DUMPF("{\"max_sent\": %" PRId64 ", \"max_acked\": %" PRId64 ", \"num_inflight\": %zu}", sender->max_sent,
                     sender->max_acked, sender->num_inflight);
    } else {
        QUICLY_DUMPF("null");
    }
Exit:
    return ret;
}

int quicly_dump_recvstate(quicly_recvstate_t *state, ptls_buffer_t *buf)
{
    int ret;

    QUICLY_DUMPF("{\"received\": ");
    QUICLY_DUMP_RANGES(&state->received);
    QUICLY_DUMPF(", \"data_off\": %" PRIu64 ", \"eos\": %" PRIu64 "}", state->data_off, state->eos);
Exit:
    return ret;
}

int quicly_dump_sendstate(quicly_sendstate_t *state, ptls_buffer_t *buf)
{
    int ret;

    QUICLY_DUMPF("{\"acked\": ");
    QUICLY_DUMP_RANGES(&state->acked);
    QUICLY_DUMPF(", \"pending\": ");
    QUICLY_DUMP_RANGES(&state->pending);
    QUICLY_DUMPF(", \"size_inflight\": %" PRIu64 ", \"final_size\": %" PRIu64 "}", state->size_inflight, state->final_size);
Exit:
    return ret;
}

int quicly_dump_sentmap(quicly_sentmap_t *map, ptls_buffer_t *buf)
{
    quicly_sentmap_iter_t iter;
    const quicly_sent_packet_t *sent_packet;
    int is_first = 1, ret;

    QUICLY_DUMPF("{\"entries\": [");
    for (quicly_sentmap_init_iter(map, &iter); (sent_packet = quicly_sentmap_get(&iter))->packet_number != UINT64_MAX;
         quicly_sentmap_skip(&iter)) {
        if (is_first) {
            is_first = 0;
        } else {
            QUICLY_DUMPF(", ");
        }
        QUICLY_DUMPF("{\"packet_number\": %" PRIu64 ", \"sent_at\": %" PRId64 ", \"ack_epoch\": %" PRIu8
                     ", \"bytes_in_flight\": %" PRIu16 ", \"frames\": \"TBD\"}",
                     sent_packet->packet_number, sent_packet->sent_at, sent_packet->ack_epoch, sent_packet->bytes_in_flight);
    }
    QUICLY_DUMPF("], \"bytes_in_flight\": %zu}", map->bytes_in_flight);

Exit:
    return ret;
}

int quicly_dump_cid_plaintext(const quicly_cid_plaintext_t *cid, ptls_buffer_t *buf)
{
    int ret;

    QUICLY_DUMPF("{\"master_id\": %" PRIu32 ", \"path_id\": %" PRIu32 ", \"thread_id\": %" PRIu32 ", \"node_id\": \"%016" PRIx64
                 "\"}",
                 cid->master_id, cid->path_id, cid->thread_id, cid->node_id);
Exit:
    return ret;
}

int quicly_dump_sender_state(quicly_sender_state_t *state, ptls_buffer_t *buf)
{
    const char *s;

    if (state == NULL) {
        s = NULL;
    } else {
        switch (*state) {
        case QUICLY_SENDER_STATE_NONE:
            s = "none";
            break;
        case QUICLY_SENDER_STATE_SEND:
            s = "send";
            break;
        case QUICLY_SENDER_STATE_UNACKED:
            s = "unacked";
            break;
        case QUICLY_SENDER_STATE_ACKED:
            s = "acked";
            break;
        }
    }

    return quicly_dumpstr(s, buf);
}
