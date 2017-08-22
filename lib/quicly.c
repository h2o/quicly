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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "khash.h"
#include "quicly.h"
#include "quicly/ack.h"

#define QUICLY_PROTOCOL_VERSION 0xff000005

#define QUICLY_PACKET_TYPE_VERSION_NEGOTIATION 1
#define QUICLY_PACKET_TYPE_CLIENT_INITIAL 2
#define QUICLY_PACKET_TYPE_SERVER_STATELESS_RETRY 3
#define QUICLY_PACKET_TYPE_SERVER_CLEARTEXT 4
#define QUICLY_PACKET_TYPE_CLIENT_CLEARTEXT 5
#define QUICLY_PACKET_TYPE_0RTT_PROTECTED 6
#define QUICLY_PACKET_TYPE_1RTT_KEY_PHASE_0 7
#define QUICLY_PACKET_TYPE_1RTT_KEY_PHASE_1 8
#define QUICLY_PACKET_TYPE_PUBLIC_RESET 8
#define QUICLY_PACKET_TYPE_IS_VALID(type) ((uint8_t)(type)-1 < QUICLY_PACKET_TYPE_PUBLIC_RESET)

#define QUICLY_STREAM_HEADER_SIZE_MAX 14 /* (datalen16 + streamid32 + offset64) */

#define QUICLY_FRAME_TYPE_PADDING 0
#define QUICLY_FRAME_TYPE_MAX_STREAM_DATA 5
#define QUICLY_FRAME_TYPE_STREAM 0xc0
#define QUICLY_FRAME_TYPE_STREAM_BIT_FIN 0x20
#define QUICLY_FRAME_TYPE_STREAM_BIT_DATA_LENGTH 1
#define QUICLY_FRAME_TYPE_ACK 0xa0

#define QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS 26
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA 0
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_DATA 1
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_ID 2
#define QUICLY_TRANSPORT_PARAMETER_ID_IDLE_TIMEOUT 3
#define QUICLY_TRANSPORT_PARAMETER_ID_TRUNCATE_CONNECTION_ID 4

#define GET_TYPE_FROM_PACKET_HEADER(p) (*(uint8_t *)(p)&0x1f)

KHASH_MAP_INIT_INT(quicly_stream_t, quicly_stream_t *)

#define QUICLY_DEBUG_LOG(conn, stream_id, ...)                                                                                     \
    if (0) {                                                                                                                       \
        quicly_conn_t *c = (conn);                                                                                                 \
        char buf[1024];                                                                                                            \
        snprintf(buf, sizeof(buf), __VA_ARGS__);                                                                                   \
        fprintf(stderr, "%s:%p,%" PRIu32 ": %s\n", quicly_is_client(c) ? "client" : "server", (c), (stream_id), buf);              \
    }

struct st_quicly_packet_protection_t {
    uint64_t packet_number;
    struct {
        ptls_aead_context_t *early_data;
        ptls_aead_context_t *key_phase0;
        ptls_aead_context_t *key_phase1;
    } aead;
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
};

struct st_quicly_conn_t {
    struct _st_quicly_conn_public_t super;
    /**
     * hashtable of streams
     */
    khash_t(quicly_stream_t) * streams;
    struct {
        /**
         * crypto parameters
         */
        struct st_quicly_packet_protection_t pp;
        /**
         * acks to be sent to peer
         */
        struct st_quicly_ranges_t ack_queue;
    } ingress;
    struct {
        /**
         * crypto parameters
         */
        struct st_quicly_packet_protection_t pp;
        /**
         * contains actions that needs to be performed when an ack is being received
         */
        quicly_acks_t acks;
        /**
         *
         */
        uint64_t packet_number;
        /**
         *
         */
        unsigned acks_require_encryption : 1;
    } egress;
};

struct st_quicly_crypto_stream_data_t {
    quicly_conn_t *conn;
    ptls_t *tls;
    ptls_handshake_properties_t handshake_properties;
    struct {
        ptls_raw_extension_t ext[2];
        ptls_buffer_t buf;
    } transport_parameters;
};

struct st_quicly_decoded_frame_t {
    uint8_t type;
    union {
        struct {
            uint32_t stream_id;
            unsigned fin : 1;
            uint64_t offset;
            ptls_iovec_t data;
        } stream;
        struct {
            uint64_t largest_acknowledged;
            uint64_t smallest_acknowledged;
            uint16_t ack_delay;
            uint8_t num_gaps;
            uint64_t ack_block_lengths[257];
            uint8_t gaps[256];
        } ack;
        struct {
            uint32_t stream_id;
            uint64_t max_stream_data;
        } max_stream_data;
    } data;
};

static const quicly_transport_parameters_t transport_params_before_handshake = {8192, 16, 100, 60, 0};

static uint16_t decode16(const uint8_t **src)
{
    uint16_t v = (uint16_t)(*src)[0] << 8 | (*src)[1];
    *src += 2;
    return v;
}

static uint32_t decode32(const uint8_t **src)
{
    uint32_t v = (uint32_t)(*src)[0] << 24 | (uint32_t)(*src)[1] << 16 | (uint32_t)(*src)[2] << 8 | (*src)[3];
    *src += 4;
    return v;
}

static uint64_t decode64(const uint8_t **src)
{
    uint64_t v = (uint64_t)(*src)[0] << 56 | (uint64_t)(*src)[1] << 48 | (uint64_t)(*src)[2] << 40 | (uint64_t)(*src)[3] << 32 |
                 (uint64_t)(*src)[4] << 24 | (uint64_t)(*src)[5] << 16 | (uint64_t)(*src)[6] << 8 | (*src)[7];
    *src += 8;
    return v;
}

static uint64_t decodev(const uint8_t **src, unsigned size)
{
    uint64_t v = 0;

    do {
        v = v << 8 | *(*src)++;
    } while (--size != 0);
    return v;
}

static uint8_t *encode16(uint8_t *p, uint16_t v)
{
    *p++ = (uint8_t)(v >> 8);
    *p++ = (uint8_t)v;
    return p;
}

static uint8_t *encode32(uint8_t *p, uint32_t v)
{
    *p++ = (uint8_t)(v >> 24);
    *p++ = (uint8_t)(v >> 16);
    *p++ = (uint8_t)(v >> 8);
    *p++ = (uint8_t)v;
    return p;
}

static uint8_t *encode64(uint8_t *p, uint64_t v)
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

static uint8_t *encodev(uint8_t *p, unsigned size, uint64_t v)
{
    size *= 8;
    do {
        size -= 8;
        *p++ = (uint8_t)(v >> size);
    } while (size != 0);
    return p;
}

static unsigned clz32(uint32_t v)
{
    QUICLY_BUILD_ASSERT(sizeof(unsigned) == 4);
    return v != 0 ? __builtin_clz(v) : 32;
}

static unsigned clz64(uint64_t v)
{
    QUICLY_BUILD_ASSERT(sizeof(long long) == 8);
    return v != 0 ? __builtin_clzll(v) : 64;
}

#define FNV1A_OFFSET_BASIS ((uint64_t)14695981039346656037u)

static uint64_t fnv1a(uint64_t hash, const uint8_t *p, const uint8_t *end)
{
    while (p != end) {
        hash = hash ^ (uint64_t)*p++;
        hash *= 1099511628211u;
    }

    return hash;
}

static int verify_cleartext_packet(quicly_decoded_packet_t *packet)
{
    uint64_t calced, received;
    const uint8_t *p;

    if (packet->payload.len < 8)
        return 0;
    packet->payload.len -= 8;

    calced = fnv1a(FNV1A_OFFSET_BASIS, packet->header.base, packet->header.base + packet->header.len);
    calced = fnv1a(calced, packet->payload.base, packet->payload.base + packet->payload.len);

    p = packet->payload.base + packet->payload.len;
    received = decode64(&p);

    return calced == received;
}

static void free_packet_protection(struct st_quicly_packet_protection_t *pp)
{
    if (pp->aead.early_data != NULL)
        ptls_aead_free(pp->aead.early_data);
    if (pp->aead.key_phase0 != NULL)
        ptls_aead_free(pp->aead.key_phase0);
    if (pp->aead.key_phase1 != NULL)
        ptls_aead_free(pp->aead.key_phase1);
}

int quicly_decode_packet(quicly_decoded_packet_t *packet, const uint8_t *src, size_t len)
{
    if (len < 2)
        return QUICLY_ERROR_INVALID_PACKET_HEADER;

    packet->header.base = (void *)src;

    const uint8_t *src_end = src + len;
    uint8_t first_byte = *src++;

    if ((first_byte & 0x80) != 0) {
        /* long header */
        packet->type = first_byte & 0x7f;
        packet->is_long_header = 1;
        packet->has_connection_id = 1;
        if (!QUICLY_PACKET_TYPE_IS_VALID(packet->type))
            return QUICLY_ERROR_INVALID_PACKET_HEADER;
        if (src_end - src < 16)
            return QUICLY_ERROR_INVALID_PACKET_HEADER;
        packet->connection_id = decode64(&src);
        packet->packet_number = decode32(&src);
        packet->version = decode32(&src);
    } else {
        /* short header */
        packet->type = (first_byte & 0x20) != 0 ? QUICLY_PACKET_TYPE_1RTT_KEY_PHASE_1 : QUICLY_PACKET_TYPE_1RTT_KEY_PHASE_0;
        packet->is_long_header = 0;
        if ((first_byte & 0x40) != 0) {
            packet->has_connection_id = 1;
            if (src_end - src < 8)
                return QUICLY_ERROR_INVALID_PACKET_HEADER;
            packet->connection_id = decode64(&src);
        } else {
            packet->has_connection_id = 0;
        }
        unsigned type = first_byte & 0x1f, packet_number_size;
        switch (type) {
        case 1:
        case 2:
        case 3:
            packet_number_size = 1 << (type - 1);
            break;
        default:
            return QUICLY_ERROR_INVALID_PACKET_HEADER;
        }
        if (src_end - src < packet_number_size)
            return QUICLY_ERROR_INVALID_PACKET_HEADER;
        packet->packet_number = (uint32_t)decodev(&src, packet_number_size);
    }

    packet->header.len = src - packet->header.base;
    packet->payload = ptls_iovec_init(src, src_end - src);
    return 0;
}

static int decode_frame(struct st_quicly_decoded_frame_t *frame, const uint8_t **src, const uint8_t *end)
{
    if (*src == end)
        goto CorruptFrame;

    uint8_t type_flags = *(*src)++;

    if (type_flags >= QUICLY_FRAME_TYPE_STREAM) {

        /* stream frame */
        frame->type = QUICLY_FRAME_TYPE_STREAM;

        { /* obtain stream_id */
            unsigned stream_id_length = ((type_flags >> 3) & 3) + 1;
            if (end - *src < stream_id_length)
                goto CorruptFrame;
            frame->data.stream.stream_id = 0;
            do {
                frame->data.stream.stream_id = (frame->data.stream.stream_id << 8) | *(*src)++;
            } while (--stream_id_length != 0);
        }

        { /* obtain offset */
            unsigned offset_mode = type_flags >> 1 & 3;
            if (offset_mode == 0) {
                frame->data.stream.offset = 0;
            } else {
                unsigned offset_length = 1 << offset_mode;
                if (end - *src < offset_length)
                    goto CorruptFrame;
                frame->data.stream.offset = decodev(src, offset_length);
            }
        }

        /* obtain data */
        if ((type_flags & QUICLY_FRAME_TYPE_STREAM_BIT_DATA_LENGTH) != 0) {
            if (end - *src < 2)
                goto CorruptFrame;
            uint16_t data_length = decode16(src);
            if (end - *src < data_length)
                goto CorruptFrame;
            frame->data.stream.data = ptls_iovec_init(*src, data_length);
            *src += data_length;
        } else {
            frame->data.stream.data = ptls_iovec_init(*src, end - *src);
            *src = end;
        }

        /* fin bit */
        frame->data.stream.fin = (type_flags & QUICLY_FRAME_TYPE_STREAM_BIT_FIN) != 0;
        if (!frame->data.stream.fin && frame->data.stream.data.len == 0)
            return QUICLY_ERROR_EMPTY_STREAM_FRAME_NO_FIN;

        return 0;

    } else if (type_flags >= QUICLY_FRAME_TYPE_ACK) {

        /* ACK frame */
        unsigned num_ts, largest_ack_size, ack_block_length_size, i;

        frame->type = QUICLY_FRAME_TYPE_ACK;

        /* obtain num_gaps, num_ts, largest_ack_size, ack_block_size */
        if (end - *src < 4)
            goto CorruptFrame;
        if ((type_flags & 0x10) != 0) {
            frame->data.ack.num_gaps = *(*src)++;
        } else {
            frame->data.ack.num_gaps = 0;
        }
        num_ts = *(*src)++;
        largest_ack_size = 1 << (type_flags >> 2 & 3);
        ack_block_length_size = 1 << (type_flags & 3);

        /* size check */
        unsigned remaining = largest_ack_size + 2 + (1 + ack_block_length_size) * (frame->data.ack.num_gaps + 1) - 1 +
                             (num_ts != 0 ? 2 + 3 * num_ts : 0);
        if (end - *src < remaining)
            goto CorruptFrame;

        frame->data.ack.largest_acknowledged = decodev(src, largest_ack_size);
        frame->data.ack.ack_delay = decode16(src);

        frame->data.ack.smallest_acknowledged = frame->data.ack.largest_acknowledged + 1;
        frame->data.ack.ack_block_lengths[0] = decodev(src, ack_block_length_size);
        frame->data.ack.smallest_acknowledged -= frame->data.ack.ack_block_lengths[0];
        for (i = 0; i != frame->data.ack.num_gaps; ++i) {
            frame->data.ack.gaps[i] = *(*src)++;
            frame->data.ack.smallest_acknowledged -= frame->data.ack.gaps[i];
            frame->data.ack.ack_block_lengths[i] = decodev(src, ack_block_length_size);
            frame->data.ack.smallest_acknowledged -= frame->data.ack.ack_block_lengths[i + 1];
        }

        return 0;

    } else {

        switch (type_flags) {
        case QUICLY_FRAME_TYPE_PADDING:
            frame->type = QUICLY_FRAME_TYPE_PADDING;
            return 0;

        case QUICLY_FRAME_TYPE_MAX_STREAM_DATA:
            if (end - *src < 4 + 8)
                goto CorruptFrame;
            frame->type = QUICLY_FRAME_TYPE_MAX_STREAM_DATA;
            frame->data.max_stream_data.stream_id = decode32(src);
            frame->data.max_stream_data.max_stream_data = decode64(src);
            return 0;

        default:
            assert(!"FIXME");
            break;
        }
    }

/* fallthru */
CorruptFrame:
    return QUICLY_ERROR_INVALID_FRAME_DATA;
}

static uint8_t *emit_long_header(quicly_conn_t *conn, uint8_t *dst, uint8_t type, uint64_t connection_id,
                                 uint32_t rounded_packet_number)
{
    *dst++ = 0x80 | type;
    dst = encode64(dst, connection_id);
    dst = encode32(dst, rounded_packet_number);
    dst = encode32(dst, QUICLY_PROTOCOL_VERSION);
    return dst;
}

static size_t encode_stream_frame_id_offset(uint8_t *type, uint8_t *dst, uint32_t stream_id, uint64_t offset)
{
    uint8_t *p = dst;

    *type = QUICLY_FRAME_TYPE_STREAM;

    {
        static const unsigned bits_table[] = {32, 24, 16, 8, 8};
        unsigned bits = bits_table[clz32(stream_id) / 8];
        *type |= bits - 8;
        do {
            *p++ = (uint8_t)(stream_id >> (bits -= 8));
        } while (bits != 0);
    }

    if (offset != 0) {
        static const uint8_t flag_table[] = {3, 3, 2, 1};
        uint8_t flag = flag_table[clz64(offset) / 16];
        *type |= flag << 1;
        unsigned bits = 8 << flag;
        do {
            *p++ = (uint8_t)(offset >> (bits -= 8));
        } while (bits != 0);
    }

    return p - dst;
}

static int set_peeraddr(quicly_conn_t *conn, struct sockaddr *addr, socklen_t addrlen)
{
    int ret;

    if (conn->super.peer.salen != addrlen) {
        struct sockaddr *newsa;
        if ((newsa = malloc(addrlen)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        free(conn->super.peer.sa);
        conn->super.peer.sa = newsa;
        conn->super.peer.salen = addrlen;
    }

    memcpy(conn->super.peer.sa, addr, addrlen);
    ret = 0;

Exit:
    return ret;
}

static void on_sendbuf_change(quicly_sendbuf_t *buf, int err)
{
    /* TODO */
}

static void on_recvbuf_change(quicly_recvbuf_t *buf, int err)
{
    /* TODO */
}

static quicly_stream_t *open_stream(quicly_conn_t *conn, uint32_t stream_id)
{
    quicly_stream_t *stream;

    if ((stream = malloc(sizeof(*stream))) == NULL)
        return NULL;
    stream->conn = conn;
    stream->stream_id = stream_id;
    quicly_sendbuf_init(&stream->sendbuf, on_sendbuf_change);
    quicly_recvbuf_init(&stream->recvbuf, on_recvbuf_change);
    stream->data = NULL;
    stream->on_receive = NULL;
    stream->recv_window_size = conn->super.ctx->transport_params.initial_max_stream_data;
    quicly_maxsender_init(&stream->_max_stream_data_sender, stream->recv_window_size);
    stream->_peer_max_stream_data = conn->super.peer.transport_params.initial_max_stream_data;

    int r;
    khiter_t iter = kh_put(quicly_stream_t, conn->streams, stream_id, &r);
    assert(iter != kh_end(conn->streams));
    kh_val(conn->streams, iter) = stream;

    return stream;
}

void destroy_stream(quicly_conn_t *conn, quicly_stream_t *stream)
{
    khiter_t iter = kh_get(quicly_stream_t, conn->streams, stream->stream_id);
    assert(iter != kh_end(conn->streams));
    kh_del(quicly_stream_t, conn->streams, iter);

    quicly_sendbuf_dispose(&stream->sendbuf);
    quicly_recvbuf_dispose(&stream->recvbuf);
    quicly_maxsender_dispose(&stream->_max_stream_data_sender);
    free(stream);
}

quicly_stream_t *quicly_get_stream(quicly_conn_t *conn, uint32_t stream_id)
{
    khiter_t iter = kh_get(quicly_stream_t, conn->streams, stream_id);
    if (iter != kh_end(conn->streams))
        return kh_val(conn->streams, iter);
    return NULL;
}

void quicly_free(quicly_conn_t *conn)
{
    quicly_stream_t *stream;

    free_packet_protection(&conn->ingress.pp);
    free_packet_protection(&conn->egress.pp);
    quicly_acks_dispose(&conn->egress.acks);

    kh_foreach_value(conn->streams, stream, { destroy_stream(conn, stream); });
    kh_destroy(quicly_stream_t, conn->streams);

    free(conn->super.peer.sa);
    free(conn);
}

static int setup_1rtt_secret(struct st_quicly_packet_protection_t *pp, ptls_t *tls, const char *label, int is_enc)
{
    ptls_cipher_suite_t *cipher = ptls_get_cipher(tls);
    int ret;

    if ((ret = ptls_export_secret(tls, pp->secret, cipher->hash->digest_size, label, ptls_iovec_init(NULL, 0))) != 0)
        return ret;
    if ((pp->aead.key_phase0 = ptls_aead_new(cipher->aead, cipher->hash, is_enc, pp->secret)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    return 0;
}

static int setup_1rtt(quicly_conn_t *conn, ptls_t *tls)
{
    int ret;

    if ((ret = setup_1rtt_secret(&conn->ingress.pp, tls,
                                 quicly_is_client(conn) ? "EXPORTER-QUIC server 1-RTT Secret" : "EXPORTER-QUIC client 1-RTT Secret",
                                 0)) != 0)
        goto Exit;
    if ((ret = setup_1rtt_secret(&conn->egress.pp, tls,
                                 quicly_is_client(conn) ? "EXPORTER-QUIC client 1-RTT Secret" : "EXPORTER-QUIC server 1-RTT Secret",
                                 1)) != 0)
        goto Exit;

    conn->super.state = QUICLY_STATE_1RTT_ENCRYPTED;

Exit:
    return 0;
}

static void senddata_free(struct st_quicly_buffer_vec_t *vec)
{
    free(vec->p);
    free(vec);
}

static void write_tlsbuf(quicly_stream_t *stream, ptls_buffer_t *tlsbuf)
{
    if (tlsbuf->off != 0) {
        assert(tlsbuf->is_allocated);
        quicly_sendbuf_write(&stream->sendbuf, tlsbuf->base, tlsbuf->off, senddata_free);
        ptls_buffer_init(tlsbuf, "", 0);
    } else {
        assert(!tlsbuf->is_allocated);
    }
}

static int crypto_stream_receive_handshake(quicly_conn_t *conn, quicly_stream_t *stream)
{
    struct st_quicly_crypto_stream_data_t *data = stream->data;
    ptls_iovec_t input;
    ptls_buffer_t buf;
    int ret = PTLS_ERROR_IN_PROGRESS;

    ptls_buffer_init(&buf, "", 0);
    while (ret == PTLS_ERROR_IN_PROGRESS && (input = quicly_recvbuf_get(&stream->recvbuf)).len != 0) {
        ret = ptls_handshake(data->tls, &buf, input.base, &input.len, &data->handshake_properties);
        quicly_recvbuf_shift(&stream->recvbuf, input.len);
    }
    write_tlsbuf(stream, &buf);

    switch (ret) {
    case 0:
        QUICLY_DEBUG_LOG(conn, 0, "handshake complete");
        /* state is 1RTT_ENCRYPTED when handling ClientFinished */
        if (conn->super.state < QUICLY_STATE_1RTT_ENCRYPTED) {
            if ((ret = setup_1rtt(conn, data->tls)) != 0)
                goto Exit;
        }
        break;
    case PTLS_ERROR_IN_PROGRESS:
        if (conn->super.state == QUICLY_STATE_BEFORE_SH)
            conn->super.state = QUICLY_STATE_BEFORE_SF;
        ret = 0;
        break;
    default:
        break;
    }

Exit:
    return ret;
}

static int do_apply_stream_frame(quicly_conn_t *conn, quicly_stream_t *stream, uint64_t off, ptls_iovec_t data)
{
    int ret;

    /* make adjustments for retransmit */
    if (off < stream->recvbuf.data_off) {
        if (off + data.len <= stream->recvbuf.data_off)
            return 0;
        size_t delta = stream->recvbuf.data_off - off;
        off = stream->recvbuf.data_off;
        data.base += delta;
        data.len -= delta;
    }

    /* try the fast (copyless) path */
    if (stream->recvbuf.data_off == off && stream->recvbuf.data.len == 0) {
        struct st_quicly_buffer_vec_t vec;
        assert(stream->recvbuf.received.num_ranges == 1);
        assert(stream->recvbuf.received.ranges[0].end == stream->recvbuf.data_off);

        stream->recvbuf.received.ranges[0].end += data.len;
        quicly_buffer_set_fast_external(&stream->recvbuf.data, &vec, data.base, data.len);

        if ((ret = stream->on_receive(conn, stream)) != 0)
            return ret;
        assert(vec.next == NULL);

        if (stream->recvbuf.data.len != 0) {
            size_t keeplen = stream->recvbuf.data.len;
            quicly_buffer_init(&stream->recvbuf.data);
            if ((ret = quicly_buffer_push(&stream->recvbuf.data, data.base + data.len - keeplen, keeplen, NULL)) != 0)
                return ret;
        }
        return 0;
    }

    uint64_t prev_end = stream->recvbuf.received.ranges[0].end;
    if ((ret = quicly_recvbuf_write(&stream->recvbuf, off, data.base, data.len)) != 0)
        return ret;
    if (prev_end != stream->recvbuf.received.ranges[0].end || prev_end == stream->recvbuf.eos)
        ret = stream->on_receive(conn, stream);
    return ret;
}

static int apply_stream_frame(quicly_conn_t *conn, quicly_stream_t *stream, struct st_quicly_decoded_frame_t *frame)
{
    int ret;

    QUICLY_DEBUG_LOG(conn, stream->stream_id, "received; off=%" PRIu64 ",len=%zu", frame->data.stream.offset,
                     frame->data.stream.data.len);

    if (frame->data.stream.fin &&
        (ret = quicly_recvbuf_mark_eos(&stream->recvbuf, frame->data.stream.offset + frame->data.stream.data.len)) != 0)
        return ret;

    return do_apply_stream_frame(conn, stream, frame->data.stream.offset, frame->data.stream.data);
}

#define PUSH_TRANSPORT_PARAMETER(buf, id, block)                                                                                   \
    do {                                                                                                                           \
        ptls_buffer_push16((buf), (id));                                                                                           \
        ptls_buffer_push_block((buf), 2, block);                                                                                   \
    } while (0)

static int encode_transport_parameter_list(quicly_transport_parameters_t *params, ptls_buffer_t *buf)
{
    int ret;

    ptls_buffer_push_block(buf, 2, {
        PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA,
                                 { ptls_buffer_push32(buf, params->initial_max_stream_data); });
        PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_DATA,
                                 { ptls_buffer_push32(buf, params->initial_max_data); });
        PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_ID,
                                 { ptls_buffer_push32(buf, params->initial_max_stream_id); });
        PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_IDLE_TIMEOUT,
                                 { ptls_buffer_push16(buf, params->idle_timeout); });
        if (params->truncate_connection_id)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_TRUNCATE_CONNECTION_ID, {});
    });
    ret = 0;
Exit:
    return ret;
}

static int decode_transport_parameter_list(quicly_transport_parameters_t *params, const uint8_t *src, const uint8_t *end)
{
#define ID_TO_BIT(id) ((uint64_t)1 << (id))

    uint64_t found_id_bits = 0,
             must_found_id_bits = ID_TO_BIT(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA) |
                                  ID_TO_BIT(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_DATA) |
                                  ID_TO_BIT(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_ID) |
                                  ID_TO_BIT(QUICLY_TRANSPORT_PARAMETER_ID_IDLE_TIMEOUT);
    int ret;

    /* set optional parameters to their default values */
    params->truncate_connection_id = 0;

    /* decode the parameters block */
    ptls_decode_block(src, end, 2, {
        while (src != end) {
            uint16_t id;
            if ((ret = ptls_decode16(&id, &src, end)) != 0)
                goto Exit;
            if (id < sizeof(found_id_bits) * 8) {
                if ((found_id_bits & ID_TO_BIT(id)) != 0) {
                    ret = QUICLY_ERROR_INVALID_STREAM_DATA; /* FIXME error code */
                    goto Exit;
                }
                found_id_bits |= ID_TO_BIT(id);
            }
            found_id_bits |= ID_TO_BIT(id);
            ptls_decode_open_block(src, end, 2, {
                switch (id) {
                case QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA:
                    if ((ret = ptls_decode32(&params->initial_max_stream_data, &src, end)) != 0)
                        goto Exit;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_DATA:
                    if ((ret = ptls_decode32(&params->initial_max_data, &src, end)) != 0)
                        goto Exit;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_ID:
                    if ((ret = ptls_decode32(&params->initial_max_stream_id, &src, end)) != 0)
                        goto Exit;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_IDLE_TIMEOUT:
                    if ((ret = ptls_decode16(&params->idle_timeout, &src, end)) != 0)
                        goto Exit;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_TRUNCATE_CONNECTION_ID:
                    params->truncate_connection_id = 1;
                    break;
                default:
                    src = end;
                    break;
                }
            });
        }
    });

    /* check that we have found all the required parameters */
    if ((found_id_bits & must_found_id_bits) != must_found_id_bits) {
        ret = QUICLY_ERROR_INVALID_STREAM_DATA; /* FIXME error code */
        goto Exit;
    }

    ret = 0;
Exit:
    return ret;

#undef ID_TO_BIT
}

static int collect_transport_parameters(ptls_t *tls, struct st_ptls_handshake_properties_t *properties, uint16_t type)
{
    return type == QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS;
}

static quicly_conn_t *create_connection(quicly_context_t *ctx, const char *server_name, struct sockaddr *sa, socklen_t salen,
                                        ptls_handshake_properties_t *handshake_properties, quicly_stream_t **crypto_stream)
{
    quicly_conn_t *conn;
    struct st_quicly_crypto_stream_data_t *crypto_data;

    *crypto_stream = NULL;

    if ((conn = malloc(sizeof(*conn))) == NULL)
        return NULL;

    memset(conn, 0, sizeof(*conn));
    conn->super.ctx = ctx;
    conn->super.peer.transport_params = transport_params_before_handshake;
    conn->streams = kh_init(quicly_stream_t);
    quicly_ranges_init(&conn->ingress.ack_queue);
    quicly_acks_init(&conn->egress.acks);

    if (set_peeraddr(conn, sa, salen) != 0)
        goto Fail;

    /* instantiate the crypto stream */
    if ((*crypto_stream = open_stream(conn, 0)) == NULL)
        goto Fail;
    if ((crypto_data = malloc(sizeof(*crypto_data))) == NULL)
        goto Fail;
    (*crypto_stream)->data = crypto_data;
    (*crypto_stream)->on_receive = crypto_stream_receive_handshake;
    crypto_data->conn = conn;
    if ((crypto_data->tls = ptls_new(ctx->tls, server_name == NULL)) == NULL)
        goto Fail;
    if (server_name != NULL && ptls_set_server_name(crypto_data->tls, server_name, strlen(server_name)) != 0)
        goto Fail;
    if (handshake_properties != NULL) {
        assert(handshake_properties->additional_extensions == NULL);
        assert(handshake_properties->collect_extension == NULL);
        assert(handshake_properties->collected_extensions == NULL);
        crypto_data->handshake_properties = *handshake_properties;
    } else {
        crypto_data->handshake_properties = (ptls_handshake_properties_t){{{{NULL}}}};
    }
    crypto_data->handshake_properties.collect_extension = collect_transport_parameters;
    if (server_name != NULL) {
        conn->super.host.next_stream_id = 1;
        conn->super.peer.next_stream_id = 2;
    } else {
        conn->super.host.next_stream_id = 2;
        conn->super.peer.next_stream_id = 1;
    }

    return conn;
Fail:
    if (conn != NULL)
        quicly_free(conn);
    return NULL;
}

static int client_collected_extensions(ptls_t *tls, ptls_handshake_properties_t *properties, ptls_raw_extension_t *slots)
{
    struct st_quicly_crypto_stream_data_t *crypto_data =
        (void *)((char *)properties - offsetof(struct st_quicly_crypto_stream_data_t, handshake_properties));
    int ret;

    if (slots[0].type == UINT16_MAX) {
        ret = 0; // allow abcense of the extension for the time being PTLS_ALERT_MISSING_EXTENSION;
        goto Exit;
    }
    assert(slots[0].type == QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS);
    assert(slots[1].type == UINT16_MAX);

    const uint8_t *src = slots[0].data.base, *end = src + slots[0].data.len;

    ptls_decode_open_block(src, end, 1, {
        int found_negotiated_version = 0;
        do {
            uint32_t supported_version;
            if ((ret = ptls_decode32(&supported_version, &src, end)) != 0)
                goto Exit;
            if (supported_version == QUICLY_PROTOCOL_VERSION)
                found_negotiated_version = 1;
        } while (src != end);
        if (!found_negotiated_version) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER; /* FIXME is this the correct error code? */
            goto Exit;
        }
    });
    ret = decode_transport_parameter_list(&crypto_data->conn->super.peer.transport_params, src, end);

Exit:
    return ret;
}

int quicly_connect(quicly_conn_t **_conn, quicly_context_t *ctx, const char *server_name, struct sockaddr *sa, socklen_t salen,
                   ptls_handshake_properties_t *handshake_properties)
{
    quicly_conn_t *conn;
    quicly_stream_t *crypto_stream;
    struct st_quicly_crypto_stream_data_t *crypto_data;
    ptls_buffer_t buf;
    int ret;

    if ((conn = create_connection(ctx, server_name, sa, salen, handshake_properties, &crypto_stream)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    crypto_data = crypto_stream->data;

    /* handshake */
    ptls_buffer_init(&crypto_data->transport_parameters.buf, "", 0);
    ptls_buffer_push32(&crypto_data->transport_parameters.buf, QUICLY_PROTOCOL_VERSION);
    ptls_buffer_push32(&crypto_data->transport_parameters.buf, QUICLY_PROTOCOL_VERSION);
    if ((ret = encode_transport_parameter_list(&ctx->transport_params, &crypto_data->transport_parameters.buf)) != 0)
        goto Exit;
    crypto_data->transport_parameters.ext[0] =
        (ptls_raw_extension_t){QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS,
                               {crypto_data->transport_parameters.buf.base, crypto_data->transport_parameters.buf.off}};
    crypto_data->transport_parameters.ext[1] = (ptls_raw_extension_t){UINT16_MAX};
    crypto_data->handshake_properties.additional_extensions = crypto_data->transport_parameters.ext;
    crypto_data->handshake_properties.collected_extensions = client_collected_extensions;

    ptls_buffer_init(&buf, "", 0);
    if ((ret = ptls_handshake(crypto_data->tls, &buf, NULL, 0, &crypto_data->handshake_properties)) != PTLS_ERROR_IN_PROGRESS)
        goto Exit;
    write_tlsbuf(crypto_stream, &buf);

    *_conn = conn;
    ret = 0;

Exit:
    if (ret != 0) {
        if (conn != NULL)
            quicly_free(conn);
    }
    return ret;
}

static int server_collected_extensions(ptls_t *tls, ptls_handshake_properties_t *properties, ptls_raw_extension_t *slots)
{
    struct st_quicly_crypto_stream_data_t *crypto_data =
        (void *)((char *)properties - offsetof(struct st_quicly_crypto_stream_data_t, handshake_properties));
    int ret;

    if (slots[0].type == UINT16_MAX) {
        ret = 0; // allow abcense of the extension for the time being PTLS_ALERT_MISSING_EXTENSION;
        goto Exit;
    }
    assert(slots[0].type == QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS);
    assert(slots[1].type == UINT16_MAX);

    { /* decode transport_parameters extension */
        const uint8_t *src = slots[0].data.base, *end = src + slots[0].data.len;
        uint32_t negotiated_version, initial_version;
        if ((ret = ptls_decode32(&negotiated_version, &src, end)) != 0)
            goto Exit;
        if ((ret = ptls_decode32(&initial_version, &src, end)) != 0)
            goto Exit;
        if (!(negotiated_version == QUICLY_PROTOCOL_VERSION && initial_version == QUICLY_PROTOCOL_VERSION)) {
            ret = QUICLY_ERROR_VERSION_NEGOTIATION_MISMATCH;
            goto Exit;
        }
        if ((ret = decode_transport_parameter_list(&crypto_data->conn->super.peer.transport_params, src, end)) != 0)
            goto Exit;
    }

    /* set transport_parameters extension to be sent in EE */
    assert(properties->additional_extensions == NULL);
    ptls_buffer_init(&crypto_data->transport_parameters.buf, "", 0);
    ptls_buffer_push_block(&crypto_data->transport_parameters.buf, 1,
                           { ptls_buffer_push32(&crypto_data->transport_parameters.buf, QUICLY_PROTOCOL_VERSION); });
    if ((ret = encode_transport_parameter_list(&crypto_data->conn->super.ctx->transport_params,
                                               &crypto_data->transport_parameters.buf)) != 0)
        goto Exit;
    properties->additional_extensions = crypto_data->transport_parameters.ext;
    crypto_data->transport_parameters.ext[0] =
        (ptls_raw_extension_t){QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS,
                               {crypto_data->transport_parameters.buf.base, crypto_data->transport_parameters.buf.off}};
    crypto_data->transport_parameters.ext[1] = (ptls_raw_extension_t){UINT16_MAX};
    crypto_data->handshake_properties.additional_extensions = crypto_data->transport_parameters.ext;

    ret = 0;

Exit:
    return ret;
}

int quicly_accept(quicly_conn_t **_conn, quicly_context_t *ctx, struct sockaddr *sa, socklen_t salen,
                  ptls_handshake_properties_t *handshake_properties, quicly_decoded_packet_t *packet)
{
    quicly_conn_t *conn = NULL;
    quicly_stream_t *crypto_stream;
    struct st_quicly_crypto_stream_data_t *crypto_data;
    struct st_quicly_decoded_frame_t frame;
    int ret;

    /* ignore any packet that does not  */
    if (packet->type != QUICLY_PACKET_TYPE_CLIENT_INITIAL) {
        ret = QUICLY_ERROR_PACKET_IGNORED;
        goto Exit;
    }
    if (!verify_cleartext_packet(packet)) {
        ret = QUICLY_ERROR_DECRYPTION_FAILURE;
        goto Exit;
    }
    {
        const uint8_t *p = packet->payload.base, *end = p + packet->payload.len;
        for (; p < end; ++p) {
            if (*p != QUICLY_FRAME_TYPE_PADDING)
                break;
        }
        if ((ret = decode_frame(&frame, &p, end)) != 0)
            goto Exit;
        if (frame.type != QUICLY_FRAME_TYPE_STREAM) {
            ret = QUICLY_ERROR_INVALID_FRAME_DATA;
            goto Exit;
        }
        if (frame.data.stream.offset != 0) {
            ret = QUICLY_ERROR_INVALID_STREAM_DATA;
            goto Exit;
        }
        /* FIXME check packet size */
        for (; p < end; ++p) {
            if (*p != QUICLY_FRAME_TYPE_PADDING) {
                ret = QUICLY_ERROR_INVALID_FRAME_DATA;
                goto Exit;
            }
        }
    }

    if ((conn = create_connection(ctx, NULL, sa, salen, handshake_properties, &crypto_stream)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    crypto_data = crypto_stream->data;
    crypto_data->handshake_properties.collected_extensions = server_collected_extensions;

    if ((ret = quicly_ranges_update(&conn->ingress.ack_queue, packet->packet_number, packet->packet_number + 1)) != 0)
        goto Exit;

    if ((ret = apply_stream_frame(conn, crypto_stream, &frame)) != 0)
        goto Exit;
    if (crypto_stream->recvbuf.data_off != frame.data.stream.data.len) {
        /* garbage after clienthello? */
        ret = QUICLY_ERROR_TBD;
        goto Exit;
    }

    *_conn = conn;

Exit:
    if (!(ret == 0 || ret == PTLS_ERROR_IN_PROGRESS)) {
        if (conn != NULL)
            quicly_free(conn);
    }
    return ret;
}

static int on_ack_stream(quicly_conn_t *conn, int acked, quicly_ack_t *ack)
{
    quicly_stream_t *stream;

    QUICLY_DEBUG_LOG(conn, ack->data.stream.stream_id, "%s; off=%" PRIu64 ",len=%zu", acked ? "acked" : "lost",
                     ack->data.stream.args.start, (size_t)(ack->data.stream.args.end - ack->data.stream.args.start));

    /* TODO cache pointer to stream (using a generation counter?) */
    if ((stream = quicly_get_stream(conn, ack->data.stream.stream_id)) == NULL)
        return 0;

    if (acked) {
        return quicly_sendbuf_acked(&stream->sendbuf, &ack->data.stream.args);
    } else {
        /* FIXME handle rto error */
        return quicly_sendbuf_lost(&stream->sendbuf, &ack->data.stream.args);
    }
}

static int on_ack_max_stream_data(quicly_conn_t *conn, int acked, quicly_ack_t *ack)
{
    quicly_stream_t *stream;

    /* TODO cache pointer to stream (using a generation counter?) */
    if ((stream = quicly_get_stream(conn, ack->data.stream.stream_id)) == NULL)
        return 0;

    if (acked) {
        quicly_maxsender_acked(&stream->_max_stream_data_sender, &ack->data.max_stream_data.args);
    } else {
        quicly_maxsender_lost(&stream->_max_stream_data_sender, &ack->data.max_stream_data.args);
    }

    return 0;
}

struct st_quicly_send_context_t {
    uint8_t packet_type;
    ptls_aead_context_t *aead;
    int64_t now;
    quicly_raw_packet_t **packets;
    size_t max_packets;
    size_t num_packets;
    quicly_raw_packet_t *target;
    uint8_t *dst;
    uint8_t *dst_end;
    uint8_t *dst_unencrypted_from;
};

static inline void encrypt_packet(struct st_quicly_send_context_t *s)
{
    ptls_aead_encrypt_update(s->aead, s->dst_unencrypted_from, s->dst_unencrypted_from, s->dst - s->dst_unencrypted_from);
    s->dst_unencrypted_from = s->dst;
}

static void commit_send_packet(quicly_conn_t *conn, struct st_quicly_send_context_t *s)
{
    if (s->aead != NULL) {
        if (s->dst != s->dst_unencrypted_from)
            encrypt_packet(s);
        s->dst += ptls_aead_encrypt_final(s->aead, s->dst);
    } else {
        uint64_t hash = fnv1a(FNV1A_OFFSET_BASIS, s->target->data.base, s->dst);
        s->dst = encode64(s->dst, hash);
    }
    s->target->data.len = s->dst - s->target->data.base;
    s->packets[s->num_packets++] = s->target;
    ++conn->egress.packet_number;

    s->target = NULL;
    s->dst = NULL;
    s->dst_end = NULL;
    s->dst_unencrypted_from = NULL;
}

static int prepare_packet(quicly_conn_t *conn, struct st_quicly_send_context_t *s, size_t min_space)
{
    /* allocate and setup the new packet if necessary */
    if (s->dst_end - s->dst < min_space || GET_TYPE_FROM_PACKET_HEADER(s->target->data.base) != s->packet_type) {
        if (s->target != NULL) {
            while (s->dst != s->dst_end)
                *s->dst++ = QUICLY_FRAME_TYPE_PADDING;
            commit_send_packet(conn, s);
        }
        if (s->num_packets >= s->max_packets)
            return 0;
        if ((s->target =
                 conn->super.ctx->alloc_packet(conn->super.ctx, conn->super.peer.salen, conn->super.ctx->max_packet_size)) == NULL)
            return PTLS_ERROR_NO_MEMORY;
        s->target->salen = conn->super.peer.salen;
        memcpy(&s->target->sa, conn->super.peer.sa, conn->super.peer.salen);
        s->dst = s->target->data.base;
        s->dst_end = s->target->data.base + conn->super.ctx->max_packet_size;
        s->dst = emit_long_header(conn, s->dst, s->packet_type, conn->super.connection_id, (uint32_t)conn->egress.packet_number);
        s->dst_unencrypted_from = s->dst;
        if (s->aead != NULL) {
            s->dst_end -= s->aead->algo->tag_size;
            ptls_aead_encrypt_init(s->aead, conn->egress.packet_number, s->target->data.base, s->dst - s->target->data.base);
        } else {
            s->dst_end -= 8; /* space for fnv1a-64 */
        }
        assert(s->dst < s->dst_end);
    }

    return 0;
}

static int send_ack_frame(quicly_conn_t *conn, struct st_quicly_send_context_t *s, size_t *range_index,
                          unsigned largest_acknowledged_mode, unsigned block_length_mode)
{
    uint8_t type = QUICLY_FRAME_TYPE_ACK | (*range_index != 0 ? 0x10 : 0) | (largest_acknowledged_mode << 2) | block_length_mode,
            *num_gaps_at = NULL;
    unsigned largest_acknowledged_length = 1 << largest_acknowledged_mode, block_length_length = 1 << block_length_mode;
    int ret;

    if ((ret = prepare_packet(conn, s, 1 + (*range_index != 0) + largest_acknowledged_length + 2 + block_length_length)) != 0)
        return ret;
    if (s->dst == NULL)
        return 0;

    *s->dst++ = type;
    if (*range_index != 0) {
        num_gaps_at = s->dst++;
        *num_gaps_at = 0;
    }
    *s->dst++ = 0; /* TODO num_ts */
    s->dst = encodev(s->dst, largest_acknowledged_length, conn->ingress.ack_queue.ranges[*range_index].end - 1);
    s->dst = encode16(s->dst, 0); /* TODO ack_delay */
    s->dst = encodev(s->dst, block_length_length,
                     conn->ingress.ack_queue.ranges[*range_index].end - conn->ingress.ack_queue.ranges[*range_index].start);

    if (--*range_index != SIZE_MAX) {
        do {
            if (s->dst_end - s->dst < 1 + block_length_length)
                break;
            uint64_t gap =
                conn->ingress.ack_queue.ranges[*range_index + 1].start - conn->ingress.ack_queue.ranges[*range_index].end;
            if (gap > 255)
                break;
            *s->dst++ = gap;
            s->dst = encodev(s->dst, block_length_length,
                             conn->ingress.ack_queue.ranges[*range_index].end - conn->ingress.ack_queue.ranges[*range_index].start);
            --*range_index;
            if (++*num_gaps_at == 255)
                break;
        } while (*range_index != SIZE_MAX);
    }

    return 0;
}

static int send_ack(quicly_conn_t *conn, struct st_quicly_send_context_t *s)
{
    static const unsigned encoding_mode[] = {3, 3, 3, 3, 2, 2, 1, 0, 0};
    unsigned largest_acknowledged_mode, block_length_mode;
    size_t range_index;
    int ret;

    if (conn->ingress.ack_queue.num_ranges == 0)
        return 0;

    /* calculate modes */
    largest_acknowledged_mode =
        encoding_mode[clz64(conn->ingress.ack_queue.ranges[conn->ingress.ack_queue.num_ranges - 1].end - 1) / 8];
    {
        uint64_t max_ack_block_length = 0;
        size_t i;
        for (i = 0; i < conn->ingress.ack_queue.num_ranges; ++i) {
            size_t bl = conn->ingress.ack_queue.ranges[i].end - conn->ingress.ack_queue.ranges[i].start;
            if (bl > max_ack_block_length)
                max_ack_block_length = bl;
        }
        block_length_mode = encoding_mode[clz64(max_ack_block_length) / 8];
    }

    range_index = conn->ingress.ack_queue.num_ranges - 1;
    do {
        if ((ret = send_ack_frame(conn, s, &range_index, largest_acknowledged_mode, block_length_mode)) != 0)
            break;
        if (s->dst == NULL)
            break;
    } while (range_index != SIZE_MAX);

    quicly_ranges_clear(&conn->ingress.ack_queue);
    return ret;
}

static int send_max_stream_data_frame(quicly_stream_t *stream, struct st_quicly_send_context_t *s)
{
#define FRAME_SIZE (1 + 4 + 8) /* including stream type */

    quicly_ack_t *ack;
    uint64_t new_value;
    int ret;

    if ((ret = prepare_packet(stream->conn, s, FRAME_SIZE)) != 0)
        return ret;
    if (s->dst == NULL)
        return 0;

    if ((ack = quicly_acks_allocate(&stream->conn->egress.acks, stream->conn->egress.packet_number, s->now, FRAME_SIZE,
                                    on_ack_max_stream_data)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    new_value = stream->recvbuf.data_off + stream->recv_window_size;

    /* write packet */
    *s->dst++ = QUICLY_FRAME_TYPE_MAX_STREAM_DATA;
    s->dst = encode32(s->dst, stream->stream_id);
    s->dst = encode64(s->dst, new_value);

    /* register ack */
    ack->data.max_stream_data.stream_id = stream->stream_id;
    quicly_maxsender_record(&stream->_max_stream_data_sender, new_value, &ack->data.max_stream_data.args);

    return 0;

#undef FRAME_SIZE
}

static int send_stream_frame(quicly_stream_t *stream, struct st_quicly_send_context_t *s, quicly_sendbuf_dataiter_t *iter,
                             size_t max_bytes)
{
    uint8_t type;
    uint8_t encoded_id_offset[QUICLY_STREAM_HEADER_SIZE_MAX];
    size_t encoded_id_offset_size = encode_stream_frame_id_offset(&type, encoded_id_offset, stream->stream_id, iter->stream_off);
    size_t min_required_space = encoded_id_offset_size + (iter->stream_off != stream->sendbuf.eos);
    int ret;

    if ((ret = prepare_packet(stream->conn, s, min_required_space)) != 0)
        return ret;
    if (s->dst == NULL)
        return 0;

    uint8_t *type_at = s->dst++;

    /* emit stream header as well as calculating the size of the data to send */
    size_t capacity = s->dst_end - s->dst - encoded_id_offset_size;
    size_t avail = max_bytes - (iter->stream_off + max_bytes > stream->sendbuf.eos);
    size_t copysize = capacity <= avail ? capacity : avail;
    if (iter->stream_off + copysize >= stream->sendbuf.eos) {
        assert(iter->stream_off + avail == stream->sendbuf.eos);
        type |= QUICLY_FRAME_TYPE_STREAM_BIT_FIN;
    }
    memcpy(s->dst, encoded_id_offset, encoded_id_offset_size);
    s->dst += encoded_id_offset_size;
    if (copysize + 2 < capacity) {
        type |= QUICLY_FRAME_TYPE_STREAM_BIT_DATA_LENGTH;
        s->dst = encode16(s->dst, (uint16_t)copysize);
    }
    *type_at = type;
    if (s->aead != NULL)
        encrypt_packet(s);

    QUICLY_DEBUG_LOG(stream->conn, stream->stream_id, "sending; off=%" PRIu64 ",len=%zu", iter->stream_off, copysize);

    /* send data */
    quicly_ack_t *ack;
    if ((ack = quicly_acks_allocate(&stream->conn->egress.acks, stream->conn->egress.packet_number, s->now,
                                    s->dst - type_at + copysize, on_ack_stream)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    ack->data.stream.stream_id = stream->stream_id;
    quicly_sendbuf_emit(&stream->sendbuf, iter, copysize, s->dst, &ack->data.stream.args, s->aead);
    s->dst += copysize;
    s->dst_unencrypted_from = s->dst;

    return 0;
}

static int send_stream_frames(quicly_stream_t *stream, struct st_quicly_send_context_t *s)
{
    quicly_sendbuf_dataiter_t iter;
    uint64_t max_stream_data;
    size_t i;

    max_stream_data = stream->_peer_max_stream_data;
    if (max_stream_data == stream->sendbuf.eos)
        ++max_stream_data;

    quicly_sendbuf_init_dataiter(&stream->sendbuf, &iter);

    for (i = 0; i != stream->sendbuf.pending.num_ranges; ++i) {
        uint64_t start = stream->sendbuf.pending.ranges[i].start, end = stream->sendbuf.pending.ranges[i].end;
        if (max_stream_data <= start)
            goto ShrinkRanges;
        if (max_stream_data < end)
            end = max_stream_data;

        if (iter.stream_off != start) {
            assert(iter.stream_off <= start);
            quicly_sendbuf_advance_dataiter(&iter, start - iter.stream_off);
        }
        /* when end == eos, iter.stream_off becomes end+1 after calling send_steram_frame; hence `<` is used */
        while (iter.stream_off < end) {
            int ret = send_stream_frame(stream, s, &iter, end - iter.stream_off);
            if (ret != 0)
                return ret;
            if (s->dst == NULL)
                goto ShrinkToIter;
        }

        if (iter.stream_off < stream->sendbuf.pending.ranges[i].end)
            goto ShrinkToIter;
    }

    quicly_ranges_clear(&stream->sendbuf.pending);
    return 0;

ShrinkToIter:
    stream->sendbuf.pending.ranges[i].start = iter.stream_off;
ShrinkRanges:
    quicly_ranges_shrink(&stream->sendbuf.pending, 0, i);
    return 0;
}

static int send_stream(quicly_stream_t *stream, struct st_quicly_send_context_t *s)
{
    int ret;

    /* send MAX_STREAM_DATA if necessary */
    if (quicly_maxsender_should_update(&stream->_max_stream_data_sender, stream->recvbuf.data_off, stream->recv_window_size, 512)) {
        if ((ret = send_max_stream_data_frame(stream, s)) != 0)
            return ret;
    }

    return send_stream_frames(stream, s);
}

static int handle_timeouts(quicly_conn_t *conn, int64_t now)
{
    quicly_acks_iter_t iter;
    quicly_ack_t *ack;
    int ret;
    int64_t sent_before = now - conn->super.ctx->initial_rto;

    for (quicly_acks_init_iter(&conn->egress.acks, &iter); (ack = quicly_acks_get(&iter)) != NULL; quicly_acks_next(&iter)) {
        if (sent_before < ack->sent_at)
            break;
        if ((ret = ack->acked(conn, 0, ack)) != 0)
            return ret;
        quicly_acks_release(&conn->egress.acks, &iter);
    }

    return 0;
}

int quicly_send(quicly_conn_t *conn, quicly_raw_packet_t **packets, size_t *num_packets)
{
    quicly_stream_t *stream;
    struct st_quicly_send_context_t s = {UINT8_MAX, NULL, conn->super.ctx->now(conn->super.ctx), packets, *num_packets};
    int ret;

    /* handle timeouts */
    if ((ret = handle_timeouts(conn, s.now)) != 0)
        goto Exit;

    /* send cleartext frames */
    if (quicly_is_client(conn)) {
        if (quicly_get_state(conn) == QUICLY_STATE_BEFORE_SH) {
            s.packet_type = QUICLY_PACKET_TYPE_CLIENT_INITIAL;
        } else {
            s.packet_type = QUICLY_PACKET_TYPE_CLIENT_CLEARTEXT;
        }
    } else {
        s.packet_type = QUICLY_PACKET_TYPE_SERVER_CLEARTEXT;
    }
    s.aead = NULL;
    if (!conn->egress.acks_require_encryption && s.packet_type != QUICLY_PACKET_TYPE_CLIENT_INITIAL) {
        if ((ret = send_ack(conn, &s)) != 0)
            goto Exit;
    }
    if ((ret = send_stream(quicly_get_stream(conn, 0), &s)) != 0)
        goto Exit;
    if (s.target != NULL) {
        if (s.packet_type == QUICLY_PACKET_TYPE_CLIENT_INITIAL) {
            if (s.num_packets != 0)
                return QUICLY_ERROR_HANDSHAKE_TOO_LARGE;
            const size_t max_size = 1272; /* max UDP packet size excluding fnv1a hash */
            assert(s.dst - s.target->data.base <= max_size);
            memset(s.dst, 0, s.target->data.base + max_size - s.dst);
            s.dst = s.target->data.base + max_size;
        }
        commit_send_packet(conn, &s);
    }

    /* send encrypted frames */
    if (quicly_get_state(conn) == QUICLY_STATE_1RTT_ENCRYPTED) {
        s.packet_type = QUICLY_PACKET_TYPE_1RTT_KEY_PHASE_0;
        s.aead = conn->egress.pp.aead.key_phase0;
        if ((ret = send_ack(conn, &s)) != 0)
            goto Exit;
        kh_foreach_value(conn->streams, stream, {
            if (stream->stream_id != 0) {
                if ((ret = send_stream(stream, &s)) != 0)
                    goto Exit;
            }
        });
        if (s.target != NULL)
            commit_send_packet(conn, &s);
    }

    *num_packets = s.num_packets;
    ret = 0;
Exit:
    return ret;
}

static int handle_stream_frame(quicly_conn_t *conn, struct st_quicly_decoded_frame_t *frame)
{
    quicly_stream_t *stream = quicly_get_stream(conn, frame->data.stream.stream_id);
    int ret = 0;

    /* open new stream(s) if necessary */
    if (stream == NULL && frame->data.stream.stream_id % 2 != quicly_is_client(conn) &&
        (conn->super.peer.next_stream_id != 0 && conn->super.peer.next_stream_id <= frame->data.stream.stream_id)) {
        do {
            if ((stream = open_stream(conn, conn->super.peer.next_stream_id)) == NULL) {
                ret = PTLS_ERROR_NO_MEMORY;
                goto Exit;
            }
            if ((ret = conn->super.ctx->on_stream_open(conn->super.ctx, conn, stream)) != 0)
                goto Exit;
            conn->super.peer.next_stream_id += 2;
        } while (frame->data.stream.stream_id != stream->stream_id);
        /* disallow opening new streams if the number has overlapped */
        if (conn->super.peer.next_stream_id < 2)
            conn->super.peer.next_stream_id = 0;
    }

    if (stream != NULL) {
        if ((ret = apply_stream_frame(conn, stream, frame)) != 0)
            goto Exit;
    }

Exit:
    return ret;
}

static int handle_ack_frame(quicly_conn_t *conn, struct st_quicly_decoded_frame_t *frame)
{
    quicly_acks_iter_t iter;
    uint64_t packet_number = frame->data.ack.smallest_acknowledged;
    int ret;

    quicly_acks_init_iter(&conn->egress.acks, &iter);
    if (quicly_acks_get(&iter) == NULL)
        return 0;

    size_t gap_index = frame->data.ack.num_gaps;
    while (1) {
        uint64_t block_length = frame->data.ack.ack_block_lengths[gap_index];
        if (block_length != 0) {
            while (quicly_acks_get(&iter)->packet_number < packet_number) {
                quicly_acks_next(&iter);
                if (quicly_acks_get(&iter) == NULL)
                    goto Exit;
            }
            do {
                int found_active = 0;
                while (quicly_acks_get(&iter)->packet_number == packet_number) {
                    found_active = 1;
                    quicly_ack_t *ack = quicly_acks_get(&iter);
                    if ((ret = ack->acked(conn, 1, ack)) != 0)
                        return ret;
                    quicly_acks_release(&conn->egress.acks, &iter);
                    quicly_acks_next(&iter);
                    if (quicly_acks_get(&iter) == NULL)
                        break;
                }
                if (!found_active)
                    QUICLY_DEBUG_LOG(conn, 0, "dupack");
                if (quicly_acks_get(&iter) == NULL)
                    goto Exit;
            } while (++packet_number, --block_length != 0);
        }
        if (gap_index-- == 0)
            break;
        packet_number += frame->data.ack.gaps[gap_index];
    }

Exit:
    return 0;
}

static int handle_max_stream_data_frame(quicly_conn_t *conn, struct st_quicly_decoded_frame_t *frame)
{
    quicly_stream_t *stream = quicly_get_stream(conn, frame->data.stream.stream_id);

    if (stream == NULL)
        return 0;

    if (stream->_peer_max_stream_data < frame->data.max_stream_data.max_stream_data)
        stream->_peer_max_stream_data = frame->data.max_stream_data.max_stream_data;

    /* TODO schedule for delivery */
    return 0;
}

int quicly_receive(quicly_conn_t *conn, quicly_decoded_packet_t *packet)
{
    ptls_aead_context_t *aead = NULL;
    int ret;

    /* FIXME check peer address */
    conn->super.connection_id = packet->connection_id;

    /* ignore packets having wrong connection id */
    if (packet->connection_id != conn->super.connection_id) {
        ret = QUICLY_ERROR_PACKET_IGNORED;
        goto Exit;
    }

    if (!packet->is_long_header && conn->super.state != QUICLY_STATE_1RTT_ENCRYPTED) {
        ret = QUICLY_ERROR_INVALID_PACKET_HEADER;
        goto Exit;
    }

    switch (packet->type) {
    case QUICLY_PACKET_TYPE_CLIENT_CLEARTEXT:
        if (quicly_is_client(conn)) {
            ret = QUICLY_ERROR_INVALID_PACKET_HEADER;
            goto Exit;
        }
        break;
    case QUICLY_PACKET_TYPE_SERVER_CLEARTEXT:
        if (!quicly_is_client(conn)) {
            ret = QUICLY_ERROR_INVALID_PACKET_HEADER;
            goto Exit;
        }
        break;
    case QUICLY_PACKET_TYPE_0RTT_PROTECTED:
        if (quicly_is_client(conn) || (aead = conn->ingress.pp.aead.early_data) == NULL) {
            ret = QUICLY_ERROR_INVALID_PACKET_HEADER;
            goto Exit;
        }
        break;
    case QUICLY_PACKET_TYPE_1RTT_KEY_PHASE_0:
        if ((aead = conn->ingress.pp.aead.key_phase0) == NULL) {
            /* drop 1rtt-encrypted packets received prior to handshake completion (due to loss of the packet carrying the latter) */
            ret = quicly_get_state(conn) == QUICLY_STATE_1RTT_ENCRYPTED ? QUICLY_ERROR_INVALID_PACKET_HEADER : 0;
            goto Exit;
        }
        break;
    case QUICLY_PACKET_TYPE_1RTT_KEY_PHASE_1:
        if ((aead = conn->ingress.pp.aead.key_phase1) == NULL) {
            ret = QUICLY_ERROR_INVALID_PACKET_HEADER;
            goto Exit;
        }
        break;
    case QUICLY_PACKET_TYPE_CLIENT_INITIAL:
        /* FIXME ignore for time being */
        ret = 0;
        goto Exit;
    default:
        ret = QUICLY_ERROR_INVALID_PACKET_HEADER;
        goto Exit;
    }

    if (aead != NULL) {
        if ((packet->payload.len = ptls_aead_decrypt(aead, packet->payload.base, packet->payload.base, packet->payload.len,
                                                     packet->packet_number, packet->header.base, packet->header.len)) == SIZE_MAX) {
            ret = QUICLY_ERROR_DECRYPTION_FAILURE;
            goto Exit;
        }
    } else {
        if (!verify_cleartext_packet(packet)) {
            ret = QUICLY_ERROR_DECRYPTION_FAILURE;
            goto Exit;
        }
    }

    const uint8_t *p = packet->payload.base, *end = p + packet->payload.len;
    int should_ack = 0;
    do {
        struct st_quicly_decoded_frame_t frame;
        if ((ret = decode_frame(&frame, &p, end)) != 0)
            goto Exit;
        if (frame.type != QUICLY_FRAME_TYPE_ACK)
            should_ack = 1;
        switch (frame.type) {
        case QUICLY_FRAME_TYPE_PADDING:
            break;
        case QUICLY_FRAME_TYPE_STREAM:
            if ((ret = handle_stream_frame(conn, &frame)) != 0)
                goto Exit;
            break;
        case QUICLY_FRAME_TYPE_ACK:
            if ((ret = handle_ack_frame(conn, &frame)) != 0)
                goto Exit;
            break;
        case QUICLY_FRAME_TYPE_MAX_STREAM_DATA:
            if ((ret = handle_max_stream_data_frame(conn, &frame)) != 0)
                goto Exit;
            break;
        default:
            assert(!"FIXME");
            break;
        }
    } while (p != end);
    if (should_ack) {
        if ((ret = quicly_ranges_update(&conn->ingress.ack_queue, packet->packet_number, packet->packet_number + 1)) != 0)
            goto Exit;
        if (aead != NULL)
            conn->egress.acks_require_encryption = 1;
    }

Exit:
    return ret;
}

int quicly_open_stream(quicly_conn_t *conn, quicly_stream_t **stream)
{
    if (conn->super.host.next_stream_id == 0)
        return QUICLY_ERROR_TOO_MANY_OPEN_STREAMS;

    if ((*stream = open_stream(conn, conn->super.host.next_stream_id)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    if ((conn->super.host.next_stream_id += 2) < 2)
        conn->super.host.next_stream_id = 0;

    return 0;
}

int quicly_reset_stream(quicly_stream_t *stream)
{
    /* TODO */
    return QUICLY_ERROR_TBD;
}

quicly_raw_packet_t *quicly_default_alloc_packet(quicly_context_t *ctx, socklen_t salen, size_t payloadsize)
{
    quicly_raw_packet_t *packet;

    if ((packet = malloc(offsetof(quicly_raw_packet_t, sa) + salen + payloadsize)) == NULL)
        return NULL;
    packet->salen = salen;
    packet->data.base = (uint8_t *)packet + offsetof(quicly_raw_packet_t, sa) + salen;

    return packet;
}

void quicly_default_free_packet(quicly_context_t *ctx, quicly_raw_packet_t *packet)
{
    free(packet);
}
