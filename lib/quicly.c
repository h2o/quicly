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
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "khash.h"
#include "quicly.h"
#include "quicly/ack.h"
#include "quicly/frame.h"

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

#define QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS 26
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA 0
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_DATA 1
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_ID 2
#define QUICLY_TRANSPORT_PARAMETER_ID_IDLE_TIMEOUT 3
#define QUICLY_TRANSPORT_PARAMETER_ID_TRUNCATE_CONNECTION_ID 4

#define GET_TYPE_FROM_PACKET_HEADER(p) (*(uint8_t *)(p)&0x1f)

KHASH_MAP_INIT_INT(quicly_stream_t, quicly_stream_t *)

#define DEBUG_LOG(conn, stream_id, ...)                                                                                            \
    do {                                                                                                                           \
        quicly_conn_t *_conn = (conn);                                                                                             \
        if (_conn->super.ctx->debug_log != NULL) {                                                                                 \
            char buf[1024];                                                                                                        \
            snprintf(buf, sizeof(buf), __VA_ARGS__);                                                                               \
            _conn->super.ctx->debug_log(_conn->super.ctx, "%s:%" PRIx64 ",%" PRIu32 ": %s\n",                                      \
                                        quicly_is_client(_conn) ? "client" : "server", _conn->super.connection_id, (stream_id),    \
                                        buf);                                                                                      \
        }                                                                                                                          \
    } while (0)

struct st_quicly_packet_protection_t {
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
    /**
     *
     */
    struct {
        /**
         * crypto parameters
         */
        struct st_quicly_packet_protection_t pp;
        /**
         * acks to be sent to peer
         */
        quicly_ranges_t ack_queue;
        /**
         *
         */
        struct {
            __uint128_t bytes_consumed;
            quicly_maxsender_t sender;
        } max_data;
        /**
         *
         */
        quicly_maxsender_t max_stream_id;
        /**
         *
         */
        uint64_t next_expected_packet_number;
    } ingress;
    /**
     *
     */
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
        quicly_loss_t loss;
        /**
         *
         */
        uint64_t packet_number;
        /**
         *
         */
        struct {
            __uint128_t permitted;
            __uint128_t sent;
        } max_data;
        /**
         *
         */
        uint32_t max_stream_id;
        /**
         *
         */
        quicly_sender_state_t stream_id_blocked_state;
        /**
         *
         */
        int64_t send_ack_at;
        /**
         *
         */
        unsigned acks_require_encryption : 1;
    } egress;
    /**
     * crypto data
     */
    struct {
        quicly_stream_t stream;
        ptls_t *tls;
        ptls_handshake_properties_t handshake_properties;
        struct {
            ptls_raw_extension_t ext[2];
            ptls_buffer_t buf;
        } transport_parameters;
        unsigned pending_control : 1;
        unsigned pending_data : 1;
    } crypto;
    /**
     *
     */
    struct {
        quicly_linklist_t control;
        quicly_linklist_t stream_fin_only;
        quicly_linklist_t stream_with_payload;
    } pending_link;
};

static const quicly_transport_parameters_t transport_params_before_handshake = {8192, 16, 100, 60, 0};

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
    received = quicly_decode64(&p);

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
        packet->connection_id = quicly_decode64(&src);
        packet->packet_number.bits = quicly_decode32(&src);
        packet->packet_number.mask = UINT32_MAX;
        packet->version = quicly_decode32(&src);
    } else {
        /* short header */
        packet->type = (first_byte & 0x20) != 0 ? QUICLY_PACKET_TYPE_1RTT_KEY_PHASE_1 : QUICLY_PACKET_TYPE_1RTT_KEY_PHASE_0;
        packet->is_long_header = 0;
        if ((first_byte & 0x40) != 0) {
            packet->has_connection_id = 1;
            if (src_end - src < 8)
                return QUICLY_ERROR_INVALID_PACKET_HEADER;
            packet->connection_id = quicly_decode64(&src);
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
        packet->packet_number.bits = (uint32_t)quicly_decodev(&src, packet_number_size);
        packet->packet_number.mask = UINT32_MAX >> ((4 - packet_number_size) * 8);
    }

    packet->header.len = src - packet->header.base;
    packet->payload = ptls_iovec_init(src, src_end - src);
    return 0;
}

uint64_t quicly_determine_packet_number(quicly_decoded_packet_t *packet, uint64_t next_expected)
{
    uint64_t actual = (next_expected & ~(uint64_t)packet->packet_number.mask) + packet->packet_number.bits;

    if (((packet->packet_number.bits - (uint32_t)next_expected) & packet->packet_number.mask) > (packet->packet_number.mask >> 1)) {
        if (actual >= (uint64_t)packet->packet_number.mask + 1)
            actual -= (uint64_t)packet->packet_number.mask + 1;
    }

    return actual;
}

static uint8_t *emit_long_header(quicly_conn_t *conn, uint8_t *dst, uint8_t type, uint64_t connection_id,
                                 uint32_t rounded_packet_number)
{
    *dst++ = 0x80 | type;
    dst = quicly_encode64(dst, connection_id);
    dst = quicly_encode32(dst, rounded_packet_number);
    dst = quicly_encode32(dst, QUICLY_PROTOCOL_VERSION);
    return dst;
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

static void sched_stream_control(quicly_stream_t *stream)
{
    if (stream->stream_id != 0) {
        if (!quicly_linklist_is_linked(&stream->_send_aux.pending_link.control))
            quicly_linklist_insert(&stream->conn->pending_link.control, &stream->_send_aux.pending_link.control);
    } else {
        stream->conn->crypto.pending_control = 1;
    }
}

static void resched_stream_data(quicly_stream_t *stream)
{
    quicly_linklist_t *target = NULL;

    if (stream->stream_id == 0) {
        stream->conn->crypto.pending_data = 1;
        return;
    }

    /* unlink so that we would round-robin the streams */
    if (quicly_linklist_is_linked(&stream->_send_aux.pending_link.stream))
        quicly_linklist_unlink(&stream->_send_aux.pending_link.stream);

    if (stream->sendbuf.pending.num_ranges != 0) {
        if (stream->sendbuf.pending.ranges[0].start == stream->sendbuf.eos) {
            /* fin is the only thing to be sent, and it can be sent if window size is zero */
            target = &stream->conn->pending_link.stream_fin_only;
        } else {
            /* check if we can send payload */
            if (stream->sendbuf.pending.ranges[0].start < stream->_send_aux.max_stream_data)
                target = &stream->conn->pending_link.stream_with_payload;
        }
    }

    if (target != NULL)
        quicly_linklist_insert(target, &stream->_send_aux.pending_link.stream);
}

static int stream_id_blocked(quicly_conn_t *conn)
{
    return conn->super.host.next_stream_id == 0 || conn->super.host.next_stream_id > conn->egress.max_stream_id;
}

static int should_update_max_stream_data(quicly_stream_t *stream)
{
    return quicly_maxsender_should_update(&stream->_send_aux.max_stream_data_sender, stream->recvbuf.data_off,
                                          stream->_recv_aux.window, 512);
}

static void on_sendbuf_change(quicly_sendbuf_t *buf)
{
    quicly_stream_t *stream = (void *)((char *)buf - offsetof(quicly_stream_t, sendbuf));
    assert(stream->stream_id != 0 || buf->eos == UINT64_MAX);

    resched_stream_data(stream);
}

static void on_recvbuf_change(quicly_recvbuf_t *buf, size_t shift_amount)
{
    quicly_stream_t *stream = (void *)((char *)buf - offsetof(quicly_stream_t, recvbuf));

    if (stream->stream_id != 0) {
        stream->conn->ingress.max_data.bytes_consumed += shift_amount;
        if (should_update_max_stream_data(stream))
            sched_stream_control(stream);
    }
}

static void init_stream(quicly_stream_t *stream, quicly_conn_t *conn, uint32_t stream_id)
{
    stream->conn = conn;
    stream->stream_id = stream_id;
    quicly_sendbuf_init(&stream->sendbuf, on_sendbuf_change);
    quicly_recvbuf_init(&stream->recvbuf, on_recvbuf_change);

    stream->_send_aux.max_stream_data = conn->super.peer.transport_params.initial_max_stream_data;
    stream->_send_aux.max_sent = 0;
    stream->_send_aux.stop_sending.sender_state = QUICLY_SENDER_STATE_NONE;
    stream->_send_aux.stop_sending.reason = 0;
    stream->_send_aux.rst.sender_state = QUICLY_SENDER_STATE_NONE;
    stream->_send_aux.rst.reason = 0;
    quicly_maxsender_init(&stream->_send_aux.max_stream_data_sender, conn->super.ctx->transport_params.initial_max_stream_data);
    quicly_linklist_init(&stream->_send_aux.pending_link.control);
    quicly_linklist_init(&stream->_send_aux.pending_link.stream);

    stream->_recv_aux.window = conn->super.ctx->transport_params.initial_max_stream_data;
    stream->_recv_aux.rst_reason = QUICLY_ERROR_FIN_CLOSED;

    int r;
    khiter_t iter = kh_put(quicly_stream_t, conn->streams, stream_id, &r);
    assert(iter != kh_end(conn->streams));
    kh_val(conn->streams, iter) = stream;
}

static quicly_stream_t *open_stream(quicly_conn_t *conn, uint32_t stream_id)
{
    quicly_stream_t *stream;

    if ((stream = conn->super.ctx->alloc_stream(conn->super.ctx)) == NULL)
        return NULL;
    init_stream(stream, conn, stream_id);
    return stream;
}

static void destroy_stream(quicly_stream_t *stream)
{
    quicly_conn_t *conn = stream->conn;
    khiter_t iter = kh_get(quicly_stream_t, conn->streams, stream->stream_id);
    assert(iter != kh_end(conn->streams));
    kh_del(quicly_stream_t, conn->streams, iter);

    quicly_sendbuf_dispose(&stream->sendbuf);
    conn->ingress.max_data.bytes_consumed += stream->recvbuf.data.len;
    quicly_recvbuf_dispose(&stream->recvbuf);
    quicly_maxsender_dispose(&stream->_send_aux.max_stream_data_sender);
    quicly_linklist_unlink(&stream->_send_aux.pending_link.control);
    quicly_linklist_unlink(&stream->_send_aux.pending_link.stream);

    if (stream->stream_id != 0) {
        if (quicly_is_client(conn) == stream->stream_id % 2) {
            --conn->super.host.num_streams;
        } else {
            --conn->super.peer.num_streams;
        }
        conn->super.ctx->free_stream(stream);
    }
}

quicly_stream_t *quicly_get_stream(quicly_conn_t *conn, uint32_t stream_id)
{
    khiter_t iter = kh_get(quicly_stream_t, conn->streams, stream_id);
    if (iter != kh_end(conn->streams))
        return kh_val(conn->streams, iter);
    return NULL;
}

void quicly_get_max_data(quicly_conn_t *conn, __uint128_t *send_permitted, __uint128_t *sent, __uint128_t *consumed)
{
    if (send_permitted != NULL)
        *send_permitted = conn->egress.max_data.permitted;
    if (sent != NULL)
        *sent = conn->egress.max_data.sent;
    if (consumed != NULL)
        *consumed = conn->ingress.max_data.bytes_consumed;
}

void quicly_free(quicly_conn_t *conn)
{
    quicly_stream_t *stream;

    free_packet_protection(&conn->ingress.pp);
    quicly_ranges_dispose(&conn->ingress.ack_queue);
    quicly_maxsender_dispose(&conn->ingress.max_data.sender);
    quicly_maxsender_dispose(&conn->ingress.max_stream_id);
    free_packet_protection(&conn->egress.pp);
    quicly_acks_dispose(&conn->egress.acks);

    kh_foreach_value(conn->streams, stream, { destroy_stream(stream); });
    kh_destroy(quicly_stream_t, conn->streams);

    assert(!quicly_linklist_is_linked(&conn->pending_link.control));
    assert(!quicly_linklist_is_linked(&conn->pending_link.stream_fin_only));
    assert(!quicly_linklist_is_linked(&conn->pending_link.stream_with_payload));

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
    static const char *labels[2] = {"EXPORTER-QUIC client 1-RTT Secret", "EXPORTER-QUIC server 1-RTT Secret"};
    int ret;

    if ((ret = setup_1rtt_secret(&conn->ingress.pp, tls, labels[quicly_is_client(conn)], 0)) != 0)
        goto Exit;
    if ((ret = setup_1rtt_secret(&conn->egress.pp, tls, labels[!quicly_is_client(conn)], 1)) != 0)
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

static void write_tlsbuf(quicly_conn_t *conn, ptls_buffer_t *tlsbuf)
{
    if (tlsbuf->off != 0) {
        assert(tlsbuf->is_allocated);
        quicly_sendbuf_write(&conn->crypto.stream.sendbuf, tlsbuf->base, tlsbuf->off, senddata_free);
        ptls_buffer_init(tlsbuf, "", 0);
    } else {
        assert(!tlsbuf->is_allocated);
    }
}

static int crypto_stream_receive_handshake(quicly_stream_t *_stream)
{
    quicly_conn_t *conn = (void *)((char *)_stream - offsetof(quicly_conn_t, crypto.stream));
    ptls_iovec_t input;
    ptls_buffer_t buf;
    int ret = PTLS_ERROR_IN_PROGRESS;

    ptls_buffer_init(&buf, "", 0);
    while (ret == PTLS_ERROR_IN_PROGRESS && (input = quicly_recvbuf_get(&conn->crypto.stream.recvbuf)).len != 0) {
        ret = ptls_handshake(conn->crypto.tls, &buf, input.base, &input.len, &conn->crypto.handshake_properties);
        quicly_recvbuf_shift(&conn->crypto.stream.recvbuf, input.len);
    }
    write_tlsbuf(conn, &buf);

    switch (ret) {
    case 0:
        DEBUG_LOG(conn, 0, "handshake complete");
        /* state is 1RTT_ENCRYPTED when handling ClientFinished */
        if (conn->super.state < QUICLY_STATE_1RTT_ENCRYPTED) {
            conn->egress.max_data.permitted = (__uint128_t)conn->super.peer.transport_params.initial_max_data_kb * 1024;
            conn->egress.max_stream_id = conn->super.peer.transport_params.initial_max_stream_id;
            if ((ret = setup_1rtt(conn, conn->crypto.tls)) != 0)
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

static int do_apply_stream_frame(quicly_stream_t *stream, uint64_t off, ptls_iovec_t data)
{
    int ret;

    /* adjust the range of supplied data so that we not go above eos */
    if (stream->recvbuf.eos <= off)
        return 0;
    if (stream->recvbuf.eos < off + data.len)
        data.len = stream->recvbuf.eos - off;

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
        struct st_quicly_buffer_vec_t vec = {NULL};
        assert(stream->recvbuf.received.num_ranges == 1);
        assert(stream->recvbuf.received.ranges[0].end == stream->recvbuf.data_off);

        if (data.len != 0) {
            stream->recvbuf.received.ranges[0].end += data.len;
            quicly_buffer_set_fast_external(&stream->recvbuf.data, &vec, data.base, data.len);
        }
        if ((ret = stream->on_update(stream)) != 0)
            return ret;
        /* stream might have been destroyed; in such case vec.len would be zero (see quicly_buffer_dispose) */
        if (vec.len != 0 && stream->recvbuf.data.len != 0) {
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
        ret = stream->on_update(stream);
    return ret;
}

static int apply_stream_frame(quicly_stream_t *stream, quicly_stream_frame_t *frame)
{
    int ret;

    DEBUG_LOG(stream->conn, stream->stream_id, "received; off=%" PRIu64 ",len=%zu", frame->offset, frame->data.len);

    if (frame->is_fin && (ret = quicly_recvbuf_mark_eos(&stream->recvbuf, frame->offset + frame->data.len)) != 0)
        return ret;
    if ((ret = do_apply_stream_frame(stream, frame->offset, frame->data)) != 0)
        return ret;
    if (should_update_max_stream_data(stream))
        sched_stream_control(stream);

    return ret;
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
                                 { ptls_buffer_push32(buf, params->initial_max_data_kb); });
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
                    if ((ret = ptls_decode32(&params->initial_max_data_kb, &src, end)) != 0)
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
                                        ptls_handshake_properties_t *handshake_properties)
{
    ptls_t *tls = NULL;
    quicly_conn_t *conn;

    if ((tls = ptls_new(ctx->tls, server_name == NULL)) == NULL)
        return NULL;
    if (server_name != NULL && ptls_set_server_name(tls, server_name, strlen(server_name)) != 0) {
        ptls_free(tls);
        return NULL;
    }
    if ((conn = malloc(sizeof(*conn))) == NULL) {
        ptls_free(tls);
        return NULL;
    }

    memset(conn, 0, sizeof(*conn));
    conn->super.ctx = ctx;
    if (server_name != NULL) {
        conn->super.host.next_stream_id = 1;
        conn->super.peer.next_stream_id = 2;
        ctx->tls->random_bytes(&conn->super.connection_id, sizeof(conn->super.connection_id));
    } else {
        conn->super.host.next_stream_id = 2;
        conn->super.peer.next_stream_id = 1;
    }
    conn->super.peer.transport_params = transport_params_before_handshake;
    conn->streams = kh_init(quicly_stream_t);
    quicly_ranges_init(&conn->ingress.ack_queue);
    quicly_maxsender_init(&conn->ingress.max_data.sender, conn->super.ctx->transport_params.initial_max_data_kb);
    quicly_maxsender_init(&conn->ingress.max_stream_id, conn->super.ctx->transport_params.initial_max_stream_id);
    quicly_acks_init(&conn->egress.acks);
    quicly_loss_init(&conn->egress.loss, &conn->super.ctx->loss,
                     conn->super.ctx->loss.default_initial_rtt /* FIXME remember initial_rtt in session ticket */);
    conn->egress.send_ack_at = INT64_MAX;
    init_stream(&conn->crypto.stream, conn, 0);
    conn->crypto.stream.on_update = crypto_stream_receive_handshake;
    conn->crypto.tls = tls;
    if (handshake_properties != NULL) {
        assert(handshake_properties->additional_extensions == NULL);
        assert(handshake_properties->collect_extension == NULL);
        assert(handshake_properties->collected_extensions == NULL);
        conn->crypto.handshake_properties = *handshake_properties;
    } else {
        conn->crypto.handshake_properties = (ptls_handshake_properties_t){{{{NULL}}}};
    }
    conn->crypto.handshake_properties.collect_extension = collect_transport_parameters;
    quicly_linklist_init(&conn->pending_link.control);
    quicly_linklist_init(&conn->pending_link.stream_fin_only);
    quicly_linklist_init(&conn->pending_link.stream_with_payload);

    if (set_peeraddr(conn, sa, salen) != 0) {
        quicly_free(conn);
        return NULL;
    }

    return conn;
}

static int client_collected_extensions(ptls_t *tls, ptls_handshake_properties_t *properties, ptls_raw_extension_t *slots)
{
    quicly_conn_t *conn = (void *)((char *)properties - offsetof(quicly_conn_t, crypto.handshake_properties));
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
    ret = decode_transport_parameter_list(&conn->super.peer.transport_params, src, end);

Exit:
    return ret;
}

int quicly_connect(quicly_conn_t **_conn, quicly_context_t *ctx, const char *server_name, struct sockaddr *sa, socklen_t salen,
                   ptls_handshake_properties_t *handshake_properties)
{
    quicly_conn_t *conn;
    ptls_buffer_t buf;
    int ret;

    if ((conn = create_connection(ctx, server_name, sa, salen, handshake_properties)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* handshake */
    ptls_buffer_init(&conn->crypto.transport_parameters.buf, "", 0);
    ptls_buffer_push32(&conn->crypto.transport_parameters.buf, QUICLY_PROTOCOL_VERSION);
    ptls_buffer_push32(&conn->crypto.transport_parameters.buf, QUICLY_PROTOCOL_VERSION);
    if ((ret = encode_transport_parameter_list(&ctx->transport_params, &conn->crypto.transport_parameters.buf)) != 0)
        goto Exit;
    conn->crypto.transport_parameters.ext[0] =
        (ptls_raw_extension_t){QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS,
                               {conn->crypto.transport_parameters.buf.base, conn->crypto.transport_parameters.buf.off}};
    conn->crypto.transport_parameters.ext[1] = (ptls_raw_extension_t){UINT16_MAX};
    conn->crypto.handshake_properties.additional_extensions = conn->crypto.transport_parameters.ext;
    conn->crypto.handshake_properties.collected_extensions = client_collected_extensions;

    ptls_buffer_init(&buf, "", 0);
    if ((ret = ptls_handshake(conn->crypto.tls, &buf, NULL, 0, &conn->crypto.handshake_properties)) != PTLS_ERROR_IN_PROGRESS)
        goto Exit;
    write_tlsbuf(conn, &buf);

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
    quicly_conn_t *conn = (void *)((char *)properties - offsetof(quicly_conn_t, crypto.handshake_properties));
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
        if ((ret = decode_transport_parameter_list(&conn->super.peer.transport_params, src, end)) != 0)
            goto Exit;
    }

    /* set transport_parameters extension to be sent in EE */
    assert(properties->additional_extensions == NULL);
    ptls_buffer_init(&conn->crypto.transport_parameters.buf, "", 0);
    ptls_buffer_push_block(&conn->crypto.transport_parameters.buf, 1,
                           { ptls_buffer_push32(&conn->crypto.transport_parameters.buf, QUICLY_PROTOCOL_VERSION); });
    if ((ret = encode_transport_parameter_list(&conn->super.ctx->transport_params, &conn->crypto.transport_parameters.buf)) != 0)
        goto Exit;
    properties->additional_extensions = conn->crypto.transport_parameters.ext;
    conn->crypto.transport_parameters.ext[0] =
        (ptls_raw_extension_t){QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS,
                               {conn->crypto.transport_parameters.buf.base, conn->crypto.transport_parameters.buf.off}};
    conn->crypto.transport_parameters.ext[1] = (ptls_raw_extension_t){UINT16_MAX};
    conn->crypto.handshake_properties.additional_extensions = conn->crypto.transport_parameters.ext;

    ret = 0;

Exit:
    return ret;
}

int quicly_accept(quicly_conn_t **_conn, quicly_context_t *ctx, struct sockaddr *sa, socklen_t salen,
                  ptls_handshake_properties_t *handshake_properties, quicly_decoded_packet_t *packet)
{
    quicly_conn_t *conn = NULL;
    quicly_stream_frame_t frame;
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
        const uint8_t *src = packet->payload.base, *end = src + packet->payload.len;
        uint8_t type_flags;
        for (; src < end; ++src) {
            if (*src != QUICLY_FRAME_TYPE_PADDING)
                break;
        }
        if (src == end || (type_flags = *src++) < QUICLY_FRAME_TYPE_STREAM) {
            ret = QUICLY_ERROR_TBD;
            goto Exit;
        }
        if ((ret = quicly_decode_stream_frame(type_flags, &src, end, &frame)) != 0)
            goto Exit;
        if (!(frame.stream_id == 0 && frame.offset == 0)) {
            ret = QUICLY_ERROR_INVALID_STREAM_DATA;
            goto Exit;
        }
        /* FIXME check packet size */
        for (; src < end; ++src) {
            if (*src != QUICLY_FRAME_TYPE_PADDING) {
                ret = QUICLY_ERROR_TBD;
                goto Exit;
            }
        }
    }

    if ((conn = create_connection(ctx, NULL, sa, salen, handshake_properties)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    conn->crypto.handshake_properties.collected_extensions = server_collected_extensions;

    if ((ret = quicly_ranges_update(&conn->ingress.ack_queue, packet->packet_number.bits,
                                    (uint64_t)packet->packet_number.bits + 1)) != 0)
        goto Exit;
    conn->ingress.next_expected_packet_number = (uint64_t)packet->packet_number.bits + 1;

    if ((ret = apply_stream_frame(&conn->crypto.stream, &frame)) != 0)
        goto Exit;
    if (conn->crypto.stream.recvbuf.data_off != frame.data.len) {
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
    int ret;

    DEBUG_LOG(conn, ack->data.stream.stream_id, "%s; off=%" PRIu64 ",len=%zu", acked ? "acked" : "lost",
              ack->data.stream.args.start, (size_t)(ack->data.stream.args.end - ack->data.stream.args.start));

    /* TODO cache pointer to stream (using a generation counter?) */
    if ((stream = quicly_get_stream(conn, ack->data.stream.stream_id)) == NULL)
        return 0;

    if (acked) {
        if ((ret = quicly_sendbuf_acked(&stream->sendbuf, &ack->data.stream.args)) != 0)
            return ret;
        if (quicly_stream_is_closable(stream) && (ret = stream->on_update(stream)) != 0)
            return ret;
    } else {
        /* FIXME handle rto error */
        if ((ret = quicly_sendbuf_lost(&stream->sendbuf, &ack->data.stream.args)) != 0)
            return ret;
        if (stream->_send_aux.rst.sender_state == QUICLY_SENDER_STATE_NONE)
            resched_stream_data(stream);
    }

    return 0;
}

static int on_ack_max_stream_data(quicly_conn_t *conn, int acked, quicly_ack_t *ack)
{
    quicly_stream_t *stream;

    /* TODO cache pointer to stream (using a generation counter?) */
    if ((stream = quicly_get_stream(conn, ack->data.stream.stream_id)) != NULL) {
        if (acked) {
            quicly_maxsender_acked(&stream->_send_aux.max_stream_data_sender, &ack->data.max_stream_data.args);
        } else {
            quicly_maxsender_lost(&stream->_send_aux.max_stream_data_sender, &ack->data.max_stream_data.args);
            if (should_update_max_stream_data(stream))
                sched_stream_control(stream);
        }
    }

    return 0;
}

static int on_ack_max_data(quicly_conn_t *conn, int acked, quicly_ack_t *ack)
{
    if (acked) {
        quicly_maxsender_acked(&conn->ingress.max_data.sender, &ack->data.max_data.args);
    } else {
        quicly_maxsender_lost(&conn->ingress.max_data.sender, &ack->data.max_data.args);
    }

    return 0;
}

static int on_ack_max_stream_id(quicly_conn_t *conn, int acked, quicly_ack_t *ack)
{
    if (acked) {
        quicly_maxsender_acked(&conn->ingress.max_stream_id, &ack->data.max_stream_id.args);
    } else {
        quicly_maxsender_lost(&conn->ingress.max_stream_id, &ack->data.max_stream_id.args);
    }

    return 0;
}

static void on_ack_stream_state_sender(quicly_sender_state_t *sender_state, int acked)
{
    *sender_state = acked ? QUICLY_SENDER_STATE_ACKED : QUICLY_SENDER_STATE_SEND;
}

static int on_ack_rst_stream(quicly_conn_t *conn, int acked, quicly_ack_t *ack)
{
    quicly_stream_t *stream;
    int ret = 0;

    if ((stream = quicly_get_stream(conn, ack->data.stream_state_sender.stream_id)) != NULL) {
        assert(stream->sendbuf.acked.num_ranges == 1);
        assert(stream->sendbuf.acked.ranges[0].end - stream->sendbuf.eos <= 1);
        on_ack_stream_state_sender(&stream->_send_aux.rst.sender_state, acked);
        if (stream->_send_aux.rst.sender_state == QUICLY_SENDER_STATE_ACKED) {
            stream->sendbuf.acked.ranges[0].end = stream->sendbuf.eos + 1;
            if (quicly_stream_is_closable(stream))
                ret = stream->on_update(stream);
        }
    }

    return ret;
}

static int on_ack_stop_sending(quicly_conn_t *conn, int acked, quicly_ack_t *ack)
{
    quicly_stream_t *stream;

    if ((stream = quicly_get_stream(conn, ack->data.stream_state_sender.stream_id)) != NULL) {
        on_ack_stream_state_sender(&stream->_send_aux.stop_sending.sender_state, acked);
        if (stream->_send_aux.stop_sending.sender_state != QUICLY_SENDER_STATE_ACKED)
            sched_stream_control(stream);
    }

    return 0;
}

static int on_ack_stream_id_blocked(quicly_conn_t *conn, int acked, quicly_ack_t *ack)
{
    if (!acked && conn->egress.stream_id_blocked_state == QUICLY_SENDER_STATE_UNACKED && stream_id_blocked(conn)) {
        conn->egress.stream_id_blocked_state = QUICLY_SENDER_STATE_SEND;
    } else {
        conn->egress.stream_id_blocked_state = QUICLY_SENDER_STATE_NONE;
    }

    return 0;
}

int64_t quicly_get_first_timeout(quicly_conn_t *conn)
{
    return conn->egress.loss.alarm_at < conn->egress.send_ack_at ? conn->egress.loss.alarm_at : conn->egress.send_ack_at;
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

static int commit_send_packet(quicly_conn_t *conn, struct st_quicly_send_context_t *s)
{
    if (s->aead != NULL) {
        if (s->dst != s->dst_unencrypted_from)
            encrypt_packet(s);
        s->dst += ptls_aead_encrypt_final(s->aead, s->dst);
    } else {
        if (s->packet_type == QUICLY_PACKET_TYPE_CLIENT_INITIAL) {
            if (s->num_packets != 0)
                return QUICLY_ERROR_HANDSHAKE_TOO_LARGE;
            const size_t max_size = 1272; /* max UDP packet size excluding fnv1a hash */
            assert(s->dst - s->target->data.base <= max_size);
            memset(s->dst, 0, s->target->data.base + max_size - s->dst);
            s->dst = s->target->data.base + max_size;
        }
        uint64_t hash = fnv1a(FNV1A_OFFSET_BASIS, s->target->data.base, s->dst);
        s->dst = quicly_encode64(s->dst, hash);
    }
    s->target->data.len = s->dst - s->target->data.base;
    s->packets[s->num_packets++] = s->target;
    ++conn->egress.packet_number;

    s->target = NULL;
    s->dst = NULL;
    s->dst_end = NULL;
    s->dst_unencrypted_from = NULL;

    return 0;
}

static int prepare_packet(quicly_conn_t *conn, struct st_quicly_send_context_t *s, size_t min_space)
{
    int ret;

    /* allocate and setup the new packet if necessary */
    if (s->dst_end - s->dst < min_space || GET_TYPE_FROM_PACKET_HEADER(s->target->data.base) != s->packet_type) {
        if (s->target != NULL && (ret = commit_send_packet(conn, s)) != 0)
            return ret;
        if (s->num_packets >= s->max_packets)
            return QUICLY_ERROR_SENDBUF_FULL;
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

static int prepare_acked_packet(quicly_conn_t *conn, struct st_quicly_send_context_t *s, size_t min_space, quicly_ack_t **ack,
                                quicly_ack_cb ack_cb)
{
    int ret;

    if ((ret = prepare_packet(conn, s, min_space)) != 0)
        return ret;
    if ((*ack = quicly_acks_allocate(&conn->egress.acks, conn->egress.packet_number, s->now, ack_cb)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    return ret;
}

static int send_ack(quicly_conn_t *conn, struct st_quicly_send_context_t *s)
{
    quicly_ack_frame_encode_params_t encode_params;
    size_t range_index;
    int ret;

    if (conn->ingress.ack_queue.num_ranges == 0)
        return 0;

    quicly_determine_encode_ack_frame_params(&conn->ingress.ack_queue, &encode_params);

    range_index = conn->ingress.ack_queue.num_ranges - 1;
    do {
        if ((ret = prepare_packet(conn, s, quicly_ack_frame_get_minimum_capacity(&encode_params, range_index))) != 0)
            break;
        s->dst = quicly_encode_ack_frame(s->dst, s->dst_end, &conn->ingress.ack_queue, &range_index, &encode_params);
    } while (range_index != SIZE_MAX);

    quicly_ranges_clear(&conn->ingress.ack_queue);
    conn->egress.send_ack_at = INT64_MAX;
    return ret;
}

static int prepare_stream_state_sender(quicly_stream_t *stream, quicly_sender_state_t *sender, struct st_quicly_send_context_t *s,
                                       size_t min_space, quicly_ack_cb ack_cb)
{
    quicly_ack_t *ack;
    int ret;

    if ((ret = prepare_acked_packet(stream->conn, s, min_space, &ack, ack_cb)) != 0)
        return ret;
    ack->data.stream_state_sender.stream_id = stream->stream_id;
    *sender = QUICLY_SENDER_STATE_UNACKED;

    return 0;
}

static int send_stream_control_frames(quicly_stream_t *stream, struct st_quicly_send_context_t *s)
{
    int ret;

    /* send STOP_SENDING if necessray */
    if (stream->_send_aux.stop_sending.sender_state == QUICLY_SENDER_STATE_SEND) {
        if ((ret = prepare_stream_state_sender(stream, &stream->_send_aux.stop_sending.sender_state, s,
                                               QUICLY_STOP_SENDING_FRAME_SIZE, on_ack_stop_sending)) != 0)
            return ret;
        s->dst = quicly_encode_stop_sending_frame(s->dst, stream->stream_id, stream->_send_aux.stop_sending.reason);
    }

    /* send MAX_STREAM_DATA if necessary */
    if (should_update_max_stream_data(stream)) {
        uint64_t new_value = stream->recvbuf.data_off + stream->_recv_aux.window;
        quicly_ack_t *ack;
        /* prepare */
        if ((ret = prepare_acked_packet(stream->conn, s, QUICLY_MAX_STREAM_DATA_FRAME_SIZE, &ack, on_ack_max_stream_data)) != 0)
            return ret;
        /* send */
        s->dst = quicly_encode_max_stream_data_frame(s->dst, stream->stream_id, new_value);
        /* register ack */
        ack->data.max_stream_data.stream_id = stream->stream_id;
        quicly_maxsender_record(&stream->_send_aux.max_stream_data_sender, new_value, &ack->data.max_stream_data.args);
    }

    /* send RST_STREAM if necessary */
    if (stream->_send_aux.rst.sender_state == QUICLY_SENDER_STATE_SEND) {
        if ((ret = prepare_stream_state_sender(stream, &stream->_send_aux.rst.sender_state, s, QUICLY_RST_FRAME_SIZE,
                                               on_ack_rst_stream)) != 0)
            return ret;
        s->dst =
            quicly_encode_rst_stream_frame(s->dst, stream->stream_id, stream->_send_aux.rst.reason, stream->_send_aux.max_sent);
    }

    return 0;
}

static int send_stream_frame(quicly_stream_t *stream, struct st_quicly_send_context_t *s, quicly_sendbuf_dataiter_t *iter,
                             size_t max_bytes)
{
    size_t stream_id_length, offset_length;
    quicly_ack_t *ack;
    int ret;

    quicly_determine_stream_frame_field_lengths(stream->stream_id, iter->stream_off, &stream_id_length, &offset_length);

    if ((ret =
             prepare_acked_packet(stream->conn, s, 1 + stream_id_length + offset_length + (iter->stream_off != stream->sendbuf.eos),
                                  &ack, on_ack_stream)) != 0)
        return ret;

    size_t capacity = s->dst_end - s->dst - (1 + stream_id_length + offset_length);
    size_t avail = max_bytes - (iter->stream_off + max_bytes > stream->sendbuf.eos);
    size_t copysize = capacity <= avail ? capacity : avail;

    s->dst = quicly_encode_stream_frame_header(s->dst, iter->stream_off + copysize >= stream->sendbuf.eos, stream->stream_id,
                                               stream_id_length, iter->stream_off, offset_length,
                                               copysize + 2 < capacity ? copysize : SIZE_MAX);
    if (s->aead != NULL)
        encrypt_packet(s);

    DEBUG_LOG(stream->conn, stream->stream_id, "sending; off=%" PRIu64 ",len=%zu", iter->stream_off, copysize);

    /* adjust remaining send window */
    if (stream->_send_aux.max_sent < iter->stream_off + copysize) {
        if (stream->stream_id != 0) {
            uint64_t delta = iter->stream_off + copysize - stream->_send_aux.max_sent;
            assert(stream->conn->egress.max_data.sent + delta <= stream->conn->egress.max_data.permitted);
            stream->conn->egress.max_data.sent += delta;
        }
        stream->_send_aux.max_sent = iter->stream_off + copysize;
        if (stream->_send_aux.max_sent == stream->sendbuf.eos)
            ++stream->_send_aux.max_sent;
    }

    /* send */
    quicly_sendbuf_emit(&stream->sendbuf, iter, copysize, s->dst, &ack->data.stream.args, s->aead);
    s->dst += copysize;
    s->dst_unencrypted_from = s->dst;

    ack->data.stream.stream_id = stream->stream_id;

    return 0;
}

static int send_stream_data(quicly_stream_t *stream, struct st_quicly_send_context_t *s)
{
    quicly_sendbuf_dataiter_t iter;
    uint64_t max_stream_data;
    size_t i;
    int ret = 0;

    /* determine the maximum offset than can be sent */
    if (stream->_send_aux.max_sent >= stream->sendbuf.eos) {
        max_stream_data = stream->sendbuf.eos + 1;
    } else {
        uint64_t delta = stream->_send_aux.max_stream_data - stream->_send_aux.max_sent;
        if (stream->stream_id != 0 && stream->conn->egress.max_data.permitted - stream->conn->egress.max_data.sent < delta)
            delta = (uint64_t)(stream->conn->egress.max_data.permitted - stream->conn->egress.max_data.sent);
        max_stream_data = stream->_send_aux.max_sent + delta;
        if (max_stream_data == stream->sendbuf.eos)
            ++max_stream_data;
    }

    /* emit packets in the pending ranges */
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
            if ((ret = send_stream_frame(stream, s, &iter, end - iter.stream_off)) != 0) {
                if (ret == QUICLY_ERROR_SENDBUF_FULL)
                    goto ShrinkToIter;
                return ret;
            }
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
    return ret;
}

static int retire_acks(quicly_conn_t *conn, size_t count)
{
    quicly_acks_iter_t iter;
    quicly_ack_t *ack;
    uint64_t pn;
    int ret;

    assert(count != 0);

    quicly_acks_init_iter(&conn->egress.acks, &iter);
    ack = quicly_acks_get(&iter);

    do {
        if ((pn = ack->packet_number) == UINT64_MAX)
            break;
        do {
            if ((ret = ack->acked(conn, 0, ack)) != 0)
                return ret;
            quicly_acks_release(&conn->egress.acks, &iter);
            quicly_acks_next(&iter);
        } while ((ack = quicly_acks_get(&iter))->packet_number == pn);
    } while (--count != 0);

    return 0;
}

static int do_detect_loss(quicly_loss_t *ld, int64_t now, uint64_t largest_acked, uint32_t delay_until_lost, int64_t *loss_time)
{
    quicly_conn_t *conn = (void *)((char *)ld - offsetof(quicly_conn_t, egress.loss));
    quicly_acks_iter_t iter;
    quicly_ack_t *ack;
    int64_t sent_before = now - delay_until_lost;
    uint64_t logged_pn = UINT64_MAX;
    int ret;

    quicly_acks_init_iter(&conn->egress.acks, &iter);

    /* handle loss */
    while ((ack = quicly_acks_get(&iter))->sent_at <= sent_before) {
        if (ack->packet_number != logged_pn) {
            logged_pn = ack->packet_number;
            DEBUG_LOG(conn, 0, "RTO; packet-number: %" PRIu64, logged_pn);
        }
        if ((ret = ack->acked(conn, 0, ack)) != 0)
            return ret;
        quicly_acks_release(&conn->egress.acks, &iter);
        quicly_acks_next(&iter);
    }

    /* schedule next alarm */
    *loss_time = ack->sent_at == INT64_MAX ? INT64_MAX : ack->sent_at + delay_until_lost;

    return 0;
}

int quicly_send(quicly_conn_t *conn, quicly_raw_packet_t **packets, size_t *num_packets)
{
    struct st_quicly_send_context_t s = {UINT8_MAX, NULL, conn->super.ctx->now(conn->super.ctx), packets, *num_packets};
    int ret;

    /* handle timeouts */
    if (conn->egress.loss.alarm_at <= s.now) {
        size_t min_packets_to_send;
        if ((ret = quicly_loss_on_alarm(&conn->egress.loss, s.now, conn->egress.packet_number - 1, do_detect_loss,
                                        &min_packets_to_send)) != 0)
            goto Exit;
        if (min_packets_to_send != 0) {
            /* better way to notify the app that we want to send some packets outside the congestion window? */
            assert(min_packets_to_send <= *num_packets);
            *num_packets = min_packets_to_send;
            if ((ret = retire_acks(conn, min_packets_to_send)) != 0)
                goto Exit;
        }
    }

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
    if (conn->egress.send_ack_at <= s.now && !conn->egress.acks_require_encryption &&
        s.packet_type != QUICLY_PACKET_TYPE_CLIENT_INITIAL) {
        if ((ret = send_ack(conn, &s)) != 0)
            goto Exit;
    }
    if (conn->crypto.pending_control || conn->crypto.pending_data) {
        if (conn->crypto.pending_control) {
            if ((ret = send_stream_control_frames(&conn->crypto.stream, &s)) != 0)
                goto Exit;
            conn->crypto.pending_control = 0;
        }
        if (conn->crypto.pending_data) {
            if ((ret = send_stream_data(&conn->crypto.stream, &s)) != 0)
                goto Exit;
            conn->crypto.pending_data = 0;
        }
    }
    if (s.target != NULL) {
        if (!conn->egress.acks_require_encryption && s.packet_type != QUICLY_PACKET_TYPE_CLIENT_INITIAL) {
            if ((ret = send_ack(conn, &s)) != 0)
                goto Exit;
        }
        if ((ret = commit_send_packet(conn, &s)) != 0)
            goto Exit;
    }

    /* send encrypted frames */
    if (quicly_get_state(conn) == QUICLY_STATE_1RTT_ENCRYPTED) {
        s.packet_type = QUICLY_PACKET_TYPE_1RTT_KEY_PHASE_0;
        s.aead = conn->egress.pp.aead.key_phase0;
        /* acks */
        if (conn->egress.send_ack_at <= s.now) {
            if ((ret = send_ack(conn, &s)) != 0)
                goto Exit;
        }
        /* max_stream_id */
        uint32_t max_stream_id;
        if ((max_stream_id = quicly_maxsender_should_update_stream_id(
                 &conn->ingress.max_stream_id, conn->super.peer.next_stream_id, conn->super.peer.num_streams,
                 conn->super.ctx->transport_params.initial_max_stream_id, 768)) != 0) {
            quicly_ack_t *ack;
            if ((ret = prepare_acked_packet(conn, &s, QUICLY_MAX_STREAM_ID_FRAME_SIZE, &ack, on_ack_max_stream_id)) != 0)
                goto Exit;
            s.dst = quicly_encode_max_stream_id_frame(s.dst, max_stream_id);
            quicly_maxsender_record(&conn->ingress.max_stream_id, max_stream_id, &ack->data.max_stream_id.args);
        }
        /* max_data */
        if (quicly_maxsender_should_update(&conn->ingress.max_data.sender, (uint64_t)(conn->ingress.max_data.bytes_consumed / 1024),
                                           conn->super.ctx->transport_params.initial_max_data_kb, 512)) {
            quicly_ack_t *ack;
            if ((ret = prepare_acked_packet(conn, &s, QUICLY_MAX_DATA_FRAME_SIZE, &ack, on_ack_max_data)) != 0)
                goto Exit;
            uint64_t new_value =
                (uint64_t)(conn->ingress.max_data.bytes_consumed / 1024) + conn->super.ctx->transport_params.initial_max_data_kb;
            s.dst = quicly_encode_max_data_frame(s.dst, new_value);
            quicly_maxsender_record(&conn->ingress.max_data.sender, new_value, &ack->data.max_data.args);
        }
        /* stream_id_blocked */
        if (conn->egress.stream_id_blocked_state == QUICLY_SENDER_STATE_SEND) {
            if (stream_id_blocked(conn)) {
                quicly_ack_t *ack;
                if ((ret = prepare_acked_packet(conn, &s, 1, &ack, on_ack_stream_id_blocked)) != 0)
                    goto Exit;
                *s.dst++ = QUICLY_FRAME_TYPE_STREAM_ID_BLOCKED;
                conn->egress.stream_id_blocked_state = QUICLY_SENDER_STATE_UNACKED;
            } else {
                conn->egress.stream_id_blocked_state = QUICLY_SENDER_STATE_NONE;
            }
        }
        /* stream-level control frames */
        while (s.num_packets != s.max_packets && quicly_linklist_is_linked(&conn->pending_link.control)) {
            quicly_stream_t *stream =
                (void *)((char *)conn->pending_link.control.next - offsetof(quicly_stream_t, _send_aux.pending_link.control));
            if ((ret = send_stream_control_frames(stream, &s)) != 0)
                goto Exit;
            quicly_linklist_unlink(&stream->_send_aux.pending_link.control);
        }
        /* fin-only STREAM frames */
        while (s.num_packets != s.max_packets && quicly_linklist_is_linked(&conn->pending_link.stream_fin_only)) {
            quicly_stream_t *stream = (void *)((char *)conn->pending_link.stream_fin_only.next -
                                               offsetof(quicly_stream_t, _send_aux.pending_link.stream));
            if ((ret = send_stream_data(stream, &s)) != 0)
                goto Exit;
            resched_stream_data(stream);
        }
        /* STREAM frames with payload */
        while (s.num_packets != s.max_packets && quicly_linklist_is_linked(&conn->pending_link.stream_with_payload) &&
               conn->egress.max_data.sent < conn->egress.max_data.permitted) {
            quicly_stream_t *stream = (void *)((char *)conn->pending_link.stream_with_payload.next -
                                               offsetof(quicly_stream_t, _send_aux.pending_link.stream));
            if ((ret = send_stream_data(stream, &s)) != 0)
                goto Exit;
            resched_stream_data(stream);
        }
        /* commit */
        if (s.target != NULL) {
            if ((ret = send_ack(conn, &s)) != 0)
                goto Exit;
            commit_send_packet(conn, &s);
        }
    }

    quicly_loss_update_alarm(&conn->egress.loss, s.now, conn->egress.acks.head != NULL);

    ret = 0;
Exit:
    if (ret == QUICLY_ERROR_SENDBUF_FULL)
        ret = 0;
    if (ret == 0)
        *num_packets = s.num_packets;
    return ret;
}

static int get_stream_or_open_if_new(quicly_conn_t *conn, uint32_t stream_id, quicly_stream_t **stream)
{
    int ret = 0;

    if ((*stream = quicly_get_stream(conn, stream_id)) != NULL)
        goto Exit;

    if (stream_id % 2 != quicly_is_client(conn) && conn->super.peer.next_stream_id != 0 &&
        conn->super.peer.next_stream_id <= stream_id) {
        /* open new streams upto given id */
        do {
            if ((*stream = open_stream(conn, conn->super.peer.next_stream_id)) == NULL) {
                ret = PTLS_ERROR_NO_MEMORY;
                goto Exit;
            }
            if ((ret = conn->super.ctx->on_stream_open(*stream)) != 0) {
                destroy_stream(*stream);
                *stream = NULL;
                goto Exit;
            }
            ++conn->super.peer.num_streams;
            conn->super.peer.next_stream_id += 2;
        } while (stream_id != (*stream)->stream_id);
        /* disallow opening new streams if the number has overlapped */
        if (conn->super.peer.next_stream_id < 2)
            conn->super.peer.next_stream_id = 0;
    }

Exit:
    return ret;
}

static int handle_stream_frame(quicly_conn_t *conn, quicly_stream_frame_t *frame)
{
    quicly_stream_t *stream;
    int ret;

    if ((ret = get_stream_or_open_if_new(conn, frame->stream_id, &stream)) != 0 || stream == NULL)
        return ret;
    return apply_stream_frame(stream, frame);
}

static int handle_rst_stream_frame(quicly_conn_t *conn, quicly_rst_stream_frame_t *frame)
{
    quicly_stream_t *stream;
    uint64_t bytes_missing;
    int ret;

    if ((ret = get_stream_or_open_if_new(conn, frame->stream_id, &stream)) != 0 || stream == NULL)
        return ret;

    if ((ret = quicly_recvbuf_reset(&stream->recvbuf, frame->final_offset, &bytes_missing)) != 0)
        return ret;
    stream->_recv_aux.rst_reason = frame->reason;
    conn->ingress.max_data.bytes_consumed += bytes_missing;

    if (quicly_stream_is_closable(stream))
        ret = stream->on_update(stream);

    return ret;
}

static int handle_ack_frame(quicly_conn_t *conn, quicly_ack_frame_t *frame, int64_t now)
{
    quicly_acks_iter_t iter;
    uint64_t packet_number = frame->smallest_acknowledged;
    int64_t last_packet_sent_at = INT64_MAX;
    int ret;

    quicly_acks_init_iter(&conn->egress.acks, &iter);

    size_t gap_index = frame->num_gaps;
    while (1) {
        uint64_t block_length = frame->ack_block_lengths[gap_index];
        if (block_length != 0) {
            while (quicly_acks_get(&iter)->packet_number < packet_number)
                quicly_acks_next(&iter);
            do {
                quicly_ack_t *ack;
                while ((ack = quicly_acks_get(&iter))->packet_number == packet_number) {
                    last_packet_sent_at = ack->sent_at;
                    if ((ret = ack->acked(conn, 1, ack)) != 0)
                        return ret;
                    quicly_acks_release(&conn->egress.acks, &iter);
                    quicly_acks_next(&iter);
                }
                if (quicly_loss_on_packet_acked(&conn->egress.loss, packet_number)) {
                    /* FIXME notify CC that RTO has been verified */
                }
                ++packet_number;
            } while (--block_length != 0);
        }
        if (gap_index-- == 0)
            break;
        packet_number += frame->gaps[gap_index];
    }

    quicly_loss_on_ack_received(&conn->egress.loss, frame->largest_acknowledged,
                                last_packet_sent_at <= now && packet_number >= frame->largest_acknowledged
                                    ? (uint32_t)(now - last_packet_sent_at)
                                    : UINT32_MAX);
    quicly_loss_detect_loss(&conn->egress.loss, now, conn->egress.packet_number - 1, frame->largest_acknowledged, do_detect_loss);
    quicly_loss_update_alarm(&conn->egress.loss, now, conn->egress.acks.head != NULL);

    return 0;
}

static int handle_max_stream_data_frame(quicly_conn_t *conn, quicly_max_stream_data_frame_t *frame)
{
    quicly_stream_t *stream = quicly_get_stream(conn, frame->stream_id);

    if (stream == NULL)
        return 0;

    if (frame->max_stream_data < stream->_send_aux.max_stream_data)
        return 0;
    stream->_send_aux.max_stream_data = frame->max_stream_data;

    if (stream->_send_aux.rst.sender_state == QUICLY_SENDER_STATE_NONE)
        resched_stream_data(stream);

    return 0;
}

static int handle_stream_blocked_frame(quicly_conn_t *conn, quicly_stream_blocked_frame_t *frame)
{
    quicly_stream_t *stream;

    if ((stream = quicly_get_stream(conn, frame->stream_id)) != NULL)
        quicly_maxsender_reset(&stream->_send_aux.max_stream_data_sender, 0);

    return 0;
}

static int handle_max_stream_id_frame(quicly_conn_t *conn, quicly_max_stream_id_frame_t *frame)
{
    if (frame->max_stream_id < conn->egress.max_stream_id)
        return 0;
    conn->egress.max_stream_id = frame->max_stream_id;
    /* TODO notify the app? */
    return 0;
}

static int handle_stop_sending_frame(quicly_conn_t *conn, quicly_stop_sending_frame_t *frame)
{
    quicly_stream_t *stream;
    int ret;

    if ((ret = get_stream_or_open_if_new(conn, frame->stream_id, &stream)) != 0 || stream == NULL)
        return ret;

    quicly_reset_stream(stream, QUICLY_RESET_STREAM_EGRESS, QUICLY_ERROR_TBD);
    return 0;
}

static int handle_max_data_frame(quicly_conn_t *conn, quicly_max_data_frame_t *frame)
{
    __uint128_t new_value = (__uint128_t)frame->max_data_kb * 1024;

    if (new_value < conn->egress.max_data.permitted)
        return 0;
    conn->egress.max_data.permitted = new_value;

    /* TODO schedule for delivery */
    return 0;
}

int quicly_receive(quicly_conn_t *conn, quicly_decoded_packet_t *packet)
{
    int64_t now = conn->super.ctx->now(conn->super.ctx);
    ptls_aead_context_t *aead = NULL;
    uint64_t packet_number;
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
            /* drop 1rtt-encrypted packets received prior to handshake completion (due to loss of the packet carrying the
             * latter) */
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

    packet_number = quicly_determine_packet_number(packet, conn->ingress.next_expected_packet_number);
    if (aead != NULL) {
        if ((packet->payload.len = ptls_aead_decrypt(aead, packet->payload.base, packet->payload.base, packet->payload.len,
                                                     packet_number, packet->header.base, packet->header.len)) == SIZE_MAX) {
            ret = QUICLY_ERROR_DECRYPTION_FAILURE;
            goto Exit;
        }
    } else {
        if (!verify_cleartext_packet(packet)) {
            ret = QUICLY_ERROR_DECRYPTION_FAILURE;
            goto Exit;
        }
    }
    conn->ingress.next_expected_packet_number = packet_number + 1;

    if (packet->payload.len == 0) {
        ret = QUICLY_ERROR_INVALID_FRAME_DATA;
        goto Exit;
    }

    const uint8_t *src = packet->payload.base, *end = src + packet->payload.len;
    int is_ack_only = 1;
    do {
        uint8_t type_flags = *src++;
        if (type_flags >= QUICLY_FRAME_TYPE_STREAM) {
            quicly_stream_frame_t frame;
            if ((ret = quicly_decode_stream_frame(type_flags, &src, end, &frame)) != 0)
                goto Exit;
            if ((ret = handle_stream_frame(conn, &frame)) != 0)
                goto Exit;
            is_ack_only = 0;
        } else if (type_flags >= QUICLY_FRAME_TYPE_ACK) {
            quicly_ack_frame_t frame;
            if ((ret = quicly_decode_ack_frame(type_flags, &src, end, &frame)) != 0)
                goto Exit;
            if ((ret = handle_ack_frame(conn, &frame, now)) != 0)
                goto Exit;
        } else {
            switch (type_flags) {
            case QUICLY_FRAME_TYPE_PADDING:
                ret = 0;
                break;
            case QUICLY_FRAME_TYPE_RST_STREAM: {
                quicly_rst_stream_frame_t frame;
                if ((ret = quicly_decode_rst_stream_frame(&src, end, &frame)) != 0)
                    goto Exit;
                if ((ret = handle_rst_stream_frame(conn, &frame)) != 0)
                    goto Exit;
            } break;
            case QUICLY_FRAME_TYPE_MAX_DATA: {
                quicly_max_data_frame_t frame;
                if ((ret = quicly_decode_max_data_frame(&src, end, &frame)) != 0)
                    goto Exit;
                if ((ret = handle_max_data_frame(conn, &frame)) != 0)
                    goto Exit;
            } break;
            case QUICLY_FRAME_TYPE_MAX_STREAM_DATA: {
                quicly_max_stream_data_frame_t frame;
                if ((ret = quicly_decode_max_stream_data_frame(&src, end, &frame)) != 0)
                    goto Exit;
                if ((ret = handle_max_stream_data_frame(conn, &frame)) != 0)
                    goto Exit;
            } break;
            case QUICLY_FRAME_TYPE_MAX_STREAM_ID: {
                quicly_max_stream_id_frame_t frame;
                if ((ret = quicly_decode_max_stream_id_frame(&src, end, &frame)) != 0)
                    goto Exit;
                if ((ret = handle_max_stream_id_frame(conn, &frame)) != 0)
                    goto Exit;
            } break;
            case QUICLY_FRAME_TYPE_PING:
                ret = 0;
                break;
            case QUICLY_FRAME_TYPE_BLOCKED:
                quicly_maxsender_reset(&conn->ingress.max_data.sender, 0);
                ret = 0;
                break;
            case QUICLY_FRAME_TYPE_STREAM_BLOCKED: {
                quicly_stream_blocked_frame_t frame;
                if ((ret = quicly_decode_stream_blocked_frame(&src, end, &frame)) != 0)
                    goto Exit;
                if ((ret = handle_stream_blocked_frame(conn, &frame)) != 0)
                    goto Exit;
            } break;
            case QUICLY_FRAME_TYPE_STREAM_ID_BLOCKED:
                quicly_maxsender_reset(&conn->ingress.max_stream_id, 0);
                ret = 0;
                break;
            case QUICLY_FRAME_TYPE_STOP_SENDING: {
                quicly_stop_sending_frame_t frame;
                if ((ret = quicly_decode_stop_sending_frame(&src, end, &frame)) != 0)
                    goto Exit;
                if ((ret = handle_stop_sending_frame(conn, &frame)) != 0)
                    goto Exit;
            } break;
            default:
                assert(!"FIXME");
                break;
            }
            is_ack_only = 0;
        }
    } while (src != end);

    if ((ret = quicly_ranges_update(&conn->ingress.ack_queue, packet_number, packet_number + 1)) != 0)
        goto Exit;
    if (aead != NULL)
        conn->egress.acks_require_encryption = 1;
    if (!is_ack_only && conn->egress.send_ack_at == INT64_MAX) {
        conn->egress.send_ack_at = conn->super.ctx->now(conn->super.ctx) + QUICLY_DELAYED_ACK_TIMEOUT;
    }

Exit:
    return ret;
}

int quicly_open_stream(quicly_conn_t *conn, quicly_stream_t **stream)
{
    if (stream_id_blocked(conn)) {
        conn->egress.stream_id_blocked_state = QUICLY_SENDER_STATE_SEND;
        return QUICLY_ERROR_TOO_MANY_OPEN_STREAMS;
    }

    if ((*stream = open_stream(conn, conn->super.host.next_stream_id)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    ++conn->super.host.num_streams;
    if ((conn->super.host.next_stream_id += 2) < 2)
        conn->super.host.next_stream_id = 0;

    return 0;
}

void quicly_reset_stream(quicly_stream_t *stream, unsigned direction, uint32_t reason)
{
    if ((direction & QUICLY_RESET_STREAM_EGRESS) != 0) {
        /* if we have not yet sent FIN, then... */
        if (stream->_send_aux.max_sent <= stream->sendbuf.eos) {
            /* close the sender and mark the eos as the only byte that's not confirmed */
            assert(!quicly_sendbuf_transfer_complete(&stream->sendbuf));
            quicly_sendbuf_shutdown(&stream->sendbuf);
            quicly_sendbuf_ackargs_t ackargs = {0, stream->sendbuf.eos};
            quicly_sendbuf_acked(&stream->sendbuf, &ackargs);
            /* setup RST_STREAM */
            stream->_send_aux.rst.sender_state = QUICLY_SENDER_STATE_SEND;
            stream->_send_aux.rst.reason = reason;
            /* schedule for delivery */
            sched_stream_control(stream);
        }
    }

    if ((direction & QUICLY_RESET_STREAM_INGRESS) != 0) {
        /* send STOP_SENDING if the incoming side of the stream is still open */
        if (stream->recvbuf.eos == UINT64_MAX && stream->_send_aux.stop_sending.sender_state == QUICLY_SENDER_STATE_NONE) {
            stream->_send_aux.stop_sending.sender_state = QUICLY_SENDER_STATE_SEND;
            sched_stream_control(stream);
        }
    }
}

void quicly_close_stream(quicly_stream_t *stream)
{
    assert(quicly_stream_is_closable(stream));
    destroy_stream(stream);
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

quicly_stream_t *quicly_default_alloc_stream(quicly_context_t *ctx)
{
    return malloc(sizeof(quicly_stream_t));
}

void quicly_default_free_stream(quicly_stream_t *stream)
{
    free(stream);
}

int64_t quicly_default_now(quicly_context_t *ctx)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

void quicly_default_debug_log(quicly_context_t *ctx, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}
