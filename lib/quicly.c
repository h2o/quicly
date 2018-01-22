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

#define QUICLY_PROTOCOL_VERSION 0xff000008

#define QUICLY_PACKET_TYPE_INITIAL 0xff
#define QUICLY_PACKET_TYPE_RETRY 0xfe
#define QUICLY_PACKET_TYPE_HANDSHAKE 0xfd
#define QUICLY_PACKET_TYPE_0RTT_PROTECTED 0xfc
#define QUICLY_PACKET_TYPE_LONG_MIN QUICLY_PACKET_TYPE_0RTT_PROTECTED

#define QUICLY_PACKET_TYPE_IS_1RTT(t) (((t)&0x80) == 0)
#define QUICLY_PACKET_TYPE_1RTT_TO_KEY_PHASE(t) (((t)&0x20) != 0)

#define QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS 26
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA 0
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_DATA 1
#define QUICLY_TRANSPORT_PARAMETER_ID_IDLE_TIMEOUT 3
#define QUICLY_TRANSPORT_PARAMETER_ID_STATELESS_RESET_TOKEN 6
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_ID_BIDI 2
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_ID_UNI 8
#define QUICLY_TRANSPORT_PARAMETER_ID_OMIT_CONNECTION_ID 4

#define STATELESS_RESET_TOKEN_SIZE 16

#define STREAM_IS_CLIENT_INITIATED(stream_id) (((stream_id)&1) == 0)
#define STREAM_IS_UNI(stream_id) (((stream_id)&2) != 0)

KHASH_MAP_INIT_INT64(quicly_stream_t, quicly_stream_t *)

#define DEBUG_LOG(conn, stream_id, ...)                                                                                            \
    do {                                                                                                                           \
        quicly_conn_t *_conn = (conn);                                                                                             \
        if (_conn->super.ctx->debug_log != NULL) {                                                                                 \
            char buf[1024];                                                                                                        \
            snprintf(buf, sizeof(buf), __VA_ARGS__);                                                                               \
            _conn->super.ctx->debug_log(_conn->super.ctx, "%s:%" PRIx64 ",%" PRIu64 ": %s\n",                                      \
                                        quicly_is_client(_conn) ? "client" : "server", _conn->super.connection_id,                 \
                                        (uint64_t)(stream_id), buf);                                                               \
        }                                                                                                                          \
    } while (0)

struct st_quicly_packet_protection_t {
    struct {
        ptls_aead_context_t *handshake;
        ptls_aead_context_t *early_data;
        ptls_aead_context_t *one_rtt[2];
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
            uint64_t bytes_consumed;
            quicly_maxsender_t sender;
        } max_data;
        /**
         *
         */
        quicly_maxsender_t max_stream_id_bidi;
        /**
         *
         */
        quicly_maxsender_t max_stream_id_uni;
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
        uint64_t packet_number;
        /**
         *
         */
        struct {
            uint64_t permitted;
            uint64_t sent;
        } max_data;
        /**
         *
         */
        uint64_t max_stream_id_bidi;
        /**
         *
         */
        uint64_t max_stream_id_uni;
        /**
         *
         */
        quicly_sender_state_t stream_id_blocked_state;
        /**
         *
         */
        int64_t send_ack_at;
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

const quicly_context_t quicly_default_context = {
    NULL,      /* tls */
    1280,      /* max_packet_size */
    1000,      /* initial_rto */
    16384,     /* initial_max_stream_data */
    65536,     /* initial_max_data */
    600,       /* idle_timeout */
    100,       /* max_concurrent_streams_bidi */
    0,         /* max_concurrent_streams_uni */
    {0, NULL}, /* stateless_retry {enforce_use, key} */
    0,         /* enforce_version_negotiation */
    quicly_default_alloc_packet,
    quicly_default_free_packet,
    quicly_default_alloc_stream,
    quicly_default_free_stream,
    NULL, /* on_stream_open */
    quicly_default_now,
    NULL, /* debug_log */
};

static const quicly_transport_parameters_t transport_params_before_handshake = {8192, 16, 100, 60, 0};

static void free_packet_protection(struct st_quicly_packet_protection_t *pp)
{
    if (pp->aead.handshake != NULL)
        ptls_aead_free(pp->aead.handshake);
    if (pp->aead.early_data != NULL)
        ptls_aead_free(pp->aead.early_data);
    if (pp->aead.one_rtt[0] != NULL)
        ptls_aead_free(pp->aead.one_rtt[0]);
    if (pp->aead.one_rtt[1] != NULL)
        ptls_aead_free(pp->aead.one_rtt[1]);
}

int quicly_decode_packet(quicly_decoded_packet_t *packet, const uint8_t *src, size_t len)
{
    if (len < 2)
        goto Error;

    packet->header.base = (void *)src;

    const uint8_t *src_end = src + len;

    packet->first_byte = *src++;
    if (!QUICLY_PACKET_TYPE_IS_1RTT(packet->first_byte)) {
        /* long header */
        if (src_end - src < 16)
            goto Error;
        packet->connection_id = quicly_decode64(&src);
        packet->version = quicly_decode32(&src);
        packet->packet_number.bits = quicly_decode32(&src);
        packet->packet_number.mask = UINT32_MAX;
    } else {
        /* short header */
        if ((packet->first_byte & 0x40) == 0) {
            if (src_end - src < 8)
                goto Error;
            packet->connection_id = quicly_decode64(&src);
        }
        switch (packet->first_byte & 0x1f) {
        case 0x1f:
            if (src_end - src < 1)
                goto Error;
            packet->packet_number.bits = *src++;
            packet->packet_number.mask = UINT8_MAX;
            break;
        case 0x1e:
            if (src_end - src < 2)
                goto Error;
            packet->packet_number.bits = quicly_decode16(&src);
            packet->packet_number.mask = UINT16_MAX;
            break;
        case 0x1d:
            if (src_end - src < 4)
                goto Error;
            packet->packet_number.bits = quicly_decode32(&src);
            packet->packet_number.mask = UINT32_MAX;
            break;
        default:
            goto Error;
        }
    }

    packet->header.len = src - packet->header.base;
    packet->payload = ptls_iovec_init(src, src_end - src);
    return 0;

Error:
    return QUICLY_ERROR_PROTOCOL_VIOLATION;
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

static int stream_id_blocked(quicly_conn_t *conn, int uni)
{
    uint64_t *next_id = uni ? &conn->super.host.next_stream_id_uni : &conn->super.host.next_stream_id_bidi,
             *max_id = uni ? &conn->egress.max_stream_id_uni : &conn->egress.max_stream_id_bidi;
    return *next_id > *max_id;
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

static void init_stream_properties(quicly_stream_t *stream)
{
    quicly_sendbuf_init(&stream->sendbuf, on_sendbuf_change);
    quicly_recvbuf_init(&stream->recvbuf, on_recvbuf_change);

    stream->_send_aux.max_stream_data = stream->conn->super.peer.transport_params.initial_max_stream_data;
    stream->_send_aux.max_sent = 0;
    stream->_send_aux.stop_sending.sender_state = QUICLY_SENDER_STATE_NONE;
    stream->_send_aux.stop_sending.reason = 0;
    stream->_send_aux.rst.sender_state = QUICLY_SENDER_STATE_NONE;
    stream->_send_aux.rst.reason = 0;
    quicly_maxsender_init(&stream->_send_aux.max_stream_data_sender, stream->conn->super.ctx->initial_max_stream_data);
    quicly_linklist_init(&stream->_send_aux.pending_link.control);
    quicly_linklist_init(&stream->_send_aux.pending_link.stream);

    stream->_recv_aux.window = stream->conn->super.ctx->initial_max_stream_data;
    stream->_recv_aux.rst_reason = QUICLY_ERROR_FIN_CLOSED;
}

static void dispose_stream_properties(quicly_stream_t *stream)
{
    quicly_sendbuf_dispose(&stream->sendbuf);
    quicly_recvbuf_dispose(&stream->recvbuf);
    quicly_maxsender_dispose(&stream->_send_aux.max_stream_data_sender);
    quicly_linklist_unlink(&stream->_send_aux.pending_link.control);
    quicly_linklist_unlink(&stream->_send_aux.pending_link.stream);
}

static void init_stream(quicly_stream_t *stream, quicly_conn_t *conn, uint64_t stream_id)
{
    stream->conn = conn;
    stream->stream_id = stream_id;

    int r;
    khiter_t iter = kh_put(quicly_stream_t, conn->streams, stream_id, &r);
    assert(iter != kh_end(conn->streams));
    kh_val(conn->streams, iter) = stream;

    init_stream_properties(stream);
}

static void reinit_stream_properties(quicly_stream_t *stream)
{
    dispose_stream_properties(stream);
    init_stream_properties(stream);
}

static quicly_stream_t *open_stream(quicly_conn_t *conn, uint64_t stream_id)
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

    conn->ingress.max_data.bytes_consumed += stream->recvbuf.data.len;
    dispose_stream_properties(stream);

    if (stream->stream_id != 0) {
        if (quicly_is_client(conn) == STREAM_IS_CLIENT_INITIATED(stream->stream_id)) {
            --conn->super.host.num_streams;
        } else {
            --conn->super.peer.num_streams;
        }
        conn->super.ctx->free_stream(stream);
    }
}

quicly_stream_t *quicly_get_stream(quicly_conn_t *conn, uint64_t stream_id)
{
    khiter_t iter = kh_get(quicly_stream_t, conn->streams, stream_id);
    if (iter != kh_end(conn->streams))
        return kh_val(conn->streams, iter);
    return NULL;
}

void quicly_get_max_data(quicly_conn_t *conn, uint64_t *send_permitted, uint64_t *sent, uint64_t *consumed)
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
    quicly_maxsender_dispose(&conn->ingress.max_stream_id_bidi);
    quicly_maxsender_dispose(&conn->ingress.max_stream_id_uni);
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

static int setup_handshake_secret(ptls_aead_context_t **aead, ptls_cipher_suite_t *cs, const void *master_secret, const char *label,
                                  int is_enc)
{
    uint8_t aead_secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    if ((ret = ptls_hkdf_expand_label(cs->hash, aead_secret, cs->hash->digest_size,
                                      ptls_iovec_init(master_secret, cs->hash->digest_size), label, ptls_iovec_init(NULL, 0))) != 0)
        goto Exit;
    if ((*aead = ptls_aead_new(cs->aead, cs->hash, is_enc, aead_secret)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

Exit:
    ptls_clear_memory(aead_secret, sizeof(aead_secret));
    return ret;
}

static int setup_handshake_encryption(ptls_aead_context_t **ingress, ptls_aead_context_t **egress, quicly_context_t *ctx,
                                      uint64_t connection_id, int is_client)
{
    static const uint8_t salt[] = {0xaf, 0xc8, 0x24, 0xec, 0x5f, 0xc7, 0x7e, 0xca, 0x1e, 0x9d,
                                   0x36, 0xf3, 0x7f, 0xb2, 0xd4, 0x65, 0x18, 0xc3, 0x66, 0x39};
    static const char *labels[2] = {"QUIC client handshake secret", "QUIC server handshake secret"};
    ptls_cipher_suite_t **cs;
    uint8_t ikm[8], secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    /* find aes128gcm cipher */
    for (cs = ctx->tls->cipher_suites;; ++cs) {
        assert(cs != NULL);
        if ((*cs)->id == PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)
            break;
    }

    /* extract master secret */
    quicly_encode64(ikm, connection_id);
    if ((ret = ptls_hkdf_extract((*cs)->hash, secret, ptls_iovec_init(salt, sizeof(salt)), ptls_iovec_init(ikm, sizeof(ikm)))) != 0)
        goto Exit;

    /* create aead contexts */
    if ((ret = setup_handshake_secret(ingress, *cs, secret, labels[is_client], 0)) != 0)
        goto Exit;
    if ((ret = setup_handshake_secret(egress, *cs, secret, labels[!is_client], 1)) != 0)
        goto Exit;

Exit:
    ptls_clear_memory(secret, sizeof(secret));
    return ret;
}

static int setup_1rtt_secret(struct st_quicly_packet_protection_t *pp, ptls_t *tls, const char *label, int is_enc)
{
    ptls_cipher_suite_t *cipher = ptls_get_cipher(tls);
    int ret;

    if ((ret = ptls_export_secret(tls, pp->secret, cipher->hash->digest_size, label, ptls_iovec_init(NULL, 0), 0)) != 0)
        return ret;
    if ((pp->aead.one_rtt[0] = ptls_aead_new(cipher->aead, cipher->hash, is_enc, pp->secret)) == NULL)
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

static int crypto_stream_receive_post_handshake(quicly_stream_t *_stream)
{
    quicly_conn_t *conn = (void *)((char *)_stream - offsetof(quicly_conn_t, crypto.stream));
    ptls_buffer_t buf;
    ptls_iovec_t input;
    int ret = 0;

    ptls_buffer_init(&buf, "", 0);
    while ((input = quicly_recvbuf_get(&conn->crypto.stream.recvbuf)).len != 0) {
        if ((ret = ptls_receive(conn->crypto.tls, &buf, input.base, &input.len)) != 0)
            goto Exit;
        quicly_recvbuf_shift(&conn->crypto.stream.recvbuf, input.len);
        if (buf.off != 0) {
            fprintf(stderr, "ptls_receive returned application data\n");
            ret = QUICLY_ERROR_TBD;
            goto Exit;
        }
    }

Exit:
    ptls_buffer_dispose(&buf);
    return ret;
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
        conn->crypto.stream.on_update = crypto_stream_receive_post_handshake;
        /* state is 1RTT_ENCRYPTED when handling ClientFinished */
        if (conn->super.state < QUICLY_STATE_1RTT_ENCRYPTED) {
            conn->egress.max_data.permitted = conn->super.peer.transport_params.initial_max_data;
            conn->egress.max_stream_id_bidi = conn->super.peer.transport_params.initial_max_stream_id_bidi;
            conn->egress.max_stream_id_uni = conn->super.peer.transport_params.initial_max_stream_id_uni;
            if ((ret = setup_1rtt(conn, conn->crypto.tls)) != 0)
                goto Exit;
        }
        break;
    case PTLS_ERROR_IN_PROGRESS:
        if (conn->super.state == QUICLY_STATE_BEFORE_SH)
            conn->super.state = QUICLY_STATE_BEFORE_SF;
        ret = 0;
        break;
    case PTLS_ERROR_STATELESS_RETRY:
        assert(!quicly_is_client(conn));
        assert(conn->super.state == QUICLY_STATE_BEFORE_SH);
        conn->super.state = QUICLY_STATE_SEND_STATELESS_RETRY;
        conn->egress.packet_number = conn->ingress.next_expected_packet_number - 1;
        ret = 0;
        break;
    default:
        break;
    }

Exit:
    return ret;
}

static int crypto_stream_receive_stateless_retry(quicly_stream_t *_stream)
{
    quicly_conn_t *conn = (void *)((char *)_stream - offsetof(quicly_conn_t, crypto.stream));
    ptls_iovec_t input = quicly_recvbuf_get(&conn->crypto.stream.recvbuf);
    size_t consumed = input.len;
    ptls_buffer_t buf;
    int ret;

    ptls_buffer_init(&buf, "", 0);

    /* should have received HRR */
    ret = ptls_handshake(conn->crypto.tls, &buf, input.base, &consumed, &conn->crypto.handshake_properties);
    quicly_recvbuf_shift(&conn->crypto.stream.recvbuf, consumed);
    if (ret != PTLS_ERROR_IN_PROGRESS)
        goto Error;
    if (input.len != consumed)
        goto Error;
    if (buf.off == 0)
        goto Error;

    /* send the 2nd ClientHello */
    reinit_stream_properties(&conn->crypto.stream);
    conn->crypto.stream.on_update = crypto_stream_receive_handshake;
    write_tlsbuf(conn, &buf);

    return 0;

Error:
    ptls_buffer_dispose(&buf);
    return QUICLY_ERROR_TBD;
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

static int encode_transport_parameter_list(quicly_context_t *ctx, ptls_buffer_t *buf, int is_client)
{
    int ret;

    ptls_buffer_push_block(buf, 2, {
        PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA,
                                 { ptls_buffer_push32(buf, ctx->initial_max_stream_data); });
        PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_DATA,
                                 { ptls_buffer_push32(buf, ctx->initial_max_data); });
        PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_IDLE_TIMEOUT, { ptls_buffer_push16(buf, ctx->idle_timeout); });
        if (!is_client) {
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_STATELESS_RESET_TOKEN, {
                /* FIXME implement stateless reset */
                static const uint8_t zeroes[16] = {0};
                ptls_buffer_pushv(buf, zeroes, sizeof(zeroes));
            });
        }
        if (ctx->max_concurrent_streams_bidi != 0) {
            uint32_t max_stream_id = ctx->max_concurrent_streams_bidi * 4 - (is_client ? 3 : 0);
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_ID_BIDI,
                                     { ptls_buffer_push32(buf, max_stream_id); });
        }
        if (ctx->max_concurrent_streams_uni != 0) {
            uint32_t max_stream_id = ctx->max_concurrent_streams_uni * 4 - (is_client ? 1 : 2);
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_ID_UNI,
                                     { ptls_buffer_push32(buf, max_stream_id); });
        }
    });
    ret = 0;
Exit:
    return ret;
}

static int decode_transport_parameter_list(quicly_transport_parameters_t *params, int is_client, const uint8_t *src,
                                           const uint8_t *end)
{
#define ID_TO_BIT(id) ((uint64_t)1 << (id))

    uint64_t found_id_bits = 0,
             must_found_id_bits = ID_TO_BIT(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA) |
                                  ID_TO_BIT(QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_DATA) |
                                  ID_TO_BIT(QUICLY_TRANSPORT_PARAMETER_ID_IDLE_TIMEOUT);
    int ret;

    if (is_client)
        must_found_id_bits = ID_TO_BIT(QUICLY_TRANSPORT_PARAMETER_ID_STATELESS_RESET_TOKEN);

    /* set optional parameters to their default values */
    params->initial_max_stream_id_bidi = 0;
    params->initial_max_stream_id_uni = 0;
    params->omit_connection_id = 0;

    /* decode the parameters block */
    ptls_decode_block(src, end, 2, {
        while (src != end) {
            uint16_t id;
            if ((ret = ptls_decode16(&id, &src, end)) != 0)
                goto Exit;
            if (id < sizeof(found_id_bits) * 8) {
                if ((found_id_bits & ID_TO_BIT(id)) != 0) {
                    ret = QUICLY_ERROR_TRANSPORT_PARAMETER;
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
                case QUICLY_TRANSPORT_PARAMETER_ID_STATELESS_RESET_TOKEN:
                    if (!is_client || end - src != STATELESS_RESET_TOKEN_SIZE) {
                        ret = QUICLY_ERROR_TRANSPORT_PARAMETER;
                        goto Exit;
                    }
                    /* TODO remember */
                    src = end;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_IDLE_TIMEOUT:
                    if ((ret = ptls_decode16(&params->idle_timeout, &src, end)) != 0)
                        goto Exit;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_ID_BIDI:
                    if ((ret = ptls_decode32(&params->initial_max_stream_id_bidi, &src, end)) != 0)
                        goto Exit;
                    if (STREAM_IS_UNI(params->initial_max_stream_id_bidi)) {
                        ret = QUICLY_ERROR_TRANSPORT_PARAMETER;
                        goto Exit;
                    }
                    if (is_client != STREAM_IS_CLIENT_INITIATED(params->initial_max_stream_id_bidi)) {
                        ret = QUICLY_ERROR_TRANSPORT_PARAMETER;
                        goto Exit;
                    }
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_ID_UNI:
                    if ((ret = ptls_decode32(&params->initial_max_stream_id_uni, &src, end)) != 0)
                        goto Exit;
                    if (!STREAM_IS_UNI(params->initial_max_stream_id_uni)) {
                        ret = QUICLY_ERROR_TRANSPORT_PARAMETER;
                        goto Exit;
                    }
                    if (is_client != STREAM_IS_CLIENT_INITIATED(params->initial_max_stream_id_uni)) {
                        ret = QUICLY_ERROR_TRANSPORT_PARAMETER;
                        goto Exit;
                    }
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_OMIT_CONNECTION_ID:
                    params->omit_connection_id = 1;
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
        ret = QUICLY_ERROR_TRANSPORT_PARAMETER;
        goto Exit;
    }

    ret = 0;
Exit:
    /* FIXME convert to quic error */
    return ret;

#undef ID_TO_BIT
}

static int collect_transport_parameters(ptls_t *tls, struct st_ptls_handshake_properties_t *properties, uint16_t type)
{
    return type == QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS;
}

static quicly_conn_t *create_connection(quicly_context_t *ctx, uint64_t connection_id, const char *server_name, struct sockaddr *sa,
                                        socklen_t salen, ptls_handshake_properties_t *handshake_properties)
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
    conn->super.connection_id = connection_id;
    conn->super.state = QUICLY_STATE_BEFORE_SH;
    if (server_name != NULL) {
        conn->super.host.next_stream_id_bidi = 4;
        conn->super.host.next_stream_id_uni = 1;
        conn->super.peer.next_stream_id_bidi = 2;
        conn->super.peer.next_stream_id_uni = 3;
    } else {
        conn->super.host.next_stream_id_bidi = 2;
        conn->super.host.next_stream_id_uni = 3;
        conn->super.peer.next_stream_id_bidi = 4;
        conn->super.peer.next_stream_id_uni = 1;
    }
    conn->super.peer.transport_params = transport_params_before_handshake;
    if (server_name != NULL && ctx->enforce_version_negotiation) {
        ctx->tls->random_bytes(&conn->super.version, sizeof(conn->super.version));
        conn->super.version = (conn->super.version & 0xf0f0f0f0) | 0x0a0a0a0a;
    } else {
        conn->super.version = QUICLY_PROTOCOL_VERSION;
    }
    conn->streams = kh_init(quicly_stream_t);
    quicly_ranges_init(&conn->ingress.ack_queue);
    quicly_maxsender_init(&conn->ingress.max_data.sender, conn->super.ctx->initial_max_data);
    quicly_maxsender_init(&conn->ingress.max_stream_id_bidi,
                          conn->super.ctx->max_concurrent_streams_bidi * 4 + conn->super.peer.next_stream_id_bidi);
    quicly_maxsender_init(&conn->ingress.max_stream_id_uni,
                          conn->super.ctx->max_concurrent_streams_uni * 4 + conn->super.peer.next_stream_id_uni);
    quicly_acks_init(&conn->egress.acks);
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

    uint32_t negotiated_version;
    if ((ret = ptls_decode32(&negotiated_version, &src, end)) != 0)
        goto Exit;
    if (negotiated_version != QUICLY_PROTOCOL_VERSION) {
        fprintf(stderr, "version negotiation not supported\n");
        ret = QUICLY_ERROR_TBD;
        goto Exit;
    }

    ptls_decode_open_block(src, end, 1, {
        int found_negotiated_version = 0;
        do {
            uint32_t supported_version;
            if ((ret = ptls_decode32(&supported_version, &src, end)) != 0)
                goto Exit;
            if (supported_version == negotiated_version)
                found_negotiated_version = 1;
        } while (src != end);
        if (!found_negotiated_version) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER; /* FIXME is this the correct error code? */
            goto Exit;
        }
    });
    ret = decode_transport_parameter_list(&conn->super.peer.transport_params, 1, src, end);

Exit:
    return ret;
}

static int setup_initial_packet_payload(quicly_conn_t *conn)
{
    ptls_buffer_t buf;
    int ret;

    ptls_buffer_init(&conn->crypto.transport_parameters.buf, "", 0);
    ptls_buffer_push32(&conn->crypto.transport_parameters.buf, conn->super.version);
    if ((ret = encode_transport_parameter_list(conn->super.ctx, &conn->crypto.transport_parameters.buf, 1)) != 0)
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

    ret = 0;
Exit:
    /* FIXME possibly leaking buf */
    return ret;
}

int quicly_connect(quicly_conn_t **_conn, quicly_context_t *ctx, const char *server_name, struct sockaddr *sa, socklen_t salen,
                   ptls_handshake_properties_t *handshake_properties)
{
    quicly_conn_t *conn;
    uint64_t connection_id;
    int ret;

    ctx->tls->random_bytes(&connection_id, sizeof(connection_id));
    if ((conn = create_connection(ctx, connection_id, server_name, sa, salen, handshake_properties)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((ret = setup_handshake_encryption(&conn->ingress.pp.aead.handshake, &conn->egress.pp.aead.handshake, ctx, connection_id,
                                          1)) != 0)
        goto Exit;
    if ((ret = setup_initial_packet_payload(conn)) != 0)
        goto Exit;

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
        uint32_t initial_version;
        if ((ret = ptls_decode32(&initial_version, &src, end)) != 0)
            goto Exit;
        if (initial_version != QUICLY_PROTOCOL_VERSION) {
            fprintf(stderr, "version negotiation not supported\n");
            ret = QUICLY_ERROR_VERSION_NEGOTIATION;
            goto Exit;
        }
        if ((ret = decode_transport_parameter_list(&conn->super.peer.transport_params, 0, src, end)) != 0)
            goto Exit;
    }

    /* set transport_parameters extension to be sent in EE */
    assert(properties->additional_extensions == NULL);
    ptls_buffer_init(&conn->crypto.transport_parameters.buf, "", 0);
    ptls_buffer_push32(&conn->crypto.transport_parameters.buf, QUICLY_PROTOCOL_VERSION);
    ptls_buffer_push_block(&conn->crypto.transport_parameters.buf, 1,
                           { ptls_buffer_push32(&conn->crypto.transport_parameters.buf, QUICLY_PROTOCOL_VERSION); });
    if ((ret = encode_transport_parameter_list(conn->super.ctx, &conn->crypto.transport_parameters.buf, 0)) != 0)
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
    ptls_aead_context_t *aead_ingress = NULL, *aead_egress = NULL;
    quicly_stream_frame_t frame;
    int ret;

    /* ignore any packet that does not  */
    if (packet->first_byte != QUICLY_PACKET_TYPE_INITIAL) {
        ret = QUICLY_ERROR_PACKET_IGNORED;
        goto Exit;
    }
    if (packet->version != QUICLY_PROTOCOL_VERSION) {
        ret = QUICLY_ERROR_VERSION_NEGOTIATION;
        goto Exit;
    }
    if ((ret = setup_handshake_encryption(&aead_ingress, &aead_egress, ctx, packet->connection_id, 0)) != 0)
        goto Exit;
    if ((packet->payload.len = ptls_aead_decrypt(aead_ingress, packet->payload.base, packet->payload.base, packet->payload.len,
                                                 packet->packet_number.bits, packet->header.base, packet->header.len)) ==
        SIZE_MAX) {
        ret = QUICLY_ERROR_TBD;
        goto Exit;
    }

    {
        const uint8_t *src = packet->payload.base, *end = src + packet->payload.len;
        uint8_t type_flags;
        for (; src < end; ++src) {
            if (*src != QUICLY_FRAME_TYPE_PADDING)
                break;
        }
        if (src == end || ((type_flags = *src++) & ~QUICLY_FRAME_TYPE_STREAM_BITS) != QUICLY_FRAME_TYPE_STREAM_BASE) {
            ret = QUICLY_ERROR_TBD;
            goto Exit;
        }
        if ((ret = quicly_decode_stream_frame(type_flags, &src, end, &frame)) != 0)
            goto Exit;
        if (!(frame.stream_id == 0 && frame.offset == 0)) {
            ret = QUICLY_ERROR_PROTOCOL_VIOLATION;
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

    if ((conn = create_connection(ctx, packet->connection_id, NULL, sa, salen, handshake_properties)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    conn->ingress.pp.aead.handshake = aead_ingress;
    aead_ingress = NULL;
    conn->egress.pp.aead.handshake = aead_egress;
    aead_egress = NULL;
    conn->crypto.handshake_properties.collected_extensions = server_collected_extensions;
    /* TODO should there be a way to set use of stateless reset per SNI or something? */
    conn->crypto.handshake_properties.server.cookie.enforce_use = ctx->stateless_retry.enforce_use;
    conn->crypto.handshake_properties.server.cookie.key = ctx->stateless_retry.key;

    if ((ret = quicly_ranges_update(&conn->ingress.ack_queue, packet->packet_number.bits,
                                    (uint64_t)packet->packet_number.bits + 1)) != 0)
        goto Exit;
    assert(conn->egress.send_ack_at == INT64_MAX);
    conn->egress.send_ack_at = conn->super.ctx->now(conn->super.ctx) + QUICLY_DELAYED_ACK_TIMEOUT;
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
        if (aead_ingress != NULL)
            ptls_aead_free(aead_ingress);
        if (aead_egress != NULL)
            ptls_aead_free(aead_egress);
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

static int on_ack_max_stream_id_bidi(quicly_conn_t *conn, int acked, quicly_ack_t *ack)
{
    if (acked) {
        quicly_maxsender_acked(&conn->ingress.max_stream_id_bidi, &ack->data.max_stream_id.args);
    } else {
        quicly_maxsender_lost(&conn->ingress.max_stream_id_bidi, &ack->data.max_stream_id.args);
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
    if (!acked && conn->egress.stream_id_blocked_state == QUICLY_SENDER_STATE_UNACKED && stream_id_blocked(conn, 0)) {
        conn->egress.stream_id_blocked_state = QUICLY_SENDER_STATE_SEND;
    } else {
        conn->egress.stream_id_blocked_state = QUICLY_SENDER_STATE_NONE;
    }

    return 0;
}

int64_t quicly_get_first_timeout(quicly_conn_t *conn)
{
    int64_t at = conn->egress.send_ack_at;
    quicly_acks_iter_t iter;
    quicly_ack_t *ack;

    quicly_acks_init_iter(&conn->egress.acks, &iter);
    if ((ack = quicly_acks_get(&iter)) != NULL) {
        int64_t cand = ack->sent_at + conn->super.ctx->initial_rto;
        if (cand < at)
            at = cand;
    }

    return at;
}

struct st_quicly_send_context_t {
    uint8_t first_byte;
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
    assert(s->aead != NULL);

    if (s->first_byte == QUICLY_PACKET_TYPE_INITIAL) {
        if (s->num_packets != 0)
            return QUICLY_ERROR_HANDSHAKE_TOO_LARGE;
        const size_t max_size = 1264; /* max UDP packet size excluding aead tag */
        assert(s->dst - s->target->data.base <= max_size);
        memset(s->dst, 0, s->target->data.base + max_size - s->dst);
        s->dst = s->target->data.base + max_size;
    }

    if (s->dst != s->dst_unencrypted_from)
        encrypt_packet(s);
    s->dst += ptls_aead_encrypt_final(s->aead, s->dst);

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
    if (s->dst_end - s->dst < min_space || *s->target->data.base != s->first_byte) {
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
        /* emit header */
        *s->dst++ = s->first_byte;
        s->dst = quicly_encode64(s->dst, conn->super.connection_id);
        if ((s->first_byte & 0x80) != 0)
            s->dst = quicly_encode32(s->dst, QUICLY_PROTOCOL_VERSION);
        s->dst = quicly_encode32(s->dst, (uint32_t)conn->egress.packet_number);
        s->dst_unencrypted_from = s->dst;
        assert(s->aead != NULL);
        s->dst_end -= s->aead->algo->tag_size;
        ptls_aead_encrypt_init(s->aead, conn->egress.packet_number, s->target->data.base, s->dst - s->target->data.base);
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
    size_t range_index;
    int ret;

    if (conn->ingress.ack_queue.num_ranges == 0)
        return 0;

    range_index = conn->ingress.ack_queue.num_ranges - 1;
    do {
        if ((ret = prepare_packet(conn, s, QUICLY_ACK_FRAME_CAPACITY)) != 0)
            break;
        s->dst = quicly_encode_ack_frame(s->dst, s->dst_end, &conn->ingress.ack_queue, &range_index);
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
                                               QUICLY_STOP_SENDING_FRAME_CAPACITY, on_ack_stop_sending)) != 0)
            return ret;
        s->dst = quicly_encode_stop_sending_frame(s->dst, stream->stream_id, stream->_send_aux.stop_sending.reason);
    }

    /* send MAX_STREAM_DATA if necessary */
    if (should_update_max_stream_data(stream)) {
        uint64_t new_value = stream->recvbuf.data_off + stream->_recv_aux.window;
        quicly_ack_t *ack;
        /* prepare */
        if ((ret = prepare_acked_packet(stream->conn, s, QUICLY_MAX_STREAM_DATA_FRAME_CAPACITY, &ack, on_ack_max_stream_data)) != 0)
            return ret;
        /* send */
        s->dst = quicly_encode_max_stream_data_frame(s->dst, stream->stream_id, new_value);
        /* register ack */
        ack->data.max_stream_data.stream_id = stream->stream_id;
        quicly_maxsender_record(&stream->_send_aux.max_stream_data_sender, new_value, &ack->data.max_stream_data.args);
    }

    /* send RST_STREAM if necessary */
    if (stream->_send_aux.rst.sender_state == QUICLY_SENDER_STATE_SEND) {
        if ((ret = prepare_stream_state_sender(stream, &stream->_send_aux.rst.sender_state, s, QUICLY_RST_FRAME_CAPACITY,
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
    quicly_ack_t *ack;
    size_t copysize;
    int must_pad, ret;

    if ((ret = prepare_acked_packet(stream->conn, s, QUICLY_STREAM_FRAME_CAPACITY, &ack, on_ack_stream)) != 0)
        return ret;

    copysize = max_bytes - (iter->stream_off + max_bytes > stream->sendbuf.eos);
    s->dst =
        quicly_encode_stream_frame_header(s->dst, s->dst_end, stream->stream_id, iter->stream_off + copysize >= stream->sendbuf.eos,
                                          iter->stream_off, &copysize, &must_pad);
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

    /* pad if necessary */
    if (must_pad) {
        while (s->dst != s->dst_end)
            *s->dst++ = QUICLY_FRAME_TYPE_PADDING;
    }

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

static int handle_timeouts(quicly_conn_t *conn, int64_t now)
{
    quicly_acks_iter_t iter;
    quicly_ack_t *ack;
    int ret;
    int64_t sent_before = now - conn->super.ctx->initial_rto;
    uint64_t logged_pn = UINT64_MAX;

    for (quicly_acks_init_iter(&conn->egress.acks, &iter); (ack = quicly_acks_get(&iter)) != NULL; quicly_acks_next(&iter)) {
        if (sent_before < ack->sent_at)
            break;
        if (ack->packet_number != logged_pn) {
            logged_pn = ack->packet_number;
            DEBUG_LOG(conn, 0, "RTO; packet-number: %" PRIu64, logged_pn);
        }
        if ((ret = ack->acked(conn, 0, ack)) != 0)
            return ret;
        quicly_acks_release(&conn->egress.acks, &iter);
    }

    return 0;
}

quicly_raw_packet_t *quicly_send_version_negotiation(quicly_context_t *ctx, struct sockaddr *sa, socklen_t salen,
                                                     uint64_t connection_id)
{
    quicly_raw_packet_t *packet;
    uint8_t *dst;

    if ((packet = ctx->alloc_packet(ctx, salen, ctx->max_packet_size)) == NULL)
        return NULL;
    packet->salen = salen;
    memcpy(&packet->sa, sa, salen);
    dst = packet->data.base;

    /* type_flags */
    ctx->tls->random_bytes(dst, 1);
    *dst |= 0x80;
    ++dst;
    /* connection-id */
    dst = quicly_encode64(dst, connection_id);
    /* version */
    dst = quicly_encode32(dst, 0);
    /* supported_versions */
    dst = quicly_encode32(dst, QUICLY_PROTOCOL_VERSION);

    packet->data.len = dst - packet->data.base;

    return packet;
}

int quicly_send(quicly_conn_t *conn, quicly_raw_packet_t **packets, size_t *num_packets)
{
    struct st_quicly_send_context_t s = {UINT8_MAX, conn->egress.pp.aead.handshake, conn->super.ctx->now(conn->super.ctx), packets,
                                         *num_packets};
    int ret;

    /* handle timeouts */
    if ((ret = handle_timeouts(conn, s.now)) != 0)
        goto Exit;

    /* send cleartext frames */
    switch (quicly_get_state(conn)) {
    case QUICLY_STATE_SEND_STATELESS_RETRY:
        assert(!quicly_is_client(conn));
        s.first_byte = QUICLY_PACKET_TYPE_RETRY;
        break;
    case QUICLY_STATE_BEFORE_SH:
        assert(quicly_is_client(conn));
        s.first_byte = QUICLY_PACKET_TYPE_INITIAL;
        break;
    default:
        s.first_byte = QUICLY_PACKET_TYPE_HANDSHAKE;
        if (conn->egress.send_ack_at <= s.now && quicly_get_state(conn) != QUICLY_STATE_1RTT_ENCRYPTED) {
            if ((ret = send_ack(conn, &s)) != 0)
                goto Exit;
        }
        break;
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
        if ((ret = commit_send_packet(conn, &s)) != 0)
            goto Exit;
    }

    /* send encrypted frames */
    if (quicly_get_state(conn) == QUICLY_STATE_1RTT_ENCRYPTED) {
        s.first_byte = 0x1d; /* 1rtt,has-connection-id,key-phase=0,packet-number-size=4 */
        s.aead = conn->egress.pp.aead.one_rtt[0];
        /* acks */
        if (conn->egress.send_ack_at <= s.now) {
            if ((ret = send_ack(conn, &s)) != 0)
                goto Exit;
        }
        /* max_stream_id (TODO uni) */
        uint64_t max_stream_id;
        if ((max_stream_id = quicly_maxsender_should_update_stream_id(
                 &conn->ingress.max_stream_id_bidi, conn->super.peer.next_stream_id_bidi, conn->super.peer.num_streams,
                 conn->super.ctx->max_concurrent_streams_bidi, 768)) != 0) {
            quicly_ack_t *ack;
            if ((ret = prepare_acked_packet(conn, &s, QUICLY_MAX_STREAM_ID_FRAME_CAPACITY, &ack, on_ack_max_stream_id_bidi)) != 0)
                goto Exit;
            s.dst = quicly_encode_max_stream_id_frame(s.dst, max_stream_id);
            quicly_maxsender_record(&conn->ingress.max_stream_id_bidi, max_stream_id, &ack->data.max_stream_id.args);
        }
        /* max_data */
        if (quicly_maxsender_should_update(&conn->ingress.max_data.sender, conn->ingress.max_data.bytes_consumed,
                                           conn->super.ctx->initial_max_data, 512)) {
            quicly_ack_t *ack;
            if ((ret = prepare_acked_packet(conn, &s, QUICLY_MAX_DATA_FRAME_CAPACITY, &ack, on_ack_max_data)) != 0)
                goto Exit;
            uint64_t new_value = conn->ingress.max_data.bytes_consumed + conn->super.ctx->initial_max_data;
            s.dst = quicly_encode_max_data_frame(s.dst, new_value);
            quicly_maxsender_record(&conn->ingress.max_data.sender, new_value, &ack->data.max_data.args);
        }
        /* stream_id_blocked (TODO uni) */
        if (conn->egress.stream_id_blocked_state == QUICLY_SENDER_STATE_SEND) {
            if (stream_id_blocked(conn, 0)) {
                quicly_ack_t *ack;
                if ((ret = prepare_acked_packet(conn, &s, QUICLY_STREAM_ID_BLOCKED_FRAME_CAPACITY, &ack,
                                                on_ack_stream_id_blocked)) != 0)
                    goto Exit;
                s.dst = quicly_encode_stream_id_blocked_frame(s.dst, conn->egress.max_stream_id_bidi);
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

    ret = 0;
Exit:
    if (ret == QUICLY_ERROR_SENDBUF_FULL)
        ret = 0;
    if (ret == 0) {
        *num_packets = s.num_packets;
        if (s.first_byte == QUICLY_PACKET_TYPE_RETRY)
            ret = QUICLY_ERROR_CONNECTION_CLOSED;
    }
    return ret;
}

static int get_stream_or_open_if_new(quicly_conn_t *conn, uint64_t stream_id, quicly_stream_t **stream)
{
    int ret = 0;

    if ((*stream = quicly_get_stream(conn, stream_id)) != NULL)
        goto Exit;

    /* TODO implement */
    if (STREAM_IS_UNI(stream_id)) {
        ret = QUICLY_ERROR_INTERNAL;
        goto Exit;
    }

    if (STREAM_IS_CLIENT_INITIATED(stream_id) != quicly_is_client(conn) && conn->super.peer.next_stream_id_bidi <= stream_id) {
        /* open new streams upto given id */
        do {
            if ((*stream = open_stream(conn, conn->super.peer.next_stream_id_bidi)) == NULL) {
                ret = PTLS_ERROR_NO_MEMORY;
                goto Exit;
            }
            if ((ret = conn->super.ctx->on_stream_open(*stream)) != 0) {
                destroy_stream(*stream);
                *stream = NULL;
                goto Exit;
            }
            ++conn->super.peer.num_streams;
            conn->super.peer.next_stream_id_bidi += 4;
        } while (stream_id != (*stream)->stream_id);
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
    stream->_recv_aux.rst_reason = frame->app_error_code;
    conn->ingress.max_data.bytes_consumed += bytes_missing;

    if (quicly_stream_is_closable(stream))
        ret = stream->on_update(stream);

    return ret;
}

static int handle_ack_frame(quicly_conn_t *conn, quicly_ack_frame_t *frame)
{
    quicly_acks_iter_t iter;
    uint64_t packet_number = frame->smallest_acknowledged;
    int ret;

    quicly_acks_init_iter(&conn->egress.acks, &iter);
    if (quicly_acks_get(&iter) == NULL)
        return 0;

    size_t gap_index = frame->num_gaps;
    while (1) {
        uint64_t block_length = frame->ack_block_lengths[gap_index];
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
                    DEBUG_LOG(conn, 0, "dupack? (pn=%" PRIu64 ")", packet_number);
                if (quicly_acks_get(&iter) == NULL)
                    goto Exit;
            } while (++packet_number, --block_length != 0);
        }
        if (gap_index-- == 0)
            break;
        packet_number += frame->gaps[gap_index];
    }

Exit:
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
    uint64_t *slot = STREAM_IS_UNI(frame->max_stream_id) ? &conn->egress.max_stream_id_uni : &conn->egress.max_stream_id_bidi;
    if (frame->max_stream_id < *slot)
        return 0;
    *slot = frame->max_stream_id;
    /* TODO notify the app? */
    return 0;
}

static int handle_ping_frame(quicly_conn_t *conn, quicly_ping_frame_t *frame)
{
    fprintf(stderr, "received ping; TODO implement pong\n");
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
    if (frame->max_data < conn->egress.max_data.permitted)
        return 0;
    conn->egress.max_data.permitted = frame->max_data;

    /* TODO schedule for delivery */
    return 0;
}

static int negotiate_using_version(quicly_conn_t *conn, uint32_t version)
{
    ptls_t *newtls = NULL;
    const char *server_name;
    int ret;

    conn->super.version = version;

    /* reinit TLS */
    if ((newtls = ptls_new(conn->super.ctx->tls, 0)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((server_name = ptls_get_server_name(conn->crypto.tls)) != NULL &&
        (ret = ptls_set_server_name(newtls, server_name, strlen(server_name))) != 0)
        goto Exit;
    ptls_free(conn->crypto.tls);
    conn->crypto.tls = newtls;
    newtls = NULL;

    /* reinit properties of stream zero */
    reinit_stream_properties(&conn->crypto.stream);

    /* setup initial payload */
    ptls_buffer_dispose(&conn->crypto.transport_parameters.buf);
    if ((ret = setup_initial_packet_payload(conn)) != 0)
        goto Exit;

    ret = 0;
Exit:
    if (newtls != NULL)
        ptls_free(newtls);
    return ret;
}

static int handle_version_negotiation_packet(quicly_conn_t *conn, quicly_decoded_packet_t *packet)
{
#define CAN_SELECT(v) ((v) != conn->super.version && (v) == QUICLY_PROTOCOL_VERSION)

    const uint8_t *src = packet->payload.base, *end = src + packet->payload.len;

    if ((end - src) % 4 != 0)
        return QUICLY_ERROR_PROTOCOL_VIOLATION;
    /* first supported version is contained in the packet_number field */
    if (CAN_SELECT(packet->packet_number.bits))
        return negotiate_using_version(conn, packet->packet_number.bits);
    while (src != end) {
        uint32_t supported_version = quicly_decode32(&src);
        if (CAN_SELECT(supported_version))
            return negotiate_using_version(conn, supported_version);
    }
    return QUICLY_ERROR_VERSION_NEGOTIATION_FAILURE;
}

int quicly_receive(quicly_conn_t *conn, quicly_decoded_packet_t *packet)
{
    ptls_aead_context_t *aead;
    uint64_t packet_number;
    int ret;

    /* FIXME check peer address (and also invocation timing?) */
    conn->super.connection_id = packet->connection_id;

    /* ignore packets having wrong connection id */
    if (packet->connection_id != conn->super.connection_id) {
        ret = QUICLY_ERROR_PACKET_IGNORED;
        goto Exit;
    }

    if (conn->super.state != QUICLY_STATE_1RTT_ENCRYPTED && QUICLY_PACKET_TYPE_IS_1RTT(packet->first_byte)) {
        /* FIXME enqueue the packet? */
        ret = QUICLY_ERROR_PACKET_IGNORED;
        goto Exit;
    }

    if (QUICLY_PACKET_TYPE_IS_1RTT(packet->first_byte)) {
        int key_phase = QUICLY_PACKET_TYPE_1RTT_TO_KEY_PHASE(packet->first_byte);
        if ((aead = conn->ingress.pp.aead.one_rtt[key_phase]) == NULL) {
            /* drop 1rtt-encrypted packets received prior to handshake completion (due to loss of the packet carrying the latter) */
            ret = key_phase == 0 && quicly_get_state(conn) != QUICLY_STATE_1RTT_ENCRYPTED ? 0 : QUICLY_ERROR_TBD;
            goto Exit;
        }
    } else {
        if (conn->super.state == QUICLY_STATE_BEFORE_SH && packet->version == 0)
            return handle_version_negotiation_packet(conn, packet);
        switch (packet->first_byte) {
        case QUICLY_PACKET_TYPE_RETRY:
            if (!(quicly_is_client(conn) && quicly_get_state(conn) == QUICLY_STATE_BEFORE_SH) ||
                (aead = conn->ingress.pp.aead.handshake) == NULL) {
                ret = QUICLY_ERROR_PROTOCOL_VIOLATION;
                goto Exit;
            }
            if (conn->egress.packet_number - 1 != packet->packet_number.bits) {
                ret = QUICLY_ERROR_PROTOCOL_VIOLATION;
                goto Exit;
            }
            conn->crypto.stream.on_update = crypto_stream_receive_stateless_retry;
            break;
        case QUICLY_PACKET_TYPE_HANDSHAKE:
            if ((aead = conn->ingress.pp.aead.handshake) == NULL) {
                ret = QUICLY_ERROR_PROTOCOL_VIOLATION;
                goto Exit;
            }
            break;
        case QUICLY_PACKET_TYPE_0RTT_PROTECTED:
            if (quicly_is_client(conn) || (aead = conn->ingress.pp.aead.early_data) == NULL) {
                ret = QUICLY_ERROR_PROTOCOL_VIOLATION;
                goto Exit;
            }
            break;
        case QUICLY_PACKET_TYPE_INITIAL:
            /* FIXME ignore for time being */
            ret = 0;
            goto Exit;
        default:
            ret = QUICLY_ERROR_PROTOCOL_VIOLATION;
            goto Exit;
        }
    }

    packet_number = quicly_determine_packet_number(packet, conn->ingress.next_expected_packet_number);
    if ((packet->payload.len = ptls_aead_decrypt(aead, packet->payload.base, packet->payload.base, packet->payload.len,
                                                 packet_number, packet->header.base, packet->header.len)) == SIZE_MAX) {
        ret = QUICLY_ERROR_TBD;
        goto Exit;
    }
    conn->ingress.next_expected_packet_number = packet_number + 1;

    if (packet->payload.len == 0) {
        ret = QUICLY_ERROR_PROTOCOL_VIOLATION;
        goto Exit;
    }

    const uint8_t *src = packet->payload.base, *end = src + packet->payload.len;
    int is_ack_only = 1;
    do {
        uint8_t type_flags = *src++;
        if ((type_flags & ~QUICLY_FRAME_TYPE_STREAM_BITS) == QUICLY_FRAME_TYPE_STREAM_BASE) {
            quicly_stream_frame_t frame;
            if ((ret = quicly_decode_stream_frame(type_flags, &src, end, &frame)) != 0)
                goto Exit;
            if ((ret = handle_stream_frame(conn, &frame)) != 0)
                goto Exit;
            is_ack_only = 0;
        } else if (type_flags >= QUICLY_FRAME_TYPE_ACK) {
            /* TODO use separate decoding logic (like the one in quicly_accept) for stateless-retry */
            if (packet->first_byte == QUICLY_PACKET_TYPE_RETRY) {
                ret = QUICLY_ERROR_TBD;
                goto Exit;
            }
            quicly_ack_frame_t frame;
            if ((ret = quicly_decode_ack_frame(type_flags, &src, end, &frame)) != 0)
                goto Exit;
            if ((ret = handle_ack_frame(conn, &frame)) != 0)
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
            case QUICLY_FRAME_TYPE_CONNECTION_CLOSE:
            case QUICLY_FRAME_TYPE_APPLICATION_CLOSE: {
                quicly_close_frame_t frame;
                if ((ret = quicly_decode_connection_close_frame(&src, end, &frame)) != 0)
                    goto Exit;
                fprintf(stderr, "%s close:%" PRIx32 ":%.*s\n",
                        type_flags == QUICLY_FRAME_TYPE_CONNECTION_CLOSE ? "connection" : "application", frame.error_code,
                        (int)frame.reason_phrase.len, frame.reason_phrase.base);
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
            case QUICLY_FRAME_TYPE_PING: {
                quicly_ping_frame_t frame;
                if ((ret = quicly_decode_ping_frame(&src, end, &frame)) != 0)
                    goto Exit;
                if ((ret = handle_ping_frame(conn, &frame)) != 0)
                    goto Exit;
            } break;
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
            case QUICLY_FRAME_TYPE_STREAM_ID_BLOCKED: {
                quicly_stream_id_blocked_frame_t frame;
                if ((ret = quicly_decode_stream_id_blocked_frame(&src, end, &frame)) != 0)
                    goto Exit;
                quicly_maxsender_reset(
                    STREAM_IS_UNI(frame.stream_id) ? &conn->ingress.max_stream_id_uni : &conn->ingress.max_stream_id_bidi, 0);
                ret = 0;
            } break;
            case QUICLY_FRAME_TYPE_STOP_SENDING: {
                quicly_stop_sending_frame_t frame;
                if ((ret = quicly_decode_stop_sending_frame(&src, end, &frame)) != 0)
                    goto Exit;
                if ((ret = handle_stop_sending_frame(conn, &frame)) != 0)
                    goto Exit;
            } break;
            default:
                fprintf(stderr, "ignoring frame type:%02x\n", (unsigned)type_flags);
                ret = QUICLY_ERROR_TBD;
                goto Exit;
            }
            is_ack_only = 0;
        }
    } while (src != end);

    if ((ret = quicly_ranges_update(&conn->ingress.ack_queue, packet_number, packet_number + 1)) != 0)
        goto Exit;
    if (!is_ack_only && conn->egress.send_ack_at == INT64_MAX) {
        conn->egress.send_ack_at = conn->super.ctx->now(conn->super.ctx) + QUICLY_DELAYED_ACK_TIMEOUT;
    }

Exit:
    return ret;
}

int quicly_open_stream(quicly_conn_t *conn, quicly_stream_t **stream)
{
    if (stream_id_blocked(conn, 0)) {
        conn->egress.stream_id_blocked_state = QUICLY_SENDER_STATE_SEND;
        return QUICLY_ERROR_TOO_MANY_OPEN_STREAMS;
    }

    if ((*stream = open_stream(conn, conn->super.host.next_stream_id_bidi)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    ++conn->super.host.num_streams;
    conn->super.host.next_stream_id_bidi += 4;

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
