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
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "khash.h"
#include "cc.h"
#include "quicly.h"
#include "quicly/ack.h"
#include "quicly/frame.h"

#define QUICLY_PROTOCOL_VERSION 0xff00000f

#define QUICLY_PACKET_TYPE_INITIAL 0xff
#define QUICLY_PACKET_TYPE_RETRY 0xfe
#define QUICLY_PACKET_TYPE_HANDSHAKE 0xfd
#define QUICLY_PACKET_TYPE_0RTT_PROTECTED 0xfc
#define QUICLY_PACKET_TYPE_LONG_MIN QUICLY_PACKET_TYPE_0RTT_PROTECTED

#define QUICLY_PACKET_TYPE_IS_1RTT(t) (((t)&0x80) == 0)
#define QUICLY_PACKET_TYPE_1RTT_TO_KEY_PHASE(t) (((t)&0x40) == 0) /* first slot is for 0-rtt and odd-numbered generations */

#define QUICLY_TLS_EXTENSION_TYPE_TRANSPORT_PARAMETERS 0xffa5
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL 0
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_DATA 1
#define QUICLY_TRANSPORT_PARAMETER_ID_IDLE_TIMEOUT 3
#define QUICLY_TRANSPORT_PARAMETER_ID_ACK_DELAY_EXPONENT 7
#define QUICLY_TRANSPORT_PARAMETER_ID_STATELESS_RESET_TOKEN 6
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_BIDI 2
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_UNI 8
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE 10
#define QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_UNI 11
#define QUICLY_TRANSPORT_PARAMETER_ID_MAX_ACK_DELAY 12

#define QUICLY_ACK_DELAY_EXPONENT 10

#define QUICLY_EPOCH_INITIAL 0
#define QUICLY_EPOCH_0RTT 1
#define QUICLY_EPOCH_HANDSHAKE 2
#define QUICLY_EPOCH_1RTT 3

/**
 * do not try to send frames that require ACK if the send window is below this value
 */
#define MIN_SEND_WINDOW 64

#define HKDF_BASE_LABEL "quic "

#define STATELESS_RESET_TOKEN_SIZE 16

KHASH_MAP_INIT_INT64(quicly_stream_t, quicly_stream_t *)

#define INT_EVENT_ATTR(label, value) _int_event_attr(QUICLY_EVENT_ATTRIBUTE_##label, value)
#define VEC_EVENT_ATTR(label, value) _vec_event_attr(QUICLY_EVENT_ATTRIBUTE_##label, value)
#define LOG_IS_REQUIRED(ctx, type) (((ctx)->event_log.mask & ((uint64_t)1 << (type))) != 0)
#define LOG_EVENT(ctx, type, ...)                                                                                                  \
    do {                                                                                                                           \
        quicly_context_t *_ctx = (ctx);                                                                                            \
        quicly_event_type_t _type = (type);                                                                                        \
        if (LOG_IS_REQUIRED(_ctx, _type)) {                                                                                        \
            quicly_event_attribute_t attributes[] = {INT_EVENT_ATTR(TIME, now), __VA_ARGS__};                                      \
            _ctx->event_log.cb(_ctx, _type, attributes, sizeof(attributes) / sizeof(attributes[0]));                               \
        }                                                                                                                          \
    } while (0)

#define LOG_CONNECTION_EVENT(conn, type, ...)                                                                                      \
    do {                                                                                                                           \
        quicly_conn_t *_conn = (conn);                                                                                             \
        LOG_EVENT(_conn->super.ctx, (type), INT_EVENT_ATTR(CONNECTION, quicly_get_master_id(_conn)), __VA_ARGS__);                 \
    } while (0)
#define LOG_STREAM_EVENT(conn, stream_id, type, ...)                                                                               \
    LOG_CONNECTION_EVENT((conn), (type), INT_EVENT_ATTR(STREAM_ID, stream_id), __VA_ARGS__)

struct st_quicly_cipher_context_t {
    ptls_aead_context_t *aead;
    ptls_cipher_context_t *pne;
};

struct st_quicly_pending_path_challenge_t {
    struct st_quicly_pending_path_challenge_t *next;
    uint8_t is_response;
    uint8_t data[QUICLY_PATH_CHALLENGE_DATA_LEN];
};

struct st_quicly_pn_space_t {
    /**
     * acks to be sent to peer
     */
    quicly_ranges_t ack_queue;
    /**
     * time at when the largest pn in the ack_queue has been received (or INT64_MAX if none)
     */
    int64_t largest_pn_received_at;
    /**
     *
     */
    uint64_t next_expected_packet_number;
    /**
     *
     */
    int64_t send_ack_at;
    /**
     * packet count before ack is sent
     */
    uint32_t unacked_count;
};

struct st_quicly_handshake_space_t {
    struct st_quicly_pn_space_t super;
    struct {
        struct st_quicly_cipher_context_t ingress;
        struct st_quicly_cipher_context_t egress;
    } cipher;
};

struct st_quicly_application_space_t {
    struct st_quicly_pn_space_t super;
    struct {
        /**
         * we might have up to two keys enabled (e.g. 0-RTT + 1-RTT or two 1-RTT keys during key update), or could be zero keys when
         * waiting for ClientFinished
         */
        struct st_quicly_cipher_context_t ingress[2];
        /**
         *
         */
        struct st_quicly_cipher_context_t egress_0rtt;
        /**
         *
         */
        struct st_quicly_cipher_context_t egress_1rtt;
    } cipher;
};

struct st_quicly_conn_t {
    struct _st_quicly_conn_public_t super;
    /**
     * the initial context
     */
    struct st_quicly_handshake_space_t *initial;
    /**
     * the handshake context
     */
    struct st_quicly_handshake_space_t *handshake;
    /**
     * 0-RTT and 1-RTT context
     */
    struct st_quicly_application_space_t *application;
    /**
     * hashtable of streams
     */
    khash_t(quicly_stream_t) * streams;
    /**
     *
     */
    struct {
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
        struct {
            quicly_maxsender_t *uni, *bidi;
        } max_stream_id;
    } ingress;
    /**
     *
     */
    struct {
        /**
         * contains actions that needs to be performed when an ack is being received
         */
        quicly_acks_t acks;
        /**
         * all packets where pn < max_lost_pn are deemed lost
         */
        uint64_t max_lost_pn;
        /**
         * loss recovery
         */
        quicly_loss_t loss;
        /**
         * next or the currently encoding packet number (TODO move to pnspace)
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
        struct {
            struct st_quicly_max_stream_id_t {
                quicly_stream_id_t id;
                quicly_maxsender_t blocked_sender;
            } uni, bidi;
        } max_stream_id;
        /**
         *
         */
        struct {
            struct st_quicly_pending_path_challenge_t *head, **tail_ref;
        } path_challenge;
        /**
         *
         */
        int64_t last_retransmittable_sent_at;
        /**
         *
         */
        int64_t send_ack_at;
        /**
         *
         */
        struct {
            struct cc_var ccv;
            size_t bytes_in_flight;
            uint64_t end_of_recovery;
            unsigned in_first_rto : 1;
            /**
             * collected by on_ack_cc, number of packets / octets that have been newly acknowledged or declared lost
             */
            struct {
                size_t nsegs;
                size_t nbytes;
            } this_ack;
        } cc;
    } egress;
    /**
     * crypto data
     */
    struct {
        ptls_t *tls;
        ptls_handshake_properties_t handshake_properties;
        struct {
            ptls_raw_extension_t ext[2];
            ptls_buffer_t buf;
        } transport_parameters;
        /**
         * bit vector indicating if there's any pending handshake data at epoch 0,1,2
         */
        uint8_t pending_flows;
    } crypto;
    /**
     *
     */
    struct {
        /**
         * contains list of blocked streams (sorted in ascending order of stream_ids)
         */
        struct {
            quicly_linklist_t uni;
            quicly_linklist_t bidi;
        } stream_id_blocked;
        quicly_linklist_t control;
        quicly_linklist_t stream_fin_only;
        quicly_linklist_t stream_with_payload;
    } pending_link;
};

static int update_traffic_key_cb(ptls_update_traffic_key_t *self, ptls_t *tls, int is_enc, size_t epoch, const void *secret);
static int retire_acks_by_ack_epoch(quicly_conn_t *conn, uint8_t ack_epoch);

const quicly_context_t quicly_default_context = {
    NULL,                                                /* tls */
    0,                                                   /* next_master_id */
    1280,                                                /* max_packet_size */
    &quicly_loss_default_conf,                           /* loss */
    {1 * 1024 * 1024, 1 * 1024 * 1024, 1 * 1024 * 1024}, /* initial_max_stream_data */
    16 * 1024 * 1024,                                    /* initial_max_data */
    600,                                                 /* idle_timeout */
    100,                                                 /* max_concurrent_streams_bidi */
    0,                                                   /* max_concurrent_streams_uni */
    {0, NULL},                                           /* stateless_retry {enforce_use, key} */
    0,                                                   /* enforce_version_negotiation */
    quicly_default_alloc_packet,
    quicly_default_free_packet,
    quicly_default_alloc_stream,
    quicly_default_free_stream,
    NULL, /* on_stream_open */
    NULL, /* on_conn_close */
    quicly_default_now,
    {0, NULL}, /* event_log */
};

static const quicly_transport_parameters_t transport_params_before_handshake = {
    {0, 0, 0}, 0, 0, 0, 0, 3, QUICLY_DELAYED_ACK_TIMEOUT};

static __thread int64_t now;

static void update_now(quicly_context_t *ctx)
{
    static __thread int64_t base;

    now = ctx->now(ctx);

    assert(cc_hz == 100);
    if (base == 0)
        base = now;
    int new_ticks = (int)((now - base) / 10);
    if (cc_ticks != new_ticks)
        cc_ticks = new_ticks;
}

static inline quicly_event_attribute_t _int_event_attr(quicly_event_attribute_type_t type, int64_t value)
{
    quicly_event_attribute_t t;

    assert(QUICLY_EVENT_ATTRIBUTE_TYPE_INT_MIN <= type && type < QUICLY_EVENT_ATTRIBUTE_TYPE_INT_MAX);
    t.type = type;
    t.value.i = value;
    return t;
}

static inline quicly_event_attribute_t _vec_event_attr(quicly_event_attribute_type_t type, ptls_iovec_t value)
{
    quicly_event_attribute_t t;

    assert(QUICLY_EVENT_ATTRIBUTE_TYPE_VEC_MIN <= type && type < QUICLY_EVENT_ATTRIBUTE_TYPE_VEC_MAX);
    t.type = type;
    t.value.v = value;
    return t;
}

static void dispose_cipher(struct st_quicly_cipher_context_t *ctx)
{
    ptls_aead_free(ctx->aead);
    ptls_cipher_free(ctx->pne);
}

static size_t decode_cid_length(uint8_t src)
{
    return src != 0 ? src + 3 : 0;
}

static uint8_t encode_cid_length(size_t len)
{
    return len != 0 ? (uint8_t)len - 3 : 0;
}

size_t quicly_decode_packet(quicly_decoded_packet_t *packet, const uint8_t *src, size_t len, size_t host_cidl)
{
    const uint8_t *src_end = src + len;

    if (len < 2)
        goto Error;

    packet->octets = ptls_iovec_init(src, len);
    packet->datagram_size = len;
    ++src;

    if (!QUICLY_PACKET_TYPE_IS_1RTT(packet->octets.base[0])) {
        /* long header */
        uint64_t rest_length;
        if (src_end - src < 5)
            goto Error;
        packet->version = quicly_decode32(&src);
        packet->cid.dest.len = decode_cid_length(*src >> 4);
        packet->cid.src.len = decode_cid_length(*src & 0xf);
        ++src;
        if (src_end - src < packet->cid.dest.len + packet->cid.src.len)
            goto Error;
        packet->cid.dest.base = (void *)src;
        src += packet->cid.dest.len;
        packet->cid.src.base = (void *)src;
        src += packet->cid.src.len;
        if (packet->version == 0) {
            /* version negotiation packet does not have the length field nor is ever coalesced */
            packet->encrypted_off = src - packet->octets.base;
        } else {
            if (packet->octets.base[0] == QUICLY_PACKET_TYPE_INITIAL) {
                uint64_t token_len;
                if ((token_len = quicly_decodev(&src, src_end)) == UINT64_MAX)
                    goto Error;
                if (src_end - src < token_len)
                    goto Error;
                packet->token = ptls_iovec_init(src, token_len);
                src += token_len;
            }
            if ((rest_length = quicly_decodev(&src, src_end)) == UINT64_MAX)
                goto Error;
            if (rest_length < 1)
                goto Error;
            if (src_end - src < rest_length)
                goto Error;
            packet->encrypted_off = src - packet->octets.base;
            packet->octets.len = packet->encrypted_off + rest_length;
        }
    } else {
        /* short header */
        if (host_cidl != 0) {
            if (src_end - src < host_cidl)
                goto Error;
            packet->cid.dest = ptls_iovec_init(src, host_cidl);
            src += host_cidl;
        } else {
            packet->cid.dest = ptls_iovec_init(NULL, 0);
        }
        packet->cid.src = ptls_iovec_init(NULL, 0);
        packet->version = 0;
        packet->encrypted_off = src - packet->octets.base;
    }

    return packet->octets.len;

Error:
    return SIZE_MAX;
}

uint64_t quicly_determine_packet_number(uint32_t bits, uint32_t mask, uint64_t next_expected)
{
    uint64_t actual = (next_expected & ~(uint64_t)mask) + bits;

    if (((bits - (uint32_t)next_expected) & mask) > (mask >> 1)) {
        if (actual >= (uint64_t)mask + 1)
            actual -= (uint64_t)mask + 1;
    }

    return actual;
}

static void assert_consistency(quicly_conn_t *conn, int run_timers)
{
    if (conn->egress.acks.num_in_flight != 0) {
        assert(conn->egress.loss.alarm_at != INT64_MAX);
    } else {
        assert(conn->egress.loss.loss_time == INT64_MAX);
    }
    if (run_timers)
        assert(now < conn->egress.loss.alarm_at);
}

static void init_max_stream_id(struct st_quicly_max_stream_id_t *m)
{
    m->id = -1;
    quicly_maxsender_init(&m->blocked_sender, -1);
}

static void update_max_stream_id(struct st_quicly_max_stream_id_t *m, quicly_stream_id_t id)
{
    if (m->id < id) {
        m->id = id;
        if (m->blocked_sender.max_acked < id)
            m->blocked_sender.max_acked = id;
    }
}

int quicly_connection_is_ready(quicly_conn_t *conn)
{
    return conn->application != NULL;
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
    assert(stream->stream_id >= 0);

    if (!quicly_linklist_is_linked(&stream->_send_aux.pending_link.control))
        quicly_linklist_insert(&stream->conn->pending_link.control, &stream->_send_aux.pending_link.control);
}

static void resched_stream_data(quicly_stream_t *stream)
{
    quicly_linklist_t *target = NULL;

    if (stream->stream_id < 0 && -3 <= stream->stream_id) {
        uint8_t mask = 1 << -(1 + stream->stream_id);
        if (stream->sendbuf.pending.num_ranges != 0) {
            stream->conn->crypto.pending_flows |= mask;
        } else {
            stream->conn->crypto.pending_flows &= ~mask;
        }
        return;
    }

    /* do nothing if blocked */
    if (stream->stream_id_blocked)
        return;

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

static int should_update_max_stream_data(quicly_stream_t *stream)
{
    if (stream->recvbuf.eos != UINT64_MAX)
        return 0;
    return quicly_maxsender_should_update(&stream->_send_aux.max_stream_data_sender, stream->recvbuf.data_off,
                                          stream->_recv_aux.window, 512);
}

static void on_sendbuf_change(quicly_sendbuf_t *buf)
{
    quicly_stream_t *stream = (void *)((char *)buf - offsetof(quicly_stream_t, sendbuf));
    assert(stream->stream_id >= 0 || buf->eos == UINT64_MAX);

    resched_stream_data(stream);
}

static void on_recvbuf_change(quicly_recvbuf_t *buf, size_t shift_amount)
{
    quicly_stream_t *stream = (void *)((char *)buf - offsetof(quicly_stream_t, recvbuf));

    if (stream->stream_id >= 0) {
        stream->conn->ingress.max_data.bytes_consumed += shift_amount;
        if (should_update_max_stream_data(stream))
            sched_stream_control(stream);
    }
}

static int schedule_path_challenge(quicly_conn_t *conn, int is_response, const uint8_t *data)
{
    struct st_quicly_pending_path_challenge_t *pending;

    if ((pending = malloc(sizeof(struct st_quicly_pending_path_challenge_t))) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    pending->next = NULL;
    pending->is_response = is_response;
    memcpy(pending->data, data, QUICLY_PATH_CHALLENGE_DATA_LEN);

    *conn->egress.path_challenge.tail_ref = pending;
    conn->egress.path_challenge.tail_ref = &pending->next;
    return 0;
}

static void write_tlsbuf(quicly_conn_t *conn, ptls_buffer_t *tlsbuf, size_t epoch_offsets[5])
{
    size_t epoch;

    if (tlsbuf->off == 0)
        return;

    for (epoch = 0; epoch < 4; ++epoch) {
        size_t len = epoch_offsets[epoch + 1] - epoch_offsets[epoch];
        if (len == 0)
            continue;
        quicly_stream_t *stream = quicly_get_stream(conn, -(quicly_stream_id_t)(1 + epoch));
        assert(stream != NULL);
        quicly_sendbuf_write(&stream->sendbuf, tlsbuf->base + epoch_offsets[epoch], len, NULL);
    }
}

static int crypto_on_update(quicly_stream_t *flow)
{
    quicly_conn_t *conn = flow->conn;
    ptls_buffer_t buf;
    size_t in_epoch = -(1 + flow->stream_id), epoch_offsets[5] = {0};
    ptls_iovec_t input;
    int ret = 0;

    ptls_buffer_init(&buf, "", 0);

    /* send handshake messages to picotls, and let it fill in the response */
    while ((input = quicly_recvbuf_get(&flow->recvbuf)).len != 0) {
        ret = ptls_handle_message(conn->crypto.tls, &buf, epoch_offsets, in_epoch, input.base, input.len,
                                  &conn->crypto.handshake_properties);
        quicly_recvbuf_shift(&flow->recvbuf, input.len);
        LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_CRYPTO_HANDSHAKE, INT_EVENT_ATTR(TLS_ERROR, ret));
        switch (ret) {
        case 0:
            break;
        case PTLS_ERROR_IN_PROGRESS:
            ret = 0;
            break;
        default:
            goto Exit;
        }
    }

    write_tlsbuf(conn, &buf, epoch_offsets);

Exit:
    ptls_buffer_dispose(&buf);
    return ret;
}

static void init_stream_properties(quicly_stream_t *stream, uint32_t initial_max_stream_data_local,
                                   uint32_t initial_max_stream_data_remote)
{
    int uni = quicly_stream_is_unidirectional(stream->stream_id),
        self_initiated = quicly_stream_is_client_initiated(stream->stream_id) == quicly_is_client(stream->conn);

    if (!uni || self_initiated) {
        quicly_sendbuf_init(&stream->sendbuf, on_sendbuf_change);
    } else {
        quicly_sendbuf_init_closed(&stream->sendbuf);
    }
    if (!uni || !self_initiated) {
        quicly_recvbuf_init(&stream->recvbuf, on_recvbuf_change);
    } else {
        quicly_recvbuf_init_closed(&stream->recvbuf);
    }
    stream->stream_id_blocked = 0;

    stream->_send_aux.max_stream_data = initial_max_stream_data_remote;
    stream->_send_aux.max_sent = 0;
    stream->_send_aux.stop_sending.sender_state = QUICLY_SENDER_STATE_NONE;
    stream->_send_aux.stop_sending.error_code = 0;
    stream->_send_aux.rst.sender_state = QUICLY_SENDER_STATE_NONE;
    stream->_send_aux.rst.error_code = 0;
    quicly_maxsender_init(&stream->_send_aux.max_stream_data_sender, initial_max_stream_data_local);
    quicly_linklist_init(&stream->_send_aux.pending_link.control);
    quicly_linklist_init(&stream->_send_aux.pending_link.stream);

    stream->_recv_aux.window = initial_max_stream_data_local;
}

static void dispose_stream_properties(quicly_stream_t *stream)
{
    quicly_sendbuf_dispose(&stream->sendbuf);
    quicly_recvbuf_dispose(&stream->recvbuf);
    quicly_maxsender_dispose(&stream->_send_aux.max_stream_data_sender);
    quicly_linklist_unlink(&stream->_send_aux.pending_link.control);
    quicly_linklist_unlink(&stream->_send_aux.pending_link.stream);
}

static quicly_stream_t *open_stream(quicly_conn_t *conn, uint64_t stream_id, uint32_t initial_max_stream_data_local,
                                    uint32_t initial_max_stream_data_remote)
{
    quicly_stream_t *stream;

    if ((stream = conn->super.ctx->alloc_stream(conn->super.ctx)) == NULL)
        return NULL;
    stream->conn = conn;
    stream->stream_id = stream_id;
    stream->host_cid = &conn->super.host.cid;

    int r;
    khiter_t iter = kh_put(quicly_stream_t, conn->streams, stream_id, &r);
    assert(iter != kh_end(conn->streams));
    kh_val(conn->streams, iter) = stream;

    init_stream_properties(stream, initial_max_stream_data_local, initial_max_stream_data_remote);

    return stream;
}

static struct st_quicly_conn_streamgroup_state_t *get_streamgroup_state(quicly_conn_t *conn, quicly_stream_id_t stream_id)
{
    if (quicly_is_client(conn) == quicly_stream_is_client_initiated(stream_id)) {
        return quicly_stream_is_unidirectional(stream_id) ? &conn->super.host.uni : &conn->super.host.bidi;
    } else {
        return quicly_stream_is_unidirectional(stream_id) ? &conn->super.peer.uni : &conn->super.peer.bidi;
    }
}

static void destroy_stream(quicly_stream_t *stream)
{
    quicly_conn_t *conn = stream->conn;
    khiter_t iter = kh_get(quicly_stream_t, conn->streams, stream->stream_id);
    assert(iter != kh_end(conn->streams));
    kh_del(quicly_stream_t, conn->streams, iter);

    if (stream->stream_id < 0) {
        size_t epoch = -(1 + stream->stream_id);
        if (epoch <= 2)
            stream->conn->crypto.pending_flows &= ~(uint8_t)(1 << epoch);
    } else {
        conn->ingress.max_data.bytes_consumed += stream->recvbuf.data.len;
        struct st_quicly_conn_streamgroup_state_t *group = get_streamgroup_state(conn, stream->stream_id);
        --group->num_streams;
    }

    dispose_stream_properties(stream);
    conn->super.ctx->free_stream(stream);
}

quicly_stream_t *quicly_get_stream(quicly_conn_t *conn, quicly_stream_id_t stream_id)
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

static int create_handshake_flow(quicly_conn_t *conn, size_t epoch)
{
    quicly_stream_t *stream;

    if ((stream = open_stream(conn, -(quicly_stream_id_t)(1 + epoch), 65536, 65536)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    stream->on_update = crypto_on_update;
    return 0;
}

static void destroy_handshake_flow(quicly_conn_t *conn, size_t epoch)
{
    quicly_stream_t *stream = quicly_get_stream(conn, -(quicly_stream_id_t)(1 + epoch));
    assert(stream != NULL);
    destroy_stream(stream);
    retire_acks_by_ack_epoch(conn, epoch);
}

static struct st_quicly_pn_space_t *alloc_pn_space(size_t sz)
{
    struct st_quicly_pn_space_t *space;

    if ((space = malloc(sz)) == NULL)
        return NULL;

    quicly_ranges_init(&space->ack_queue);
    space->largest_pn_received_at = INT64_MAX;
    space->next_expected_packet_number = 0;
    space->send_ack_at = INT64_MAX;
    space->unacked_count = 0;
    if (sz != sizeof(*space))
        memset((uint8_t *)space + sizeof(*space), 0, sz - sizeof(*space));

    return space;
}

static void do_free_pn_space(struct st_quicly_pn_space_t *space)
{
    quicly_ranges_dispose(&space->ack_queue);
    free(space);
}

static int record_receipt(struct st_quicly_pn_space_t *space, uint64_t pn, int is_ack_only, size_t epoch)
{
    int ret;

    if ((ret = quicly_ranges_add(&space->ack_queue, pn, pn + 1)) != 0)
        goto Exit;
    if (space->ack_queue.num_ranges >= QUICLY_ENCODE_ACK_MAX_BLOCKS) {
        assert(space->ack_queue.num_ranges == QUICLY_ENCODE_ACK_MAX_BLOCKS);
        quicly_ranges_shrink(&space->ack_queue, 0, 1);
    }
    if (space->ack_queue.ranges[space->ack_queue.num_ranges - 1].end == pn + 1) {
        /* FIXME implement deduplication at an earlier moment? */
        space->largest_pn_received_at = now;
    }
    /* TODO (jri): If not ack-only packet, then maintain count of such packets that are received.
     * Send ack immediately when this number exceeds the threshold.
     */
    if (!is_ack_only) {
        space->unacked_count++;
        /* Ack after QUICLY_NUM_PACKETS_BEFORE_ACK packets or after the delayed ack timeout */
        if (space->unacked_count >= QUICLY_NUM_PACKETS_BEFORE_ACK || epoch == QUICLY_EPOCH_INITIAL ||
            epoch == QUICLY_EPOCH_HANDSHAKE) {
            space->send_ack_at = now;
        } else if (space->send_ack_at == INT64_MAX) {
            /* FIXME use 1/4 minRTT */
            space->send_ack_at = now + QUICLY_DELAYED_ACK_TIMEOUT;
        }
    }

    ret = 0;
Exit:
    return ret;
}

static void free_handshake_space(struct st_quicly_handshake_space_t **space)
{
    if (*space != NULL) {
        if ((*space)->cipher.ingress.aead != NULL)
            dispose_cipher(&(*space)->cipher.ingress);
        if ((*space)->cipher.egress.aead != NULL)
            dispose_cipher(&(*space)->cipher.egress);
        do_free_pn_space(&(*space)->super);
        *space = NULL;
    }
}

static int setup_cipher(struct st_quicly_cipher_context_t *ctx, ptls_aead_algorithm_t *aead, ptls_hash_algorithm_t *hash,
                        int is_enc, const void *secret)
{
    uint8_t pnekey[PTLS_MAX_SECRET_SIZE];
    int ret;

    *ctx = (struct st_quicly_cipher_context_t){NULL};

    if ((ctx->aead = ptls_aead_new(aead, hash, is_enc, secret, HKDF_BASE_LABEL)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((ret = ptls_hkdf_expand_label(hash, pnekey, aead->ctr_cipher->key_size, ptls_iovec_init(secret, hash->digest_size), "pn",
                                      ptls_iovec_init(NULL, 0), HKDF_BASE_LABEL)) != 0)
        goto Exit;
    if ((ctx->pne = ptls_cipher_new(aead->ctr_cipher, is_enc, pnekey)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (QUICLY_DEBUG) {
        char *secret_hex = quicly_hexdump(secret, hash->digest_size, SIZE_MAX),
             *pnekey_hex = quicly_hexdump(pnekey, aead->ctr_cipher->key_size, SIZE_MAX);
        fprintf(stderr, "%s:\n  aead-secret: %s\n  pne-key: %s\n", __FUNCTION__, secret_hex, pnekey_hex);
        free(secret_hex);
        free(pnekey_hex);
    }

    ret = 0;
Exit:
    if (ret != 0) {
        if (ctx->aead != NULL) {
            ptls_aead_free(ctx->aead);
            ctx->aead = NULL;
        }
        if (ctx->pne != NULL) {
            ptls_cipher_free(ctx->pne);
            ctx->pne = NULL;
        }
    }
    ptls_clear_memory(pnekey, sizeof(pnekey));
    return ret;
}

static int setup_handshake_space_and_flow(quicly_conn_t *conn, size_t epoch)
{
    struct st_quicly_handshake_space_t **space = epoch == 0 ? &conn->initial : &conn->handshake;
    if ((*space = (void *)alloc_pn_space(sizeof(struct st_quicly_handshake_space_t))) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    return create_handshake_flow(conn, epoch);
}

static void free_application_space(struct st_quicly_application_space_t **space)
{
    if (*space != NULL) {
#define DISPOSE_CIPHER(label)                                                                                                      \
    if ((*space)->cipher.label.aead != NULL)                                                                                       \
    dispose_cipher(&(*space)->cipher.label)
        DISPOSE_CIPHER(ingress[0]);
        DISPOSE_CIPHER(ingress[1]);
        DISPOSE_CIPHER(egress_0rtt);
        DISPOSE_CIPHER(egress_1rtt);
#undef DISPOSE_CIPHER
        do_free_pn_space(&(*space)->super);
        *space = NULL;
    }
}

static int setup_application_space_and_flow(quicly_conn_t *conn, int setup_0rtt)
{
    if ((conn->application = (void *)alloc_pn_space(sizeof(struct st_quicly_application_space_t))) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    if (setup_0rtt) {
        int ret;
        if ((ret = create_handshake_flow(conn, 1)) != 0)
            return ret;
    }
    return create_handshake_flow(conn, 3);
}

static void apply_peer_transport_params(quicly_conn_t *conn)
{
    conn->egress.max_data.permitted = conn->super.peer.transport_params.initial_max_data;
    update_max_stream_id(&conn->egress.max_stream_id.uni,
                         conn->super.peer.transport_params.initial_max_streams_uni * 4 - (quicly_is_client(conn) ? 2 : 1));
    update_max_stream_id(&conn->egress.max_stream_id.bidi,
                         conn->super.peer.transport_params.initial_max_streams_bidi * 4 - (quicly_is_client(conn) ? 4 : 3));
}

void quicly_free(quicly_conn_t *conn)
{
    quicly_stream_t *stream;

    quicly_maxsender_dispose(&conn->ingress.max_data.sender);
    if (conn->ingress.max_stream_id.uni != NULL)
        quicly_maxsender_dispose(conn->ingress.max_stream_id.uni);
    if (conn->ingress.max_stream_id.bidi != NULL)
        quicly_maxsender_dispose(conn->ingress.max_stream_id.bidi);
    while (conn->egress.path_challenge.head != NULL) {
        struct st_quicly_pending_path_challenge_t *pending = conn->egress.path_challenge.head;
        conn->egress.path_challenge.head = pending->next;
        free(pending);
    }
    cc_destroy(&conn->egress.cc.ccv);
    quicly_acks_dispose(&conn->egress.acks);

    kh_foreach_value(conn->streams, stream, { destroy_stream(stream); });
    kh_destroy(quicly_stream_t, conn->streams);

    assert(!quicly_linklist_is_linked(&conn->pending_link.stream_id_blocked.uni));
    assert(!quicly_linklist_is_linked(&conn->pending_link.stream_id_blocked.bidi));
    assert(!quicly_linklist_is_linked(&conn->pending_link.control));
    assert(!quicly_linklist_is_linked(&conn->pending_link.stream_fin_only));
    assert(!quicly_linklist_is_linked(&conn->pending_link.stream_with_payload));

    free_handshake_space(&conn->initial);
    free_handshake_space(&conn->handshake);
    free_application_space(&conn->application);

    free(conn->super.peer.sa);
    free(conn);
}

static int setup_initial_key(struct st_quicly_cipher_context_t *ctx, ptls_cipher_suite_t *cs, const void *master_secret,
                             const char *label, int is_enc)
{
    uint8_t aead_secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    if ((ret = ptls_hkdf_expand_label(cs->hash, aead_secret, cs->hash->digest_size,
                                      ptls_iovec_init(master_secret, cs->hash->digest_size), label, ptls_iovec_init(NULL, 0),
                                      HKDF_BASE_LABEL)) != 0)
        goto Exit;
    if ((ret = setup_cipher(ctx, cs->aead, cs->hash, is_enc, aead_secret)) != 0)
        goto Exit;

Exit:
    ptls_clear_memory(aead_secret, sizeof(aead_secret));
    return ret;
}

static int setup_initial_encryption(struct st_quicly_cipher_context_t *ingress, struct st_quicly_cipher_context_t *egress,
                                    ptls_cipher_suite_t **cipher_suites, ptls_iovec_t cid, int is_client)
{
    static const uint8_t salt[] = {0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c, 0x32, 0x96,
                                   0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f, 0xe0, 0x6d, 0x6c, 0x38};
    static const char *labels[2] = {"client in", "server in"};
    ptls_cipher_suite_t **cs;
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    /* find aes128gcm cipher */
    for (cs = cipher_suites;; ++cs) {
        assert(cs != NULL);
        if ((*cs)->id == PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)
            break;
    }

    /* extract master secret */
    if ((ret = ptls_hkdf_extract((*cs)->hash, secret, ptls_iovec_init(salt, sizeof(salt)), cid)) != 0)
        goto Exit;

    /* create aead contexts */
    if ((ret = setup_initial_key(ingress, *cs, secret, labels[is_client], 0)) != 0)
        goto Exit;
    if ((ret = setup_initial_key(egress, *cs, secret, labels[!is_client], 1)) != 0)
        goto Exit;

Exit:
    ptls_clear_memory(secret, sizeof(secret));
    return ret;
}

static int do_apply_stream_frame(quicly_stream_t *stream, uint64_t off, ptls_iovec_t data)
{
    int ret;

    /* adjust the range of supplied data so that we not go above eos */
    if (stream->recvbuf.eos < off)
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
        quicly_buffer_vec_t vec = {NULL};
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

    LOG_STREAM_EVENT(stream->conn, stream->stream_id, QUICLY_EVENT_TYPE_STREAM_RECEIVE, INT_EVENT_ATTR(OFFSET, frame->offset),
                     INT_EVENT_ATTR(LENGTH, frame->data.len));

    if (frame->is_fin && (ret = quicly_recvbuf_mark_eos(&stream->recvbuf, frame->offset + frame->data.len)) != 0)
        return ret;
    if ((ret = do_apply_stream_frame(stream, frame->offset, frame->data)) != 0)
        return ret;
    if (should_update_max_stream_data(stream))
        sched_stream_control(stream);

    return ret;
}

static int apply_handshake_flow(quicly_conn_t *conn, size_t epoch, quicly_stream_frame_t *frame)
{
    quicly_stream_t *stream = quicly_get_stream(conn, -(quicly_stream_id_t)(1 + epoch));

    return apply_stream_frame(stream, frame);
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
        if (ctx->initial_max_stream_data.bidi_local != 0)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                                     { ptls_buffer_push32(buf, ctx->initial_max_stream_data.bidi_local); });
        if (ctx->initial_max_stream_data.bidi_remote != 0)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                                     { ptls_buffer_push32(buf, ctx->initial_max_stream_data.bidi_remote); });
        if (ctx->initial_max_stream_data.uni != 0)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_UNI,
                                     { ptls_buffer_push32(buf, ctx->initial_max_stream_data.uni); });
        if (ctx->initial_max_data != 0)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_DATA,
                                     { ptls_buffer_push32(buf, ctx->initial_max_data); });
        if (ctx->idle_timeout != 0)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_IDLE_TIMEOUT,
                                     { ptls_buffer_push16(buf, ctx->idle_timeout); });
        if (!is_client) {
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_STATELESS_RESET_TOKEN, {
                /* FIXME implement stateless reset */
                static const uint8_t zeroes[16] = {0};
                ptls_buffer_pushv(buf, zeroes, sizeof(zeroes));
            });
        }
        if (ctx->max_streams_bidi != 0)
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_BIDI,
                                     { ptls_buffer_push16(buf, ctx->max_streams_bidi); });
        if (ctx->max_streams_uni != 0) {
            PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_UNI,
                                     { ptls_buffer_push16(buf, ctx->max_streams_uni); });
        }
        PUSH_TRANSPORT_PARAMETER(buf, QUICLY_TRANSPORT_PARAMETER_ID_ACK_DELAY_EXPONENT,
                                 { ptls_buffer_push(buf, QUICLY_ACK_DELAY_EXPONENT); });
    });
    ret = 0;
Exit:
    return ret;
}

static int decode_transport_parameter_list(quicly_transport_parameters_t *params, int is_client, const uint8_t *src,
                                           const uint8_t *end)
{
#define ID_TO_BIT(id) ((uint64_t)1 << (id))

    uint64_t found_id_bits = 0;
    int ret;

    /* set parameters to their default values */
    *params = (quicly_transport_parameters_t){{0}, 0, 0, 0, 0, 3};

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
                case QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
                    if ((ret = ptls_decode32(&params->initial_max_stream_data.bidi_local, &src, end)) != 0)
                        goto Exit;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
                    if ((ret = ptls_decode32(&params->initial_max_stream_data.bidi_remote, &src, end)) != 0)
                        goto Exit;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAM_DATA_UNI:
                    if ((ret = ptls_decode32(&params->initial_max_stream_data.uni, &src, end)) != 0)
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
                case QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_BIDI:
                    if ((ret = ptls_decode16(&params->initial_max_streams_bidi, &src, end)) != 0)
                        goto Exit;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_STREAMS_UNI:
                    if ((ret = ptls_decode16(&params->initial_max_streams_uni, &src, end)) != 0)
                        goto Exit;
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_ACK_DELAY_EXPONENT:
                    if (src == end) {
                        ret = QUICLY_ERROR_TRANSPORT_PARAMETER;
                        goto Exit;
                    }
                    if ((params->ack_delay_exponent = *src++) > 20) {
                        ret = QUICLY_ERROR_TRANSPORT_PARAMETER;
                        goto Exit;
                    }
                    break;
                case QUICLY_TRANSPORT_PARAMETER_ID_MAX_ACK_DELAY:
                    if (src == end) {
                        ret = QUICLY_ERROR_TRANSPORT_PARAMETER;
                        goto Exit;
                    }
                    params->max_ack_delay = *src++;
                    break;
                default:
                    src = end;
                    break;
                }
            });
        }
    });

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

static void set_cid(quicly_cid_t *dest, ptls_iovec_t src)
{
    memcpy(dest->cid, src.base, src.len);
    dest->len = src.len;
}

static quicly_conn_t *create_connection(quicly_context_t *ctx, const char *server_name, struct sockaddr *sa, socklen_t salen,
                                        ptls_handshake_properties_t *handshake_properties)
{
    ptls_t *tls = NULL;
    struct {
        quicly_conn_t _;
        quicly_maxsender_t max_stream_id_bidi;
        quicly_maxsender_t max_stream_id_uni;
    } * conn;

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
    conn->_.super.ctx = ctx;
    conn->_.super.master_id = ctx->next_master_id++;
    conn->_.super.state = QUICLY_STATE_FIRSTFLIGHT;
    if (server_name != NULL) {
        ctx->tls->random_bytes(conn->_.super.peer.cid.cid, 8);
        conn->_.super.peer.cid.len = 8;
        conn->_.super.host.bidi.next_stream_id = 0;
        conn->_.super.host.uni.next_stream_id = 2;
        conn->_.super.peer.bidi.next_stream_id = 1;
        conn->_.super.peer.uni.next_stream_id = 3;
    } else {
        conn->_.super.host.bidi.next_stream_id = 1;
        conn->_.super.host.uni.next_stream_id = 3;
        conn->_.super.peer.bidi.next_stream_id = 0;
        conn->_.super.peer.uni.next_stream_id = 2;
    }
    conn->_.super.peer.transport_params = transport_params_before_handshake;
    if (server_name != NULL && ctx->enforce_version_negotiation) {
        ctx->tls->random_bytes(&conn->_.super.version, sizeof(conn->_.super.version));
        conn->_.super.version = (conn->_.super.version & 0xf0f0f0f0) | 0x0a0a0a0a;
    } else {
        conn->_.super.version = QUICLY_PROTOCOL_VERSION;
    }
    conn->_.streams = kh_init(quicly_stream_t);
    quicly_maxsender_init(&conn->_.ingress.max_data.sender, conn->_.super.ctx->initial_max_data);
    if (conn->_.super.ctx->max_streams_uni != 0) {
        conn->_.ingress.max_stream_id.uni = &conn->max_stream_id_uni;
        quicly_maxsender_init(conn->_.ingress.max_stream_id.uni,
                              conn->_.super.ctx->max_streams_uni * 4 - 4 + conn->_.super.peer.uni.next_stream_id);
    }
    if (conn->_.super.ctx->max_streams_bidi != 0) {
        conn->_.ingress.max_stream_id.bidi = &conn->max_stream_id_bidi;
        quicly_maxsender_init(conn->_.ingress.max_stream_id.bidi,
                              conn->_.super.ctx->max_streams_bidi * 4 - 4 + conn->_.super.peer.bidi.next_stream_id);
    }
    quicly_acks_init(&conn->_.egress.acks);
    quicly_loss_init(&conn->_.egress.loss, conn->_.super.ctx->loss,
                     conn->_.super.ctx->loss->default_initial_rtt /* FIXME remember initial_rtt in session ticket */,
                     &conn->_.super.peer.transport_params.max_ack_delay);
    init_max_stream_id(&conn->_.egress.max_stream_id.uni);
    init_max_stream_id(&conn->_.egress.max_stream_id.bidi);
    conn->_.egress.path_challenge.tail_ref = &conn->_.egress.path_challenge.head;
    conn->_.egress.send_ack_at = INT64_MAX;
    cc_init(&conn->_.egress.cc.ccv, &newreno_cc_algo, 1280 * 8, 1280);
    conn->_.egress.cc.ccv.ccvc.ccv.snd_scale = 14; /* FIXME */
    conn->_.egress.cc.end_of_recovery = UINT64_MAX;
    conn->_.crypto.tls = tls;
    if (handshake_properties != NULL) {
        assert(handshake_properties->additional_extensions == NULL);
        assert(handshake_properties->collect_extension == NULL);
        assert(handshake_properties->collected_extensions == NULL);
        conn->_.crypto.handshake_properties = *handshake_properties;
    } else {
        conn->_.crypto.handshake_properties = (ptls_handshake_properties_t){{{{NULL}}}};
    }
    conn->_.crypto.handshake_properties.collect_extension = collect_transport_parameters;
    quicly_linklist_init(&conn->_.pending_link.stream_id_blocked.uni);
    quicly_linklist_init(&conn->_.pending_link.stream_id_blocked.bidi);
    quicly_linklist_init(&conn->_.pending_link.control);
    quicly_linklist_init(&conn->_.pending_link.stream_fin_only);
    quicly_linklist_init(&conn->_.pending_link.stream_with_payload);

    if (set_peeraddr(&conn->_, sa, salen) != 0) {
        quicly_free(&conn->_);
        return NULL;
    }

    *ptls_get_data_ptr(tls) = &conn->_;

    return &conn->_;
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
        fprintf(stderr, "unexpected negotiated version\n");
        ret = QUICLY_ERROR_VERSION_NEGOTIATION;
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

int quicly_connect(quicly_conn_t **_conn, quicly_context_t *ctx, const char *server_name, struct sockaddr *sa, socklen_t salen,
                   ptls_handshake_properties_t *handshake_properties)
{
    quicly_conn_t *conn = NULL;
    const quicly_cid_t *server_cid;
    ptls_buffer_t buf;
    size_t epoch_offsets[5] = {0};
    size_t max_early_data_size;
    int ret;

    update_now(ctx);

    if ((conn = create_connection(ctx, server_name, sa, salen, handshake_properties)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    server_cid = quicly_get_peer_cid(conn);

    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_CONNECT, VEC_EVENT_ATTR(DCID, ptls_iovec_init(server_cid->cid, server_cid->len)),
                         VEC_EVENT_ATTR(SCID, ptls_iovec_init(conn->super.host.cid.cid, conn->super.host.cid.len)));

    if ((ret = setup_handshake_space_and_flow(conn, 0)) != 0)
        goto Exit;
    if ((ret = setup_initial_encryption(&conn->initial->cipher.ingress, &conn->initial->cipher.egress, ctx->tls->cipher_suites,
                                        ptls_iovec_init(server_cid->cid, server_cid->len), 1)) != 0)
        goto Exit;

    /* handshake */
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
    conn->crypto.handshake_properties.client.max_early_data_size = &max_early_data_size;
    ret = ptls_handle_message(conn->crypto.tls, &buf, epoch_offsets, 0, NULL, 0, &conn->crypto.handshake_properties);
    conn->crypto.handshake_properties.client.max_early_data_size = NULL;
    if (ret != PTLS_ERROR_IN_PROGRESS)
        goto Exit;
    write_tlsbuf(conn, &buf, epoch_offsets);
    ptls_buffer_dispose(&buf);

    if (max_early_data_size != 0)
        apply_peer_transport_params(conn);

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
        /* TODO we need to check initial_version when supporting multiple versions */
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

static ptls_iovec_t decrypt_packet(struct st_quicly_cipher_context_t *ctx, uint64_t *next_expected_pn,
                                   quicly_decoded_packet_t *packet, uint64_t *pn)
{
    size_t encrypted_len = packet->octets.len - packet->encrypted_off, iv_offset;
    uint8_t pnbuf[4];
    uint32_t pnbits, pnmask;
    size_t pnlen;

    /* determine the IV offset of pne */
    if (encrypted_len < ctx->pne->algo->iv_size + 1) {
        goto Error;
    } else if (encrypted_len < ctx->pne->algo->iv_size + 4) {
        iv_offset = packet->octets.len - ctx->pne->algo->iv_size;
    } else {
        iv_offset = packet->encrypted_off + 4;
    }

    /* decrypt PN */
    ptls_cipher_init(ctx->pne, packet->octets.base + iv_offset);
    ptls_cipher_encrypt(ctx->pne, pnbuf, packet->octets.base + packet->encrypted_off, sizeof(pnbuf));
    if ((pnbuf[0] & 0x80) == 0) {
        pnbits = pnbuf[0];
        pnmask = 0x7f;
        pnlen = 1;
    } else {
        pnbits = ((uint32_t)(pnbuf[0] & 0x3f) << 8) | pnbuf[1];
        if ((pnbuf[0] & 0x40) == 0) {
            pnmask = 0x3fff;
            pnlen = 2;
        } else {
            pnbits = (pnbits << 16) | ((uint32_t)pnbuf[2] << 8) | pnbuf[3];
            pnmask = 0x3fffffff;
            pnlen = 4;
        }
    }

    /* write-back the decrypted PN for AEAD */
    memcpy(packet->octets.base + packet->encrypted_off, pnbuf, pnlen);

    /* AEAD */
    *pn = quicly_determine_packet_number(pnbits, pnmask, *next_expected_pn);
    size_t aead_off = packet->encrypted_off + pnlen, ptlen;
    if ((ptlen = ptls_aead_decrypt(ctx->aead, packet->octets.base + aead_off, packet->octets.base + aead_off,
                                   packet->octets.len - aead_off, *pn, packet->octets.base, aead_off)) == SIZE_MAX) {
        if (QUICLY_DEBUG)
            fprintf(stderr, "%s: aead decryption failure (pn: %" PRIu64 ")\n", __FUNCTION__, *pn);
        goto Error;
    }

    if (QUICLY_DEBUG) {
        char *payload_hex = quicly_hexdump(packet->octets.base + aead_off, ptlen, 4);
        fprintf(stderr, "%s: AEAD payload:\n%s", __FUNCTION__, payload_hex);
        free(payload_hex);
    }

    if (*next_expected_pn <= *pn)
        *next_expected_pn = *pn + 1;
    return ptls_iovec_init(packet->octets.base + aead_off, ptlen);

Error:
    return ptls_iovec_init(NULL, 0);
}

int quicly_accept(quicly_conn_t **_conn, quicly_context_t *ctx, struct sockaddr *sa, socklen_t salen,
                  ptls_handshake_properties_t *handshake_properties, quicly_decoded_packet_t *packet)
{
    quicly_conn_t *conn = NULL;
    struct st_quicly_cipher_context_t ingress_cipher = {NULL}, egress_cipher = {NULL};
    ptls_iovec_t payload;
    uint64_t next_expected_pn, pn;
    quicly_stream_frame_t frame;
    int ret;

    update_now(ctx);

    /* ignore any packet that does not  */
    if (packet->octets.base[0] != QUICLY_PACKET_TYPE_INITIAL) {
        ret = QUICLY_ERROR_PACKET_IGNORED;
        goto Exit;
    }
    if (packet->version != QUICLY_PROTOCOL_VERSION) {
        ret = QUICLY_ERROR_VERSION_NEGOTIATION;
        goto Exit;
    }
    if (packet->cid.dest.len < 8) {
        ret = QUICLY_ERROR_PROTOCOL_VIOLATION;
        goto Exit;
    }
    if ((ret = setup_initial_encryption(&ingress_cipher, &egress_cipher, ctx->tls->cipher_suites, packet->cid.dest, 0)) != 0)
        goto Exit;
    next_expected_pn = 0; /* is this correct? do we need to take care of underflow? */
    if ((payload = decrypt_packet(&ingress_cipher, &next_expected_pn, packet, &pn)).base == NULL) {
        ret = QUICLY_ERROR_PACKET_IGNORED;
        goto Exit;
    }

    {
        const uint8_t *src = payload.base, *end = src + payload.len;
        for (; src < end; ++src) {
            if (*src != QUICLY_FRAME_TYPE_PADDING)
                break;
        }
        if (src == end || *src++ != QUICLY_FRAME_TYPE_CRYPTO) {
            ret = QUICLY_ERROR_PROTOCOL_VIOLATION;
            goto Exit;
        }
        if ((ret = quicly_decode_crypto_frame(&src, end, &frame)) != 0)
            goto Exit;
        if (frame.offset != 0) {
            ret = QUICLY_ERROR_PROTOCOL_VIOLATION;
            goto Exit;
        }
        /* FIXME check packet size */
        for (; src < end; ++src) {
            if (*src != QUICLY_FRAME_TYPE_PADDING) {
                ret = QUICLY_ERROR_PROTOCOL_VIOLATION;
                goto Exit;
            }
        }
    }

    if ((conn = create_connection(ctx, NULL, sa, salen, handshake_properties)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    set_cid(&conn->super.peer.cid, packet->cid.src);
    /* TODO let the app set host cid after successful return from quicly_accept / quicly_connect */
    ctx->tls->random_bytes(conn->super.host.cid.cid, 8);
    conn->super.host.cid.len = 8;
    set_cid(&conn->super.host.cid, packet->cid.dest);
    if ((ret = setup_handshake_space_and_flow(conn, 0)) != 0)
        goto Exit;
    conn->initial->cipher.ingress = ingress_cipher;
    ingress_cipher = (struct st_quicly_cipher_context_t){NULL};
    conn->initial->cipher.egress = egress_cipher;
    egress_cipher = (struct st_quicly_cipher_context_t){NULL};
    conn->crypto.handshake_properties.collected_extensions = server_collected_extensions;
    /* TODO should there be a way to set use of stateless reset per SNI or something? */
    if (ctx->stateless_retry.enforce_use) {
        conn->crypto.handshake_properties.server.enforce_retry = 1;
        conn->crypto.handshake_properties.server.retry_uses_cookie = 1;
    }
    conn->crypto.handshake_properties.server.cookie.key = ctx->stateless_retry.key;

    ++conn->super.num_packets.received;
    assert(conn->initial->super.send_ack_at == INT64_MAX);

    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_ACCEPT, VEC_EVENT_ATTR(DCID, packet->cid.dest),
                         VEC_EVENT_ATTR(SCID, packet->cid.src));
    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_CRYPTO_DECRYPT, INT_EVENT_ATTR(PACKET_NUMBER, pn),
                         INT_EVENT_ATTR(LENGTH, payload.len));

    /* TODO log cid */

    if ((ret = record_receipt(&conn->initial->super, pn, 0, QUICLY_EPOCH_INITIAL)) != 0)
        goto Exit;
    conn->initial->super.next_expected_packet_number = next_expected_pn;

    if ((ret = apply_handshake_flow(conn, 0, &frame)) != 0)
        goto Exit;

    conn->super.state = QUICLY_STATE_CONNECTED;
    *_conn = conn;

Exit:
    if (!(ret == 0 || ret == PTLS_ERROR_IN_PROGRESS)) {
        if (conn != NULL)
            quicly_free(conn);
        if (ingress_cipher.aead != NULL)
            dispose_cipher(&ingress_cipher);
        if (egress_cipher.aead != NULL)
            dispose_cipher(&egress_cipher);
    }
    return ret;
}

static int on_ack_ack(quicly_conn_t *conn, int acked, quicly_ack_t *ack)
{
    /* TODO log */

    if (acked) {
        /* find the pn space */
        struct st_quicly_pn_space_t *space;
        switch (ack->ack_epoch) {
        case QUICLY_EPOCH_INITIAL:
            space = &conn->initial->super;
            break;
        case QUICLY_EPOCH_HANDSHAKE:
            space = &conn->handshake->super;
            break;
        case QUICLY_EPOCH_1RTT:
            space = &conn->application->super;
            break;
        default:
            assert(!"FIXME");
        }
        if (space != NULL) {
            quicly_ranges_subtract(&space->ack_queue, ack->data.ack.range.start, ack->data.ack.range.end);
            if (space->ack_queue.num_ranges == 0) {
                space->largest_pn_received_at = INT64_MAX;
                space->send_ack_at = INT64_MAX;
                space->unacked_count = 0;
            }
        }
    }

    return 0;
}

static int on_ack_stream(quicly_conn_t *conn, int acked, quicly_ack_t *ack)
{
    quicly_stream_t *stream;
    int ret;

    LOG_STREAM_EVENT(conn, ack->data.stream.stream_id, acked ? QUICLY_EVENT_TYPE_STREAM_ACKED : QUICLY_EVENT_TYPE_STREAM_LOST,
                     INT_EVENT_ATTR(OFFSET, ack->data.stream.args.start),
                     INT_EVENT_ATTR(LENGTH, ack->data.stream.args.end - ack->data.stream.args.start));

    /* TODO cache pointer to stream (using a generation counter?) */
    if ((stream = quicly_get_stream(conn, ack->data.stream.stream_id)) == NULL)
        return 0;

    if (acked) {
        if ((ret = quicly_sendbuf_acked(&stream->sendbuf, &ack->data.stream.args, ack->is_alive)) != 0)
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
    quicly_maxsender_t *maxsender = quicly_stream_is_unidirectional(ack->data.max_stream_id.args.value)
                                        ? conn->ingress.max_stream_id.uni
                                        : conn->ingress.max_stream_id.bidi;
    assert(maxsender != NULL); /* we would only receive an ACK if we have sent the frame */

    if (acked) {
        quicly_maxsender_acked(maxsender, &ack->data.max_stream_id.args);
    } else {
        quicly_maxsender_lost(maxsender, &ack->data.max_stream_id.args);
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
    quicly_maxsender_ackargs_t *ackargs = &ack->data.stream_id_blocked.args;
    struct st_quicly_max_stream_id_t *m =
        quicly_stream_is_unidirectional(ackargs->value) ? &conn->egress.max_stream_id.uni : &conn->egress.max_stream_id.bidi;

    if (acked) {
        quicly_maxsender_acked(&m->blocked_sender, ackargs);
    } else {
        quicly_maxsender_lost(&m->blocked_sender, ackargs);
    }

    return 0;
}

static int on_ack_cc(quicly_conn_t *conn, int acked, quicly_ack_t *ack)
{
    if (ack->is_alive) {
        conn->egress.cc.this_ack.nsegs += 1;
        conn->egress.cc.this_ack.nbytes += ack->data.cc.bytes_in_flight;
    }
    return 0;
}

static ssize_t round_send_window(ssize_t window)
{
    if (window < MIN_SEND_WINDOW * 2) {
        if (window < MIN_SEND_WINDOW) {
            return 0;
        } else {
            return MIN_SEND_WINDOW * 2;
        }
    }
    return window;
}

int64_t quicly_get_first_timeout(quicly_conn_t *conn)
{
    if (conn->super.state == QUICLY_STATE_DRAINING)
        return INT64_MAX;

    if (round_send_window((ssize_t)cc_get_cwnd(&conn->egress.cc.ccv) - (ssize_t)conn->egress.cc.bytes_in_flight) > 0) {
        if (conn->crypto.pending_flows != 0 || quicly_linklist_is_linked(&conn->pending_link.control) ||
            quicly_linklist_is_linked(&conn->pending_link.stream_fin_only) ||
            quicly_linklist_is_linked(&conn->pending_link.stream_with_payload))
            return 0;
    }

    int64_t at = conn->egress.loss.alarm_at;

#define CHECK_SPACE(label, egress_label)                                                                                           \
    do {                                                                                                                           \
        if (conn->label != NULL && conn->label->super.send_ack_at < at && conn->label->cipher.egress_label.aead != NULL)           \
            at = conn->label->super.send_ack_at;                                                                                   \
    } while (0)

    /* use macro defined above to check initial, handshake, and 0/1RTT ack spaces. */
    CHECK_SPACE(initial, egress);
    CHECK_SPACE(handshake, egress);
    CHECK_SPACE(application, egress_1rtt);

#undef CHECK_SPACE

    return at;
}

/* data structure that is used during one call through quicly_send()
 */
struct st_quicly_send_context_t {
    /* current encryption context */
    struct {
        struct st_quicly_cipher_context_t *cipher;
        int first_byte; /* first byte of packet == epoch */
    } current;

    /* packet under construction */
    struct {
        quicly_datagram_t *packet;
        struct st_quicly_cipher_context_t *cipher;
        uint8_t *first_byte_at;
        const uint8_t *ack_epoch; /* expected epoch of ACK for this packet */
        uint8_t to_be_acked : 1;  /* retransmittable packet (consumes congestion window) */
    } target;

    /* output buffer into which list of datagrams is written */
    quicly_datagram_t **packets;
    /* max number of datagrams that can be stored in |packets| */
    size_t max_packets;
    /* number of datagrams currently stored in |packets| */
    size_t num_packets;
    /* minimum packets that need to be sent */
    size_t min_packets_to_send;
    /* the currently available window for sending (in bytes) */
    ssize_t send_window;
    /* location where next frame should be written */
    uint8_t *dst;
    /* end of the payload area, beyond which frames cannot be written */
    uint8_t *dst_end;
    /* address at which payload starts */
    uint8_t *dst_encrypt_from;
};

static int commit_send_packet(quicly_conn_t *conn, struct st_quicly_send_context_t *s, int coalesced)
{
    assert(s->target.cipher->aead != NULL);

    assert(s->dst != s->dst_encrypt_from);

    if (!coalesced && s->target.packet->data.base[0] == QUICLY_PACKET_TYPE_INITIAL &&
        conn->super.state == QUICLY_STATE_FIRSTFLIGHT) {
        const size_t max_size = 1264; /* max UDP packet size excluding aead tag */
        assert(quicly_is_client(conn));
        assert(s->dst - s->target.packet->data.base <= max_size);
        memset(s->dst, 0, s->target.packet->data.base + max_size - s->dst);
        s->dst = s->target.packet->data.base + max_size;
    }

    if ((*s->target.first_byte_at & 0x80) != 0) {
        uint16_t length = s->dst - s->dst_encrypt_from + s->target.cipher->aead->algo->tag_size + 4;
        length |= 0x4000;
        quicly_encode16(s->dst_encrypt_from - 6, length);
    }
    quicly_encode32(s->dst_encrypt_from - 4, (uint32_t)conn->egress.packet_number | 0xc0000000);

    s->dst = s->dst_encrypt_from + ptls_aead_encrypt(s->target.cipher->aead, s->dst_encrypt_from, s->dst_encrypt_from,
                                                     s->dst - s->dst_encrypt_from, conn->egress.packet_number,
                                                     s->target.first_byte_at, s->dst_encrypt_from - s->target.first_byte_at);

    ptls_cipher_init(s->target.cipher->pne, s->dst_encrypt_from);
    ptls_cipher_encrypt(s->target.cipher->pne, s->dst_encrypt_from - 4, s->dst_encrypt_from - 4, 4);

    /* register CC callback if the packet is carrying any acknowledgible data */
    if (s->target.to_be_acked) {
        size_t packet_size = s->dst - s->target.first_byte_at;
        quicly_ack_t *ack;
        if ((ack = quicly_acks_allocate(&conn->egress.acks, conn->egress.packet_number, now, on_ack_cc, *s->target.ack_epoch, 1)) ==
            NULL)
            return PTLS_ERROR_NO_MEMORY;
        ack->data.cc.bytes_in_flight = packet_size;
        conn->egress.cc.bytes_in_flight += packet_size;
        s->send_window -= packet_size;
    }

    s->target.packet->data.len = s->dst - s->target.packet->data.base;
    assert(s->target.packet->data.len <= conn->super.ctx->max_packet_size);

    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_PACKET_COMMIT, INT_EVENT_ATTR(PACKET_NUMBER, conn->egress.packet_number),
                         INT_EVENT_ATTR(LENGTH, s->target.packet->data.len), INT_EVENT_ATTR(ACK_ONLY, !s->target.to_be_acked));

    ++conn->egress.packet_number;
    ++conn->super.num_packets.sent;
    conn->super.num_bytes_sent += s->target.packet->data.len;

    if (!coalesced) {
        s->packets[s->num_packets++] = s->target.packet;
        s->target.packet = NULL;
        s->target.cipher = NULL;
        s->target.first_byte_at = NULL;
    }

    return 0;
}

static inline uint8_t *emit_cid(uint8_t *dst, const quicly_cid_t *cid)
{
    if (cid->len != 0) {
        memcpy(dst, cid->cid, cid->len);
        dst += cid->len;
    }
    return dst;
}

static int _do_prepare_packet(quicly_conn_t *conn, struct st_quicly_send_context_t *s, size_t min_space, int to_be_acked)
{
    int coalescible, ret;

    assert(s->current.first_byte != -1);

    /* allocate and setup the new packet if necessary */
    if (s->dst_end - s->dst < min_space || s->target.first_byte_at == NULL) {
        coalescible = 0;
    } else if (*s->target.first_byte_at != s->current.first_byte) {
        coalescible = (*s->target.first_byte_at & 0x80) != 0;
    } else if (s->dst_end - s->dst < min_space) {
        coalescible = 0;
    } else {
        /* use the existing packet */
        goto TargetReady;
    }

    /* commit at the same time determining if we will coalesce the packets */
    if (s->target.packet != NULL) {
        if (coalescible) {
            size_t overhead = s->target.cipher->aead->algo->tag_size;
            if ((s->current.first_byte & 0x80) != 0) {
                overhead = 1 + 4 + 1 + conn->super.peer.cid.len + conn->super.host.cid.len + 2 + 4;
            } else {
                overhead = 1 + conn->super.peer.cid.len + 4;
            }
            overhead += s->current.cipher->aead->algo->tag_size;
            if (overhead + min_space > s->dst_end - s->dst)
                coalescible = 0;
        }
        /* close out packet under construction */
        if ((ret = commit_send_packet(conn, s, coalescible)) != 0)
            return ret;
    } else {
        coalescible = 0;
    }

    /* allocate packet */
    if (coalescible) {
        s->target.cipher = s->current.cipher;
    } else {
        if (s->num_packets >= s->max_packets)
            return QUICLY_ERROR_SENDBUF_FULL;
        s->send_window = round_send_window(s->send_window);
        if (to_be_acked && s->send_window < (ssize_t)min_space)
            return QUICLY_ERROR_SENDBUF_FULL;
        if ((s->target.packet =
                 conn->super.ctx->alloc_packet(conn->super.ctx, conn->super.peer.salen, conn->super.ctx->max_packet_size)) == NULL)
            return PTLS_ERROR_NO_MEMORY;
        s->target.packet->salen = conn->super.peer.salen;
        memcpy(&s->target.packet->sa, conn->super.peer.sa, conn->super.peer.salen);
        s->target.cipher = s->current.cipher;
        s->dst = s->target.packet->data.base;
        s->dst_end = s->target.packet->data.base + conn->super.ctx->max_packet_size;
    }
    s->target.to_be_acked = 0;

    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_PACKET_PREPARE, INT_EVENT_ATTR(FIRST_OCTET, s->current.first_byte),
                         VEC_EVENT_ATTR(DCID, ptls_iovec_init(conn->super.peer.cid.cid, conn->super.peer.cid.len)));

    /* emit header */
    s->target.first_byte_at = s->dst;
    *s->dst++ = s->current.first_byte;
    if ((s->current.first_byte & 0x80) != 0) {
        s->dst = quicly_encode32(s->dst, conn->super.version);
        *s->dst++ = (encode_cid_length(conn->super.peer.cid.len) << 4) | encode_cid_length(conn->super.host.cid.len);
        s->dst = emit_cid(s->dst, &conn->super.peer.cid);
        s->dst = emit_cid(s->dst, &conn->super.host.cid);
        /* token */
        if (s->current.first_byte == QUICLY_PACKET_TYPE_INITIAL)
            *s->dst++ = 0;
        /* payload length is filled laterwards */
        *s->dst++ = 0;
        *s->dst++ = 0;
    } else {
        s->dst = emit_cid(s->dst, &conn->super.peer.cid);
    }
    s->dst += 4; /* space for PN bits, filled in at commit time */
    s->dst_encrypt_from = s->dst;
    assert(s->target.cipher->aead != NULL);
    s->dst_end -= s->target.cipher->aead->algo->tag_size;
    assert(s->dst < s->dst_end);

    /* determine ack_epoch, the expected epoch of the ACKs for the current packet */
    switch (s->current.first_byte) {
        static const uint8_t epoch_initial = QUICLY_EPOCH_INITIAL, epoch_handshake = QUICLY_EPOCH_HANDSHAKE,
                             epoch_1rtt = QUICLY_EPOCH_1RTT;
    case QUICLY_PACKET_TYPE_INITIAL:
        s->target.ack_epoch = &epoch_initial;
        break;
    case QUICLY_PACKET_TYPE_HANDSHAKE:
        s->target.ack_epoch = &epoch_handshake;
        break;
    case QUICLY_PACKET_TYPE_0RTT_PROTECTED:
        s->target.ack_epoch = &epoch_1rtt;
        break;
    default:
        if ((s->current.first_byte & 0x80) != 0) {
            s->target.ack_epoch = NULL;
        } else {
            s->target.ack_epoch = &epoch_1rtt;
        }
        break;
    }

    /* add PING or empty CRYPTO for TLP, RTO packets so that last_retransmittable_sent_at changes */
    if (s->num_packets < s->min_packets_to_send) {
        if ((s->current.first_byte & 0x80) == 0) {
            *s->dst++ = QUICLY_FRAME_TYPE_PING;
        } else {
            size_t payload_len = 0;
            s->dst = quicly_encode_crypto_frame_header(s->dst, s->dst_end, 0, &payload_len);
        }
        to_be_acked = 1;
    }

TargetReady:
    if (to_be_acked) {
        s->target.to_be_acked = 1;
        conn->egress.last_retransmittable_sent_at = now;
    }
    return 0;
}

static int prepare_packet(quicly_conn_t *conn, struct st_quicly_send_context_t *s, size_t min_space)
{
    return _do_prepare_packet(conn, s, min_space, 0);
}

static int prepare_acked_packet(quicly_conn_t *conn, struct st_quicly_send_context_t *s, size_t min_space, quicly_ack_t **ack,
                                quicly_ack_cb ack_cb)
{
    int ret;

    if ((ret = _do_prepare_packet(conn, s, min_space, 1)) != 0)
        return ret;
    if ((*ack = quicly_acks_allocate(&conn->egress.acks, conn->egress.packet_number, now, ack_cb, *s->target.ack_epoch, 1)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    /* TODO return the remaining window that the sender can use */
    return ret;
}

static int send_ack(quicly_conn_t *conn, struct st_quicly_pn_space_t *space, struct st_quicly_send_context_t *s)
{
    uint64_t ack_delay;
    int ret;

    if (space->ack_queue.num_ranges == 0)
        return 0;

    /* calc ack_delay */
    if (space->largest_pn_received_at < now) {
        /* We underreport ack_delay up to 1 milliseconds assuming that QUICLY_ACK_DELAY_EXPONENT is 10. It's considered a non-issue
         * because our time measurement is at millisecond granurality anyways. */
        ack_delay = ((now - space->largest_pn_received_at) * 1000) >> QUICLY_ACK_DELAY_EXPONENT;
    } else {
        ack_delay = 0;
    }

    /* emit ack frame */
Emit:
    if ((ret = prepare_packet(conn, s, QUICLY_ACK_FRAME_CAPACITY)) != 0)
        return ret;
    uint8_t *new_dst = quicly_encode_ack_frame(s->dst, s->dst_end, &space->ack_queue, ack_delay);
    if (new_dst == NULL) {
        /* no space, retry with new MTU-sized packet */
        if ((ret = commit_send_packet(conn, s, 0)) != 0)
            return ret;
        goto Emit;
    }
    s->dst = new_dst;

    { /* save what's inflight */
        size_t i;
        for (i = 0; i != space->ack_queue.num_ranges; ++i) {
            quicly_ack_t *ack;
            if ((ack = quicly_acks_allocate(&conn->egress.acks, conn->egress.packet_number, now, on_ack_ack, *s->target.ack_epoch,
                                            0)) == NULL)
                return PTLS_ERROR_NO_MEMORY;
            ack->data.ack.range = space->ack_queue.ranges[i];
        }
    }

    space->send_ack_at = INT64_MAX;
    space->unacked_count = 0;

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
        /* FIXME also send an empty STREAM frame */
        if ((ret = prepare_stream_state_sender(stream, &stream->_send_aux.stop_sending.sender_state, s,
                                               QUICLY_STOP_SENDING_FRAME_CAPACITY, on_ack_stop_sending)) != 0)
            return ret;
        s->dst = quicly_encode_stop_sending_frame(s->dst, stream->stream_id, stream->_send_aux.stop_sending.error_code);
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
            quicly_encode_rst_stream_frame(s->dst, stream->stream_id, stream->_send_aux.rst.error_code, stream->_send_aux.max_sent);
    }

    return 0;
}

static int send_stream_frame(quicly_stream_t *stream, struct st_quicly_send_context_t *s, quicly_sendbuf_dataiter_t *iter,
                             size_t max_bytes)
{
    quicly_ack_t *ack;
    size_t copysize;
    int is_fin = 0, ret;

    if ((ret = prepare_acked_packet(stream->conn, s, QUICLY_STREAM_FRAME_CAPACITY, &ack, on_ack_stream)) != 0)
        return ret;

    copysize = max_bytes - (iter->stream_off + max_bytes > stream->sendbuf.eos);
    if (stream->stream_id < 0) {
        s->dst = quicly_encode_crypto_frame_header(s->dst, s->dst_end, iter->stream_off, &copysize);
    } else {
        is_fin = iter->stream_off + copysize >= stream->sendbuf.eos;
        s->dst = quicly_encode_stream_frame_header(s->dst, s->dst_end, stream->stream_id, is_fin, iter->stream_off, &copysize);
    }

    LOG_STREAM_EVENT(stream->conn, stream->stream_id, QUICLY_EVENT_TYPE_STREAM_SEND, INT_EVENT_ATTR(OFFSET, iter->stream_off),
                     INT_EVENT_ATTR(LENGTH, copysize), INT_EVENT_ATTR(FIN, is_fin));

    /* adjust remaining send window */
    if (stream->_send_aux.max_sent < iter->stream_off + copysize) {
        if (stream->stream_id >= 0) {
            uint64_t delta = iter->stream_off + copysize - stream->_send_aux.max_sent;
            assert(stream->conn->egress.max_data.sent + delta <= stream->conn->egress.max_data.permitted);
            stream->conn->egress.max_data.sent += delta;
        }
        stream->_send_aux.max_sent = iter->stream_off + copysize;
        if (stream->_send_aux.max_sent == stream->sendbuf.eos)
            ++stream->_send_aux.max_sent;
    }

    /* send */
    quicly_sendbuf_emit(&stream->sendbuf, iter, copysize, s->dst, &ack->data.stream.args);
    s->dst += copysize;

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
        if (stream->stream_id >= 0 && stream->conn->egress.max_data.permitted - stream->conn->egress.max_data.sent < delta)
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
    if (i != 0)
        quicly_ranges_shrink(&stream->sendbuf.pending, 0, i);
    return ret;
}

static void init_acks_iter(quicly_conn_t *conn, quicly_acks_iter_t *iter)
{
    /* TODO find a better threshold */
    int64_t retire_before = now - ((conn->egress.loss.rtt.smoothed + conn->egress.loss.rtt.variance) * 4 +
                                   conn->super.peer.transport_params.max_ack_delay + QUICLY_DELAYED_ACK_TIMEOUT);
    quicly_ack_t *ack;

    quicly_acks_init_iter(&conn->egress.acks, iter);

    while ((ack = quicly_acks_get(iter))->sent_at < retire_before && !ack->is_alive) {
        quicly_acks_release(&conn->egress.acks, iter);
        quicly_acks_next(iter);
    }
}

int retire_acks_by_ack_epoch(quicly_conn_t *conn, uint8_t ack_epoch)
{
    quicly_acks_iter_t iter;
    quicly_ack_t *ack;
    int ret = 0;

    conn->egress.cc.this_ack.nsegs = 0;
    conn->egress.cc.this_ack.nbytes = 0;

    for (init_acks_iter(conn, &iter); (ack = quicly_acks_get(&iter))->packet_number != UINT64_MAX; quicly_acks_next(&iter)) {
        if (ack->ack_epoch == ack_epoch) {
            if (conn->egress.max_lost_pn <= ack->packet_number) {
                if ((ret = quicly_acks_on_ack(&conn->egress.acks, 0, ack, conn)) != 0)
                    return ret;
            }
            quicly_acks_release(&conn->egress.acks, &iter);
        }
    }

    assert(conn->egress.cc.bytes_in_flight >= conn->egress.cc.this_ack.nbytes);
    conn->egress.cc.bytes_in_flight -= conn->egress.cc.this_ack.nbytes;

    return ret;
}

/* Determine frames to be retransmitted on TLP and RTO.
 */
static int retire_acks_by_count(quicly_conn_t *conn, size_t count)
{
    quicly_acks_iter_t iter;
    quicly_ack_t *ack;
    uint64_t pn;
    int ret;

    assert(count != 0);

    init_acks_iter(conn, &iter);

    while ((pn = (ack = quicly_acks_get(&iter))->packet_number) < conn->egress.max_lost_pn)
        quicly_acks_next(&iter);

    conn->egress.cc.this_ack.nsegs = 0;
    conn->egress.cc.this_ack.nbytes = 0;

    do {
        if ((pn = ack->packet_number) == UINT64_MAX)
            break;
        do {
            if ((ret = quicly_acks_on_ack(&conn->egress.acks, 0, ack, conn)) != 0)
                return ret;
            quicly_acks_next(&iter);
        } while ((ack = quicly_acks_get(&iter))->packet_number == pn);
        conn->egress.max_lost_pn = pn + 1;
    } while (--count != 0);

    assert(conn->egress.cc.bytes_in_flight >= conn->egress.cc.this_ack.nbytes);
    conn->egress.cc.bytes_in_flight -= conn->egress.cc.this_ack.nbytes;

    return 0;
}

/* this function ensures that the value returned in loss_time is when the next
 * application timer should be set for loss detection. if no timer is required,
 * loss_time is set to INT64_MAX.
 */
static int do_detect_loss(quicly_loss_t *ld, uint64_t largest_pn, uint32_t delay_until_lost, int64_t *loss_time)
{
    quicly_conn_t *conn = (void *)((char *)ld - offsetof(quicly_conn_t, egress.loss));
    quicly_acks_iter_t iter;
    quicly_ack_t *ack;
    int64_t sent_before = now - delay_until_lost;
    uint64_t largest_newly_lost_pn = UINT64_MAX;
    int ret;

    *loss_time = INT64_MAX;

    init_acks_iter(conn, &iter);

    /* handle loss */
    conn->egress.cc.this_ack.nsegs = 0;
    conn->egress.cc.this_ack.nbytes = 0;

    /* mark packets as lost if they are smaller than the largest_pn and outside
     * the early retransmit window. in other words, packets that are not ready
     * to be marked as lost according to the early retransmit timer.
     */
    while ((ack = quicly_acks_get(&iter))->packet_number < largest_pn && ack->sent_at <= sent_before) {
        if (ack->is_alive && conn->egress.max_lost_pn <= ack->packet_number) {
            if (ack->packet_number != largest_newly_lost_pn) {
                ++conn->super.num_packets.lost;
                largest_newly_lost_pn = ack->packet_number;
                LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_PACKET_LOST, INT_EVENT_ATTR(PACKET_NUMBER, largest_newly_lost_pn));
            }
            if ((ret = quicly_acks_on_ack(&conn->egress.acks, 0, ack, conn)) != 0)
                return ret;
        }
        quicly_acks_next(&iter);
    }
    assert(conn->egress.cc.bytes_in_flight >= conn->egress.cc.this_ack.nbytes);
    conn->egress.cc.bytes_in_flight -= conn->egress.cc.this_ack.nbytes;
    if (largest_newly_lost_pn != UINT64_MAX) {
        conn->egress.max_lost_pn = largest_newly_lost_pn + 1;
        conn->egress.cc.end_of_recovery = conn->egress.packet_number - 1;
        if (conn->egress.cc.this_ack.nbytes != 0 && conn->egress.loss.rto_count == 0) {
            cc_cong_signal(&conn->egress.cc.ccv, CC_ECN, (uint32_t)conn->egress.cc.bytes_in_flight);
            LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_CC_CONGESTION, INT_EVENT_ATTR(MAX_LOST_PN, conn->egress.max_lost_pn),
                                 INT_EVENT_ATTR(END_OF_RECOVERY, conn->egress.cc.end_of_recovery),
                                 INT_EVENT_ATTR(BYTES_IN_FLIGHT, conn->egress.cc.bytes_in_flight),
                                 INT_EVENT_ATTR(CWND, cc_get_cwnd(&conn->egress.cc.ccv)));
        }
    }

    /* schedule early retransmit alarm if there is a packet outstanding that is smaller than largest_pn */
    while (ack->packet_number < largest_pn && ack->sent_at != INT64_MAX) {
        if (ack->is_alive) {
            *loss_time = ack->sent_at + delay_until_lost;
            break;
        } else if (ack->acked != on_ack_ack) {
            break;
        }
        quicly_acks_next(&iter);
        ack = quicly_acks_get(&iter);
    }

    return 0;
}

static void update_loss_alarm(quicly_conn_t *conn)
{
    quicly_loss_update_alarm(&conn->egress.loss, now, conn->egress.last_retransmittable_sent_at,
                             conn->egress.acks.num_in_flight != 0);
}

static void open_id_blocked_streams(quicly_conn_t *conn, int uni)
{
    quicly_stream_id_t max_stream_id;
    quicly_linklist_t *anchor;

    if (uni) {
        max_stream_id = conn->egress.max_stream_id.uni.id;
        anchor = &conn->pending_link.stream_id_blocked.uni;
    } else {
        max_stream_id = conn->egress.max_stream_id.bidi.id;
        anchor = &conn->pending_link.stream_id_blocked.bidi;
    }

    while (quicly_linklist_is_linked(anchor)) {
        quicly_stream_t *stream = (void *)((char *)anchor->next - offsetof(quicly_stream_t, _send_aux.pending_link.control));
        if (stream->stream_id > max_stream_id)
            break;
        assert(stream->stream_id_blocked);
        quicly_linklist_unlink(&stream->_send_aux.pending_link.control);
        stream->stream_id_blocked = 0;
        /* TODO retain separate flags for stream states so that we do not always need to sched for both control and data */
        sched_stream_control(stream);
        resched_stream_data(stream);
    }
}

static int send_stream_frames(quicly_conn_t *conn, struct st_quicly_send_context_t *s)
{
    int ret = 0;

    /* fin-only STREAM frames */
    while (s->num_packets != s->max_packets && quicly_linklist_is_linked(&conn->pending_link.stream_fin_only)) {
        quicly_stream_t *stream =
            (void *)((char *)conn->pending_link.stream_fin_only.next - offsetof(quicly_stream_t, _send_aux.pending_link.stream));
        if ((ret = send_stream_data(stream, s)) != 0)
            goto Exit;
        resched_stream_data(stream);
    }
    /* STREAM frames with payload */
    while (s->num_packets != s->max_packets && quicly_linklist_is_linked(&conn->pending_link.stream_with_payload) &&
           conn->egress.max_data.sent < conn->egress.max_data.permitted) {
        quicly_stream_t *stream = (void *)((char *)conn->pending_link.stream_with_payload.next -
                                           offsetof(quicly_stream_t, _send_aux.pending_link.stream));
        if ((ret = send_stream_data(stream, s)) != 0)
            goto Exit;
        resched_stream_data(stream);
    }

Exit:
    return 0;
}

quicly_datagram_t *quicly_send_version_negotiation(quicly_context_t *ctx, struct sockaddr *sa, socklen_t salen,
                                                   ptls_iovec_t dest_cid, ptls_iovec_t src_cid)
{
    quicly_datagram_t *packet;
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
    /* version */
    dst = quicly_encode32(dst, 0);
    /* connection-id */
    *dst++ = (encode_cid_length(dest_cid.len) << 4) | encode_cid_length(src_cid.len);
    if (dest_cid.len != 0) {
        memcpy(dst, dest_cid.base, dest_cid.len);
        dst += dest_cid.len;
    }
    if (src_cid.len != 0) {
        memcpy(dst, src_cid.base, src_cid.len);
        dst += src_cid.len;
    }
    /* supported_versions */
    dst = quicly_encode32(dst, QUICLY_PROTOCOL_VERSION);

    packet->data.len = dst - packet->data.base;

    return packet;
}

static int send_handshake_flow(quicly_conn_t *conn, size_t epoch, struct st_quicly_send_context_t *s)
{
    struct st_quicly_pn_space_t *ack_space = NULL;
    int ret = 0;

    switch (epoch) {
    case QUICLY_EPOCH_INITIAL:
        if (conn->initial == NULL || (s->current.cipher = &conn->initial->cipher.egress)->aead == NULL)
            return 0;
        s->current.first_byte = QUICLY_PACKET_TYPE_INITIAL;
        ack_space = &conn->initial->super;
        break;
    case QUICLY_EPOCH_0RTT:
        if (conn->application == NULL || (s->current.cipher = &conn->application->cipher.egress_0rtt)->aead == NULL)
            return 0;
        s->current.first_byte = QUICLY_PACKET_TYPE_0RTT_PROTECTED;
        break;
    case QUICLY_EPOCH_HANDSHAKE:
        if (conn->handshake == NULL || (s->current.cipher = &conn->handshake->cipher.egress)->aead == NULL)
            return 0;
        s->current.first_byte = QUICLY_PACKET_TYPE_HANDSHAKE;
        ack_space = &conn->handshake->super;
        break;
    default:
        assert(!"logic flaw");
        return 0;
    }

    /* send ACK */
    if (ack_space != NULL && ack_space->send_ack_at <= now)
        if ((ret = send_ack(conn, ack_space, s)) != 0)
            goto Exit;

    /* send data */
    if ((conn->crypto.pending_flows & (uint8_t)(1 << epoch)) != 0) {
        quicly_stream_t *stream = quicly_get_stream(conn, -(quicly_stream_id_t)(1 + epoch));
        assert(stream != NULL);
        if ((ret = send_stream_data(stream, s)) != 0)
            goto Exit;
        resched_stream_data(stream);
    }

Exit:
    return ret;
}

static int update_traffic_key_cb(ptls_update_traffic_key_t *self, ptls_t *_tls, int is_enc, size_t epoch, const void *secret)
{
    quicly_conn_t *conn = *ptls_get_data_ptr(_tls);
    ptls_cipher_suite_t *cipher = ptls_get_cipher(conn->crypto.tls);
    struct st_quicly_cipher_context_t *cipher_slot;
    int ret;

    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_CRYPTO_UPDATE_SECRET, INT_EVENT_ATTR(IS_ENC, is_enc),
                         INT_EVENT_ATTR(EPOCH, epoch));

    switch (epoch) {
    case QUICLY_EPOCH_0RTT:
        assert(is_enc == quicly_is_client(conn));
        if (conn->application == NULL && (ret = setup_application_space_and_flow(conn, 1)) != 0)
            return ret;
        cipher_slot = is_enc ? &conn->application->cipher.egress_0rtt : &conn->application->cipher.ingress[0];
        break;
    case QUICLY_EPOCH_HANDSHAKE:
        if (is_enc && conn->application != NULL && quicly_is_client(conn) &&
            !conn->crypto.handshake_properties.client.early_data_accepted_by_peer) {
            /* 0-RTT is rejected */
            assert(conn->application->cipher.egress_0rtt.aead != NULL);
            dispose_cipher(&conn->application->cipher.egress_0rtt);
            conn->application->cipher.egress_0rtt = (struct st_quicly_cipher_context_t){NULL};
            retire_acks_by_ack_epoch(conn, 3); /* retire all packets with ack_epoch == 3; they are all 0-RTT packets */
        }
        if (conn->handshake == NULL && (ret = setup_handshake_space_and_flow(conn, 2)) != 0)
            return ret;
        cipher_slot = is_enc ? &conn->handshake->cipher.egress : &conn->handshake->cipher.ingress;
        break;
    case QUICLY_EPOCH_1RTT:
        if (is_enc)
            apply_peer_transport_params(conn);
        if (conn->application == NULL && (ret = setup_application_space_and_flow(conn, 0)) != 0)
            return ret;
        cipher_slot = is_enc ? &conn->application->cipher.egress_1rtt : &conn->application->cipher.ingress[1];
        break;
    default:
        assert(!"logic flaw");
        break;
    }

    if ((ret = setup_cipher(cipher_slot, cipher->aead, cipher->hash, is_enc, secret)) != 0)
        return ret;

    if (epoch == QUICLY_EPOCH_1RTT && is_enc) {
        /* update states now that we have 1-RTT write key */
        open_id_blocked_streams(conn, 1);
        open_id_blocked_streams(conn, 0);
    }

    return 0;
}

int quicly_send(quicly_conn_t *conn, quicly_datagram_t **packets, size_t *num_packets)
{
    struct st_quicly_send_context_t s = {{NULL, -1}, {NULL, NULL, NULL}, packets, *num_packets};
    int ret;

    update_now(conn->super.ctx);

    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_SEND);

    switch (quicly_get_state(conn)) {
    case QUICLY_STATE_SEND_RETRY:
        assert(!"TODO");
        return 0;
    case QUICLY_STATE_DRAINING:
        *num_packets = 0;
        return QUICLY_ERROR_CONNECTION_CLOSED;
    default:
        break;
    }

    /* handle timeouts */
    if (conn->egress.loss.alarm_at <= now) {
        if ((ret = quicly_loss_on_alarm(&conn->egress.loss, conn->egress.packet_number - 1, conn->egress.loss.largest_acked_packet,
                                        do_detect_loss, &s.min_packets_to_send)) != 0)
            goto Exit;
        switch (s.min_packets_to_send) {
        case 1: /* TLP (try to send new data when handshake is done, otherwise retire oldest handshake packets and retransmit) */
            LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_CC_TLP, INT_EVENT_ATTR(BYTES_IN_FLIGHT, conn->egress.cc.bytes_in_flight),
                                 INT_EVENT_ATTR(CWND, cc_get_cwnd(&conn->egress.cc.ccv)));
            if (!ptls_handshake_is_complete(conn->crypto.tls)) {
                if ((ret = retire_acks_by_count(conn, s.min_packets_to_send)) != 0)
                    goto Exit;
            }
            break;
        case 2: /* RTO */ {
            uint32_t cc_type = 0;
            if (!conn->egress.cc.in_first_rto) {
                cc_type = CC_FIRST_RTO;
                cc_cong_signal(&conn->egress.cc.ccv, cc_type, (uint32_t)conn->egress.cc.bytes_in_flight);
                conn->egress.cc.in_first_rto = 1;
            }
            LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_CC_RTO, INT_EVENT_ATTR(CC_TYPE, cc_type),
                                 INT_EVENT_ATTR(BYTES_IN_FLIGHT, conn->egress.cc.bytes_in_flight),
                                 INT_EVENT_ATTR(CWND, cc_get_cwnd(&conn->egress.cc.ccv)));
            if ((ret = retire_acks_by_count(conn, s.min_packets_to_send)) != 0)
                goto Exit;
        } break;
        default:
            break;
        }
    }

    { /* calculate send window */
        uint32_t cwnd = cc_get_cwnd(&conn->egress.cc.ccv);
        if (conn->egress.cc.bytes_in_flight < cwnd)
            s.send_window = cwnd - conn->egress.cc.bytes_in_flight;
    }

    /* If TLP or RTO, ensure there's enough send_window to send */
    if (s.min_packets_to_send != 0) {
        assert(s.min_packets_to_send <= s.max_packets);
        if (s.send_window < s.min_packets_to_send * conn->super.ctx->max_packet_size)
            s.send_window = s.min_packets_to_send * conn->super.ctx->max_packet_size;
    }

    { /* send handshake flows */
        size_t epoch;
        for (epoch = 0; epoch <= 2; ++epoch)
            if ((ret = send_handshake_flow(conn, epoch, &s)) != 0)
                goto Exit;
    }

    /* send encrypted frames */
    if (conn->application != NULL) {
        if ((s.current.cipher = &conn->application->cipher.egress_1rtt)->aead != NULL) {
            s.current.first_byte = 0x30; /* short header, key-phase=0 */
            /* acks */
            if (conn->application->super.unacked_count != 0 || conn->application->super.send_ack_at <= now) {
                if ((ret = send_ack(conn, &conn->application->super, &s)) != 0)
                    goto Exit;
            }
            /* respond to all pending received PATH_CHALLENGE frames */
            if (conn->egress.path_challenge.head != NULL) {
                do {
                    struct st_quicly_pending_path_challenge_t *c = conn->egress.path_challenge.head;
                    if ((ret = prepare_packet(conn, &s, QUICLY_PATH_CHALLENGE_FRAME_CAPACITY)) != 0)
                        goto Exit;
                    s.dst = quicly_encode_path_challenge_frame(s.dst, c->is_response, c->data);
                    conn->egress.path_challenge.head = c->next;
                    free(c);
                } while (conn->egress.path_challenge.head != NULL);
                conn->egress.path_challenge.tail_ref = &conn->egress.path_challenge.head;
            }
/* send max_stream_id frames */
#define SEND_MAX_STREAM_ID(label)                                                                                                  \
    if (conn->ingress.max_stream_id.label != NULL) {                                                                               \
        quicly_stream_id_t max_stream_id;                                                                                          \
        if ((max_stream_id = quicly_maxsender_should_update_stream_id(                                                             \
                 conn->ingress.max_stream_id.label, conn->super.peer.label.next_stream_id, conn->super.peer.label.num_streams,     \
                 conn->super.ctx->max_streams_##label, 768)) >= 0) {                                                               \
            quicly_ack_t *ack;                                                                                                     \
            if ((ret = prepare_acked_packet(conn, &s, QUICLY_MAX_STREAM_ID_FRAME_CAPACITY, &ack, on_ack_max_stream_id)) != 0)      \
                goto Exit;                                                                                                         \
            s.dst = quicly_encode_max_stream_id_frame(s.dst, max_stream_id);                                                       \
            quicly_maxsender_record(conn->ingress.max_stream_id.label, max_stream_id, &ack->data.max_stream_id.args);              \
        }                                                                                                                          \
    }
            SEND_MAX_STREAM_ID(uni);
            SEND_MAX_STREAM_ID(bidi);
#undef SEND_MAX_STREAM_ID
            /* send connection-level flow control frame */
            if (quicly_maxsender_should_update(&conn->ingress.max_data.sender, conn->ingress.max_data.bytes_consumed,
                                               conn->super.ctx->initial_max_data, 512)) {
                quicly_ack_t *ack;
                if ((ret = prepare_acked_packet(conn, &s, QUICLY_MAX_DATA_FRAME_CAPACITY, &ack, on_ack_max_data)) != 0)
                    goto Exit;
                uint64_t new_value = conn->ingress.max_data.bytes_consumed + conn->super.ctx->initial_max_data;
                s.dst = quicly_encode_max_data_frame(s.dst, new_value);
                quicly_maxsender_record(&conn->ingress.max_data.sender, new_value, &ack->data.max_data.args);
            }
/* send stream_id_blocked frames */
#define SEND_STREAM_ID_BLOCKED(label)                                                                                              \
    if (quicly_linklist_is_linked(&conn->pending_link.stream_id_blocked.label)) {                                                  \
        struct st_quicly_max_stream_id_t *max_stream_id = &conn->egress.max_stream_id.label;                                       \
        quicly_stream_t *max_stream = (void *)((char *)conn->pending_link.stream_id_blocked.label.prev -                           \
                                               offsetof(quicly_stream_t, _send_aux.pending_link.control));                         \
        assert(max_stream_id->id < max_stream->stream_id);                                                                         \
        if (quicly_maxsender_should_send_blocked(&max_stream_id->blocked_sender, max_stream->stream_id)) {                         \
            quicly_ack_t *ack;                                                                                                     \
            if ((ret = prepare_acked_packet(conn, &s, QUICLY_STREAM_ID_BLOCKED_FRAME_CAPACITY, &ack, on_ack_stream_id_blocked)) != \
                0)                                                                                                                 \
                goto Exit;                                                                                                         \
            s.dst = quicly_encode_stream_id_blocked_frame(s.dst, max_stream->stream_id);                                           \
            quicly_maxsender_record(&max_stream_id->blocked_sender, max_stream->stream_id, &ack->data.stream_id_blocked.args);     \
        }                                                                                                                          \
    }
            SEND_STREAM_ID_BLOCKED(uni);
            SEND_STREAM_ID_BLOCKED(bidi);
#undef SEND_STREAM_ID_BLOCKED
        } else if ((s.current.cipher = &conn->application->cipher.egress_0rtt)->aead != NULL) {
            s.current.first_byte = QUICLY_PACKET_TYPE_0RTT_PROTECTED;
        } else {
            s.current.cipher = NULL;
        }
        if (s.current.cipher != NULL) {
            /* send stream-level control frames */
            while (s.num_packets != s.max_packets && quicly_linklist_is_linked(&conn->pending_link.control)) {
                quicly_stream_t *stream =
                    (void *)((char *)conn->pending_link.control.next - offsetof(quicly_stream_t, _send_aux.pending_link.control));
                if ((ret = send_stream_control_frames(stream, &s)) != 0)
                    goto Exit;
                quicly_linklist_unlink(&stream->_send_aux.pending_link.control);
            }
            /* send STREAM frames */
            if ((ret = send_stream_frames(conn, &s)) != 0)
                goto Exit;
        }
    }

    if (s.target.packet != NULL)
        commit_send_packet(conn, &s, 0);

    /* TLP (TODO use these packets to retransmit data) */
    if (s.min_packets_to_send != 0) {
        if ((s.current.first_byte & 0x80) != 0) {
            if (conn->handshake != NULL && (s.current.cipher = &conn->handshake->cipher.egress)->aead != NULL) {
                s.current.first_byte = QUICLY_PACKET_TYPE_HANDSHAKE;
            } else {
                s.current.cipher = &conn->initial->cipher.egress;
                s.current.first_byte = QUICLY_PACKET_TYPE_INITIAL;
            }
        }
        while (s.num_packets < s.min_packets_to_send) {
            if ((ret = prepare_packet(conn, &s, 1)) != 0)
                goto Exit;
            assert(s.target.to_be_acked);
            commit_send_packet(conn, &s, 0);
        }
        assert(conn->egress.last_retransmittable_sent_at == now);
    }

    ret = 0;
Exit:
    if (ret == QUICLY_ERROR_SENDBUF_FULL)
        ret = 0;
    if (ret == 0) {
        update_loss_alarm(conn);
        *num_packets = s.num_packets;
        if (s.current.first_byte == QUICLY_PACKET_TYPE_RETRY)
            ret = QUICLY_ERROR_CONNECTION_CLOSED;
    }
    if (ret == 0)
        assert_consistency(conn, 1);
    return ret;
}

static int get_stream_or_open_if_new(quicly_conn_t *conn, uint64_t stream_id, quicly_stream_t **stream)
{
    int ret = 0;

    if ((*stream = quicly_get_stream(conn, stream_id)) != NULL)
        goto Exit;

    if (quicly_stream_is_client_initiated(stream_id) != quicly_is_client(conn)) {
        /* open new streams upto given id */
        struct st_quicly_conn_streamgroup_state_t *group = get_streamgroup_state(conn, stream_id);
        if (group->next_stream_id <= stream_id) {
            uint32_t max_stream_data_local, max_stream_data_remote;
            if (quicly_stream_is_unidirectional(stream_id)) {
                max_stream_data_local = conn->super.ctx->initial_max_stream_data.uni;
                max_stream_data_remote = 0;
            } else {
                max_stream_data_local = conn->super.ctx->initial_max_stream_data.bidi_remote;
                max_stream_data_remote = conn->super.peer.transport_params.initial_max_stream_data.bidi_local;
            }
            do {
                if ((*stream = open_stream(conn, group->next_stream_id, max_stream_data_local, max_stream_data_remote)) == NULL) {
                    ret = PTLS_ERROR_NO_MEMORY;
                    goto Exit;
                }
                if ((ret = conn->super.ctx->on_stream_open(*stream)) != 0) {
                    destroy_stream(*stream);
                    *stream = NULL;
                    goto Exit;
                }
                ++group->num_streams;
                group->next_stream_id += 4;
            } while (stream_id != (*stream)->stream_id);
        }
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

    if ((ret = quicly_recvbuf_reset(&stream->recvbuf, frame->app_error_code, frame->final_offset, &bytes_missing)) != 0)
        return ret;
    conn->ingress.max_data.bytes_consumed += bytes_missing;

    if (quicly_stream_is_closable(stream))
        ret = stream->on_update(stream);

    return ret;
}

static int handle_ack_frame(quicly_conn_t *conn, size_t epoch, quicly_ack_frame_t *frame)
{
    quicly_acks_iter_t iter;
    uint64_t packet_number = frame->smallest_acknowledged;
    uint32_t bytes_in_flight = (uint32_t)conn->egress.cc.bytes_in_flight;
    struct {
        uint64_t packet_number;
        int64_t sent_at;
    } largest_newly_acked = {UINT64_MAX, INT64_MAX};
    uint64_t smallest_newly_acked = UINT64_MAX;
    int ret;

    if (epoch == 1)
        return QUICLY_ERROR_PROTOCOL_VIOLATION;

    conn->egress.cc.this_ack.nsegs = 0;
    conn->egress.cc.this_ack.nbytes = 0;

    init_acks_iter(conn, &iter);

    size_t gap_index = frame->num_gaps;
    while (1) {
        uint64_t block_length = frame->ack_block_lengths[gap_index];
        if (block_length != 0) {
            while (quicly_acks_get(&iter)->packet_number < packet_number)
                quicly_acks_next(&iter);
            do {
                quicly_ack_t *ack;
                if ((ack = quicly_acks_get(&iter))->packet_number == packet_number) {
                    ++conn->super.num_packets.ack_received;
                    int apply = epoch == ack->ack_epoch;
                    if (apply) {
                        largest_newly_acked.packet_number = packet_number;
                        largest_newly_acked.sent_at = ack->sent_at;
                        if (smallest_newly_acked == UINT64_MAX)
                            smallest_newly_acked = packet_number;
                    }
                    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_PACKET_ACKED, INT_EVENT_ATTR(PACKET_NUMBER, packet_number),
                                         INT_EVENT_ATTR(NEWLY_ACKED, apply));
                    do {
                        if (apply) {
                            if ((ret = quicly_acks_on_ack(&conn->egress.acks, 1, ack, conn)) != 0)
                                return ret;
                            quicly_acks_release(&conn->egress.acks, &iter);
                        }
                        quicly_acks_next(&iter);
                    } while ((ack = quicly_acks_get(&iter))->packet_number == packet_number);
                }
                ++packet_number;
            } while (--block_length != 0);
        }
        if (gap_index-- == 0)
            break;
        packet_number += frame->gaps[gap_index];
    }

    /* update bytes in pipe */
    assert(conn->egress.cc.bytes_in_flight >= conn->egress.cc.this_ack.nbytes);
    conn->egress.cc.bytes_in_flight -= conn->egress.cc.this_ack.nbytes;

    /* OnPacketAcked */
    uint32_t latest_rtt = UINT32_MAX, ack_delay = 0;
    if (largest_newly_acked.packet_number == frame->largest_acknowledged) {
        int64_t t = now - largest_newly_acked.sent_at;
        if (0 <= t && t < 100000) { /* ignore RTT above 100 seconds */
            latest_rtt = (uint32_t)t;
            uint64_t ack_delay_microsecs = frame->ack_delay << conn->super.peer.transport_params.ack_delay_exponent;
            ack_delay = (uint32_t)((ack_delay_microsecs * 2 + 1000) / 2000);
        }
    }
    quicly_loss_on_ack_received(
        &conn->egress.loss, frame->largest_acknowledged, latest_rtt, ack_delay,
        0 /* this relies on the fact that we do not (yet) retransmit ACKs and therefore latest_rtt becoming UINT32_MAX */);
    /* OnPacketAckedCC */
    uint32_t cc_type = 0;
    /* TODO (jri): this function should be called for every packet newly acked. (kazuho) I do not think so;
     * quicly_loss_on_packet_acked is NOT OnPacketAcked */
    if (smallest_newly_acked != UINT64_MAX) {
        if (quicly_loss_on_packet_acked(&conn->egress.loss, smallest_newly_acked)) {
            cc_type = CC_RTO;
            conn->egress.cc.in_first_rto = 0;
        } else if (conn->egress.cc.in_first_rto) {
            cc_type = CC_RTO_ERR;
            conn->egress.cc.in_first_rto = 0;
        }
    }
    if (cc_type != 0)
        cc_cong_signal(&conn->egress.cc.ccv, cc_type, bytes_in_flight);
    int exit_recovery = frame->largest_acknowledged >= conn->egress.cc.end_of_recovery;
    cc_ack_received(&conn->egress.cc.ccv, CC_ACK, bytes_in_flight, (uint16_t)conn->egress.cc.this_ack.nsegs,
                    (uint32_t)conn->egress.cc.this_ack.nbytes,
                    conn->egress.loss.rtt.smoothed / 10 /* TODO better way of converting to cc_ticks */, exit_recovery);
    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_CC_ACK_RECEIVED, INT_EVENT_ATTR(PACKET_NUMBER, frame->largest_acknowledged),
                         INT_EVENT_ATTR(ACKED_PACKETS, conn->egress.cc.this_ack.nsegs),
                         INT_EVENT_ATTR(ACKED_BYTES, conn->egress.cc.this_ack.nbytes), INT_EVENT_ATTR(CC_TYPE, cc_type),
                         INT_EVENT_ATTR(CC_EXIT_RECOVERY, exit_recovery), INT_EVENT_ATTR(CWND, cc_get_cwnd(&conn->egress.cc.ccv)),
                         INT_EVENT_ATTR(BYTES_IN_FLIGHT, bytes_in_flight));
    if (exit_recovery)
        conn->egress.cc.end_of_recovery = UINT64_MAX;

    /* loss-detection  */
    quicly_loss_detect_loss(&conn->egress.loss, frame->largest_acknowledged, do_detect_loss);
    update_loss_alarm(conn);

    return 0;
}

static int handle_max_stream_data_frame(quicly_conn_t *conn, quicly_max_stream_data_frame_t *frame)
{
    quicly_stream_t *stream;

    if (quicly_stream_is_unidirectional(frame->stream_id) &&
        quicly_stream_is_client_initiated(frame->stream_id) == quicly_is_client(conn))
        return QUICLY_ERROR_FRAME_ENCODING;

    if ((stream = quicly_get_stream(conn, frame->stream_id)) == NULL)
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

    if (quicly_stream_is_unidirectional(frame->stream_id) &&
        quicly_stream_is_client_initiated(frame->stream_id) != quicly_is_client(conn))
        return QUICLY_ERROR_FRAME_ENCODING;

    if ((stream = quicly_get_stream(conn, frame->stream_id)) != NULL)
        quicly_maxsender_reset(&stream->_send_aux.max_stream_data_sender, 0);

    return 0;
}

static int handle_max_stream_id_frame(quicly_conn_t *conn, quicly_max_stream_id_frame_t *frame)
{
    int uni = quicly_stream_is_unidirectional(frame->max_stream_id);

    update_max_stream_id(uni ? &conn->egress.max_stream_id.uni : &conn->egress.max_stream_id.bidi, frame->max_stream_id);
    open_id_blocked_streams(conn, uni);

    return 0;
}

static int handle_path_challenge_frame(quicly_conn_t *conn, quicly_path_challenge_frame_t *frame)
{
    return schedule_path_challenge(conn, 1, frame->data);
}

static int handle_new_token_frame(quicly_conn_t *conn, quicly_new_token_frame_t *frame)
{
    /* TODO save the token along with the session ticket */
    return 0;
}

static int handle_stop_sending_frame(quicly_conn_t *conn, quicly_stop_sending_frame_t *frame)
{
    quicly_stream_t *stream;
    int ret;

    /* FIXME draft-14 section 7.15; "Receiving a STOP_SENDING frame for a send stream that is “Ready” or non-existent MUST be
     * treated as a connection error of type PROTOCOL_VIOLATION." */
    if ((ret = get_stream_or_open_if_new(conn, frame->stream_id, &stream)) != 0 || stream == NULL)
        return ret;

    if (stream->sendbuf.error_code == QUICLY_STREAM_ERROR_IS_OPEN)
        stream->sendbuf.error_code = frame->app_error_code;
    quicly_reset_stream(stream, 0 /* STOPPING */);
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
    /* set selected version */
    conn->super.version = version;
    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_QUIC_VERSION_SWITCH, INT_EVENT_ATTR(QUIC_VERSION, version));

    { /* reschedule the Initial packet for immediate resend (FIXME logic below fails if the first packet was already deemed lost) */
        quicly_acks_t *acks = &conn->egress.acks;
        quicly_acks_iter_t iter;
        quicly_acks_init_iter(acks, &iter);
        quicly_ack_t *ack = quicly_acks_get(&iter);
        int ret = quicly_acks_on_ack(acks, 0, ack, conn);
        assert(ret == 0);
        quicly_acks_release(acks, &iter);
    }

    return 0;
}

static int handle_version_negotiation_packet(quicly_conn_t *conn, quicly_decoded_packet_t *packet)
{
#define CAN_SELECT(v) ((v) != conn->super.version && (v) == QUICLY_PROTOCOL_VERSION)

    const uint8_t *src = packet->octets.base + packet->encrypted_off, *end = packet->octets.base + packet->octets.len;

    if (src == end || (end - src) % 4 != 0)
        return QUICLY_ERROR_PROTOCOL_VIOLATION;
    while (src != end) {
        uint32_t supported_version = quicly_decode32(&src);
        if (CAN_SELECT(supported_version))
            return negotiate_using_version(conn, supported_version);
    }
    return QUICLY_ERROR_VERSION_NEGOTIATION;

#undef CAN_SELECT
}

int quicly_is_destination(quicly_conn_t *conn, int is_1rtt, ptls_iovec_t cid)
{
    if (quicly_cid_is_equal(&conn->super.host.cid, cid)) {
        return 1;
    } else if (!is_1rtt && !quicly_is_client(conn) && quicly_cid_is_equal(&conn->super.host.offered_cid, cid)) {
        /* long header pacekt carrying the offered CID */
        return 1;
    }
    return 0;
}

static void handle_close(quicly_conn_t *conn, uint16_t error_code, uint64_t *frame_type, ptls_iovec_t reason_phrase)
{
    conn->super.state = QUICLY_STATE_DRAINING;
    if (conn->super.ctx->on_conn_close != NULL)
        conn->super.ctx->on_conn_close(conn, error_code, frame_type, (const char *)reason_phrase.base, reason_phrase.len);
}

static int handle_payload(quicly_conn_t *conn, size_t epoch, const uint8_t *src, size_t _len, int *is_ack_only)
{
    const uint8_t *end = src + _len;
    int ret = 0;

    *is_ack_only = 1;

    do {
        uint8_t type_flags = *src++;
        switch (type_flags) {
        case QUICLY_FRAME_TYPE_PADDING:
            break;
        case QUICLY_FRAME_TYPE_CONNECTION_CLOSE: {
            quicly_connection_close_frame_t frame;
            if ((ret = quicly_decode_connection_close_frame(&src, end, &frame)) != 0)
                goto Exit;
            handle_close(conn, frame.error_code, &frame.frame_type, frame.reason_phrase);
        } break;
        case QUICLY_FRAME_TYPE_APPLICATION_CLOSE: {
            quicly_application_close_frame_t frame;
            if ((ret = quicly_decode_application_close_frame(&src, end, &frame)) != 0)
                goto Exit;
            handle_close(conn, frame.error_code, NULL, frame.reason_phrase);
        } break;
        case QUICLY_FRAME_TYPE_ACK:
        case QUICLY_FRAME_TYPE_ACK_ECN: {
            quicly_ack_frame_t frame;
            if ((ret = quicly_decode_ack_frame(&src, end, &frame, type_flags == QUICLY_FRAME_TYPE_ACK_ECN)) != 0)
                goto Exit;
            if ((ret = handle_ack_frame(conn, epoch, &frame)) != 0)
                goto Exit;
        } break;
        case QUICLY_FRAME_TYPE_CRYPTO: {
            quicly_stream_frame_t frame;
            if ((ret = quicly_decode_crypto_frame(&src, end, &frame)) != 0)
                goto Exit;
            if ((ret = apply_handshake_flow(conn, epoch, &frame)) != 0)
                goto Exit;
            *is_ack_only = 0;
        } break;
        default:
            /* 0-rtt, 1-rtt only frames */
            if (!(epoch == 1 || epoch == 3)) {
                ret = QUICLY_ERROR_PROTOCOL_VIOLATION;
                goto Exit;
            }
            if ((type_flags & ~QUICLY_FRAME_TYPE_STREAM_BITS) == QUICLY_FRAME_TYPE_STREAM_BASE) {
                quicly_stream_frame_t frame;
                if ((ret = quicly_decode_stream_frame(type_flags, &src, end, &frame)) != 0)
                    goto Exit;
                if ((ret = handle_stream_frame(conn, &frame)) != 0)
                    goto Exit;
            } else {
                switch (type_flags) {
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
                case QUICLY_FRAME_TYPE_BLOCKED: {
                    quicly_blocked_frame_t frame;
                    if ((ret = quicly_decode_blocked_frame(&src, end, &frame)) != 0)
                        goto Exit;
                    quicly_maxsender_reset(&conn->ingress.max_data.sender, 0);
                    ret = 0;
                } break;
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
                    quicly_maxsender_t *maxsender = quicly_stream_is_unidirectional(frame.stream_id)
                                                        ? conn->ingress.max_stream_id.uni
                                                        : conn->ingress.max_stream_id.bidi;
                    if (maxsender != NULL)
                        quicly_maxsender_reset(maxsender, 0);
                    ret = 0;
                } break;
                case QUICLY_FRAME_TYPE_NEW_CONNECTION_ID: {
                    quicly_new_connection_id_frame_t frame;
                    if ((ret = quicly_decode_new_connection_id_frame(&src, end, &frame)) != 0)
                        goto Exit;
                    /* TODO */
                } break;
                case QUICLY_FRAME_TYPE_STOP_SENDING: {
                    quicly_stop_sending_frame_t frame;
                    if ((ret = quicly_decode_stop_sending_frame(&src, end, &frame)) != 0)
                        goto Exit;
                    if ((ret = handle_stop_sending_frame(conn, &frame)) != 0)
                        goto Exit;
                } break;
                case QUICLY_FRAME_TYPE_PATH_CHALLENGE: {
                    quicly_path_challenge_frame_t frame;
                    if ((ret = quicly_decode_path_challenge_frame(&src, end, &frame)) != 0)
                        goto Exit;
                    if ((ret = handle_path_challenge_frame(conn, &frame)) != 0)
                        goto Exit;
                } break;
                case QUICLY_FRAME_TYPE_NEW_TOKEN: {
                    quicly_new_token_frame_t frame;
                    if ((ret = quicly_decode_new_token_frame(&src, end, &frame)) != 0)
                        goto Exit;
                    if ((ret = handle_new_token_frame(conn, &frame)) != 0)
                        goto Exit;
                } break;
                default:
                    fprintf(stderr, "ignoring frame type:%02x\n", (unsigned)type_flags);
                    *is_ack_only = 0;
                    ret = QUICLY_ERROR_FRAME_ENCODING;
                    goto Exit;
                }
            }
            *is_ack_only = 0;
            break;
        }
    } while (src != end);

Exit:
    return ret;
}

int quicly_receive(quicly_conn_t *conn, quicly_decoded_packet_t *packet)
{
    struct st_quicly_pn_space_t **space;
    size_t epoch;
    struct st_quicly_cipher_context_t *cipher;
    ptls_iovec_t payload;
    uint64_t pn;
    int is_ack_only, ret;

    update_now(conn->super.ctx);

    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_RECEIVE, VEC_EVENT_ATTR(DCID, packet->cid.dest),
                         (packet->octets.base[0] & 0x80) != 0 ? VEC_EVENT_ATTR(SCID, packet->cid.src)
                                                              : (quicly_event_attribute_t){QUICLY_EVENT_ATTRIBUTE_NULL},
                         INT_EVENT_ATTR(LENGTH, packet->octets.len), INT_EVENT_ATTR(FIRST_OCTET, packet->octets.base[0]));

    if (conn->super.state == QUICLY_STATE_FIRSTFLIGHT) {
        assert(quicly_is_client(conn));
        if (QUICLY_PACKET_TYPE_IS_1RTT(packet->octets.base[0])) {
            ret = QUICLY_ERROR_PACKET_IGNORED;
            goto Exit;
        }
        /* FIXME check peer address */
        memcpy(conn->super.peer.cid.cid, packet->cid.src.base, packet->cid.src.len);
        conn->super.peer.cid.len = packet->cid.src.len;
    }
    if (conn->super.state == QUICLY_STATE_DRAINING) {
        ret = 0;
        goto Exit;
    }

    if (QUICLY_PACKET_TYPE_IS_1RTT(packet->octets.base[0])) {
        int key_phase = QUICLY_PACKET_TYPE_1RTT_TO_KEY_PHASE(packet->octets.base[0]);
        if (conn->application == NULL || (cipher = &conn->application->cipher.ingress[key_phase])->aead == NULL) {
            ret = QUICLY_ERROR_PACKET_IGNORED;
            goto Exit;
        }
        space = (void *)&conn->application;
        epoch = 3;
    } else {
        if (conn->super.state == QUICLY_STATE_FIRSTFLIGHT) {
            if (packet->version == 0)
                return handle_version_negotiation_packet(conn, packet);
        }
        switch (packet->octets.base[0]) {
        case QUICLY_PACKET_TYPE_RETRY:
            assert(!"FIXME");
            return 0;
        case QUICLY_PACKET_TYPE_INITIAL:
            if (conn->initial == NULL || (cipher = &conn->initial->cipher.ingress)->aead == NULL) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            space = (void *)&conn->initial;
            epoch = 0;
            break;
        case QUICLY_PACKET_TYPE_HANDSHAKE:
            if (conn->handshake == NULL || (cipher = &conn->handshake->cipher.ingress)->aead == NULL) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            space = (void *)&conn->handshake;
            epoch = 2;
            break;
        case QUICLY_PACKET_TYPE_0RTT_PROTECTED:
            if (quicly_is_client(conn)) {
                ret = QUICLY_ERROR_PROTOCOL_VIOLATION;
                goto Exit;
            }
            if (conn->application == NULL || (cipher = &conn->application->cipher.ingress[0])->aead == NULL) {
                ret = QUICLY_ERROR_PACKET_IGNORED;
                goto Exit;
            }
            space = (void *)&conn->application;
            epoch = 1;
            break;
        default:
            ret = QUICLY_ERROR_PROTOCOL_VIOLATION;
            goto Exit;
        }
    }

    if ((payload = decrypt_packet(cipher, &(*space)->next_expected_packet_number, packet, &pn)).base == NULL) {
        ret = QUICLY_ERROR_PACKET_IGNORED;
        goto Exit;
    }

    if (payload.len == 0) {
        ret = QUICLY_ERROR_PROTOCOL_VIOLATION;
        goto Exit;
    }

    LOG_CONNECTION_EVENT(conn, QUICLY_EVENT_TYPE_CRYPTO_DECRYPT, INT_EVENT_ATTR(PACKET_NUMBER, pn),
                         INT_EVENT_ATTR(LENGTH, payload.len));

    if (conn->super.state == QUICLY_STATE_FIRSTFLIGHT)
        conn->super.state = QUICLY_STATE_CONNECTED;

    if ((ret = handle_payload(conn, epoch, payload.base, payload.len, &is_ack_only)) != 0)
        goto Exit;
    ++conn->super.num_packets.received;

    if (*space != NULL) {
        if ((ret = record_receipt(*space, pn, is_ack_only, epoch)) != 0)
            goto Exit;
    }

Exit:
    if (ret == 0)
        assert_consistency(conn, 0);
    return ret;
}

int quicly_open_stream(quicly_conn_t *conn, quicly_stream_t **stream, int uni)
{
    struct st_quicly_conn_streamgroup_state_t *group;
    quicly_stream_id_t *max_stream_id;
    uint32_t max_stream_data_local, max_stream_data_remote;

    /* determine the states */
    if (uni) {
        group = &conn->super.host.uni;
        max_stream_id = &conn->egress.max_stream_id.uni.id;
        max_stream_data_local = 0;
        max_stream_data_remote = conn->super.peer.transport_params.initial_max_stream_data.uni;
    } else {
        group = &conn->super.host.bidi;
        max_stream_id = &conn->egress.max_stream_id.bidi.id;
        max_stream_data_local = conn->super.ctx->initial_max_stream_data.bidi_local;
        max_stream_data_remote = conn->super.peer.transport_params.initial_max_stream_data.bidi_remote;
    }

    /* open */
    if ((*stream = open_stream(conn, group->next_stream_id, max_stream_data_local, max_stream_data_remote)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    ++group->num_streams;
    group->next_stream_id += 4;

    /* adjust blocked */
    if ((*stream)->stream_id > *max_stream_id) {
        (*stream)->stream_id_blocked = 1;
        quicly_linklist_insert((uni ? &conn->pending_link.stream_id_blocked.uni : &conn->pending_link.stream_id_blocked.bidi)->prev,
                               &(*stream)->_send_aux.pending_link.control);
    }

    return 0;
}

void quicly_reset_stream(quicly_stream_t *stream, uint16_t error_code)
{
    assert(!(quicly_stream_is_unidirectional(stream->stream_id) &&
             quicly_stream_is_client_initiated(stream->stream_id) != quicly_is_client(stream->conn)));

    /* do nothing if FIN has been sent */
    if (stream->_send_aux.max_sent > stream->sendbuf.eos)
        return;

    /* close the sender and mark the eos as the only byte that's not confirmed */
    assert(!quicly_sendbuf_transfer_complete(&stream->sendbuf));
    quicly_sendbuf_shutdown(&stream->sendbuf);
    if (stream->sendbuf.eos != 0) {
        quicly_sendbuf_ackargs_t ackargs = {0, stream->sendbuf.eos};
        quicly_sendbuf_acked(&stream->sendbuf, &ackargs, 0);
    }

    /* setup RST_STREAM */
    stream->_send_aux.rst.sender_state = QUICLY_SENDER_STATE_SEND;
    stream->_send_aux.rst.error_code = error_code;

    /* schedule for delivery */
    sched_stream_control(stream);
}

void quicly_request_stop(quicly_stream_t *stream, uint16_t error_code)
{
    assert(!(quicly_stream_is_unidirectional(stream->stream_id) &&
             quicly_stream_is_client_initiated(stream->stream_id) == quicly_is_client(stream->conn)));

    /* send STOP_SENDING if the incoming side of the stream is still open */
    if (stream->recvbuf.eos == UINT64_MAX && stream->_send_aux.stop_sending.sender_state == QUICLY_SENDER_STATE_NONE) {
        stream->recvbuf._error_code = QUICLY_STREAM_ERROR_STOPPED;
        stream->_send_aux.stop_sending.sender_state = QUICLY_SENDER_STATE_SEND;
        stream->_send_aux.stop_sending.error_code = error_code;
        sched_stream_control(stream);
    }
}

void quicly_close_stream(quicly_stream_t *stream)
{
    assert(quicly_stream_is_closable(stream));
    destroy_stream(stream);
}

quicly_datagram_t *quicly_default_alloc_packet(quicly_context_t *ctx, socklen_t salen, size_t payloadsize)
{
    quicly_datagram_t *packet;

    if ((packet = malloc(offsetof(quicly_datagram_t, sa) + salen + payloadsize)) == NULL)
        return NULL;
    packet->salen = salen;
    packet->data.base = (uint8_t *)packet + offsetof(quicly_datagram_t, sa) + salen;

    return packet;
}

void quicly_default_free_packet(quicly_context_t *ctx, quicly_datagram_t *packet)
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

static void tohex(char *dst, uint8_t v)
{
    dst[0] = "0123456789abcdef"[v >> 4];
    dst[1] = "0123456789abcdef"[v & 0xf];
}

FILE *quicly_default_event_log_fp;

void quicly_default_event_log(quicly_context_t *ctx, quicly_event_type_t type, const quicly_event_attribute_t *attributes,
                              size_t num_attributes)
{
    ptls_buffer_t buf;
    uint8_t smallbuf[256];
    size_t i, j;

    ptls_buffer_init(&buf, smallbuf, sizeof(smallbuf));

#define EMIT(s)                                                                                                                    \
    do {                                                                                                                           \
        const char *_s = (s);                                                                                                      \
        size_t _l = strlen(_s);                                                                                                    \
        if (ptls_buffer_reserve(&buf, _l) != 0)                                                                                    \
            goto Exit;                                                                                                             \
        memcpy(buf.base + buf.off, _s, _l);                                                                                        \
        buf.off += _l;                                                                                                             \
    } while (0)

    EMIT("{\"type\":\"");
    EMIT(quicly_event_type_names[type]);
    EMIT("\"");
    for (i = 0; i != num_attributes; ++i) {
        const quicly_event_attribute_t *attr = attributes + i;
        if (attr->type == QUICLY_EVENT_ATTRIBUTE_NULL)
            continue;
        EMIT(", \"");
        EMIT(quicly_event_attribute_names[attr->type]);
        if (QUICLY_EVENT_ATTRIBUTE_TYPE_INT_MIN <= attr->type && attr->type < QUICLY_EVENT_ATTRIBUTE_TYPE_INT_MAX) {
            char int64buf[sizeof("-9223372036854775808")];
            sprintf(int64buf, "\":%" PRId64, attr->value.i);
            EMIT(int64buf);
        } else if (QUICLY_EVENT_ATTRIBUTE_TYPE_VEC_MIN <= attr->type && attr->type < QUICLY_EVENT_ATTRIBUTE_TYPE_VEC_MAX) {
            EMIT("\":\"");
            if (ptls_buffer_reserve(&buf, attr->value.v.len * 2) != 0)
                goto Exit;
            for (j = 0; j != attr->value.v.len; ++j) {
                tohex((void *)(buf.base + buf.off), attr->value.v.base[j]);
                buf.off += 2;
            }
            EMIT("\"");
        } else {
            assert(!"unexpected type");
        }
    }
    EMIT("}\n");

#undef EMIT

    fwrite(buf.base, 1, buf.off, quicly_default_event_log_fp != NULL ? quicly_default_event_log_fp : stderr);

Exit:
    ptls_buffer_dispose(&buf);
}

char *quicly_hexdump(const uint8_t *bytes, size_t len, size_t indent)
{
    size_t i, line, row, bufsize = indent == SIZE_MAX ? len * 2 + 1 : (indent + 5 + 3 * 16 + 2 + 16 + 1) * ((len + 15) / 16) + 1;
    char *buf, *p;

    if ((buf = malloc(bufsize)) == NULL)
        return NULL;
    p = buf;
    if (indent == SIZE_MAX) {
        for (i = 0; i != len; ++i) {
            tohex(p, bytes[i]);
            p += 2;
        }
    } else {
        for (line = 0; line * 16 < len; ++line) {
            for (i = 0; i < indent; ++i)
                *p++ = ' ';
            tohex(p, (line >> 4) & 0xff);
            p += 2;
            tohex(p, (line << 4) & 0xff);
            p += 2;
            *p++ = ' ';
            for (row = 0; row < 16; ++row) {
                *p++ = row == 8 ? '-' : ' ';
                if (line * 16 + row < len) {
                    tohex(p, bytes[line * 16 + row]);
                    p += 2;
                } else {
                    *p++ = ' ';
                    *p++ = ' ';
                }
            }
            *p++ = ' ';
            *p++ = ' ';
            for (row = 0; row < 16; ++row) {
                if (line * 16 + row < len) {
                    int ch = bytes[line * 16 + row];
                    *p++ = 0x20 <= ch && ch < 0x7f ? ch : '.';
                } else {
                    *p++ = ' ';
                }
            }
            *p++ = '\n';
        }
    }
    *p++ = '\0';

    assert(p - buf <= bufsize);

    return buf;
}

void quicly_amend_ptls_context(ptls_context_t *ptls)
{
    static ptls_update_traffic_key_t update_traffic_key = {update_traffic_key_cb};

    ptls->omit_end_of_early_data = 1;
    ptls->max_early_data_size = UINT32_MAX;
    ptls->hkdf_label_prefix = HKDF_BASE_LABEL;
    ptls->update_traffic_key = &update_traffic_key;
}

/**
 * an array of event names corresponding to quicly_event_type_t
 */
const char *quicly_event_type_names[] = {"connect",
                                         "accept",
                                         "send",
                                         "receive",
                                         "packet-prepare",
                                         "packet-commit",
                                         "packet-acked",
                                         "packet-lost",
                                         "crypto-decrypt",
                                         "crypto-handshake",
                                         "crypto-update-secret",
                                         "cc-tlp",
                                         "cc-rto",
                                         "cc-ack-received",
                                         "cc-congestion",
                                         "stream-send",
                                         "stream-receive",
                                         "stream-acked",
                                         "stream-lost",
                                         "quic-version-switch"};

const char *quicly_event_attribute_names[] = {NULL,
                                              "time",
                                              "epoch",
                                              "pn",
                                              "conn",
                                              "tls-error",
                                              "off",
                                              "len",
                                              "stream-id",
                                              "fin",
                                              "is-enc",
                                              "quic-version",
                                              "ack-only",
                                              "max-lost-pn",
                                              "end-of-recovery",
                                              "bytes-in-flight",
                                              "cwnd",
                                              "newly-acked",
                                              "first-octet",
                                              "cc-type",
                                              "cc-end-of-recovery",
                                              "cc-exit-recovery",
                                              "acked-packets",
                                              "acked-bytes",
                                              "dcid",
                                              "scid"};
