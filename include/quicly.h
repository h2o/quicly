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
#ifndef quicly_h
#define quicly_h

#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "picotls.h"
#include "quicly/constants.h"
#include "quicly/linklist.h"
#include "quicly/loss.h"
#include "quicly/recvbuf.h"
#include "quicly/sendbuf.h"
#include "quicly/maxsender.h"

typedef struct st_quicly_raw_packet_t {
    ptls_iovec_t data;
    socklen_t salen;
    struct sockaddr sa;
} quicly_raw_packet_t;

typedef struct st_quicly_context_t quicly_context_t;
typedef struct st_quicly_conn_t quicly_conn_t;
typedef struct st_quicly_stream_t quicly_stream_t;

typedef quicly_raw_packet_t *(*quicly_alloc_packet_cb)(quicly_context_t *ctx, socklen_t salen, size_t payloadsize);
typedef void (*quicly_free_packet_cb)(quicly_context_t *ctx, quicly_raw_packet_t *packet);
typedef quicly_stream_t *(*quicly_alloc_stream_cb)(quicly_context_t *ctx);
typedef void (*quicly_free_stream_cb)(quicly_stream_t *stream);
typedef int (*quicly_stream_open_cb)(quicly_stream_t *stream);
typedef int (*quicly_stream_update_cb)(quicly_stream_t *stream);
typedef int64_t (*quicly_now_cb)(quicly_context_t *ctx);
typedef void (*quicly_debug_log_cb)(quicly_context_t *ctx, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

typedef struct st_quicly_transport_parameters_t {
    /**
     * in octets
     */
    uint32_t initial_max_stream_data;
    /**
     * in KB
     */
    uint32_t initial_max_data_kb;
    /**
     *
     */
    uint32_t initial_max_stream_id;
    /**
     * in seconds
     */
    uint16_t idle_timeout;
    /**
     *
     */
    unsigned truncate_connection_id : 1;
} quicly_transport_parameters_t;

struct st_quicly_context_t {
    /**
     * tls context to use
     */
    ptls_context_t *tls;
    /**
     * MTU
     */
    uint16_t max_packet_size;
    /**
     * loss detection parameters
     */
    quicly_loss_conf_t loss;
    /**
     * transport parameters
     */
    quicly_transport_parameters_t transport_params;
    /**
     * callback for allocating memory for raw packet
     */
    quicly_alloc_packet_cb alloc_packet;
    /**
     * callback for freeing memory allocated by alloc_packet
     */
    quicly_free_packet_cb free_packet;
    /**
     * callback called to allocate memory for a new stream
     */
    quicly_alloc_stream_cb alloc_stream;
    /**
     * callback called to free memory allocated for a stream
     */
    quicly_free_stream_cb free_stream;
    /**
     * callback called when a new stream is opened by peer
     */
    quicly_stream_open_cb on_stream_open;
    /**
     * returns current time in milliseconds
     */
    quicly_now_cb now;
    /**
     * optional callback for debug logging
     */
    quicly_debug_log_cb debug_log;
};

typedef enum { QUICLY_STATE_BEFORE_SH = 0, QUICLY_STATE_BEFORE_SF, QUICLY_STATE_1RTT_ENCRYPTED } quicly_state_t;

struct _st_quicly_conn_public_t {
    quicly_context_t *ctx;
    uint64_t connection_id;
    quicly_state_t state;
    struct {
        uint32_t num_streams;
        uint32_t next_stream_id;
    } host;
    struct {
        uint32_t num_streams;
        uint32_t next_stream_id;
        struct sockaddr *sa;
        socklen_t salen;
        quicly_transport_parameters_t transport_params;
    } peer;
};

typedef enum {
    QUICLY_SENDER_STATE_NONE,
    QUICLY_SENDER_STATE_SEND,
    QUICLY_SENDER_STATE_UNACKED,
    QUICLY_SENDER_STATE_ACKED,
} quicly_sender_state_t;

struct st_quicly_stream_t {
    /**
     *
     */
    quicly_conn_t *conn;
    /**
     * stream id
     */
    uint32_t stream_id;
    /**
     * send buffer
     */
    quicly_sendbuf_t sendbuf;
    /**
     * receive buffer
     */
    quicly_recvbuf_t recvbuf;
    /**
     * the receive callback
     */
    quicly_stream_update_cb on_update;
    /**
     *
     */
    struct {
        /**
         * send window
         */
        uint64_t max_stream_data;
        /**
         * 1 + maximum offset of data that has been sent at least once (counting eos)
         */
        uint64_t max_sent;
        /**
         *
         */
        struct {
            quicly_sender_state_t sender_state;
            uint32_t reason;
        } stop_sending;
        /**
         * rst_stream
         */
        struct {
            quicly_sender_state_t sender_state;
            uint32_t reason;
        } rst;
        /**
         * sends receive window updates to peer
         */
        quicly_maxsender_t max_stream_data_sender;
        /**
         * linklist of pending streams
         */
        struct {
            quicly_linklist_t control;
            quicly_linklist_t stream;
        } pending_link;
    } _send_aux;
    /**
     *
     */
    struct {
        /**
         * size of the receive window
         */
        uint32_t window;
        /**
         *
         */
        uint32_t rst_reason;
    } _recv_aux;
};

typedef struct st_quicly_decode_packet_t {
    uint8_t type;
    uint8_t is_long_header : 1;
    uint8_t has_connection_id : 1;
    uint64_t connection_id;
    struct {
        uint32_t bits;
        uint32_t mask;
    } packet_number;
    uint32_t version;
    ptls_iovec_t header;
    ptls_iovec_t payload;
} quicly_decoded_packet_t;

#define QUICLY_RESET_STREAM_EGRESS 1
#define QUICLY_RESET_STREAM_INGRESS 2
#define QUICLY_RESET_STREAM_BOTH_DIRECTIONS (QUICLY_RESET_STREAM_INGRESS | QUICLY_RESET_STREAM_EGRESS)

/**
 *
 */
int quicly_decode_packet(quicly_decoded_packet_t *packet, const uint8_t *src, size_t len);
/**
 *
 */
uint64_t quicly_determine_packet_number(quicly_decoded_packet_t *packet, uint64_t next_expected);
/**
 *
 */
static quicly_context_t *quicly_get_context(quicly_conn_t *conn);
/**
 *
 */
static uint64_t quicly_get_connection_id(quicly_conn_t *conn);
/**
 *
 */
static quicly_state_t quicly_get_state(quicly_conn_t *conn);
/**
 *
 */
static uint32_t quicly_num_streams(quicly_conn_t *conn);
/**
 *
 */
static int quicly_is_client(quicly_conn_t *conn);
/**
 *
 */
static uint32_t quicly_get_next_stream_id(quicly_conn_t *conn);
/**
 *
 */
static void quicly_get_peername(quicly_conn_t *conn, struct sockaddr **sa, socklen_t *salen);
/**
 *
 */
void quicly_get_max_data(quicly_conn_t *conn, __uint128_t *send_permitted, __uint128_t *sent, __uint128_t *consumed);
/**
 *
 */
void quicly_free(quicly_conn_t *conn);
/**
 *
 */
int64_t quicly_get_first_timeout(quicly_conn_t *conn);
/**
 *
 */
int quicly_send(quicly_conn_t *conn, quicly_raw_packet_t **packets, size_t *num_packets);
/**
 *
 */
int quicly_receive(quicly_conn_t *conn, quicly_decoded_packet_t *packet);
/**
 *
 */
int quicly_connect(quicly_conn_t **conn, quicly_context_t *ctx, const char *server_name, struct sockaddr *sa, socklen_t salen,
                   ptls_handshake_properties_t *handshake_properties);
/**
 *
 */
int quicly_accept(quicly_conn_t **conn, quicly_context_t *ctx, struct sockaddr *sa, socklen_t salen,
                  ptls_handshake_properties_t *handshake_properties, quicly_decoded_packet_t *packet);
/**
 *
 */
quicly_stream_t *quicly_get_stream(quicly_conn_t *conn, uint32_t stream_id);
/**
 *
 */
int quicly_open_stream(quicly_conn_t *conn, quicly_stream_t **stream);
/**
 *
 */
static int quicly_stream_is_closable(quicly_stream_t *stream);
/**
 *
 */
void quicly_reset_stream(quicly_stream_t *stream, unsigned direction, uint32_t reason);
/**
 *
 */
void quicly_close_stream(quicly_stream_t *stream);
/**
 *
 */
quicly_raw_packet_t *quicly_default_alloc_packet(quicly_context_t *ctx, socklen_t salen, size_t payloadsize);
/**
 *
 */
void quicly_default_free_packet(quicly_context_t *ctx, quicly_raw_packet_t *packet);
/**
 *
 */
quicly_stream_t *quicly_default_alloc_stream(quicly_context_t *ctx);
/**
 *
 */
void quicly_default_free_stream(quicly_stream_t *stream);
/**
 *
 */
int64_t quicly_default_now(quicly_context_t *ctx);
/**
 *
 */
void quicly_default_debug_log(quicly_context_t *ctx, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* inline definitions */

inline quicly_state_t quicly_get_state(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (void *)conn;
    return c->state;
}

inline uint32_t quicly_num_streams(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (void *)conn;
    return 1 + c->host.num_streams + c->peer.num_streams;
}

inline quicly_context_t *quicly_get_context(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (void *)conn;
    return c->ctx;
}

inline uint64_t quicly_get_connection_id(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (void *)conn;
    return c->connection_id;
}

inline int quicly_is_client(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (void *)conn;
    return c->host.next_stream_id % 2 != 0;
}

inline uint32_t quicly_get_next_stream_id(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (void *)conn;
    return c->host.next_stream_id;
}

inline void quicly_get_peername(quicly_conn_t *conn, struct sockaddr **sa, socklen_t *salen)
{
    struct _st_quicly_conn_public_t *c = (void *)conn;
    *sa = c->peer.sa;
    *salen = c->peer.salen;
}

inline int quicly_stream_is_closable(quicly_stream_t *stream)
{
    if (!quicly_sendbuf_transfer_complete(&stream->sendbuf))
        return 0;
    if (!quicly_recvbuf_transfer_complete(&stream->recvbuf))
        return 0;
    return 1;
}

#endif
