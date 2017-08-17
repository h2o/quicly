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
#include "quicly/error.h"
#include "quicly/recvbuf.h"
#include "quicly/sendbuf.h"

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
typedef int (*quicly_stream_open_cb)(quicly_context_t *ctx, quicly_conn_t *conn, quicly_stream_t *stream);

typedef struct st_quicly_transport_parameters_t {
    /**
     * in octets
     */
    uint32_t initial_max_stream_data;
    /**
     * in KB
     */
    uint32_t initial_max_data;
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
     * callback called when a new stream is opened by peer
     */
    quicly_stream_open_cb on_stream_open;
};

typedef enum { QUICLY_STATE_BEFORE_SH = 0, QUICLY_STATE_BEFORE_SF, QUICLY_STATE_1RTT_ENCRYPTED } quicly_state_t;

struct _st_quicly_conn_public_t {
    quicly_context_t *ctx;
    uint64_t connection_id;
    quicly_state_t state;
    struct {
        uint32_t next_stream_id;
    } host;
    struct {
        uint32_t next_stream_id;
        struct sockaddr *sa;
        socklen_t salen;
        quicly_transport_parameters_t transport_params;
    } peer;
};

struct st_quicly_stream_t {
    uint32_t stream_id;
    quicly_sendbuf_t sendbuf;
    quicly_recvbuf_t recvbuf;
    void *data;
    int (*on_receive)(quicly_conn_t *conn, quicly_stream_t *stream);
};

typedef struct st_quicly_decode_packet_t {
    uint8_t type;
    uint8_t is_long_header : 1;
    uint8_t has_connection_id : 1;
    uint64_t connection_id;
    uint32_t packet_number;
    uint32_t version;
    ptls_iovec_t header;
    ptls_iovec_t payload;
} quicly_decoded_packet_t;

int quicly_decode_packet(quicly_decoded_packet_t *packet, const uint8_t *src, size_t len);

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
void quicly_free(quicly_conn_t *conn);
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
int quicly_reset_stream(quicly_stream_t *stream);
/**
 *
 */
quicly_raw_packet_t *quicly_default_alloc_packet(quicly_context_t *ctx, socklen_t salen, size_t payloadsize);
/**
 *
 */
void quicly_default_free_packet(quicly_context_t *ctx, quicly_raw_packet_t *packet);

/* inline definitions */

inline quicly_state_t quicly_get_state(quicly_conn_t *conn)
{
    struct _st_quicly_conn_public_t *c = (void *)conn;
    return c->state;
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

#endif
