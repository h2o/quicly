/*
 * Copyright (c) 2026 Fastly, Zac Shenker
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
#include <string.h>
#include "quicly/streambuf.h"
#include "test.h"

/* connection-level tests of the RESET_STREAM_AT frame; see draft-ietf-quic-reliable-stream-reset */

#define APP_ERROR(n) QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(n)
#define TEST_DATA_LEN 10

static const char test_data[] = "0123456789";

static quicly_conn_t *client, *server;
/**
 * number of times `on_receive_reset` has been called on the stream returned by `open_stream`; section 5.2 allows multiple resets to
 * be received for one stream, but the application is to be notified only once
 */
static size_t num_on_receive_reset;
static quicly_stream_callbacks_t counting_callbacks;

static void count_on_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
    ++num_on_receive_reset;
    stream_callbacks.on_receive_reset(stream, err);
}

static void connect_pair(void)
{
    quicly_address_t dest, src;
    struct iovec datagram;
    uint8_t datagrambuf[quic_ctx.transport_params.max_udp_payload_size];
    size_t num_datagrams = 1;
    quicly_decoded_packet_t decoded;
    quicly_error_t ret;

    ret = quicly_connect(&client, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL,
                         NULL, NULL);
    ok(ret == 0);
    ret = quicly_send(client, &dest, &src, &datagram, &num_datagrams, datagrambuf, sizeof(datagrambuf));
    ok(ret == 0);
    ok(num_datagrams == 1);
    ok(decode_packets(&decoded, &datagram, 1) == 1);
    ret = quicly_accept(&server, &quic_ctx, NULL, &fake_address.sa, &decoded, NULL, new_master_id(), NULL, NULL);
    ok(ret == 0);

    /* run the handshake to completion, so that the datagrams being held back by the tests below carry 1-RTT packets only */
    transmit(server, client);
    transmit(client, server);
    transmit(server, client);
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(client, server);
    ok(quicly_connection_is_ready(client));
    ok(quicly_connection_is_ready(server));

    num_on_receive_reset = 0;
}

static void free_pair(void)
{
    quicly_free(client);
    quicly_free(server);
    client = NULL;
    server = NULL;
}

/**
 * Opens a stream on the client, writes `delivered` bytes of TEST_DATA and lets them reach the server, then writes the remaining
 * TEST_DATA_LEN - `delivered` bytes and drops the datagram carrying them. Upon return, `size_inflight` is TEST_DATA_LEN while the
 * server has received the first `delivered` bytes only.
 */
static void open_stream(int unidirectional, size_t delivered, quicly_stream_t **client_stream, quicly_stream_t **server_stream)
{
    quicly_address_t dest, src;
    struct iovec datagram;
    uint8_t datagrambuf[quic_ctx.transport_params.max_udp_payload_size];
    size_t num_datagrams = 1;
    quicly_error_t ret;

    ret = quicly_open_stream(client, client_stream, unidirectional);
    ok(ret == 0);
    ok(!(*client_stream)->streams_blocked);

    if (delivered != 0)
        quicly_streambuf_egress_write(*client_stream, test_data, delivered);
    transmit(client, server);

    /* when nothing has been delivered, the server learns about the stream from the reset frame alone */
    *server_stream = quicly_get_stream(server, (*client_stream)->stream_id);
    ok((*server_stream != NULL) == (delivered != 0));
    if (*server_stream != NULL)
        (*server_stream)->callbacks = &counting_callbacks;

    if (delivered != TEST_DATA_LEN) {
        quicly_streambuf_egress_write(*client_stream, test_data + delivered, TEST_DATA_LEN - delivered);
        ret = quicly_send(client, &dest, &src, &datagram, &num_datagrams, datagrambuf, sizeof(datagrambuf));
        ok(ret == 0);
        ok(num_datagrams == 1); /* dropped; the bytes above `delivered` never reach the server */
    }
    ok((*client_stream)->sendstate.size_inflight == TEST_DATA_LEN);
}

/**
 * Emits one datagram from `src` into `buf` without delivering it.
 */
static void hold_datagram(quicly_conn_t *src, struct iovec *datagram, uint8_t *buf, size_t bufsize)
{
    quicly_address_t dest, srcaddr;
    size_t num_datagrams = 1;
    quicly_error_t ret;

    ret = quicly_send(src, &dest, &srcaddr, datagram, &num_datagrams, buf, bufsize);
    ok(ret == 0);
    ok(num_datagrams == 1);
}

/**
 * Delivers one datagram.
 */
static void deliver_datagram(quicly_conn_t *dst, struct iovec *datagram)
{
    quicly_decoded_packet_t decoded[4];
    size_t num_decoded = decode_packets(decoded, datagram, 1), i;
    quicly_error_t ret;

    for (i = 0; i != num_decoded; ++i) {
        ret = quicly_receive(dst, NULL, &fake_address.sa, decoded + i);
        ok(ret == 0 || ret == QUICLY_ERROR_PACKET_IGNORED);
    }
}

/**
 * Returns the error that `conn` has closed itself with, zero indicating that it remains connected; the offending frame type is
 * checked as well, unless `expected_frame_type` is UINT64_MAX. Note that `quicly_receive` turns a protocol violation into a local
 * connection close, reporting no error to its caller.
 */
static quicly_error_t local_close_error(quicly_conn_t *conn, uint64_t expected_frame_type)
{
    uint64_t frame_type;
    int is_remote;
    quicly_error_t err;

    if (quicly_get_state(conn) < QUICLY_STATE_CLOSING)
        return 0;

    err = quicly_get_close_reason(conn, &frame_type, NULL, &is_remote);
    ok(!is_remote);
    if (expected_frame_type != UINT64_MAX)
        ok(frame_type == expected_frame_type);
    return err;
}

static uint64_t num_reset_stream_at_sent(quicly_conn_t *conn)
{
    quicly_stats_t stats;
    quicly_get_stats(conn, &stats);
    return stats.num_frames_sent.reset_stream_at;
}

static uint64_t num_reset_stream_at_received(quicly_conn_t *conn)
{
    quicly_stats_t stats;
    quicly_get_stats(conn, &stats);
    return stats.num_frames_received.reset_stream_at;
}

/**
 * Section 5: a Reliable Size of zero is logically equivalent to RESET_STREAM, and quicly sends that frame rather than a
 * RESET_STREAM_AT carrying zero.
 */
static void test_zero_is_reset_stream(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *server_streambuf;
    quicly_stats_t stats;

    connect_pair();
    open_stream(0, TEST_DATA_LEN, &client_stream, &server_stream);
    server_streambuf = server_stream->data;

    quicly_reset_stream_at(client_stream, APP_ERROR(11), 0);
    ok(client_stream->_send_aux.reset_stream.reliable_size == 0);
    transmit(client, server);

    quicly_get_stats(client, &stats);
    ok(stats.num_frames_sent.reset_stream == 1);
    ok(stats.num_frames_sent.reset_stream_at == 0);
    quicly_get_stats(server, &stats);
    ok(stats.num_frames_received.reset_stream == 1);
    ok(stats.num_frames_received.reset_stream_at == 0);

    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_stream->recvstate.reliable_size == 0);
    ok(num_on_receive_reset == 1);
    ok(server_streambuf->error_received.reset_stream == APP_ERROR(11));

    free_pair();
}

/**
 * The receiving application is handed exactly the bytes below the Reliable Size; the bytes above it are neither retransmitted by
 * the sender nor waited for by the receiver.
 */
static void test_prefix_delivery(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *server_streambuf;
    uint64_t max_data_sent_at_start, max_data_consumed_at_start, tmp;

    connect_pair();
    quicly_get_max_data(client, NULL, &max_data_sent_at_start, NULL, NULL);
    quicly_get_max_data(server, NULL, NULL, &max_data_consumed_at_start, NULL);

    open_stream(0, 5, &client_stream, &server_stream);
    server_streambuf = server_stream->data;
    ok(buffer_is(&server_streambuf->super.ingress, "01234"));

    quicly_reset_stream_at(client_stream, APP_ERROR(1), 5);
    ok(client_stream->_send_aux.reset_stream.reliable_size == 5);
    ok(client_stream->sendstate.final_size == TEST_DATA_LEN);
    transmit(client, server);

    ok(num_reset_stream_at_sent(client) == 1);
    ok(num_reset_stream_at_received(server) == 1);
    ok(num_on_receive_reset == 1);
    ok(server_streambuf->error_received.reset_stream == APP_ERROR(1));

    /* the prefix has been received in full, hence the transfer is complete even though the Final Size has not been reached */
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_stream->recvstate.reliable_size == 5);
    ok(server_stream->recvstate.eos == TEST_DATA_LEN);
    ok(quicly_recvstate_bytes_available(&server_stream->recvstate) == 5);
    ok(buffer_is(&server_streambuf->super.ingress, "01234"));
    ok(!server_streambuf->is_detached); /* the send side of the bidirectional stream is still open */

    /* the bytes above the Reliable Size are never retransmitted, no matter how long we wait */
    for (size_t i = 0; i < 4; ++i) {
        quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
        transmit(server, client);
        transmit(client, server);
    }
    ok(buffer_is(&server_streambuf->super.ingress, "01234"));

    /* Each offset below the Final Size is credited exactly once: 5 bytes by the STREAM frame, 5 more by the reset. */
    quicly_get_max_data(client, NULL, &tmp, NULL, NULL);
    ok(tmp == max_data_sent_at_start + TEST_DATA_LEN);
    quicly_get_max_data(server, NULL, NULL, &tmp, NULL);
    ok(tmp == max_data_consumed_at_start + TEST_DATA_LEN);
    ok(max_data_is_equal(client, server));

    free_pair();
}

/**
 * Section 5.2: the Reliable Size can be reduced, and the receiver then provides the smaller prefix only. Covers both the case where
 * the smaller prefix is still incomplete and the case where it has already been received in full, the latter completing the
 * transfer at once.
 */
static void test_lower_reliable_size(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *server_streambuf;

    connect_pair();
    open_stream(0, 3, &client_stream, &server_stream);
    server_streambuf = server_stream->data;

    quicly_reset_stream_at(client_stream, APP_ERROR(1), 8);
    transmit(client, server);
    ok(num_reset_stream_at_received(server) == 1);
    ok(!quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_stream->recvstate.reliable_size == 8);
    ok(quicly_recvstate_bytes_available(&server_stream->recvstate) == 3);
    ok(num_on_receive_reset == 1);

    /* lower to an offset that has not been received in full; the stream keeps receiving */
    quicly_reset_stream_at(client_stream, APP_ERROR(1), 5);
    ok(client_stream->_send_aux.reset_stream.reliable_size == 5);
    transmit(client, server);
    ok(num_reset_stream_at_received(server) == 2);
    ok(!quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_stream->recvstate.reliable_size == 5);
    ok(num_on_receive_reset == 1); /* the application is notified of the first reset only */

    /* lower to an offset that has been received in full; the transfer completes immediately */
    quicly_reset_stream_at(client_stream, APP_ERROR(1), 3);
    transmit(client, server);
    ok(num_reset_stream_at_sent(client) == 3);
    ok(num_reset_stream_at_received(server) == 3);
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_stream->recvstate.reliable_size == 3);
    ok(quicly_recvstate_bytes_available(&server_stream->recvstate) == 3);
    ok(buffer_is(&server_streambuf->super.ingress, "012"));
    ok(num_on_receive_reset == 1);
    ok(max_data_is_equal(client, server));

    free_pair();
}

/**
 * Section 5.2: the sender must not increase the Reliable Size; a request to do so is a no-op.
 */
static void test_raise_is_ignored_locally(void)
{
    quicly_stream_t *client_stream, *server_stream;

    connect_pair();
    open_stream(0, 3, &client_stream, &server_stream);

    quicly_reset_stream_at(client_stream, APP_ERROR(1), 5);
    transmit(client, server);
    ok(server_stream->recvstate.reliable_size == 5);
    ok(num_reset_stream_at_sent(client) == 1);

    /* raising is a no-op; neither the error code nor the Reliable Size changes, and no frame is sent */
    quicly_reset_stream_at(client_stream, APP_ERROR(2), 8);
    ok(client_stream->_send_aux.reset_stream.reliable_size == 5);
    ok(client_stream->_send_aux.reset_stream.error_code == 1);
    transmit(client, server);
    ok(num_reset_stream_at_sent(client) == 1);
    ok(server_stream->recvstate.reliable_size == 5);

    free_pair();
}

/**
 * Section 5.2: reordering can deliver a RESET_STREAM_AT carrying a higher Reliable Size after one carrying a lower value; the
 * receiver ignores the former rather than treating it as an error.
 */
static void test_raise_is_ignored_on_wire(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *server_streambuf;
    struct iovec reordered;
    uint8_t reorderedbuf[quic_ctx.transport_params.max_udp_payload_size];

    connect_pair();
    open_stream(0, 3, &client_stream, &server_stream);
    server_streambuf = server_stream->data;

    /* hold back the frame carrying the higher Reliable Size */
    quicly_reset_stream_at(client_stream, APP_ERROR(1), 8);
    hold_datagram(client, &reordered, reorderedbuf, sizeof(reorderedbuf));

    /* deliver the frame carrying the lower Reliable Size first */
    quicly_reset_stream_at(client_stream, APP_ERROR(1), 5);
    transmit(client, server);
    ok(server_stream->recvstate.reliable_size == 5);
    ok(!quicly_recvstate_transfer_complete(&server_stream->recvstate));

    /* the reordered frame is accepted by the frame handler, yet does not raise the Reliable Size */
    deliver_datagram(server, &reordered);
    ok(num_reset_stream_at_received(server) == 2);
    ok(server_stream->recvstate.reliable_size == 5);
    ok(!quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(quicly_recvstate_bytes_available(&server_stream->recvstate) == 3);
    ok(buffer_is(&server_streambuf->super.ingress, "012"));
    ok(num_on_receive_reset == 1);
    ok(max_data_is_equal(client, server));

    free_pair();
}

/**
 * Section 4: a Reliable Size greater than the Final Size is a FRAME_ENCODING_ERROR (rather than a FINAL_SIZE_ERROR).
 */
static void test_reliable_size_above_final_size(void)
{
    quicly_stream_t *client_stream, *server_stream;

    connect_pair();
    open_stream(0, TEST_DATA_LEN, &client_stream, &server_stream);

    /* craft a frame whose Reliable Size is above the Final Size, which is `size_inflight` */
    quicly_reset_stream_at(client_stream, APP_ERROR(1), 5);
    client_stream->_send_aux.reset_stream.reliable_size = TEST_DATA_LEN + 1;
    transmit(client, server);
    ok(local_close_error(server, QUICLY_FRAME_TYPE_RESET_STREAM_AT) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);

    free_pair();
}

/**
 * Section 5.2: the Application Error Code must not change between the resets received for one stream.
 */
static void test_error_code_is_immutable(void)
{
    quicly_stream_t *client_stream, *server_stream;

    connect_pair();
    open_stream(0, 3, &client_stream, &server_stream);

    quicly_reset_stream_at(client_stream, APP_ERROR(1), 5);
    transmit(client, server);
    ok(server_stream->recvstate.app_error_code == 1);

    /* lower the Reliable Size, but craft the frame to carry a different error code */
    quicly_reset_stream_at(client_stream, APP_ERROR(1), 3);
    client_stream->_send_aux.reset_stream.error_code = 2;
    transmit(client, server);
    ok(local_close_error(server, QUICLY_FRAME_TYPE_RESET_STREAM_AT) == QUICLY_TRANSPORT_ERROR_STREAM_STATE);

    free_pair();
}

/**
 * Section 5.2: the Final Size must not change between the resets received for one stream.
 */
static void test_final_size_is_immutable(void)
{
    quicly_stream_t *client_stream, *server_stream;

    connect_pair();
    open_stream(0, 3, &client_stream, &server_stream);

    quicly_reset_stream_at(client_stream, APP_ERROR(1), 5);
    transmit(client, server);
    ok(server_stream->recvstate.eos == TEST_DATA_LEN);

    /* lower the Reliable Size, but craft the frame to declare a different Final Size */
    quicly_reset_stream_at(client_stream, APP_ERROR(1), 3);
    client_stream->sendstate.size_inflight = TEST_DATA_LEN + 1;
    transmit(client, server);
    ok(local_close_error(server, QUICLY_FRAME_TYPE_RESET_STREAM_AT) == QUICLY_TRANSPORT_ERROR_FINAL_SIZE);

    free_pair();
}

/**
 * Section 5.2: a RESET_STREAM frame received after a RESET_STREAM_AT frame is legal, being equivalent to a Reliable Size of zero.
 */
static void test_reset_stream_after_reset_stream_at(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *server_streambuf;
    quicly_stats_t stats;

    connect_pair();
    open_stream(0, 3, &client_stream, &server_stream);
    server_streambuf = server_stream->data;

    quicly_reset_stream_at(client_stream, APP_ERROR(1), 5);
    transmit(client, server);
    ok(!quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_stream->recvstate.reliable_size == 5);

    /* lowering to zero sends a RESET_STREAM frame, which the receiver accepts */
    quicly_reset_stream(client_stream, APP_ERROR(1));
    ok(client_stream->_send_aux.reset_stream.reliable_size == 0);
    transmit(client, server);

    quicly_get_stats(client, &stats);
    ok(stats.num_frames_sent.reset_stream_at == 1);
    ok(stats.num_frames_sent.reset_stream == 1);
    quicly_get_stats(server, &stats);
    ok(stats.num_frames_received.reset_stream_at == 1);
    ok(stats.num_frames_received.reset_stream == 1);

    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_stream->recvstate.reliable_size == 0);
    ok(num_on_receive_reset == 1);
    ok(buffer_is(&server_streambuf->super.ingress, "012"));
    ok(max_data_is_equal(client, server));

    free_pair();
}

/**
 * Section 5.3: neither side of the stream may go away while bytes below the Reliable Size are still outstanding, and both must do
 * so promptly once those bytes have been received and acknowledged respectively. A unidirectional stream is used, so that the state
 * of each endpoint hinges on one direction only.
 */
static void test_destroyability(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *client_streambuf, *server_streambuf;
    size_t i;

    connect_pair();
    open_stream(1, 0, &client_stream, &server_stream);
    ok(server_stream == NULL); /* the server does not know about the stream yet */
    client_streambuf = client_stream->data;

    quicly_reset_stream_at(client_stream, APP_ERROR(1), 5);
    ok(!quicly_sendstate_transfer_complete(&client_stream->sendstate));
    transmit(client, server);

    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    assert(server_stream != NULL);
    server_streambuf = server_stream->data;
    ok(server_streambuf->error_received.reset_stream == APP_ERROR(1));

    /* receive side: the stream lives on, as none of the bytes below the Reliable Size have arrived */
    ok(!quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_stream->recvstate.reliable_size == 5);
    ok(server_stream->recvstate.eos == TEST_DATA_LEN);
    ok(!server_streambuf->is_detached);
    ok(quicly_num_streams(server) == 1);

    /* send side: the RESET_STREAM_AT frame gets acknowledged, yet the bytes below the Reliable Size do not */
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);
    ok(client_stream->_send_aux.reset_stream.sender_state == QUICLY_SENDER_STATE_ACKED);
    ok(!quicly_sendstate_transfer_complete(&client_stream->sendstate));
    ok(!client_streambuf->is_detached);
    ok(quicly_num_streams(client) == 1);

    /* the lost prefix is retransmitted; once it arrives, the receive side goes away at once */
    for (i = 0; i < 10 && !server_streambuf->is_detached; ++i) {
        quic_now = quicly_get_first_timeout(client);
        transmit(client, server);
    }
    ok(server_streambuf->is_detached);
    ok(quicly_num_streams(server) == 0);
    ok(buffer_is(&server_streambuf->super.ingress, "01234"));
    ok(!client_streambuf->is_detached); /* the retransmission has not been acknowledged yet */

    /* and the send side goes away once the prefix is acknowledged */
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);
    ok(client_streambuf->is_detached);
    ok(quicly_num_streams(client) == 0);

    free_pair();
}

/**
 * Section 5: STREAM frames carrying the bytes below the Reliable Size are retransmitted when lost, while the bytes above it are
 * not.
 */
static void test_retransmit_prefix(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *server_streambuf;
    quicly_stats_t stats;
    uint64_t stream_data_sent_at_start;
    size_t i;

    connect_pair();
    quicly_get_stats(client, &stats);
    stream_data_sent_at_start = stats.num_bytes.stream_data_sent;
    open_stream(0, 0, &client_stream, &server_stream);

    quicly_reset_stream_at(client_stream, APP_ERROR(1), 5);
    transmit(client, server);

    /* the server learns about the stream from the reset frame, none of the stream data having arrived */
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    assert(server_stream != NULL);
    server_streambuf = server_stream->data;
    ok(server_streambuf->error_received.reset_stream == APP_ERROR(1));
    ok(buffer_is(&server_streambuf->super.ingress, ""));

    for (i = 0; i < 10 && !quicly_recvstate_transfer_complete(&server_stream->recvstate); ++i) {
        quic_now = quicly_get_first_timeout(client);
        transmit(client, server);
    }
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(buffer_is(&server_streambuf->super.ingress, "01234"));

    /* exactly the 5 bytes below the Reliable Size have been retransmitted */
    quicly_get_stats(client, &stats);
    ok(stats.num_bytes.stream_data_sent - stream_data_sent_at_start == TEST_DATA_LEN + 5);
    ok(stats.num_bytes.stream_data_resent == 5);
    ok(max_data_is_equal(client, server));

    free_pair();
}

/**
 * Section 4: a lost RESET_STREAM_AT frame is retransmitted.
 */
static void test_retransmit_frame(void)
{
    quicly_stream_t *client_stream, *server_stream;
    struct iovec dropped;
    uint8_t droppedbuf[quic_ctx.transport_params.max_udp_payload_size];
    size_t i;

    connect_pair();
    open_stream(0, TEST_DATA_LEN, &client_stream, &server_stream);
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);
    ok(client_stream->sendstate.acked.ranges[0].end == TEST_DATA_LEN);

    /* drop the datagram carrying the RESET_STREAM_AT frame */
    quicly_reset_stream_at(client_stream, APP_ERROR(1), 5);
    hold_datagram(client, &dropped, droppedbuf, sizeof(droppedbuf));
    ok(num_reset_stream_at_sent(client) == 1);
    ok(num_reset_stream_at_received(server) == 0);
    ok(client_stream->_send_aux.reset_stream.sender_state == QUICLY_SENDER_STATE_UNACKED);

    for (i = 0; i < 10 && num_reset_stream_at_received(server) == 0; ++i) {
        quic_now = quicly_get_first_timeout(client);
        transmit(client, server);
    }
    ok(num_reset_stream_at_received(server) == 1);
    ok(num_reset_stream_at_sent(client) == 2);
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_stream->recvstate.reliable_size == 5);
    ok(num_on_receive_reset == 1);

    free_pair();
}

/**
 * Section 5.1: a RESET_STREAM_AT frame can be sent after a STREAM frame carrying the FIN bit. Here the FIN is lost, hence the
 * receiver learns the Final Size from the reset.
 */
static void test_after_fin(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *server_streambuf;
    quicly_address_t dest, src;
    struct iovec datagram;
    uint8_t datagrambuf[quic_ctx.transport_params.max_udp_payload_size];
    size_t num_datagrams = 1;
    quicly_error_t ret;

    connect_pair();
    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    quicly_streambuf_egress_write(client_stream, test_data, 5);
    transmit(client, server);
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    assert(server_stream != NULL);
    server_stream->callbacks = &counting_callbacks;
    server_streambuf = server_stream->data;

    /* shut down the stream, dropping the datagram that carries the FIN */
    quicly_streambuf_egress_write(client_stream, test_data + 5, TEST_DATA_LEN - 5);
    quicly_streambuf_egress_shutdown(client_stream);
    ret = quicly_send(client, &dest, &src, &datagram, &num_datagrams, datagrambuf, sizeof(datagrambuf));
    ok(ret == 0);
    ok(num_datagrams == 1);
    ok(client_stream->sendstate.final_size == TEST_DATA_LEN);
    ok(server_stream->recvstate.eos == UINT64_MAX);

    quicly_reset_stream_at(client_stream, APP_ERROR(1), 5);
    ok(client_stream->_send_aux.reset_stream.reliable_size == 5);
    transmit(client, server);

    ok(num_reset_stream_at_received(server) == 1);
    ok(server_stream->recvstate.eos == TEST_DATA_LEN);
    ok(server_stream->recvstate.reliable_size == 5);
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(buffer_is(&server_streambuf->super.ingress, "01234"));
    ok(num_on_receive_reset == 1);
    ok(max_data_is_equal(client, server));

    free_pair();
}

/**
 * Section 5.1: a RESET_STREAM_AT frame arriving after the FIN has already been received is ignored, as the transfer is complete.
 */
static void test_after_fin_received(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *server_streambuf;
    quicly_error_t ret;

    connect_pair();
    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    quicly_streambuf_egress_write(client_stream, test_data, TEST_DATA_LEN);
    quicly_streambuf_egress_shutdown(client_stream);
    transmit(client, server);
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    assert(server_stream != NULL);
    server_stream->callbacks = &counting_callbacks;
    server_streambuf = server_stream->data;
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(buffer_is(&server_streambuf->super.ingress, test_data));

    quicly_reset_stream_at(client_stream, APP_ERROR(1), 5);
    transmit(client, server);

    ok(num_reset_stream_at_received(server) == 1);
    ok(server_stream->recvstate.reliable_size == UINT64_MAX); /* the reset leaves no trace */
    ok(num_on_receive_reset == 0);
    ok(buffer_is(&server_streambuf->super.ingress, test_data));
    ok(max_data_is_equal(client, server));

    free_pair();
}

/**
 * Section 5.1: reordering can deliver the RESET_STREAM_AT frame before the STREAM frame carrying the FIN bit.
 */
static void test_before_fin(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *server_streambuf;
    struct iovec reordered;
    uint8_t reorderedbuf[quic_ctx.transport_params.max_udp_payload_size];
    quicly_error_t ret;

    connect_pair();
    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    quicly_streambuf_egress_write(client_stream, test_data, 3);
    transmit(client, server);
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    assert(server_stream != NULL);
    server_stream->callbacks = &counting_callbacks;
    server_streambuf = server_stream->data;

    /* hold back the datagram carrying the FIN */
    quicly_streambuf_egress_write(client_stream, test_data + 3, TEST_DATA_LEN - 3);
    quicly_streambuf_egress_shutdown(client_stream);
    hold_datagram(client, &reordered, reorderedbuf, sizeof(reorderedbuf));

    quicly_reset_stream_at(client_stream, APP_ERROR(1), 6);
    transmit(client, server);
    ok(server_stream->recvstate.eos == TEST_DATA_LEN);
    ok(server_stream->recvstate.reliable_size == 6);
    ok(!quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(buffer_is(&server_streambuf->super.ingress, "012"));
    ok(num_on_receive_reset == 1);

    /* the FIN that follows agrees with the Final Size already known, and completes the transfer */
    deliver_datagram(server, &reordered);
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(buffer_is(&server_streambuf->super.ingress, test_data));
    ok(num_on_receive_reset == 1);
    ok(max_data_is_equal(client, server));

    free_pair();
}

/**
 * Sections 5.1 and 5.2, RFC 9000 section 4.5: a FIN arriving after the reset must agree with the Final Size that the reset
 * declared.
 */
static void test_before_fin_size_mismatch(void)
{
    quicly_stream_t *client_stream, *server_stream;
    struct iovec reordered;
    uint8_t reorderedbuf[quic_ctx.transport_params.max_udp_payload_size];
    quicly_error_t ret;

    connect_pair();
    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    quicly_streambuf_egress_write(client_stream, test_data, 3);
    transmit(client, server);
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    assert(server_stream != NULL);

    /* hold back the datagram carrying the FIN, which is at TEST_DATA_LEN */
    quicly_streambuf_egress_write(client_stream, test_data + 3, TEST_DATA_LEN - 3);
    quicly_streambuf_egress_shutdown(client_stream);
    hold_datagram(client, &reordered, reorderedbuf, sizeof(reorderedbuf));

    /* craft the reset to declare a Final Size one above the FIN */
    quicly_reset_stream_at(client_stream, APP_ERROR(1), 6);
    client_stream->sendstate.size_inflight = TEST_DATA_LEN + 1;
    transmit(client, server);
    ok(server_stream->recvstate.eos == TEST_DATA_LEN + 1);

    deliver_datagram(server, &reordered);
    ok(local_close_error(server, UINT64_MAX) == QUICLY_TRANSPORT_ERROR_FINAL_SIZE);

    free_pair();
}

/**
 * Section 4: the Final Size is subject to flow control, a violation being a FLOW_CONTROL_ERROR.
 */
static void test_flow_control_error(void)
{
    quicly_stream_t *client_stream, *server_stream;

    connect_pair();
    open_stream(0, TEST_DATA_LEN, &client_stream, &server_stream);
    ok(server_stream->_recv_aux.window == quic_ctx.transport_params.max_stream_data.bidi_remote);

    /* craft the reset to declare a Final Size one above the stream-level limit */
    quicly_reset_stream_at(client_stream, APP_ERROR(1), 5);
    client_stream->sendstate.size_inflight = server_stream->recvstate.data_off + server_stream->_recv_aux.window + 1;
    transmit(client, server);
    ok(local_close_error(server, QUICLY_FRAME_TYPE_RESET_STREAM_AT) == QUICLY_TRANSPORT_ERROR_FLOW_CONTROL);

    free_pair();
}

/**
 * Section 5.4: a STOP_SENDING frame received for a stream that has been reset with a non-zero Reliable Size lowers the value to
 * zero, which is to say that a RESET_STREAM frame is sent.
 */
static void test_stop_sending(void)
{
    quicly_stream_t *client_stream, *server_stream;
    quicly_stats_t stats;
    uint64_t eos;

    connect_pair();
    open_stream(0, 3, &client_stream, &server_stream);

    quicly_reset_stream_at(client_stream, APP_ERROR(1), 5);
    transmit(client, server);
    ok(server_stream->recvstate.reliable_size == 5);
    ok(!quicly_recvstate_transfer_complete(&server_stream->recvstate));

    /* `quicly_request_stop` is a no-op once the final size is known, hence hide it for the duration of the call; that emulates a
     * peer that stops reading while the reliable prefix is still being delivered */
    eos = server_stream->recvstate.eos;
    server_stream->recvstate.eos = UINT64_MAX;
    quicly_request_stop(server_stream, APP_ERROR(7));
    server_stream->recvstate.eos = eos;
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);
    ok(client_stream->_send_aux.reset_stream.reliable_size == 0);
    ok(client_stream->_send_aux.reset_stream.error_code == 1); /* the error code of the first reset is retained */

    transmit(client, server);
    quicly_get_stats(client, &stats);
    ok(stats.num_frames_sent.reset_stream_at == 1);
    ok(stats.num_frames_sent.reset_stream == 1);
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_stream->recvstate.reliable_size == 0);
    ok(num_on_receive_reset == 1);

    free_pair();
}

/**
 * Documented limitation: `quicly_reset_stream_at` caps the Reliable Size to `size_inflight`, as quicly declares the Final Size to
 * be that value and a larger one would call for deferring the frame until flow control credit becomes available (section 4).
 * Resetting with a Reliable Size covering bytes that the application has written but quicly has not sent yet therefore degrades to
 * a smaller Reliable Size. This test pins that behaviour; it is to be revisited if the cap is ever lifted.
 */
static void test_cap_to_size_inflight(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *server_streambuf;

    connect_pair();
    open_stream(0, 3, &client_stream, &server_stream);
    server_streambuf = server_stream->data;

    /* write bytes that have not been put on the wire, then ask for all of them to be delivered reliably */
    quicly_streambuf_egress_write(client_stream, "abcde", 5);
    ok(client_stream->sendstate.size_inflight == TEST_DATA_LEN);
    quicly_reset_stream_at(client_stream, APP_ERROR(1), TEST_DATA_LEN + 5);
    ok(client_stream->_send_aux.reset_stream.reliable_size == TEST_DATA_LEN); /* capped, rather than deferred */
    ok(client_stream->sendstate.final_size == TEST_DATA_LEN);
    transmit(client, server);

    ok(server_stream->recvstate.eos == TEST_DATA_LEN);
    ok(server_stream->recvstate.reliable_size == TEST_DATA_LEN);

    /* the bytes below the cap are still delivered reliably */
    for (size_t i = 0; i < 10 && !quicly_recvstate_transfer_complete(&server_stream->recvstate); ++i) {
        quic_now = quicly_get_first_timeout(client);
        transmit(client, server);
    }
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(buffer_is(&server_streambuf->super.ingress, test_data));

    free_pair();
}

/**
 * Documented limitation: `quicly_reset_stream_at` degrades to a plain RESET_STREAM when the peer has not advertised the
 * reset_stream_at transport parameter.
 */
static void test_degrade_without_tp(void)
{
    quicly_stream_t *client_stream, *server_stream;
    quicly_stats_t stats;

    quic_ctx.transport_params.reset_stream_at = 0;
    connect_pair();
    quic_ctx.transport_params.reset_stream_at = 1;

    ok(!quicly_get_remote_transport_parameters(client)->reset_stream_at);
    open_stream(0, 5, &client_stream, &server_stream);

    quicly_reset_stream_at(client_stream, APP_ERROR(1), 5);
    ok(client_stream->_send_aux.reset_stream.reliable_size == 0);
    transmit(client, server);

    quicly_get_stats(client, &stats);
    ok(stats.num_frames_sent.reset_stream == 1);
    ok(stats.num_frames_sent.reset_stream_at == 0);
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_stream->recvstate.reliable_size == 0);

    free_pair();
}

/**
 * Section 3: a RESET_STREAM_AT frame received on a connection on which we have not advertised the transport parameter is a
 * FRAME_ENCODING_ERROR, the frame type being unknown.
 */
static void test_tp_not_advertised(void)
{
    quicly_stream_t *client_stream, *server_stream;

    quic_ctx.transport_params.reset_stream_at = 0;
    connect_pair();
    open_stream(0, TEST_DATA_LEN, &client_stream, &server_stream);

    /* craft a RESET_STREAM_AT frame in spite of the peer not having advertised support */
    quicly_reset_stream(client_stream, APP_ERROR(1));
    ok(client_stream->_send_aux.reset_stream.reliable_size == 0);
    client_stream->_send_aux.reset_stream.reliable_size = 5;
    transmit(client, server);
    ok(local_close_error(server, QUICLY_FRAME_TYPE_RESET_STREAM_AT) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
    ok(server_stream->recvstate.reliable_size == UINT64_MAX); /* the frame has had no effect */

    free_pair();
    quic_ctx.transport_params.reset_stream_at = 1;
}

void test_reset_stream_at(void)
{
    uint8_t reset_stream_at_orig = quic_ctx.transport_params.reset_stream_at;
    uint64_t max_streams_uni_orig = quic_ctx.transport_params.max_streams_uni;

    counting_callbacks = stream_callbacks;
    counting_callbacks.on_receive_reset = count_on_receive_reset;

    quic_ctx.transport_params.reset_stream_at = 1;
    quic_ctx.transport_params.max_streams_uni = 10;

    subtest("zero-is-reset-stream", test_zero_is_reset_stream);
    subtest("prefix-delivery", test_prefix_delivery);
    subtest("lower-reliable-size", test_lower_reliable_size);
    subtest("raise-is-ignored-locally", test_raise_is_ignored_locally);
    subtest("raise-is-ignored-on-wire", test_raise_is_ignored_on_wire);
    subtest("reliable-size-above-final-size", test_reliable_size_above_final_size);
    subtest("error-code-is-immutable", test_error_code_is_immutable);
    subtest("final-size-is-immutable", test_final_size_is_immutable);
    subtest("reset-stream-after-reset-stream-at", test_reset_stream_after_reset_stream_at);
    subtest("destroyability", test_destroyability);
    subtest("retransmit-prefix", test_retransmit_prefix);
    subtest("retransmit-frame", test_retransmit_frame);
    subtest("after-fin", test_after_fin);
    subtest("after-fin-received", test_after_fin_received);
    subtest("before-fin", test_before_fin);
    subtest("before-fin-size-mismatch", test_before_fin_size_mismatch);
    subtest("flow-control-error", test_flow_control_error);
    subtest("stop-sending", test_stop_sending);
    subtest("cap-to-size-inflight", test_cap_to_size_inflight);
    subtest("degrade-without-tp", test_degrade_without_tp);
    subtest("tp-not-advertised", test_tp_not_advertised);

    quic_ctx.transport_params.reset_stream_at = reset_stream_at_orig;
    quic_ctx.transport_params.max_streams_uni = max_streams_uni_orig;
}
