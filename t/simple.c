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
#include <string.h>
#include "test.h"

static quicly_conn_t *client, *server;

static void test_handshake(void)
{
    quicly_raw_packet_t *packets[32];
    size_t num_packets;
    quicly_decoded_packet_t decoded[32];
    int ret, i;

    /* send CH */
    ret = quicly_connect(&client, &quic_ctx, "example.com", (void *)"abc", 3, NULL);
    ok(ret == 0);
    num_packets = sizeof(packets) / sizeof(packets[0]);
    ret = quicly_send(client, packets, &num_packets);
    ok(ret == 0);
    ok(num_packets == 1);
    ok(packets[0]->data.len == 1280);

    /* receive CH, send handshake upto ServerFinished */
    decode_packets(decoded, packets, num_packets);
    ret = quicly_accept(&server, &quic_ctx, (void *)"abc", 3, NULL, decoded);
    ok(ret == 0);
    free_packets(packets, num_packets);
    ok(quicly_get_state(server) == QUICLY_STATE_1RTT_ENCRYPTED);
    num_packets = sizeof(packets) / sizeof(packets[0]);
    ret = quicly_send(server, packets, &num_packets);
    ok(ret == 0);
    ok(num_packets != 0);

    /* receive ServerFinished */
    decode_packets(decoded, packets, num_packets);
    for (i = 0; i != num_packets; ++i) {
        ret = quicly_receive(client, decoded + i);
        ok(ret == 0);
    }
    free_packets(packets, num_packets);
    ok(quicly_get_state(client) == QUICLY_STATE_1RTT_ENCRYPTED);
}

static void simple_http(void)
{
    const char *req = "GET / HTTP/1.0\r\n\r\n", *resp = "HTTP/1.0 200 OK\r\n\r\nhello world";
    quicly_stream_t *client_stream, *server_stream;
    int ret;

    ret = quicly_open_stream(client, &client_stream);
    ok(ret == 0);
    client_stream->on_receive = buffering_on_receive;
    quicly_sendbuf_write(&client_stream->sendbuf, req, strlen(req), NULL);
    quicly_sendbuf_shutdown(&client_stream->sendbuf);

    transmit(client, server);

    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    ok(recvbuf_is(&server_stream->recvbuf, req));
    ok(quicly_recvbuf_is_shutdown(&server_stream->recvbuf));
    quicly_sendbuf_write(&server_stream->sendbuf, resp, strlen(resp), NULL);
    quicly_sendbuf_shutdown(&server_stream->sendbuf);

    transmit(server, client);

    ok(recvbuf_is(&client_stream->recvbuf, resp));
    ok(quicly_recvbuf_is_shutdown(&client_stream->recvbuf));
}

static void tiny_window(void)
{
    quicly_stream_t *client_stream, *server_stream;
    int ret;

    quic_ctx.transport_params.initial_max_stream_data = 4;

    ret = quicly_open_stream(client, &client_stream);
    ok(ret == 0);
    client_stream->_peer_max_stream_data = 4;

    quicly_sendbuf_write(&client_stream->sendbuf, "hello world", 11, NULL);
    quicly_sendbuf_shutdown(&client_stream->sendbuf);

    transmit(client, server);

    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    recvbuf_is(&server_stream->recvbuf, "hel");
    ok(quicly_recvbuf_available(&server_stream->recvbuf) == 1);

    transmit(server, client);
    transmit(client, server);

    recvbuf_is(&server_stream->recvbuf, "lo w");
    ok(quicly_recvbuf_available(&server_stream->recvbuf) == 0);

    transmit(server, client);
    transmit(client, server);

    recvbuf_is(&server_stream->recvbuf, "orld");
    ok(quicly_recvbuf_is_shutdown(&server_stream->recvbuf));
}

void test_simple(void)
{
    subtest("handshake", test_handshake);
    subtest("simple-http", simple_http);
    subtest("tiny-window", tiny_window);
}
