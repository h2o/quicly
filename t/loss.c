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

static void transmit_cond(quicly_conn_t *src, quicly_conn_t *dst, size_t *num_sent, size_t *num_received, int (*cond)(void),
                          int64_t latency)
{
    quicly_raw_packet_t *packets[32];
    size_t i;
    quicly_decoded_packet_t decoded[32];
    int ret;

    *num_sent = sizeof(packets) / sizeof(packets[0]);
    ret = quicly_send(src, packets, num_sent);
    ok(ret == 0);
    quic_now += latency;

    *num_received = 0;

    if (*num_sent != 0) {
        size_t num_decoded = decode_packets(decoded, packets, *num_sent, quicly_is_client(dst) ? 0 : 8);
        assert(*num_sent == num_decoded);
        for (i = 0; i != num_decoded; ++i) {
            if (cond()) {
                ret = quicly_receive(dst, decoded + i);
                ok(ret == 0 || ret == QUICLY_ERROR_PACKET_IGNORED);
                ++*num_received;
            }
        }
        free_packets(packets, num_decoded);
    }
    quic_now += latency;
}

static int cond_true(void)
{
    return 1;
}

static int cond_even_up(void)
{
    static size_t cnt;
    return cnt++ % 2 == 0;
}

static int cond_even_down(void)
{
    static size_t cnt;
    return cnt++ % 2 == 0;
}

static void test_even(void)
{
    quicly_loss_conf_t lossconf = quicly_loss_default_conf;
    size_t num_sent, num_received;
    int ret;

    lossconf.max_tlps = 0;
    quic_ctx.loss = &lossconf;

    quic_now = 0;

    { /* transmit first flight */
        quicly_raw_packet_t *raw;
        size_t num_packets;
        quicly_decoded_packet_t decoded;

        ret = quicly_connect(&client, &quic_ctx, "example.com", (void *)"abc", 3, NULL);
        ok(ret == 0);
        num_packets = 1;
        ret = quicly_send(client, &raw, &num_packets);
        ok(ret == 0);
        ok(num_packets == 1);
        decode_packets(&decoded, &raw, 1, 8);
        ok(num_packets == 1);
        ret = quicly_accept(&server, &quic_ctx, (void *)"abc", 3, NULL, &decoded);
        ok(ret == 0);
        free_packets(&raw, 1);
        cond_even_up();
    }

    /* drop 2nd packet from server */
    transmit_cond(server, client, &num_sent, &num_received, cond_even_down, 0);
    ok(num_sent == 2);
    ok(num_received == 1);
    ok(quicly_get_state(client) == QUICLY_STATE_HANDSHAKE);

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;

    /* after ack-timeout, server sends the delayed ack */
    transmit_cond(server, client, &num_sent, &num_received, cond_even_down, 0);
    ok(num_sent == 1);
    ok(num_received == 1);

    /* client sends delayed-ack that gets dropped */
    transmit_cond(client, server, &num_sent, &num_received, cond_even_up, 0);
    ok(num_sent == 1);
    ok(num_received == 0);

    ok(quicly_get_state(client) == QUICLY_STATE_HANDSHAKE);

    quic_now += 1000;

    /* server resends the contents of all the packets (in cleartext) */
    transmit_cond(server, client, &num_sent, &num_received, cond_even_down, 0);
    ok(num_sent == 2);
    ok(num_received == 1);
    ok(quicly_get_state(client) == QUICLY_STATE_1RTT_ENCRYPTED);

    quic_ctx.loss = &quicly_loss_default_conf;
}

static unsigned rand_ratio;

static int cond_rand(void)
{
    static uint32_t seed = 1;
    seed = seed * 1103515245 + 12345;

    uint32_t v = (seed >> 10) & 1023;
    return v < rand_ratio;
}

static int fully_received(quicly_recvbuf_t *buf)
{
    return buf->received.ranges[0].end == buf->eos;
}

static void loss_core(int downstream_only)
{
    size_t num_sent, num_received;
    int ret;

    quic_now = 0;

    { /* transmit first flight */
        quicly_raw_packet_t *raw;
        size_t num_packets;
        quicly_decoded_packet_t decoded;

        ret = quicly_connect(&client, &quic_ctx, "example.com", (void *)"abc", 3, NULL);
        ok(ret == 0);
        num_packets = 1;
        ret = quicly_send(client, &raw, &num_packets);
        ok(ret == 0);
        ok(num_packets == 1);
        quic_now += 10;
        decode_packets(&decoded, &raw, 1, 8);
        ok(num_packets == 1);
        ret = quicly_accept(&server, &quic_ctx, (void *)"abc", 3, NULL, &decoded);
        ok(ret == 0);
        free_packets(&raw, 1);
        quic_now += 10;
    }

    quicly_stream_t *client_stream = NULL, *server_stream = NULL;
    const char *req = "GET / HTTP/1.0\r\n\r\n", *resp = "HTTP/1.0 200 OK\r\n\r\nhello world";
    size_t i;
    for (i = 0; i < 1000; ++i) {
        int64_t client_timeout = quicly_get_first_timeout(client), server_timeout = quicly_get_first_timeout(server),
                min_timeout = client_timeout < server_timeout ? client_timeout : server_timeout;
        assert(min_timeout != INT64_MAX);
        assert(min_timeout == 0 || quic_now < min_timeout + 40); /* we might have spent two RTTs in the loop below */
        if (quic_now < min_timeout)
            quic_now = min_timeout;
        transmit_cond(server, client, &num_sent, &num_received, cond_rand, 10);
        if (quicly_get_state(client) == QUICLY_STATE_1RTT_ENCRYPTED) {
            if (client_stream == NULL) {
                ret = quicly_open_stream(client, &client_stream);
                ok(ret == 0);
                client_stream->on_update = on_update_noop;
                quicly_sendbuf_write(&client_stream->sendbuf, req, strlen(req), NULL);
                quicly_sendbuf_shutdown(&client_stream->sendbuf);
            } else if (fully_received(&client_stream->recvbuf)) {
                ok(recvbuf_is(&client_stream->recvbuf, resp));
                ok(max_data_is_equal(client, server));
                return;
            }
        }
        transmit_cond(client, server, &num_sent, &num_received, downstream_only ? cond_true : cond_rand, 10);
        if (client_stream != NULL && (server_stream = quicly_get_stream(server, client_stream->stream_id)) != NULL) {
            if (fully_received(&server_stream->recvbuf) && server_stream->recvbuf.data_off == 0) {
                ok(recvbuf_is(&server_stream->recvbuf, req));
                quicly_sendbuf_write(&server_stream->sendbuf, resp, strlen(resp), NULL);
                quicly_sendbuf_shutdown(&server_stream->sendbuf);
            }
        }
    }
    ok(0);
}

static void test_downstream_core(void)
{
    loss_core(1);
}

static void test_downstream(void)
{
    size_t i;

    for (i = 0; i != 100; ++i) {
        rand_ratio = 256;
        subtest("75%", test_downstream_core);
        rand_ratio = 512;
        subtest("50%", test_downstream_core);
        rand_ratio = 768;
        subtest("25%", test_downstream_core);
        rand_ratio = 921;
        subtest("10%", test_downstream_core);
        rand_ratio = 973;
        subtest("5%", test_downstream_core);
        rand_ratio = 1014;
        subtest("1%", test_downstream_core);
    }
}

static void test_bidirectional_core(void)
{
    loss_core(0);
}

static void test_bidirectional(void)
{
    size_t i;

    for (i = 0; i != 100; ++i) {
        rand_ratio = 256;
        subtest("75%", test_bidirectional_core);
        rand_ratio = 512;
        subtest("50%", test_bidirectional_core);
        rand_ratio = 768;
        subtest("25%", test_bidirectional_core);
        rand_ratio = 921;
        subtest("10%", test_bidirectional_core);
        rand_ratio = 973;
        subtest("5%", test_bidirectional_core);
        rand_ratio = 1014;
        subtest("1%", test_bidirectional_core);
    }
}

void test_loss(void)
{
    subtest("even", test_even);
    subtest("downstream", test_downstream);
    subtest("bidirectional", test_bidirectional);
}
