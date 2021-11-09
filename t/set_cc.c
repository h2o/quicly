/*
 * Copyright (c) 2021 Fastly, Kazuho Oku, Goro Fuji.
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
#include "quicly.h"
#include "test.h"

static void test_quicly_set_cc(void)
{
    quicly_conn_t *client, *server;
    quicly_address_t dest, src;
    struct iovec packets[8];
    uint8_t packetsbuf[PTLS_ELEMENTSOF(packets) * quic_ctx.transport_params.max_udp_payload_size];
    quicly_decoded_packet_t decoded[PTLS_ELEMENTSOF(packets) * 4];
    int ret;

    ret = quicly_connect(&client, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL,
                         NULL);
    ok(ret == 0);
    size_t num_packets = PTLS_ELEMENTSOF(packets);
    ret = quicly_send(client, &dest, &src, packets, &num_packets, packetsbuf, sizeof(packetsbuf));
    ok(ret == 0);

    size_t num_decoded = decode_packets(decoded, packets, num_packets);
    ok(num_decoded == 1);
    ret = quicly_accept(&server, &quic_ctx, NULL, &fake_address.sa, decoded, NULL, new_master_id(), NULL);
    ok(ret == 0);

    quicly_stats_t stats;

    // init CC with pico
    quicly_set_cc(server, &quicly_cc_type_pico);
    ret = quicly_get_stats(server, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "pico") == 0);

    // pico to pico
    quicly_set_cc(server, &quicly_cc_type_pico);
    ret = quicly_get_stats(server, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "pico") == 0);

    // reno to pico
    quicly_set_cc(server, &quicly_cc_type_reno);
    quicly_set_cc(server, &quicly_cc_type_pico);
    ret = quicly_get_stats(server, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "pico") == 0);

    // cubic to pico
    quicly_set_cc(server, &quicly_cc_type_cubic);
    quicly_set_cc(server, &quicly_cc_type_pico);
    ret = quicly_get_stats(server, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "pico") == 0);

    // pico to reno
    quicly_set_cc(server, &quicly_cc_type_pico);
    quicly_set_cc(server, &quicly_cc_type_reno);
    ret = quicly_get_stats(server, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "reno") == 0);

    // pico to cubic
    quicly_set_cc(server, &quicly_cc_type_pico);
    quicly_set_cc(server, &quicly_cc_type_cubic);
    ret = quicly_get_stats(server, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "cubic") == 0);

    // reno to cubic
    quicly_set_cc(server, &quicly_cc_type_reno);
    quicly_set_cc(server, &quicly_cc_type_cubic);
    ret = quicly_get_stats(server, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "cubic") == 0);

    // cubic to reno
    quicly_set_cc(server, &quicly_cc_type_cubic);
    quicly_set_cc(server, &quicly_cc_type_reno);
    ret = quicly_get_stats(server, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "reno") == 0);
}

void test_set_cc(void)
{
    subtest("quicly_set_cc", test_quicly_set_cc);
}
