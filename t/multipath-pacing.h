/* Pacing must limit a large send window independently on each path and
 * expose a wakeup that lets queued reliable data make progress. */
static void test_multipath_pacing(void)
{
    int64_t saved_now = quic_now;
    quicly_context_t saved_ctx = quic_ctx;
    quic_ctx.transport_params.initial_max_path_id = 4;
    quic_ctx.egress[0].pacing = 1;
    quic_ctx.path_scheduler = &quicly_round_robin_path_scheduler;
    quicly_conn_t *client, *server;
    setup_multipath_regression_peers(&client, &server, 0);
    ok(quic_ctx.cid_encryptor != NULL);
    open_multipath_test_path(client);
    multipath_run(client, server, 100, -1, -1);
    uint64_t sent_before[2];
    for (size_t i = 0; i < 2; ++i) {
        quicly_path_space_t *ps = client->path_spaces[i];
        ok(quicly_is_path_available(client, i));
        ok(ps->pacer != NULL);
        /* A large cwnd removes congestion-window exhaustion as a possible
         * reason for the bounded first burst. The deliberately high RTT makes
         * the pacer's ten-packet burst allowance dominate its rate window. */
        ps->cc.cwnd = 1024 * 1024;
        ps->loss.rtt.latest = ps->loss.rtt.smoothed = 20000;
        quicly_pacer_reset(ps->pacer);
        sent_before[i] = get_path(client, i)->num_packets.bytes_sent;
    }
    ok(client->path_spaces[0]->pacer != client->path_spaces[1]->pacer);
    quicly_stream_t *stream;
    ok(quicly_open_stream(client, &stream, 0) == 0);
    uint8_t data[50000];
    for (size_t i = 0; i < sizeof(data); ++i)
        data[i] = (uint8_t)(i * 13 + i / 29);
    ok(quicly_streambuf_egress_write(stream, data, sizeof(data)) == 0);
    /* Leave ACKs pending at the receiver, and keep time fixed. */
    for (size_t i = 0; i < 32; ++i)
        transmit_multipath(client, server);
    for (size_t i = 0; i < 2; ++i) {
        uint64_t sent = get_path(client, i)->num_packets.bytes_sent - sent_before[i];
        ok(sent > 0);
        ok(sent <= QUICLY_PACER_BURST_HIGH * client->path_spaces[i]->max_udp_payload_size);
    }
    int64_t wake_at = quicly_get_first_timeout(client);
    ok(wake_at > quic_now);
    ok(wake_at <= quic_now + 200);
    quic_now = wake_at;
    ok(transmit_multipath(client, server) != 0);
    transmit_multipath(server, client);
    quicly_stream_t *received = NULL;
    for (size_t i = 0; i < 5000; ++i) {
        multipath_round(client, server, -1, -1);
        received = quicly_get_stream(server, stream->stream_id);
        if (received != NULL && quicly_streambuf_ingress_get(received).len == sizeof(data))
            break;
    }
    ok(received != NULL);
    if (received != NULL) {
        ptls_iovec_t bytes = quicly_streambuf_ingress_get(received);
        ok(bytes.len == sizeof(data));
        if (bytes.len == sizeof(data))
            ok(memcmp(bytes.base, data, sizeof(data)) == 0);
    }
    free_multipath_regression_peers(client, server, saved_ctx);
    quic_now = saved_now;
}
