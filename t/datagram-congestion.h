static void do_test_datagram_congestion_accounting(void)
{
    uint16_t saved_max_datagram_frame_size = quic_ctx.transport_params.max_datagram_frame_size;
    quicly_receive_datagram_frame_t *saved_receiver = quic_ctx.receive_datagram_frame;
    static quicly_receive_datagram_frame_t receiver = {test_queue_receive_datagram};
    quic_ctx.transport_params.max_datagram_frame_size = 1200;
    quic_ctx.receive_datagram_frame = &receiver;

    quicly_conn_t *client, *server;
    test_setup_connected_peers(&client, &server);
    exchange_until_idle(client, server);
    client->super.stats.num_respected_app_limited = 1;
    struct st_quicly_conn_path_t *path = get_path(client, 0);
    uint32_t cwnd = get_cc(client, path)->cwnd;
    uint64_t frames_before = client->super.stats.num_frames_sent.datagram;
    uint8_t payload_bytes[1000] = {0};
    ptls_iovec_t payload = ptls_iovec_init(payload_bytes, sizeof(payload_bytes));
    size_t emitted = 0;
    int send_ok = 1;
    for (; emitted != 100;) {
        quicly_address_t dest, src;
        struct iovec datagrams[8];
        uint8_t buffer[sizeof(datagrams) / sizeof(datagrams[0]) * 1500];
        size_t count = sizeof(datagrams) / sizeof(datagrams[0]);
        quicly_send_datagram_frames(client, &payload, 1);
        if (quicly_send(client, &dest, &src, datagrams, &count, buffer, sizeof(buffer)) != 0) {
            send_ok = 0;
            break;
        }
        if (count == 0)
            break;
        emitted += count;
    }
    uint64_t bytes_in_flight = get_loss(client, path)->sentmap.bytes_in_flight;
    ok(send_ok && emitted < 100 && bytes_in_flight <= cwnd + *get_max_udp_payload_size(client, path));
    ok(client->super.stats.num_frames_sent.datagram - frames_before == emitted);
    ok(quicly_get_num_datagram_frames_path(client, 0) == 1);
    /* A queued DATAGRAM behind a full window is congestion-limited, even when
     * there are no sendable STREAM bytes. CUBIC must keep its clock running. */
    ok(quicly_ratemeter_is_cc_limited(&client->path_spaces[0]->ratemeter));
    if (get_cc(client, path)->type == &quicly_cc_type_cubic)
        ok(get_cc(client, path)->state.pico.cubic.cc_limited);

    quicly_address_t dest, src;
    struct iovec datagrams[8];
    uint8_t buffer[sizeof(datagrams) / sizeof(datagrams[0]) * 1500];
    size_t count = sizeof(datagrams) / sizeof(datagrams[0]);
    ok(quicly_send(client, &dest, &src, datagrams, &count, buffer, sizeof(buffer)) == 0 && count == 0 &&
       quicly_get_num_datagram_frames_path(client, 0) == 1);
    ok(quicly_get_first_timeout(client) > 0);

    quicly_free(client);
    quicly_free(server);

    quic_ctx.transport_params.max_datagram_frame_size = saved_max_datagram_frame_size;
    quic_ctx.receive_datagram_frame = saved_receiver;
}

static void test_datagram_congestion_accounting(void)
{
    quicly_init_cc_t *saved_init_cc = quic_ctx.init_cc;
    quic_ctx.init_cc = &quicly_cc_reno_init;
    do_test_datagram_congestion_accounting();
    quic_ctx.init_cc = &quicly_cc_cubic_init;
    do_test_datagram_congestion_accounting();
    quic_ctx.init_cc = saved_init_cc;
}

static void test_datagram_congestion_path_isolation(void)
{
    quicly_conn_t conn = {0};
    quicly_path_space_t ps = {0}, other = {0};
    struct st_quicly_conn_path_t path = {0}, other_path = {0};
    conn.super.remote.address_validation.validated = 1;
    conn.super.stats.num_respected_app_limited = 1;
    conn.stash.now = 1;
    conn.path_spaces[0] = &ps;
    conn.path_spaces[1] = &other;
    ps.addrs[0] = &path;
    other.addrs[0] = &other_path;
    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &ps.cc, 2400, 0, 1);
    quicly_ratemeter_init(&ps.ratemeter);
    ps.loss.sentmap.bytes_in_flight = ps.cc.cwnd;

    /* Work on a different path must not start this path's growth clock. */
    other_path.datagram_frame_payloads.count = 1;
    update_ratemeter(&conn, &ps, 0, 0, 0);
    ok(!quicly_ratemeter_is_cc_limited(&ps.ratemeter));
    ok(!ps.cc.state.pico.cubic.cc_limited);
    path.datagram_frame_payloads.count = 1;
    update_ratemeter(&conn, &ps, 0, 0, 0);
    ok(quicly_ratemeter_is_cc_limited(&ps.ratemeter));
    ok(ps.cc.state.pico.cubic.cc_limited);

    /* Queued data on an unvalidated or abandoned address cannot be sent. */
    path.probe_only = 1;
    update_ratemeter(&conn, &ps, 0, 0, 0);
    ok(!ps.cc.state.pico.cubic.cc_limited);
    path.probe_only = 0;
    path.abandoned = 1;
    update_ratemeter(&conn, &ps, 0, 0, 0);
    ok(!ps.cc.state.pico.cubic.cc_limited);
    path.abandoned = 0;
    conn.super.remote.address_validation.validated = 0;
    update_ratemeter(&conn, &ps, 0, 0, 0);
    ok(!ps.cc.state.pico.cubic.cc_limited);
    conn.super.remote.address_validation.validated = 1;
    update_ratemeter(&conn, &ps, 0, 0, 0);
    ok(ps.cc.state.pico.cubic.cc_limited);
    path.datagram_frame_payloads.count = 0;
    update_ratemeter(&conn, &ps, 0, 0, 0);
    ok(!quicly_ratemeter_is_cc_limited(&ps.ratemeter));
    ok(!ps.cc.state.pico.cubic.cc_limited);
}

static void test_datagram_cubic_progress(void)
{
    int64_t saved_now = quic_now;
    quicly_context_t saved_ctx = quic_ctx;
    static quicly_receive_datagram_frame_t receiver = {test_queue_receive_datagram};
    quic_ctx.transport_params.max_datagram_frame_size = 1200;
    quic_ctx.receive_datagram_frame = &receiver;
    quic_ctx.init_cc = &quicly_cc_cubic_init;
    quicly_conn_t *client, *server;
    test_setup_connected_peers(&client, &server);
    client->super.stats.num_respected_app_limited = 1;
    quicly_cc_t *cc = &client->path_spaces[0]->cc;
    uint32_t initial = 2 * client->path_spaces[0]->max_udp_payload_size;
    /* Start congestion avoidance at the minimum window, as after a loss
     * episode. A continuously backlogged, loss-free DATAGRAM flow must grow. */
    cc->cwnd = cc->ssthresh = initial;
    cc->state.pico.cubic.w_est = initial;
    cc->state.pico.cubic.cwnd_prior = initial;
    cc->state.pico.cubic.epoch_start = 0;
    cc->state.pico.cubic.cc_limited = 0;
    uint8_t bytes[1000] = {0};
    ptls_iovec_t payload = ptls_iovec_init(bytes, sizeof(bytes));
    uint64_t acked_before = get_path(client, 0)->num_packets.bytes_acked;
    for (size_t round = 0; round < 200; ++round) {
        for (size_t queued = quicly_get_num_datagram_frames_path(client, 0); queued < 64; ++queued)
            quicly_send_datagram_frames(client, &payload, 1);
        transmit(client, server);
        quic_now += 20;
        int was_cc_limited = cc->state.pico.cubic.cc_limited;
        transmit(server, client);
        if (was_cc_limited && quicly_get_num_datagram_frames_path(client, 0) != 0)
            ok(cc->state.pico.cubic.cc_limited);
        quic_now += 20;
    }
    ok(get_path(client, 0)->num_packets.bytes_acked > acked_before);
    ok(cc->cwnd > initial * 2);
    quicly_free(client);
    quicly_free(server);
    quic_ctx = saved_ctx;
    quic_now = saved_now;
}
