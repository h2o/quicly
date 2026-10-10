static quicly_context_t setup_multipath_scheduling_peers(quicly_conn_t **client, quicly_conn_t **server,
                                                         quicly_path_scheduler_t *scheduler)
{
    quicly_context_t saved = setup_multipath_regression_peers(client, server, 0);
    quic_ctx.path_scheduler = scheduler;
    struct sockaddr_in remote = {.sin_family = AF_INET, .sin_port = htons(10000), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(20000), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    ok(quicly_open_path(*client, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
    for (size_t i = 0; i < 100; ++i) {
        ++quic_now;
        transmit_multipath(*client, *server);
        transmit_multipath(*server, *client);
    }
    ok(quicly_is_path_available(*client, 1));
    /* ask the client to reserve path 1 for backup use */
    ok(quicly_set_path_status(*server, 1, 1) == 0);
    for (size_t i = 0; i < 100; ++i) {
        ++quic_now;
        transmit_multipath(*server, *client);
        transmit_multipath(*client, *server);
    }
    ok((*client)->path_spaces[1]->is_backup);
    return saved;
}

static size_t multipath_received_length(quicly_conn_t *conn, quicly_stream_id_t stream_id)
{
    quicly_stream_t *stream = quicly_get_stream(conn, stream_id);
    return stream != NULL ? quicly_streambuf_ingress_get(stream).len : 0;
}

static void test_multipath_backup_affinity(void)
{
    quicly_path_scheduler_t *schedulers[] = {&quicly_default_path_scheduler, &quicly_round_robin_path_scheduler};
    for (size_t n = 0; n < PTLS_ELEMENTSOF(schedulers); ++n) {
        int64_t saved_now = quic_now;
        quicly_conn_t *client, *server;
        quicly_context_t saved = setup_multipath_scheduling_peers(&client, &server, schedulers[n]);
        quicly_stream_t *pinned, *ordinary;
        ok(quicly_open_stream(client, &pinned, 0) == 0);
        ok(quicly_open_stream(client, &ordinary, 0) == 0);
        ok(quicly_set_stream_path_affinity(pinned, 1) == 0);
        uint8_t data[5000];
        memset(data, 0x5a, sizeof(data));
        ok(quicly_streambuf_egress_write(pinned, data, sizeof(data)) == 0);
        ok(quicly_streambuf_egress_write(ordinary, data, sizeof(data)) == 0);
        uint32_t cwnd = client->path_spaces[0]->cc.cwnd;
        client->path_spaces[0]->cc.cwnd = 0;
        for (size_t i = 0; i < 100; ++i) {
            ++quic_now;
            transmit_multipath(client, server);
            transmit_multipath(server, client);
        }
        ok(multipath_received_length(server, pinned->stream_id) == sizeof(data));
        /* congestion alone must not promote a backup or leak unbound streams onto it */
        ok(multipath_received_length(server, ordinary->stream_id) == 0);
        ok(client->path_spaces[1]->is_backup);
        client->path_spaces[0]->cc.cwnd = cwnd;
        for (size_t i = 0; i < 100; ++i) {
            ++quic_now;
            transmit_multipath(client, server);
            transmit_multipath(server, client);
        }
        ok(multipath_received_length(server, ordinary->stream_id) == sizeof(data));
        /* a writable primary must not cause a busy loop when only a blocked, backup-bound stream has pending data */
        ok(quicly_streambuf_egress_write(pinned, data, sizeof(data)) == 0);
        cwnd = client->path_spaces[1]->cc.cwnd;
        client->path_spaces[1]->cc.cwnd = 0;
        ok(quicly_get_first_timeout(client) > quic_now);
        client->path_spaces[1]->cc.cwnd = cwnd;
        for (size_t i = 0; i < 100; ++i) {
            ++quic_now;
            transmit_multipath(client, server);
            transmit_multipath(server, client);
        }
        ok(multipath_received_length(server, pinned->stream_id) == 2 * sizeof(data));
        free_multipath_regression_peers(client, server, saved);
        quic_now = saved_now;
    }
}

static void test_multipath_backup_failover(void)
{
    quicly_path_scheduler_t *schedulers[] = {&quicly_default_path_scheduler, &quicly_round_robin_path_scheduler};
    for (size_t n = 0; n < PTLS_ELEMENTSOF(schedulers); ++n) {
        int64_t saved_now = quic_now;
        quicly_conn_t *client, *server;
        quicly_context_t saved = setup_multipath_scheduling_peers(&client, &server, schedulers[n]);
        quicly_stream_t *stream;
        ok(quicly_open_stream(client, &stream, 0) == 0);
        uint8_t data[8000];
        for (size_t i = 0; i < sizeof(data); ++i)
            data[i] = (uint8_t)i;
        ok(quicly_streambuf_egress_write(stream, data, sizeof(data)) == 0);
        /* blackhole the primary without deleting it or manually declaring its packets lost */
        for (size_t i = 0; i < 3000 && multipath_received_length(server, stream->stream_id) != sizeof(data); ++i) {
            ++quic_now;
            transmit_multipath_with_loss(client, server, 0);
            transmit_multipath_with_loss(server, client, 0);
        }
        ok(multipath_received_length(server, stream->stream_id) == sizeof(data));
        quicly_stream_t *received = quicly_get_stream(server, stream->stream_id);
        if (received != NULL && quicly_streambuf_ingress_get(received).len == sizeof(data))
            ok(memcmp(quicly_streambuf_ingress_get(received).base, data, sizeof(data)) == 0);
        ok(!get_path(client, 0)->abandoned);
        ok(client->path_spaces[0]->loss.pto_count >= 2);
        ok(client->path_spaces[1]->is_backup);
        /* restore connectivity. recovery probes must still run on the excluded path */
        for (size_t i = 0; i < 3000 && client->path_spaces[0]->loss.pto_count != 0; ++i) {
            ++quic_now;
            transmit_multipath(client, server);
            transmit_multipath(server, client);
        }
        ok(client->path_spaces[0]->loss.pto_count == 0);
        for (size_t i = 0; i < 100; ++i) {
            ++quic_now;
            transmit_multipath(client, server);
            transmit_multipath(server, client);
        }
        uint64_t primary_before = get_path(client, 0)->num_packets.bytes_sent;
        uint64_t backup_before = get_path(client, 1)->num_packets.bytes_sent;
        ok(quicly_streambuf_egress_write(stream, data, sizeof(data)) == 0);
        for (size_t i = 0; i < 100; ++i) {
            ++quic_now;
            transmit_multipath(client, server);
            transmit_multipath(server, client);
        }
        ok(multipath_received_length(server, stream->stream_id) == 2 * sizeof(data));
        ok(get_path(client, 0)->num_packets.bytes_sent > primary_before + sizeof(data));
        ok(get_path(client, 1)->num_packets.bytes_sent == backup_before);
        free_multipath_regression_peers(client, server, saved);
        quic_now = saved_now;
    }
}

static void test_multipath_backup_transient_loss(void)
{
    quicly_path_scheduler_t *schedulers[] = {&quicly_default_path_scheduler, &quicly_round_robin_path_scheduler};
    for (size_t n = 0; n < PTLS_ELEMENTSOF(schedulers); ++n) {
        int64_t saved_now = quic_now;
        quicly_conn_t *client, *server;
        quicly_context_t saved = setup_multipath_scheduling_peers(&client, &server, schedulers[n]);
        quicly_stream_t *stream;
        ok(quicly_open_stream(client, &stream, 0) == 0);
        uint8_t data[1000];
        memset(data, 0xa5, sizeof(data));
        ok(quicly_streambuf_egress_write(stream, data, sizeof(data)) == 0);
        uint64_t backup_before = get_path(client, 1)->num_packets.bytes_sent;
        for (size_t i = 0; i < 1000 && client->path_spaces[0]->loss.pto_count <= 0; ++i) {
            ++quic_now;
            transmit_multipath_with_loss(client, server, 0);
            transmit_multipath_with_loss(server, client, 0);
        }
        ok(client->path_spaces[0]->loss.pto_count == 1);
        ok(get_path(client, 1)->num_packets.bytes_sent == backup_before);
        for (size_t i = 0; i < 1000 && multipath_received_length(server, stream->stream_id) != sizeof(data); ++i) {
            ++quic_now;
            transmit_multipath(client, server);
            transmit_multipath(server, client);
        }
        ok(multipath_received_length(server, stream->stream_id) == sizeof(data));
        free_multipath_regression_peers(client, server, saved);
        quic_now = saved_now;
    }
}
