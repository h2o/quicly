/* regression coverage for queues and validation that must progress independently of ordinary data scheduling */
static void test_multipath_tuple_lifecycle(void)
{
    quicly_conn_t *client, *server;
    quicly_context_t saved = setup_multipath_regression_peers(&client, &server, 0);
    /* The server's Initial replaces the client's original destination CID in path zero's live set. */
    quicly_cid_t *server_cid = &server->super.local.long_header_src_cid;
    ok(quicly_cid_is_equal(quicly_get_remote_cid(client), ptls_iovec_init(server_cid->cid, server_cid->len)));
    /* Multipath's zero-length CID prohibition must inspect the live set, not the initial compatibility snapshot. */
    uint8_t cid_len = client->path_spaces[0]->remote_cid_set.cids[0].cid.len;
    client->path_spaces[0]->remote_cid_set.cids[0].cid.len = 0;
    ok(apply_remote_transport_params(client) == QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION);
    client->path_spaces[0]->remote_cid_set.cids[0].cid.len = cid_len;
    struct sockaddr_in remote = {.sin_family = AF_INET, .sin_port = htons(10000), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(20000), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    ok(quicly_open_path(client, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
    struct st_quicly_conn_path_t *path = get_path(client, 1);
    quicly_tuple_t tuple, untouched;
    memset(&tuple, 0xa5, sizeof(tuple));
    untouched = tuple;
    ok(quicly_get_path_tuple(client, SIZE_MAX, &tuple) == -1);
    ok(memcmp(&tuple, &untouched, sizeof(tuple)) == 0);
    ok(quicly_get_path_tuple(client, QUICLY_MAX_PATH_INDICES - 1, &tuple) == -1);
    ok(memcmp(&tuple, &untouched, sizeof(tuple)) == 0);
    ok(quicly_get_path_tuple(client, 1, &tuple) == 0);
    ok(tuple.path_id == path->path_id && tuple.dcid.len == 0);
    ok(compare_socket_address(&tuple.address.remote.sa, (struct sockaddr *)&remote) == 0);
    ok(path->dcid == UINT64_MAX);
    ok(setup_path_dcid(client, 1));
    ok(quicly_get_path_tuple(client, 1, &tuple) == 0);
    ok(tuple.dcid.len != 0);
    uint64_t sequence = path->dcid;
    dissociate_cid(client, path->path_id, sequence);
    ok(quicly_get_path_tuple(client, 1, &tuple) == 0 && tuple.dcid.len == 0);
    ok(path->dcid == UINT64_MAX);
    ok(quicly_abandon_path(client, path->path_id, QUICLY_PATH_ABANDON_ERROR_APPLICATION) == 0);
    ok(quicly_get_path_tuple(client, 1, &tuple) == 0 && tuple.dcid.len == 0);
    free_multipath_regression_peers(client, server, saved);
}

static void test_multipath_unopened_abandoned_status(void)
{
    int64_t saved_now = quic_now;
    quicly_conn_t *client, *server;
    quicly_context_t saved = setup_multipath_regression_peers(&client, &server, 0);
    quicly_path_space_t *ps = find_path_space_by_id(client, 1);
    ok(ps != NULL && ps->addrs[0] == NULL);
    ok(quicly_set_path_status(client, 1, 1) == 0);

    /* Receive abandonment before the path has an address, while a local status update is queued. */
    quicly_send_context_t s;
    struct iovec datagram;
    uint8_t buf[1500];
    test_setup_send_context(server, &s, &datagram, buf, sizeof(buf));
    ok(do_allocate_frame(server, &s, 32, ALLOCATE_FRAME_TYPE_ACK_ELICITING) == 0);
    s.dst = quicly_encode_path_abandon_frame(s.dst, 1, QUICLY_PATH_ABANDON_ERROR_APPLICATION);
    ok(commit_send_packet(server, &s, 0) == 0);
    update_send_alarm(server, scheduler_can_send(server), server->path_spaces[0]);
    unlock_now(server);
    quicly_decoded_packet_t decoded;
    ok(decode_packets(&decoded, &datagram, 1) == 1);
    ok(quicly_receive(client, NULL, &fake_address.sa, &decoded) == 0);
    ok(path_id_is_abandoned(client, 1));
    ok(ps->addrs[0] == NULL);
    ok(ps->path_status.sender == QUICLY_SENDER_STATE_NONE);
    ok(quicly_set_path_status(client, 1, 0) == QUICLY_ERROR_PACKET_IGNORED);
    ok(quicly_set_path_status(client, 1, 1) == QUICLY_ERROR_PACKET_IGNORED);

    uint64_t status_before = client->super.stats.num_frames_sent.path_status;
    uint64_t abandon_before = client->super.stats.num_frames_sent.path_abandon;
    transmit_multipath(client, server);
    ok(client->super.stats.num_frames_sent.path_status == status_before);
    ok(client->super.stats.num_frames_sent.path_abandon > abandon_before);
    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    free_multipath_regression_peers(client, server, saved);
    quic_now = saved_now;
}

/* Also runnable in isolation under LeakSanitizer: unlike traffic-statistics fixtures, every owned buffer is released. */
static void test_multipath_lifecycle_cleanup(void)
{
    quicly_context_t original = quic_ctx;
    int64_t original_now = quic_now;
    quicly_stream_callbacks_t callbacks = stream_callbacks;
    callbacks.on_destroy = quicly_streambuf_destroy;
    for (unsigned n = 0; n < 8; ++n) {
        quic_ctx.egress[0].pacing = n % 2;
        quicly_conn_t *client, *server;
        quicly_context_t saved = setup_multipath_regression_peers(&client, &server, 0);
        struct sockaddr_in remote = {.sin_family = AF_INET, .sin_port = htons(10000), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(20000), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        ok(quicly_open_path(client, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
        uint32_t path_id = get_path(client, 1)->path_id;
        size_t candidate = encode_flat_path_index(1, 1);
        remote.sin_port = htons(10001);
        lock_now(client, 0);
        ok(new_path(client, candidate, path_id, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
        unlock_now(client);
        ptls_iovec_t data = ptls_iovec_init("pending", 7);
        quicly_send_datagram_frames_path(client, 0, &data, 1);
        quicly_send_datagram_frames_path(client, 1, &data, 1);
        quicly_send_datagram_frames_path(client, candidate, &data, 1);
        quicly_stream_t *stream;
        ok(quicly_open_stream(client, &stream, 0) == 0);
        stream->callbacks = &callbacks;
        ok(quicly_streambuf_egress_write(stream, "pending stream", 14) == 0);
        if (n >= 4) {
            lock_now(client, 0);
            ok(promote_path(client, candidate) == 0);
            unlock_now(client);
            ok(get_path(client, candidate) == NULL);
            ok(quicly_get_num_datagram_frames_path(client, 1) == 1);
        }
        ok(quicly_abandon_path(client, path_id, QUICLY_PATH_ABANDON_ERROR_APPLICATION) == 0);
        if (n % 4 >= 2) {
            lock_now(client, 0);
            int64_t expires = abandoned_path_expires_at(client, get_path(client, 1));
            quic_now = expires;
            unlock_now(client);
            lock_now(client, 0);
            expire_abandoned_path_state(client, 1);
            if (get_path(client, candidate) != NULL)
                expire_abandoned_path_state(client, candidate);
            unlock_now(client);
            ok(client->path_spaces[1] == NULL);
            ok(path_id_is_abandoned(client, path_id));
        }
        free_multipath_regression_peers(client, server, saved);
    }
    quic_ctx = original;
    quic_now = original_now;
}
