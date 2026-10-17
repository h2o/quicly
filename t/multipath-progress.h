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

static void test_multipath_datagram_rank_progress(void)
{
    quicly_path_scheduler_t *schedulers[] = {&quicly_default_path_scheduler, &quicly_round_robin_path_scheduler};
    for (size_t n = 0; n < PTLS_ELEMENTSOF(schedulers); ++n) {
        custom_recovery_fixture_t f;
        custom_recovery_setup(&f);
        quic_ctx.path_scheduler = schedulers[n];
        ptls_iovec_t data = ptls_iovec_init("queued on explicit path", 23);
        /* an explicit backup queue must drain even while the primary remains healthy */
        quicly_send_datagram_frames_path(f.client, 1, &data, 1);
        ok(custom_recovery_transmit(f.client, f.server, 0, 1) == 1);
        ok(quicly_get_num_datagram_frames_path(f.client, 1) == 0);
        ok(f.server_policy.received_datagrams == 1);
        for (size_t i = 0; i < 100; ++i)
            custom_recovery_round(&f, 0, 1);

        /* let real packet loss demote the primary, then queue a DATAGRAM without a pinned stream to select that path */
        quicly_stream_t *stream;
        ok(quicly_open_stream(f.client, &stream, 0) == 0);
        ok(quicly_streambuf_egress_write(stream, "loss", 4) == 0);
        int64_t until = quic_now + f.bound;
        while (quic_now < until && f.client->path_spaces[0]->loss.pto_count < 2)
            custom_recovery_round(&f, 1, 1);
        ok(f.client->path_spaces[0]->loss.pto_count >= 2);
        ok(path_scheduling_rank(get_path(f.client, 0)) > preferred_path_rank(f.client));
        quicly_send_datagram_frames_path(f.client, 0, &data, 1);
        for (size_t i = 0; i < 3; ++i) {
            size_t count = custom_recovery_transmit(f.client, f.server, 1, 1);
            ok(count != 0 || quicly_get_first_timeout(f.client) > quic_now);
        }
        ok(quicly_get_num_datagram_frames_path(f.client, 0) == 0);
        custom_recovery_free(&f);
    }
}

static void test_multipath_path_zero_validation(void)
{
    custom_recovery_fixture_t f;
    custom_recovery_setup(&f);
    f.client_policy.data = 0;
    f.client_policy.eligible = 2;
    ptls_iovec_t data = ptls_iovec_init("queued", 6);
    quicly_send_datagram_frames_path(f.client, 0, &data, 1);
    struct st_quicly_conn_path_t *path = get_path(f.client, 0);
    path->path_response.send_ = 1;
    recalc_send_probe_at(f.client);
    uint64_t before = f.client->super.stats.num_frames_sent.path_response;
    ok(custom_recovery_transmit(f.client, f.server, 0, 1) == 0);
    ok(path->path_response.send_);
    ok(quicly_get_first_timeout(f.client) > quic_now);
    f.client_policy.eligible = 3;
    ok(quicly_get_first_timeout(f.client) <= quic_now);
    ok(custom_recovery_transmit(f.client, f.server, 0, 1) == 1);
    ok(!path->path_response.send_);
    ok(f.client->super.stats.num_frames_sent.path_response == before + 1);
    ok(quicly_get_num_datagram_frames_path(f.client, 0) == 1);
    for (size_t i = 0; i < 3; ++i) {
        size_t count = custom_recovery_transmit(f.client, f.server, 0, 1);
        ok(count != 0 || quicly_get_first_timeout(f.client) > quic_now);
    }
    custom_recovery_free(&f);
}

static void multipath_progress_deliver_response(quicly_conn_t *conn, size_t index, const uint8_t *data)
{
    struct st_quicly_handle_payload_state_t state = {
        .path_index = index, .src = data, .end = data + QUICLY_PATH_CHALLENGE_DATA_LEN};
    ok(handle_path_response_frame(conn, &state) == 0);
}

static void test_multipath_short_validation(void)
{
    /* cover a lone challenge, challenge plus response/PING near minimum credit, and credit growing before first response */
    for (size_t mode = 0; mode < 3; ++mode) {
        custom_recovery_fixture_t f;
        custom_recovery_setup(&f);
        f.server_policy.eligible = 2;
        f.server_policy.data = f.client_policy.data = 0;
        struct st_quicly_conn_path_t *path = get_path(f.server, 1);
        path->path_challenge.send_at = quic_now;
        path->path_challenge.address_validated = path->path_challenge.sent_full_size = 0;
        path->path_challenge.num_sent = 0;
        path->path_response.send_ = mode == 1;
        path->probe_only = 1;
        path->bytes_received = mode == 1 ? 20 : 100;
        path->bytes_sent = 0;
        recalc_send_probe_at(f.server);
        uint8_t short_nonce[QUICLY_PATH_CHALLENGE_DATA_LEN];
        memcpy(short_nonce, path->path_challenge.data, sizeof(short_nonce));
        ptls_iovec_t data = ptls_iovec_init("queued", 6);
        quicly_send_datagram_frames_path(f.server, 1, &data, 1);
        quicly_stream_t *stream;
        ok(quicly_open_stream(f.server, &stream, 0) == 0);
        ok(quicly_set_stream_path_affinity(stream, 1) == 0);
        ok(quicly_streambuf_egress_write(stream, "queued", 6) == 0);
        uint64_t validated = f.server->super.stats.num_paths.validated;
        uint64_t allowance = calc_amplification_limit_allowance(f.server, path);
        ok(quicly_get_first_timeout(f.server) <= quic_now);
        /* a short datagram must end the batch even if sixteen output slots are available */
        ok(custom_recovery_transmit(f.server, f.client, 0, 16) == 1);
        ok(path->bytes_sent == allowance);
        ok(!path->path_challenge.sent_full_size && !path->path_challenge.address_validated);
        ok(!path->path_response.send_);
        ok(custom_recovery_transmit(f.server, f.client, 0, 1) == 0);
        ok(quicly_get_first_timeout(f.server) > quic_now);

        if (mode == 2) {
            /* more inbound bytes fund a full-size retry before the short response arrives */
            path->bytes_received += 1500;
            quic_now = path->path_challenge.send_at;
        } else {
            ok(custom_recovery_transmit(f.client, f.server, 0, 1) == 1);
            ok(path->path_challenge.address_validated);
            ok(calc_amplification_limit_allowance(f.server, path) == UINT64_MAX);
            ok(path->path_challenge.send_at <= quic_now);
            ok(path->probe_only && f.server->super.stats.num_paths.validated == validated);
            ok(memcmp(short_nonce, path->path_challenge.data, sizeof(short_nonce)) != 0);
        }
        uint64_t sent_before = path->bytes_sent;
        ok(custom_recovery_transmit(f.server, f.client, 0, 1) == 1);
        ok(path->bytes_sent - sent_before >= QUICLY_MIN_CLIENT_INITIAL_SIZE);
        ok(path->path_challenge.sent_full_size);
        ok(memcmp(short_nonce, path->path_challenge.data, sizeof(short_nonce)) != 0);
        /* a delayed response to the short probe cannot complete MTU validation */
        multipath_progress_deliver_response(f.server, 1, short_nonce);
        ok(path->probe_only && path->path_challenge.send_at != INT64_MAX);
        ok(f.server->super.stats.num_paths.validated == validated);
        ok(custom_recovery_transmit(f.client, f.server, 0, 1) == 1);
        ok(!path->probe_only && path->path_challenge.send_at == INT64_MAX);
        ok(f.server->super.stats.num_paths.validated == validated + 1);
        multipath_progress_deliver_response(f.server, 1, path->path_challenge.data);
        ok(f.server->super.stats.num_paths.validated == validated + 1);
        ok(quicly_get_num_datagram_frames_path(f.server, 1) == 1);
        ok(multipath_received_length(f.client, stream->stream_id) == 0);
        custom_recovery_free(&f);
    }
}

/* model port translation while delivering real encrypted packets in both directions */
static size_t multipath_progress_nat_transmit(custom_recovery_fixture_t *f, int from_client)
{
    quicly_conn_t *src = from_client ? f->client : f->server, *dst = from_client ? f->server : f->client;
    quicly_address_t remote, local;
    struct iovec datagram;
    uint8_t buffer[1500];
    size_t count = 1;
    ok(quicly_send(src, &remote, &local, &datagram, &count, buffer, sizeof(buffer)) == 0);
    if (count != 0) {
        if (from_client && local.sin.sin_port == htons(20000))
            local.sin.sin_port = htons(20001);
        if (!from_client && remote.sin.sin_port == htons(20001))
            remote.sin.sin_port = htons(20000);
        quicly_decoded_packet_t decoded[4];
        size_t packets = decode_packets(decoded, &datagram, count);
        for (size_t i = 0; i < packets; ++i)
            ok(quicly_receive(dst, &remote.sa, &local.sa, decoded + i) == 0);
    }
    return count != 0 ? datagram.iov_len : 0;
}

static void test_multipath_small_rebinding(void)
{
    custom_recovery_fixture_t f;
    custom_recovery_setup(&f);
    /* rebinding needs an unused peer-issued CID in addition to amplification credit */
    ok(quicly_local_cid_set_size(&f.client->path_spaces[1]->local_cid_set, 2));
    f.client->egress.pending_flows |= QUICLY_PENDING_FLOW_OTHERS_BIT;
    for (size_t i = 0; i < 100; ++i)
        custom_recovery_round(&f, 0, 1);
    f.client_policy.data = 2;
    f.server_policy.data = 0;
    f.server_policy.eligible = UINT_MAX;
    quicly_stream_t *stream;
    ok(quicly_open_stream(f.client, &stream, 0) == 0);
    ok(quicly_set_stream_path_affinity(stream, 1) == 0);
    ok(quicly_streambuf_egress_write(stream, "rebind", 6) == 0);
    size_t received = multipath_progress_nat_transmit(&f, 1);
    ok(received != 0 && received < 400);
    size_t index = SIZE_MAX;
    for (size_t i = 0; i < QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT * QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT; ++i) {
        struct st_quicly_conn_path_t *p = get_path(f.server, i);
        if (p != NULL && p->address.remote.sin.sin_port == htons(20001))
            index = i;
    }
    ok(index != SIZE_MAX);
    if (index != SIZE_MAX) {
        struct st_quicly_conn_path_t *path = get_path(f.server, index);
        uint64_t before = f.server->super.stats.num_frames_sent.path_challenge;
        size_t sent = multipath_progress_nat_transmit(&f, 0);
        ok(sent != 0 && sent <= 3 * received);
        ok(f.server->super.stats.num_frames_sent.path_challenge == before + 1);
        ok(!path->path_challenge.sent_full_size);
        for (size_t i = 0; i < 100 && path->path_challenge.send_at != INT64_MAX; ++i) {
            ++quic_now;
            multipath_progress_nat_transmit(&f, 1);
            multipath_progress_nat_transmit(&f, 0);
        }
        ok(path->path_challenge.send_at == INT64_MAX && !path->probe_only);
        ok(get_path(f.server, 1) == path);
        ok(multipath_received_length(f.server, stream->stream_id) == 6);
    }
    custom_recovery_free(&f);
}

static void test_multipath_validation_retry_limit(void)
{
    /* responses must work both while the final challenge is outstanding and after successful validation;
     * an unanswered final challenge must still expire when its timer fires */
    for (size_t mode = 0; mode < 3; ++mode) {
        custom_recovery_fixture_t f;
        custom_recovery_setup(&f);
        quicly_local_cid_set_size(&f.server->path_spaces[0]->local_cid_set, QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT);
        f.server->egress.pending_flows |= QUICLY_PENDING_FLOW_OTHERS_BIT;
        for (size_t i = 0; i < 100; ++i)
            custom_recovery_round(&f, 0, 1);
        struct sockaddr_in remote = {.sin_family = AF_INET, .sin_port = htons(30000), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(40000), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        size_t candidate;
        lock_now(f.client, 1);
        ok(open_path(f.client, &candidate, 0, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
        unlock_now(f.client);
        struct st_quicly_conn_path_t *path = get_path(f.client, candidate);
        ok(path_has_usable_dcid(path));
        f.client_policy.eligible = 1u << candidate;
        f.client_policy.data = 0;
        quicly_address_t dst, src;
        struct iovec packet;
        uint8_t buffer[1500];
        /* drop each probe, advancing through real retry timers up to the final permitted challenge */
        for (size_t i = 0; i <= quic_ctx.max_probe_packets; ++i) {
            if (path->path_challenge.send_at > quic_now)
                quic_now = path->path_challenge.send_at;
            size_t count = 1;
            ok(quicly_send(f.client, &dst, &src, &packet, &count, buffer, sizeof(buffer)) == 0);
            ok(count == 1);
        }
        ok(path->path_challenge.num_sent == quic_ctx.max_probe_packets + 1);
        ok(path->path_challenge.send_at > quic_now);
        if (mode == 2)
            quic_now = path->path_challenge.send_at;
        lock_now(f.client, 1);
        if (mode == 1) {
            multipath_progress_deliver_response(f.client, candidate, path->path_challenge.data);
            ok(path->path_challenge.send_at == INT64_MAX);
            ok(promote_path(f.client, candidate) == 0);
            candidate = 0;
            ok(get_path(f.client, candidate) == path);
            f.client_policy.eligible = 1;
        }
        uint8_t nonce[QUICLY_PATH_CHALLENGE_DATA_LEN] = {1};
        struct st_quicly_handle_payload_state_t state = {.path_index = candidate, .src = nonce, .end = nonce + sizeof(nonce)};
        ok(handle_path_challenge_frame(f.client, &state) == 0);
        unlock_now(f.client);
        uint64_t responses = f.client->super.stats.num_frames_sent.path_response;
        uint64_t challenges = f.client->super.stats.num_frames_sent.path_challenge;
        size_t count = 1;
        ok(quicly_send(f.client, &dst, &src, &packet, &count, buffer, sizeof(buffer)) == 0);
        ok(f.client->super.stats.num_frames_sent.path_challenge == challenges);
        if (mode == 2) {
            ok(path->abandoned);
            ok(count == 0);
            ok(f.client->super.stats.num_frames_sent.path_response == responses);
        } else {
            ok(!path->abandoned);
            ok(count == 1);
            ok(!path->path_response.send_);
            ok(f.client->super.stats.num_frames_sent.path_response == responses + 1);
        }
        custom_recovery_free(&f);
    }
}
