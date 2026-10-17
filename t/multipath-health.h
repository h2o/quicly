/* automatic failover tests */
static quicly_stream_callbacks_t health_stream_callbacks;

static quicly_error_t health_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    quicly_error_t ret = on_stream_open(self, stream);
    if (ret == 0)
        stream->callbacks = &health_stream_callbacks;
    return ret;
}

static quicly_stream_open_t health_stream_open = {health_on_stream_open};

static void health_setup_with_policy(quicly_conn_t **client, quicly_conn_t **server, unsigned threshold)
{
    health_stream_callbacks = stream_callbacks;
    health_stream_callbacks.on_destroy = quicly_streambuf_destroy;
    quic_ctx.stream_open = &health_stream_open;
    quic_ctx.transport_params.initial_max_path_id = 4;
    quic_ctx.multipath_failover_pto_threshold = threshold;
    quic_ctx.path_scheduler = &quicly_round_robin_path_scheduler;
    char key[] = "0123456789abcdef";
    quic_ctx.cid_encryptor = quicly_new_default_cid_encryptor(&ptls_openssl_quiclb, &ptls_openssl_aes128ecb, &ptls_openssl_sha256,
                                                              ptls_iovec_init(key, strlen(key)));
    test_setup_connected_peers(client, server);
    get_path(*client, 0)->address.local = get_path(*client, 0)->address.remote = fake_address;
    get_path(*server, 0)->address.local = get_path(*server, 0)->address.remote = fake_address;
    struct sockaddr_in remote = {.sin_family = AF_INET, .sin_port = htons(10000), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(20000), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    ok(quicly_open_path(*client, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
    for (size_t i = 0; i < 100; ++i) {
        ++quic_now;
        transmit_multipath(*client, *server);
        transmit_multipath(*server, *client);
    }
    ok(get_path(*client, 1)->path_challenge.send_at == INT64_MAX);
    ok(!get_path(*client, 1)->probe_only);
}

static void health_setup(quicly_conn_t **client, quicly_conn_t **server)
{
    health_setup_with_policy(client, server, 2);
}

static void test_multipath_automatic_failover_with_scheduler(quicly_path_scheduler_t *scheduler)
{
    quicly_context_t saved = quic_ctx;
    int64_t saved_now = quic_now;
    quicly_conn_t *client, *server;
    health_setup(&client, &server);
    quicly_stream_t *stream;
    ok(quicly_open_stream(client, &stream, 0) == 0);
    uint8_t data[50000];
    for (size_t i = 0; i < sizeof(data); ++i)
        data[i] = (uint8_t)(i * 13 + i / 31);
    ok(quicly_streambuf_egress_write(stream, data, sizeof(data)) == 0);
    quicly_stream_t *reverse;
    ok(quicly_open_stream(server, &reverse, 0) == 0);
    ok(quicly_streambuf_egress_write(reverse, data, sizeof(data)) == 0);
    /* force first flight onto dropped path */
    client->next_send_path_index = 1;
    ok(transmit_multipath_with_loss(client, server, 20000) == 0);
    quic_ctx.path_scheduler = scheduler;
    quicly_stream_t *received = NULL;
    size_t elapsed, offered = sizeof(data);
    for (elapsed = 0; elapsed < 5000; ++elapsed) {
        /* keep fresh data ready across PTO */
        ok(quicly_streambuf_egress_write(stream, data, 1000) == 0);
        offered += 1000;
        ++quic_now;
        transmit_multipath_with_loss(client, server, 20000);
        transmit_multipath(server, client);
        received = quicly_get_stream(server, stream->stream_id);
        if (received != NULL && quicly_streambuf_ingress_get(received).len >= sizeof(data))
            break;
    }
    ok(elapsed < 5000);
    ok(get_path(client, 1) != NULL && !get_path(client, 1)->abandoned);
    ok(client->path_spaces[1]->health.state == QUICLY_PATH_SUSPECT);
    quicly_path_health_t stats;
    ok(quicly_get_path_health(client, 1, &stats) == 0);
    ok(stats.state == QUICLY_PATH_SUSPECT);
    ok(received != NULL);
    if (received != NULL) {
        ptls_iovec_t bytes = quicly_streambuf_ingress_get(received);
        ok(bytes.len >= sizeof(data));
        if (bytes.len >= sizeof(data))
            ok(memcmp(bytes.base, data, sizeof(data)) == 0);
    }
    /* probes must remain bounded by PTO backoff */
    uint64_t packets_before = get_path(client, 1)->num_packets.sent;
    int pto_before = client->path_spaces[1]->loss.pto_count;
    for (size_t i = 0; i < 5000; ++i) {
        ++quic_now;
        transmit_multipath_with_loss(client, server, 20000);
        transmit_multipath(server, client);
    }
    ok(get_path(client, 1)->num_packets.sent - packets_before <= 20);
    ok(client->path_spaces[1]->loss.pto_count > pto_before);
    ok(client->path_spaces[1]->health.state == QUICLY_PATH_SUSPECT);
    received = quicly_get_stream(server, stream->stream_id);
    ok(received != NULL && quicly_streambuf_ingress_get(received).len == offered);
    quicly_stream_t *reverse_received = quicly_get_stream(client, reverse->stream_id);
    ok(reverse_received != NULL && quicly_streambuf_ingress_get(reverse_received).len == sizeof(data));
    if (reverse_received != NULL && quicly_streambuf_ingress_get(reverse_received).len == sizeof(data))
        ok(memcmp(quicly_streambuf_ingress_get(reverse_received).base, data, sizeof(data)) == 0);
    /* restore blackholed path and verify recovery */
    size_t recovered_after;
    for (recovered_after = 0; recovered_after < 20000; ++recovered_after) {
        ok(quicly_streambuf_egress_write(stream, data, 1000) == 0);
        offered += 1000;
        ++quic_now;
        transmit_multipath(client, server);
        transmit_multipath(server, client);
        if (client->path_spaces[1]->health.state == QUICLY_PATH_USABLE)
            break;
    }
    ok(recovered_after < 20000);
    for (size_t i = 0; i < 1000; ++i) {
        ++quic_now;
        transmit_multipath(client, server);
        transmit_multipath(server, client);
    }
    ok(quicly_streambuf_ingress_get(received).len == offered);
    quicly_free(client);
    quicly_free(server);
    quicly_free_default_cid_encryptor(quic_ctx.cid_encryptor);
    quic_ctx = saved;
    quic_now = saved_now;
}

/* verify recovery when scheduler avoids suspect path */
static quicly_error_t health_primary_only_scheduler(quicly_path_scheduler_t *scheduler, quicly_conn_t *conn,
                                                    quicly_send_context_t *send_context)
{
    (void)scheduler;
    return quicly_send_on_path(conn, send_context, 0, NULL);
}

static void test_multipath_automatic_failover(void)
{
    test_multipath_automatic_failover_with_scheduler(&quicly_round_robin_path_scheduler);
    test_multipath_automatic_failover_with_scheduler(&quicly_default_path_scheduler);
    quicly_path_scheduler_t primary_only = {health_primary_only_scheduler};
    test_multipath_automatic_failover_with_scheduler(&primary_only);
}

/* disabling health suppression retains the target branch's existing reliable recovery */
static void test_multipath_failover_disabled(void)
{
    quicly_context_t saved = quic_ctx;
    int64_t saved_now = quic_now;
    quicly_conn_t *client, *server;
    health_setup_with_policy(&client, &server, 0);
    quicly_stream_t *stream;
    ok(quicly_open_stream(client, &stream, 0) == 0);
    uint8_t data[50000] = {0};
    ok(quicly_streambuf_egress_write(stream, data, sizeof(data)) == 0);
    client->next_send_path_index = 1;
    ok(transmit_multipath_with_loss(client, server, 20000) == 0);
    for (size_t elapsed = 0; elapsed < 1000; ++elapsed) {
        ok(quicly_streambuf_egress_write(stream, data, 1000) == 0);
        ++quic_now;
        transmit_multipath_with_loss(client, server, 20000);
        transmit_multipath(server, client);
    }
    quicly_stream_t *received = quicly_get_stream(server, stream->stream_id);
    /* normal bounded PTO retransmission still advances the early prefix without opting into full-flight failover */
    ok(received != NULL && quicly_streambuf_ingress_get(received).len > 0);
    quicly_path_health_t stats;
    ok(quicly_get_path_health(client, 1, &stats) == 0);
    ok(stats.state == QUICLY_PATH_USABLE);
    quicly_free(client);
    quicly_free(server);
    quicly_free_default_cid_encryptor(quic_ctx.cid_encryptor);
    quic_ctx = saved;
    quic_now = saved_now;
}

static uint64_t health_prepare_packet(quicly_path_space_t *ps, int ack_eliciting)
{
    uint64_t pn = ps->packet_number++;
    ok(quicly_sentmap_prepare(&ps->loss.sentmap, pn, quic_now - 1, QUICLY_EPOCH_1RTT) == 0);
    ps->loss.sentmap._pending_packet->data.packet.path_id = ps->path_id;
    quicly_sentmap_commit(&ps->loss.sentmap, ack_eliciting ? 100 : 0, ack_eliciting, 0);
    ps->last_retransmittable_sent_at = quic_now - 1;
    return pn;
}

static void health_ack_packet(quicly_conn_t *conn, quicly_path_space_t *ps, uint64_t pn)
{
    quicly_ack_frame_t ack = {.largest_acknowledged = pn, .smallest_acknowledged = pn, .ack_block_lengths = {1}};
    /* receive feedback on path 0 for path 1 data */
    struct st_quicly_handle_payload_state_t state = {.epoch = QUICLY_EPOCH_1RTT, .path_index = 0};
    ok(process_ack_frame_core(conn, &state, ps->path_id, &ack) == 0);
}

static void test_multipath_health_progress(void)
{
    quicly_context_t saved = quic_ctx;
    int64_t saved_now = quic_now;
    quicly_conn_t *client, *server;
    health_setup(&client, &server);
    quicly_path_space_t *bad = client->path_spaces[1], *other = client->path_spaces[0];
    lock_now(client, 0);
    for (uint32_t rtt = 20; rtt <= 80; rtt *= 2) {
        other->loss.rtt.smoothed = other->loss.rtt.latest = rtt;
        other->loss.rtt.variance = rtt / 2;
        other->health.last_ack_at = client->stash.now;
        ok(path_has_health_alternative(client, bad, 1));
        other->health.last_ack_at = client->stash.now - 10000;
        ok(!path_has_health_alternative(client, bad, 1));
        ok(path_has_health_alternative(client, bad, 0));
    }
    other->health.last_ack_at = client->stash.now;
    get_path(client, 0)->probe_only = 1;
    ok(!path_has_health_alternative(client, bad, 1));
    get_path(client, 0)->probe_only = 0;
    get_path(client, 0)->path_challenge.send_at = client->stash.now;
    ok(!path_has_health_alternative(client, bad, 1));
    get_path(client, 0)->path_challenge.send_at = INT64_MAX;
    other->health.state = QUICLY_PATH_SUSPECT;
    ok(!path_has_health_alternative(client, bad, 0));
    other->health.state = QUICLY_PATH_USABLE;
    other->loss.pto_count = 2;
    ok(!path_has_health_alternative(client, bad, 1));
    other->loss.pto_count = 0;

    uint64_t old = health_prepare_packet(bad, 1);
    bad->health.state = QUICLY_PATH_SUSPECT;
    bad->health.fresh_from_pn = bad->packet_number;
    int64_t alternate_progress = other->health.last_ack_at;
    health_ack_packet(client, bad, old);
    ok(bad->health.state == QUICLY_PATH_SUSPECT);
    uint64_t not_eliciting = health_prepare_packet(bad, 0);
    health_ack_packet(client, bad, not_eliciting);
    ok(bad->health.state == QUICLY_PATH_SUSPECT);
    uint64_t fresh = health_prepare_packet(bad, 1);
    health_ack_packet(client, bad, fresh);
    ok(bad->health.state == QUICLY_PATH_RECOVERING);
    health_ack_packet(client, bad, fresh); /* duplicate ACK does not complete recovery */
    ok(bad->health.state == QUICLY_PATH_RECOVERING);
    bad->cc.cwnd = 1000000;
    int saved_egress = client->egress.alt_ctx;
    client->egress.alt_ctx = 1;
    quic_ctx.egress[1].cc.initcwnd_packets = 3;
    size_t initial = quicly_cc_calc_initial_cwnd(get_egress_context(client)->cc.initcwnd_packets, bad->max_udp_payload_size);
    size_t window = calc_send_window(client, bad, 0, UINT64_MAX, UINT64_MAX, 0);
    ok(window <= initial);
    health_ack_packet(client, bad, health_prepare_packet(bad, 1));
    ok(bad->health.state == QUICLY_PATH_USABLE);
    ok(calc_send_window(client, bad, 0, UINT64_MAX, UINT64_MAX, 0) > initial);
    ok(other->health.last_ack_at == alternate_progress);
    client->egress.alt_ctx = saved_egress;
    unlock_now(client);
    quicly_free(client);
    quicly_free(server);
    quicly_free_default_cid_encryptor(quic_ctx.cid_encryptor);
    quic_ctx = saved;
    quic_now = saved_now;
}

static void test_multipath_suspect_affinity(void)
{
    quicly_context_t saved = quic_ctx;
    int64_t saved_now = quic_now;
    quicly_conn_t *client, *server;
    health_setup(&client, &server);
    quicly_stream_t *affine, *mobile;
    ok(quicly_open_stream(client, &affine, 0) == 0);
    ok(quicly_set_stream_path_affinity(affine, 1) == 0);
    ok(quicly_open_stream(client, &mobile, 0) == 0);
    uint8_t data[50000] = {7};
    ok(quicly_streambuf_egress_write(affine, data, sizeof(data)) == 0);
    ok(quicly_streambuf_egress_write(mobile, data, sizeof(data)) == 0);
    client->next_send_path_index = 1;
    for (size_t i = 0; i < 1000; ++i) {
        ++quic_now;
        transmit_multipath_with_loss(client, server, 20000);
        transmit_multipath(server, client);
    }
    ok(client->path_spaces[1]->health.state == QUICLY_PATH_SUSPECT);
    quicly_stream_t *received = quicly_get_stream(server, affine->stream_id);
    ok(received == NULL || quicly_streambuf_ingress_get(received).len == 0);
    received = quicly_get_stream(server, mobile->stream_id);
    ok(received != NULL && quicly_streambuf_ingress_get(received).len == sizeof(data));
    ok(affine->affinity_path_id == 1);
    ok(quicly_get_first_timeout(client) > quic_now);
    /* affine stream resumes after recovery */
    for (size_t i = 0; i < 5000; ++i) {
        ++quic_now;
        transmit_multipath(client, server);
        transmit_multipath(server, client);
        received = quicly_get_stream(server, affine->stream_id);
        if (received != NULL && quicly_streambuf_ingress_get(received).len == sizeof(data))
            break;
    }
    ok(received != NULL && quicly_streambuf_ingress_get(received).len == sizeof(data));
    ok(affine->affinity_path_id == 1);
    quicly_free(client);
    quicly_free(server);
    quicly_free_default_cid_encryptor(quic_ctx.cid_encryptor);
    quic_ctx = saved;
    quic_now = saved_now;
}

struct health_delayed_packet {
    struct health_delayed_packet *next;
    quicly_conn_t *receiver;
    quicly_address_t dest, src;
    int64_t at;
    size_t len;
    uint8_t bytes[];
};

static void health_deliver_due(struct health_delayed_packet **queue)
{
    for (struct health_delayed_packet **at = queue; *at != NULL;) {
        struct health_delayed_packet *packet = *at;
        if (packet->at > quic_now) {
            at = &packet->next;
            continue;
        }
        *at = packet->next;
        struct iovec raw = {.iov_base = packet->bytes, .iov_len = packet->len};
        quicly_decoded_packet_t decoded[4];
        size_t count = decode_packets(decoded, &raw, 1);
        for (size_t i = 0; i < count; ++i) {
            quicly_error_t ret = quicly_receive(packet->receiver, &packet->dest.sa, &packet->src.sa, decoded + i);
            ok(ret == 0 || ret == QUICLY_ERROR_PACKET_IGNORED);
        }
        free(packet);
    }
}

/* drop_port: -1 no fault, -2 blackhole all paths */
static void health_delayed_send(quicly_conn_t *sender, quicly_conn_t *receiver, struct health_delayed_packet **queue,
                                uint32_t delay, int drop_port)
{
    quicly_address_t dest, src;
    struct iovec datagrams[32];
    uint8_t bytes[32 * 1500];
    size_t count = PTLS_ELEMENTSOF(datagrams);
    ok(quicly_send(sender, &dest, &src, datagrams, &count, bytes, sizeof(bytes)) == 0);
    if (drop_port == -2 || (count != 0 && ntohs(src.sin.sin_port) == drop_port))
        return;
    /* append in send order */
    struct health_delayed_packet **tail = queue;
    while (*tail != NULL)
        tail = &(*tail)->next;
    for (size_t i = 0; i < count; ++i) {
        struct health_delayed_packet *packet = malloc(sizeof(*packet) + datagrams[i].iov_len);
        assert(packet != NULL);
        *packet = (struct health_delayed_packet){
            .receiver = receiver, .dest = dest, .src = src, .at = quic_now + delay, .len = datagrams[i].iov_len};
        memcpy(packet->bytes, datagrams[i].iov_base, packet->len);
        *tail = packet;
        tail = &packet->next;
    }
}

static void test_multipath_health_rtt_matrix(void)
{
    for (uint32_t rtt = 20; rtt <= 80; rtt *= 2) {
        for (size_t failed_path = 0; failed_path < 3; ++failed_path) {
            quicly_context_t saved = quic_ctx;
            int64_t saved_now = quic_now;
            quicly_conn_t *client, *server;
            health_setup(&client, &server);
            for (size_t i = 0; i < 2; ++i) {
                quicly_conn_t *conn = i == 0 ? client : server;
                for (size_t p = 0; p < 2; ++p) {
                    conn->path_spaces[p]->loss.rtt.smoothed = conn->path_spaces[p]->loss.rtt.latest = rtt;
                    conn->path_spaces[p]->loss.rtt.minimum = rtt;
                    conn->path_spaces[p]->loss.rtt.variance = rtt / 4;
                }
            }
            struct health_delayed_packet *queue = NULL;
            quicly_stream_t *stream, *received = NULL;
            ok(quicly_open_stream(client, &stream, 0) == 0);
            uint8_t data[50000];
            memset(data, 91, sizeof(data));
            ok(quicly_streambuf_egress_write(stream, data, sizeof(data)) == 0);
            client->next_send_path_index = failed_path % 2;
            size_t elapsed;
            for (elapsed = 0; elapsed < 5000; ++elapsed) {
                ++quic_now;
                health_deliver_due(&queue);
                ok(quicly_streambuf_egress_write(stream, data, 1000) == 0);
                int drop = failed_path == 0 ? 0 : 20000;
                if (failed_path == 2)
                    drop = elapsed < 1000 ? -2 : -1;
                health_delayed_send(client, server, &queue, rtt / 2, drop);
                health_delayed_send(server, client, &queue, rtt / 2, failed_path == 2 && elapsed < 1000 ? -2 : -1);
                received = quicly_get_stream(server, stream->stream_id);
                if (received != NULL && quicly_streambuf_ingress_get(received).len >= sizeof(data))
                    break;
            }
            ok(elapsed < 5000);
            ok(received != NULL && quicly_streambuf_ingress_get(received).len >= sizeof(data));
            if (received != NULL && quicly_streambuf_ingress_get(received).len >= sizeof(data))
                ok(memcmp(quicly_streambuf_ingress_get(received).base, data, sizeof(data)) == 0);
            if (failed_path < 2)
                ok(client->path_spaces[failed_path]->health.state == QUICLY_PATH_SUSPECT);
            fprintf(stderr, "RTT %u ms, failed path %zu (2=all): prefix after %zu ms\n", rtt, failed_path, elapsed);
            while (queue != NULL) {
                struct health_delayed_packet *next = queue->next;
                free(queue);
                queue = next;
            }
            quicly_free(client);
            quicly_free(server);
            quicly_free_default_cid_encryptor(quic_ctx.cid_encryptor);
            quic_ctx = saved;
            quic_now = saved_now;
        }
    }
}
