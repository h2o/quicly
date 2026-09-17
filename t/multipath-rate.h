/* Exercise the ACK handler, not only the standalone rate estimator. */
static void rate_test_ack(quicly_conn_t *conn, size_t path_index, uint16_t bytes)
{
    quicly_path_space_t *ps = conn->path_spaces[path_index];
    uint64_t pn = ps->packet_number++;
    ok(quicly_sentmap_prepare(&ps->loss.sentmap, pn, quic_now - 1, QUICLY_EPOCH_1RTT) == 0);
    ps->loss.sentmap._pending_packet->data.packet.path_id = ps->path_id;
    quicly_sentmap_commit(&ps->loss.sentmap, bytes, 1, 0);
    ps->last_retransmittable_sent_at = quic_now - 1;
    quicly_ack_frame_t ack = {.largest_acknowledged = pn, .smallest_acknowledged = pn, .ack_block_lengths = {1}};
    struct st_quicly_handle_payload_state_t state = {.epoch = QUICLY_EPOCH_1RTT};
    lock_now(conn, 0);
    ok(process_ack_frame_core(conn, &state, ps->path_id, &ack) == 0);
    /* Duplicate ACKs must not add bytes to either rate estimate. */
    ok(process_ack_frame_core(conn, &state, ps->path_id, &ack) == 0);
    unlock_now(conn);
}

static void test_multipath_delivery_rate(void)
{
    int64_t orig_now = quic_now;
    uint64_t orig_max_path_id = quic_ctx.transport_params.initial_max_path_id;
    quicly_cid_encryptor_t *orig_cid_encryptor = quic_ctx.cid_encryptor;
    char cid_key[] = "0123456789abcdef";
    quic_ctx.transport_params.initial_max_path_id = 4;
    quic_ctx.cid_encryptor = quicly_new_default_cid_encryptor(&ptls_openssl_quiclb, &ptls_openssl_aes128ecb,
                                                           &ptls_openssl_sha256, ptls_iovec_init(cid_key, strlen(cid_key)));
    quicly_conn_t *client, *server;
    test_setup_connected_peers(&client, &server);
    struct sockaddr_in remote = {.sin_family = AF_INET, .sin_port = htons(12345),
                                 .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)}};
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(54321),
                                .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)}};
    ok(new_path(client, 1, 1, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
    get_path(client, 1)->probe_only = 0;

    ptls_iovec_t backlog = ptls_iovec_init("queued", 6);
    for (size_t p = 0; p != 2; ++p) {
        quicly_send_datagram_frames_path(client, p, &backlog, 1);
        quicly_ratemeter_init(&client->path_spaces[p]->ratemeter);
        quicly_ratemeter_enter_cc_limited(&client->path_spaces[p]->ratemeter, client->path_spaces[p]->packet_number);
    }
    uint64_t initial_acked = client->super.stats.num_bytes.ack_received;
    rate_test_ack(client, 0, 1000);
    rate_test_ack(client, 1, 200);

    /* Replace path one's address while its first rate sample is in progress.
     * Its address counters restart, but its packet-number-space total must not. */
    size_t candidate = encode_flat_path_index(1, 1);
    remote.sin_port = htons(12346);
    ok(new_path(client, candidate, 1, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
    get_path(client, candidate)->probe_only = 0;
    quicly_send_datagram_frames_path(client, candidate, &backlog, 1);
    lock_now(client, 0);
    ok(promote_path(client, candidate) == 0);
    unlock_now(client);
    ok(get_path(client, 1)->num_packets.bytes_acked == 0);
    for (size_t p = 0; p != 2; ++p)
        if (!quicly_ratemeter_is_cc_limited(&client->path_spaces[p]->ratemeter))
            quicly_ratemeter_enter_cc_limited(&client->path_spaces[p]->ratemeter, client->path_spaces[p]->packet_number);

    for (int step = 1; step <= 5; ++step) {
        quic_now += 10;
        /* Interleave the smaller path's ACKs between the larger path's samples. */
        rate_test_ack(client, 1, 200);
        rate_test_ack(client, 0, 1000);
        for (size_t p = 0; p != 2; ++p) {
            quicly_rate_t rate;
            quicly_ratemeter_report(&client->path_spaces[p]->ratemeter, &rate);
            ok(rate.latest == (p == 0 ? 100000 : 20000));
            ok(rate.smoothed == rate.latest);
            ok(rate.stdev == 0);
        }
    }
    /* Both partial and completed samples stay path-local; public legacy stats
     * report path zero, while the connection byte total still covers all paths. */
    ok(client->super.stats.num_bytes.ack_received - initial_acked == 6 * 1200);
    ok(get_path(client, 1)->num_packets.bytes_acked == 5 * 200);
    quicly_rate_t public_rate;
    ok(quicly_get_delivery_rate(client, &public_rate) == 0);
    ok(public_rate.latest == 100000);
    quicly_stats_t stats;
    ok(quicly_get_stats(client, &stats) == 0);
    ok(stats.delivery_rate.latest == 100000);

    quicly_free(client);
    quicly_free(server);
    quicly_free_default_cid_encryptor(quic_ctx.cid_encryptor);
    quic_ctx.cid_encryptor = orig_cid_encryptor;
    quic_ctx.transport_params.initial_max_path_id = orig_max_path_id;
    quic_now = orig_now;
}
