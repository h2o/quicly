/* Queue pressure and partial sends exercise real packets, without retransmitting DATAGRAMs. */
static void test_queue_receive_datagram(quicly_receive_datagram_frame_t *self, quicly_conn_t *conn, ptls_iovec_t payload)
{
    (void)self;
    (void)conn;
    (void)payload;
}

static void test_datagram_queue(void)
{
    quicly_context_t saved = quic_ctx;
    static quicly_receive_datagram_frame_t receiver = {test_queue_receive_datagram};
    quic_ctx.transport_params.max_datagram_frame_size = 1200;
    quic_ctx.receive_datagram_frame = &receiver;
    quicly_conn_t *client, *server;
    test_setup_connected_peers(&client, &server);
    exchange_until_idle(client, server);
    uint8_t bytes[1000] = {0};
    ptls_iovec_t payload = ptls_iovec_init(bytes, sizeof(bytes));
    size_t capacity = PTLS_ELEMENTSOF(get_path(client, 0)->datagram_frame_payloads.payloads);
    for (size_t i = 0; i < capacity; ++i)
        quicly_send_datagram_frames(client, &payload, 1);
    ok(quicly_get_num_datagram_frames_path(client, 0) == capacity);
    quicly_send_datagram_frames(client, &payload, 1);
    ok(quicly_get_num_datagram_frames_path(client, 0) == capacity);
    quicly_address_t dest, src;
    struct iovec datagrams[2];
    uint8_t buffer[3000];
    size_t count = PTLS_ELEMENTSOF(datagrams);
    uint64_t frames = client->super.stats.num_frames_sent.datagram;
    ok(quicly_send(client, &dest, &src, datagrams, &count, buffer, sizeof(buffer)) == 0);
    ok(count > 0 && count < capacity);
    ok(quicly_get_num_datagram_frames_path(client, 0) == capacity - count);
    ok(client->super.stats.num_frames_sent.datagram - frames == count);
    /* Only the freed slots can be refilled. Closing also frees the unsent suffix. */
    for (size_t i = 0; i < count; ++i)
        quicly_send_datagram_frames(client, &payload, 1);
    ok(quicly_get_num_datagram_frames_path(client, 0) == capacity);
    quicly_free(client);
    quicly_free(server);
    quic_ctx = saved;
}

static void test_sparse_datagram_queues(void)
{
    quicly_conn_t conn = {0};
    quicly_path_space_t ps = {0};
    struct st_quicly_conn_path_t path = {0};
    ok(!quicly_has_datagram_frames(&conn));
    conn.egress.datagram_frame_payloads.count = 1;
    ok(quicly_has_datagram_frames(&conn));
    conn.egress.datagram_frame_payloads.count = 0;
    /* Holes and the highest candidate index must not hide queued work.
     * Abandoned paths retain their queues until the normal cleanup runs. */
    for (size_t i = 0; i < PTLS_ELEMENTSOF(conn.path_spaces); ++i) {
        conn.path_spaces[i] = &ps;
        for (size_t j = 0; j < PTLS_ELEMENTSOF(ps.addrs); ++j) {
            ps.addrs[j] = &path;
            path.datagram_frame_payloads.count = 0;
            ok(!quicly_has_datagram_frames(&conn));
            path.datagram_frame_payloads.count = 1;
            path.abandoned = j % 2;
            ok(quicly_has_datagram_frames(&conn));
            ps.addrs[j] = NULL;
        }
        conn.path_spaces[i] = NULL;
    }
    ok(!quicly_has_datagram_frames(&conn));
}
