/* Queue pressure and partial sends exercise real packets, without retransmitting DATAGRAMs. */
static void test_queue_receive_datagram(quicly_receive_datagram_frame_t *self, quicly_conn_t *conn, ptls_iovec_t payload)
{
    (void)self;
    (void)conn;
    (void)payload;
}

static void test_datagram_queue_partial_send(void)
{
    quicly_context_t saved = quic_ctx;
    static quicly_receive_datagram_frame_t receiver = {test_queue_receive_datagram};
    quic_ctx.max_datagram_frame_payloads = 64;
    quic_ctx.transport_params.max_datagram_frame_size = 1200;
    quic_ctx.receive_datagram_frame = &receiver;
    quicly_conn_t *client, *server;
    test_setup_connected_peers(&client, &server);
    exchange_until_idle(client, server);
    uint8_t bytes[1000] = {0};
    ptls_iovec_t payload = ptls_iovec_init(bytes, sizeof(bytes));
    ok(get_path(client, 0)->datagram_frame_payloads.entries == NULL);
    size_t capacity = quicly_get_max_datagram_frames_path(client, 0);
    for (size_t i = 0; i < capacity; ++i)
        quicly_send_datagram_frames(client, &payload, 1);
    ok(get_path(client, 0)->datagram_frame_payloads.entries != NULL);
    ok(get_path(server, 0)->datagram_frame_payloads.entries == NULL);
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

static void test_datagram_queue_capacity(size_t capacity)
{
    quicly_context_t ctx = quic_ctx;
    ctx.max_datagram_frame_payloads = capacity;
    quicly_conn_t conn = {0};
    quicly_path_space_t ps = {0};
    struct st_quicly_conn_path_t path = {0};
    conn.super.ctx = &ctx;
    conn.path_spaces[0] = &ps;
    ps.addrs[0] = &path;
    path.path_space = &ps;
    ok(quicly_get_max_datagram_frames_path(&conn, 0) == capacity);
    quicly_send_datagram_frames_path(&conn, 0, NULL, 0);
    ok(path.datagram_frame_payloads.entries == NULL);

    for (size_t i = 0; i != capacity + 1; ++i) {
        uint8_t value = (uint8_t)i;
        ptls_iovec_t payload = ptls_iovec_init(&value, 1);
        quicly_send_datagram_frames_path(&conn, 0, &payload, 1);
    }
    ok(quicly_get_num_datagram_frames_path(&conn, 0) == capacity);
    /* Refill a freed slot and check the copied payloads stay in FIFO order after wrapping. */
    consume_path_datagram_frame_payloads(&path, 1);
    uint8_t value = (uint8_t)capacity;
    ptls_iovec_t payload = ptls_iovec_init(&value, 1);
    quicly_send_datagram_frames_path(&conn, 0, &payload, 1);
    value = UINT8_MAX;
    ok(quicly_get_num_datagram_frames_path(&conn, 0) == capacity);
    for (size_t i = 1; i <= capacity; ++i) {
        ptls_iovec_t first = path.datagram_frame_payloads.entries[path.datagram_frame_payloads.head];
        ok(first.len == 1 && *(uint8_t *)first.base == i);
        consume_path_datagram_frame_payloads(&path, 1);
    }
    ok(quicly_get_num_datagram_frames_path(&conn, 0) == 0);
    quicly_send_datagram_frames_path(&conn, 0, &payload, 1);
    ok(quicly_get_num_datagram_frames_path(&conn, 0) == 1);
    clear_path_datagram_frame_payloads(&path);
    ok(path.datagram_frame_payloads.entries == NULL && quicly_get_num_datagram_frames_path(&conn, 0) == 0);
}

static void test_datagram_queue_overflow(void)
{
    quicly_context_t ctx = quic_ctx;
    quicly_conn_t conn = {0};
    quicly_path_space_t ps = {0};
    struct st_quicly_conn_path_t path = {0};
    conn.super.ctx = &ctx;
    conn.path_spaces[0] = &ps;
    ps.addrs[0] = &path;
    path.path_space = &ps;
    ptls_iovec_t payloads[] = {ptls_iovec_init("a", 1), ptls_iovec_init("b", 1)};
    size_t capacities[] = {SIZE_MAX / sizeof(ptls_iovec_t) + 1, SIZE_MAX / sizeof(ptls_iovec_t) + 2, SIZE_MAX};
    for (size_t i = 0; i != PTLS_ELEMENTSOF(capacities); ++i) {
        ctx.max_datagram_frame_payloads = capacities[i];
        quicly_send_datagram_frames_path(&conn, 0, payloads, PTLS_ELEMENTSOF(payloads));
        ok(path.datagram_frame_payloads.entries == NULL && quicly_get_num_datagram_frames_path(&conn, 0) == 0);
        clear_path_datagram_frame_payloads(&path);
    }
    /* Rejected capacities must leave the queue usable after correcting the configuration. */
    ctx.max_datagram_frame_payloads = 2;
    quicly_send_datagram_frames_path(&conn, 0, payloads, PTLS_ELEMENTSOF(payloads));
    ok(quicly_get_num_datagram_frames_path(&conn, 0) == PTLS_ELEMENTSOF(payloads));
    clear_path_datagram_frame_payloads(&path);
}

static void test_datagram_queue(void)
{
    subtest("partial-send", test_datagram_queue_partial_send);
    subtest("capacity-one", test_datagram_queue_capacity, 1);
    subtest("capacity-two", test_datagram_queue_capacity, 2);
    subtest("capacity-three", test_datagram_queue_capacity, 3);
    subtest("overflow", test_datagram_queue_overflow);
}

static void test_sparse_datagram_queues(void)
{
    quicly_conn_t conn = {0};
    quicly_path_space_t ps = {0};
    struct st_quicly_conn_path_t path = {0};
    ok(!quicly_has_datagram_frames(&conn));
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
