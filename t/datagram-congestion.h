static void test_datagram_congestion_accounting(void)
{
    uint16_t saved_max_datagram_frame_size = quic_ctx.transport_params.max_datagram_frame_size;
    quicly_receive_datagram_frame_t *saved_receiver = quic_ctx.receive_datagram_frame;
    static quicly_receive_datagram_frame_t receiver = {test_queue_receive_datagram};
    quic_ctx.transport_params.max_datagram_frame_size = 1200;
    quic_ctx.receive_datagram_frame = &receiver;

    quicly_conn_t *client, *server;
    test_setup_connected_peers(&client, &server);
    exchange_until_idle(client, server);
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
