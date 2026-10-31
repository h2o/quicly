/* Lifecycle traversal must preserve epoch isolation, PTO credit, and late-ACK state. */
static unsigned path_sentmap_callbacks;
static quicly_error_t path_sentmap_error;

static quicly_error_t path_sentmap_on_update(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked,
                                             quicly_sent_t *sent)
{
    path_sentmap_callbacks |= 1u << packet->packet_number;
    return path_sentmap_error;
}

static void test_path_sentmap(void)
{
    quicly_conn_t conn = {.super = {.state = QUICLY_STATE_CONNECTED}, .stash = {.now = 1}};
    quicly_path_space_t ps = {0};
    quicly_loss_init(&ps.loss, &quic_ctx.egress[0].loss, 100, &conn.super.remote.transport_params.max_ack_delay,
                     &conn.super.remote.transport_params.ack_delay_exponent);
    path_sentmap_callbacks = 0;
    path_sentmap_error = 0;
    for (uint64_t pn = 0; pn < 4; ++pn) {
        ok(quicly_sentmap_prepare(&ps.loss.sentmap, pn, 1, pn == 0 ? QUICLY_EPOCH_INITIAL : QUICLY_EPOCH_1RTT) == 0);
        ok(quicly_sentmap_allocate(&ps.loss.sentmap, path_sentmap_on_update) != NULL);
        quicly_sentmap_commit(&ps.loss.sentmap, 100, 0);
    }
    size_t budget = 100;
    ok(mark_frames_on_pto(&conn, &ps, QUICLY_EPOCH_1RTT, &budget) == 0);
    ok(budget == 0 && path_sentmap_callbacks == 2);
    ok(ps.loss.sentmap.bytes_in_flight == 400 && ps.loss.sentmap.num_packets == 4);
    /* The already-probed packet consumes no credit on the next pass; the last packet saturates the budget. */
    path_sentmap_callbacks = 0;
    budget = 150;
    ok(mark_frames_on_pto(&conn, &ps, QUICLY_EPOCH_1RTT, &budget) == 0);
    ok(budget == 0 && path_sentmap_callbacks == 12);
    path_sentmap_callbacks = 0;
    budget = 100;
    ok(mark_frames_on_pto(&conn, &ps, QUICLY_EPOCH_1RTT, &budget) == 0);
    ok(budget == 100 && path_sentmap_callbacks == 0);
    /* Discarding application keys must leave Initial packets intact. */
    ok(update_path_sentmap(&conn, &ps, QUICLY_SENTMAP_EVENT_EXPIRED, 1u << QUICLY_EPOCH_1RTT, NULL, 0) == 0);
    ok(ps.loss.sentmap.num_packets == 1 && ps.loss.sentmap.bytes_in_flight == 100);
    ok(update_path_sentmap(&conn, &ps, QUICLY_SENTMAP_EVENT_LOST, ~0u, NULL, 0) == 0);
    ok(path_sentmap_callbacks == 1);
    ok(ps.loss.sentmap.num_packets == 1 && ps.loss.sentmap.bytes_in_flight == 0);
    ok(update_path_sentmap(&conn, &ps, QUICLY_SENTMAP_EVENT_EXPIRED, ~0u, NULL, 0) == 0);
    ok(ps.loss.sentmap.num_packets == 0);
    /* Expiration can fail before traversal starts; propagate the callback error instead of using an unfinished iterator. */
    ok(quicly_sentmap_prepare(&ps.loss.sentmap, 4, 1, QUICLY_EPOCH_1RTT) == 0);
    ok(quicly_sentmap_allocate(&ps.loss.sentmap, path_sentmap_on_update) != NULL);
    quicly_sentmap_commit(&ps.loss.sentmap, 0, 0);
    conn.super.state = QUICLY_STATE_CLOSING;
    conn.stash.now = 100000;
    path_sentmap_callbacks = 0;
    path_sentmap_error = PTLS_ERROR_NO_MEMORY;
    ok(update_path_sentmap(&conn, &ps, QUICLY_SENTMAP_EVENT_LOST, ~0u, NULL, 1) == PTLS_ERROR_NO_MEMORY);
    ok(path_sentmap_callbacks == 16);
    quicly_loss_dispose(&ps.loss);
    path_sentmap_error = 0;
}
