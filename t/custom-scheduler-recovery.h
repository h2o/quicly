/* the scheduler and its hooks deliberately use only public APIs and never delegate to a built-in scheduler. */
typedef struct st_custom_recovery_policy_t {
    unsigned eligible, data;
    size_t preferred;
    size_t maintenance_packets, data_packets, empty_maintenance;
    int duplicate_packets;
    size_t received_datagrams;
} custom_recovery_policy_t;

static int custom_recovery_eligible(quicly_path_scheduler_t *self, quicly_conn_t *conn, size_t path_index)
{
    custom_recovery_policy_t *policy = *quicly_get_data(conn);
    return path_index < 32 && (policy->eligible & (1u << path_index)) != 0;
}

static int custom_recovery_data_ready(quicly_path_scheduler_t *self, quicly_conn_t *conn, size_t path_index)
{
    custom_recovery_policy_t *policy = *quicly_get_data(conn);
    return path_index < 32 && (policy->data & (1u << path_index)) != 0;
}

static quicly_error_t custom_recovery_send_data(quicly_path_scheduler_t *self, quicly_conn_t *conn, quicly_send_context_t *s)
{
    custom_recovery_policy_t *policy = *quicly_get_data(conn);
    size_t count = 0;
    quicly_error_t ret;
    /* the application chooses its own order. health is a fact, not an imposed backup policy. */
    size_t first = policy->preferred;
    quicly_path_health_t health;
    if (quicly_get_path_health(conn, first, &health) == 0 && health.pto_count >= 2)
        first ^= 1;
    for (size_t n = 0; n < 2; ++n) {
        size_t index = first ^ n;
        if (!custom_recovery_eligible(self, conn, index) || !custom_recovery_data_ready(self, conn, index) ||
            !quicly_is_path_available(conn, index))
            continue;
        if ((ret = quicly_send_on_path(conn, s, index, &count)) != 0)
            return ret;
        if (count != 0) {
            policy->data_packets += count;
            break;
        }
    }
    return 0;
}

static quicly_error_t custom_recovery_send(quicly_path_scheduler_t *self, quicly_conn_t *conn, quicly_send_context_t *s)
{
    custom_recovery_policy_t *policy = *quicly_get_data(conn);
    quicly_stats_t before, after;
    quicly_get_stats(conn, &before);
    size_t count = 0;
    quicly_error_t ret = quicly_send_path_maintenance(conn, s, &count);
    quicly_get_stats(conn, &after);
    ok(after.num_frames_sent.stream == before.num_frames_sent.stream);
    ok(after.num_frames_sent.datagram == before.num_frames_sent.datagram);
    if (ret != 0)
        return ret;
    if (count != 0) {
        size_t repeated = 0;
        ok(quicly_send_path_maintenance(conn, s, &repeated) == 0);
        ok(repeated == count);
        return 0;
    }
    ++policy->empty_maintenance;
    return custom_recovery_send_data(self, conn, s);
}

static quicly_path_scheduler_t custom_recovery_scheduler = {custom_recovery_send, custom_recovery_eligible,
                                                            custom_recovery_data_ready};
static quicly_path_scheduler_t custom_data_only_scheduler = {custom_recovery_send_data, custom_recovery_eligible,
                                                             custom_recovery_data_ready};

static void custom_recovery_receive_datagram(quicly_receive_datagram_frame_t *self, quicly_conn_t *conn, ptls_iovec_t payload)
{
    custom_recovery_policy_t *policy = *quicly_get_data(conn);
    ++policy->received_datagrams;
}

typedef struct st_custom_recovery_fixture_t {
    quicly_conn_t *client, *server;
    custom_recovery_policy_t client_policy, server_policy;
    quicly_context_t saved;
    int64_t saved_now, bound;
} custom_recovery_fixture_t;

static void custom_recovery_setup(custom_recovery_fixture_t *f)
{
    *f = (custom_recovery_fixture_t){.saved = quic_ctx,
                                     .saved_now = quic_now,
                                     .client_policy = {.eligible = 3, .data = 3},
                                     .server_policy = {.eligible = 3, .data = 3}};
    static quicly_receive_datagram_frame_t receiver = {custom_recovery_receive_datagram};
    quic_ctx.transport_params.max_datagram_frame_size = 1200;
    quic_ctx.transport_params.max_data = 1024 * 1024;
    quic_ctx.transport_params.max_stream_data.bidi_local = quic_ctx.transport_params.max_stream_data.bidi_remote = 1024 * 1024;
    quic_ctx.receive_datagram_frame = &receiver;
    setup_multipath_scheduling_peers(&f->client, &f->server, &quicly_default_path_scheduler);
    *quicly_get_data(f->client) = &f->client_policy;
    *quicly_get_data(f->server) = &f->server_policy;
    quic_ctx.path_scheduler = &custom_recovery_scheduler;
    /* allow six exponentially backed-off PTO intervals, plus packet/ACK exchange, with a finite 8KB initial transfer. */
    f->bound = (int64_t)ceil(64 * get_max_pto(f->client)) + 100;
}

static void custom_recovery_free(custom_recovery_fixture_t *f)
{
    free_multipath_regression_peers(f->client, f->server, f->saved);
    quic_now = f->saved_now;
}

static size_t custom_recovery_transmit(quicly_conn_t *src, quicly_conn_t *dst, unsigned drop, size_t budget)
{
    quicly_address_t remote, local;
    struct iovec datagrams[16];
    uint8_t buffer[16 * 1500];
    size_t count = budget;
    quicly_stats_t before, after;
    quicly_get_stats(src, &before);
    ok(count <= PTLS_ELEMENTSOF(datagrams));
    ok(quicly_send(src, &remote, &local, datagrams, &count, buffer, budget * 1500) == 0);
    quicly_get_stats(src, &after);
    if (count != 0) {
        custom_recovery_policy_t *policy = *quicly_get_data(src);
        if (before.num_frames_sent.stream == after.num_frames_sent.stream &&
            before.num_frames_sent.datagram == after.num_frames_sent.datagram)
            policy->maintenance_packets += count;
        size_t path = local.sin.sin_port == 0 ? 0 : 1;
        ok(custom_recovery_eligible(&custom_recovery_scheduler, src, path));
        ok(count <= budget);
        if ((drop & (1u << path)) == 0) {
            quicly_decoded_packet_t decoded[32];
            size_t packets = decode_packets(decoded, datagrams, count);
            for (size_t i = 0; i < packets; ++i) {
                quicly_error_t ret = quicly_receive(dst, &remote.sa, &local.sa, decoded + i);
                ok(ret == 0 || ret == QUICLY_ERROR_PACKET_IGNORED);
                if (policy->duplicate_packets) {
                    quicly_path_stats_t before[2], after[2];
                    for (size_t p = 0; p < 2; ++p)
                        ok(quicly_get_path_stats(dst, p, before + p) == 0);
                    ret = quicly_receive(dst, &remote.sa, &local.sa, decoded + i);
                    ok(ret == 0 || ret == QUICLY_ERROR_PACKET_IGNORED);
                    for (size_t p = 0; p < 2; ++p) {
                        ok(quicly_get_path_stats(dst, p, after + p) == 0);
                        ok(before[p].bytes_in_flight == after[p].bytes_in_flight);
                    }
                }
            }
        }
    }
    return count;
}

static void custom_recovery_round(custom_recovery_fixture_t *f, unsigned drop, size_t budget)
{
    ++quic_now;
    custom_recovery_transmit(f->client, f->server, drop, budget);
    custom_recovery_transmit(f->server, f->client, drop, budget);
}

static void test_custom_recovery_blackhole(void)
{
    for (int sustained = 0; sustained < 2; ++sustained) {
        custom_recovery_fixture_t f;
        custom_recovery_setup(&f);
        /* ACKs and PTO probes must also progress without a maintenance helper or automatic failover. */
        if (sustained) {
            quic_ctx.path_scheduler = &custom_data_only_scheduler;
            quic_ctx.multipath_failover_pto_threshold = 0;
        }
        quicly_stream_t *stream;
        ok(quicly_open_stream(f.client, &stream, 0) == 0);
        uint8_t initial[8000];
        for (size_t i = 0; i < sizeof(initial); ++i)
            initial[i] = (uint8_t)(i * 13);
        ok(quicly_streambuf_egress_write(stream, initial, sizeof(initial)) == 0);
        size_t initial_packets = custom_recovery_transmit(f.client, f.server, 1, 16);
        ok(initial_packets != 0);
        ok(multipath_received_length(f.server, stream->stream_id) == 0);
        int64_t until = quic_now + f.bound;
        size_t appended = 0;
        quicly_stream_t *reverse = NULL;
        if (sustained) {
            f.server_policy.duplicate_packets = 1;
            ok(quicly_open_stream(f.server, &reverse, 0) == 0);
            ok(quicly_set_stream_path_affinity(reverse, 1) == 0);
        }
        while (quic_now < until && multipath_received_length(f.server, stream->stream_id) < sizeof(initial)) {
            if (sustained) {
                ok(quicly_streambuf_egress_write(stream, initial, 64) == 0);
                ok(quicly_stream_can_send(stream, 1) && !quicly_is_blocked(f.client));
                ok(quicly_streambuf_egress_write(reverse, initial, 64) == 0);
                appended += 64;
            }
            custom_recovery_round(&f, 1, 16);
        }
        ok(multipath_received_length(f.server, stream->stream_id) >= sizeof(initial));
        quicly_stream_t *received = quicly_get_stream(f.server, stream->stream_id);
        if (received != NULL && quicly_streambuf_ingress_get(received).len >= sizeof(initial))
            ok(memcmp(quicly_streambuf_ingress_get(received).base, initial, sizeof(initial)) == 0);
        if (sustained)
            ok(appended > 0); /* prefix advanced while the producer was still publishing. */
        quicly_path_health_t health;
        ok(quicly_get_path_health(f.client, 0, &health) == 0);
        ok(health.pto_count >= 2 && !health.abandoned);
        ok(f.server_policy.maintenance_packets != 0); /* ACKs must escape the blackholed primary. */
        f.client_policy.data = 2;                     /* keep data off path zero even after connectivity returns. */
        until = quic_now + f.bound;
        do {
            custom_recovery_round(&f, 0, 1); /* one-datagram budgets must also permit recovery probes. */
            ok(quicly_get_path_health(f.client, 0, &health) == 0);
        } while (quic_now < until && health.pto_count != 0);
        ok(health.pto_count == 0);
        ok(f.client_policy.maintenance_packets != 0);
        custom_recovery_free(&f);
    }
}

static void test_custom_recovery_eligibility(void)
{
    custom_recovery_fixture_t f;
    custom_recovery_setup(&f);
    quicly_stream_t *pinned, *ordinary;
    ok(quicly_open_stream(f.client, &pinned, 0) == 0);
    ok(quicly_open_stream(f.client, &ordinary, 0) == 0);
    ok(quicly_set_stream_path_affinity(pinned, 0) == 0);
    uint8_t bytes[4000];
    memset(bytes, 0x5a, sizeof(bytes));
    ok(quicly_streambuf_egress_write(pinned, bytes, sizeof(bytes)) == 0);
    custom_recovery_transmit(f.client, f.server, 1, 16);
    ok(quicly_streambuf_egress_write(ordinary, bytes, sizeof(bytes)) == 0);
    int64_t until = quic_now + f.bound;
    quicly_path_health_t health;
    do {
        custom_recovery_round(&f, 1, 16);
        ok(quicly_get_path_health(f.client, 0, &health) == 0);
    } while (quic_now < until &&
             (health.pto_count < 2 || multipath_received_length(f.server, ordinary->stream_id) < sizeof(bytes)));
    ok(health.pto_count >= 2);
    ok(multipath_received_length(f.server, ordinary->stream_id) == sizeof(bytes));
    ok(multipath_received_length(f.server, pinned->stream_id) == 0);
    ok(pinned->affinity_path_id == 0);
    /* removing that socket also preserves affinity while unrelated traffic continues on the backup. */
    f.client_policy.eligible = f.server_policy.eligible = 2;
    ok(quicly_streambuf_egress_write(ordinary, bytes, sizeof(bytes)) == 0);
    until = quic_now + f.bound;
    while (quic_now < until && multipath_received_length(f.server, ordinary->stream_id) < 2 * sizeof(bytes))
        custom_recovery_round(&f, 0, 16);
    ok(multipath_received_length(f.server, ordinary->stream_id) == 2 * sizeof(bytes));
    quicly_stream_t *received = quicly_get_stream(f.server, ordinary->stream_id);
    if (received != NULL && quicly_streambuf_ingress_get(received).len == 2 * sizeof(bytes)) {
        const uint8_t *payload = quicly_streambuf_ingress_get(received).base;
        ok(memcmp(payload, bytes, sizeof(bytes)) == 0 && memcmp(payload + sizeof(bytes), bytes, sizeof(bytes)) == 0);
    }
    ok(multipath_received_length(f.server, pinned->stream_id) == 0);
    ok(pinned->affinity_path_id == 0);
    /* all sockets disappear. due ACKs and queues must wait, while loss bookkeeping and idle expiration still progress. */
    f.client_policy.eligible = f.server_policy.eligible = 0;
    int64_t expires = f.client->idle_timeout.at;
    for (size_t calls = 0; calls < 64 && quic_now < expires; ++calls) {
        custom_recovery_transmit(f.client, f.server, 0, 1);
        int64_t next = quicly_get_first_timeout(f.client);
        ok(next > quic_now);
        if (next <= quic_now)
            break;
        quic_now = next;
    }
    ok(quic_now >= expires);
    quicly_address_t remote, local;
    struct iovec packet;
    uint8_t buffer[1500];
    size_t count = 1;
    ok(quicly_send(f.client, &remote, &local, &packet, &count, buffer, sizeof(buffer)) == QUICLY_ERROR_FREE_CONNECTION);
    ok(count == 0);
    custom_recovery_free(&f);
}

static void test_custom_recovery_data_policy(void)
{
    custom_recovery_fixture_t f;
    custom_recovery_setup(&f);
    f.client_policy.data = 0;
    quicly_stream_t *stream;
    ok(quicly_open_stream(f.client, &stream, 0) == 0);
    ok(quicly_streambuf_egress_write(stream, "custom placement", 16) == 0);
    ptls_iovec_t datagram = ptls_iovec_init("fec symbol", 10);
    quicly_send_datagram_frames_path(f.client, 1, &datagram, 1);
    ok(quicly_set_path_status(f.client, 1, 1) == 0);
    /* force maintenance with queued application traffic; neither queue may be consumed. */
    f.client->path_spaces[1]->loss.alarm_at = quic_now;
    size_t queued = quicly_get_num_datagram_frames_path(f.client, 1);
    custom_recovery_round(&f, 0, 1);
    ok(multipath_received_length(f.server, stream->stream_id) == 0);
    ok(quicly_get_num_datagram_frames_path(f.client, 1) == queued);
    for (size_t i = 0; i < 100; ++i)
        custom_recovery_round(&f, 0, 1);
    quicly_path_health_t peer_status;
    ok(quicly_get_path_health(f.server, 1, &peer_status) == 0 && peer_status.peer_is_backup);
    ok(quicly_get_first_timeout(f.client) > quic_now);
    /* deliberately prefer the peer's backup for unbound data: custom policy is not forced to use built-in ranking. */
    f.client_policy.data = 2;
    for (size_t i = 0; i < 100; ++i)
        custom_recovery_round(&f, 0, 1);
    ok(multipath_received_length(f.server, stream->stream_id) == 16);
    ok(quicly_get_num_datagram_frames_path(f.client, 1) == 0);
    ok(f.server_policy.received_datagrams == 1);
    /* lose a real DATAGRAM packet and let repeated PTO maintenance run with no replacement application payload. */
    quicly_send_datagram_frames_path(f.client, 1, &datagram, 1);
    int64_t until = quic_now + f.bound;
    while (quic_now < until && quicly_get_num_datagram_frames_path(f.client, 1) != 0)
        custom_recovery_round(&f, 2, 1);
    quicly_stats_t before, after;
    quicly_get_stats(f.client, &before);
    quicly_path_health_t health;
    do {
        custom_recovery_round(&f, 2, 1);
        ok(quicly_get_path_health(f.client, 1, &health) == 0);
    } while (quic_now < until && health.pto_count < 2);
    ok(health.pto_count >= 2);
    for (size_t i = 0; i < 100; ++i)
        custom_recovery_round(&f, 0, 1);
    quicly_get_stats(f.client, &after);
    ok(before.num_frames_sent.datagram == after.num_frames_sent.datagram);
    ok(f.server_policy.received_datagrams == 1);
    ok(f.client_policy.empty_maintenance != 0 && f.client_policy.data_packets != 0);
    custom_recovery_free(&f);
}

static void test_custom_recovery_health(void)
{
    custom_recovery_fixture_t f;
    custom_recovery_setup(&f);
    quicly_path_health_t h;
    quicly_rtt_init(&f.client->path_spaces[1]->loss.rtt, &quic_ctx.egress[0].loss, 17);
    ok(quicly_get_path_health(f.client, 1, &h) == 0);
    ok(h.path_index == 1 && h.path_id == 1 && h.peer_is_backup && h.validated && !h.probe_only && !h.abandoned);
    ok(!h.rtt_is_sampled && h.rtt_smoothed == 17);
    float samples[] = {0.25f, 0.625f};
    for (size_t i = 0; i < PTLS_ELEMENTSOF(samples); ++i) {
        quicly_rtt_init(&f.client->path_spaces[1]->loss.rtt, &quic_ctx.egress[0].loss, 17);
        quicly_rtt_update(&f.client->path_spaces[1]->loss.rtt, samples[i], 0, quic_now);
        f.client->path_spaces[1]->loss.pto_count = i == 0 ? -1 : 2;
        ok(quicly_get_path_health(f.client, 1, &h) == 0);
        ok(h.rtt_is_sampled && fabsf(h.rtt_smoothed - samples[i]) < 0.00001f);
        ok(h.pto_count == (i == 0 ? -1 : 2));
        quicly_path_stats_t legacy;
        ok(quicly_get_path_stats(f.client, 1, &legacy) == 0 && legacy.rtt_smoothed == 0);
    }
    quicly_path_health_t saved = h;
    ok(quicly_get_path_health(f.client, SIZE_MAX, &h) == -1 && memcmp(&h, &saved, sizeof(h)) == 0);
    ok(quicly_get_path_health(f.client, 3, &h) == -1 && memcmp(&h, &saved, sizeof(h)) == 0);
    /* address candidates have distinct local indices but share their wire path's recovery state. */
    struct sockaddr_in remote = {.sin_family = AF_INET, .sin_port = htons(30000), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(40000), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    size_t candidate;
    lock_now(f.client, 1);
    ok(open_path(f.client, &candidate, 1, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
    unlock_now(f.client);
    ok(candidate != 1);
    ok(quicly_get_path_health(f.client, candidate, &h) == 0);
    ok(h.path_index == candidate && h.path_id == 1 && h.probe_only && !h.validated);
    ok(h.pto_count == saved.pto_count && h.rtt_smoothed == saved.rtt_smoothed && h.peer_is_backup);
    ok(delete_path(f.client, candidate) == 0);
    ok(quicly_get_path_health(f.client, candidate, &h) == 0 && h.abandoned);
    ok(destroy_path_state(f.client, candidate) == 0);
    ok(quicly_get_path_health(f.client, candidate, &h) == -1);
    size_t reused;
    lock_now(f.client, 1);
    ok(open_path(f.client, &reused, 0, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
    unlock_now(f.client);
    ok(quicly_get_path_health(f.client, reused, &h) == 0 && h.path_id == 0 && h.path_index != h.path_id);
    /* reuse the original candidate slot with its original path ID; stale abandonment must not leak into the snapshot. */
    lock_now(f.client, 1);
    ok(open_path(f.client, &reused, 1, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
    unlock_now(f.client);
    ok(reused == candidate);
    ok(quicly_get_path_health(f.client, reused, &h) == 0 && !h.abandoned && h.probe_only && h.path_id == 1);
    ok(quicly_abandon_path(f.client, 1, QUICLY_PATH_ABANDON_ERROR_APPLICATION) == 0);
    ok(quicly_get_path_health(f.client, 1, &h) == 0 && h.abandoned && h.path_id == 1);
    ok(destroy_path_state(f.client, candidate) == 0);
    ok(destroy_path_state(f.client, 1) == 0);
    ok(quicly_get_path_health(f.client, 1, &h) == -1);
    lock_now(f.client, 1);
    ok(open_path(f.client, &reused, 4, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
    unlock_now(f.client);
    ok(reused == 1);
    ok(quicly_get_path_health(f.client, reused, &h) == 0 && h.path_index == 1 && h.path_id == 4);
    ok(!h.abandoned && h.probe_only && h.pto_count == 0 && !h.rtt_is_sampled && !h.peer_is_backup);
    custom_recovery_free(&f);
}

static void test_custom_recovery_maintenance_idempotence(void)
{
    custom_recovery_fixture_t f;
    custom_recovery_setup(&f);
    f.client_policy.data = 0;
    quicly_stream_t *stream;
    ok(quicly_open_stream(f.client, &stream, 0) == 0);
    ok(quicly_streambuf_egress_write(stream, "pending", 7) == 0);
    ptls_iovec_t symbol = ptls_iovec_init("symbol", 6);
    quicly_send_datagram_frames_path(f.client, 1, &symbol, 1);
    f.client->path_spaces[1]->loss.alarm_at = quic_now;

    quicly_send_context_t s;
    struct iovec datagram;
    uint8_t buffer[1500];
    size_t count = 0, repeated = 0;
    quicly_stats_t before, first, second;
    quicly_get_stats(f.client, &before);
    test_setup_send_context(f.client, &s, &datagram, buffer, sizeof(buffer));
    ok(quicly_send_path_maintenance(f.client, &s, &count) == 0 && count == 1);
    quicly_get_stats(f.client, &first);
    uint64_t next_pn = f.client->path_spaces[1]->packet_number;
    ok(quicly_send_path_maintenance(f.client, &s, &repeated) == 0 && repeated == count);
    quicly_get_stats(f.client, &second);
    ok(second.num_packets.sent == first.num_packets.sent);
    ok(f.client->path_spaces[1]->packet_number == next_pn);
    ok(second.num_frames_sent.stream == before.num_frames_sent.stream);
    ok(second.num_frames_sent.datagram == before.num_frames_sent.datagram);
    ok(quicly_get_num_datagram_frames_path(f.client, 1) == 1);
    unlock_now(f.client);
    custom_recovery_free(&f);
}

static void test_custom_recovery_limits(void)
{
    test_custom_recovery_maintenance_idempotence();
    quicly_context_t saved = quic_ctx;
    quic_ctx.egress[0].pacing = 1;
    custom_recovery_fixture_t f;
    custom_recovery_setup(&f);
    f.client_policy.data = 0;
    quicly_send_context_t s;
    struct iovec datagram;
    uint8_t buffer[1500];
    size_t count = SIZE_MAX;
    test_setup_send_context(f.client, &s, &datagram, buffer, sizeof(buffer));
    ok(quicly_send_path_maintenance(f.client, &s, &count) == 0 && count == 0);
    ok(quicly_send_path_maintenance(f.client, &s, &count) == 0 && count == 0);
    f.client_policy.eligible = 1;
    ok(quicly_send_on_path(f.client, &s, 1, &count) == 0 && count == 0);
    unlock_now(f.client);
    f.client_policy.eligible = 3;

    quicly_stream_t *stream;
    ok(quicly_open_stream(f.client, &stream, 0) == 0);
    ok(quicly_set_stream_path_affinity(stream, 1) == 0);
    ok(quicly_streambuf_egress_write(stream, "bounded", 7) == 0);
    ptls_iovec_t symbol = ptls_iovec_init("symbol", 6);
    quicly_send_datagram_frames_path(f.client, 1, &symbol, 1);
    f.client_policy.data = 2;
    quicly_path_space_t *ps = f.client->path_spaces[1];
    uint32_t cwnd = ps->cc.cwnd;
    ps->cc.cwnd = 0;
    ok(custom_recovery_transmit(f.client, f.server, 0, 1) == 0);
    ok(quicly_get_first_timeout(f.client) > quic_now);
    ps->cc.cwnd = cwnd;
    ok(ps->pacer != NULL);
    ps->pacer->at = quic_now;
    ps->pacer->bytes_sent = (size_t)calc_pacer_send_rate(ps) * 100 + 20 * ps->max_udp_payload_size;
    ok(custom_recovery_transmit(f.client, f.server, 0, 1) == 0);
    ok(quicly_get_first_timeout(f.client) > quic_now);
    /* the existing PTO exception permits a probe, not fresh application data, with a one-packet output budget. */
    ps->loss.alarm_at = quic_now;
    ok(custom_recovery_transmit(f.client, f.server, 0, 1) == 1);
    ok(multipath_received_length(f.server, stream->stream_id) == 0);
    ok(quicly_get_num_datagram_frames_path(f.client, 1) == 1);
    ok(ps->cc.cwnd == cwnd && ps->is_backup);

    /* amplification credit is a hard limit even for a recovery probe. */
    f.server_policy.eligible = 2;
    f.server_policy.data = 0;
    struct st_quicly_conn_path_t *server_path = get_path(f.server, 1);
    server_path->path_challenge.send_at = quic_now + 1000;
    server_path->path_challenge.address_validated = 0;
    server_path->bytes_received = 1;
    server_path->bytes_sent = quic_ctx.pre_validation_amplification_limit;
    f.server->path_spaces[1]->loss.alarm_at = quic_now;
    ok(custom_recovery_transmit(f.server, f.client, 0, 1) == 0);
    ok(quicly_get_first_timeout(f.server) > quic_now);
    server_path->bytes_sent--; /* positive credit too small for a packet must not be rounded up into an amplification violation. */
    ok(custom_recovery_transmit(f.server, f.client, 0, 1) == 0);
    ok(quicly_get_first_timeout(f.server) > quic_now);
    server_path->bytes_received += 1500;
    f.server->path_spaces[1]->loss.alarm_at = quic_now;
    uint64_t allowance = calc_amplification_limit_allowance(f.server, server_path);
    uint64_t bytes_before = server_path->bytes_sent;
    ok(custom_recovery_transmit(f.server, f.client, 0, 1) == 1);
    ok(server_path->bytes_sent - bytes_before <= allowance);

    /* validation probes obey physical eligibility too, independently of the custom data scheduler. */
    f.client_policy.eligible = 1;
    f.client_policy.data = 0;
    struct st_quicly_conn_path_t *client_path = get_path(f.client, 1);
    client_path->path_challenge.send_at = quic_now;
    client_path->probe_only = 1;
    uint64_t challenges = client_path->path_challenge.num_sent;
    recalc_send_probe_at(f.client);
    custom_recovery_transmit(f.client, f.server, 0, 1);
    ok(client_path->path_challenge.num_sent == challenges);

    /* closing cleanup must finish without a physical path and without repeatedly returning an immediate deadline. */
    f.client_policy.eligible = 0;
    ok(quicly_close(f.client, 0, "test") == 0);
    quicly_error_t ret = 0;
    for (size_t i = 0; i < 32 && ret == 0; ++i) {
        quicly_address_t remote, local;
        count = 1;
        ret = quicly_send(f.client, &remote, &local, &datagram, &count, buffer, sizeof(buffer));
        ok(count == 0);
        if (ret == 0) {
            int64_t next = quicly_get_first_timeout(f.client);
            ok(next > quic_now);
            if (next <= quic_now)
                break;
            quic_now = next;
        }
    }
    ok(ret == QUICLY_ERROR_FREE_CONNECTION);
    custom_recovery_free(&f);
    quic_ctx = saved;
}

static void test_custom_recovery_single_path(void)
{
    int64_t saved_now = quic_now;
    quicly_context_t saved = quic_ctx;
    quic_ctx.transport_params.enable_multipath = 0;
    quic_ctx.transport_params.initial_max_path_id = 0;
    quicly_conn_t *client, *server;
    test_setup_connected_peers(&client, &server);
    exchange_until_idle(client, server);
    custom_recovery_policy_t policy = {.eligible = 1, .data = 1};
    *quicly_get_data(client) = &policy;
    quic_ctx.path_scheduler = &custom_recovery_scheduler;
    quicly_send_context_t s;
    struct iovec packet;
    uint8_t buffer[1500];
    size_t count = SIZE_MAX;
    test_setup_send_context(client, &s, &packet, buffer, sizeof(buffer));
    ok(!quicly_is_multipath(client));
    ok(quicly_send_path_maintenance(client, &s, &count) == 0 && count == 0);
    unlock_now(client);
    quicly_free(client);
    quicly_free(server);

    /* with no socket even for path zero, handshake expiration is still an actionable future deadline. */
    policy.eligible = 0;
    ok(quicly_connect(&client, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL,
                      NULL, NULL) == 0);
    *quicly_get_data(client) = &policy;
    quicly_address_t remote, local;
    count = 1;
    ok(quicly_send(client, &remote, &local, &packet, &count, buffer, sizeof(buffer)) == 0 && count == 0);
    int64_t next = quicly_get_first_timeout(client);
    ok(next > quic_now && next != INT64_MAX);
    quic_now = next;
    count = 1;
    ok(quicly_send(client, &remote, &local, &packet, &count, buffer, sizeof(buffer)) == QUICLY_ERROR_FREE_CONNECTION);
    ok(count == 0);
    quicly_free(client);
    quic_ctx = saved;
    quic_now = saved_now;
}

static void test_custom_recovery_opt_in(void)
{
    unsigned saved_threshold = quic_ctx.multipath_failover_pto_threshold;
    quic_ctx.multipath_failover_pto_threshold = 2;
    custom_recovery_fixture_t f;
    custom_recovery_setup(&f);
    f.client_policy.data = 0;
    quicly_stream_t *stream;
    ok(quicly_open_stream(f.client, &stream, 0) == 0);
    ok(quicly_streambuf_egress_write(stream, "application policy", 18) == 0);
    ptls_iovec_t symbol = ptls_iovec_init("fec", 3);
    quicly_send_datagram_frames_path(f.client, 1, &symbol, 1);
    quicly_path_space_t *path = f.client->path_spaces[1];
    f.client->path_spaces[0]->health.last_ack_at = quic_now;
    f.client_policy.eligible = 2;
    lock_now(f.client, 0);
    ok(!path_has_health_alternative(f.client, path, 1));
    unlock_now(f.client);
    path->loss.pto_count = 1;
    path->loss.alarm_at = quic_now;
    quicly_stats_t before, after;
    quicly_get_stats(f.client, &before);
    ok(custom_recovery_transmit(f.client, f.server, 2, 1) == 1);
    ok(path->health.state == QUICLY_PATH_USABLE); /* the only alternative has no physical socket */
    f.client_policy.eligible = 3;
    path->loss.pto_count = 1;
    path->loss.alarm_at = quic_now;
    ok(custom_recovery_transmit(f.client, f.server, 2, 1) == 1);
    ok(path->health.state == QUICLY_PATH_SUSPECT);
    quicly_get_stats(f.client, &after);
    ok(after.num_frames_sent.stream == before.num_frames_sent.stream);
    ok(after.num_frames_sent.datagram == before.num_frames_sent.datagram);
    ok(quicly_get_num_datagram_frames_path(f.client, 1) == 1);
    ok(multipath_received_length(f.server, stream->stream_id) == 0);
    /* with data disabled on both paths, fresh probe ACKs must complete both recovery transitions */
    int64_t until = quic_now + f.bound;
    int saw_recovering = 0;
    while (quic_now < until && path->health.state != QUICLY_PATH_USABLE) {
        custom_recovery_round(&f, 0, 1);
        saw_recovering |= path->health.state == QUICLY_PATH_RECOVERING;
    }
    ok(saw_recovering && path->health.state == QUICLY_PATH_USABLE);
    quicly_get_stats(f.client, &after);
    ok(after.num_frames_sent.stream == before.num_frames_sent.stream);
    ok(after.num_frames_sent.datagram == before.num_frames_sent.datagram);
    custom_recovery_free(&f);
    test_custom_recovery_eligibility();
    quic_ctx.multipath_failover_pto_threshold = saved_threshold;
}
