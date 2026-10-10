static void test_multipath_egress_context(void)
{
    quicly_context_t original = quic_ctx;
    quicly_init_cc_t *const controllers[] = {&quicly_cc_reno_init, &quicly_cc_cubic_init, &quicly_cc_cuback_init,
                                             &quicly_cc_pico_init};

    for (size_t alt = 0; alt <= QUICLY_NUM_ALT_EGRESS; ++alt) {
        quic_ctx = original;
        memset(quic_ctx.alt_egress_ratio, 0, sizeof(quic_ctx.alt_egress_ratio));
        quic_ctx.egress[alt] = original.egress[0];
        struct st_quicly_context_egress_t *policy = &quic_ctx.egress[alt];
        policy->cc.init_cc = controllers[alt];
        policy->cc.initcwnd_packets = 12 + alt;
        policy->cc.normalize_mtu = alt % 2;
        policy->cc.rapid_start = 1;
        policy->cc.abba = 1;
        policy->loss.min_pto = 5 + alt;
        policy->pacing = alt % 2;
        if (alt != 0)
            quic_ctx.alt_egress_ratio[alt - 1] = 255;

        quicly_conn_t *client, *server;
        quicly_context_t saved = setup_multipath_regression_peers(&client, &server, 0);
        ok(quicly_get_alt_egress(client) == alt);
        ok(quicly_get_alt_egress(server) == alt);
        ok(client->path_spaces[0]->cc.conf == &policy->cc);

        /* new path inherits selected policy and fractional initial RTT */
        quicly_rtt_init(&client->path_spaces[0]->loss.rtt, &policy->loss, 0.25f);
        quicly_rtt_update(&client->path_spaces[0]->loss.rtt, 0.25f, 0, quic_now);
        /* exercise fresh path space allocation */
        if (client->path_spaces[1] != NULL) {
            free_path_space(client->path_spaces[1]);
            client->path_spaces[1] = NULL;
        }
        lock_now(client, 0);
        ok(new_path(client, 1, 1, &fake_address.sa, &fake_address.sa) == 0);
        quicly_path_space_t *ps = client->path_spaces[1];
        ok(ps->cc.conf == &policy->cc && ps->loss.conf == &policy->loss);
        ok(ps->cc.type->cc_init == controllers[alt]);
        ok(ps->cc.cwnd == quicly_cc_calc_initial_cwnd(policy->cc.initcwnd_packets, ps->max_udp_payload_size));
        ok(ps->cc.rapid_start.state == QUICLY_CC_RAPID_START_STATE_PROBING);
        ok((ps->pacer != NULL) == policy->pacing);
        ok(ps->pacer == NULL || ps->pacer != client->path_spaces[0]->pacer);
        ok(ps->loss.rtt.smoothed == 0.25f);
        ok(calc_pacer_send_rate(ps) == quicly_pacer_calc_send_rate(2, ps->cc.cwnd, 0.25f));

        /* promotion resets only affected path, retaining policy and fractional RTT */
        uint32_t primary_cwnd = client->path_spaces[0]->cc.cwnd;
        size_t candidate = encode_flat_path_index(1, 1);
        ok(new_path(client, candidate, 1, &fake_address.sa, &fake_address.sa) == 0);
        ok(promote_path(client, candidate) == 0);
        ok(ps->cc.conf == &policy->cc && ps->loss.conf == &policy->loss);
        ok(ps->cc.type->cc_init == controllers[alt]);
        ok(ps->loss.rtt.smoothed == 0.25f && ps->loss.rtt.latest == 0);
        ok(client->path_spaces[0]->cc.cwnd == primary_cwnd);
        ok(quicly_get_alt_egress(client) == alt);

        /* changing running controller must not change experiment assignment */
        ok(quicly_set_cc(client, &quicly_cc_type_reno));
        if (client->path_spaces[2] != NULL) {
            free_path_space(client->path_spaces[2]);
            client->path_spaces[2] = NULL;
        }
        ok(new_path(client, 2, 2, &fake_address.sa, &fake_address.sa) == 0);
        for (size_t i = 0; i != 3; ++i) {
            ok(client->path_spaces[i]->cc.type == &quicly_cc_type_reno);
            ok(client->path_spaces[i]->cc.conf == &policy->cc);
        }
        ok(quicly_get_alt_egress(client) == alt);
        unlock_now(client);
        free_multipath_regression_peers(client, server, saved);
    }
    quic_ctx = original;
}

static void test_multipath_fractional_timing(void)
{
    quicly_conn_t *client, *server;
    quicly_context_t saved = setup_multipath_regression_peers(&client, &server, 0);
    int64_t saved_now = quic_now;
    quic_now = INT64_C(1800000000000);
    quic_now_submillisec = 0.125;
    lock_now(client, 0);
    ok(new_path(client, 1, 1, &fake_address.sa, &fake_address.sa) == 0);
    quicly_path_space_t *ps = client->path_spaces[1];
    quicly_rtt_t primary_rtt = client->path_spaces[0]->loss.rtt;
    uint64_t primary_acked = client->path_spaces[0]->bytes_acked;
    uint64_t pn = ps->packet_number++;
    ok(quicly_sentmap_prepare(&ps->loss.sentmap, pn, client->stash.now_double, QUICLY_EPOCH_1RTT) == 0);
    ps->loss.sentmap._pending_packet->data.packet.path_id = ps->path_id;
    quicly_sentmap_commit(&ps->loss.sentmap, 1200, 1, 0);
    ps->last_retransmittable_sent_at = client->stash.now_double;
    ok(ps->last_retransmittable_sent_at == quic_now + 0.125);
    unlock_now(client);

    /* PATH_ACK on path zero measures path one fractional RTT only */
    quic_now_submillisec = 0.75;
    quicly_ack_frame_t ack = {.largest_acknowledged = pn, .smallest_acknowledged = pn, .ack_block_lengths = {1}};
    struct st_quicly_handle_payload_state_t state = {.epoch = QUICLY_EPOCH_1RTT};
    lock_now(client, 0);
    ok(process_ack_frame_core(client, &state, ps->path_id, &ack) == 0);
    ok(ps->loss.rtt.latest == 0.625f);
    ok(memcmp(&primary_rtt, &client->path_spaces[0]->loss.rtt, sizeof(primary_rtt)) == 0);
    ok(client->path_spaces[0]->bytes_acked == primary_acked);
    ok(ps->bytes_acked == 1200);

    /* key retention and shutdown use maximum unrounded path PTO */
    get_path(client, 1)->probe_only = 0;
    client->super.remote.transport_params.max_ack_delay = 0;
    for (size_t i = 0; i != 2; ++i) {
        client->path_spaces[i]->loss.rtt.smoothed = 1.125f + i;
        client->path_spaces[i]->loss.rtt.variance = 0;
    }
    double pto = quicly_rtt_get_pto(&ps->loss.rtt, 0, ps->loss.conf->min_pto);
    ok(get_max_pto(client) == pto && pto != floor(pto));
    ok(add_three_max_pto(client, client->stash.now_double) == (int64_t)ceil(quic_now + 0.75 + 3 * pto));
    ok(add_three_max_pto(client, INT64_MAX) == INT64_MAX);
    ok(get_max_sentmap_expiration_time(client) == 4 * pto);
    unlock_now(client);
    quic_now_submillisec = 0;
    quic_now = saved_now;
    free_multipath_regression_peers(client, server, saved);
}
