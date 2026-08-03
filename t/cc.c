/*
 * Copyright (c) 2017-2024 Fastly, Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include "quicly.h"
#include "test.h"

static void test_pico_undo_loss(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, initcwnd, 0);
    uint32_t bytes_per_mtu_increase = cc.state.pico.bytes_per_mtu_increase;

    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.recovery_end == 20);
    ok(cc.num_loss_episodes == 1);
    ok(cc.state.pico.undo.num_packets_lost == 1);
    ok(cc.cwnd < initcwnd);
    ok(cc.ssthresh == cc.cwnd);
    ok(cc.cwnd_exiting_slow_start == initcwnd);
    ok(cc.exit_slow_start_at == 1000);

    cc.type->cc_on_late_ack(&cc, 10, 1100);
    ok(cc.recovery_end == 0);
    ok(cc.num_loss_episodes == 0);
    ok(cc.num_loss_episodes_undone == 1);
    ok(cc.num_loss_episodes_undone_in_startup == 1);
    ok(cc.state.pico.undo.num_packets_lost == 0);
    ok(cc.cwnd == initcwnd);
    ok(cc.ssthresh == UINT32_MAX);
    ok(cc.state.pico.bytes_per_mtu_increase == bytes_per_mtu_increase);
    ok(cc.cwnd_exiting_slow_start == 0);
    ok(cc.exit_slow_start_at == INT64_MAX);
}

static void test_pico_undo_multiple_losses(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, initcwnd, 0);

    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    uint32_t reduced_cwnd = cc.cwnd;
    cc.type->cc_on_lost(&cc, &loss, mtu, 11, 20, 1001, mtu);
    ok(cc.state.pico.undo.num_packets_lost == 2);

    cc.type->cc_on_late_ack(&cc, 9, 1099);
    ok(cc.state.pico.undo.num_packets_lost == 2);
    ok(cc.recovery_end == 20);

    cc.type->cc_on_late_ack(&cc, 10, 1100);
    ok(cc.state.pico.undo.num_packets_lost == 1);
    ok(cc.recovery_end == 20);
    ok(cc.cwnd == reduced_cwnd);
    ok(cc.num_loss_episodes == 1);

    cc.type->cc_on_late_ack(&cc, 11, 1101);
    ok(cc.state.pico.undo.num_packets_lost == 0);
    ok(cc.recovery_end == 0);
    ok(cc.cwnd == initcwnd);
    ok(cc.ssthresh == UINT32_MAX);
    ok(cc.num_loss_episodes == 0);
    ok(cc.num_loss_episodes_undone == 1);
    ok(cc.num_loss_episodes_undone_in_startup == 1);
}

static void test_pico_undo_rapid_start_loss(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, initcwnd, 0);
    cc.type->enable_rapid_start(&cc, 900);
    ok(quicly_cc_rapid_start_is_enabled(&cc.rapid_start));

    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.rapid_start.newest_rtt_sample_until == -1);

    cc.type->cc_on_late_ack(&cc, 10, 1100);
    ok(cc.rapid_start.newest_rtt_sample_until == 0);
    ok(cc.recovery_end == 0);
    ok(cc.cwnd == initcwnd);
    ok(cc.ssthresh == UINT32_MAX);

    cc.type->cc_on_lost(&cc, &loss, mtu, 20, 30, 1200, mtu);
    ok(cc.cwnd == initcwnd / 2);
    ok(cc.ssthresh == cc.cwnd);
}

static void test_pico_undo_jumpstart_loss(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu, jumpcwnd = 24 * mtu;

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, initcwnd, 0);
    cc.type->cc_jumpstart(&cc, jumpcwnd, 10);
    ok(quicly_cc_in_jumpstart(&cc));
    ok(cc.cwnd == jumpcwnd);

    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.pico.undo.cwnd == jumpcwnd / 2);
    ok(cc.cwnd < jumpcwnd);
    ok(!quicly_cc_in_jumpstart(&cc));

    cc.type->cc_on_late_ack(&cc, 10, 1100);
    ok(cc.recovery_end == 0);
    ok(cc.cwnd == jumpcwnd / 2);
    ok(cc.ssthresh == UINT32_MAX);

    cc.type->cc_on_acked(&cc, &loss, mtu, 11, 18 * mtu, 1, 20, 1200, mtu);
    ok(cc.cwnd != 18 * mtu);
    ok(cc.cwnd_exiting_jumpstart == 0);
    ok(!quicly_cc_in_jumpstart(&cc));
}

static void test_cubic_undo_loss(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0);

    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.recovery_end == 20);
    ok(cc.num_loss_episodes == 1);
    ok(cc.state.cubic.undo.num_packets_lost == 1);
    ok(cc.cwnd < initcwnd);
    ok(cc.ssthresh == cc.cwnd);
    ok(cc.cwnd_exiting_slow_start == initcwnd);
    ok(cc.exit_slow_start_at == 1000);
    /* the congestion event installed cubic state; undo must roll all of it back */
    ok(cc.state.cubic.w_max == initcwnd);
    ok(cc.state.cubic.avoidance_start == 1000);
    ok(cc.state.cubic.k != 0);

    cc.type->cc_on_late_ack(&cc, 10, 1100);
    ok(cc.recovery_end == 0);
    ok(cc.num_loss_episodes == 0);
    ok(cc.num_loss_episodes_undone == 1);
    ok(cc.num_loss_episodes_undone_in_startup == 1);
    ok(cc.state.cubic.undo.num_packets_lost == 0);
    ok(cc.cwnd == initcwnd);
    ok(cc.ssthresh == UINT32_MAX);
    ok(cc.cwnd_exiting_slow_start == 0);
    ok(cc.exit_slow_start_at == INT64_MAX);
    /* restored to the pre-loss (pristine) cubic state */
    ok(cc.state.cubic.k == 0);
    ok(cc.state.cubic.w_max == 0);
    ok(cc.state.cubic.w_last_max == 0);
    ok(cc.state.cubic.avoidance_start == 0);
}

static void test_cubic_undo_multiple_losses(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0);

    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    uint32_t reduced_cwnd = cc.cwnd;
    cc.type->cc_on_lost(&cc, &loss, mtu, 11, 20, 1001, mtu);
    ok(cc.state.cubic.undo.num_packets_lost == 2);
    ok(cc.cwnd == reduced_cwnd); /* second loss is inside the recovery window: no further reduction */

    /* a late ACK below start_pn must not count towards the undo */
    cc.type->cc_on_late_ack(&cc, 9, 1099);
    ok(cc.state.cubic.undo.num_packets_lost == 2);
    ok(cc.recovery_end == 20);

    cc.type->cc_on_late_ack(&cc, 10, 1100);
    ok(cc.state.cubic.undo.num_packets_lost == 1);
    ok(cc.recovery_end == 20);
    ok(cc.cwnd == reduced_cwnd); /* not yet undone */
    ok(cc.num_loss_episodes == 1);

    cc.type->cc_on_late_ack(&cc, 11, 1101);
    ok(cc.state.cubic.undo.num_packets_lost == 0);
    ok(cc.recovery_end == 0);
    ok(cc.cwnd == initcwnd);
    ok(cc.ssthresh == UINT32_MAX);
    ok(cc.num_loss_episodes == 0);
    ok(cc.num_loss_episodes_undone == 1);
    ok(cc.num_loss_episodes_undone_in_startup == 1);
}

/**
 * Fast convergence (RFC 8312 4.6) derives w_max from w_last_max asymmetrically, so an undo that restores only one of the two
 * silently corrupts every later congestion event. This exercises an undo of a congestion-avoidance episode that took the fast
 * convergence branch.
 */
static void test_cubic_undo_fast_convergence(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0);

    /* First episode, in startup, left NOT undone so that the connection enters congestion avoidance. Undoing a startup episode
     * would restore ssthresh to UINT32_MAX and put us back in startup. */
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.ssthresh != UINT32_MAX);
    ok(cc.state.cubic.w_last_max == initcwnd);
    uint32_t ca_cwnd = cc.cwnd;

    /* Second episode, now in congestion avoidance and below w_last_max, so it takes the fast convergence branch. */
    cc.type->cc_on_lost(&cc, &loss, mtu, 20, 30, 2000, mtu);
    ok(cc.state.cubic.w_last_max == ca_cwnd);
    ok(cc.state.cubic.w_max < ca_cwnd); /* scaled down by (1 + beta) / 2 */
    uint32_t w_max_1 = cc.state.cubic.w_max, w_last_max_1 = cc.state.cubic.w_last_max;

    cc.type->cc_on_late_ack(&cc, 20, 2010);
    ok(cc.num_loss_episodes_undone == 1);
    ok(cc.num_loss_episodes_undone_in_startup == 0); /* this episode was not in startup */
    ok(cc.cwnd == ca_cwnd);
    ok(cc.state.cubic.w_last_max == initcwnd); /* rolled back to the value the first episode left */
    ok(cc.state.cubic.w_max == initcwnd);

    /* Repeating the same congestion event at the same CWND must reproduce the same result. It would not if w_last_max had been
     * left holding the post-episode value, which is the failure mode restoring only w_max would cause. */
    cc.type->cc_on_lost(&cc, &loss, mtu, 30, 40, 3000, mtu);
    ok(cc.state.cubic.w_max == w_max_1);
    ok(cc.state.cubic.w_last_max == w_last_max_1);
}

static void test_cubic_undo_ecn_not_undoable(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0);

    /* zero bytes => ECN signal rather than a lost packet; it enters recovery but arms no undo */
    cc.type->cc_on_lost(&cc, &loss, 0, 10, 20, 1000, mtu);
    ok(cc.recovery_end == 20);
    ok(cc.num_loss_episodes == 1);
    ok(cc.state.cubic.undo.num_packets_lost == 0);
    uint32_t reduced_cwnd = cc.cwnd;

    cc.type->cc_on_late_ack(&cc, 10, 1100);
    ok(cc.cwnd == reduced_cwnd);
    ok(cc.num_loss_episodes == 1);
    ok(cc.num_loss_episodes_undone == 0);
}

static void test_cubic_undo_jumpstart_loss(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu, jumpcwnd = 24 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0);
    cc.type->cc_jumpstart(&cc, jumpcwnd, 10);
    ok(quicly_cc_in_jumpstart(&cc));
    ok(cc.cwnd == jumpcwnd);

    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.cubic.undo.cwnd == jumpcwnd / 2);
    ok(cc.cwnd < jumpcwnd);
    ok(!quicly_cc_in_jumpstart(&cc));

    cc.type->cc_on_late_ack(&cc, 10, 1100);
    ok(cc.recovery_end == 0);
    ok(cc.cwnd == jumpcwnd / 2);
    ok(cc.ssthresh == UINT32_MAX);
    ok(!quicly_cc_in_jumpstart(&cc)); /* jumpstart is not re-entered after an undo */
}

static void test_rapid_start(void)
{
    struct st_quicly_cc_rapid_start_t rs;
    quicly_rtt_t rtt = {};

    quicly_cc_init_rapid_start(&rs, 1);
    rtt.minimum = rtt.latest = 16;

    ok(!quicly_cc_rapid_start_use_3x(&rs, &rtt)); /* no sample => 2x */
    quicly_cc_rapid_start_update_rtt(&rs, &rtt, 1);
    ok(quicly_cc_rapid_start_use_3x(&rs, &rtt)); /* floor == min => 3x */

    /* 2 samples after 1/4 min_rtt */
    quicly_cc_rapid_start_update_rtt(&rs, &rtt, 5);
    ok(rs.rtt_samples[0] == 16);
    ok(rs.rtt_samples[1] == 16);
    ok(rs.rtt_samples[2] == UINT32_MAX);
    ok(quicly_cc_rapid_start_use_3x(&rs, &rtt)); /* floor == min => 3x */

    /* after another 1/2 min_rtt, rtt increases to min + 5 */
    rtt.latest = 21;
    quicly_cc_rapid_start_update_rtt(&rs, &rtt, 13);
    ok(rs.rtt_samples[0] == 21);
    ok(rs.rtt_samples[1] == UINT32_MAX);
    ok(rs.rtt_samples[2] == 16);
    ok(rs.rtt_samples[3] == 16);
    ok(quicly_cc_rapid_start_use_3x(&rs, &rtt)); /* floor == min => 3x */

    /* after another 1/2 min_rtt, smaller samples are pushed out */
    quicly_cc_rapid_start_update_rtt(&rs, &rtt, 21);
    ok(!quicly_cc_rapid_start_use_3x(&rs, &rtt));
}

void test_cc(void)
{
    subtest("rapid-start", test_rapid_start);
    subtest("pico-undo-loss", test_pico_undo_loss);
    subtest("pico-undo-multiple-losses", test_pico_undo_multiple_losses);
    subtest("pico-undo-rapid-start-loss", test_pico_undo_rapid_start_loss);
    subtest("pico-undo-jumpstart-loss", test_pico_undo_jumpstart_loss);
    subtest("cubic-undo-loss", test_cubic_undo_loss);
    subtest("cubic-undo-multiple-losses", test_cubic_undo_multiple_losses);
    subtest("cubic-undo-fast-convergence", test_cubic_undo_fast_convergence);
    subtest("cubic-undo-ecn-not-undoable", test_cubic_undo_ecn_not_undoable);
    subtest("cubic-undo-jumpstart-loss", test_cubic_undo_jumpstart_loss);
}
