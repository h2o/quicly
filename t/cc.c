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

/**
 * Compares CWND against a value calculated using floating point arithmetic, tolerating an off-by-one; the compiler is allowed to
 * evaluate the same expression differently between translation units (e.g., by contracting a multiply-add into an FMA).
 */
static int cwnd_is(uint32_t actual, double expected)
{
    uint32_t truncated = (uint32_t)expected;
    return actual == truncated || actual == truncated + 1 || actual + 1 == truncated;
}

static void test_pico_ecn(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, initcwnd, 0);

    /* exit slow start by observing a packet loss */
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.cwnd == initcwnd / 2);
    ok(cc.num_ecn_loss_episodes == 0);
    uint32_t cwnd_in_ca = cc.cwnd;

    /* a CE mark (i.e., zero-byte congestion report) reduces CWND by QUICLY_BETA_ECN rather than by QUICLY_BETA_LOSS */
    cc.type->cc_on_lost(&cc, &loss, 0, 20, 30, 1100, mtu);
    ok(cc.num_loss_episodes == 2);
    ok(cc.num_ecn_loss_episodes == 1);
    ok(cwnd_is(cc.cwnd, cwnd_in_ca * QUICLY_BETA_ECN));
    ok(cc.ssthresh == cc.cwnd);
    ok(cc.state.pico.undo.num_packets_lost == 0); /* CE marks cannot be undone by late ACKs */
    /* the increase rate follows the factor being used; here, Reno's 1 MTU per RTT, i.e. per post-reduction CWND bytes acked */
    ok(cc.state.pico.bytes_per_mtu_increase == cc.cwnd);

    /* a packet loss reduces CWND by QUICLY_BETA_LOSS */
    uint32_t cwnd_before_loss = cc.cwnd;
    cc.type->cc_on_lost(&cc, &loss, mtu, 30, 40, 1200, mtu);
    ok(cc.num_ecn_loss_episodes == 1);
    ok(cwnd_is(cc.cwnd, cwnd_before_loss * QUICLY_BETA_LOSS));
}

static void test_pico_ecn_rapid_start(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, initcwnd, 0);
    cc.type->enable_rapid_start(&cc, 900);

    /* upon a CE mark, the silence factor derived from QUICLY_BETA_ECN (i.e., 0.95x) is applied */
    cc.type->cc_on_lost(&cc, &loss, 0, 10, 20, 1000, mtu);
    ok(cc.rapid_start.newest_rtt_sample_until == -1);
    ok(cc.rapid_start.recovery.by_ecn);
    ok(cwnd_is(cc.cwnd, initcwnd * QUICLY_RAPID_START_LOSS_FACTOR(QUICLY_BETA_ECN)));
    uint32_t cwnd_entering_recovery = cc.cwnd;

    /* during the recovery period, CWND is reduced by ack_factor (0.1x) per byte newly acked */
    cc.type->cc_on_acked(&cc, &loss, 4 * mtu, 15, 8 * mtu, 1, 20, 1100, mtu);
    ok(cwnd_is(cc.cwnd, cwnd_entering_recovery - QUICLY_RAPID_START_ACK_FACTOR(QUICLY_BETA_ECN) * (4 * mtu)));
    uint32_t cwnd_after_ack = cc.cwnd;

    /* a packet loss detected within the same recovery period is accounted using loss_factor (0.95x), the factor being retained
     * from when the recovery period was entered, even though the episode is no longer counted as an ECN-only one */
    cc.type->cc_on_lost(&cc, &loss, mtu, 16, 20, 1100, mtu);
    ok(cc.num_loss_episodes == 1);
    ok(cc.num_ecn_loss_episodes == 0);
    ok(cwnd_is(cc.cwnd, cwnd_after_ack - QUICLY_RAPID_START_LOSS_FACTOR(QUICLY_BETA_ECN) * mtu));
}

static void test_cubic_fast_convergence(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 100 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0);

    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.pico.cubic.w_max == 50 * mtu);
    ok(cc.state.pico.cubic.w_est == 0);

    cc.cwnd = 45 * mtu;
    cc.type->cc_on_lost(&cc, &loss, mtu, 20, 30, 1100, mtu);
    ok(cc.state.pico.cubic.w_max == 45 * mtu * 85 / 100);
    ok(cc.state.pico.cubic.w_est == 0);

    /* The effective W_max is 38.25 MTUs, so a 40-MTU congestion window does not trigger fast convergence again. */
    cc.cwnd = 40 * mtu;
    cc.type->cc_on_lost(&cc, &loss, mtu, 30, 40, 1200, mtu);
    ok(cc.state.pico.cubic.w_max == 40 * mtu);
    ok(cc.state.pico.cubic.cwnd_prior == 40 * mtu);
    ok(cc.state.pico.cubic.w_est == 0);
}

static void test_cubic_target_bounds(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0);
    cc.ssthresh = cc.cwnd;
    cc.state.pico.cubic.w_max = cc.cwnd;
    cc.state.pico.cubic.w_est = cc.cwnd;
    cc.state.pico.cubic.cwnd_prior = cc.cwnd;

    cc.type->cc_on_acked(&cc, &loss, mtu, 1, cc.cwnd, 1, 2, 1000000, mtu);
    ok(cc.cwnd == initcwnd + mtu / 2);

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0);
    cc.ssthresh = cc.cwnd;
    cc.state.pico.cubic.w_max = cc.cwnd / 2;
    cc.state.pico.cubic.cwnd_prior = cc.cwnd;
    cc.state.pico.cubic.w_est = cc.state.pico.cubic.w_max - 1;
    cc.type->cc_on_acked(&cc, &loss, 0, 1, cc.cwnd, 1, 2, 0, mtu);
    ok(cc.cwnd == initcwnd);
}

static void test_cubic_rapid_start_epoch(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0);
    cc.type->enable_rapid_start(&cc, 900);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.pico.cubic.w_max != 0);
    ok(cc.state.pico.cubic.cwnd_prior != 0);
    ok(cc.state.pico.cubic.w_est == 0);
    ok(cc.state.pico.cubic.epoch_start == 1000);

    cc.type->cc_on_acked(&cc, &loss, 4 * mtu, 15, 8 * mtu, 1, 20, 1100, mtu);
    uint32_t cwnd_prior_during_recovery = cc.state.pico.cubic.cwnd_prior;
    ok(cc.state.pico.cubic.w_est == 0);
    ok(cc.state.pico.cubic.epoch_start == 1000);

    /* Further reduction during recovery does not initialize or restart the epoch. */
    cc.type->cc_on_lost(&cc, &loss, mtu, 16, 20, 1150, mtu);
    ok(cc.state.pico.cubic.w_est == 0);
    ok(cc.state.pico.cubic.epoch_start == 1000);
    uint32_t cwnd_epoch = cc.cwnd;

    /* The first ACK beyond recovery establishes the Cubic epoch from Rapid Start's progressively reduced CWND. */
    cc.type->cc_on_acked(&cc, &loss, 0, 20, 0, 1, 21, 1200, mtu);
    ok(cc.state.pico.cubic.cwnd_prior == (uint32_t)(cwnd_epoch / QUICLY_BETA_LOSS));
    ok(cc.state.pico.cubic.cwnd_prior != cwnd_prior_during_recovery);
    ok(cc.state.pico.cubic.w_max == cc.state.pico.cubic.cwnd_prior);
    ok(cc.state.pico.cubic.w_est == cwnd_epoch);
    ok(cc.state.pico.cubic.epoch_start == 1000);
}

static void test_cubic_abe(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 100 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0);

    /* Establish a 50-MTU W_max when leaving ordinary slow start. */
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.pico.cubic.w_max == 50 * mtu);

    /* An ECN event below W_max reduces by 0.85 and applies FC using (1 + 0.85) / 2, i.e. 0.925. */
    cc.cwnd = 45 * mtu;
    cc.type->cc_on_lost(&cc, &loss, 0, 20, 30, 1100, mtu);
    ok(cc.state.pico.cubic.by_ecn);
    ok(cc.cwnd == (uint32_t)(45 * mtu * QUICLY_BETA_ECN));
    ok(cc.state.pico.cubic.w_max == (uint32_t)(45 * mtu * (1 + QUICLY_BETA_ECN) / 2));
    ok(cc.state.pico.cubic.k == 0);

    /* The ECN epoch uses alpha_ecn ~= 0.729, and Cubic intentionally ignores cc_limited for now. */
    uint32_t cwnd_epoch = cc.cwnd;
    double expected_w_est =
        cwnd_epoch + (1 + 0.8) * (1 - QUICLY_BETA_ECN) / ((1 - 0.8) * (1 + QUICLY_BETA_ECN)) * mtu / cwnd_epoch * mtu;
    cc.type->cc_on_acked(&cc, &loss, mtu, 30, mtu, 0, 31, 1200, mtu);
    ok(cc.state.pico.cubic.k > 0);
    ok((uint32_t)cc.state.pico.cubic.w_est == (uint32_t)expected_w_est);
}

static void test_cubic_undo_loss(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.pico.cubic.cwnd_prior != 0);

    cc.type->cc_on_late_ack(&cc, 10, 1100);
    ok(cc.cwnd == initcwnd);
    ok(cc.ssthresh == UINT32_MAX);
    ok(cc.recovery_end == 0);
    ok(cc.state.pico.cubic.cwnd_prior == 0);
    ok(cc.num_loss_episodes_undone == 1);
}

static void test_cubic_legacy_name(void)
{
    quicly_cc_t cc;

    quicly_cc_cubic_legacy_init.cb(&quicly_cc_cubic_legacy_init, &cc, 12000, 0);
    ok(cc.type == &quicly_cc_type_cubic_legacy);
    ok(strcmp(cc.type->name, "cubic-legacy") == 0);
}

static void test_pico_ack_countdown(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, initcwnd, 0);
    cc.type->cc_on_acked(&cc, &loss, mtu - 1, 1, mtu - 1, 1, 2, 100, mtu);
    ok(cc.cwnd == initcwnd);
    ok(cc.state.pico.bytes_to_mtu_increase == 1);

    cc.type->cc_on_acked(&cc, &loss, 1, 2, 1, 1, 3, 100, mtu);
    ok(cc.cwnd == initcwnd + mtu);
    ok(cc.state.pico.bytes_to_mtu_increase == mtu);

    /* The interval switches to Pico's congestion-avoidance rate when an increase reaches ssthresh. */
    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, initcwnd, 0);
    cc.ssthresh = initcwnd + mtu;
    cc.type->cc_on_acked(&cc, &loss, mtu, 1, mtu, 1, 2, 100, mtu);
    ok(cc.cwnd == cc.ssthresh);
    ok(cc.state.pico.bytes_to_mtu_increase == initcwnd * QUICLY_BETA_LOSS);
}

static void test_pico_switch_resets_ack_credit(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_reno_init.cb(&quicly_cc_reno_init, &cc, initcwnd, 0);
    cc.ssthresh = cc.cwnd;
    cc.type->cc_on_acked(&cc, &loss, initcwnd - 1, 1, initcwnd - 1, 1, 2, 100, mtu);
    ok(cc.cwnd == initcwnd);
    ok(cc.state.pico.bytes_to_mtu_increase == 1);

    ok(quicly_cc_type_pico.cc_switch(&cc));
    ok(cc.state.pico.bytes_to_mtu_increase == 0);
    cc.type->cc_on_acked(&cc, &loss, 1, 2, 1, 1, 3, 100, mtu);
    ok(cc.cwnd == initcwnd);
    ok(cc.state.pico.bytes_to_mtu_increase == initcwnd * QUICLY_BETA_LOSS - 1);

    ok(quicly_cc_type_reno.cc_switch(&cc));
    ok(cc.state.pico.bytes_to_mtu_increase == 0);
    ok(cc.state.pico.reno.beta == QUICLY_BETA_LOSS);

    ok(quicly_cc_type_reno5.cc_switch(&cc));
    ok(cc.state.pico.reno.beta == QUICLY_BETA_RENO5);
}

static void test_reno_policy(quicly_init_cc_t *init, double beta)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 100 * mtu;

    /* Reno grows by one MTU for each current-CWND bytes acknowledged. */
    init->cb(init, &cc, initcwnd, 0);
    ok(cc.state.pico.reno.beta == beta);
    cc.ssthresh = cc.cwnd;
    cc.type->cc_on_acked(&cc, &loss, initcwnd - 1, 1, initcwnd - 1, 1, 2, 100, mtu);
    ok(cc.cwnd == initcwnd);
    ok(cc.state.pico.bytes_to_mtu_increase == 1);
    cc.type->cc_on_acked(&cc, &loss, 1, 2, 1, 1, 3, 100, mtu);
    ok(cc.cwnd == initcwnd + mtu);

    /* Startup uses the shared 0.5 reduction; subsequent loss uses the policy beta. */
    init->cb(init, &cc, initcwnd, 0);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.cwnd == initcwnd / 2);
    cc.cwnd = 40 * mtu;
    cc.type->cc_on_lost(&cc, &loss, mtu, 20, 30, 1100, mtu);
    ok(cwnd_is(cc.cwnd, 40 * mtu * beta));
    ok(cc.state.pico.bytes_to_mtu_increase == 0);
    cc.type->cc_on_acked(&cc, &loss, mtu, 30, mtu, 1, 31, 1200, mtu);
    ok(cc.state.pico.bytes_to_mtu_increase == cc.cwnd - mtu);

    /* Reno policies use the same beta for ECN and packet loss. */
    init->cb(init, &cc, initcwnd, 0);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    cc.cwnd = 40 * mtu;
    cc.type->cc_on_lost(&cc, &loss, 0, 20, 30, 1100, mtu);
    ok(cwnd_is(cc.cwnd, 40 * mtu * beta));
}

static void test_cuback_reno_friendly_post_bdp_estimate(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, w_max = 2 * mtu;

    quicly_cc_cuback_init.cb(&quicly_cc_cuback_init, &cc, w_max, 0);
    cc.ssthresh = cc.cwnd;
    cc.state.pico.cuback.cwnd_prior = w_max;
    cc.state.pico.cuback.bandwidth = w_max * 1000. / loss.rtt.smoothed;
    cc.state.pico.bytes_to_mtu_increase = 0;

    /* Above W_max, RFC 9438 uses alpha == 1. Moving from 2 to 3 MTUs therefore requires (3^2 - 2^2) / 2 == 2.5 MTUs
     * to be acknowledged. As the first ACK of an epoch also receives CWND bytes of credit (Cubic being at W(RTT) when it
     * exits recovery), only the remainder has to be supplied here. */
    cc.type->cc_on_acked(&cc, &loss, 5 * mtu / 2 - 1 - w_max, 1, 5 * mtu / 2 - 1 - w_max, 1, 2, 100, mtu);
    ok(cc.cwnd == w_max);
    ok(cc.state.pico.bytes_to_mtu_increase == 1);
    cc.type->cc_on_acked(&cc, &loss, 1, 2, 1, 1, 3, 100, mtu);
    ok(cc.cwnd == w_max + mtu);
    ok(cc.state.pico.bytes_to_mtu_increase == 7 * mtu / 2);
}

static void test_cuback_deferred_bdp_estimate(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    /* An ordinary first loss retains the estimated BDP as W_max, matching HEAD's special 0.5 startup reduction. */
    quicly_cc_cuback_init.cb(&quicly_cc_cuback_init, &cc, initcwnd, 0);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.pico.cuback.cwnd_prior == initcwnd / 2);

    /* Rapid Start continues adjusting CWND throughout recovery, so W_max is derived from the final CWND afterward. */
    quicly_cc_cuback_init.cb(&quicly_cc_cuback_init, &cc, initcwnd, 0);
    cc.type->enable_rapid_start(&cc, 900);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.pico.cuback.bandwidth > 0);
    ok(cc.state.pico.cuback.cwnd_prior == 0);
    ok(cc.state.pico.bytes_to_mtu_increase == 0);

    uint32_t cwnd_after_recovery = cc.cwnd;
    cc.type->cc_on_acked(&cc, &loss, 1, 20, 1, 1, 21, 1100, mtu);
    ok(cc.state.pico.cuback.cwnd_prior == (uint32_t)(cwnd_after_recovery / QUICLY_BETA_LOSS));
    ok(cc.state.pico.bytes_to_mtu_increase != 0);
}

static void test_cuback_fast_convergence_rising_epochs(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 200 * mtu;
    uint64_t pn = 10;

    quicly_cc_cuback_init.cb(&quicly_cc_cuback_init, &cc, initcwnd, 0);

    /* The startup reduction establishes a 100-MTU raw peak. */
    cc.type->cc_on_lost(&cc, &loss, mtu, pn, pn + 10, 1000, mtu);
    pn += 10;
    ok(cc.state.pico.cuback.cwnd_prior == 100 * mtu);
    ok(cc.state.pico.cuback.rising_epochs == 0);

    /* Exactly 1% is treated as noise and does not begin a rising streak. */
    cc.cwnd = cc.state.pico.cuback.cwnd_prior * 101 / 100;
    cc.type->cc_on_lost(&cc, &loss, mtu, pn, pn + 10, 1100, mtu);
    pn += 10;
    ok(!cc.state.pico.cuback.fast_convergence);
    ok(cc.state.pico.cuback.rising_epochs == 0);

    /* Two non-FC peaks rising by more than 1% arm one-shot suppression. */
    cc.cwnd = 1.01 * cc.state.pico.cuback.cwnd_prior + 1;
    cc.type->cc_on_lost(&cc, &loss, mtu, pn, pn + 10, 1200, mtu);
    pn += 10;
    ok(!cc.state.pico.cuback.fast_convergence);
    ok(cc.state.pico.cuback.rising_epochs == 1);
    cc.cwnd = 1.01 * cc.state.pico.cuback.cwnd_prior + 1;
    cc.type->cc_on_lost(&cc, &loss, mtu, pn, pn + 10, 1300, mtu);
    pn += 10;
    ok(!cc.state.pico.cuback.fast_convergence);
    ok(cc.state.pico.cuback.rising_epochs == 2);

    /* The first lower peak does not enter FC, but consumes the protection. A further reduction enters FC normally. */
    cc.cwnd = cc.state.pico.cuback.cwnd_prior - mtu;
    cc.type->cc_on_lost(&cc, &loss, mtu, pn, pn + 10, 1400, mtu);
    pn += 10;
    ok(!cc.state.pico.cuback.fast_convergence);
    ok(cc.state.pico.cuback.rising_epochs == 0);
    cc.cwnd = cc.state.pico.cuback.cwnd_prior - mtu;
    cc.type->cc_on_lost(&cc, &loss, mtu, pn, pn + 10, 1500, mtu);
    ok(cc.state.pico.cuback.fast_convergence);
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
    subtest("reno", test_reno_policy, &quicly_cc_reno_init, QUICLY_BETA_LOSS);
    subtest("reno5", test_reno_policy, &quicly_cc_reno5_init, QUICLY_BETA_RENO5);
    subtest("cubic-fast-convergence", test_cubic_fast_convergence);
    subtest("cubic-target-bounds", test_cubic_target_bounds);
    subtest("cubic-rapid-start-epoch", test_cubic_rapid_start_epoch);
    subtest("cubic-abe", test_cubic_abe);
    subtest("cubic-undo-loss", test_cubic_undo_loss);
    subtest("cubic-legacy-name", test_cubic_legacy_name);
    subtest("pico-ack-countdown", test_pico_ack_countdown);
    subtest("pico-switch-resets-ack-credit", test_pico_switch_resets_ack_credit);
    subtest("cuback-reno-friendly-post-bdp-estimate", test_cuback_reno_friendly_post_bdp_estimate);
    subtest("cuback-deferred-bdp-estimate", test_cuback_deferred_bdp_estimate);
    subtest("cuback-fast-convergence-rising-epochs", test_cuback_fast_convergence_rising_epochs);
    subtest("pico-undo-loss", test_pico_undo_loss);
    subtest("pico-undo-multiple-losses", test_pico_undo_multiple_losses);
    subtest("pico-undo-rapid-start-loss", test_pico_undo_rapid_start_loss);
    subtest("pico-undo-jumpstart-loss", test_pico_undo_jumpstart_loss);
    subtest("pico-ecn", test_pico_ecn);
    subtest("pico-ecn-rapid-start", test_pico_ecn_rapid_start);
}
