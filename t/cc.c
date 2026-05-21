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
}
