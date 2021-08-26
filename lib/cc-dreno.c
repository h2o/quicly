/*
 * Copyright (c) 2021 Fastly, Janardhan Iyengar, Kazuho Oku
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
#include <stdlib.h>
#include "quicly/cc.h"
#include "quicly.h"

#define DELAY_TARGET_MSEC 20
#define BETA_DRAIN 0.4
#define BETA_PERIOD_MIN 10

static void schedule_next_drain(quicly_cc_t *cc, const quicly_loss_t *loss)
{
    cc->state.dreno.next_drain_episode = cc->num_loss_episodes + BETA_PERIOD_MIN + ((cc->cwnd ^ loss->rtt.smoothed) & 3);
}

static void on_lost(quicly_cc_t *cc, const quicly_loss_t *loss, uint64_t next_pn, uint32_t max_udp_payload_size)
{
    cc->recovery_end = next_pn;

    ++cc->num_loss_episodes;
    if (cc->cwnd_exiting_slow_start == 0) {
        cc->cwnd_exiting_slow_start = cc->cwnd;
        schedule_next_drain(cc, loss);
    }

    if (cc->state.dreno.next_drain_episode <= cc->num_loss_episodes) {
        cc->state.dreno.draining = 1;
        schedule_next_drain(cc, loss);
    } else {
        cc->state.dreno.draining = 0;
    }

    /* Reduce congestion window. */
    double beta;
    if (cc->state.dreno.draining) {
        fprintf(stderr, "***deep drain: %" PRIu32 "\n", cc->num_loss_episodes);
        beta = BETA_DRAIN;
    } else {
        beta = 1. - (double)DELAY_TARGET_MSEC / loss->rtt.latest2;
        if (beta < QUICLY_RENO_BETA)
            beta = QUICLY_RENO_BETA;
    }
    cc->cwnd *= beta;
    fprintf(stderr, "cwnd: %" PRIu32 ", next_pn: %" PRIu64 "\n", cc->cwnd, next_pn);
    if (cc->cwnd < QUICLY_MIN_CWND * max_udp_payload_size)
        cc->cwnd = QUICLY_MIN_CWND * max_udp_payload_size;
    cc->ssthresh = cc->cwnd;

    if (cc->cwnd_minimum > cc->cwnd)
        cc->cwnd_minimum = cc->cwnd;

    cc->state.dreno.rtt_floor = loss->rtt.latest2;
    fprintf(stderr, "on_lost floor=%" PRIu32 "\n", cc->state.dreno.rtt_floor);
}


static void dreno_on_acked(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                           uint64_t next_pn, int64_t now, uint32_t max_udp_payload_size)
{
    assert(inflight >= bytes);

    if (loss->rtt.latest2 < cc->state.dreno.rtt_floor) {
        cc->state.dreno.rtt_floor = loss->rtt.latest2;
        fprintf(stderr, "on_ack floor=%" PRIu32 "\n", cc->state.dreno.rtt_floor);
    }

    /* Do not increase congestion window while in recovery. */
    if (largest_acked < cc->recovery_end)
        return;

    /* delayed-based loss detection (TODO consider slow start) */
    if (cc->cwnd_exiting_slow_start != 0 && loss->rtt.latest2 >= cc->state.dreno.rtt_floor + DELAY_TARGET_MSEC) {
        on_lost(cc, loss, next_pn, max_udp_payload_size);
        return;
    }

    /* Slow start. */
    if (cc->cwnd < cc->ssthresh) {
        cc->cwnd += bytes;
        if (cc->cwnd_maximum < cc->cwnd)
            cc->cwnd_maximum = cc->cwnd;
        return;
    }
    /* Congestion avoidance. */
    cc->state.dreno.stash += cc->state.dreno.draining ? bytes * 10 : bytes;
    if (cc->state.dreno.stash < cc->cwnd)
        return;
    /* Increase congestion window by 1 MSS per congestion window acked. */
    uint32_t count = cc->state.dreno.stash / cc->cwnd;
    cc->state.dreno.stash -= count * cc->cwnd;
    cc->cwnd += count * max_udp_payload_size;
    if (cc->cwnd_maximum < cc->cwnd)
        cc->cwnd_maximum = cc->cwnd;
}

static void dreno_on_lost(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t lost_pn, uint64_t next_pn,
                          int64_t now, uint32_t max_udp_payload_size)
{
    /* Nothing to do if loss is in recovery window. */
    if (lost_pn < cc->recovery_end)
        return;

    on_lost(cc, loss, next_pn, max_udp_payload_size);
}


static int dreno_on_switch(quicly_cc_t *cc)
{
    return 0;
}

static void dreno_init(quicly_init_cc_t *self, quicly_cc_t *cc, uint32_t initcwnd, int64_t now)
{
    memset(cc, 0, sizeof(quicly_cc_t));
    cc->type = &quicly_cc_type_dreno;
    cc->cwnd = cc->cwnd_initial = cc->cwnd_maximum = initcwnd;
    cc->ssthresh = cc->cwnd_minimum = UINT32_MAX;
    cc->state.dreno.rtt_floor = UINT32_MAX;
}

quicly_cc_type_t quicly_cc_type_dreno = {"dreno",
                                        &quicly_cc_dreno_init,
                                        dreno_on_acked,
                                        dreno_on_lost,
                                        quicly_cc_reno_on_persistent_congestion,
                                        quicly_cc_reno_on_sent,
                                        dreno_on_switch};
quicly_init_cc_t quicly_cc_dreno_init = {dreno_init};
