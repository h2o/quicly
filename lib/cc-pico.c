/*
 * Copyright (c) 2021 Fastly, Kazuho Oku
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
#include <math.h>
#include "quicly/cc.h"
#include "quicly.h"

/**
 * When decreasing the CWND due to a loss event, amount of time relative to RTT spent in silence. After this period, Pico sends
 * packets at a slower rate until the end of the recovery period so that the size of CWND becomes QUICLY_RENO_BETA of the original
 * value.
 */
#define SILENCE_PERIOD 0.1
/**
 * CWND size is multiplied by this factor every RT, when it is likely that the bottleneck buffer is empty
 */
#define INCREASE_RATIO_WHEN_EMPTY 0.05

/**
 * Calculates the increase ratio to be used in congestion avoidance phase.
 */
static uint32_t calc_bytes_per_mtu_increase(uint32_t cwnd, uint32_t rtt, uint32_t mtu)
{
    /* Reno: CWND size after reduction */
    uint32_t reno = cwnd * QUICLY_RENO_BETA;
    /* Cubic: Average of `(CWND / RTT) * K / 0.3CWND`, where K and CWND have two modes due to "fast convergence." */
    uint32_t cubic = 1.447 / 0.3 * 1000 * cbrt(0.3 / 0.4 * cwnd / mtu) / rtt * mtu;

    return reno < cubic ? reno : cubic;
}

/**
 * Adjusts `quicly_cc_t` after CWND is reduced.
 */
static void fixup_post_cwnd_reduction(quicly_cc_t *cc, uint32_t max_udp_payload_size)
{
    if (cc->cwnd < QUICLY_MIN_CWND * max_udp_payload_size)
        cc->cwnd = QUICLY_MIN_CWND * max_udp_payload_size;
    cc->ssthresh = cc->cwnd;

    if (cc->cwnd_minimum > cc->cwnd)
        cc->cwnd_minimum = cc->cwnd;
}

static int handle_recovery_period(quicly_cc_t *cc, uint64_t pn, uint32_t bytes, uint32_t max_udp_payload_size)
{
    if (pn < cc->recovery_end) {
        cc->cwnd -= bytes * (1 - QUICLY_RENO_BETA / (1. - SILENCE_PERIOD));
        if (cc->cwnd < cc->state.pico.cwnd_post_recovery)
            cc->cwnd = cc->state.pico.cwnd_post_recovery;
        fixup_post_cwnd_reduction(cc, max_udp_payload_size);
        return 1;
    } else {
        if (cc->state.pico.cwnd_post_recovery != 0) {
            cc->cwnd = cc->state.pico.cwnd_post_recovery;
            fixup_post_cwnd_reduction(cc, max_udp_payload_size);
            cc->state.pico.cwnd_post_recovery = 0;
        }
            return 0;
    }
}

/* TODO: Avoid increase if sender was application limited. */
static void pico_on_acked(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                          uint64_t next_pn, int64_t now, uint32_t max_udp_payload_size)
{
    assert(inflight >= bytes);

    int rtt_at_floor = 0;
    if (loss->rtt.latest_as_reported <= cc->state.pico.rtt_floor) {
        rtt_at_floor = 1;
        cc->state.pico.rtt_floor = loss->rtt.latest_as_reported;
    }

    /* Do not increase congestion window while in recovery. */
    if (handle_recovery_period(cc, largest_acked, bytes, max_udp_payload_size))
        return;

    cc->state.reno.stash += bytes;

    /* Calculate the amount of bytes required to be acked for incrementing CWND by one MTU. */
    uint32_t bytes_per_mtu_increase;
    if (cc->cwnd < cc->ssthresh) {
        bytes_per_mtu_increase = max_udp_payload_size;
    } else {
        bytes_per_mtu_increase = cc->state.pico.bytes_per_mtu_increase;
        if (rtt_at_floor) {
            uint32_t rapid_increase = max_udp_payload_size / INCREASE_RATIO_WHEN_EMPTY;
            if (rapid_increase < bytes_per_mtu_increase)
                bytes_per_mtu_increase += rapid_increase;
        }
    }

    /* Bail out if we do not yet have enough bytes being acked. */
    if (cc->state.reno.stash < bytes_per_mtu_increase)
        return;

    /* Update CWND, reducing stash relative to the amount we've adjusted the CWND */
    uint32_t count = cc->state.reno.stash / bytes_per_mtu_increase;
    cc->cwnd += count * max_udp_payload_size;
    cc->state.reno.stash -= count * bytes_per_mtu_increase;

    if (cc->cwnd_maximum < cc->cwnd)
        cc->cwnd_maximum = cc->cwnd;
}

static void pico_on_lost(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t lost_pn, uint64_t next_pn,
                         int64_t now, uint32_t max_udp_payload_size)
{
    if (handle_recovery_period(cc, lost_pn, bytes, max_udp_payload_size))
        return;

    cc->recovery_end = next_pn;

    ++cc->num_loss_episodes;
    if (cc->cwnd_exiting_slow_start == 0)
        cc->cwnd_exiting_slow_start = cc->cwnd;

    /* Calculate increase rate. */
    cc->state.pico.bytes_per_mtu_increase = calc_bytes_per_mtu_increase(cc->cwnd, loss->rtt.smoothed, max_udp_payload_size);

    /* Reduce congestion window. */
    cc->state.pico.cwnd_post_recovery = cc->cwnd * QUICLY_RENO_BETA;
    cc->cwnd *= 1. - SILENCE_PERIOD;
    fixup_post_cwnd_reduction(cc, max_udp_payload_size);

    if (cc->cwnd_minimum > cc->cwnd)
        cc->cwnd_minimum = cc->cwnd;

    cc->state.pico.stash = 0;
    cc->state.pico.rtt_floor = loss->rtt.latest_as_reported;
}

static void pico_on_persistent_congestion(quicly_cc_t *cc, const quicly_loss_t *loss, int64_t now)
{
    /* TODO */
}

static void pico_on_sent(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, int64_t now)
{
    /* Unused */
}

static void pico_init_pico_state(quicly_cc_t *cc, uint32_t stash)
{
    cc->state.pico.stash = stash;
    cc->state.pico.bytes_per_mtu_increase = cc->cwnd * QUICLY_RENO_BETA; /* use Reno, for simplicity */
}

static void pico_reset(quicly_cc_t *cc, uint32_t initcwnd)
{
    *cc = (quicly_cc_t){
        .type = &quicly_cc_type_pico,
        .cwnd = initcwnd,
        .cwnd_initial = initcwnd,
        .cwnd_maximum = initcwnd,
        .cwnd_minimum = UINT32_MAX,
        .ssthresh = UINT32_MAX,
    };
    pico_init_pico_state(cc, 0);
}

static int pico_on_switch(quicly_cc_t *cc)
{
    if (cc->type == &quicly_cc_type_pico) {
        return 1; /* nothing to do */
    } else if (cc->type == &quicly_cc_type_reno) {
        cc->type = &quicly_cc_type_reno;
        pico_init_pico_state(cc, cc->state.reno.stash);
        return 1;
    } else if (cc->type == &quicly_cc_type_cubic) {
        /* When in slow start, state can be reused as-is; otherwise, restart. */
        if (cc->cwnd_exiting_slow_start == 0) {
            cc->type = &quicly_cc_type_reno;
            pico_init_pico_state(cc, 0);
        } else {
            pico_reset(cc, cc->cwnd_initial);
        }
        return 1;
    }

    return 0;
}

static void pico_init(quicly_init_cc_t *self, quicly_cc_t *cc, uint32_t initcwnd, int64_t now)
{
    pico_reset(cc, initcwnd);
}

quicly_cc_type_t quicly_cc_type_pico = {
    "pico", &quicly_cc_pico_init, pico_on_acked, pico_on_lost, pico_on_persistent_congestion, pico_on_sent, pico_on_switch};
quicly_init_cc_t quicly_cc_pico_init = {pico_init};
