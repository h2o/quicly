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
#include <stdlib.h>
#include "quicly/cc.h"
#include "quicly.h"

#define DELAY_TARGET_MSEC 5
#define DRAIN_INTERVAL_NUM_EPISODES 12

static void schedule_next_drain(quicly_cc_t *cc, const quicly_loss_t *loss, int64_t now, int in_delay_mode)
{
    if (in_delay_mode) {
        /* In delay mode, drain interval is set relative to RTT. The rationale is:
         * * The amount of bandwidth being released amortized over time should be independent from RTT and relative only to the flow
         *   rate.
         * * Assuming that the increase ratio used after draining is relative to the RTT, drain period should also be relative to
         *   the RTT in order to achieve fairness.
         */
        cc->state.pico.delay_based.next_drain.at = now + 50 * loss->rtt.smoothed;
        fprintf(stderr, "%s: delay-mode; now=%" PRId64 ", at=%" PRId64 "\n", __FUNCTION__, now,
                cc->state.pico.delay_based.next_drain.at);
    } else {
        /* between 0.75x - 1.25x of DRAIN_INTERVAL_NUM_EPISODES */
        uint32_t ratio_permil = 768 + (rand() % 512);
        cc->state.pico.delay_based.next_drain.loss_episode =
            cc->num_loss_episodes + DRAIN_INTERVAL_NUM_EPISODES * ratio_permil / 1024;
        fprintf(stderr, "%s: loss-mode; episode=%" PRIu32 "\n", __FUNCTION__, cc->state.pico.delay_based.next_drain.loss_episode);
    }
}

static int should_drain(quicly_cc_t *cc, int64_t now, int in_delay_mode)
{
    if (in_delay_mode) {
        return cc->state.pico.delay_based.next_drain.at <= now;
    } else {
        return cc->state.pico.delay_based.next_drain.loss_episode <= cc->num_loss_episodes;
    }
}

/**
 * Calculates the increase ratio to be used in congestion avoidance phase.
 */
static uint32_t calc_bytes_per_mtu_increase(uint32_t cwnd, uint32_t rtt, uint32_t mtu)
{
    /* Reno: CWND size after reduction */
    uint32_t reno = cwnd * QUICLY_RENO_BETA;
    /* Cubic: Average of `(CWND / RTT) * K / 0.3CWND`, where K and CWND have two modes due to "fast convergence." */
    uint32_t cubic = 1.447 / 0.3 * 1000 * cbrt(0.3 / 0.4 * cwnd / mtu) / rtt * mtu;

    fprintf(stderr, "reno: %" PRIu32 ", cubic: %" PRIu32 "\n", reno, cubic);
    return reno < cubic ? reno : cubic;
}

static void on_lost(quicly_cc_t *cc, const quicly_loss_t *loss, uint64_t next_pn, int64_t now, uint32_t max_udp_payload_size)
{
    cc->recovery_end = next_pn;

    ++cc->num_loss_episodes;
    if (cc->cwnd_exiting_slow_start == 0) {
        cc->cwnd_exiting_slow_start = cc->cwnd;
        cc->state.pico.delay_based.next_drain.loss_episode = 3;
    }

#define SET_CWND(w, d)                                                                                                             \
    do {                                                                                                                           \
        cc->cwnd = (w);                                                                                                            \
        if (cc->cwnd < QUICLY_MIN_CWND * max_udp_payload_size)                                                                     \
            cc->cwnd = QUICLY_MIN_CWND * max_udp_payload_size;                                                                     \
        if (!(d))                                                                                                                  \
            cc->ssthresh = cc->cwnd;                                                                                               \
        if (cc->cwnd_minimum > cc->cwnd)                                                                                           \
            cc->cwnd_minimum = cc->cwnd;                                                                                           \
    } while (0)

    if (should_drain(cc, now, cc->state.pico.delay_based.in_delay_mode)) {
        /* Draining. */
        schedule_next_drain(cc, loss, now, 1);
        double beta;
        if (cc->state.pico.delay_based.in_delay_mode) {
            uint32_t rtt_current = loss->rtt.smoothed + loss->rtt.variance;
            if (rtt_current < cc->state.pico.delay_based.rtt_floor + DELAY_TARGET_MSEC)
                rtt_current = cc->state.pico.delay_based.rtt_floor + DELAY_TARGET_MSEC;
            beta = 1 - (1 - ((double)cc->state.pico.delay_based.rtt_floor / rtt_current)) * 2;
            if (beta < QUICLY_RENO_BETA)
                beta = QUICLY_RENO_BETA;
        } else {
            beta = 0.4;
        }
        fprintf(stderr, "drain@%" PRId64 ": cwnd: %" PRIu32 ", rtt_floor: %" PRIu32 ", srtt: %" PRIu32 ", beta: %f\n", now,
                cc->cwnd, cc->state.pico.delay_based.rtt_floor, loss->rtt.smoothed, beta);
        cc->state.pico.bytes_per_mtu_increase = calc_bytes_per_mtu_increase(cc->cwnd, loss->rtt.smoothed, max_udp_payload_size);
        SET_CWND(cc->cwnd * beta, 1);
        cc->state.pico.delay_based.in_delay_mode = 1;
        cc->state.pico.delay_based.rtt_floor = loss->rtt.latest_as_reported;
    } else {
        /* Loss-based. Use Cubic-friendly values. */
        cc->state.pico.bytes_per_mtu_increase = calc_bytes_per_mtu_increase(cc->cwnd, loss->rtt.smoothed, max_udp_payload_size);
        if (cc->state.pico.delay_based.in_delay_mode || cc->state.pico.delay_based.rapid_increase_on_next_loss) {
            /* Switching from delay-based to loss-based. Because it is likely that we have given up B/W due to repeated delay-based
             * reduction, we do a rapid increase, in order to regain bandwidth from the competing flow, hoping that we'd be on
             * parity well before we drain the next time. */
            cc->state.pico.delay_based.in_delay_mode = 0;
            cc->state.pico.delay_based.rapid_increase_on_next_loss = 0;
            cc->state.pico.bytes_per_mtu_increase /= 8;
            if (cc->state.pico.bytes_per_mtu_increase < max_udp_payload_size)
                cc->state.pico.bytes_per_mtu_increase = max_udp_payload_size;
            schedule_next_drain(cc, loss, now, 0);
        }
        fprintf(stderr, "loss@%" PRId64 ": cwnd: %" PRIu32 ", increase: %f\n", now, cc->cwnd,
                (double)max_udp_payload_size / cc->state.pico.bytes_per_mtu_increase);
        SET_CWND(cc->cwnd * QUICLY_RENO_BETA, 0);
        cc->state.pico.delay_based.rtt_loss = loss->rtt.latest_as_reported;
    }

#undef SET_CWND
}

/* TODO: Avoid increase if sender was application limited. */
static void pico_on_acked(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                          uint64_t next_pn, int64_t now, uint32_t max_udp_payload_size)
{
    assert(inflight >= bytes);

    if (loss->rtt.latest_as_reported < cc->state.pico.delay_based.rtt_floor)
        cc->state.pico.delay_based.rtt_floor = loss->rtt.latest_as_reported;

    /* Do not increase congestion window while in recovery. */
    if (largest_acked < cc->recovery_end)
        return;

    cc->state.reno.stash += bytes;

    uint32_t bytes_per_mtu_increase;

    if (cc->state.pico.delay_based.in_delay_mode) {
        /* Delay-based */
        if (loss->rtt.latest_as_reported > cc->state.pico.delay_based.rtt_loss * 0.9) {
            /* It is likely that there's competing loss-based traffic, hence switch to loss-based mode. */
            fprintf(stderr, "time-based fallback to loss-based mode\n");
            schedule_next_drain(cc, loss, now, 0);
            cc->state.pico.bytes_per_mtu_increase =
                calc_bytes_per_mtu_increase(cc->cwnd * QUICLY_RENO_BETA, loss->rtt.smoothed, max_udp_payload_size);
            cc->state.pico.delay_based.in_delay_mode = 0;
            cc->state.pico.delay_based.rapid_increase_on_next_loss = 1;
            bytes_per_mtu_increase = cc->state.pico.bytes_per_mtu_increase;
        } else {
            /* drain when enough time has elapsed */
            if (cc->state.pico.delay_based.next_drain.at <= now) {
                on_lost(cc, loss, next_pn, now, max_udp_payload_size);
                return;
            }
            /* Additive increase while the delay is smaller than `rtt_floor`. Use large value so that the bandwidth would be
             * fulfilled at an early point. */
            if (loss->rtt.latest_as_reported < cc->state.pico.delay_based.rtt_floor + DELAY_TARGET_MSEC) {
                bytes_per_mtu_increase = cc->state.pico.bytes_per_mtu_increase;
                if (loss->rtt.latest_as_reported < cc->state.pico.delay_based.rtt_floor + 1) {
                    /* Bottleneck queue might be empty. Therefore, increase at at which we'd reach equilibrium within 1 second. */
                    uint32_t fast_increase = max_udp_payload_size / (loss->rtt.latest_as_reported / 1000. * (0.1 / 0.9));
                    if (fast_increase < bytes_per_mtu_increase)
                        bytes_per_mtu_increase = fast_increase;
                }
            } else {
                cc->state.reno.stash = cc->state.reno.stash > bytes * 2 ? cc->state.reno.stash - bytes * 2 : 0;
                bytes_per_mtu_increase = UINT32_MAX;
            }
        }
    } else if (cc->cwnd < cc->ssthresh) {
        /* Slow start. */
        bytes_per_mtu_increase = max_udp_payload_size;
    } else if (loss->rtt.latest_as_reported < cc->state.pico.delay_based.rtt_loss * 0.6) {
        /* During loss-based congestion avoidance, detected a dip beyond loss-based CC. Switch to delay-mode and see what
         * happens. */
        fprintf(stderr, "switching to delay-based mode\n");
        cc->state.pico.delay_based.in_delay_mode = 1;
        cc->state.pico.bytes_per_mtu_increase =
            calc_bytes_per_mtu_increase(cc->cwnd / QUICLY_RENO_BETA, cc->state.pico.delay_based.rtt_loss, max_udp_payload_size);
        cc->state.reno.stash = 0;
        bytes_per_mtu_increase = UINT32_MAX;
    } else {
        /* Loss-based congestion avoidance. */
        bytes_per_mtu_increase = cc->state.pico.bytes_per_mtu_increase;
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
    /* Nothing to do if loss is in recovery window. */
    if (lost_pn < cc->recovery_end)
        return;

    on_lost(cc, loss, next_pn, now, max_udp_payload_size);
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
    memset(&cc->state.pico.delay_based, 0, sizeof(cc->state.pico.delay_based));
    cc->state.pico.delay_based.rtt_floor = UINT32_MAX;
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
