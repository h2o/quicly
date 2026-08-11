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
#include "quicly/pacer.h"
#include "quicly/cc.h"
#include "quicly.h"

/**
 * C of Cubic
 */
#define QUICLY_CUBIC_C 0.4

/* Cubic reaches original CWND (i.e., Wmax) in K seconds, therefore:
 *   amount_to_increase = (1 - beta) * Wmax
 *   amount_to_be_acked = K * Wmax / RTT_at_Wmax
 * where
 *   K = ((1 - beta) / 0.4 * Wmax / MTU)^(1/3)
 *
 * In addition, when competition causes congestion peaks to decline gradually, fast-convergence and normal epochs are expected to
 * alternate: a peak below the retained Wmax triggers fast convergence, while the resulting Wmax of (1 + beta) / 2 (typically 0.85x)
 * makes the next peak a normal event unless it declines by more than 15%.
 *
 * When fast convergence occurs, Wmax becomes (1 + beta) / 2 while cwnd_epoch remains beta. The modified K (K') is therefore:
 *
 *   K' = ((1 - beta) / 2 / 0.4 * Wmax / MTU)^(1/3) = 0.5^(1/3) * K
 *
 * where K' represents the time to reach 0.85 * Wmax. As the cubic curve is point symmetric around that point, reaching the
 * original Wmax takes 2 * K'.
 *
 * Therefore, amortizing one fast-convergence period and one normal period gives:
 *
 *   K_amortized = (K + 2K') / 2 = (1 + 2 * 0.5^(1/3)) / 2 * K = 1.2937..
 */
#define QUICLY_CUBIC_FAST_CONVERGENCE_ADJUST ((1 + 2 * cbrt(0.5)) / 2)

/**
 * Calculates the increase ratio to be used in congestion avoidance phase.
 */
static uint32_t pico_bytes_per_mtu_increase(uint32_t cwnd, uint32_t rtt, uint32_t mtu)
{
    /* Reno: CWND size after reduction */
    uint32_t reno = cwnd * QUICLY_RENO_BETA;

    /* Cubic: Cubic reaches Wmax in K seconds */
    uint32_t cubic = QUICLY_CUBIC_FAST_CONVERGENCE_ADJUST / 0.3 * 1000 * cbrt(0.3 / 0.4 * cwnd / mtu) / rtt * mtu;

    return reno < cubic ? reno : cubic;
}

/**
 * Returns the time at which CWND reaches `w`, that being the inverse of `max(W_cubic, W_reno)`. Both curves increase monotonically,
 * hence so does their maximum, and the inverse of a maximum is the minimum of the inverses.
 */
static double cuback_time_at(const struct st_quicly_cc_cuback_t *state, double w, double anchor, double k, uint32_t mtu)
{
    static const double friendly_alpha = 3 * (1 - QUICLY_RENO_BETA) / (1 + QUICLY_RENO_BETA);

    double t_cubic = (k + cbrt((w - (double)state->w_max) / (QUICLY_CUBIC_C * mtu))) * QUICLY_CUBIC_FAST_CONVERGENCE_ADJUST;
    /* RFC 9438, Section 4.3 switches alpha to one after the Reno-friendly estimate reaches the congestion window prior to
     * reduction (W_max here). The inverse curve is therefore piecewise at W_max. */
    double w_friendly = w < state->w_max ? w : state->w_max;
    double t_reno = (w_friendly * w_friendly - anchor * anchor) / (2 * friendly_alpha * mtu * state->bandwidth);
    if (w > state->w_max)
        t_reno += (w * w - (double)state->w_max * state->w_max) / (2 * mtu * state->bandwidth);
    double t = t_cubic < t_reno ? t_cubic : t_reno;
    return t > 0 ? t : 0;
}

/**
 * Calculates the number of bytes that have to be acked for incrementing CWND by one MTU, when Cuback is used.
 *
 * Cuback is an ACK-driven variant of Cubic. It traces the same two curves as Cubic - W_cubic and the Reno-friendly W_reno - but
 * drives them by the bytes being acked rather than by the clock.
 *
 * Both curves being monotonically increasing, CWND - being their maximum - is monotonically increasing as well, hence the position
 * on the time axis can be recovered from CWND, the inverse of a maximum being the minimum of the inverses:
 *
 *   W_cubic(t)    = C * MSS * (t / adjust - K)^3 + W_max
 *   W_reno(t)     = sqrt(anchor^2 + 2 * alpha * MSS * bandwidth * t), switching alpha to 1 at W_max
 *   W^-1_cubic(w) = adjust * (K + cbrt((w - W_max) / (C * MSS)))
 *   W^-1_reno(w)  = (w^2 - anchor^2) / (2 * alpha * MSS * bandwidth),                  w <= W_max
 *                   (W_max^2 - anchor^2) / (2 * alpha * MSS * bandwidth)
 *                     + (w^2 - W_max^2) / (2 * MSS * bandwidth),                      w > W_max
 *
 * That leaves W_max and the delivery rate observed at the last congestion event as the only state to retain. The amount to be acked
 * for incrementing CWND by one MTU is the time the curve takes to climb that far, converted by the latter:
 *
 *   bytes_per_mtu_increase = (W^-1(cwnd + MTU) - W^-1(cwnd)) * bandwidth
 *
 * Being expressed in bytes to be acked, it does not advance while the sender is limited by anything other than CWND; this is the
 * property that Cubic obtains by excluding application-limited periods from its clock.
 *
 * Also, use of ACK-clock mitigates the need for fast convergence, because if a competing flow grows faster, the clock naturally
 * slows down, yielding more bandwidth to the competition.
 */
static uint32_t cuback_bytes_per_mtu_increase(const struct st_quicly_cc_cuback_t *state, uint32_t cwnd, uint32_t mtu)
{
    double anchor = (double)state->w_max * QUICLY_RENO_BETA; /* CWND after reduction; where both curves depart from */
    /* Seconds taken by the cubic curve to climb from `anchor` back to W_max; the fast convergence adjustment stretches the time
     * axis rather than K, so that the curve still departs from `anchor` at t == 0. */
    double k = cbrt((double)state->w_max * ((1 - QUICLY_RENO_BETA) / QUICLY_CUBIC_C) / mtu);

    double t0 = cuback_time_at(state, cwnd, anchor, k, mtu);
    double t1 = cuback_time_at(state, (double)cwnd + mtu, anchor, k, mtu);
    double bytes = (t1 - t0) * state->bandwidth;

    /* Past W_max the curve grows without bound, therefore the increase is capped at 50% of CWND per RTT as RFC 9438 does. Below
     * W_max the cap is not applied, it being the climb back to a window that the path had already sustained. */
    if (cwnd > state->w_max && bytes < (double)mtu * 2)
        bytes = (double)mtu * 2;

    /* Return the value capping the bounds so to avoid infinite loop or overflow. */
    if (bytes < 1)
        return 1;
    if (bytes > 0x7fffffff)
        return 0x7fffffff;
    return (uint32_t)bytes;
}

/**
 * Updates the estimate of the BDP that the congestion controller holds. Called when rapid start adjusts CWND (its estimate) during
 * recovery, which needs to be reflected to that of cuback.
 */
static void update_bdp_estimate(quicly_cc_t *cc)
{
    if (cc->type == &quicly_cc_type_cuback)
        cc->state.pico.cuback.w_max = cc->cwnd / QUICLY_RENO_BETA;
}

/* TODO: Avoid increase if sender was application limited. */
static void pico_on_acked(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                          int cc_limited, uint64_t next_pn, int64_t now, uint32_t max_udp_payload_size)
{
    assert(inflight >= bytes);

    /* In recovery period: CWND remains the same (but either jumpstart or rapid start may handle it differently). */
    if (largest_acked < cc->recovery_end) {
        if (quicly_cc_rapid_start_is_enabled(&cc->rapid_start)) {
            if (cc->num_loss_episodes == 1) {
                quicly_cc_rapid_start_on_recovery(&cc->rapid_start, &cc->cwnd, bytes, 0);
                update_bdp_estimate(cc);
            }
        } else {
            quicly_cc_jumpstart_on_acked(cc, 1, bytes, largest_acked, inflight, next_pn);
        }
        return;
    }

    quicly_cc_jumpstart_on_acked(cc, 0, bytes, largest_acked, inflight, next_pn);

    if (!cc_limited)
        return;

    cc->state.pico.stash += bytes;

    /* Calculate the amount of bytes required to be acked for incrementing CWND by one MTU. */
    uint32_t bytes_per_mtu_increase;
    if (cc->cwnd < cc->ssthresh) {
        if (cc->num_loss_episodes == 0)
            quicly_cc_rapid_start_update_rtt(&cc->rapid_start, &loss->rtt, now);
        bytes_per_mtu_increase =
            quicly_cc_rapid_start_use_3x(&cc->rapid_start, &loss->rtt) ? max_udp_payload_size / 2 : max_udp_payload_size;
    } else if (cc->type == &quicly_cc_type_cuback) {
        /* Cuback: bytes_per_mtu_increase is a function of CWND; adjust stash and cwnd while recalculating the value for every time
         * CWND += mtu. */
        if (cc->state.pico.cuback.bandwidth > 0) {
            while (1) {
                uint32_t step = cuback_bytes_per_mtu_increase(&cc->state.pico.cuback, cc->cwnd, max_udp_payload_size);
                if (cc->state.pico.stash < step)
                    break;
                cc->state.pico.stash -= step;
                cc->cwnd = quicly_u32_add_saturating(cc->cwnd, max_udp_payload_size);
            }
            goto UpdateMaximum;
        } else {
            /* The curve remains undefined until the first congestion event; this is reachable only when the CC has been switched
             * while in congestion avoidance. Use Reno until then. */
            bytes_per_mtu_increase = cc->cwnd;
        }
    } else {
        bytes_per_mtu_increase = cc->state.pico.bytes_per_mtu_increase;
    }

    /* Bail out if we do not yet have enough bytes being acked. */
    if (cc->state.pico.stash < bytes_per_mtu_increase)
        return;

    { /* Update CWND, reducing stash relative to the amount we've adjusted the CWND */
        uint32_t count = cc->state.pico.stash / bytes_per_mtu_increase;
        cc->cwnd = quicly_u32_add_saturating(cc->cwnd, count * max_udp_payload_size);
        cc->state.pico.stash -= count * bytes_per_mtu_increase;
    }

UpdateMaximum:
    if (cc->cwnd_maximum < cc->cwnd)
        cc->cwnd_maximum = cc->cwnd;
}

static void pico_on_lost(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t lost_pn, uint64_t next_pn,
                         int64_t now, uint32_t max_udp_payload_size)
{
    quicly_cc__update_ecn_episodes(cc, bytes, lost_pn);

    /* Nothing to do if loss is in recovery window (modulo when exiting rapid start, in which case CWND is further reduced relative
     * to the number of bytes lost. */
    if (lost_pn < cc->recovery_end) {
        if (bytes != 0 && cc->state.pico.undo.num_packets_lost != 0)
            ++cc->state.pico.undo.num_packets_lost;
        if (cc->num_loss_episodes == 1 && quicly_cc_rapid_start_is_enabled(&cc->rapid_start)) {
            quicly_cc_rapid_start_on_recovery(&cc->rapid_start, &cc->cwnd, 0, bytes);
            update_bdp_estimate(cc);
            goto ClampMinAndUpdateMetrics;
        }
        return;
    }

    /* Zero-byte congestion reports are ECN signals, not lost packets. They still enter recovery below, but cannot be undone by
     * late ACKs because no packet was deemed lost. */
    if (bytes != 0) {
        cc->state.pico.undo.num_packets_lost = 1;
        cc->state.pico.undo.start_pn = lost_pn;
        cc->state.pico.undo.cwnd = cc->cwnd;
        if (quicly_cc_in_jumpstart(cc)) {
            cc->state.pico.undo.cwnd /= 2;
            if (cc->state.pico.undo.cwnd < cc->cwnd_initial)
                cc->state.pico.undo.cwnd = cc->cwnd_initial;
        }
        cc->state.pico.undo.ssthresh = cc->ssthresh;
        cc->state.pico.undo.bytes_per_mtu_increase = cc->state.pico.bytes_per_mtu_increase;
        cc->state.pico.undo.cuback = cc->state.pico.cuback;
    } else {
        cc->state.pico.undo.num_packets_lost = 0;
    }

    cc->recovery_end = next_pn;
    ++cc->num_loss_episodes;

    /* end of slow start */
    if (cc->cwnd_exiting_slow_start == 0) {
        assert(cc->ssthresh == UINT32_MAX);
        /* jumpstart: if detected loss during the validating phase, advance to validating phase */
        quicly_cc_jumpstart_on_first_loss(cc, lost_pn, quicly_cc_rapid_start_is_enabled(&cc->rapid_start));
        /* save values */
        cc->cwnd_exiting_slow_start = cc->cwnd;
        cc->exit_slow_start_at = now;
    }

    { /* calculate increase rate based on current estimate of BDP (usually from CWND before reduction) */
        uint32_t bdp = cc->cwnd;
        if (cc->num_loss_episodes == 1) {
            if (quicly_cc_is_jumpstart_ack(cc, lost_pn)) {
                bdp = cc->jumpstart.bytes_acked;
            } else if (quicly_cc_rapid_start_is_enabled(&cc->rapid_start)) {
                /* Rapid Start might have already switched to 2x, but it's unclear if the entire RT was in 2x. Therefore, use a
                 * conservative estimate of BDP. It could make the next CA epoch slightly aggressive, but nowhere near as aggressive
                 * as startup, so we're fine. */
                bdp = cc->cwnd / 3;
            } else {
                bdp = cc->cwnd / 2;
            }
            if (bdp < QUICLY_MIN_CWND * max_udp_payload_size)
                bdp = QUICLY_MIN_CWND * max_udp_payload_size;
        }
        if (cc->type == &quicly_cc_type_cuback) {
            /* Retain the two values that define the curves: the target window and the throughput. */
            cc->state.pico.cuback.w_max = bdp;
            cc->state.pico.cuback.bandwidth = loss->rtt.smoothed != 0 ? bdp * 1000. / loss->rtt.smoothed : 0;
            cc->state.pico.stash = 0;
        } else {
            cc->state.pico.bytes_per_mtu_increase = pico_bytes_per_mtu_increase(bdp, loss->rtt.smoothed, max_udp_payload_size);
        }
    }

    /* Reduce congestion window. At the end of Slow Start, 0.5x is used, because the 1 RTT delay in ACK causes the sender to
     * overshoot by 2x (note: after 0.5x reduction, CWND is still as large as BDP+QUEUE, so further reduction is preferable).
     *
     * In rapid start, upon the first loss we multiply CWND by QUICLY_RAPID_START_LOSS_FACTOR (0.9x when beta is 0.7), then reduce
     * proportionally to the bytes acked and deemed lost during recovery, with a lower bound of 1/3 * beta.
     * Rationale: at a small loss, reducing by beta mirrors CA's single signal behavior. With up to ~67% loss (typical for 3x
     * growth under tail-drop), CWND upon loss detection is 3 * (BDP + Q); therefore clamping to 1/3 * beta reproduces the CA
     * target. For loss >67% (i.e., beyond queue overflow), we keep the lower bound to avoid over-shrinking. */
    if (cc->ssthresh == UINT32_MAX) {
        if (quicly_cc_rapid_start_is_enabled(&cc->rapid_start)) {
            uint32_t base = cc->cwnd_initial;
            if (base < cc->jumpstart.bytes_acked)
                base = cc->jumpstart.bytes_acked;
            quicly_cc_rapid_start_on_first_lost(&cc->rapid_start, &cc->cwnd, base * 0.5);
            update_bdp_estimate(cc);
        } else {
            cc->cwnd *= 0.5;
        }
    } else {
        cc->cwnd *= QUICLY_RENO_BETA;
    }

ClampMinAndUpdateMetrics:
    /* After CWND has been reduced, adjust if it is below permitted minimum and update metrics. */
    if (cc->cwnd < QUICLY_MIN_CWND * max_udp_payload_size)
        cc->cwnd = QUICLY_MIN_CWND * max_udp_payload_size;
    cc->ssthresh = cc->cwnd;

    if (cc->cwnd_minimum > cc->cwnd)
        cc->cwnd_minimum = cc->cwnd;
}

static void pico_on_late_ack(quicly_cc_t *cc, uint64_t pn, int64_t now)
{
    if (!(cc->state.pico.undo.start_pn <= pn && pn < cc->recovery_end))
        return;
    if (cc->state.pico.undo.num_packets_lost == 0)
        return;

    if (--cc->state.pico.undo.num_packets_lost != 0)
        return;

    int was_in_startup = cc->state.pico.undo.ssthresh == UINT32_MAX;
    cc->cwnd = cc->state.pico.undo.cwnd;
    cc->ssthresh = cc->state.pico.undo.ssthresh;
    cc->state.pico.stash = 0;
    cc->state.pico.bytes_per_mtu_increase = cc->state.pico.undo.bytes_per_mtu_increase;
    cc->state.pico.cuback = cc->state.pico.undo.cuback;
    cc->recovery_end = 0;
    --cc->num_loss_episodes;
    ++cc->num_loss_episodes_undone;
    if (was_in_startup) {
        ++cc->num_loss_episodes_undone_in_startup;
        cc->cwnd_exiting_slow_start = 0;
        cc->exit_slow_start_at = INT64_MAX;
        quicly_cc_jumpstart_reset(cc);
        cc->rapid_start.newest_rtt_sample_until = 0;
    }
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

    /* both pico and cuback acts as reno until congestion is observed, including when switching from a different CC */
    cc->state.pico.bytes_per_mtu_increase = cc->cwnd * QUICLY_RENO_BETA;
    cc->state.pico.cuback = (struct st_quicly_cc_cuback_t){0};
}

static void pico_reset(quicly_cc_t *cc, quicly_cc_type_t *type, uint32_t initcwnd)
{
    *cc = (quicly_cc_t){
        .type = type,
        .cwnd = initcwnd,
        .cwnd_initial = initcwnd,
        .cwnd_maximum = initcwnd,
        .cwnd_minimum = UINT32_MAX,
        .exit_slow_start_at = INT64_MAX,
        .ssthresh = UINT32_MAX,
    };
    pico_init_pico_state(cc, 0);

    quicly_cc_jumpstart_reset(cc);
}

/**
 * Switches to `type`, which is either Pico or Cuback; the two share their state representation.
 */
static int switch_to(quicly_cc_t *cc, quicly_cc_type_t *type)
{
    if (cc->type == type) {
        return 1; /* nothing to do */
    } else if (cc->type == &quicly_cc_type_reno) {
        cc->type = type;
        pico_init_pico_state(cc, cc->state.reno.stash);
        return 1;
    } else if (cc->type == &quicly_cc_type_cubic || cc->type == &quicly_cc_type_pico || cc->type == &quicly_cc_type_cuback) {
        /* When in slow start, state can be reused as-is; otherwise, restart. */
        if (cc->cwnd_exiting_slow_start == 0) {
            cc->type = type;
            pico_init_pico_state(cc, 0);
        } else {
            pico_reset(cc, type, cc->cwnd_initial);
        }
        return 1;
    }

    return 0;
}

static int pico_on_switch(quicly_cc_t *cc)
{
    return switch_to(cc, &quicly_cc_type_pico);
}

static int cuback_on_switch(quicly_cc_t *cc)
{
    return switch_to(cc, &quicly_cc_type_cuback);
}

static void pico_enable_rapid_start(quicly_cc_t *cc, int64_t now)
{
    quicly_cc_init_rapid_start(&cc->rapid_start, now);
}

static void pico_init(quicly_init_cc_t *self, quicly_cc_t *cc, uint32_t initcwnd, int64_t now)
{
    pico_reset(cc, &quicly_cc_type_pico, initcwnd);
}

static void cuback_init(quicly_init_cc_t *self, quicly_cc_t *cc, uint32_t initcwnd, int64_t now)
{
    pico_reset(cc, &quicly_cc_type_cuback, initcwnd);
}

quicly_cc_type_t quicly_cc_type_pico = {"pico",
                                        &quicly_cc_pico_init,
                                        pico_on_acked,
                                        pico_on_lost,
                                        pico_on_persistent_congestion,
                                        pico_on_sent,
                                        pico_on_switch,
                                        pico_on_late_ack,
                                        quicly_cc_jumpstart_enter,
                                        pico_enable_rapid_start};
quicly_init_cc_t quicly_cc_pico_init = {pico_init};

quicly_cc_type_t quicly_cc_type_cuback = {"cuback",
                                          &quicly_cc_cuback_init,
                                          pico_on_acked,
                                          pico_on_lost,
                                          pico_on_persistent_congestion,
                                          pico_on_sent,
                                          cuback_on_switch,
                                          pico_on_late_ack,
                                          quicly_cc_jumpstart_enter,
                                          pico_enable_rapid_start};
quicly_init_cc_t quicly_cc_cuback_init = {cuback_init};
