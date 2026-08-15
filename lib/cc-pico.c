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

/**
 * Calculates the increase ratio to be used in congestion avoidance phase.
 */
static uint32_t pico_bytes_per_mtu_increase(uint32_t cwnd, double rtt, uint32_t mtu, double beta)
{
    /* Reno: CWND size after reduction */
    uint32_t reno = cwnd * beta;

    /* Cubic: Cubic reaches original CWND (i.e., Wmax) in K seconds, therefore:
     *   amount_to_increase = (1 - beta) * Wmax
     *   amount_to_be_acked = K * Wmax / RTT_at_Wmax
     * where
     *   K = ((1 - beta) / 0.4 * Wmax / MTU)^(1/3)
     *
     * Hence:
     *   bytes_per_mtu_increase = amount_to_be_acked / amount_to_increase * MTU
     *     = (K * Wmax / RTT_at_Wmax) / ((1 - beta) * Wmax) * MTU
     *     = K * MTU / ((1 - beta) * RTT_at_Wmax)
     *
     * In addition, we have to adjust the value to take fast convergence into account. When competition causes congestion peaks to
     * decline gradually, fast-convergence and normal epochs are expected to alternate: a peak below the retained Wmax triggers fast
     * convergence, while the resulting Wmax of (1 + beta) / 2 makes the next peak a normal event unless it declines further.
     *
     * When fast convergence occurs, Wmax becomes (1 + beta) / 2 * Wmax while cwnd_epoch remains beta * Wmax. The modified K (K')
     * is therefore:
     *
     *   K' = (((1 - beta) / 2) / 0.4 * Wmax / MTU)^(1/3) = 0.5^(1/3) * K
     *
     * where K' represents the time to reach (1 + beta) / 2 * Wmax. As the cubic curve is point symmetric around that point,
     * reaching the original Wmax takes 2 * K'. Amortizing one fast-convergence period and one normal period gives:
     *
     *   bytes_per_mtu_increase = ((1 + 0.5^(1/3) * 2) / 2) * K * MTU / ((1 - beta) * RTT_at_Wmax)
     *                          ~= 1.293700525984 * K * MTU / ((1 - beta) * RTT_at_Wmax)
     */
    double cubic = 1.293700525984 / (1 - beta) * 1000 * cbrt((1 - beta) / 0.4 * cwnd / mtu) / rtt * mtu;

    double bytes = reno < cubic ? reno : cubic;
    return bytes < 1 ? 1 : bytes > UINT32_MAX ? UINT32_MAX : (uint32_t)bytes;
}

/**
 * Returns the number of bytes sent when the Cuback CWND reaches `w`.
 *
 * Cuback is an ACK-driven variant of Cubic. It traces the same two curves as Cubic - W_cubic and the Reno-friendly W_reno shown
 * below - but drives them by the bytes being acked rather than by the clock.
 *
 * Let Tr be the time at which the Reno-friendly curve reaches cwnd_prior:
 *
 *   Tr = (cwnd_prior^2 - Wepoch^2) / (2 * alpha * MSS * bandwidth)
 *
 * The two time-domain curves are:
 *
 *   W_cubic(t) = C * MSS * (t - K)^3 + Wmax
 *   W_reno(t)  = sqrt(Wepoch^2 + 2 * alpha * MSS * bandwidth * t),                   t <= Tr
 *                sqrt(cwnd_prior^2 + 2 * MSS * bandwidth * (t - Tr)),                t > Tr
 *
 * As both curves are monotonically increasing, CWND - being their maximum - is monotonically increasing as well. Therefore, the
 * amount sent can be recovered from CWND, the inverse of a maximum being the minimum of the inverses. Inverting the curves gives
 * the time at which each reaches `w`. Multiplying that time by bandwidth converts the result to bytes sent since the epoch began:
 *
 *   bytes_cubic(w) = bandwidth * (K + cbrt((w - Wmax) / (C * MSS)))
 *   bytes_reno(w)  = (w^2 - Wepoch^2) / (2 * alpha * MSS),                           w <= cwnd_prior
 *                    (cwnd_prior^2 - Wepoch^2) / (2 * alpha * MSS)
 *                      + (w^2 - cwnd_prior^2) / (2 * MSS),                           w > cwnd_prior
 *   bytes_sent(w)  = min(bytes_cubic(w), bytes_reno(w))
 *
 * Wepoch is equal to ssthresh, therefore the only Cuback-specific states that need to be retained are:
 *
 * * Wmax
 * * bandwidth observed at the last congestion event
 * * (cwnd_prior as a value separate from Wmax, if fast convergence is needed)
 * * (alpha, if ABE is supported and uses a different alpha when reacting to ECN-CE)
 *
 * These values remain immutable during each epoch. The congestion-avoidance trajectory is expressed entirely as pure functions
 * using them, taking CWND as the only parameter.
 *
 * Using the `bytes_sent` function, the congestion controller calculates bytes needed to be acked before incrementing the CWND
 * (`bytes_sent(cwnd + mtu) - bytes_sent(cwnd)`) and drives congestion avoidance, the same way as in the case of Reno.
 *
 * In addition to being simple, the approach has two positive side-effects:
 *
 * * As CWND is driven by acks rather than by time, CWND does not advance while nothing is inflight. Congestion control becomes
 *   safer without accurate app-limited tracking.
 * * Because the clock is the ack stream, a flow whose share is being taken advances more slowly than one that is taking, thereby
 *   yielding bandwidth. Fast convergence could be still helpful.
 *
 * __Note on the reno-friendly region__
 *
 * Neither Cubic nor Cuback tracks Reno exactly; they are both more aggressive than Reno.
 *
 * Cubic accumulates W_est += alpha * segments_acked / cwnd. Those bytes are delivered along the cubic curve, which sits above the
 * reno curve early in the epoch, so W_est is credited with volume that a Reno flow would not yet have sent, and therefore reaches
 * cwnd_prior sooner than it ought to.
 *
 * Cuback evaluates the reno curve as a pure function of the bytes sent since the epoch began and so carries no such drift, but it
 * has the opposite bias. The one RT of credit granted when the epoch begins - which exists because Cubic aims at W_cubic(t + RTT)
 * - advances the byte counter and therefore both curves, whereas Cubic applies that lookahead to W_cubic alone. Cancelling it for
 * this branch alone would mean departing from `cwnd_epoch - alpha * MSS`.
 *
 * Both also share a bias that no such adjustment removes: immediately after the reduction the cubic curve is often the cheaper of
 * the two, so the concave climb owns the first part of every epoch. As more packets would be inflight than with Reno, the ack clock
 * runs faster, and this becomes a compound effect.
 *
 * The two biases unique to each are of comparable magnitude, and empirically Cuback and Cubic land within about a point of each
 * other when measured against a common competitor. Therefore, the biases are left uncorrected, since the design goal of Cuback is
 * to create a controller in parity with Cubic.
 */
static double cuback_cwnd_to_bytes_sent(double w, double w_epoch, double w_max, double cwnd_prior, double bandwidth, double k,
                                        uint32_t mtu, double friendly_alpha)
{
    double bytes_cubic = (k + cbrt((w - w_max) / (QUICLY_CUBIC_C * mtu))) * bandwidth;
    /* RFC 9438, Section 4.3 switches alpha to one after the Reno-friendly estimate reaches the congestion window prior to
     * reduction. Bandwidth cancels when converting the Reno time to bytes sent. */
    double w_friendly = w < cwnd_prior ? w : cwnd_prior;
    double bytes_reno = (w_friendly * w_friendly - w_epoch * w_epoch) / (2 * friendly_alpha * mtu);
    if (w > cwnd_prior)
        bytes_reno += (w * w - cwnd_prior * cwnd_prior) / (2 * mtu);
    double bytes = bytes_cubic < bytes_reno ? bytes_cubic : bytes_reno;
    return bytes > 0 ? bytes : 0;
}

/**
 * Calculates the number of bytes that have to be acked for incrementing CWND by one MTU, when Cuback is used.
 */
static uint32_t cuback_bytes_per_mtu_increase(const struct st_quicly_cc_cuback_t *state, uint32_t cwnd, uint32_t cwnd_epoch,
                                              uint32_t mtu)
{
#define CALC_FRIENDLY_ALPHA(Breno, Bcubic) (((1 + Breno) * (1 - Bcubic)) / ((1 - Breno) * (1 + Bcubic)))
    static const double friendly_alpha[2] = {CALC_FRIENDLY_ALPHA(0.5, QUICLY_BETA_LOSS), CALC_FRIENDLY_ALPHA(0.8, QUICLY_BETA_ECN)};
#undef CALC_FRIENDLY_ALPHA

    /* Fast convergence: derive Wmax as the midpoint of cwnd_prior and cwnd_epoch rather than hard-coding it to 0.85 * cwnd_prior.
     * Otherwise, with ABE using QUICLY_BETA_ECN (0.85), Wmax equals cwnd_epoch and K becomes zero, causing the CC to skip the
     * concave region and start at the plateau. */
    double w_max =
        state->trend == QUICLY_CUBIC_TREND_FAST_CONVERGENCE ? ((double)state->cwnd_prior + cwnd_epoch) / 2 : state->cwnd_prior;
    /* Seconds taken by the cubic curve to climb from `cwnd_epoch` back to W_max. Derived from the gap between the two rather than
     * from W_max alone, as fast convergence and the varying reduction ratios move them apart. */
    double k = cbrt((w_max - cwnd_epoch) / (QUICLY_CUBIC_C * mtu));

    double bytes0 = cuback_cwnd_to_bytes_sent(cwnd, cwnd_epoch, w_max, state->cwnd_prior, state->bandwidth, k, mtu,
                                              friendly_alpha[state->by_ecn]);
    double bytes1 = cuback_cwnd_to_bytes_sent((double)cwnd + mtu, cwnd_epoch, w_max, state->cwnd_prior, state->bandwidth, k, mtu,
                                              friendly_alpha[state->by_ecn]);
    double bytes = bytes1 - bytes0;

    /* Past W_max the curve grows without bound, therefore the increase is capped at 50% of CWND per RTT as RFC 9438 does. Below
     * W_max the cap is not applied, it being the climb back to a window that the path had already sustained. */
    if (cwnd > w_max && bytes < (double)mtu * 2)
        bytes = (double)mtu * 2;

    return bytes < 1 ? 1 : bytes > UINT32_MAX ? UINT32_MAX : (uint32_t)bytes;
}

static void cuback_update_trend(struct st_quicly_cc_cuback_t *state, uint32_t peak, uint32_t cwnd_epoch)
{
    static const uint8_t transitions[][3] = {{QUICLY_CUBIC_TREND_FAST_CONVERGENCE, 0, 1},
                                             {QUICLY_CUBIC_TREND_FAST_CONVERGENCE, 0, 2},
                                             {0, 0, 2},
                                             {QUICLY_CUBIC_TREND_FAST_CONVERGENCE, 0, 1}};
    const double previous_w_max =
        state->trend == QUICLY_CUBIC_TREND_FAST_CONVERGENCE ? ((double)state->cwnd_prior + cwnd_epoch) / 2 : state->cwnd_prior;
    const int trend_index = peak < previous_w_max ? 0 : peak <= 1.01 * state->cwnd_prior ? 1 : 2;

    /* A flow that gained share while its peer was reduced can retain an elevated bandwidth estimate. As the peer recovers, that
     * estimate slows the flow's ACK-driven clock and CWND increase, thereby raising the chance of Cuback observing a loss before
     * it reaches Wmax. To avoid entering fast convergence under such circumstances, suppress one apparent fast convergence after
     * two rising epochs. */
    state->trend = transitions[state->trend][trend_index];
}

/**
 * Calculates the size of the next ACK interval from the current congestion-control state.
 */
static uint32_t calc_bytes_per_mtu_increase(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t max_udp_payload_size,
                                            uint32_t *bytes_available)
{
    if (cc->cwnd < cc->ssthresh) {
        return quicly_cc_rapid_start_use_3x(&cc->rapid_start, &loss->rtt) ? max_udp_payload_size / 2 : max_udp_payload_size;
    } else if (cc->type == &quicly_cc_type_cuback) {
        if (cc->state.pico.cuback.bandwidth == 0) {
            /* The curve remains undefined until the first congestion event; this is reachable only when the CC has been switched
             * while in congestion avoidance. Use Reno until then. */
            return cc->cwnd;
        }
        /* When exiting recovery, Cubic's CWND is W(t), so to be on par, run Cuback's clock for the same amount. */
        if (bytes_available != NULL)
            *bytes_available += cc->cwnd;
        return cuback_bytes_per_mtu_increase(&cc->state.pico.cuback, cc->cwnd, cc->ssthresh, max_udp_payload_size);
    } else {
        assert(cc->type == &quicly_cc_type_pico);
        return cc->state.pico.bytes_per_mtu_increase;
    }
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
                cc->ssthresh = cc->cwnd;
            }
        } else {
            quicly_cc_jumpstart_on_acked(cc, 1, bytes, largest_acked, inflight, next_pn);
        }
        return;
    }

    quicly_cc_jumpstart_on_acked(cc, 0, bytes, largest_acked, inflight, next_pn);

    if (!cc_limited)
        return;

    /* When Rapid Start is used, setting cwnd_prior is deferred, as the BDP estimate becomes available only after recovery ends. */
    if (cc->type == &quicly_cc_type_cuback && cc->state.pico.cuback.bandwidth > 0 && cc->state.pico.cuback.cwnd_prior == 0)
        cc->state.pico.cuback.cwnd_prior = cc->cwnd / (cc->rapid_start.recovery.by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS);

    if (cc->cwnd < cc->ssthresh && cc->num_loss_episodes == 0)
        quicly_cc_rapid_start_update_rtt(&cc->rapid_start, &loss->rtt, now);

    /* Apply this ACK to the current interval. One ACK can span multiple intervals. */
    uint32_t bytes_available = bytes;
    if (cc->state.pico.bytes_to_mtu_increase == 0)
        cc->state.pico.bytes_to_mtu_increase = calc_bytes_per_mtu_increase(cc, loss, max_udp_payload_size, &bytes_available);
    while (bytes_available >= cc->state.pico.bytes_to_mtu_increase) {
        bytes_available -= cc->state.pico.bytes_to_mtu_increase;
        cc->cwnd = quicly_u32_add_saturating(cc->cwnd, max_udp_payload_size);
        cc->state.pico.bytes_to_mtu_increase = calc_bytes_per_mtu_increase(cc, loss, max_udp_payload_size, NULL);
    }
    cc->state.pico.bytes_to_mtu_increase -= bytes_available;
    assert(cc->state.pico.bytes_to_mtu_increase != 0);

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
            goto ClampMinAndUpdateMetrics;
        }
        return;
    }

    double beta = bytes == 0 ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS;

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
        cc->state.pico.undo.bytes_to_mtu_increase = cc->state.pico.bytes_to_mtu_increase;
        if (cc->type == &quicly_cc_type_cuback) {
            cc->state.pico.undo.cuback = cc->state.pico.cuback;
        } else {
            cc->state.pico.undo.bytes_per_mtu_increase = cc->state.pico.bytes_per_mtu_increase;
        }
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
            if (cc->num_loss_episodes == 1) {
                /* Exiting startup: adopt the calculated BDP as the prior CWND or defer until the exiting recovery. */
                cc->state.pico.cuback.cwnd_prior = quicly_cc_rapid_start_is_enabled(&cc->rapid_start) ? 0 : bdp;
            } else {
                cuback_update_trend(&cc->state.pico.cuback, bdp, cc->ssthresh);
                cc->state.pico.cuback.cwnd_prior = bdp;
            }
            cc->state.pico.cuback.by_ecn = bytes == 0;
            cc->state.pico.cuback.bandwidth = loss->rtt.smoothed != 0 ? bdp * 1000. / loss->rtt.smoothed : 0;
            cc->state.pico.bytes_to_mtu_increase = 0;
        } else {
            cc->state.pico.bytes_per_mtu_increase =
                pico_bytes_per_mtu_increase(bdp, loss->rtt.smoothed, max_udp_payload_size, beta);
            cc->state.pico.bytes_to_mtu_increase = cc->state.pico.bytes_per_mtu_increase;
        }
    }

    /* Reduce congestion window. At the end of Slow Start, 0.5x is used, because the 1 RTT delay in ACK causes the sender to
     * overshoot by 2x (note: after 0.5x reduction, CWND is still as large as BDP+QUEUE, so further reduction is preferable). That
     * 2x overshoot builds up regardless of if congestion is signalled by a CE mark or by a packet loss, therefore `beta` is not
     * used here.
     *
     * In rapid start, upon the first congestion signal we multiply CWND by QUICLY_RAPID_START_LOSS_FACTOR (0.9x when beta is 0.7,
     * 0.95x when it is 0.85), then reduce proportionally to the bytes acked and deemed lost during recovery, with a lower bound of
     * 1/3 * beta.
     * Rationale: at a small loss, reducing by beta mirrors CA's single signal behavior. With up to ~67% loss (typical for 3x
     * growth under tail-drop), CWND upon loss detection is 3 * (BDP + Q); therefore clamping to 1/3 * beta reproduces the CA
     * target. For loss >67% (i.e., beyond queue overflow), we keep the lower bound to avoid over-shrinking. */
    if (cc->ssthresh == UINT32_MAX) {
        if (quicly_cc_rapid_start_is_enabled(&cc->rapid_start)) {
            uint32_t base = cc->cwnd_initial;
            if (base < cc->jumpstart.bytes_acked)
                base = cc->jumpstart.bytes_acked;
            quicly_cc_rapid_start_on_first_lost(&cc->rapid_start, &cc->cwnd, bytes == 0, base * 0.5);
        } else {
            cc->cwnd *= 0.5;
        }
    } else {
        cc->cwnd *= beta;
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
    cc->state.pico.bytes_to_mtu_increase = cc->state.pico.undo.bytes_to_mtu_increase;
    if (cc->type == &quicly_cc_type_cuback) {
        cc->state.pico.cuback = cc->state.pico.undo.cuback;
    } else {
        cc->state.pico.bytes_per_mtu_increase = cc->state.pico.undo.bytes_per_mtu_increase;
    }
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

static void pico_init_pico_state(quicly_cc_t *cc)
{
    /* both pico and cuback acts as reno until congestion is observed, including when switching from a different CC */
    cc->state.pico.bytes_to_mtu_increase = 0;
    if (cc->type == &quicly_cc_type_cuback)
        cc->state.pico.cuback = (struct st_quicly_cc_cuback_t){0};
    else
        cc->state.pico.bytes_per_mtu_increase = cc->cwnd * QUICLY_BETA_LOSS;
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
    pico_init_pico_state(cc);

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
        pico_init_pico_state(cc);
        return 1;
    } else if (cc->type == &quicly_cc_type_cubic || cc->type == &quicly_cc_type_pico || cc->type == &quicly_cc_type_cuback) {
        /* When in slow start, state can be reused as-is; otherwise, restart. */
        if (cc->cwnd_exiting_slow_start == 0) {
            cc->type = type;
            pico_init_pico_state(cc);
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
