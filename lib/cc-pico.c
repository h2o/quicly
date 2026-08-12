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
 * Returns the number of bytes sent when the Cuback CWND reaches `w`.
 *
 * Cuback is an ACK-driven variant of Cubic. It traces the same two curves as Cubic - W_cubic and the Reno-friendly W_reno - but
 * drives them by the bytes being acked rather than by the clock.
 *
 * Both curves being monotonically increasing, CWND - being their maximum - is monotonically increasing as well, hence the amount
 * sent can be recovered from CWND, the inverse of a maximum being the minimum of the inverses:
 *
 *   bytes_sent(w)  = min(bytes_cubic(w), bytes_reno(w))
 *   bytes_cubic(w) = (K + cbrt((w - Wmax) / (C * MSS))) * bandwidth
 *   bytes_reno(w)  = (w^2 - Wepoch^2) / (2 * alpha * MSS),                           w <= Wmax
 *                    (Wmax^2 - Wepoch^2) / (2 * alpha * MSS)
 *                      + (w^2 - Wmax^2) / (2 * MSS),                                 w > Wmax
 *
 * Wepoch is equal to ssthresh, therefore Wmax and the delivery rate observed at the last congestion event are the only Cuback-
 * specific states that need to be retained. The congestion-avoidance trajectory is expressed entirely as pure functions of
 * immutable per-epoch parameters and CWND.
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
 */
static double cuback_cwnd_to_bytes_sent(const struct st_quicly_cc_cuback_t *state, double w, double w_epoch, double k, uint32_t mtu)
{
    static const double friendly_alpha = 3 * (1 - QUICLY_RENO_BETA) / (1 + QUICLY_RENO_BETA);

    double bytes_cubic = (k + cbrt((w - state->w_max) / (QUICLY_CUBIC_C * mtu))) * state->bandwidth;
    /* RFC 9438, Section 4.3 switches alpha to one after the Reno-friendly estimate reaches the congestion window prior to
     * reduction (W_max here). The inverse curve is therefore piecewise at W_max. Bandwidth cancels when converting the Reno time
     * to bytes sent. */
    double w_friendly = w < state->w_max ? w : state->w_max;
    double bytes_reno = (w_friendly * w_friendly - w_epoch * w_epoch) / (2 * friendly_alpha * mtu);
    if (w > state->w_max)
        bytes_reno += (w * w - (double)state->w_max * state->w_max) / (2 * mtu);
    double bytes = bytes_cubic < bytes_reno ? bytes_cubic : bytes_reno;
    return bytes > 0 ? bytes : 0;
}

/**
 * Calculates the number of bytes that have to be acked for incrementing CWND by one MTU, when Cuback is used.
 */
static uint32_t cuback_bytes_per_mtu_increase(const struct st_quicly_cc_cuback_t *state, uint32_t cwnd, uint32_t cwnd_epoch,
                                              uint32_t mtu)
{
    /* Seconds taken by the cubic curve to climb from `cwnd_epoch` back to W_max. Derived from the gap between the two rather than
     * from W_max alone, as fast convergence and the varying reduction ratios move them apart. */
    double k = cbrt(((double)state->w_max - cwnd_epoch) / (QUICLY_CUBIC_C * mtu));

    double bytes0 = cuback_cwnd_to_bytes_sent(state, cwnd, cwnd_epoch, k, mtu);
    double bytes1 = cuback_cwnd_to_bytes_sent(state, (double)cwnd + mtu, cwnd_epoch, k, mtu);
    double bytes = bytes1 - bytes0;

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
 * Calculates the size of the next ACK interval from the current congestion-control state.
 */
static uint32_t calc_bytes_per_mtu_increase(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t max_udp_payload_size)
{
    if (cc->cwnd < cc->ssthresh) {
        return quicly_cc_rapid_start_use_3x(&cc->rapid_start, &loss->rtt) ? max_udp_payload_size / 2 : max_udp_payload_size;
    } else if (cc->type == &quicly_cc_type_cuback) {
        if (cc->state.pico.cuback.bandwidth > 0)
            return cuback_bytes_per_mtu_increase(&cc->state.pico.cuback, cc->cwnd, cc->ssthresh, max_udp_payload_size);
        /* The curve remains undefined until the first congestion event; this is reachable only when the CC has been switched while
         * in congestion avoidance. Use Reno until then. */
        return cc->cwnd;
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

    /* When W_max was deferred for Rapid Start, derive it from the final recovery-adjusted CWND. */
    if (cc->type == &quicly_cc_type_cuback && cc->state.pico.cuback.bandwidth > 0 && cc->state.pico.cuback.w_max == 0)
        cc->state.pico.cuback.w_max = cc->cwnd / QUICLY_RENO_BETA;

    if (cc->cwnd < cc->ssthresh && cc->num_loss_episodes == 0)
        quicly_cc_rapid_start_update_rtt(&cc->rapid_start, &loss->rtt, now);

    if (cc->state.pico.bytes_to_mtu_increase == 0)
        cc->state.pico.bytes_to_mtu_increase = calc_bytes_per_mtu_increase(cc, loss, max_udp_payload_size);

    /* Apply this ACK to the current interval. One ACK can span multiple intervals. */
    uint32_t bytes_available = bytes;
    while (bytes_available >= cc->state.pico.bytes_to_mtu_increase) {
        bytes_available -= cc->state.pico.bytes_to_mtu_increase;
        cc->cwnd = quicly_u32_add_saturating(cc->cwnd, max_udp_payload_size);
        cc->state.pico.bytes_to_mtu_increase = calc_bytes_per_mtu_increase(cc, loss, max_udp_payload_size);
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
        if (cc->type == &quicly_cc_type_cuback)
            cc->state.pico.undo.cuback = cc->state.pico.cuback;
        else
            cc->state.pico.undo.bytes_per_mtu_increase = cc->state.pico.bytes_per_mtu_increase;
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
                /* Exiting startup: adopt the calculated BDP or defer until the exiting recovery */
                cc->state.pico.cuback.w_max = quicly_cc_rapid_start_is_enabled(&cc->rapid_start) ? 0 : bdp;
            } else {
                /* Fast convergence (RFC 9438, Section 4.7): when the BDP estimate comes out below the retained W_max, the path is
                 * yielding to somebody. Compare against the retained value and decide the new w_max. */
                cc->state.pico.cuback.w_max = bdp < cc->state.pico.cuback.w_max ? bdp * ((1 + QUICLY_RENO_BETA) / 2) : bdp;
            }
            cc->state.pico.cuback.bandwidth = loss->rtt.smoothed != 0 ? bdp * 1000. / loss->rtt.smoothed : 0;
            cc->state.pico.bytes_to_mtu_increase = 0;
        } else {
            cc->state.pico.bytes_per_mtu_increase = pico_bytes_per_mtu_increase(bdp, loss->rtt.smoothed, max_udp_payload_size);
            cc->state.pico.bytes_to_mtu_increase = cc->state.pico.bytes_per_mtu_increase;
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
    if (cc->type == &quicly_cc_type_cuback)
        cc->state.pico.cuback = cc->state.pico.undo.cuback;
    else
        cc->state.pico.bytes_per_mtu_increase = cc->state.pico.undo.bytes_per_mtu_increase;
    cc->state.pico.bytes_to_mtu_increase = 0;
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
        cc->state.pico.bytes_per_mtu_increase = cc->cwnd * QUICLY_RENO_BETA;
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
