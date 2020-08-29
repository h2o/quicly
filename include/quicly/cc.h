/*
 * Copyright (c) 2019 Fastly, Janardhan Iyengar
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

/* Interface definition for quicly's congestion controller.
 */

#ifndef quicly_cc_h
#define quicly_cc_h

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "quicly/constants.h"
#include "quicly/loss.h"

typedef enum {
    /**
     * Reno, with 0.7 beta reduction
     */
    CC_RENO_MODIFIED,
    /**
     * CUBIC (RFC 8312)
     */
    CC_CUBIC
} quicly_cc_type_t;

/**
 * Values to be reported by the congestion controller as part of the stats, if available.
 */
#define QUICLY_CC_COMMON_FIELDS                                                                                                    \
    /**                                                                                                                            \
     * Initial congestion window.                                                                                                  \
     */                                                                                                                            \
    uint32_t cwnd_initial;                                                                                                         \
    /**                                                                                                                            \
     * Congestion window at the end of slow start.                                                                                 \
     */                                                                                                                            \
    uint32_t cwnd_exiting_slow_start;                                                                                              \
    /**                                                                                                                            \
     * Minimum congestion window during the connection.                                                                            \
     */                                                                                                                            \
    uint32_t cwnd_minimum;                                                                                                         \
    /**                                                                                                                            \
     * Maximum congestion window during the connection.                                                                            \
     */                                                                                                                            \
    uint32_t cwnd_maximum;                                                                                                         \
    /**                                                                                                                            \
     * Total number of number of loss episodes (congestion window reductions).                                                     \
     */                                                                                                                            \
    uint32_t num_loss_episodes;                                                                                                    \
    /**                                                                                                                            \
     * Current slow start threshold.                                                                                               \
     */                                                                                                                            \
    uint32_t ssthresh

/**
 * The stats.
 */
typedef struct st_quicly_cc_stats_t {
    quicly_cc_type_t type;
    uint32_t cwnd;
    QUICLY_CC_COMMON_FIELDS;
} quicly_cc_stats_t;

#define QUICLY_CC_SET_STATS_SET_ONE(dst, src, field) ((dst)->field = (src)->field)
#define QUICLY_CC_SET_STATS(dst, cc, src)                                                                                          \
    do {                                                                                                                           \
        (dst)->type = (cc)->impl->type;                                                                                            \
        (dst)->cwnd = (cc)->cwnd;                                                                                                  \
        QUICLY_CC_SET_STATS_SET_ONE(dst, src, cwnd_initial);                                                                       \
        QUICLY_CC_SET_STATS_SET_ONE(dst, src, cwnd_exiting_slow_start);                                                            \
        QUICLY_CC_SET_STATS_SET_ONE(dst, src, cwnd_minimum);                                                                       \
        QUICLY_CC_SET_STATS_SET_ONE(dst, src, cwnd_maximum);                                                                       \
        QUICLY_CC_SET_STATS_SET_ONE(dst, src, num_loss_episodes);                                                                  \
        QUICLY_CC_SET_STATS_SET_ONE(dst, src, ssthresh);                                                                           \
    } while (0)

/**
 * Holds pointers to concrete congestion control implementation functions.
 */
struct st_quicly_cc_impl_t;

typedef struct st_quicly_cc_t {
    /**
     * Congestion controller implementation.
     */
    const struct st_quicly_cc_impl_t *impl;
    /**
     * Current congestion window.
     */
    uint32_t cwnd;
} quicly_cc_t;

struct st_quicly_cc_impl_t {
    /**
     * Congestion controller type.
     */
    quicly_cc_type_t type;
    /**
     *
     */
    void (*on_destroy)(quicly_cc_t *cc);
    /**
     * Called when a packet is newly acknowledged.
     */
    void (*on_acked)(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                     int64_t now, uint32_t max_udp_payload_size);
    /**
     * Called when a packet is detected as lost. |next_pn| is the next unsent packet number,
     * used for setting the recovery window.
     */
    void (*on_lost)(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t lost_pn, uint64_t next_pn, int64_t now,
                    uint32_t max_udp_payload_size);
    /**
     * Called when persistent congestion is observed.
     */
    void (*on_persistent_congestion)(quicly_cc_t *cc, const quicly_loss_t *loss, int64_t now);
    /**
     * Called after a packet is sent.
     */
    void (*on_sent)(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, int64_t now);
    /**
     * Callback used for obtaining the CC stats.
     */
    void (*get_stats)(quicly_cc_t *cc, quicly_cc_stats_t *stats);
};

/**
 * called to initialize a congestion controller for a new connection.
 * should in turn call one of the quicly_cc_*_init functions from cc.h with customized parameters.
 */
QUICLY_CALLBACK_TYPE(quicly_cc_t *, create_cc, uint32_t initcwnd, int64_t now);

/**
 * internal structure shared by Reno and Cubic CC
 */
struct st_quicly_cc_loss_based_t {
    /**
     *
     */
    quicly_cc_t super;
    /**
     *
     */
    QUICLY_CC_COMMON_FIELDS;
    /**
     * Packet number indicating end of recovery period, if in recovery.
     */
    uint64_t recovery_end;
    /**
     * State information specific to the congestion controller implementation.
     */
    union {
        /**
         * State information for Reno congestion control.
         */
        struct {
            /**
             * Stash of acknowledged bytes, used during congestion avoidance.
             */
            uint32_t stash;
        } reno;
        /**
         * State information for CUBIC congestion control.
         */
        struct {
            /**
             * Time offset from the latest congestion event until cwnd reaches W_max again.
             */
            double k;
            /**
             * Last cwnd value before the latest congestion event.
             */
            uint32_t w_max;
            /**
             * W_max value from the previous congestion event.
             */
            uint32_t w_last_max;
            /**
             * Timestamp of the latest congestion event.
             */
            int64_t avoidance_start;
            /**
             * Timestamp of the most recent send operation.
             */
            int64_t last_sent_time;
        } cubic;
    };
};

/**
 * The factory method for the modified Reno congestion controller.
 */
extern quicly_create_cc_t quicly_cc_reno_create;
/**
 * The factory method for the modified Reno congestion controller.
 */
extern quicly_create_cc_t quicly_cc_cubic_create;

/**
 * Calculates the initial congestion window size given the maximum UDP payload size.
 */
uint32_t quicly_cc_calc_initial_cwnd(uint16_t max_udp_payload_size);

#ifdef __cplusplus
}
#endif

#endif
