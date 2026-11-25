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

#ifndef quicly_rate_h
#define quicly_rate_h

#include <stdint.h>
#include "quicly/ranges.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * State used for estimating the delivery rate.
 * The estimator measures the bytes acknowledged over consecutive windows, each of which starts at an ACK and ends at the ACK for
 * the first packet sent after that ACK. Each window therefore spans at least one round trip, and acknowledges the packets sent
 * during the previous window as well as the first packet sent during itself. A window is application-limited if the flow was
 * application-limited at any moment during that window or the previous one. The rate measured over each window is a sample, from
 * which a smoothed rate and its variation are calculated in the same way as smoothed_rtt and rttvar of RFC 9002. As an
 * application-limited sample only shows that the path can deliver at least that much, it is used only when there is no estimate yet
 * or when it is higher than the latest sample.
 */
typedef struct st_quicly_ratemeter_t {
    /**
     * Estimate, in bytes / second. `smoothed` is NAN until the first sample is obtained.
     */
    struct {
        double latest;
        double smoothed;
        double variation;
    } estimate;
    /**
     * The window being measured.
     */
    struct st_quicly_ratemeter_window_t {
        /**
         * The window ends at an ACK for this packet number or above. UINT64_MAX until the first ACK is received.
         */
        uint64_t end_pn;
        /**
         * Time and the cumulative number of bytes acknowledged at the start of the window.
         */
        double at;
        uint64_t bytes_acked;
        /**
         * If the flow has been application-limited at any moment on each side of the window: `send_side` is the previous window,
         * during which the packets acknowledged by this window were sent, and `receive_side` is this window, during which they are
         * acknowledged. The window is application-limited if either is set.
         */
        struct {
            unsigned send_side : 1;
            unsigned receive_side : 1;
        } app_limited;
    } window;
} quicly_ratemeter_t;

/**
 * Estimated delivery rate, in bytes / second. All values are zero until the first sample is obtained.
 *
 * `latest` is comparable to what Linux reports as `tcpi_delivery_rate`: both are the rate of the most recent sample, measured from
 * the ACK received before a packet was sent until that packet is acknowledged, and an application-limited sample replaces it only
 * when higher. Linux additionally bounds each sample by the time over which the packets were sent, takes a sample at every ACK, and
 * excludes the time when no packet was in flight.
 */
typedef struct st_quicly_rate_t {
    uint64_t latest;
    uint64_t smoothed;
    uint64_t variation;
} quicly_rate_t;

/**
 *
 */
void quicly_ratemeter_init(quicly_ratemeter_t *meter);
/**
 * Notifies the estimator that the flow is application-limited at the moment.
 */
static void quicly_ratemeter_on_app_limited(quicly_ratemeter_t *meter);
/**
 * Updates the estimation upon receiving an ACK.
 */
void quicly_ratemeter_on_ack(quicly_ratemeter_t *meter, double now, uint64_t bytes_acked, uint64_t largest_pn_acked,
                             uint64_t next_pn);
/**
 * Returns the delivery rate estimate
 */
void quicly_ratemeter_report(quicly_ratemeter_t *meter, quicly_rate_t *rate);

/* inline definitions */

inline void quicly_ratemeter_on_app_limited(quicly_ratemeter_t *meter)
{
    meter->window.app_limited.receive_side = 1;
}

#ifdef __cplusplus
}
#endif

#endif
