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
 * While the flow is CC-limited, the estimator measures the bytes acknowledged over consecutive windows, each of which starts at an
 * ACK and ends at the ACK for the first packet sent after that ACK. Each window therefore spans at least one round trip. The first
 * window after becoming CC-limited is discarded, as the packets acknowledged during that window might have been sent before the
 * flow became CC-limited. When the flow stops being CC-limited, the window being measured is discarded as well. The rate measured
 * over each window is a sample, from which a smoothed rate and its variation are calculated in the same way as smoothed_rtt and
 * rttvar of RFC 9002.
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
         * The window ends at an ACK for this packet number or above. UINT64_MAX while the flow is not CC-limited.
         */
        uint64_t end_pn;
        /**
         * Time and the cumulative number of bytes acknowledged at the start of the window. `at` is NAN during the first window
         * after becoming CC-limited, which is not used as a sample.
         */
        double at;
        uint64_t bytes_acked;
    } window;
} quicly_ratemeter_t;

/**
 * Estimated delivery rate, in bytes / second. All values are zero until the first sample is obtained.
 *
 * `latest` is comparable to what Linux reports as `tcpi_delivery_rate`: both are the rate of the most recent sample, measured from
 * the ACK received before a packet was sent until that packet is acknowledged. Linux additionally bounds each sample by the time
 * over which the packets were sent, takes a sample at every ACK, and keeps the latest sample that is not application-limited.
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
 * returns if currently marked as CC-limited
 */
static int quicly_ratemeter_is_cc_limited(quicly_ratemeter_t *meter);
/**
 * Notifies the estimator that the flow is becoming CC-limited at the point of sending packets *starting* from packet number `pn`.
 */
void quicly_ratemeter_enter_cc_limited(quicly_ratemeter_t *meter, uint64_t pn);
/**
 * Notifies that the estimator that the flow is exiting from CC-limited when the packet number of the next packet will be `pn`.
 */
void quicly_ratemeter_exit_cc_limited(quicly_ratemeter_t *meter, uint64_t pn);
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

inline int quicly_ratemeter_is_cc_limited(quicly_ratemeter_t *meter)
{
    return meter->window.end_pn != UINT64_MAX;
}

#ifdef __cplusplus
}
#endif

#endif
