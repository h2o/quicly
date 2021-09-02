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

#ifndef quicly_delivery_rate_h
#define quicly_delivery_rate_h

#include <stdint.h>
#include "quicly/ranges.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef QUICLY_DELIVERY_RATE_SAMPLE_PERIOD
/**
 * sampling period of delivery rate, in milliseconds
 */
#define QUICLY_DELIVERY_RATE_SAMPLE_PERIOD 50
#endif

#ifndef QUICLY_DELIVERY_RATE_SAMPLE_COUNT
/**
 * number of samples to retain (and to calculate average from)
 */
#define QUICLY_DELIVERY_RATE_SAMPLE_COUNT 10
#endif

struct st_quicly_delivery_rate_sample_t {
    uint32_t elapsed;
    uint32_t bytes_acked;
};

/**
 * State used for estimating the delivery rate.
 */
typedef struct st_quicly_delivery_rate_t {
    /**
     * ring buffer retaining the most recent samples
     */
    struct {
        struct st_quicly_delivery_rate_sample_t entries[QUICLY_DELIVERY_RATE_SAMPLE_COUNT];
        size_t latest;
    } past_samples;
    /**
     * packet number range within which the flow has been CWND-limited
     */
    quicly_range_t pn_cwnd_limited;
    /**
     * When running, retains the start of the sampling period as well as the value of `stats.num_bytes.ack_received`. When
     * not running, at is set to INT64_MAX.
     */
    struct {
        struct {
            int64_t at;
            uint64_t bytes_acked;
        } start;
        struct st_quicly_delivery_rate_sample_t sample;
    } current;
} quicly_delivery_rate_t;

/**
 *
 */
void quicly_delivery_rate_init(quicly_delivery_rate_t *dr);
/**
 * Notifies the estimator that the flow is CWND-limited at the point of sending packets *starting* from packet number `pn`.
 */
void quicly_delivery_rate_in_cwnd_limited(quicly_delivery_rate_t *dr, uint64_t pn);
/**
 * Notifies that the estimator that the flow is not CWND-limited when the packet number of the next packet will be `pn`.
 */
void quicly_delivery_rate_not_cwnd_limited(quicly_delivery_rate_t *dr, uint64_t pn);
/**
 * Given three values, update the estimation.
 * @param bytes_acked  total number of bytes being acked from the beginning of the connection; i.e.,
 *                     `quicly_stats_t::num_bytes.ack_received`
 */
void quicly_delivery_rate_on_ack(quicly_delivery_rate_t *dr, int64_t now, uint64_t bytes_acked, uint64_t pn);
/**
 * Returns three indicators of the delivery rate estimate
 */
void quicly_delivery_rate_report(quicly_delivery_rate_t *dr, uint64_t *latest, uint64_t *smoothed, uint64_t *variance);

#ifdef __cplusplus
}
#endif

#endif
