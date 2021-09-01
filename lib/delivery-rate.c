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

#include "picotls.h"
#include "quicly/delivery-rate.h"

static void start_sampling(quicly_delivery_rate_t *dr, int64_t now, uint64_t bytes_acked)
{
    dr->current.start.at = now;
    dr->current.start.bytes_acked = bytes_acked;
}

static void commit_sample(quicly_delivery_rate_t *dr)
{
    dr->past_samples.entries[dr->past_samples.slot] = dr->current.sample;
    ++dr->past_samples.slot;
    if (dr->past_samples.slot >= PTLS_ELEMENTSOF(dr->past_samples.entries))
        dr->past_samples.slot = 0;

    dr->current.start.at = INT64_MAX;
    dr->current.sample = (struct st_quicly_delivery_rate_sample_t){};
}

void quicly_delivery_rate_init(quicly_delivery_rate_t *dr)
{
    *dr = (quicly_delivery_rate_t){
        .pn_cwnd_limited = {.start = UINT64_MAX, .end = UINT64_MAX},
        .current = {.start = {.at = INT64_MAX}},
    };
}

void quicly_delivery_rate_in_cwnd_limited(quicly_delivery_rate_t *dr, uint64_t pn)
{
    /* bail out if already in cwnd-limited phase */
    if (dr->pn_cwnd_limited.start != UINT64_MAX && dr->pn_cwnd_limited.end == UINT64_MAX)
        return;

    /* if the estimator was waiting for the end of the previous phase, and if a valid partial sample exists, commit it now */
    if (dr->pn_cwnd_limited.end != UINT64_MAX && dr->current.sample.elapsed != 0)
        commit_sample(dr);

    /* begin new cwnd-limited phase */
    dr->pn_cwnd_limited = (quicly_range_t){.start = pn, .end = UINT64_MAX};
}

void quicly_delivery_rate_not_cwnd_limited(quicly_delivery_rate_t *dr, uint64_t pn)
{
    if (dr->pn_cwnd_limited.start != UINT64_MAX && dr->pn_cwnd_limited.end == UINT64_MAX)
        dr->pn_cwnd_limited.end = pn;
}

void quicly_delivery_rate_on_ack(quicly_delivery_rate_t *dr, int64_t now, uint64_t bytes_acked, uint64_t pn)
{
    if (dr->pn_cwnd_limited.start <= pn && pn < dr->pn_cwnd_limited.end) {
        /* At the moment, the flow is CWND-limited. Either start the timer or update. */
        if (dr->current.start.at == INT64_MAX) {
            start_sampling(dr, now, bytes_acked);
        } else {
            dr->current.sample = (struct st_quicly_delivery_rate_sample_t){
                .elapsed = (uint32_t)(now - dr->current.start.at),
                .bytes_acked = (uint32_t)(bytes_acked - dr->current.start.bytes_acked),
            };
            if (dr->current.sample.elapsed >= QUICLY_DELIVERY_RATE_SAMPLE_PERIOD) {
                commit_sample(dr);
                start_sampling(dr, now, bytes_acked);
            }
        }
    } else if (dr->pn_cwnd_limited.end <= pn) {
        /* We have exitted CWND-limited state. Save current value, if any. */
        if (dr->current.start.at != INT64_MAX) {
            if (dr->current.sample.elapsed != 0)
                commit_sample(dr);
            dr->pn_cwnd_limited = (quicly_range_t){.start = UINT64_MAX, .end = UINT64_MAX};
            dr->current.start.at = INT64_MAX;
        }
    }

#undef START_SAMPLING
#undef ADVANCE_SLOT
}

static uint64_t to_speed(uint64_t bytes_acked, uint32_t elapsed)
{
    return bytes_acked * 1000 / elapsed;
}

void quicly_delivery_rate_report(quicly_delivery_rate_t *dr, uint64_t *latest, uint64_t *smoothed, uint64_t *variance)
{
    { /* Calculate latest, or return if there are no samples at all. `latest` being reported will be the most recent "full" sample
       * if available, or else a partial sample. */
        const struct st_quicly_delivery_rate_sample_t *latest_sample =
            &dr->past_samples
                 .entries[dr->past_samples.slot != 0 ? dr->past_samples.slot - 1 : PTLS_ELEMENTSOF(dr->past_samples.entries) - 1];
        if (latest_sample->elapsed == 0) {
            latest_sample = &dr->current.sample;
            if (latest_sample->elapsed == 0) {
                *latest = *smoothed = *variance = 0;
                return;
            }
        }
        *latest = to_speed(latest_sample->bytes_acked, latest_sample->elapsed);
    }

#define FOREACH_SAMPLE(func)                                                                                                       \
    do {                                                                                                                           \
        const struct st_quicly_delivery_rate_sample_t *sample;                                                                     \
        for (size_t i = 0; i < PTLS_ELEMENTSOF(dr->past_samples.entries); ++i) {                                                   \
            if ((sample = &dr->past_samples.entries[i])->elapsed != 0) {                                                           \
                func                                                                                                               \
            }                                                                                                                      \
        }                                                                                                                          \
        if ((sample = &dr->current.sample)->elapsed != 0) {                                                                        \
            func                                                                                                                   \
        }                                                                                                                          \
    } while (0)

    { /* calculate average */
        uint64_t total_acked = 0;
        uint32_t total_elapsed = 0;
        FOREACH_SAMPLE({
            total_acked += sample->bytes_acked;
            total_elapsed += sample->elapsed;
        });
        *smoothed = to_speed(total_acked, total_elapsed);
    }

    { /* calculate variance */
        uint64_t sum = 0;
        size_t count = 0;
        FOREACH_SAMPLE({
            uint64_t sample_speed = to_speed(sample->bytes_acked, sample->elapsed);
            sum += (sample_speed - *smoothed) * (sample_speed - *smoothed);
            ++count;
        });
        *variance = sum / count;
    }

#undef FOREACH_SAMPLE
}
