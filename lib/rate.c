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
#include "picotls.h"
#include "quicly/rate.h"

void quicly_ratemeter_init(quicly_ratemeter_t *meter)
{
    *meter = (quicly_ratemeter_t){
        .estimate = {.smoothed = NAN},
        .window = {.end_pn = UINT64_MAX},
    };
}

void quicly_ratemeter_enter_cc_limited(quicly_ratemeter_t *meter, uint64_t pn)
{
    assert(!quicly_ratemeter_is_cc_limited(meter));

    /* The first window ends at the ACK for the first packet sent while CC-limited, and is not used as a sample. */
    meter->window = (struct st_quicly_ratemeter_window_t){.end_pn = pn, .at = NAN};
}

void quicly_ratemeter_exit_cc_limited(quicly_ratemeter_t *meter, uint64_t pn)
{
    assert(quicly_ratemeter_is_cc_limited(meter));

    meter->window.end_pn = UINT64_MAX;
}

void quicly_ratemeter_on_ack(quicly_ratemeter_t *meter, double now, uint64_t bytes_acked, uint64_t largest_pn_acked,
                             uint64_t next_pn)
{
    if (meter->window.end_pn == UINT64_MAX || largest_pn_acked < meter->window.end_pn)
        return;

    /* The window has ended; update the estimate using the window as a sample, unless it is the first one. The estimate is updated
     * in the same way as smoothed_rtt and rttvar of RFC 9002. */
    if (!isnan(meter->window.at)) {
        double sample = (bytes_acked - meter->window.bytes_acked) * 1000 / (now - meter->window.at);
        if (isnan(meter->estimate.smoothed)) {
            meter->estimate.smoothed = sample;
            meter->estimate.variation = sample / 2;
        } else {
            meter->estimate.variation = meter->estimate.variation * 3 / 4 + fabs(meter->estimate.smoothed - sample) / 4;
            meter->estimate.smoothed = meter->estimate.smoothed * 7 / 8 + sample / 8;
        }
        meter->estimate.latest = sample;
    }

    /* start the next window, which ends at the ACK for the next packet to be sent */
    meter->window = (struct st_quicly_ratemeter_window_t){.end_pn = next_pn, .at = now, .bytes_acked = bytes_acked};
}

void quicly_ratemeter_report(quicly_ratemeter_t *meter, quicly_rate_t *rate)
{
    if (isnan(meter->estimate.smoothed)) {
        *rate = (quicly_rate_t){};
        return;
    }
    *rate = (quicly_rate_t){
        .latest = (uint64_t)round(meter->estimate.latest),
        .smoothed = (uint64_t)round(meter->estimate.smoothed),
        .variation = (uint64_t)round(meter->estimate.variation),
    };
}
