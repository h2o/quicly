/*
 * Copyright (c) 2017-2020 Fastly, Kazuho Oku
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
#include "quicly/loss.h"

void quicly_loss_init_sentmap_iter(quicly_loss_t *loss, quicly_sentmap_iter_t *iter, int64_t now, uint32_t max_ack_delay,
                                   int is_closing)
{
    quicly_sentmap_init_iter(&loss->sentmap, iter);

    int64_t retire_before = now - quicly_loss_get_sentmap_expiration_time(loss, max_ack_delay);

    /* Retire entries older than the time specified, unless the connection is alive and the number of packets in the sentmap is
     * below 32 packets. This exception exists in order to recognize excessively late-ACKs when under heavy loss. */
    const quicly_sent_packet_t *sent;
    while ((sent = quicly_sentmap_get(iter))->sent_at <= retire_before && sent->cc_bytes_in_flight == 0) {
        if (!is_closing && loss->sentmap.num_packets < 32)
            break;
        quicly_sentmap_update(&loss->sentmap, iter, QUICLY_SENTMAP_EVENT_EXPIRED);
    }
}

int quicly_loss_detect_loss(quicly_loss_t *r, quicly_loss_do_detect_cb do_detect)
{
    uint32_t delay_until_lost = ((r->rtt.latest > r->rtt.smoothed ? r->rtt.latest : r->rtt.smoothed) * 9 + 7) / 8;
    int64_t loss_time;
    int ret;

    r->loss_time = INT64_MAX;

    if ((ret = do_detect(r, delay_until_lost, &loss_time)) != 0)
        return ret;
    if (loss_time != INT64_MAX)
        r->loss_time = loss_time;

    return 0;
}
