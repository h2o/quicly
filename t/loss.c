/*
 * Copyright (c) 2017 Fastly, Kazuho Oku
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
#include "quicly/defaults.h"
#include "test.h"

#define ASSERT(expr)                                                                                                               \
    do {                                                                                                                           \
        int ret = !!(expr);                                                                                                        \
        assert(ret);                                                                                                               \
    } while (0)

static int64_t now;
static uint64_t num_packets_lost = 0;

static void on_loss_detected(quicly_loss_t *loss, const quicly_sent_packet_t *lost_packet, int is_time_threshold)
{
    ++num_packets_lost;
}

static void acked(quicly_loss_t *loss, uint64_t pn)
{
    quicly_sentmap_iter_t iter;
    const quicly_sent_packet_t *sent;

    quicly_loss_init_sentmap_iter(loss, &iter, now, quicly_spec_context.transport_params.max_ack_delay, 0);
    while ((sent = quicly_sentmap_get(&iter))->packet_number != pn) {
        assert(sent->packet_number != UINT64_MAX);
        quicly_sentmap_skip(&iter);
    }
    int64_t sent_at = sent->sent_at;
    ASSERT(quicly_sentmap_update(&loss->sentmap, &iter, QUICLY_SENTMAP_EVENT_ACKED) == 0);

    quicly_loss_on_ack_received(loss, pn, now, sent_at, 0, 1);
}

static void test_time_detection(void)
{
    quicly_loss_t loss;

    now = 0;
    num_packets_lost = 0;

    quicly_loss_init(&loss, &quicly_spec_context.loss, 20, &quicly_spec_context.transport_params.max_ack_delay,
                     &quicly_spec_context.transport_params.ack_delay_exponent);
    ok(loss.loss_time == INT64_MAX);

    /* commit packets 3 packets (pn=0..2); check that loss timer is not active */
    ASSERT(quicly_sentmap_prepare(&loss.sentmap, 0, now, 0) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10);
    ASSERT(quicly_sentmap_prepare(&loss.sentmap, 1, now, 0) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10);
    ASSERT(quicly_sentmap_prepare(&loss.sentmap, 2, now, 0) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10);
    ASSERT(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, on_loss_detected) == 0);
    ok(loss.loss_time == INT64_MAX);

    now += 10;

    /* receive ack for the 1st packet; check that loss timer is not active */
    acked(&loss, 0);
    ASSERT(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, on_loss_detected) == 0);
    ok(loss.loss_time == INT64_MAX);

    now += 10;

    /* receive ack for the 3rd packet; check that loss timer is active */
    acked(&loss, 2);
    ASSERT(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, on_loss_detected) == 0);
    ok(loss.loss_time != INT64_MAX);
    ok(num_packets_lost == 0);

    now = loss.loss_time;
    ASSERT(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, on_loss_detected) == 0);
    ok(loss.loss_time == INT64_MAX);
    ok(num_packets_lost == 1);

    quicly_loss_dispose(&loss);
}

static void test_pn_detection(void)
{
    quicly_loss_t loss;

    now = 0;
    num_packets_lost = 0;

    quicly_loss_init(&loss, &quicly_spec_context.loss, 20, &quicly_spec_context.transport_params.max_ack_delay,
                     &quicly_spec_context.transport_params.ack_delay_exponent);
    ok(loss.loss_time == INT64_MAX);

    /* commit packets 3 packets (pn=0..2); check that loss timer is not active */
    ASSERT(quicly_sentmap_prepare(&loss.sentmap, 0, now, 0) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10);
    ASSERT(quicly_sentmap_prepare(&loss.sentmap, 1, now, 0) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10);
    ASSERT(quicly_sentmap_prepare(&loss.sentmap, 2, now, 0) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10);
    ASSERT(quicly_sentmap_prepare(&loss.sentmap, 3, now, 0) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10);
    ASSERT(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, on_loss_detected) == 0);
    ok(loss.loss_time == INT64_MAX);

    /* receive ack for the 3rd packet; loss timer is activated but no packets are declared as lost */
    acked(&loss, 2);
    ASSERT(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, on_loss_detected) == 0);
    ok(loss.loss_time != INT64_MAX);
    ok(num_packets_lost == 0);

    /* receive ack for the 4th packet; loss timer is active and pn=0 is declared lost */
    acked(&loss, 3);
    ASSERT(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, on_loss_detected) == 0);
    ok(loss.loss_time != INT64_MAX);
    ok(num_packets_lost == 1);

    quicly_loss_dispose(&loss);
}

void test_loss(void)
{
    subtest("time-detection", test_time_detection);
    subtest("pn-detection", test_pn_detection);
}
