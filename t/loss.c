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
#include <math.h>
#include "quicly/loss.h"
#include "quicly/defaults.h"
#include "test.h"

static int64_t now;
static uint64_t num_packets_lost = 0;

static void on_loss_detected(quicly_loss_t *loss, const quicly_sent_packet_t *lost_packet, int is_time_threshold)
{
    ++num_packets_lost;
}

static void acked(quicly_loss_t *loss, uint64_t pn, size_t epoch)
{
    quicly_sentmap_iter_t iter;
    const quicly_sent_packet_t *sent;

    quicly_loss_init_sentmap_iter(loss, &iter, now, quicly_spec_context.transport_params.max_ack_delay, 0);
    while ((sent = quicly_sentmap_get(&iter))->packet_number != pn) {
        assert(sent->packet_number != UINT64_MAX);
        quicly_sentmap_skip(&iter);
    }
    double sent_at = sent->sent_at;
    ok(quicly_sentmap_update(&loss->sentmap, &iter, QUICLY_SENTMAP_EVENT_ACKED) == 0);

    quicly_loss_on_ack_received(loss, pn, UINT64_MAX, pn + 1, epoch, now, sent_at, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
}

static void test_time_detection(void)
{
    quicly_loss_t loss;

    now = 0;
    num_packets_lost = 0;

    quicly_loss_init(&loss, &quicly_spec_context.loss, 20, &quicly_spec_context.transport_params.max_ack_delay,
                     &quicly_spec_context.transport_params.ack_delay_exponent);
    ok(loss.loss_time == INT64_MAX);

    /* commit 3 packets (pn=0..2); check that loss timer is not active */
    ok(quicly_sentmap_prepare(&loss.sentmap, 0, now, QUICLY_EPOCH_INITIAL) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_sentmap_prepare(&loss.sentmap, 1, now, QUICLY_EPOCH_INITIAL) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_sentmap_prepare(&loss.sentmap, 2, now, QUICLY_EPOCH_INITIAL) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time == INT64_MAX);

    now += 10;

    /* receive ack for the 1st packet; check that loss timer is not active */
    acked(&loss, 0, QUICLY_EPOCH_INITIAL);
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time == INT64_MAX);

    now += 10;

    /* receive ack for the 3rd packet; check that loss timer is active */
    acked(&loss, 2, QUICLY_EPOCH_INITIAL);
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time != INT64_MAX);
    ok(num_packets_lost == 0);

    now = loss.loss_time;
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
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

    /* commit 4 packets (pn=0..3); check that loss timer is not active */
    ok(quicly_sentmap_prepare(&loss.sentmap, 0, now, QUICLY_EPOCH_INITIAL) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_sentmap_prepare(&loss.sentmap, 1, now, QUICLY_EPOCH_INITIAL) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_sentmap_prepare(&loss.sentmap, 2, now, QUICLY_EPOCH_INITIAL) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_sentmap_prepare(&loss.sentmap, 3, now, QUICLY_EPOCH_INITIAL) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time == INT64_MAX);

    /* receive ack for the 3rd packet; loss timer is activated but no packets are declared as lost */
    acked(&loss, 2, QUICLY_EPOCH_INITIAL);
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time != INT64_MAX);
    ok(num_packets_lost == 0);

    /* receive ack for the 4th packet; loss timer is active and pn=0 is declared lost */
    acked(&loss, 3, QUICLY_EPOCH_INITIAL);
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time != INT64_MAX);
    ok(num_packets_lost == 1);

    quicly_loss_dispose(&loss);
}

static void test_slow_cert_verify(void)
{
    quicly_loss_t loss;
    int64_t last_retransmittable_sent_at;
    size_t min_packets_to_send;
    int restrict_sending;

    now = 0;
    num_packets_lost = 0;

    quicly_loss_init(&loss, &quicly_spec_context.loss, 20, &quicly_spec_context.transport_params.max_ack_delay,
                     &quicly_spec_context.transport_params.ack_delay_exponent);
    ok(loss.loss_time == INT64_MAX);

    /* sent Handshake+1RTT packet */
    ok(quicly_sentmap_prepare(&loss.sentmap, 1, now, QUICLY_EPOCH_HANDSHAKE) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_sentmap_prepare(&loss.sentmap, 2, now, QUICLY_EPOCH_1RTT) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    last_retransmittable_sent_at = now;
    quicly_loss_update_alarm(&loss, now, last_retransmittable_sent_at, 1, 0, 1, 0, 1);

    now += 10;

    /* receive ack for the Handshake packet, but 1RTT packet remains unacknowledged */
    acked(&loss, 1, QUICLY_EPOCH_HANDSHAKE);
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time == INT64_MAX);
    ok(num_packets_lost == 0);

    /* PTO fires */
    now = loss.alarm_at;
    ok(quicly_loss_on_alarm(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, &min_packets_to_send,
                            &restrict_sending, on_loss_detected) == 0);
    ok(restrict_sending);
    ok(min_packets_to_send == 2);
    ok(num_packets_lost == 0);

    /* therefore send probes */
    ok(quicly_sentmap_prepare(&loss.sentmap, 3, now, QUICLY_EPOCH_HANDSHAKE) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_sentmap_prepare(&loss.sentmap, 4, now, QUICLY_EPOCH_1RTT) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);

    now += 10;

    /* again receives an ack for the Handshake packet, but 1RTT packet remains unacknowledged */
    acked(&loss, 3, QUICLY_EPOCH_HANDSHAKE);
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time == INT64_MAX);
    ok(num_packets_lost == 0);

    quicly_loss_dispose(&loss);
}

static void test_late_ack_threshold_adjustment(void)
{
    quicly_loss_t loss;

    now = 0;

    quicly_loss_init(&loss, &quicly_spec_context.loss, 20, &quicly_spec_context.transport_params.max_ack_delay,
                     &quicly_spec_context.transport_params.ack_delay_exponent);

    ok(loss.min_pn_to_relax_reorder_tolerance == 0);
    ok(loss.thresholds.use_packet_based);
    ok(loss.thresholds.time_based_percentile == 1024 / 8);

    quicly_loss_on_ack_received(&loss, 100, 100, 200, QUICLY_EPOCH_1RTT, now, now - 20, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING_LATE_ACK);
    ok(loss.min_pn_to_relax_reorder_tolerance == 200);
    ok(!loss.thresholds.use_packet_based);
    ok(loss.thresholds.time_based_percentile == 1024 / 8);

    quicly_loss_on_ack_received(&loss, 101, 101, 200, QUICLY_EPOCH_1RTT, now, now - 20, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING_LATE_ACK);
    ok(loss.min_pn_to_relax_reorder_tolerance == 200);
    ok(!loss.thresholds.use_packet_based);
    ok(loss.thresholds.time_based_percentile == 1024 / 8);

    quicly_loss_on_ack_received(&loss, 250, 199, 300, QUICLY_EPOCH_1RTT, now, now - 20, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING_LATE_ACK);
    ok(loss.min_pn_to_relax_reorder_tolerance == 200);
    ok(!loss.thresholds.use_packet_based);
    ok(loss.thresholds.time_based_percentile == 1024 / 8);

    quicly_loss_on_ack_received(&loss, 200, 200, 300, QUICLY_EPOCH_1RTT, now, now - 20, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING_LATE_ACK);
    ok(loss.min_pn_to_relax_reorder_tolerance == 300);
    ok(!loss.thresholds.use_packet_based);
    ok(loss.thresholds.time_based_percentile == 1024 / 4);

    quicly_loss_dispose(&loss);
}

static void test_fractional_rtt(void)
{
    quicly_loss_t loss;
    const double sent_at = 1800000000000.125;
    const uint16_t max_ack_delay = 1;
    const uint8_t ack_delay_exponent = 3;
    quicly_loss_init(&loss, &quicly_spec_context.loss, 20, &max_ack_delay, &ack_delay_exponent);

    /* Fractional measurements are retained even with epoch-scale timestamps. */
    quicly_loss_on_ack_received(&loss, 0, UINT64_MAX, 1, QUICLY_EPOCH_1RTT, sent_at + 1.125, sent_at, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
    ok(loss.rtt.latest == 1.125f && loss.rtt.minimum == 1.125f);
    ok(loss.rtt.smoothed == 1.125f && loss.rtt.variance == 0.5625f);
    ok(quicly_rtt_get_pto(&loss.rtt, 0, 1) == 3); /* timer granularity is still milliseconds */

    /* Subtract an encoded 256us ACK delay without rounding it to milliseconds. */
    quicly_loss_on_ack_received(&loss, 1, UINT64_MAX, 2, QUICLY_EPOCH_1RTT, sent_at + 1.625, sent_at, 32,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
    ok(fabsf(loss.rtt.latest - 1.369f) < 0.000001f);
    ok(loss.rtt.minimum == 1.125f);
    ok(fabsf(loss.rtt.smoothed - 1.1555f) < 0.000001f);
    ok(fabsf(loss.rtt.variance - 0.482875f) < 0.000001f);

    /* The peer's maximum ACK delay is still expressed in milliseconds and caps even a huge encoded delay. */
    quicly_loss_on_ack_received(&loss, 2, UINT64_MAX, 3, QUICLY_EPOCH_1RTT, sent_at + 2.625, sent_at, UINT64_C(0x3fffffffffffffff),
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
    ok(loss.rtt.latest == 1.625f);

    /* Sub-millisecond measurements and zero-duration samples retain the 1ms minimum. */
    quicly_loss_on_ack_received(&loss, 3, UINT64_MAX, 4, QUICLY_EPOCH_1RTT, sent_at + 0.001, sent_at, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
    ok(loss.rtt.latest == 1 && loss.rtt.minimum == 1);
    quicly_loss_on_ack_received(&loss, 4, UINT64_MAX, 5, QUICLY_EPOCH_1RTT, sent_at, sent_at, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
    ok(loss.rtt.latest == 1);
    quicly_loss_dispose(&loss);
}

static void test_fractional_sentmap_timers(void)
{
    quicly_loss_t loss;
    const int64_t millisec = INT64_C(1800000000000);
    const double sent_at = millisec + 0.75;
    quicly_loss_init(&loss, &quicly_spec_context.loss, 20, &quicly_spec_context.transport_params.max_ack_delay,
                     &quicly_spec_context.transport_params.ack_delay_exponent);
    for (uint64_t pn = 0; pn != 2; ++pn) {
        ok(quicly_sentmap_prepare(&loss.sentmap, pn, sent_at, QUICLY_EPOCH_1RTT) == 0);
        quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    }
    quicly_sentmap_iter_t iter;
    quicly_sentmap_init_iter(&loss.sentmap, &iter);
    quicly_sentmap_skip(&iter);
    ok(quicly_sentmap_update(&loss.sentmap, &iter, QUICLY_SENTMAP_EVENT_ACKED) == 0);
    quicly_loss_on_ack_received(&loss, 1, UINT64_MAX, 2, QUICLY_EPOCH_1RTT, sent_at + 1.125, sent_at, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);

    num_packets_lost = 0;
    /* The 1.125ms RTT gives a 2ms loss delay; sent at +0.75ms, the packet must survive the +2ms tick. */
    ok(quicly_loss_detect_loss(&loss, millisec + 2, 0, 1, on_loss_detected) == 0);
    ok(num_packets_lost == 0 && loss.loss_time == millisec + 3);
    ok(quicly_loss_detect_loss(&loss, millisec + 3, 0, 1, on_loss_detected) == 0);
    ok(num_packets_lost == 1 && loss.loss_time == INT64_MAX);

    /* Closing-state expiration waits until the first timer tick past the fractional deadline. */
    int64_t expires_at = millisec + quicly_loss_get_sentmap_expiration_time(&loss, 0) + 1;
    ok(quicly_loss_init_sentmap_iter(&loss, &iter, expires_at - 1, 0, 1) == 0);
    ok(quicly_sentmap_get(&iter)->packet_number == 0);
    ok(quicly_loss_init_sentmap_iter(&loss, &iter, expires_at, 0, 1) == 0);
    ok(quicly_sentmap_get(&iter)->packet_number == UINT64_MAX);
    /* Even the largest finite timer value must not retire the end-of-iteration sentinel. */
    ok(quicly_loss_init_sentmap_iter(&loss, &iter, INT64_MAX, 0, 1) == 0);
    ok(quicly_sentmap_get(&iter)->packet_number == UINT64_MAX);
    quicly_loss_dispose(&loss);
}

void test_loss(void)
{
    subtest("fractional-rtt", test_fractional_rtt);
    subtest("fractional-sentmap-timers", test_fractional_sentmap_timers);
    subtest("time-detection", test_time_detection);
    subtest("pn-detection", test_pn_detection);
    subtest("slow-cert-verify", test_slow_cert_verify);
    subtest("late-ack-threshold-adjustment", test_late_ack_threshold_adjustment);
}
