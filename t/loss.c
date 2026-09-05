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

static int64_t now;
static uint64_t num_packets_lost = 0;
static uint64_t num_persistent_congestion = 0;

static void on_loss_detected(quicly_loss_t *loss, const quicly_sent_packet_t *lost_packet, int is_time_threshold)
{
    ++num_packets_lost;
}

static void on_persistent_congestion(quicly_loss_t *loss)
{
    ++num_persistent_congestion;
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
    int64_t sent_at = sent->sent_at;
    ok(quicly_loss_on_packet_acked(loss, pn) == 0);
    ok(quicly_sentmap_update(&loss->sentmap, &iter, QUICLY_SENTMAP_EVENT_ACKED) == 0);

    quicly_loss_on_ack_received(loss, pn, UINT64_MAX, pn + 1, epoch, now, sent_at, 0, QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
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
    int64_t last_retransmittable_sent_at[QUICLY_NUM_EPOCHS] = {INT64_MAX, INT64_MAX, INT64_MAX, INT64_MAX};

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
    last_retransmittable_sent_at[QUICLY_EPOCH_HANDSHAKE] = now;
    last_retransmittable_sent_at[QUICLY_EPOCH_1RTT] = now;
    quicly_loss_update_alarm(&loss, now, last_retransmittable_sent_at, (1u << QUICLY_EPOCH_HANDSHAKE) | (1u << QUICLY_EPOCH_1RTT),
                             0, 0, 0, 1);

    now += 10;

    /* receive ack for the Handshake packet, but 1RTT packet remains unacknowledged */
    acked(&loss, 1, QUICLY_EPOCH_HANDSHAKE);
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time == INT64_MAX);
    ok(num_packets_lost == 0);

    /* Application Data alone must not arm PTO before confirmation. */
    quicly_loss_update_alarm(&loss, now, last_retransmittable_sent_at, 1u << QUICLY_EPOCH_1RTT, 0, 0, 0, 0);
    ok(loss.alarm_at == INT64_MAX);

    /* Once confirmed, the same outstanding packet arms an Application Data PTO including max_ack_delay. */
    quicly_loss_update_alarm(&loss, now, last_retransmittable_sent_at, 1u << QUICLY_EPOCH_1RTT, 0, 1, 0, 0);
    ok(loss.alarm_at != INT64_MAX);
    ok(loss.alarm_at > now);

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

static void send_ack_eliciting(quicly_loss_t *loss, uint64_t pn, size_t epoch, int64_t sent_at)
{
    now = sent_at;
    ok(quicly_sentmap_prepare(&loss->sentmap, pn, now, epoch) == 0);
    quicly_sentmap_commit(&loss->sentmap, 10, 0, 0);
}

static void init_persistent_congestion_test(quicly_loss_t *loss)
{
    now = 0;
    num_packets_lost = 0;
    num_persistent_congestion = 0;
    quicly_loss_init(loss, &quicly_spec_context.loss, 20, &quicly_spec_context.transport_params.max_ack_delay,
                     &quicly_spec_context.transport_params.ack_delay_exponent);
    send_ack_eliciting(loss, 0, QUICLY_EPOCH_INITIAL, 0);
    now = 10;
    acked(loss, 0, QUICLY_EPOCH_INITIAL);
}

static void detect_loss_after_ack(quicly_loss_t *loss)
{
    ok(quicly_loss_detect_loss_after_ack(loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected,
                                         on_persistent_congestion) == 0);
}

static void test_persistent_congestion(void)
{
    quicly_loss_t loss;

    /* Obtain an RTT sample before sending the packets used to establish persistent congestion. */
    init_persistent_congestion_test(&loss);

    /* The post-sample packets span more than three PTOs and are both declared lost by the ACKs for packets 4 and 5. */
    send_ack_eliciting(&loss, 1, QUICLY_EPOCH_INITIAL, 11);
    send_ack_eliciting(&loss, 2, QUICLY_EPOCH_HANDSHAKE, 400);
    send_ack_eliciting(&loss, 4, QUICLY_EPOCH_INITIAL, 401);
    send_ack_eliciting(&loss, 5, QUICLY_EPOCH_HANDSHAKE, 402);
    now = 420;
    acked(&loss, 4, QUICLY_EPOCH_INITIAL);
    acked(&loss, 5, QUICLY_EPOCH_HANDSHAKE);
    /* Exercise the loss-alarm entry point, which must retain persistent-congestion handling. */
    size_t min_packets_to_send;
    int restrict_sending;
    loss.loss_time = now;
    ok(quicly_loss_on_alarm(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, &min_packets_to_send,
                            &restrict_sending, on_loss_detected, on_persistent_congestion) == 0);
    ok(min_packets_to_send == 1);
    ok(!restrict_sending);
    ok(num_packets_lost == 2);
    ok(num_persistent_congestion == 1);

    /* The callback is emitted once for a continuous congestion period. */
    detect_loss_after_ack(&loss);
    ok(num_persistent_congestion == 1);
    quicly_loss_dispose(&loss);

    /* A persistent-congestion period can span packets declared lost by separate detection passes. */
    init_persistent_congestion_test(&loss);
    send_ack_eliciting(&loss, 1, QUICLY_EPOCH_INITIAL, 11);
    send_ack_eliciting(&loss, 2, QUICLY_EPOCH_HANDSHAKE, 400);
    send_ack_eliciting(&loss, 4, QUICLY_EPOCH_INITIAL, 401);
    now = 410;
    acked(&loss, 4, QUICLY_EPOCH_INITIAL);
    detect_loss_after_ack(&loss);
    ok(num_packets_lost == 1);
    ok(num_persistent_congestion == 0);
    send_ack_eliciting(&loss, 5, QUICLY_EPOCH_HANDSHAKE, 411);
    now = 420;
    acked(&loss, 5, QUICLY_EPOCH_HANDSHAKE);
    detect_loss_after_ack(&loss);
    ok(num_packets_lost == 2);
    ok(num_persistent_congestion == 1);
    quicly_loss_dispose(&loss);

    /* An acknowledged packet sent between the two lost packets splits the congestion period. */
    init_persistent_congestion_test(&loss);
    send_ack_eliciting(&loss, 1, QUICLY_EPOCH_INITIAL, 11);
    send_ack_eliciting(&loss, 2, QUICLY_EPOCH_HANDSHAKE, 100);
    now = 110;
    acked(&loss, 2, QUICLY_EPOCH_HANDSHAKE);
    send_ack_eliciting(&loss, 3, QUICLY_EPOCH_INITIAL, 400);
    send_ack_eliciting(&loss, 6, QUICLY_EPOCH_INITIAL, 401);
    now = 420;
    acked(&loss, 6, QUICLY_EPOCH_INITIAL);
    detect_loss_after_ack(&loss);
    ok(num_packets_lost == 2);
    ok(num_persistent_congestion == 0);
    quicly_loss_dispose(&loss);

    /* An outstanding packet between the lost packets does not interrupt persistent congestion; only an ACK does. */
    init_persistent_congestion_test(&loss);
    send_ack_eliciting(&loss, 1, QUICLY_EPOCH_INITIAL, 11);
    send_ack_eliciting(&loss, 2, QUICLY_EPOCH_1RTT, 200);
    send_ack_eliciting(&loss, 3, QUICLY_EPOCH_HANDSHAKE, 400);
    send_ack_eliciting(&loss, 5, QUICLY_EPOCH_INITIAL, 401);
    send_ack_eliciting(&loss, 6, QUICLY_EPOCH_HANDSHAKE, 402);
    now = 420;
    acked(&loss, 5, QUICLY_EPOCH_INITIAL);
    acked(&loss, 6, QUICLY_EPOCH_HANDSHAKE);
    detect_loss_after_ack(&loss);
    ok(num_packets_lost == 2);
    ok(num_persistent_congestion == 1);
    quicly_loss_dispose(&loss);
}

void test_loss(void)
{
    subtest("time-detection", test_time_detection);
    subtest("pn-detection", test_pn_detection);
    subtest("slow-cert-verify", test_slow_cert_verify);
    subtest("late-ack-threshold-adjustment", test_late_ack_threshold_adjustment);
    subtest("persistent-congestion", test_persistent_congestion);
}
