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
    int64_t sent_at = sent->sent_at;
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

static void test_rtt_floor(void)
{
    quicly_rtt_t rtt;

    quicly_rtt_init(&rtt, &quicly_spec_context.loss, quicly_spec_context.loss.default_initial_rtt);
    ok(quicly_rtt_get_floor(&rtt) == quicly_spec_context.loss.default_initial_rtt);
    quicly_rtt_init(&rtt, &quicly_spec_context.loss, 40);
    ok(quicly_rtt_get_floor(&rtt) == 40);

    quicly_rtt_update(&rtt, 16, 0, 1);
    ok(quicly_rtt_get_floor(&rtt) == 16);
    quicly_rtt_update(&rtt, 16, 0, 5);
    ok(rtt.floor.samples[0] == 16);
    ok(rtt.floor.samples[1] == 16);

    /* A lower sample in the current slot replaces its floor. */
    quicly_rtt_update(&rtt, 15, 0, 6);
    ok(quicly_rtt_get_floor(&rtt) == 15);

    /* Once the low samples age out, the floor rises. */
    quicly_rtt_update(&rtt, 21, 0, 21);
    quicly_rtt_update(&rtt, 21, 0, 25);
    quicly_rtt_update(&rtt, 21, 0, 29);
    quicly_rtt_update(&rtt, 21, 0, 33);
    ok(quicly_rtt_get_floor(&rtt) == 21);

    /* A three-slot jump retains only the previous slot 0, clearing the unsampled slots in between. */
    quicly_rtt_init(&rtt, &quicly_spec_context.loss, 40);
    quicly_rtt_update(&rtt, 16, 0, 1);
    quicly_rtt_update(&rtt, 20, 0, 5);
    quicly_rtt_update(&rtt, 24, 0, 9);
    quicly_rtt_update(&rtt, 28, 0, 13);
    ok(quicly_rtt_get_floor(&rtt) == 16);
    quicly_rtt_update(&rtt, 32, 0, 25);
    ok(quicly_rtt_get_floor(&rtt) == 28);

    /* That retained minimum must expire on the next shift, not survive in a skipped slot. */
    quicly_rtt_update(&rtt, 36, 0, 29);
    ok(quicly_rtt_get_floor(&rtt) == 32);

    /* Reinitialization discards the old floor and uses the new initial estimate until the next sample. */
    quicly_rtt_init(&rtt, &quicly_spec_context.loss, 80);
    ok(quicly_rtt_get_floor(&rtt) == 80);
    quicly_rtt_update(&rtt, 100, 0, 34);
    ok(quicly_rtt_get_floor(&rtt) == 100);

    /* Floor samples use the same ACK-delay adjustment as latest RTT. */
    quicly_rtt_update(&rtt, 120, 10, 200);
    ok(quicly_rtt_get_floor(&rtt) == 110);

    /* Sub-four-millisecond RTTs use one-millisecond slots rather than dividing by zero. */
    quicly_rtt_init(&rtt, &quicly_spec_context.loss, 20);
    quicly_rtt_update(&rtt, 3, 0, 1);
    quicly_rtt_update(&rtt, 3, 0, 2);
    ok(quicly_rtt_get_floor(&rtt) == 3);

    /* Accepted RTT samples update the floor as part of loss-core ACK processing. */
    quicly_loss_t loss;
    quicly_loss_init(&loss, &quicly_spec_context.loss, 20, &quicly_spec_context.transport_params.max_ack_delay,
                     &quicly_spec_context.transport_params.ack_delay_exponent);
    quicly_loss_on_ack_received(&loss, 0, UINT64_MAX, 1, QUICLY_EPOCH_1RTT, 100, 84, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
    ok(quicly_rtt_get_floor(&loss.rtt) == 16);
    /* An ACK without an RTT sample must not age or resample the floor. */
    int64_t newest_sample_until = loss.rtt.floor.newest_sample_until;
    quicly_loss_on_ack_received(&loss, 1, UINT64_MAX, 2, QUICLY_EPOCH_1RTT, 200, 100, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_NON_ACK_ELICITING);
    ok(loss.rtt.floor.newest_sample_until == newest_sample_until);
    ok(quicly_rtt_get_floor(&loss.rtt) == 16);
    quicly_loss_dispose(&loss);
}

void test_loss(void)
{
    subtest("time-detection", test_time_detection);
    subtest("pn-detection", test_pn_detection);
    subtest("slow-cert-verify", test_slow_cert_verify);
    subtest("late-ack-threshold-adjustment", test_late_ack_threshold_adjustment);
    subtest("rtt-floor", test_rtt_floor);
}
