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
#ifndef quicly_loss_h
#define quicly_loss_h

#include <stddef.h>
#include <stdint.h>
#include "quicly/constants.h"

typedef struct quicly_loss_conf_t {
    /**
     * Maximum number of tail loss probes before an RTO fires.
     */
    unsigned max_tlps;
    /**
     * Maximum reordering in time space before time based loss detection considers a packet lost. In percentile (1/1024) of an RTT.
     */
    unsigned time_reordering_percentile;
    /**
     * Minimum time in the future a tail loss probe alarm may be set for.
     */
    uint32_t min_tlp_timeout;
    /**
     * Minimum time in the future an RTO alarm may be set for.
     */
    uint32_t min_rto_timeout;
    /**
     * The default RTT used before an RTT sample is taken.
     */
    uint32_t default_initial_rtt;
} quicly_loss_conf_t;

extern quicly_loss_conf_t quicly_loss_default_conf;

typedef struct quicly_rtt_t {
    uint32_t smoothed;
    uint32_t variance;
    uint32_t latest;
} quicly_rtt_t;

static void quicly_rtt_init(quicly_rtt_t *rtt, const quicly_loss_conf_t *conf, uint32_t initial_rtt);
static void quicly_rtt_update(quicly_rtt_t *rtt, uint32_t latest_rtt);

typedef struct quicly_loss_t {
    /**
     * configuration
     */
    const quicly_loss_conf_t *conf;
    /**
     * The number of times a tail loss probe has been sent without receiving an ack.
     */
    uint8_t tlp_count;
    /**
     * The number of times an rto has been sent without receiving an ack.
     */
    uint8_t rto_count;
    /**
     * The last packet number sent prior to the first retransmission timeout.
     */
    uint64_t largest_sent_before_rto;
    /**
     * The time the most recent packet was sent.
     */
    int64_t time_of_last_packet_sent;
    /**
     * The largest packet number acknowledged in an ack frame.
     */
    uint64_t largest_acked_packet;
    /**
     * The time at which the next packet will be considered lost based on exceeding the reordering window in time.
     */
    uint64_t loss_time;
    /**
     *
     */

    /**
     * The time at when lostdetect_on_alarm should be called.
     */
    uint64_t alarm_at;
    /**
     * rtt
     */
    quicly_rtt_t rtt;
} quicly_loss_t;

typedef int (*quicly_loss_do_detect_cb)(quicly_loss_t *r, int64_t now, uint64_t largest_acked, uint32_t delay_until_lost,
                                        int64_t *loss_time);

static void quicly_loss_init(quicly_loss_t *r, const quicly_loss_conf_t *conf, uint32_t initial_rtt);
static void quicly_loss_update_alarm(quicly_loss_t *r, uint64_t now, int has_outstanding);
static int quicly_loss_on_packet_acked(quicly_loss_t *r, uint64_t acked);
static void quicly_loss_on_ack_received(quicly_loss_t *r, uint64_t largest_acked, uint32_t latest_rtt);
static int quicly_loss_on_alarm(quicly_loss_t *r, int64_t now, uint64_t largest_sent, quicly_loss_do_detect_cb do_detect,
                                size_t *num_packets_to_send);
static int quicly_loss_detect_loss(quicly_loss_t *r, int64_t now, uint64_t largest_sent, uint64_t largest_acked,
                                   quicly_loss_do_detect_cb do_detect);

/* inline definitions */

inline void quicly_rtt_init(quicly_rtt_t *rtt, const quicly_loss_conf_t *conf, uint32_t initial_rtt)
{
    rtt->latest = initial_rtt;
    if (rtt->latest * 2 < conf->min_tlp_timeout)
        rtt->latest = conf->min_tlp_timeout / 2;
    rtt->smoothed = rtt->latest;
    rtt->variance = rtt->latest / 2;
}

inline void quicly_rtt_update(quicly_rtt_t *rtt, uint32_t latest)
{
    rtt->latest = latest;
    if (rtt->smoothed == 0) {
        rtt->smoothed = latest;
        rtt->variance = latest / 2;
    } else {
        uint32_t absdiff = rtt->smoothed >= latest ? rtt->smoothed - latest : latest - rtt->smoothed;
        rtt->variance = (rtt->variance * 3 + absdiff) / 4;
        rtt->smoothed = (rtt->smoothed * 7 + latest) / 8;
    }
}

inline void quicly_loss_init(quicly_loss_t *r, const quicly_loss_conf_t *conf, uint32_t initial_rtt)
{
    *r = (quicly_loss_t){.conf = conf, .alarm_at = INT64_MAX};
    quicly_rtt_init(&r->rtt, conf, initial_rtt);
}

inline void quicly_loss_update_alarm(quicly_loss_t *r, uint64_t now, int has_outstanding)
{
    if (has_outstanding) {
        int64_t alarm_duration;
        if (r->loss_time != 0) {
            /* Time loss detection */
            alarm_duration = r->loss_time - now;
        } else if (r->tlp_count < r->conf->max_tlps) {
            /* Tail Loss Probe */
            if (has_outstanding) {
                alarm_duration = r->rtt.smoothed * 3 / 2 + QUICLY_DELAYED_ACK_TIMEOUT;
            } else {
                alarm_duration = r->conf->min_tlp_timeout;
            }
            if (alarm_duration < 2 * r->rtt.smoothed)
                alarm_duration = 2 * r->rtt.smoothed;
        } else {
            /* RTO alarm */
            alarm_duration = r->rtt.smoothed + 4 * r->rtt.variance;
            if (alarm_duration < r->conf->min_rto_timeout)
                alarm_duration = r->conf->min_rto_timeout;
            alarm_duration *= 1 << r->rto_count;
        }
        if (r->alarm_at > now + alarm_duration)
            r->alarm_at = now + alarm_duration;
    } else {
        r->alarm_at = INT64_MAX;
    }
}

inline int quicly_loss_on_packet_acked(quicly_loss_t *r, uint64_t acked)
{
    int rto_verified = r->rto_count > 0 && acked > r->largest_sent_before_rto;
    r->tlp_count = 0;
    r->rto_count = 0;
    return rto_verified;
}

/* After processing ack frames (including calls to on_packet_acked), application should call on_ack_received, detect_lost_packets,
 * and then update_alarm. */
inline void quicly_loss_on_ack_received(quicly_loss_t *r, uint64_t largest_acked, uint32_t latest_rtt)
{
    if (r->largest_acked_packet < largest_acked)
        r->largest_acked_packet = largest_acked;
    if (latest_rtt != UINT32_MAX)
        quicly_rtt_update(&r->rtt, latest_rtt);
}

/* After calling this function, app should:
 *  * if num_packets_to_send is zero, send things normally
 *  * if num_packets_to_send is non-zero, send the specfied number of packets immmediately
 * and then call quicly_loss_update_alarm and update the alarm */
inline int quicly_loss_on_alarm(quicly_loss_t *r, int64_t now, uint64_t largest_sent, quicly_loss_do_detect_cb do_detect,
                                size_t *num_packets_to_send)
{
    if (r->loss_time != 0) {
        /* Early retransmit or Time Loss Detection */
        *num_packets_to_send = 0;
        return quicly_loss_detect_loss(r, now, largest_sent, r->largest_acked_packet, do_detect);
    }
    if (r->tlp_count < r->conf->max_tlps) {
        /* Tail Loss Probe. */
        r->tlp_count++;
        *num_packets_to_send = 1;
        return 0;
    }
    /* RTO */
    if (r->rto_count == 0)
        r->largest_sent_before_rto = largest_sent;
    ++r->rto_count;
    *num_packets_to_send = 2;
    return 0;
}

inline int quicly_loss_detect_loss(quicly_loss_t *r, int64_t now, uint64_t largest_sent, uint64_t largest_acked,
                                   quicly_loss_do_detect_cb do_detect)
{
    uint32_t delay_until_lost = (r->rtt.latest > r->rtt.smoothed ? r->rtt.latest : r->rtt.smoothed) * 9 / 8;
    int64_t loss_time;
    int ret;

    r->loss_time = 0;
    if (largest_sent != largest_acked)
        return 0;

    if ((ret = do_detect(r, now, largest_acked, delay_until_lost, &loss_time)) != 0)
        return ret;
    if (loss_time != INT64_MAX && r->loss_time == 0)
        r->loss_time = loss_time;

    return 0;
}

#endif
