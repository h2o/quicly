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

#include <assert.h>
#include <math.h>
#include <string.h>
#include "quicly/rate.h"
#include "test.h"

#define CHECK_REPORT(el, es, ev)                                                                                                   \
    do {                                                                                                                           \
        quicly_rate_t rate;                                                                                                        \
        quicly_ratemeter_report(&meter, &rate);                                                                                    \
        ok(rate.latest == el);                                                                                                     \
        ok(rate.smoothed == es);                                                                                                   \
        ok(rate.variation == ev);                                                                                                  \
    } while (0)

/**
 * Simulates a flow sending one packet every millisecond.
 */
struct sim_t {
    quicly_ratemeter_t meter;
    double now;
    uint64_t pn;
    uint64_t bytes_acked;
    struct {
        double ack_at;
        uint64_t pn;
        uint32_t size;
    } in_flight[1000];
    size_t num_in_flight;
};

static void sim_init(struct sim_t *sim)
{
    memset(sim, 0, sizeof(*sim));
    quicly_ratemeter_init(&sim->meter);
    sim->now = 1000;
}

/**
 * Runs the simulation for `duration` milliseconds, sending packets of `packet_size` bytes, CC-limited if `cc_limited` is set. Each
 * packet sent at time T is acked at `ack_at(T)`, which must not decrease as T increases.
 */
static void sim_run(struct sim_t *sim, int64_t duration, uint32_t packet_size, int cc_limited, double (*ack_at)(double sent_at))
{
    for (int64_t i = 0; i < duration; ++i, sim->now += 1) {
        /* process ACKs */
        size_t num_acked = 0;
        while (num_acked < sim->num_in_flight && sim->in_flight[num_acked].ack_at <= sim->now) {
            sim->bytes_acked += sim->in_flight[num_acked].size;
            quicly_ratemeter_on_ack(&sim->meter, sim->in_flight[num_acked].ack_at, sim->bytes_acked, sim->in_flight[num_acked].pn,
                                    sim->pn);
            ++num_acked;
        }
        memmove(sim->in_flight, sim->in_flight + num_acked, (sim->num_in_flight - num_acked) * sizeof(sim->in_flight[0]));
        sim->num_in_flight -= num_acked;
        /* send */
        if (cc_limited != quicly_ratemeter_is_cc_limited(&sim->meter)) {
            if (cc_limited) {
                quicly_ratemeter_enter_cc_limited(&sim->meter, sim->pn);
            } else {
                quicly_ratemeter_exit_cc_limited(&sim->meter, sim->pn);
            }
        }
        assert(sim->num_in_flight < sizeof(sim->in_flight) / sizeof(sim->in_flight[0]));
        sim->in_flight[sim->num_in_flight].ack_at = ack_at(sim->now);
        sim->in_flight[sim->num_in_flight].pn = sim->pn++;
        sim->in_flight[sim->num_in_flight].size = packet_size;
        ++sim->num_in_flight;
    }
}

static double ack_after_50ms(double sent_at)
{
    return sent_at + 50;
}

static void test_basic(void)
{
    static struct sim_t sim;
#define meter sim.meter

    sim_init(&sim);
    CHECK_REPORT(0, 0, 0);

    /* CC-limited, 1KB per millisecond; each window spans one RTT (50ms) */
    sim_run(&sim, 10000, 1000, 1, ack_after_50ms);
    CHECK_REPORT(1000000, 1000000, 0);

    /* application-limited, 10 bytes per millisecond; nothing is measured */
    sim_run(&sim, 1000, 10, 0, ack_after_50ms);
    CHECK_REPORT(1000000, 1000000, 0);

    /* CC-limited, 2KB per millisecond; the first window, which includes the ACKs of packets sent while application-limited, ends
     * after one round trip but is not used */
    sim_run(&sim, 51, 2000, 1, ack_after_50ms);
    ok(isnan(meter.window.at) == 0);
    CHECK_REPORT(1000000, 1000000, 0);
    sim_run(&sim, 10000, 2000, 1, ack_after_50ms);
    CHECK_REPORT(2000000, 2000000, 0);

#undef meter
}

static void test_short_flights(void)
{
    quicly_ratemeter_t meter;
    double now = 1000;
    uint64_t pn = 0, bytes_acked = 0;

    quicly_ratemeter_init(&meter);

    /* CC-limited flights of 10 packets sent back-to-back and acked within 0.2ms, separated by 100ms of not being CC-limited; no
     * window spans a round trip while CC-limited */
    for (int flight = 0; flight < 20; ++flight) {
        quicly_ratemeter_enter_cc_limited(&meter, pn);
        uint64_t first_pn = pn;
        pn += 10;
        quicly_ratemeter_exit_cc_limited(&meter, pn);
        now += 50;
        for (int i = 0; i < 10; ++i) {
            bytes_acked += 1000;
            quicly_ratemeter_on_ack(&meter, now + 0.02 * i, bytes_acked, first_pn + i, pn);
        }
        now += 100;
    }
    CHECK_REPORT(0, 0, 0);
}

static double ack_in_clumps(double sent_at)
{
    /* ACKs are held and released every 15ms */
    return ceil((sent_at + 50) / 15) * 15;
}

static void test_ack_compression(void)
{
    static struct sim_t sim;

    sim_init(&sim);

    /* CC-limited, 1KB per millisecond, the ACKs released in clumps every 15ms; each window starts and ends at a clump, spanning
     * at least one round trip */
    sim_run(&sim, 10000, 1000, 1, ack_in_clumps);

#define meter sim.meter
    CHECK_REPORT(1000000, 1000000, 0);
#undef meter
}

void test_rate(void)
{
    subtest("basic", test_basic);
    subtest("short-flights", test_short_flights);
    subtest("ack-compression", test_ack_compression);
}
