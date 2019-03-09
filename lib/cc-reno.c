/*
 * Copyright (c) 2017 Fastly, Janardhan Iyengar
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

#include "quicly/cc.h"

#define QUICLY_INITIAL_WINDOW 10
#define QUICLY_MIN_CWND 2
#define QUICLY_RENO_BETA 0.8

void cc_init2(struct ccstate *ccs) {
    memset(ccs, 0, sizeof(struct ccstate));
    ccs->cwnd = QUICLY_INITIAL_WINDOW * QUICLY_MAX_PACKET_SIZE;
    ccs->ssthresh = UINT32_MAX;
}

int cc_can_send(struct ccstate *ccs) {
    return ccs->inflight < ccs->cwnd;
}

void cc_on_sent(struct ccstate *ccs, uint32_t bytes) {
    ccs->inflight += bytes;
}

// TODO: Avoid increase if sender was application limited
void cc_on_acked(struct ccstate *ccs, uint32_t bytes, uint64_t acked_pn) {
    assert(ccs->inflight >= bytes);
    if (acked_pn < ccs->recovery_end) {
        // no increases while in recovery
        ccs->inflight -= bytes;
        return;
    }

    // slow start
    if (ccs->inflight > ccs->ssthresh)
        ccs->cwnd += bytes;
    else {
        // congestion avoidance
        ccs->stash += bytes;
        if (ccs->stash >= ccs->cwnd) {
            // increase cwnd by 1 MSS per cwnd acked
            uint32_t count = ccs->stash / ccs->cwnd;
            ccs->stash -= count * ccs->cwnd;
            ccs->cwnd +=  count * QUICLY_MAX_PACKET_SIZE;
        }
    }
    ccs->inflight -= bytes;
}

void cc_on_lost(struct ccstate *ccs, uint32_t bytes, uint64_t lost_pn, uint64_t next_pn) {
    assert(ccs->inflight >= bytes);
    ccs->inflight -= bytes;
    // nothing to do if loss is in recovery window
    if (lost_pn < ccs->recovery_end)
        return;
    // set end of recovery window
    ccs->recovery_end = next_pn;
    ccs->cwnd *= QUICLY_RENO_BETA;
    if (ccs->cwnd < QUICLY_MIN_CWND * QUICLY_MAX_PACKET_SIZE)
        ccs->cwnd = QUICLY_MIN_CWND * QUICLY_MAX_PACKET_SIZE;
    ccs->ssthresh = ccs->cwnd;
}

void cc_on_persistent_congestion(struct ccstate *ccs) {
    // TODO
}
