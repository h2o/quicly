/*
 * Copyright (c) 2020 Fastly, Inc.
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

#include <string.h>
#include "quicly/issued_cid.h"

void quicly_issued_cid_init(quicly_issued_cid_set_t *set, quicly_issued_cid_generator_t generator, quicly_conn_t *conn)
{
    memset(set, 0, sizeof(*set));

    if (generator == NULL)
        return;

    set->_capacity = 1;
    set->cids[0].state = QUICLY_ISSUED_CID_STATE_DELIVERED;
    for (size_t i = 1; i < PTLS_ELEMENTSOF(set->cids); i++)
        set->cids[i].sequence = UINT64_MAX;
    set->_conn = conn;
    set->_generator = generator;
}

static void swap_cids(quicly_issued_cid_t *a, quicly_issued_cid_t *b)
{
    quicly_issued_cid_t tmp = *b;
    *b = *a;
    *a = tmp;
}

/**
 * change the state of a CID to PENDING, and move it forward so CIDs in pending state form FIFO
 */
static void do_mark_pending(quicly_issued_cid_set_t *set, size_t idx)
{
    set->cids[idx].state = QUICLY_ISSUED_CID_STATE_PENDING;
    for (size_t j = 0; j < idx; j++) {
        if (set->cids[j].state != QUICLY_ISSUED_CID_STATE_PENDING) {
            swap_cids(&set->cids[idx], &set->cids[j]);
            break;
        }
    }
}

void quicly_issued_cid_set_capacity(quicly_issued_cid_set_t *set, size_t capacity)
{
    assert(capacity >= 0);
    assert(capacity <= PTLS_ELEMENTSOF(set->cids));
    assert(set->_capacity <= capacity);

    for (size_t i = set->_capacity; i < capacity; i++)
        set->cids[i].state = QUICLY_ISSUED_CID_STATE_IDLE;

    set->_capacity = capacity;

    /* First we prepare N CIDs (to be precise here we prepare N-1, as we already had one upon initialization).
     * Later, every time one of the CIDs is retired, we immediately prepare one additional CID
     * to always fill the CID list. */
    for (size_t i = 0; i < capacity; i++) {
        if (set->cids[i].state != QUICLY_ISSUED_CID_STATE_IDLE)
            continue;

        if (set->_generator == NULL || set->_generator(set->_conn, &set->cids[i]) != 0)
            break;
        do_mark_pending(set, i);
    }
}

void quicly_issued_cid_mark_inflight(quicly_issued_cid_set_t *set, size_t num_sent)
{
    assert(num_sent <= set->_capacity);

    /* first, mark the first `num_sent` CIDs as INFLIGHT */
    for (size_t i = 0; i < num_sent; i++) {
        assert(set->cids[i].state == QUICLY_ISSUED_CID_STATE_PENDING);
        set->cids[i].state = QUICLY_ISSUED_CID_STATE_INFLIGHT;
    }

    /* then move the remaining PENDING CIDs (if any) to the front of the array */
    for (size_t i = num_sent; i < set->_capacity; i++) {
        if (set->cids[i].state != QUICLY_ISSUED_CID_STATE_PENDING)
            break;
        swap_cids(&set->cids[i], &set->cids[i - num_sent]);
    }
}

static size_t find_inflight(const quicly_issued_cid_set_t *set, uint64_t sequence)
{
    for (size_t i = 0; i < set->_capacity; i++) {
        if (set->cids[i].sequence == sequence) {
            assert(set->cids[i].state != QUICLY_ISSUED_CID_STATE_PENDING);
            assert(set->cids[i].state != QUICLY_ISSUED_CID_STATE_IDLE);
            return i;
        }
    }

    return SIZE_MAX;
}

int quicly_issued_cid_mark_delivered(quicly_issued_cid_set_t *set, uint64_t sequence)
{
    size_t i = find_inflight(set, sequence);
    if (i == SIZE_MAX)
        return 1;

    assert(set->cids[i].state == QUICLY_ISSUED_CID_STATE_INFLIGHT);

    set->cids[i].state = QUICLY_ISSUED_CID_STATE_DELIVERED;

    return 0;
}

int quicly_issued_cid_mark_pending(quicly_issued_cid_set_t *set, uint64_t sequence)
{
    size_t i = find_inflight(set, sequence);
    if (i == SIZE_MAX)
        return 1;

    do_mark_pending(set, i);

    return 0;
}

int quicly_issued_cid_retire(quicly_issued_cid_set_t *set, uint64_t sequence)
{
    size_t retired_at = set->_capacity;
    for (size_t i = 0; i < set->_capacity; i++) {
        if (set->cids[i].sequence != sequence || set->cids[i].state == QUICLY_ISSUED_CID_STATE_IDLE)
            continue;

        retired_at = i;
        set->cids[i].state = QUICLY_ISSUED_CID_STATE_IDLE;
        set->cids[i].sequence = UINT64_MAX;
        break;
    }
    if (retired_at == set->_capacity) /* not found */
        return 1;

    /* move following PENDING CIDs to front */
    for (size_t i = retired_at + 1; i < set->_capacity; i++) {
        if (set->cids[i].state != QUICLY_ISSUED_CID_STATE_PENDING)
            break;
        swap_cids(&set->cids[i], &set->cids[retired_at]);
        retired_at = i;
    }
    /* generate one new CID */
    if (set->_generator == NULL || set->_generator(set->_conn, &set->cids[retired_at]) == 0)
        do_mark_pending(set, retired_at);

    return 0;
}
