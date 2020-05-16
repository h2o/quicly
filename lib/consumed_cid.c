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
#include <assert.h>
#include <string.h>
#include "quicly/consumed_cid.h"

void quicly_consumed_cid_init(quicly_consumed_cid_set_t *set)
{
    memset(set, 0, sizeof(*set));
    for (size_t i = 0; i < PTLS_ELEMENTSOF(set->cids); i++) {
        set->cids[i].sequence = i;
    }
    set->_largest_sequence_expected = PTLS_ELEMENTSOF(set->cids) - 1;
}

/**
 * promote CID at idx_to_promote as the current CID for communication
 * i.e. swap cids[idx_to_promote] and cids[0]
 */
static void promote_cid(quicly_consumed_cid_set_t *set, size_t idx_to_promote)
{
    uint64_t seq_tmp = set->cids[0].sequence;

    assert(idx_to_promote > 0);
    assert(!set->cids[0].is_active);

    set->cids[0] = set->cids[idx_to_promote];
    set->cids[idx_to_promote].is_active = 0;
    set->cids[idx_to_promote].sequence = seq_tmp;
}

int quicly_consumed_cid_register(quicly_consumed_cid_set_t *set, uint64_t sequence, const uint8_t *cid, size_t cid_len,
                                 const uint8_t srt[QUICLY_STATELESS_RESET_TOKEN_LEN])
{
    int was_stored = 0;

    if (set->_largest_sequence_expected < sequence)
        return QUICLY_TRANSPORT_ERROR_CONNECTION_ID_LIMIT;

    for (size_t i = 0; i < PTLS_ELEMENTSOF(set->cids); i++) {
        if (set->cids[i].is_active) {
            /* compare newly received CID against what we already have, to see if there is duplication/conflicts */

            /* If an endpoint receives a NEW_CONNECTION_ID frame that repeats a previously issued connection ID with
             * a different Stateless Reset Token or a different sequence number, or if a sequence number is used for
             * different connection IDs, the endpoint MAY treat that receipt as a connection error of type PROTOCOL_VIOLATION.
             * (19.15)
             */
            if (quicly_cid_is_equal(&set->cids[i].cid, ptls_iovec_init(cid, cid_len))) {
                if (set->cids[i].sequence == sequence &&
                    memcmp(set->cids[i].stateless_reset_token, srt, QUICLY_STATELESS_RESET_TOKEN_LEN) == 0) {
                    /* likely a duplicate due to retransmission */
                    return 0;
                } else {
                    /* received a frame that carries conflicting information */
                    return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
                }
            }
            /* here we know CID is not equal */
            if (set->cids[i].sequence == sequence)
                return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
        } else if (set->cids[i].sequence == sequence) {
            assert(!was_stored);
            set->cids[i].sequence = sequence;
            quicly_set_cid(&set->cids[i].cid, ptls_iovec_init(cid, cid_len));
            memcpy(set->cids[i].stateless_reset_token, srt, QUICLY_STATELESS_RESET_TOKEN_LEN);
            set->cids[i].is_active = 1;
            was_stored = 1;
            if (i > 0 && !set->cids[0].is_active) {
                /* promote this CID for communication */
                promote_cid(set, i);
            }
        }
    }

    /* execution reaches here in two cases, 1) normal path, i.e. new CID was successfully registered, and 2) new CID was already
     * retired (was_stored == 0). */
    return 0;
}

static void do_unregister(quicly_consumed_cid_set_t *set, size_t idx_to_unreg)
{
    assert(set->cids[idx_to_unreg].is_active);

    set->cids[idx_to_unreg].is_active = 0;
    set->cids[idx_to_unreg].sequence = ++set->_largest_sequence_expected;
}

int quicly_consumed_cid_unregister(quicly_consumed_cid_set_t *set, uint64_t sequence)
{
    uint64_t min_seq = UINT64_MAX;
    size_t min_seq_idx = SIZE_MAX;
    for (size_t i = 0; i < PTLS_ELEMENTSOF(set->cids); i++) {
        if (sequence == set->cids[i].sequence) {
            do_unregister(set, i);
            if (i != 0)
                return 0; /* if not retiring idx=0 (current in-use CID), simply return */
        }
        if (set->cids[i].is_active && min_seq > set->cids[i].sequence) {
            /* find a CID with minimum sequence number, while iterating over the array */
            min_seq = set->cids[i].sequence;
            min_seq_idx = i;
        }
    }

    if (!set->cids[0].is_active) {
        /* we have retired the current CID (idx=0) */
        if (min_seq_idx != SIZE_MAX)
            promote_cid(set, min_seq_idx);
        return 0;
    } else {
        /* we did not unregister any slot */
        return 1;
    }
}

size_t quicly_consumed_cid_unregister_prior_to(quicly_consumed_cid_set_t *set, uint64_t seq_unreg_prior_to,
                                               uint64_t unregistered_seqs[QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT])
{
    uint64_t min_seq = UINT64_MAX, min_seq_idx = UINT64_MAX;
    size_t num_unregistered = 0;
    for (size_t i = 0; i < PTLS_ELEMENTSOF(set->cids); i++) {
        if (set->cids[i].is_active) {
            if (set->cids[i].sequence < seq_unreg_prior_to) {
                unregistered_seqs[num_unregistered++] = set->cids[i].sequence;
                do_unregister(set, i);
                continue;
            }
            if (min_seq > set->cids[i].sequence) {
                /* find a CID with minimum sequence number, while iterating over the array */
                min_seq = set->cids[i].sequence;
                min_seq_idx = i;
            }
        }
    }

    if (!set->cids[0].is_active) {
        /* we have retired the current CID (idx=0) */
        if (min_seq_idx != UINT64_MAX)
            promote_cid(set, min_seq_idx);
    }

    return num_unregistered;
}
