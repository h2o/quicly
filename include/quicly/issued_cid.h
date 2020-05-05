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

#ifndef issued_cid_h
#define issued_cid_h

#include "quicly/cid.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_quicly_issued_cid_set_t quicly_issued_cid_set_t;
typedef struct st_quicly_issued_cid_t quicly_issued_cid_t;
typedef struct st_quicly_conn_t quicly_conn_t;

/**
 * a callback function to generate a new connection ID in `cid`
 *
 * @return 0 if successfully generated, non-zero if unable to generate a CID (e.g. limit reached)
 */
typedef int (*quicly_issued_cid_generator_t)(quicly_conn_t *conn, quicly_issued_cid_t *cid);

enum en_quicly_issued_cid_state_t {
    /**
     * this entry is free for use
     */
    QUICLY_ISSUED_CID_STATE_IDLE,
    /**
     * this entry is to be sent at the next round of send operation
     */
    QUICLY_ISSUED_CID_STATE_PENDING,
    /**
     * this entry has been sent and is waiting for ACK (or to be deemed lost)
     */
    QUICLY_ISSUED_CID_STATE_INFLIGHT,
    /**
     * this CID has been delivered to the peer (ACKed) and in use
     */
    QUICLY_ISSUED_CID_STATE_DELIVERED,
};

/**
 * records information for sending NEW_CONNECTION_ID frame
 */
struct st_quicly_issued_cid_t {
    enum en_quicly_issued_cid_state_t state;
    uint64_t sequence;
    quicly_cid_t cid;
    uint8_t stateless_reset_token[QUICLY_STATELESS_RESET_TOKEN_LEN];
};

/**
 * manages a list of connection IDs we issue to the peer
 */
struct st_quicly_issued_cid_set_t {
    /**
     * storage to retain issued CIDs
     *
     * Pending CIDs (state == STATE_PENDING) are moved to the front of the array, in the order it was marked as pending.
     * This ensures that pending CIDs are sent in FIFO manner. Order of CIDs with other states is not defined.
     */
    struct st_quicly_issued_cid_t cids[QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT];
    /**
     * how many entries are actually usable in `cids`?
     */
    size_t _capacity;
    quicly_issued_cid_generator_t _generator;
    /**
     * connection object passed to the CID generator
     */
    quicly_conn_t *_conn;
};

/**
 * initialize the structure
 *
 * If `generator` is non-NULL, it is initialized with capacity==1 (sequence==0 is registered as DELIVERED).
 * Otherwise, it is initialized with capacity==0, and the capacity shall never be increased.
 */
void quicly_issued_cid_init(quicly_issued_cid_set_t *set, quicly_issued_cid_generator_t generator, quicly_conn_t *conn);
/**
 * sets a new capacity of issued CIDs.
 *
 * The new capacity must be equal to or grater than the current capacity, and must be equal to or less than the elements of `cids`.
 * When the capacity is expanded, the CID generator callback is called to generate a new CID.
 */
void quicly_issued_cid_set_capacity(quicly_issued_cid_set_t *set, size_t new_cap);
/**
 * returns true if all entries in the given set is in IDLE state
 */
static int quicly_issued_cid_is_empty(const quicly_issued_cid_set_t *set);
static size_t quicly_issued_cid_get_capacity(const quicly_issued_cid_set_t *set);
/**
 * mark the first `num_sent` pending CIDs as INFLIGHT.
 */
void quicly_issued_cid_mark_inflight(quicly_issued_cid_set_t *set, size_t num_sent);
/**
 * mark the specified CID as DELIVERED.
 *
 * @return zero if successful, non-zero if the specified CID was not found.
 */
int quicly_issued_cid_mark_delivered(quicly_issued_cid_set_t *set, uint64_t sequence);
/**
 * (re-)mark the specified CID as PENDING.
 *
 * This function is intended for rescheduling CID transmission after packet loss
 * @return zero if successful, non-zero if the specified CID was not found.
 */
int quicly_issued_cid_mark_pending(quicly_issued_cid_set_t *set, uint64_t sequence);
/**
 * remove the specified CID from the storage.
 *
 * This makes one slot for CIDs empty. The CID generator callback is then called to fill the slot with a new CID.
 * @return 0 if successfully retired the specified sequence, non-zero if the specified sequence was not found
 */
int quicly_issued_cid_retire(quicly_issued_cid_set_t *set, uint64_t sequence);

inline int quicly_issued_cid_is_empty(const quicly_issued_cid_set_t *set)
{
    for (size_t i = 0; i < set->_capacity; i++) {
        if (set->cids[i].state != QUICLY_ISSUED_CID_STATE_IDLE)
            return 0;
    }
    return 1;
}

inline size_t quicly_issued_cid_get_capacity(const quicly_issued_cid_set_t *set)
{
    return set->_capacity;
}

#ifdef __cplusplus
}
#endif

#endif
